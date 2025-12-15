use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use crate::scanner::AdvancedOsintScanner;

pub struct ScannerWatcher {
    scanner: Arc<AdvancedOsintScanner>,
    tx: mpsc::Sender<notify::Result<Event>>,
}

impl ScannerWatcher {
    pub fn new(scanner: Arc<AdvancedOsintScanner>) -> (Self, mpsc::Receiver<notify::Result<Event>>) {
        let (tx, rx) = mpsc::channel(100);
        (
            Self {
                scanner,
                tx,
            },
            rx
        )
    }

    pub async fn watch(
        &self, 
        path: PathBuf, 
        mut rx: mpsc::Receiver<notify::Result<Event>>
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::info!("Starting Watch Mode on: {:?}", path);
        println!("\n👀 WATCH MODE ACTIVE: Monitoring {:?} for changes...", path);

        // Setup watcher
        let tx_clone = self.tx.clone();
        let mut watcher = RecommendedWatcher::new(move |res| {
            // Blocking send is fine here as this runs on notify's thread
            let _ = tx_clone.blocking_send(res);
        }, Config::default())?;

        watcher.watch(&path, RecursiveMode::Recursive)?;

        // Event loop
        while let Some(res) = rx.recv().await {
            match res {
                Ok(event) => {
                    self.handle_event(event).await;
                }
                Err(e) => log::error!("Watch error: {:?}", e),
            }
        }

        Ok(())
    }

    async fn handle_event(&self, event: Event) {
        use notify::EventKind;
        
        match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) => {
                for path in event.paths {
                    if path.is_file() {
                        self.scan_file(&path).await;
                    }
                }
            }
            _ => {}
        }
    }

    async fn scan_file(&self, path: &Path) {
        println!("📝 Change detected: {:?}", path);
        match self.scanner.analyze_target(path) {
            Ok(Some(asset)) => {
                if asset.risk_score > 50 {
                    println!("\n🚨 THREAT DETECTED: {:?}", path);
                    println!("   Risk Score: {}", asset.risk_score);
                    for threat in asset.threat_indicators {
                        println!("   - [{}] {}", threat.indicator_type, threat.description);
                    }
                    if let Some(_ae) = asset.anti_evasion {
                         println!("   - Anti-Evasion detected!");
                    }
                } else {
                    println!("✅ Clean: {:?} (Risk: {})", path, asset.risk_score);
                }
            },
            Ok(None) => {
                // Skipped or filtered
            },
            Err(e) => {
                log::error!("Failed to scan detected file {:?}: {}", path, e);
            }
        }
    }
}
