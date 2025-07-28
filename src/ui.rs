use console::{style, Term};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
#[allow(dead_code)]
pub struct HackerTerminalUI {
    term: Term,
    multi_progress: MultiProgress,
    main_progress: ProgressBar,
    file_progress: ProgressBar,
    stats: Arc<Mutex<ScanStats>>,
    start_time: Instant,
}

#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    pub files_processed: u64,
    pub bytes_processed: u64,
    pub threats_found: u64,
    pub current_file: String,
    pub files_per_second: f64,
    pub bytes_per_second: f64,
}

pub enum UIEvent {
    FileStarted(String),
    FileCompleted { size: u64, threats: u32 },
    ThreatFound { file: String, threat_type: String, risk_score: u8 },
    Progress(u64),
    Complete,
}

impl HackerTerminalUI {
    pub fn new(total_files: u64, quiet: bool) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let term = Term::stdout();
        let multi_progress = MultiProgress::new();
        
        if !quiet {
            // Clear screen and hide cursor for hacker-style display
            term.clear_screen()?;
            term.hide_cursor()?;
        }

        // Main progress bar with hacker styling
        let main_style = ProgressStyle::with_template(
            "{prefix} {spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({percent}%)"
        )?
        .progress_chars("█▉▊▋▌▍▎▏  ")
        .tick_strings(&["▰▱▱▱▱▱▱", "▰▰▱▱▱▱▱", "▰▰▰▱▱▱▱", "▰▰▰▰▱▱▱", "▰▰▰▰▰▱▱", "▰▰▰▰▰▰▱", "▰▰▰▰▰▰▰", "▱▰▰▰▰▰▰"]);

        let main_progress = if quiet {
            ProgressBar::hidden()
        } else {
            multi_progress.add(ProgressBar::new(total_files))
        };
        
        main_progress.set_style(main_style);
        main_progress.set_prefix(style("🔍 OSINT").green().bold().to_string());

        // File-level progress bar for detailed feedback
        let file_style = ProgressStyle::with_template(
            "{prefix} {msg}"
        )?;

        let file_progress = if quiet {
            ProgressBar::hidden()
        } else {
            multi_progress.add(ProgressBar::new_spinner())
        };
        
        file_progress.set_style(file_style);
        file_progress.set_prefix(style("📄 FILE").cyan().bold().to_string());

        Ok(Self {
            term,
            multi_progress,
            main_progress,
            file_progress,
            stats: Arc::new(Mutex::new(ScanStats::default())),
            start_time: Instant::now(),
        })
    }

    pub async fn run(&self, mut event_receiver: mpsc::Receiver<UIEvent>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let stats = Arc::clone(&self.stats);
        let main_progress = self.main_progress.clone();
        let file_progress = self.file_progress.clone();
        let start_time = self.start_time;

        // Spawn task to update UI periodically
        let ui_stats = Arc::clone(&stats);
        let ui_main_progress = main_progress.clone();
        let _ui_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            
            loop {
                interval.tick().await;
                
                let stats_guard = ui_stats.lock().unwrap();
                let elapsed = start_time.elapsed().as_secs_f64();
                
                if elapsed > 0.0 {
                    let files_per_sec = stats_guard.files_processed as f64 / elapsed;
                    let bytes_per_sec = stats_guard.bytes_processed as f64 / elapsed;
                    let mb_per_sec = bytes_per_sec / (1024.0 * 1024.0);
                    
                    let eta = if files_per_sec > 0.0 {
                        let total = ui_main_progress.length().unwrap_or(0);
                        let current = ui_main_progress.position();
                        let remaining = total.saturating_sub(current); // This prevents underflow!
                        remaining as f64 / files_per_sec
                    } else {
                        0.0
                    };
                    let status_msg = format!(
                        "{} | {} | {} | ETA: {}",
                        style(format!("{:.0} files/s", files_per_sec)).green(),
                        style(format!("{:.1} MB/s", mb_per_sec)).yellow(),
                        style(format!("{} threats", stats_guard.threats_found)).red().bold(),
                        style(format!("{:.0}s", eta)).cyan()
                    );
                    
                    ui_main_progress.set_message(status_msg);
                }
            }
        });

        // Main event processing loop
        while let Some(event) = event_receiver.recv().await {
            match event {
                UIEvent::FileStarted(filename) => {
                    log::debug!("UI: File started - {}", filename);
                    
                    let display_name = if filename.len() > 60 {
                        format!("...{}", &filename[filename.len() - 57..])
                    } else {
                        filename.clone()
                    };
                    
                    file_progress.set_message(format!(
                        "{} {}",
                        style("Processing:").dim(),
                        style(display_name).white().bold()
                    ));
                    
                    {
                        let mut stats_guard = stats.lock().unwrap();
                        stats_guard.current_file = filename;
                    }
                },
                
                UIEvent::FileCompleted { size, threats } => {
                    log::debug!("UI: File completed - size: {}, threats: {}", size, threats);
                    
                    {
                        let mut stats_guard = stats.lock().unwrap();
                        stats_guard.files_processed += 1;
                        stats_guard.bytes_processed += size;
                        stats_guard.threats_found += u64::from(threats);
                    }
                    
                    main_progress.inc(1);
                },
                
                UIEvent::ThreatFound { file, threat_type, risk_score } => {
                    log::debug!("UI: Threat found - file: {}, type: {}, score: {}", file, threat_type, risk_score);
                    
                    if risk_score > 70 {
                        let alert = format!(
                            "🚨 {} {} in {} (Risk: {})",
                            style("HIGH RISK").red().bold(),
                            style(&threat_type).yellow(),
                            style(&file).dim(),
                            style(risk_score).red().bold()
                        );
                        
                        // Print alert above progress bars
                        println!("{}", alert);
                    }
                },
                
                UIEvent::Progress(count) => {
                    main_progress.set_position(count);
                },
                
                UIEvent::Complete => {
                    log::debug!("UI: Scan complete");
                    main_progress.finish_with_message(
                        style("✅ Analysis complete!").green().bold().to_string()
                    );
                    file_progress.finish_and_clear();
                    break;
                }
            }
        }

        // Show cursor and final cleanup
        self.term.show_cursor()?;
        
        Ok(())
    }

    pub fn create_event_sender(&self) -> mpsc::Sender<UIEvent> {
        let (sender, _) = mpsc::channel(1000);
        sender
    }

    pub fn print_summary(&self, stats: &ScanStats, elapsed: Duration) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.main_progress.is_hidden() {
            return Ok(());
        }

        println!();
        println!("{}", style("╔══════════════════════════════════════════════════════════════╗").cyan());
        println!("{}", style("║                        SCAN RESULTS                         ║").cyan().bold());
        println!("{}", style("╚══════════════════════════════════════════════════════════════╝").cyan());
        println!();
        
        println!("   {} Files Processed: {}", 
            style("📁").blue(), 
            style(stats.files_processed).white().bold());
        
        println!("   {} Data Analyzed: {:.2} MB", 
            style("💾").blue(), 
            style(stats.bytes_processed as f64 / (1024.0 * 1024.0)).white().bold());
        
        println!("   {} Threats Detected: {}", 
            style("🚨").red(), 
            style(stats.threats_found).red().bold());
        
        println!("   {} Total Duration: {:.2}s", 
            style("⏱️").blue(), 
            style(elapsed.as_secs_f64()).white().bold());
        
        let files_per_sec = stats.files_processed as f64 / elapsed.as_secs_f64();
        println!("   {} Processing Speed: {:.0} files/sec", 
            style("🚀").blue(), 
            style(files_per_sec).white().bold());

        println!();

        Ok(())
    }
}

impl Drop for HackerTerminalUI {
    fn drop(&mut self) {
        let _ = self.term.show_cursor();
    }
}