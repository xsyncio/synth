use console::{style, Term};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Terminal UI for the scanner with clean, organized output.
pub struct HackerTerminalUI {
    term: Term,
    multi_progress: MultiProgress,
    main_progress: ProgressBar,
    stats: Arc<Mutex<ScanStats>>,
    start_time: Instant,
    is_quiet: bool,
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
    pub fn new(total_files: u64) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let term = Term::stdout();
        let multi_progress = MultiProgress::new();
        
        // Clean, minimal progress style
        let main_style = ProgressStyle::with_template(
            "{spinner:.cyan} {prefix:.bold} [{bar:40.cyan/dark_gray}] {pos}/{len} {msg}"
        )?
        .progress_chars("━━╸")
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]);

        let main_progress = multi_progress.add(ProgressBar::new(total_files));
        main_progress.set_style(main_style);
        main_progress.set_prefix("Scanning");
        main_progress.enable_steady_tick(Duration::from_millis(80));

        Ok(Self {
            term,
            multi_progress,
            main_progress,
            stats: Arc::new(Mutex::new(ScanStats::default())),
            start_time: Instant::now(),
            is_quiet: false,
        })
    }

    pub async fn run(&self, mut event_receiver: mpsc::Receiver<UIEvent>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let stats = Arc::clone(&self.stats);
        let main_progress = self.main_progress.clone();
        let start_time = self.start_time;

        // Stats update task
        let ui_stats = Arc::clone(&stats);
        let ui_progress = main_progress.clone();
        let _ui_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(150));
            
            loop {
                interval.tick().await;
                
                let stats_guard = ui_stats.lock().unwrap();
                let elapsed = start_time.elapsed().as_secs_f64();
                
                if elapsed > 0.0 {
                    let files_ps = stats_guard.files_processed as f64 / elapsed;
                    let mb_ps = (stats_guard.bytes_processed as f64 / elapsed) / (1024.0 * 1024.0);
                    
                    let eta = {
                        let total = ui_progress.length().unwrap_or(0);
                        let current = ui_progress.position();
                        let remaining = total.saturating_sub(current);
                        if files_ps > 0.0 { remaining as f64 / files_ps } else { 0.0 }
                    };
                    
                    let msg = format!(
                        "{} {} {:.0}/s {} {:.1}MB/s {} {}s",
                        style("│").dim(),
                        style("📄").dim(),
                        files_ps,
                        style("│").dim(),
                        mb_ps,
                        style("│").dim(),
                        format!("{:.0}", eta)
                    );
                    
                    ui_progress.set_message(msg);
                }
            }
        });

        // Event loop
        while let Some(event) = event_receiver.recv().await {
            match event {
                UIEvent::FileStarted(_filename) => {
                    // Don't print individual files - too noisy
                },
                
                UIEvent::FileCompleted { size, threats } => {
                    {
                        let mut stats_guard = stats.lock().unwrap();
                        stats_guard.files_processed += 1;
                        stats_guard.bytes_processed += size;
                        stats_guard.threats_found += u64::from(threats);
                    }
                    main_progress.inc(1);
                },
                
                UIEvent::ThreatFound { file, threat_type, risk_score } => {
                    // Only log critical threats
                    if risk_score >= 75 && !self.is_quiet {
                        let short_file = std::path::Path::new(&file)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(&file);
                        
                        main_progress.suspend(|| {
                            eprintln!(
                                "  {} {} {} in {} ({})",
                                style("⚠").red().bold(),
                                style("CRITICAL").red().bold(),
                                style(&threat_type).yellow(),
                                style(short_file).dim(),
                                style(risk_score).red()
                            );
                        });
                    }
                },
                
                UIEvent::Progress(count) => {
                    main_progress.set_position(count);
                },
                
                UIEvent::Complete => {
                    main_progress.finish_and_clear();
                    break;
                }
            }
        }
        
        Ok(())
    }

    pub fn create_event_sender(&self) -> mpsc::Sender<UIEvent> {
        let (sender, _) = mpsc::channel(1000);
        sender
    }

    pub fn print_summary(&self, stats: &ScanStats, elapsed: Duration) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _ = self.term.clear_last_lines(1);
        
        let width = 58;
        let border = "─".repeat(width);
        
        println!();
        println!("  {} {} {}", 
            style("╭").cyan(),
            style(&border).cyan(),
            style("╮").cyan()
        );
        
        // Title
        println!("  {}  {}{}  {}", 
            style("│").cyan(),
            style("✓ SCAN COMPLETE").green().bold(),
            " ".repeat(width - 17),
            style("│").cyan()
        );
        
        println!("  {}{}{}",
            style("├").cyan(),
            style(&border).cyan(),
            style("┤").cyan()
        );
        
        // Stats
        let format_row = |label: &str, value: &str| {
            let content = format!("  {}  {}", label, style(value).white().bold());
            let padding = width - label.len() - value.len() - 4;
            format!("  {}{}{}{}",
                style("│").cyan(),
                content,
                " ".repeat(padding),
                style("│").cyan()
            )
        };
        
        println!("{}", format_row("Files Scanned:", &stats.files_processed.to_string()));
        println!("{}", format_row("Data Analyzed:", &format!("{:.1} MB", stats.bytes_processed as f64 / 1_048_576.0)));
        println!("{}", format_row("Duration:", &format!("{:.2}s", elapsed.as_secs_f64())));
        println!("{}", format_row("Speed:", &format!("{:.0} files/sec", stats.files_processed as f64 / elapsed.as_secs_f64())));
        
        println!("  {}{}{}",
            style("├").cyan(),
            style(&border).cyan(),
            style("┤").cyan()
        );
        
        // Threats count
        if stats.threats_found > 0 {
            println!("{}", format_row("Threats Found:", &format!("{}", style(stats.threats_found).red().bold())));
        } else {
            println!("{}", format_row("Threats Found:", &format!("{}", style("0").green())));
        }
        
        println!("  {} {} {}", 
            style("╰").cyan(),
            style(&border).cyan(),
            style("╯").cyan()
        );
        println!();

        Ok(())
    }
}

impl Drop for HackerTerminalUI {
    fn drop(&mut self) {
        let _ = self.term.show_cursor();
        self.multi_progress.clear().unwrap_or_default();
    }
}
