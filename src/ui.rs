use console::{style, Term};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
// Removed: use console::pad::PadStr; // This import is not needed for format! based padding

#[allow(dead_code)]
pub struct HackerTerminalUI {
    term: Term,
    multi_progress: MultiProgress,
    main_progress: ProgressBar,
    file_progress: ProgressBar,
    stats: Arc<Mutex<ScanStats>>,
    start_time: Instant,
    is_quiet: bool, // Added: Store the quiet state
}

#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    pub files_processed: u64,
    pub bytes_processed: u64,
    pub threats_found: u64,
    pub current_file: String,
    pub files_per_second: f64, // Not directly used for display in the current message, but good to keep
    pub bytes_per_second: f64, // Not directly used for display in the current message, but good to keep
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
        
        // Clear screen and hide cursor for hacker-style display
        // This should always happen for the interactive UI experience
        term.clear_screen()?;
        term.hide_cursor()?;

        // Main progress bar with enhanced hacker styling - ALWAYS VISIBLE
        let main_style = ProgressStyle::with_template(
            "{prefix} {spinner:.cyan} {elapsed_precise:.yellow} [{wide_bar:.green/blue}] {pos}/{len} ({percent}%) {msg}"
        )?
        .progress_chars("█▓▒░")
        .tick_strings(&[
            "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"
        ]);

        // Progress bar is always added now, regardless of 'quiet'
        let main_progress = multi_progress.add(ProgressBar::new(total_files));
        main_progress.set_style(main_style);
        main_progress.set_prefix(style("⚡ SYSTEM_SCAN").green().bold().to_string());

        // File-level progress bar for detailed feedback - ALWAYS VISIBLE
        let file_style = ProgressStyle::with_template(
            "{prefix} {spinner:.purple} {msg:.dim}" // Purple spinner for a subtle contrast
        )?;

        // Progress bar is always added now, regardless of 'quiet'
        let file_progress = multi_progress.add(ProgressBar::new_spinner());
        file_progress.set_style(file_style);
        file_progress.set_prefix(style("📄 PROCESSING").cyan().bold().to_string());
        file_progress.enable_steady_tick(Duration::from_millis(80)); // Make spinner a bit faster

        Ok(Self {
            term,
            multi_progress,
            main_progress,
            file_progress,
            stats: Arc::new(Mutex::new(ScanStats::default())),
            start_time: Instant::now(),
            is_quiet: true, // Changed: Always set to true to make output quiet by default
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
                        // Calculate remaining files, ensuring no underflow
                        let remaining = total.saturating_sub(current); 
                        remaining as f64 / files_per_sec
                    } else {
                        0.0
                    };
                    
                    // Enhanced status message with more techy styling
                    let status_msg = format!(
                        "[{}] {}/s | [{}] {:.1}MB/s | [{}] {} Threats | ETA: {}",
                        style("FILES").green().bold(),
                        style(format!("{:.0}", files_per_sec)).cyan(),
                        style("DATA").yellow().bold(),
                        style(format!("{:.1}", mb_per_sec)).cyan(),
                        style("ALERT").red().bold(),
                        style(stats_guard.threats_found).red().bold(),
                        style(format!("{:.0}s", eta)).color256(165) // Changed to color256 for purple
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
                        style("Analyzing:").dim().italic(), // More subtle "Analyzing"
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
                    
                    // Only print threat alerts if not in quiet mode
                    if !self.is_quiet { 
                        // Enhanced threat alert for high risk
                        if risk_score >= 75 { // Changed threshold for "CRITICAL"
                            let alert = format!(
                                "🚨 {} [CRITICAL] {} in {} (Risk: {})",
                                style("!!! BREACH DETECTED !!!").red().bold().blink(), // Blinking effect
                                style(&threat_type).yellow().bold(),
                                style(&file).white().dim(),
                                style(risk_score).red().bold()
                            );
                            
                            // Print alert above progress bars, using eprintln for critical messages
                            eprintln!("\n{}\n", alert); // Add newlines for separation
                        } else if risk_score >= 50 { // High risk
                            let alert = format!(
                                "⚠️ {} [HIGH] {} in {} (Risk: {})",
                                style("WARNING").color256(208).bold(), // Changed to color256 for orange
                                style(&threat_type).yellow(),
                                style(&file).dim(),
                                style(risk_score).color256(208).bold() // Changed to color256 for orange
                            );
                            eprintln!("{}", alert);
                        } else if risk_score >= 25 { // Medium risk
                            let alert = format!(
                                "❕ {} [MEDIUM] {} in {} (Risk: {})",
                                style("NOTICE").yellow().bold(),
                                style(&threat_type).cyan(),
                                style(&file).dim(),
                                style(risk_score).yellow().bold()
                            );
                            eprintln!("{}", alert);
                        } else { // Low risk
                            let alert = format!(
                                "✔️ {} [LOW] {} in {} (Risk: {})",
                                style("INFO").green().bold(),
                                style(&threat_type).green(),
                                style(&file).dim(),
                                style(risk_score).green().bold()
                            );
                            eprintln!("{}", alert);
                        }
                    }
                },
                
                UIEvent::Progress(count) => {
                    main_progress.set_position(count);
                },
                
                UIEvent::Complete => {
                    log::debug!("UI: Scan complete");
                    main_progress.finish_with_message(
                        style("✅ SCAN COMPLETE. REPORT GENERATED.").green().bold().to_string()
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
        // Only print the summary if not in quiet mode
        if self.is_quiet { 
            return Ok(());
        }

        println!();
        // More elaborate and glowing ASCII art border for the summary
        println!("{}", style("╔═════════════════════════════════════════════════════════════════════╗").cyan());
        // Fixed concatenation for StyledObject
        println!("{}", style("║").cyan().bold().to_string() + &style("               SYSTEM ANALYSIS REPORT                ").green().bold().to_string() + &style("║").cyan().bold().to_string());
        println!("{}", style("╠═════════════════════════════════════════════════════════════════════╣").cyan());
        
        // Using format! for padding the string content before styling
        let files_processed_line_content = format!("   {} Files Processed: {}", 
            style("📁").blue(), 
            style(stats.files_processed).white().bold()
        );
        println!(" {} {} {}", 
            style("║").cyan().bold(),
            format!("{:<67}", files_processed_line_content), // Pad the string to 67 characters, left-aligned
            style("║").cyan().bold()
        );
        
        let data_analyzed_line_content = format!("   {} Data Analyzed: {:.2} MB", 
            style("💾").blue(), 
            style(stats.bytes_processed as f64 / (1024.0 * 1024.0)).white().bold()
        );
        println!(" {} {} {}", 
            style("║").cyan().bold(),
            format!("{:<67}", data_analyzed_line_content), // Pad the string to 67 characters, left-aligned
            style("║").cyan().bold()
        );
        
        let threats_detected_line_content = format!("   {} Threats Detected: {}", 
            style("🚨").red(), 
            style(stats.threats_found).red().bold()
        );
        println!(" {} {} {}", 
            style("║").cyan().bold(),
            format!("{:<67}", threats_detected_line_content), // Pad the string to 67 characters, left-aligned
            style("║").cyan().bold()
        );
        
        let total_duration_line_content = format!("   {} Total Duration: {:.2}s", 
            style("⏱️").blue(), 
            style(elapsed.as_secs_f64()).white().bold()
        );
        println!(" {} {} {}", 
            style("║").cyan().bold(),
            format!("{:<67}", total_duration_line_content), // Pad the string to 67 characters, left-aligned
            style("║").cyan().bold()
        );
        
        let files_per_sec = stats.files_processed as f64 / elapsed.as_secs_f64();
        let processing_speed_line_content = format!("   {} Processing Speed: {:.0} files/sec", 
            style("🚀").blue(), 
            style(files_per_sec).white().bold()
        );
        println!(" {} {} {}", 
            style("║").cyan().bold(),
            format!("{:<67}", processing_speed_line_content), // Pad the string to 67 characters, left-aligned
            style("║").cyan().bold()
        );

        println!("{}", style("╚═════════════════════════════════════════════════════════════════════╝").cyan());
        println!(); // Add an extra newline for spacing

        Ok(())
    }
}

impl Drop for HackerTerminalUI {
    fn drop(&mut self) {
        let _ = self.term.show_cursor();
        // Ensure multi_progress finishes its work and clears lines
        self.multi_progress.clear().unwrap_or_default(); 
    }
}
