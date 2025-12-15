//! Scanner Module - Core scanning functionality
//!
//! This module contains the main `AdvancedOsintScanner` struct and its implementation.
//! Split into submodules for maintainability:
//! - `entry`: Entry processing and file traversal
//! - `analysis`: Analysis levels (fast, standard, deep, comprehensive)
//! - `risk`: Risk scoring and calculation

mod entry;
mod analysis;
mod risk;

use crate::analyzer::ContentAnalyzer;
use crate::cli::Args;
use crate::models::{ScanInfo, ScanReport};
use crate::secrets::SecretScanner;
use crate::threat_intel::ThreatIntelEngine;
use crate::yara::YaraEngine;
use crate::ui::{HackerTerminalUI, UIEvent};
use crate::reporter::HtmlReporter;
use crate::utils::MemoryMonitor;
use regex::Regex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

/// Main scanner struct for OSINT file analysis
pub struct AdvancedOsintScanner {
    pub(crate) args: Args,
    pub(crate) regex_pattern: Option<Regex>,
    pub(crate) exclude_patterns: Vec<Regex>,
    pub(crate) analyzer: ContentAnalyzer,
    pub(crate) secret_scanner: SecretScanner,
    pub(crate) yara_engine: YaraEngine,
    pub(crate) memory_monitor: MemoryMonitor,
    pub(crate) html_reporter: HtmlReporter,
    pub(crate) files_processed: Arc<AtomicU64>,
    pub(crate) bytes_processed: Arc<AtomicU64>,
    pub(crate) threats_found: Arc<AtomicU64>,
    pub(crate) threat_intel: ThreatIntelEngine,
    pub(crate) cloud_analyzer: crate::cloud::CloudAnalyzer,
    pub(crate) windows_forensics: crate::windows_forensics::WindowsForensics,
    pub(crate) linux_forensics: crate::linux_forensics::LinuxForensics,
}

impl AdvancedOsintScanner {
    /// Create a new scanner instance with the given arguments
    pub async fn new(args: Args) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        log::info!("Initializing OSINT scanner with mode: {}", args.mode);

        let regex_pattern = if let Some(pattern) = &args.regex_pattern {
            log::debug!("Compiling regex pattern: {}", pattern);
            Some(Regex::new(pattern)?)
        } else {
            None
        };

        let exclude_patterns: Result<Vec<Regex>, _> = args.exclude
            .iter()
            .map(|p| {
                log::debug!("Compiling exclude pattern: {}", p);
                Regex::new(p)
            })
            .collect();

        let exclude_patterns = exclude_patterns
            .map_err(|e| format!("Failed to compile exclude patterns: {}", e))?;

        log::info!("Scanner initialization complete");

        let max_memory = args.max_memory;

        Ok(Self {
            args,
            regex_pattern,
            exclude_patterns,
            analyzer: ContentAnalyzer::new(),
            secret_scanner: SecretScanner::new(),
            yara_engine: YaraEngine::new(),
            memory_monitor: MemoryMonitor::new(max_memory),
            html_reporter: HtmlReporter::new(),
            files_processed: Arc::new(AtomicU64::new(0)),
            bytes_processed: Arc::new(AtomicU64::new(0)),
            threats_found: Arc::new(AtomicU64::new(0)),
            threat_intel: ThreatIntelEngine::new(),
            cloud_analyzer: crate::cloud::CloudAnalyzer::new(),
            windows_forensics: crate::windows_forensics::WindowsForensics::new(),
            linux_forensics: crate::linux_forensics::LinuxForensics::new(),
        })
    }

    /// Main scanning entry point
    pub async fn scan(&self) -> Result<ScanReport, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        log::info!("Starting scan of directory: {}", self.args.directory);

        let base_path = std::path::Path::new(&self.args.directory);
        if !base_path.exists() {
            return Err(format!("Path does not exist: {:?}", base_path).into());
        }

        // Collect all entries first
        let entries = self.collect_entries(base_path)?;
        let total_entries = entries.len();
        log::info!("Discovered {} files for analysis", total_entries);

        // Initialize UI
        let ui = HackerTerminalUI::new(total_entries as u64)?;
        let (ui_sender, ui_receiver) = mpsc::channel(1000);
        
        // Start UI task
        let ui_task = {
            let ui_clone = ui;
            tokio::spawn(async move {
                if let Err(e) = ui_clone.run(ui_receiver).await {
                    log::error!("UI task error: {}", e);
                }
            })
        };

        // Process files in parallel
        let assets = self.process_files(entries, ui_sender.clone()).await?;

        // Signal completion to UI
        let _ = ui_sender.send(UIEvent::Complete).await;
        ui_task.await?;

        let end_time = Instant::now();
        let duration = end_time - start_time;

        log::info!("Scan completed in {:.2}s", duration.as_secs_f64());

        let scan_info = ScanInfo {
            start_time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            end_time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            duration_seconds: duration.as_secs_f64(),
            base_directory: self.args.directory.clone(),
            search_pattern: self.args.asset_name.clone(),
            mode: self.args.mode.to_string(),
            total_files_scanned: self.files_processed.load(Ordering::Relaxed),
            total_bytes_analyzed: self.bytes_processed.load(Ordering::Relaxed),
            scan_timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        };

        let report = ScanReport {
            scan_info: scan_info.clone(),
            assets,
        };

        // Generate reports
        self.generate_reports(&report).await?;

        Ok(report)
    }

    /// Generate all reports (JSON, HTML, SQLite)
    async fn generate_reports(&self, report: &ScanReport) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(output_path) = &self.args.output {
            let output_base = if let Some(path_obj) = std::path::Path::new(output_path).file_stem() {
                path_obj.to_string_lossy().to_string()
            } else {
                "osint_scan".to_string()
            };

            // Generate JSON report
            log::info!("Writing JSON results to: {:?}", output_path);
            let json = serde_json::to_string_pretty(&report)?;
            std::fs::write(output_path, json)?;

            // Generate HTML report
            log::info!("Generating HTML report...");
            if let Err(e) = self.html_reporter.generate_report(report, &output_base) {
                log::error!("Failed to generate HTML report: {}", e);
            } else {
                log::info!("✅ Reports generated successfully!");
                self.print_report_summary(report);
            }

            // Generate SQLite DB
            let db_path = output_path.with_extension("db");
            log::info!("Exporting Evidence Database to: {:?}", db_path);
            if let Err(e) = crate::exporter::SqliteExporter::export(report, &db_path) {
                log::error!("Failed to export SQLite DB: {}", e);
            } else {
                log::info!("✅ Evidence database exported successfully!");
            }
        } else {
            self.print_report_summary(report);
        }

        Ok(())
    }

    /// Print a summary of scan results
    fn print_report_summary(&self, report: &ScanReport) {
        println!("\n🎯 SCAN SUMMARY");
        println!("═══════════════════════════════════════");
        println!("📁 Directory Scanned: {}", report.scan_info.base_directory);
        println!("📊 Assets Found: {}", report.assets.len());
        println!("📄 Files Scanned: {}", report.scan_info.total_files_scanned);
        println!("💾 Data Analyzed: {:.2} MB", report.scan_info.total_bytes_analyzed as f64 / 1_048_576.0);
        println!("⏱️  Duration: {:.2}s", report.scan_info.duration_seconds);

        let risk_counts = risk::calculate_risk_breakdown(&report.assets);
        println!("\n🚨 RISK BREAKDOWN");
        println!("═══════════════════════════════════════");
        println!("🔴 Critical (76-100): {}", risk_counts.3);
        println!("🟠 High (51-75): {}", risk_counts.2);
        println!("🟡 Medium (26-50): {}", risk_counts.1);
        println!("🟢 Low (0-25): {}", risk_counts.0);

        if !report.assets.is_empty() {
            println!("\n🔍 TOP FINDINGS");
            println!("═══════════════════════════════════════");
            
            let mut sorted_assets = report.assets.clone();
            sorted_assets.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));
            
            for (i, asset) in sorted_assets.iter().take(5).enumerate() {
                let risk_emoji = match asset.risk_score {
                    0..=25 => "🟢",
                    26..=50 => "🟡",
                    51..=75 => "🟠",
                    _ => "🔴",
                };
                
                println!("{}. {} {} (Risk: {})", 
                    i + 1, 
                    risk_emoji,
                    asset.path.file_name().unwrap_or_default().to_string_lossy(),
                    asset.risk_score
                );
            }
        }

        if self.args.output.is_some() {
            println!("\n📄 Reports available in current directory!");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::SearchMode;
    use tempfile::TempDir;
    use std::io::Write;

    fn make_test_args(directory: String, mode: SearchMode) -> Args {
        Args {
            directory,
            asset_name: String::new(),
            regex_pattern: None,
            mode,
            max_depth: 10,
            threads: 0,
            max_file_size: 100,
            min_size: 0,
            max_size: None,
            follow_symlinks: false,
            case_sensitive: false,
            file_types: vec![],
            exclude: vec![],
            output: None,
            verbose: false,
            quiet: false,
            max_memory: 1024,
            watch: false,
        }
    }

    #[tokio::test]
    async fn test_scanner_creation() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let temp_dir = TempDir::new()?;
        let args = make_test_args(temp_dir.path().to_string_lossy().to_string(), SearchMode::Fast);

        let scanner = AdvancedOsintScanner::new(args).await?;
        assert!(scanner.secret_scanner.pattern_count() > 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_file_analysis() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let temp_dir = TempDir::new()?;
        let test_file = temp_dir.path().join("test.txt");
        
        {
            let mut file = std::fs::File::create(&test_file)?;
            writeln!(file, "This is a test file with some content.")?;
            writeln!(file, "It contains no secrets or threats.")?;
        }

        let args = make_test_args(temp_dir.path().to_string_lossy().to_string(), SearchMode::Standard);

        let scanner = AdvancedOsintScanner::new(args).await?;
        let result = scanner.analyze_target(&test_file)?;
        
        assert!(result.is_some());
        let asset = result.unwrap();
        assert!(asset.risk_score < 50);
        
        Ok(())
    }
}

