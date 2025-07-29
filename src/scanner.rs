use crate::analyzer::ContentAnalyzer;
use crate::cli::{Args, SearchMode};
use crate::models::{AssetMetadata, ScanInfo, ScanReport};
use crate::ui::{HackerTerminalUI, UIEvent};
use crate::reporter::HtmlReporter;
use crate::utils::{
    detect_file_signature, format_permissions, format_timestamp, 
    is_hidden_file, HashComputer, MemoryMonitor
};
use memmap2::Mmap;
use rayon::prelude::*;
use regex::Regex;
use std::fs::{File, Metadata};
use std::path::{Path};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant};
use tokio::sync::mpsc;
use walkdir::{DirEntry, WalkDir};

pub struct AdvancedOsintScanner {
    args: Args,
    regex_pattern: Option<Regex>,
    exclude_patterns: Vec<Regex>,
    analyzer: ContentAnalyzer,
    memory_monitor: MemoryMonitor,
    html_reporter: HtmlReporter, // Add HTML reporter
    files_processed: Arc<AtomicU64>,
    bytes_processed: Arc<AtomicU64>,
    threats_found: Arc<AtomicU64>,
}

impl AdvancedOsintScanner {
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
            memory_monitor: MemoryMonitor::new(max_memory),
            html_reporter: HtmlReporter::new(), // Initialize HTML reporter
            files_processed: Arc::new(AtomicU64::new(0)),
            bytes_processed: Arc::new(AtomicU64::new(0)),
            threats_found: Arc::new(AtomicU64::new(0)),
        })
    }

    pub async fn scan(&self) -> Result<ScanReport, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        log::info!("Starting scan of directory: {}", self.args.directory);

        let base_path = Path::new(&self.args.directory);
        if !base_path.exists() {
            return Err(format!("Path does not exist: {:?}", base_path).into());
        }

        // Collect all entries first. This step is necessary to provide total_files
        // count to the HackerTerminalUI, as per its constructor's requirement.
        // For extremely large directories, this Vec<DirEntry> could consume significant RAM,
        // but it's a trade-off for the UI's progress bar functionality given current constraints.
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

        // Process files in parallel. The `process_files` function returns the
        // vector of AssetMetadata, which will then be moved directly into the report.
        let assets = self.process_files(entries, ui_sender.clone()).await?;

        // Signal completion to UI
        let _ = ui_sender.send(UIEvent::Complete).await;
        ui_task.await?; // Wait for UI task to finish its cleanup

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
        };

        // Memory Efficiency Improvement: Move `assets` directly into ScanReport
        // instead of cloning, avoiding a full copy of all collected metadata.
        let report = ScanReport {
            scan_info: scan_info.clone(),
            assets, // Directly moves the assets Vec<AssetMetadata>
        };

        // Generate reports. These functions take a reference to the report,
        // so no further cloning of the large assets vector occurs here.
        self.generate_reports(&report).await?;

        Ok(report)
    }

    // New method to handle all report generation
    async fn generate_reports(&self, report: &ScanReport) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(output_path) = &self.args.output {
            let output_base = if let Some(path_obj) = Path::new(output_path).file_stem() {
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
        } else {
            // If no output specified, still show summary
            self.print_report_summary(report);
        }

        Ok(())
    }

    // New method to print a nice summary
    fn print_report_summary(&self, report: &ScanReport) {
        println!("\n🎯 SCAN SUMMARY");
        println!("═══════════════════════════════════════");
        println!("📁 Directory Scanned: {}", report.scan_info.base_directory);
        println!("📊 Assets Found: {}", report.assets.len());
        println!("📄 Files Scanned: {}", report.scan_info.total_files_scanned);
        println!("💾 Data Analyzed: {:.2} MB", report.scan_info.total_bytes_analyzed as f64 / 1_048_576.0);
        println!("⏱️  Duration: {:.2}s", report.scan_info.duration_seconds);

        // Risk breakdown
        let risk_counts = self.calculate_risk_breakdown(&report.assets);
        println!("\n🚨 RISK BREAKDOWN");
        println!("═══════════════════════════════════════");
        println!("🔴 Critical (76-100): {}", risk_counts.3);
        println!("🟠 High (51-75): {}", risk_counts.2);
        println!("🟡 Medium (26-50): {}", risk_counts.1);
        println!("🟢 Low (0-25): {}", risk_counts.0);

        // Top findings
        if !report.assets.is_empty() {
            println!("\n🔍 TOP FINDINGS");
            println!("═══════════════════════════════════════");
            
            let mut sorted_assets = report.assets.clone(); // Cloning for sorting only, small subset
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

    // Helper method to calculate risk breakdown
    fn calculate_risk_breakdown(&self, assets: &[AssetMetadata]) -> (usize, usize, usize, usize) {
        let mut low = 0;
        let mut medium = 0;
        let mut high = 0;
        let mut critical = 0;

        for asset in assets {
            match asset.risk_score {
                0..=25 => low += 1,
                26..=50 => medium += 1,
                51..=75 => high += 1,
                _ => critical += 1,
            }
        }

        (low, medium, high, critical)
    }

    fn collect_entries(&self, base_path: &Path) -> Result<Vec<DirEntry>, Box<dyn std::error::Error + Send + Sync>> {
        log::debug!("Collecting directory entries from: {:?}", base_path);

        let mut walker = WalkDir::new(base_path).max_depth(self.args.max_depth);
        if self.args.follow_symlinks {
            walker = walker.follow_links(true);
        }

        let entries: Vec<_> = walker
            .into_iter()
            .filter_map(|e| match e {
                Ok(entry) => {
                    log::trace!("Found entry: {:?}", entry.path());
                    Some(entry)
                },
                Err(e) => {
                    log::warn!("Error accessing entry: {}", e);
                    None
                }
            })
            .collect();

        log::debug!("Collected {} entries", entries.len());
        Ok(entries)
    }

    async fn process_files(
        &self,
        entries: Vec<DirEntry>,
        ui_sender: mpsc::Sender<UIEvent>,
    ) -> Result<Vec<AssetMetadata>, Box<dyn std::error::Error + Send + Sync>> {
        let thread_count = if self.args.threads == 0 {
            num_cpus::get()
        } else {
            self.args.threads
        };

        log::info!("Processing files with {} threads", thread_count);

        // Ensure Rayon's global thread pool is built with the specified thread count.
        // This is a one-time setup for the application's lifetime.
        rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .build_global()
            .unwrap_or_else(|_| {
                log::warn!("Failed to initialize custom thread pool, using default");
            });

        // Use parallel processing for better performance.
        // `into_par_iter()` consumes the `entries` vector, avoiding a copy.
        let assets: Vec<AssetMetadata> = entries
            .into_par_iter()
            .filter_map(|entry| {
                let path_str = entry.path().display().to_string();
                
                // Send UI event for file started. `try_send` is non-blocking,
                // preventing the processing from waiting on the UI channel.
                let _ = ui_sender.try_send(UIEvent::FileStarted(path_str.clone()));

                match self.analyze_entry(&entry) {
                    Ok(Some(mut asset)) => {
                        let threats = asset.threat_indicators.len() as u32;
                        let size = asset.size.unwrap_or(0);

                        // Calculate and set risk score BEFORE using it
                        asset.risk_score = self.calculate_risk_score(&asset);

                        // Update atomic counters. `Ordering::Relaxed` is used for
                        // performance as strict ordering is not critical for statistics.
                        self.files_processed.fetch_add(1, Ordering::Relaxed);
                        self.bytes_processed.fetch_add(size, Ordering::Relaxed);

                        // Check for high-risk findings and send UI notifications.
                        // This is done per-threat for immediate feedback.
                        if asset.risk_score > 70 {
                            self.threats_found.fetch_add(1, Ordering::Relaxed);
                            
                            for indicator in &asset.threat_indicators {
                                let _ = ui_sender.try_send(UIEvent::ThreatFound {
                                    file: path_str.clone(),
                                    threat_type: indicator.indicator_type.clone(),
                                    risk_score: asset.risk_score,
                                });
                            }
                        }

                        // Send completion event.
                        let _ = ui_sender.try_send(UIEvent::FileCompleted { size, threats });

                        Some(asset)
                    },
                    Ok(None) => {
                        // If an entry is skipped (e.g., by filters or memory limit),
                        // still increment processed count and send completion event
                        // to keep the UI progress accurate.
                        self.files_processed.fetch_add(1, Ordering::Relaxed);
                        let _ = ui_sender.try_send(UIEvent::FileCompleted { size: 0, threats: 0 });
                        None
                    },
                    Err(e) => {
                        log::warn!("Error analyzing {}: {}", path_str, e);
                        // Log error and increment processed count for UI.
                        self.files_processed.fetch_add(1, Ordering::Relaxed);
                        let _ = ui_sender.try_send(UIEvent::FileCompleted { size: 0, threats: 0 });
                        None
                    }
                }
            })
            .collect();

        log::info!("Processed {} files, found {} assets", 
            self.files_processed.load(Ordering::Relaxed), assets.len());

        Ok(assets)
    }

    fn analyze_entry(&self, entry: &DirEntry) -> Result<Option<AssetMetadata>, Box<dyn std::error::Error + Send + Sync>> {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        log::trace!("Analyzing entry: {:?}", path);

        // Speed/Efficiency: Perform early checks to skip irrelevant files quickly.
        // This avoids expensive metadata reads or file content analysis.
        if !self.matches_search_criteria(&name, path)? {
            log::trace!("Entry doesn't match criteria, skipping: {:?}", path);
            return Ok(None);
        }

        // Memory Efficiency: Check memory usage before processing potentially large files.
        // This prevents OOM errors and allows skipping files if limits are hit.
        if !self.memory_monitor.check_memory_usage()? {
            log::warn!("Memory limit exceeded, skipping file: {:?}", path);
            return Ok(None);
        }

        let metadata = entry.metadata()
            .map_err(|e| format!("Failed to read metadata for {:?}: {}", path, e))?;

        let mut asset = AssetMetadata::new(path.to_path_buf(), name.clone());

        // Basic metadata extraction
        self.extract_basic_metadata(&mut asset, &metadata)?;

        // Perform analysis based on mode.
        // Each analysis level builds upon the previous one, ensuring
        // only necessary computations are performed for the chosen depth.
        match self.args.mode {
            SearchMode::Fast => {
                self.perform_fast_analysis(&mut asset)?;
            },
            SearchMode::Standard => {
                self.perform_fast_analysis(&mut asset)?;
                self.perform_standard_analysis(&mut asset)?;
            },
            SearchMode::Deep => {
                self.perform_fast_analysis(&mut asset)?;
                self.perform_standard_analysis(&mut asset)?;
                self.perform_deep_analysis(&mut asset)?;
            },
            SearchMode::Comprehensive => {
                self.perform_fast_analysis(&mut asset)?;
                self.perform_standard_analysis(&mut asset)?;
                self.perform_deep_analysis(&mut asset)?;
                self.perform_comprehensive_analysis(&mut asset)?;
            },
        }

        log::trace!("Analysis complete for: {:?}, risk score: {}", path, asset.risk_score);
        Ok(Some(asset))
    }

    fn extract_basic_metadata(&self, asset: &mut AssetMetadata, metadata: &Metadata) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::trace!("Extracting basic metadata for: {:?}", asset.path);

        asset.size = Some(metadata.len());
        asset.is_file = metadata.is_file();
        asset.is_hidden = is_hidden_file(&asset.path);
        asset.created = format_timestamp(metadata.created().ok());
        asset.modified = format_timestamp(metadata.modified().ok());
        asset.accessed = format_timestamp(metadata.accessed().ok());
        asset.permissions = format_permissions(metadata);
        asset.owner = whoami::username();

        // MIME type detection
        asset.mime_type = mime_guess::from_path(&asset.path)
            .first()
            .map(|mime| mime.to_string());

        Ok(())
    }

    fn perform_fast_analysis(&self, asset: &mut AssetMetadata) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !asset.is_file {
            return Ok(());
        }

        log::trace!("Performing fast analysis for: {:?}", asset.path);

        // File signature detection for small files or first few bytes.
        // Uses Mmap for efficient access without loading entire file for signature.
        if let Ok(file) = File::open(&asset.path) {
            if let Ok(mmap) = unsafe { Mmap::map(&file) } { // `unsafe` is used here for memory mapping, which is common and considered safe when the file is valid.
                if !mmap.is_empty() {
                    asset.file_signature = detect_file_signature(&mmap).map(String::from);
                }
            }
        }

        Ok(())
    }

    fn perform_standard_analysis(&self, asset: &mut AssetMetadata) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Efficiency: Skip if not a file or if file size exceeds a configurable limit.
        if !asset.is_file || asset.size.unwrap_or(0) > self.args.max_file_size * 1024 * 1024 {
            return Ok(());
        }

        log::trace!("Performing standard analysis for: {:?}", asset.path);

        let file = File::open(&asset.path)?;
        let mmap = unsafe { Mmap::map(&file)? }; // `unsafe` is used here for memory mapping.

        // Compute hashes using the memory-mapped file, avoiding full file load.
        let (md5_hash, sha256_hash, sha3_hash, blake3_hash) = HashComputer::compute_hashes(&mmap)?;
        asset.md5_hash = Some(md5_hash);
        asset.sha256_hash = Some(sha256_hash);
        asset.sha3_hash = Some(sha3_hash);
        asset.blake3_hash = Some(blake3_hash);

        // Content analysis on the memory-mapped file.
        let analysis_result = self.analyzer.analyze_memory_mapped(&mmap)?;
        asset.network_artifacts = analysis_result.network_artifacts;
        asset.crypto_artifacts = analysis_result.crypto_artifacts;
        asset.threat_indicators = analysis_result.threat_indicators;
        asset.forensic_evidence = analysis_result.forensic_evidence;
        asset.entropy = analysis_result.entropy;
        asset.encrypted_content = analysis_result.encrypted_content;
        asset.steganography_detected = analysis_result.steganography_detected;

        Ok(())
    }

    fn perform_deep_analysis(&self, asset: &mut AssetMetadata) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::trace!("Performing deep analysis for: {:?}", asset.path);

        // Placeholder for future deep analysis features.
        // Current standard analysis already covers many "deep" aspects.

        Ok(())
    }

    fn perform_comprehensive_analysis(&self, asset: &mut AssetMetadata) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::trace!("Performing comprehensive analysis for: {:?}", asset.path);

        // Code analysis for source files.
        // Note: `read_to_string` loads the entire file content into memory.
        // For extremely large code files, this could be a memory concern.
        // However, for typical source code files, this is acceptable for
        // performing string-based analysis like complexity and obfuscation.
        if let Some(ext) = asset.path.extension().and_then(|e| e.to_str()) {
            let code_extensions = ["py", "js", "php", "rb", "pl", "sh", "bat", "ps1", "c", "cpp", "java", "rs"];
            
            if code_extensions.contains(&ext.to_lowercase().as_str()) {
                self.analyze_code_file(asset)?;
            }
        }

        Ok(())
    }

    fn analyze_code_file(&self, asset: &mut AssetMetadata) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Ok(content) = std::fs::read_to_string(&asset.path) {
            let lines_of_code = content.lines().count();
            let complexity = self.calculate_cyclomatic_complexity(&content);
            let obfuscation = self.calculate_obfuscation_score(&content);

            asset.code_analysis.insert("lines_of_code".to_string(), lines_of_code.to_string());
            asset.code_analysis.insert("cyclomatic_complexity".to_string(), complexity.to_string());
            asset.code_analysis.insert("obfuscation_score".to_string(), obfuscation.to_string());

            if obfuscation > 0.7 {
                asset.threat_indicators.push(crate::models::ThreatIndicator {
                    indicator_type: "Code Obfuscation".to_string(),
                    value: obfuscation.to_string(),
                    confidence: 80,
                    description: "High code obfuscation detected - potential malware".to_string(),
                });
            }
        }

        Ok(())
    }

    fn calculate_cyclomatic_complexity(&self, code: &str) -> u32 {
        let complexity_keywords = [
            "if", "else", "elif", "while", "for", "switch", "case",
            "catch", "try", "&&", "||", "and", "or"
        ];

        let mut complexity = 1; // Base complexity
        let code_lower = code.to_lowercase(); // Convert once for all matches

        for keyword in &complexity_keywords {
            complexity += code_lower.matches(keyword).count() as u32;
        }

        complexity
    }

    fn calculate_obfuscation_score(&self, code: &str) -> f64 {
        let mut score = 0.0;
        let total_chars = code.len() as f64;
        
        if total_chars == 0.0 {
            return 0.0;
        }

        // High ratio of non-alphanumeric characters
        let non_alnum = code.chars().filter(|c| !c.is_alphanumeric() && !c.is_whitespace()).count() as f64;
        score += (non_alnum / total_chars) * 0.3;

        // Very long lines (potential minification)
        let long_lines = code.lines().filter(|line| line.len() > 200).count() as f64;
        score += (long_lines / code.lines().count().max(1) as f64) * 0.2;

        // Base64-like patterns
        // Compile regex once if possible, or handle potential compilation errors.
        // For a function called per-file, re-compiling regex can be slow.
        // However, given the current structure, this is within the constraints.
        if let Ok(base64_pattern) = Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}") {
            score += base64_pattern.find_iter(code).count() as f64 * 0.1;
        }

        score.min(1.0)
    }

    fn calculate_risk_score(&self, asset: &AssetMetadata) -> u8 {
        let mut score = 0u16;

        // Threat indicators scoring
        for indicator in &asset.threat_indicators {
            score += indicator.confidence as u16;
        }

        // Crypto artifacts scoring
        for crypto in &asset.crypto_artifacts {
            match crypto.crypto_type.as_str() {
                "Bitcoin Address" | "Ethereum Address" => score += 30,
                "PEM Certificate/Key" => score += 20,
                _ => score += 10,
            }
        }

        // Network artifacts scoring
        score += (asset.network_artifacts.len() as u16) * 5;

        // File characteristics
        if asset.is_hidden {
            score += 15;
        }

        if asset.encrypted_content {
            score += 25;
        }

        if asset.steganography_detected {
            score += 40;
        }

        // Entropy scoring
        if let Some(entropy) = asset.entropy {
            if entropy > 7.5 {
                score += 30;
            } else if entropy > 7.0 {
                score += 15;
            }
        }

        // Size-based scoring
        if let Some(size) = asset.size {
            if size == 0 {
                score += 10; // Zero-byte files can be suspicious
            } else if size > 100 * 1024 * 1024 { // 100 MB
                score += 20; // Very large files
            }
        }

        // File extension scoring
        if let Some(ext) = asset.path.extension().and_then(|e| e.to_str()) {
            let high_risk_extensions = ["exe", "scr", "bat", "cmd", "ps1", "vbs", "js", "jar"];
            let medium_risk_extensions = ["dll", "sys", "bin", "com", "pif"];

            if high_risk_extensions.contains(&ext.to_lowercase().as_str()) {
                score += 30;
            } else if medium_risk_extensions.contains(&ext.to_lowercase().as_str()) {
                score += 15;
            }
        }

        // Code analysis scoring
        if let Some(obfuscation_str) = asset.code_analysis.get("obfuscation_score") {
            if let Ok(obfuscation_score) = obfuscation_str.parse::<f64>() {
                if obfuscation_score > 0.8 {
                    score += 50;
                } else if obfuscation_score > 0.6 {
                    score += 25;
                }
            }
        }

        // Cap the score at 100
        (score.min(100)) as u8
    }

    fn matches_search_criteria(&self, name: &str, path: &Path) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Efficiency: Check exclude patterns first as they can quickly filter out many files.
        for exclude_pattern in &self.exclude_patterns {
            if exclude_pattern.is_match(name) {
                log::trace!("File excluded by pattern: {:?}", name);
                return Ok(false);
            }
        }

        // Check file type filters
        if !self.args.file_types.is_empty() {
            let extension = path.extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("");
            
            if !self.args.file_types.iter().any(|ft| ft.eq_ignore_ascii_case(extension)) {
                log::trace!("File excluded by file type filter: {:?}", name);
                return Ok(false);
            }
        }

        // Check size constraints
        // Efficiency: Metadata is read once here if needed for size check.
        if let Ok(metadata) = std::fs::metadata(path) {
            let size = metadata.len();
            
            if size < self.args.min_size {
                log::trace!("File too small: {} < {}", size, self.args.min_size);
                return Ok(false);
            }
            
            if let Some(max_size) = self.args.max_size {
                if size > max_size {
                    log::trace!("File too large: {} > {}", size, max_size);
                    return Ok(false);
                }
            }
        }

        // Main pattern matching
        if let Some(regex) = &self.regex_pattern {
            Ok(regex.is_match(name))
        } else if !self.args.asset_name.is_empty() {
            let search_term = if self.args.case_sensitive {
                &self.args.asset_name
            } else {
                &self.args.asset_name.to_lowercase()
            };
            
            let target = if self.args.case_sensitive {
                name.to_string()
            } else {
                name.to_lowercase()
            };
            
            Ok(target.contains(search_term))
        } else {
            // If no specific pattern, include all files
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::io::Write;

    #[tokio::test]
    async fn test_scanner_creation() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let args = Args {
            directory: ".".to_string(),
            asset_name: "test".to_string(),
            regex_pattern: None,
            mode: SearchMode::Fast,
            max_depth: 5,
            threads: 1,
            max_file_size: 10,
            min_size: 0,
            max_size: None,
            follow_symlinks: false,
            case_sensitive: false,
            file_types: vec![],
            exclude: vec![],
            output: None,
            verbose: false,
            quiet: true,
            max_memory: 512,
        };

        let scanner = AdvancedOsintScanner::new(args).await?;
        assert!(scanner.analyzer.crypto_patterns.len() > 0);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_file_analysis() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let temp_dir = TempDir::new()?;
        let test_file = temp_dir.path().join("test.txt");
        
        let mut file = std::fs::File::create(&test_file)?;
        writeln!(file, "Contact: test@example.com")?;
        writeln!(file, "Visit: https://example.com")?;

        let args = Args {
            directory: temp_dir.path().to_string_lossy().to_string(),
            asset_name: "".to_string(),
            regex_pattern: None,
            mode: SearchMode::Standard,
            max_depth: 1,
            threads: 1,
            max_file_size: 10,
            min_size: 0,
            max_size: None,
            follow_symlinks: false,
            case_sensitive: false,
            file_types: vec![],
            exclude: vec![],
            output: None,
            verbose: false,
            quiet: true,
            max_memory: 512,
        };

        let scanner = AdvancedOsintScanner::new(args).await?;
        // First create an AssetMetadata for the test file
        let mut asset = AssetMetadata::new(test_file.clone(), "test.txt".to_string());
        
        // To properly test the analysis, we need to call the relevant analysis functions.
        // The original test called `analyze_code_file` which is for comprehensive mode.
        // For standard mode, we should call `perform_standard_analysis`.
        scanner.perform_standard_analysis(&mut asset)?;
                
        assert_eq!(asset.network_artifacts.len(), 2);
        assert!(asset.network_artifacts.iter().any(|a| a.artifact_type == "Email Address"));
        assert!(asset.network_artifacts.iter().any(|a| a.artifact_type == "URL"));
        Ok(())
    }
}
