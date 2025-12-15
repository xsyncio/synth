//! Entry Processing Module
//!
//! Handles file traversal, entry matching, and file processing pipelines.

use crate::cli::SearchMode;
use crate::models::AssetMetadata;
use crate::ui::UIEvent;
use rayon::prelude::*;
use std::path::Path;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;
use walkdir::{DirEntry, WalkDir};

use super::AdvancedOsintScanner;

impl AdvancedOsintScanner {
    /// Collect all directory entries for scanning
    pub(crate) fn collect_entries(&self, base_path: &Path) -> Result<Vec<DirEntry>, Box<dyn std::error::Error + Send + Sync>> {
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

    /// Process files in parallel using Rayon
    pub(crate) async fn process_files(
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

        rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .build_global()
            .unwrap_or_else(|_| {
                log::warn!("Failed to initialize custom thread pool, using default");
            });

        let assets: Vec<AssetMetadata> = entries
            .into_par_iter()
            .filter_map(|entry| {
                let path_str = entry.path().display().to_string();
                
                let _ = ui_sender.try_send(UIEvent::FileStarted(path_str.clone()));

                match self.analyze_entry(&entry) {
                    Ok(Some(mut asset)) => {
                        let threats = asset.threat_indicators.len() as u32;
                        let size = asset.size.unwrap_or(0);

                        asset.risk_score = super::risk::calculate_risk_score(self, &asset);

                        self.files_processed.fetch_add(1, Ordering::Relaxed);
                        self.bytes_processed.fetch_add(size, Ordering::Relaxed);

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

                        let _ = ui_sender.try_send(UIEvent::FileCompleted { size, threats });
                        Some(asset)
                    },
                    Ok(None) => {
                        self.files_processed.fetch_add(1, Ordering::Relaxed);
                        let _ = ui_sender.try_send(UIEvent::FileCompleted { size: 0, threats: 0 });
                        None
                    },
                    Err(e) => {
                        log::warn!("Error analyzing {}: {}", path_str, e);
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

    /// Analyze a specific target path (used by Watch Mode)
    pub fn analyze_target(&self, path: &Path) -> Result<Option<AssetMetadata>, Box<dyn std::error::Error + Send + Sync>> {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();

        log::debug!("Analyzing single target: {:?}", path);

        if !self.matches_search_criteria(&name, path)? {
            return Ok(None);
        }

        if !self.memory_monitor.check_memory_usage()? {
            log::warn!("Memory limit exceeded, skipping: {:?}", path);
            return Ok(None);
        }

        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                log::warn!("Failed to read metadata for {:?}: {}", path, e);
                return Ok(None);
            }
        };

        let mut asset = AssetMetadata::new(path.to_path_buf(), name);
        self.extract_basic_metadata(&mut asset, &metadata)?;

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

        // Cloud & Infrastructure Analysis
        self.cloud_analyzer.analyze(path, &mut asset);

        // Windows Forensics
        self.windows_forensics.analyze(path, &mut asset);
        
        // Mobile Forensics
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ext.eq_ignore_ascii_case("apk") {
                let mobile = crate::mobile::MobileForensics::new();
                mobile.analyze_apk(path, &mut asset);
            }
        }

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name == "Info.plist" || name == "Manifest.db" {
                let mobile = crate::mobile::MobileForensics::new();
                mobile.analyze_ios_backup(path, &mut asset);
            }
        }
        
        // Chat Forensics
        if self.args.mode != SearchMode::Fast {
            crate::chat::ChatAnalyzer::new().analyze(path, &mut asset);
        }

        // Linux Forensics
        self.linux_forensics.analyze(path, &mut asset);

        let calculated_score = self.threat_intel.calculate_risk_score(&asset);
        asset.risk_score = std::cmp::max(asset.risk_score, calculated_score);
        
        log::info!("Analysis complete for: {:?}, risk score: {}", path, asset.risk_score);
        
        Ok(Some(asset))
    }

    /// Analyze a directory entry
    pub(crate) fn analyze_entry(&self, entry: &DirEntry) -> Result<Option<AssetMetadata>, Box<dyn std::error::Error + Send + Sync>> {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        log::trace!("Analyzing entry: {:?}", path);

        if !self.matches_search_criteria(&name, path)? {
            log::trace!("Entry doesn't match criteria, skipping: {:?}", path);
            return Ok(None);
        }

        if !self.memory_monitor.check_memory_usage()? {
            log::warn!("Memory limit exceeded, skipping file: {:?}", path);
            return Ok(None);
        }

        let metadata = entry.metadata()
            .map_err(|e| format!("Failed to read metadata for {:?}: {}", path, e))?;

        let mut asset = AssetMetadata::new(path.to_path_buf(), name.clone());

        self.extract_basic_metadata(&mut asset, &metadata)?;

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

        asset.risk_score = self.threat_intel.calculate_risk_score(&asset);

        log::trace!("Analysis complete for: {:?}, risk score: {}", path, asset.risk_score);
        Ok(Some(asset))
    }

    /// Check if a file matches the search criteria
    pub(crate) fn matches_search_criteria(&self, name: &str, path: &Path) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Check exclude patterns first
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
            Ok(true)
        }
    }
}
