use crate::models::{AssetMetadata};
use std::path::Path;
use std::fs::File;
// use std::io::Read;

#[derive(Default)]
pub struct MobileForensics;

impl MobileForensics {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze_apk(&self, path: &Path, metadata: &mut AssetMetadata) {
        if let Ok(file) = File::open(path) {
            if let Ok(mut archive) = zip::ZipArchive::new(file) {
                    let forensics = metadata.forensic_analysis.clone().unwrap_or_default();
                let mut findings = Vec::new();
                
                // Check for AndroidManifest.xml
                if archive.by_name("AndroidManifest.xml").is_ok() {
                    findings.push("Found AndroidManifest.xml".to_string());
                    // In a real scenario, we would parse the AXML here.
                    // For now, we flag it.
                }

                // Check for classes.dex
                if archive.by_name("classes.dex").is_ok() {
                    findings.push("Found classes.dex (Dalvik Executable)".to_string());
                }

                // Check for native libraries
                let mut has_native_libs = false;
                for i in 0..archive.len() {
                    if let Ok(file) = archive.by_index(i) {
                        if file.name().starts_with("lib/") && file.name().ends_with(".so") {
                            has_native_libs = true;
                        }
                    }
                }
                if has_native_libs {
                    findings.push("Contains Native Code (.so)".to_string());
                }

                // Store findings in strings for now (using threats or generic structure)
                // We'll repurpose 'event_logs' or create a new field if strict,
                // but for now let's add them as 'suspicious content' indicators via threat_indicators
                for f in findings {
                     metadata.threat_indicators.push(crate::models::ThreatIndicator {
                        indicator_type: "APK Structure".to_string(),
                        description: f,
                        value: "Info".to_string(),
                        confidence: 100,
                    });
                }
                
                // Update forensics
                metadata.forensic_analysis = Some(forensics);
            }
        }
    }

    pub fn analyze_ios_backup(&self, path: &Path, metadata: &mut AssetMetadata) {
        // iOS Backups often have Info.plist and Manifest.db
        // path points to the directory or the specific file
        
        let _path_buf = path.to_path_buf();
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        
        if filename == "Info.plist" {
            // Parse Plist
            if let Ok(file) = File::open(path) {
                // plist crate usage
                if let Ok(value) = plist::Value::from_reader(file) {
                    if let Some(dict) = value.as_dictionary() {
                        let mut forensics = metadata.forensic_analysis.clone().unwrap_or_default();
                        
                        // Extract interesting keys
                        if let Some(name) = dict.get("Device Name").and_then(|v| v.as_string()) {
                            forensics.system_logs.push(crate::models::SystemLogEntry {
                                timestamp: "N/A".to_string(),
                                service: "iOS Backup".to_string(),
                                message: format!("Device Name: {}", name),
                                severity: "Info".to_string(),
                            });
                        }
                        if let Some(ver) = dict.get("Product Version").and_then(|v| v.as_string()) {
                            forensics.system_logs.push(crate::models::SystemLogEntry {
                                timestamp: "N/A".to_string(),
                                service: "iOS Backup".to_string(),
                                message: format!("iOS Version: {}", ver),
                                severity: "Info".to_string(),
                            });
                        }
                        
                        metadata.forensic_analysis = Some(forensics);
                    }
                }
            }
        } else if filename == "Manifest.db" {
             metadata.threat_indicators.push(crate::models::ThreatIndicator {
                indicator_type: "iOS Artifact".to_string(),
                description: "Found iOS Backup Manifest Database".to_string(),
                value: "Info".to_string(),
                confidence: 100,
            });
            
            // ToDo: parsing SQLite with rusqlite
        }
    }
}
