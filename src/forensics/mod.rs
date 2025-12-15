//! Digital Forensics Module
//!
//! Provides capabilities for extracting forensic artifacts from various file formats.
//! Supported artifacts:
//! - Windows Event Logs (.evtx)
//! - Browser History (Chrome/Firefox SQLite)
//! - Windows Prefetch files (execution tracking)
//! - Partial File Carving

use std::path::Path;
use std::fs::File;
use std::io::Read;

// Conditional imports based on features (though we have them enabled in Cargo.toml)
use evtx::EvtxParser;
use rusqlite::{Connection, OpenFlags};

use crate::models::{ForensicAnalysis, EventLogEntry, BrowserHistoryEntry, PrefetchEntry, CarvedFile};

pub struct ForensicAnalyzer;

impl ForensicAnalyzer {
    /// Analyze a file for forensic artifacts based on extension/signature
    pub fn analyze(path: &Path) -> Option<ForensicAnalysis> {
        let mut analysis = ForensicAnalysis::default();
        let mut found_any = false;

        // Check for Event Logs (.evtx)
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let lext = ext.to_lowercase();
            if lext == "evtx" {
                if let Ok(logs) = Self::parse_evtx(path) {
                    analysis.event_logs = logs;
                    found_any = true;
                }
            } else if lext == "pf" {
                // Prefetch
                if let Ok(prefetch) = Self::parse_prefetch(path) {
                    analysis.prefetch_info.push(prefetch);
                    found_any = true;
                }
            } else if lext == "zip" || lext == "jar" || lext == "docx" {
                 let archive_ev = Self::analyze_archive(path);
                 if !archive_ev.is_empty() {
                     analysis.evidence.extend(archive_ev);
                     found_any = true;
                 }
            } else if lext == "pdf" {
                 let pdf_ev = Self::analyze_pdf(path);
                 if !pdf_ev.is_empty() {
                     analysis.evidence.extend(pdf_ev);
                     found_any = true;
                 }
            }
        }
        
        // Check for SQLite databases (common for browser history)
        // We verify header first
        if Self::is_sqlite(path) {
            if let Ok(history) = Self::parse_browser_history(path) {
                analysis.browser_history = history;
                if !analysis.browser_history.is_empty() {
                    found_any = true;
                }
            }
            // Cookies
            if let Ok(cookies) = Self::parse_cookies(path) {
                if !cookies.is_empty() {
                     analysis.evidence.push(crate::models::ForensicEvidence {
                        evidence_type: "Browser Cookies".to_string(),
                        description: format!("Found {} cookies (Sample: {})", cookies.len(), cookies.first().unwrap_or(&"".to_string())),
                        confidence: 100,
                        technical_details: std::collections::HashMap::new(),
                    });
                    found_any = true;
                }
            }
        }
        
        // Always try carving for embedded files if checks pass
        let carved = Self::attempt_carving(path);
        if !carved.is_empty() {
            analysis.recovered_files = carved;
            found_any = true;
        }

        if found_any {
            Some(analysis)
        } else {
            None
        }
    }

    fn is_sqlite(path: &Path) -> bool {
        let mut buffer = [0u8; 16];
        if let Ok(mut file) = File::open(path) {
            if file.read_exact(&mut buffer).is_ok() {
                return &buffer == b"SQLite format 3\0";
            }
        }
        false
    }

    /// Parse Windows Event Logs (.evtx)
    pub fn parse_evtx(path: &Path) -> Result<Vec<EventLogEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let mut entries = Vec::new();
        let mut parser = EvtxParser::from_path(path)?;

        for record in parser.records() {
            if let Ok(r) = record {
                 entries.push(EventLogEntry {
                    event_id: r.event_record_id.try_into().unwrap_or(0), 
                    timestamp: r.timestamp.to_string(),
                    level: "Unknown".to_string(),
                    channel: "Unknown".to_string(),
                    computer: "Unknown".to_string(),
                    sid: None,
                });
            }
        }
        
        Ok(entries)
    }

    /// Parse Browser History (SQLite)
    pub fn parse_browser_history(path: &Path) -> Result<Vec<BrowserHistoryEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let mut history = Vec::new();
        
        // Open in read-only mode, immutable
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        
        // Check for Chrome/Edge 'urls' table
        let mut stmt = conn.prepare("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100")?;
        
        let rows = stmt.query_map([], |row| {
            Ok(BrowserHistoryEntry {
                url: row.get(0)?,
                title: row.get(1)?,
                visit_count: row.get(2)?,
                last_visit: row.get::<_, i64>(3)?.to_string(), // Chrome time conversion needed normally
                browser: "Chrome/Edge".to_string(),
            })
        });

        if let Ok(itr) = rows {
            for entry in itr {
                if let Ok(e) = entry {
                    history.push(e);
                }
            }
        } else {
             // Fallback: Check Firefox 'moz_places' table
             let mut stmt_ff = conn.prepare("SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 100")?;
             let rows_ff = stmt_ff.query_map([], |row| {
                Ok(BrowserHistoryEntry {
                    url: row.get(0)?,
                    title: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    visit_count: row.get(2)?,
                    last_visit: row.get::<_, Option<i64>>(3)?.unwrap_or(0).to_string(),
                    browser: "Firefox".to_string(),
                })
            });
            
            if let Ok(itr) = rows_ff {
                for entry in itr {
                    if let Ok(e) = entry {
                        history.push(e);
                    }
                }
            }
        }

        Ok(history)
    }

    /// Parse Browser Cookies (SQLite)
    pub fn parse_cookies(path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let mut results = Vec::new();
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        
        // Chrome/Edge 'cookies'
        // host_key, name, value, path
        let stmt = conn.prepare("SELECT host_key, name, path FROM cookies LIMIT 50");
        if let Ok(mut query) = stmt {
             let rows = query.query_map([], |row| {
                 Ok(format!("{}{}", row.get::<_, String>(0)?, row.get::<_, String>(2)?))
             });
             if let Ok(itr) = rows {
                 for r in itr {
                     if let Ok(s) = r { results.push(s); }
                 }
                 return Ok(results); // Return if Chrome/Edge found
             }
        }

        // Firefox 'moz_cookies'
        // host, name, value, path
        let stmt_ff = conn.prepare("SELECT host, name, path FROM moz_cookies LIMIT 50");
        if let Ok(mut query) = stmt_ff {
             let rows = query.query_map([], |row| {
                 Ok(format!("{}{}", row.get::<_, String>(0)?, row.get::<_, String>(2)?))
             });
             if let Ok(itr) = rows {
                  for r in itr {
                     if let Ok(s) = r { results.push(s); }
                 }
             }
        }
        
        Ok(results)
    }

    /// Parse Windows Prefetch (binary format) - Stub
    pub fn parse_prefetch(path: &Path) -> Result<PrefetchEntry, Box<dyn std::error::Error + Send + Sync>> {
        // Needs a full SCCA parser. 
        // For now, we'll return a stub indicating detected prefetch file.
        Ok(PrefetchEntry {
            executable: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
            hash: "Not Implemented".to_string(),
            run_count: 0,
            last_run_time: "Unknown".to_string(),
        })
    }
    
    /// Attempt partial file carving / signature detection within a file
    pub fn attempt_carving(path: &Path) -> Vec<CarvedFile> {
        let mut carved = Vec::new();
        let mut buffer = Vec::new();
        
        // Read first 1MB only for performance
        if let Ok(file) = File::open(path) {
            if file.take(1_000_000).read_to_end(&mut buffer).is_ok() {
                // Check for embedded ZIP/Jar
                // PK\x03\x04
                if let Some(idx) = Self::find_subsequence(&buffer, b"\x50\x4b\x03\x04") {
                     // Check if it's at offset 0 (which means it IS a zip)
                     // vs embedded (offset > 0)
                     if idx > 0 {
                          carved.push(CarvedFile {
                              file_type: "Embedded ZIP/Archive".to_string(),
                              offset: idx as u64,
                              size: 0, // Unknown without full parse
                              recovered_path: None,
                          });
                     }
                }
                
                // Embedded PE (MZ)
                // Often false positives with just MZ, so we check stricter or just skip
                // because MZ is common. But let's look for embedded PE by "This program cannot be run" string maybe?
                
                // Embedded PDF
                // %PDF-
                if let Some(idx) = Self::find_subsequence(&buffer, b"%PDF-") {
                     if idx > 0 {
                          carved.push(CarvedFile {
                              file_type: "Embedded PDF".to_string(),
                              offset: idx as u64,
                              size: 0,
                              recovered_path: None,
                          });
                     }
                }
            }
        }
        carved
    }

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|window| window == needle)
    }

    /// Analyze Zip archives for anomalies (Zip Bombs)
    pub fn analyze_archive(path: &Path) -> Vec<crate::models::ForensicEvidence> {
        let mut evidence = Vec::new();
        let file = match File::open(path) { Ok(f) => f, Err(_) => return evidence };
        
        let mut archive = match zip::ZipArchive::new(file) { Ok(a) => a, Err(_) => return evidence };
        
        let mut total_size: u64 = 0;
        let mut compressed_size: u64 = 0;
        let mut file_count = 0;
        
        for i in 0..archive.len() {
            if let Ok(file) = archive.by_index(i) {
                total_size += file.size();
                compressed_size += file.compressed_size();
                file_count += 1;
            }
        }

        // 1. Zip Bomb Detection (Ratio)
        if compressed_size > 0 {
            let ratio = total_size as f64 / compressed_size as f64;
            if ratio > 100.0 && total_size > 100_000_000 { // Ratio > 100:1 AND expands to > 100MB
                 evidence.push(crate::models::ForensicEvidence {
                    evidence_type: "Archive Anomaly".to_string(),
                    description: format!("Potential Zip Bomb detected. Compression ratio {:.1}:1 (Expands to {} MB)", ratio, total_size / 1_000_000),
                    confidence: 90,
                    technical_details: {
                         let mut map = std::collections::HashMap::new();
                         map.insert("ratio".to_string(), ratio.to_string());
                         map.insert("file_count".to_string(), file_count.to_string());
                         map
                    },
                 });
            }
        }
        
        // 2. recursive file count
         if file_count > 10000 {
             evidence.push(crate::models::ForensicEvidence {
                evidence_type: "Archive Structure".to_string(),
                description: format!("Unusually high file count: {}", file_count),
                confidence: 60,
                technical_details: std::collections::HashMap::new(),
             });
         }

        evidence
    }

    /// Analyze PDF for JavaScript and High-Risk content
    pub fn analyze_pdf(path: &Path) -> Vec<crate::models::ForensicEvidence> {
        let mut evidence = Vec::new();
        // Just load document structure, don't render
        let doc = match lopdf::Document::load(path) { Ok(d) => d, Err(_) => return evidence };

        // Check for JS Actions / OpenAction
        // Walk objects
        let mut js_found = false;
        let mut aa_found = false; // Additional Actions
        let mut uri_found = false;

        for (_, object) in &doc.objects {
            match object {
                 lopdf::Object::Dictionary(dict) => {
                      if dict.has(b"JS") || dict.has(b"JavaScript") {
                          js_found = true;
                      }
                      if dict.has(b"AA") || dict.has(b"OpenAction") {
                          aa_found = true;
                      }
                      if dict.has(b"URI") {
                          uri_found = true;
                      }
                 }
                 _ => {}
            }
        }

        if js_found {
            evidence.push(crate::models::ForensicEvidence {
                evidence_type: "PDF Active Content".to_string(),
                description: "Embedded JavaScript detected in PDF".to_string(),
                confidence: 85,
                technical_details: std::collections::HashMap::new(),
            });
        }
        if aa_found {
             evidence.push(crate::models::ForensicEvidence {
                evidence_type: "PDF Suspicious Action".to_string(),
                description: "Auto-execution actions (OpenAction/AA) detected".to_string(),
                confidence: 75,
                technical_details: std::collections::HashMap::new(),
             });
        }
        if uri_found {
             evidence.push(crate::models::ForensicEvidence {
                evidence_type: "PDF External Link".to_string(),
                description: "External URI trigger detected".to_string(),
                confidence: 50,
                technical_details: std::collections::HashMap::new(),
             });
        }

        evidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_sqlite_detection() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.db");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"SQLite format 3\0").unwrap();
        
        assert!(ForensicAnalyzer::is_sqlite(&file_path));
    }
}
