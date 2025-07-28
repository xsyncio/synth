use crate::models::{CryptoArtifact, ForensicEvidence, NetworkArtifact, ThreatIndicator};
use crate::utils::{calculate_entropy, is_likely_text, StreamingTextReader};
use bytes::Bytes;
use memmap2::Mmap;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs::File;
#[allow(dead_code)]
pub struct ContentAnalyzer {
    pub(crate) crypto_patterns: Vec<(Regex, String)>,
    pub(crate) network_patterns: Vec<(Regex, String)>,
    pub(crate) threat_patterns: Vec<(Regex, String, u8)>,
    pub(crate) malware_hashes: HashSet<String>,
    pub(crate) suspicious_domains: HashSet<String>,
}


impl ContentAnalyzer {
    pub fn new() -> Self {
        Self {
            crypto_patterns: Self::compile_crypto_patterns(),
            network_patterns: Self::compile_network_patterns(),
            threat_patterns: Self::compile_threat_patterns(),
            malware_hashes: Self::load_malware_hashes(),
            suspicious_domains: Self::load_suspicious_domains(),
        }
    }

    pub fn analyze_content_streaming(
        &self, 
        file: File, 
        max_size: u64
    ) -> Result<AnalysisResult, Box<dyn std::error::Error + Send + Sync>> {
        let mut result = AnalysisResult::default();
        
        // Use streaming reader for large files
        const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
        let mut reader = StreamingTextReader::new(file, CHUNK_SIZE);
        let mut total_processed = 0u64;
        
        while let Some(chunk) = reader.read_chunk()? {
            if total_processed + chunk.len() as u64 > max_size {
                log::debug!("File size limit reached, truncating analysis");
                break;
            }
            
            // Only analyze text-like content for patterns
            if is_likely_text(&chunk) {
                self.analyze_chunk(&chunk, &mut result)?;
            }
            
            total_processed += chunk.len() as u64;
        }
        
        Ok(result)
    }

    pub fn analyze_memory_mapped(
        &self, 
        mmap: &Mmap
    ) -> Result<AnalysisResult, Box<dyn std::error::Error + Send + Sync>> {
        let mut result = AnalysisResult::default();
        
        // Calculate entropy for the entire file
        result.entropy = Some(calculate_entropy(mmap));
        
        // Detect encryption based on high entropy
        if result.entropy.unwrap_or(0.0) > 7.8 {
            result.encrypted_content = true;
            result.forensic_evidence.push(ForensicEvidence {
                evidence_type: "High Entropy".to_string(),
                description: "File shows characteristics of encrypted or compressed data".to_string(),
                confidence: 85,
                technical_details: HashMap::new(),
            });
        }
        
        // Process in chunks for memory efficiency
        const CHUNK_SIZE: usize = 64 * 1024;
        for chunk in mmap.chunks(CHUNK_SIZE) {
            if is_likely_text(chunk) {
                let chunk_bytes = Bytes::copy_from_slice(chunk);
                self.analyze_chunk(&chunk_bytes, &mut result)?;
            }
        }
        
        // Detect steganography in image files
        if mmap.len() > 1000 {
            result.steganography_detected = self.detect_steganography(mmap);
        }
        
        Ok(result)
    }

    fn analyze_chunk(
        &self, 
        chunk: &Bytes, 
        result: &mut AnalysisResult
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = String::from_utf8_lossy(chunk);
        
        // Network artifact extraction
        for (pattern, description) in &self.network_patterns {
            for mat in pattern.find_iter(&content) {
                let artifact = NetworkArtifact {
                    artifact_type: description.clone(),
                    value: mat.as_str().to_string(),
                    context: Self::extract_context(&content, mat.start(), mat.end()),
                    confidence: Self::calculate_confidence(mat.as_str(), description),
                };
                
                // Check against threat intelligence
                if description == "Domain/Hostname" && 
                   self.suspicious_domains.contains(mat.as_str()) {
                    result.threat_indicators.push(ThreatIndicator {
                        indicator_type: "Malicious Domain".to_string(),
                        value: mat.as_str().to_string(),
                        confidence: 95,
                        description: "Domain found in threat intelligence feeds".to_string(),
                    });
                }
                
                result.network_artifacts.push(artifact);
            }
        }
        
        // Crypto artifact extraction
        for (pattern, description) in &self.crypto_patterns {
            for mat in pattern.find_iter(&content) {
                let artifact = CryptoArtifact {
                    crypto_type: description.clone(),
                    value: mat.as_str().to_string(),
                    algorithm: Self::detect_crypto_algorithm(mat.as_str()),
                    strength: Self::assess_crypto_strength(mat.as_str()),
                    context: Self::extract_context(&content, mat.start(), mat.end()),
                };
                result.crypto_artifacts.push(artifact);
            }
        }
        
        // Threat pattern detection
        for (pattern, description, confidence) in &self.threat_patterns {
            for mat in pattern.find_iter(&content) {
                let indicator = ThreatIndicator {
                    indicator_type: description.clone(),
                    value: mat.as_str().to_string(),
                    confidence: *confidence,
                    description: format!("Potential {} detected in file content", description),
                };
                result.threat_indicators.push(indicator);
            }
        }
        
        Ok(())
    }

    fn detect_steganography(&self, data: &[u8]) -> bool {
        if data.len() < 1000 {
            return false;
        }

        // Check for unusual patterns in LSBs for first 1000 bytes
        let mut lsb_frequency = [0u32; 2];
        for &byte in data.iter().take(1000) {
            lsb_frequency[(byte & 1) as usize] += 1;
        }

        // Calculate entropy of LSBs
        let mut lsb_entropy = 0.0;
        for &freq in &lsb_frequency {
            if freq > 0 {
                let prob = freq as f64 / 1000.0;
                lsb_entropy -= prob * prob.log2();
            }
        }

        // High LSB entropy might indicate steganography
        lsb_entropy > 0.95
    }

    fn extract_context(content: &str, start: usize, end: usize) -> String {
        let context_size = 30;
        let context_start = start.saturating_sub(context_size);
        let context_end = (end + context_size).min(content.len());
        
        content.chars()
            .skip(context_start)
            .take(context_end - context_start)
            .collect::<String>()
            .replace('\n', " ")
            .replace('\r', " ")
    }

    fn calculate_confidence(value: &str, artifact_type: &str) -> u8 {
        match artifact_type {
            "IPv4 Address" => {
                if value.starts_with("192.168.") || 
                   value.starts_with("10.") || 
                   value.starts_with("172.") {
                    60 // Private IP
                } else {
                    90 // Public IP
                }
            },
            "Email Address" => {
                if value.contains('@') && value.contains('.') && value.len() > 5 {
                    85
                } else {
                    50
                }
            },
            "URL" => {
                if value.starts_with("https://") {
                    90
                } else if value.starts_with("http://") {
                    80
                } else {
                    60
                }
            },
            "Bitcoin Address" => {
                if (value.len() >= 26 && value.len() <= 35) &&
                   (value.starts_with('1') || value.starts_with('3') || value.starts_with("bc1")) {
                    95
                } else {
                    70
                }
            },
            "Ethereum Address" => {
                if value.len() == 42 && value.starts_with("0x") {
                    95
                } else {
                    70
                }
            },
            _ => 75,
        }
    }

    fn detect_crypto_algorithm(crypto_data: &str) -> Option<String> {
        if crypto_data.contains("RSA") || crypto_data.contains("rsa") {
            Some("RSA".to_string())
        } else if crypto_data.contains("DSA") || crypto_data.contains("dsa") {
            Some("DSA".to_string())
        } else if crypto_data.contains("ECDSA") || crypto_data.contains("ecdsa") {
            Some("ECDSA".to_string())
        } else if crypto_data.len() >= 26 && crypto_data.len() <= 35 && 
                  (crypto_data.starts_with('1') || crypto_data.starts_with('3')) {
            Some("Bitcoin".to_string())
        } else if crypto_data.len() == 42 && crypto_data.starts_with("0x") {
            Some("Ethereum".to_string())
        } else if crypto_data.starts_with("bc1") {
            Some("Bitcoin Bech32".to_string())
        } else {
            None
        }
    }

    fn assess_crypto_strength(crypto_data: &str) -> String {
        if crypto_data.contains("4096") {
            "Very Strong".to_string()
        } else if crypto_data.contains("2048") {
            "Strong".to_string()
        } else if crypto_data.contains("1024") {
            "Medium".to_string()
        } else if crypto_data.contains("512") {
            "Weak".to_string()
        } else if crypto_data.len() >= 64 { // Long keys are generally stronger
            "Strong".to_string()
        } else if crypto_data.len() >= 32 {
            "Medium".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    fn compile_crypto_patterns() -> Vec<(Regex, String)> {
        let patterns = [
            (r"-----BEGIN [A-Z\s]+-----", "PEM Certificate/Key"),
            (r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", "Bitcoin Address"),
            (r"0x[a-fA-F0-9]{40}", "Ethereum Address"),
            (r"[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}", "Litecoin Address"),
            (r"r[0-9a-zA-Z]{24,34}", "Ripple Address"),
            (r"[A-Za-z0-9]{95}", "Monero Address"),
            (r"bc1[a-z0-9]{39,59}", "Bitcoin Bech32"),
            (r"[A-Za-z0-9+/]{40,}={0,2}", "Base64 Encoded Data"),
        ];

        patterns.iter()
            .filter_map(|(pattern, desc)| {
                Regex::new(pattern)
                    .map(|re| (re, desc.to_string()))
                    .map_err(|e| {
                        log::warn!("Failed to compile crypto regex '{}': {}", pattern, e);
                        e
                    })
                    .ok()
            })
            .collect()
    }

    fn compile_network_patterns() -> Vec<(Regex, String)> {
        let patterns = [
            (r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", "IPv4 Address"),
            (r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", "IPv6 Address"),
            (r"\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b", "Domain/Hostname"),
            (r#"https?://[^\s<>"{}|\\^`\[\]]+"#, "URL"),
            (r#"ftp://[^\s<>"{}|\\^`\[\]]+"#, "FTP URL"),
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "Email Address"),
            (r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", "MAC Address"),
            (r#"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|session[_-]?id)["'\s]*[:=]["'\s]*([a-zA-Z0-9+/]{16,})"#, "API Key/Token"),
        ];

        patterns.iter()
            .filter_map(|(pattern, desc)| {
                Regex::new(pattern)
                    .map(|re| (re, desc.to_string()))
                    .map_err(|e| {
                        log::warn!("Failed to compile network regex '{}': {}", pattern, e);
                        e
                    })
                    .ok()
            })
            .collect()
    }

    fn compile_threat_patterns() -> Vec<(Regex, String, u8)> {
        let patterns = [
            (r"(?i)(?:eval|exec|system|shell_exec|passthru)\s*\(", "Code Injection", 85),
            (r"(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+.*(?:FROM|INTO|TABLE)", "SQL Query", 70),
            (r"(?i)(?:<script|javascript:|vbscript:|onload=|onerror=)", "Script Injection", 80),
            (r"(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c)", "Directory Traversal", 90),
            (r"(?i)(?:cmd\.exe|powershell\.exe|/bin/sh|/bin/bash)\s", "Command Execution", 95),
            (r"(?i)(?:reverse|bind)\s+shell", "Shell Code", 95),
            (r"(?i)(?:metasploit|meterpreter|payload|exploit)", "Exploit Framework", 90),
            (r"(?i)(?:nmap|nessus|openvas|burp|sqlmap)", "Security Tools", 60),
            (r#"(?i)(?:password|passwd|pwd)\s*[:=]\s*['",]?([^'"\s]{6,})"#, "Hardcoded Password", 75),
        ];

        patterns.iter()
            .filter_map(|(pattern, desc, score)| {
                Regex::new(pattern)
                    .map(|re| (re, desc.to_string(), *score))
                    .map_err(|e| {
                        log::warn!("Failed to compile threat regex '{}': {}", pattern, e);
                        e
                    })
                    .ok()
            })
            .collect()
    }

    fn load_malware_hashes() -> HashSet<String> {
        let mut hashes = HashSet::new();
        // In production, load from threat intelligence feeds
        hashes.insert("d41d8cd98f00b204e9800998ecf8427e".to_string()); // Empty file MD5
        hashes.insert("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()); // Empty file SHA256
        hashes
    }

    fn load_suspicious_domains() -> HashSet<String> {
        let mut domains = HashSet::new();
        domains.insert("malware.com".to_string());
        domains.insert("phishing-site.net".to_string());
        domains.insert("suspicious-domain.org".to_string());
        domains
    }
}

#[derive(Debug, Default)]
pub struct AnalysisResult {
    pub network_artifacts: Vec<NetworkArtifact>,
    pub crypto_artifacts: Vec<CryptoArtifact>,
    pub threat_indicators: Vec<ThreatIndicator>,
    pub forensic_evidence: Vec<ForensicEvidence>,
    pub entropy: Option<f64>,
    pub encrypted_content: bool,
    pub steganography_detected: bool,
}

impl Default for ContentAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = ContentAnalyzer::new();
        assert!(!analyzer.crypto_patterns.is_empty());
        assert!(!analyzer.network_patterns.is_empty());
        assert!(!analyzer.threat_patterns.is_empty());
    }

    #[test]
    fn test_streaming_analysis() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let analyzer = ContentAnalyzer::new();
        
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "Contact us at test@example.com")?;
        writeln!(temp_file, "Visit https://example.com")?;
        writeln!(temp_file, "Server IP: 192.168.1.1")?;
        
        let file = File::open(temp_file.path())?;
        let result = analyzer.analyze_content_streaming(file, 1024)?;
        
        assert!(!result.network_artifacts.is_empty());
        
        // Check for expected artifacts
        let has_email = result.network_artifacts.iter()
            .any(|a| a.artifact_type == "Email Address");
        let has_url = result.network_artifacts.iter()
            .any(|a| a.artifact_type == "URL");
        let has_ip = result.network_artifacts.iter()
            .any(|a| a.artifact_type == "IPv4 Address");
        
        assert!(has_email);
        assert!(has_url);
        assert!(has_ip);
        
        Ok(())
    }
}