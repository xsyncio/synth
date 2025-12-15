//! Network Analysis Module
//!
//! Analyzes network capture files (PCAP/PCAPNG) and extracts network artifacts.
//! Features:
//! - HTTP request/response analysis
//! - DNS query extraction
//! - Email address and URL scraping
//! - Suspicious domain detection

use std::path::Path;
use std::collections::HashMap;
use pcap_parser::{PcapBlockOwned, PcapError, PcapNGReader, LegacyPcapReader};
use pcap_parser::traits::PcapReaderIterator;
use std::fs::File;
use std::io::BufReader;

/// Network analysis result
#[derive(Debug, Clone, Default)]
pub struct NetworkAnalysis {
    /// Number of packets processed
    pub packet_count: usize,
    /// Extracted URLs
    pub urls: Vec<String>,
    /// Extracted DNS queries
    pub dns_queries: Vec<String>,
    /// Extracted user agents
    pub user_agents: Vec<String>,
    /// Suspicious artifacts extracted
    pub suspicious_artifacts: Vec<String>,
    /// Protocol statistics
    pub protocol_stats: HashMap<String, usize>,
}

/// Network analyzer
pub struct NetworkAnalyzer;

impl NetworkAnalyzer {
    /// Analyze a capture file
    pub fn analyze_capture(path: &Path) -> Option<NetworkAnalysis> {
        let file = File::open(path).ok()?;
        let mut reader = BufReader::new(file);
        
        // Try PcapNG first
        if let Ok(mut pcapng) = PcapNGReader::new(65536, &mut reader) {
            return Some(Self::analyze_reader(&mut pcapng));
        }

        // Try Legacy Pcap
        let file = File::open(path).ok()?;
        let mut reader = BufReader::new(file);
        if let Ok(mut legacy) = LegacyPcapReader::new(65536, &mut reader) {
            return Some(Self::analyze_reader(&mut legacy));
        }

        None
    }

    /// Analyze using any PcapReaderIterator
    fn analyze_reader<R: PcapReaderIterator>(reader: &mut R) -> NetworkAnalysis {
        let mut analysis = NetworkAnalysis::default();
        
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::Legacy(packet) => {
                            analysis.packet_count += 1;
                            Self::analyze_packet(packet.data, &mut analysis);
                        },
                        PcapBlockOwned::NG(packet) => {
                            // Only process Enhanced Packet Blocks and Simple Packet Blocks
                            match packet {
                                pcap_parser::Block::EnhancedPacket(epb) => {
                                    analysis.packet_count += 1;
                                    Self::analyze_packet(epb.data, &mut analysis);
                                },
                                pcap_parser::Block::SimplePacket(spb) => {
                                    analysis.packet_count += 1;
                                    Self::analyze_packet(spb.data, &mut analysis);
                                },
                                _ => {}
                            }
                        },
                        _ => {}
                    }
                    reader.consume(offset);
                },
                Err(PcapError::Eof) => break,
                Err(_) => break, // Stop on error
            }
        }
        
        // Deduplicate results
        analysis.urls.sort(); analysis.urls.dedup();
        analysis.dns_queries.sort(); analysis.dns_queries.dedup();
        analysis.user_agents.sort(); analysis.user_agents.dedup();
        
        analysis
    }

    /// Analyze a single packet payload
    fn analyze_packet(data: &[u8], analysis: &mut NetworkAnalysis) {
        // Very basic protocol detection based on data
        // This is a simplified approach without a full protocol stack parser
        
        // Check for HTTP
        if let Ok(payload) = std::str::from_utf8(data) {
            if payload.contains("HTTP/1.") {
                *analysis.protocol_stats.entry("HTTP".to_string()).or_insert(0) += 1;
                
                // Extract Host header
                for line in payload.lines() {
                    if line.starts_with("Host: ") {
                        let host = line.trim_start_matches("Host: ").trim();
                        analysis.dns_queries.push(host.to_string());
                    }
                    if line.starts_with("User-Agent: ") {
                        let ua = line.trim_start_matches("User-Agent: ").trim();
                        analysis.user_agents.push(ua.to_string());
                    }
                    if line.starts_with("GET ") || line.starts_with("POST ") {
                        if let Some(url_part) = line.split_whitespace().nth(1) {
                            if url_part.starts_with("http") {
                                analysis.urls.push(url_part.to_string());
                            } else {
                                // Relative URL, combine with host later if improved
                                // For now, just store suspicious paths
                                if url_part.contains(".php") || url_part.contains(".jsp") {
                                    analysis.suspicious_artifacts.push(format!("Suspicious Path: {}", url_part));
                                }
                            }
                        }
                    }
                }
            } else if payload.contains("DNS") || (data.len() > 12 && (data[2] & 0x80 != 0)) {
                // Heuristic for DNS
                *analysis.protocol_stats.entry("DNS".to_string()).or_insert(0) += 1;
                
                // Extract rudimentary domain names from binary data if possible
                // This is complex without full DNS parsing, so we rely on strings found
            }
        }
        
        // Scan for artifacts in raw data
        Self::extract_artifacts_from_bytes(data, analysis);
    }
    
    /// Extract artifacts from raw bytes using pattern matching
    pub fn extract_artifacts_from_bytes(data: &[u8], analysis: &mut NetworkAnalysis) {
        let min_len = 4;
        let mut current_string = Vec::new();
        
        for &byte in data {
            if byte >= 0x20 && byte < 0x7F {
                current_string.push(byte);
            } else {
                if current_string.len() >= min_len {
                    if let Ok(s) = std::str::from_utf8(&current_string) {
                        // Check for email
                        if s.contains('@') && s.contains('.') {
                            // Basic email validation
                            let parts: Vec<&str> = s.split('@').collect();
                            if parts.len() == 2 && parts[1].contains('.') {
                                analysis.suspicious_artifacts.push(format!("Email: {}", s));
                            }
                        }
                        
                        // Check for Common Malware Domains / C2 extensions
                        if s.ends_with(".bit") || s.ends_with(".onion") {
                            analysis.dns_queries.push(s.to_string());
                            analysis.suspicious_artifacts.push(format!("Suspicious Domain: {}", s));
                        }

                        // Check for IPs
                        if Self::is_ip(s) {
                             // Contextless IP extraction
                             // Could be added to a list if we had one
                        }
                    }
                }
                current_string.clear();
            }
        }
    }
    
    fn is_ip(s: &str) -> bool {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() == 4 {
             parts.iter().all(|p| p.parse::<u8>().is_ok())
        } else {
            false
        }
    }
    
    /// Check if file is a capture file
    pub fn is_capture_file(path: &Path) -> bool {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            matches!(ext.to_lowercase().as_str(), "pcap" | "pcapng" | "cap")
        } else {
            // Check magic bytes
            if let Ok(data) = std::fs::read(path) {
                 if data.len() >= 4 {
                     // Pcap magic (d4 c3 b2 a1)
                     if data.starts_with(&[0xd4, 0xc3, 0xb2, 0xa1]) || data.starts_with(&[0xa1, 0xb2, 0xc3, 0xd4]) {
                         return true;
                     }
                     // PcapNG magic (0a 0d 0d 0a)
                     if data.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
                         return true;
                     }
                 }
            }
            false
        }
    }

    /// Analyze SSL/TLS Certificate
    pub fn analyze_cert(path: &Path) -> Option<Vec<(String, String)>> {
        let mut results = Vec::new();
        let data = std::fs::read(path).ok()?;
        
        // Try parsing as PEM
        if let Ok((_rem, pem)) = x509_parser::pem::parse_x509_pem(&data) {
            if let Ok(cert) = pem.parse_x509() {
                results.push(("Subject".to_string(), cert.subject().to_string()));
                results.push(("Issuer".to_string(), cert.issuer().to_string()));
                results.push(("Serial".to_string(), cert.tbs_certificate.serial.to_string()));
                results.push(("NotBefore".to_string(), cert.validity().not_before.to_string()));
                results.push(("NotAfter".to_string(), cert.validity().not_after.to_string()));
                
                // Check for self-signed
                if cert.issuer() == cert.subject() {
                    results.push(("Risk".to_string(), "Self-signed certificate detected".to_string()));
                }
            }
        } 
        // Try parsing as DER
        else if let Ok((_rem, cert)) = x509_parser::parse_x509_certificate(&data) {
            results.push(("Subject".to_string(), cert.subject().to_string()));
            results.push(("Issuer".to_string(), cert.issuer().to_string()));
             if cert.issuer() == cert.subject() {
                results.push(("Risk".to_string(), "Self-signed certificate detected".to_string()));
            }
        }

        if !results.is_empty() {
            Some(results)
        } else {
            None
        }
    }
    
    /// Analyze Email File (.eml)
    pub fn analyze_email(path: &Path) -> Option<Vec<(String, String)>> {
        let mut results = Vec::new();
        let data = std::fs::read_to_string(path).ok()?;
        
        if let Ok(parsed) = mailparse::parse_mail(data.as_bytes()) {
            for header in &parsed.headers {
                if matches!(header.get_key().to_lowercase().as_str(), "from" | "to" | "subject" | "date" | "received" | "x-mailer") {
                    results.push((header.get_key(), header.get_value()));
                }
            }
            
            // Check body for links/IPs? We already do content analysis, 
            // but we could specifically extract them here if needed.
            if let Ok(body) = parsed.get_body() {
                 if body.to_lowercase().contains("password") || body.to_lowercase().contains("urgent") {
                      results.push(("Suspicious Content".to_string(), "Phishing keywords detected".to_string()));
                 }
            }
        }
        
        if !results.is_empty() {
             Some(results)
        } else {
            None
        }
    }
    
    /// Analyze MBOX File (Bulk Emails)
    pub fn analyze_mbox(path: &Path) -> Option<Vec<(String, String)>> {
        let mut results = Vec::new();
        // Since MBOX can be large, we might want to just sample or stream.
        // For this implementation, we read it but process strictly.
        // NOTE: Large files should use a BufReader loop. Here we keep it simple for prototype.
        
        let file = File::open(path).ok()?;
        let reader = BufReader::new(file);
        use std::io::BufRead;
        
        // Count emails and extract first few headers
        let mut email_count = 0;
        let mut senders = Vec::new();
        
        for line in reader.lines() {
            if let Ok(l) = line {
                if l.starts_with("From ") {
                    email_count += 1;
                    // Attempt to extract email
                    let parts: Vec<&str> = l.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if senders.len() < 5 {
                            senders.push(parts[1].to_string());
                        }
                    }
                }
            }
        }
        
        if email_count > 0 {
            results.push(("Type".to_string(), "MBOX Archive".to_string()));
            results.push(("Email Count".to_string(), email_count.to_string()));
            results.push(("Sample Senders".to_string(), senders.join(", ")));
            Some(results)
        } else {
            None
        }
    }

    /// Analyze Configuration Files (Tor, VPN)
    pub fn analyze_config(path: &Path) -> Option<Vec<(String, String)>> {
        let mut results = Vec::new();
        let filename = path.file_name()?.to_string_lossy().to_lowercase();
        
        // Tor Config (torrc)
        if filename == "torrc" || filename.ends_with(".torrc") {
            results.push(("Type".to_string(), "Tor Configuration".to_string()));
             if let Ok(content) = std::fs::read_to_string(path) {
                 if content.contains("HiddenServiceDir") {
                      results.push(("Feature".to_string(), "Hidden Service Configured".to_string()));
                 }
                 if content.contains("EntryNodes") || content.contains("ExitNodes") {
                     results.push(("Feature".to_string(), "Custom Nodes Configured".to_string()));
                 }
             }
        }
        // OpenVPN (.ovpn)
        else if filename.ends_with(".ovpn") || filename.ends_with(".conf") {
             if let Ok(content) = std::fs::read_to_string(path) {
                 if content.contains("client") && content.contains("dev tun") {
                      results.push(("Type".to_string(), "OpenVPN Configuration".to_string()));
                      
                      // Extract remote
                      for line in content.lines() {
                          if line.starts_with("remote ") {
                              let parts: Vec<&str> = line.split_whitespace().collect();
                              if parts.len() >= 2 {
                                  results.push(("Remote".to_string(), parts[1].to_string()));
                              }
                          }
                      }
                 }
             }
        }

        if !results.is_empty() {
            Some(results)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ip() {
        assert!(NetworkAnalyzer::is_ip("192.168.1.1"));
        assert!(!NetworkAnalyzer::is_ip("999.999.999.999"));
        assert!(!NetworkAnalyzer::is_ip("example.com"));
    }
}
