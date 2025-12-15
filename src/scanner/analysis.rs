//! Analysis Level Module
//!
//! Contains different analysis levels: fast, standard, deep, comprehensive.

use crate::models::{AssetMetadata, SecretFinding};
use crate::utils::{detect_file_signature, format_permissions, format_timestamp, is_hidden_file, HashComputer};
use memmap2::Mmap;
use std::fs::{File, Metadata};

use super::AdvancedOsintScanner;

impl AdvancedOsintScanner {
    /// Extract basic file metadata
    pub(crate) fn extract_basic_metadata(&self, asset: &mut AssetMetadata, metadata: &Metadata) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::trace!("Extracting basic metadata for: {:?}", asset.path);

        asset.size = Some(metadata.len());
        asset.is_file = metadata.is_file();
        asset.is_hidden = is_hidden_file(&asset.path);
        asset.created = format_timestamp(metadata.created().ok());
        asset.modified = format_timestamp(metadata.modified().ok());
        asset.accessed = format_timestamp(metadata.accessed().ok());
        asset.permissions = format_permissions(metadata);
        asset.owner = whoami::username();

        asset.mime_type = mime_guess::from_path(&asset.path)
            .first()
            .map(|mime| mime.to_string());

        Ok(())
    }

    /// Fast analysis - minimal overhead
    pub(crate) fn perform_fast_analysis(&self, asset: &mut AssetMetadata) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !asset.is_file {
            return Ok(());
        }

        log::trace!("Performing fast analysis for: {:?}", asset.path);

        if let Ok(file) = File::open(&asset.path) {
            // SAFETY: Memory-mapping is safe - file handle is valid, read-only access
            if let Ok(mmap) = unsafe { Mmap::map(&file) } {
                if !mmap.is_empty() {
                    asset.file_signature = detect_file_signature(&mmap).map(String::from);
                }
            }
        }

        Ok(())
    }

    /// Standard analysis - hashes, content analysis, secret detection
    pub(crate) fn perform_standard_analysis(&self, asset: &mut AssetMetadata) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !asset.is_file || asset.size.unwrap_or(0) > self.args.max_file_size * 1024 * 1024 {
            return Ok(());
        }

        log::trace!("Performing standard analysis for: {:?}", asset.path);

        let file = File::open(&asset.path)?;
        // SAFETY: Memory-mapping is safe - file handle is valid, read-only access
        let mmap = unsafe { Mmap::map(&file)? };

        // Compute hashes
        let (md5_hash, sha256_hash, sha3_hash, blake3_hash) = HashComputer::compute_hashes(&mmap)?;
        asset.md5_hash = Some(md5_hash);
        asset.sha256_hash = Some(sha256_hash);
        asset.sha3_hash = Some(sha3_hash);
        asset.blake3_hash = Some(blake3_hash);

        // Content analysis
        let analysis_result = self.analyzer.analyze_memory_mapped(&mmap)?;
        asset.network_artifacts = analysis_result.network_artifacts;
        asset.crypto_artifacts = analysis_result.crypto_artifacts;
        asset.threat_indicators = analysis_result.threat_indicators;
        asset.forensic_evidence = analysis_result.forensic_evidence;
        asset.entropy = analysis_result.entropy;
        asset.entropy_map = analysis_result.entropy_map;
        asset.encrypted_content = analysis_result.encrypted_content;
        asset.steganography_detected = analysis_result.steganography_detected;

        // Secret detection
        if let Ok(content) = std::str::from_utf8(&mmap) {
            let detected = self.secret_scanner.scan(content);
            asset.detected_secrets = detected.into_iter().map(|s| {
                let redacted = if s.value.len() > 8 {
                    format!("{}...{}", &s.value[..4], &s.value[s.value.len()-4..])
                } else {
                    "*".repeat(s.value.len())
                };
                SecretFinding {
                    secret_type: s.secret_type,
                    provider: s.provider,
                    value_redacted: redacted,
                    context: s.context,
                    confidence: s.confidence,
                    severity: s.severity.to_string(),
                    validated: s.validated,
                    line_number: s.line_number,
                }
            }).collect();
        }

        Ok(())
    }

    /// Deep analysis - EXIF, forensics, steganography, network analysis
    pub(crate) fn perform_deep_analysis(&self, asset: &mut AssetMetadata) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::trace!("Performing deep analysis for: {:?}", asset.path);

        // EXIF and metadata extraction
        if crate::metadata::MetadataExtractor::supports_metadata(&asset.path) {
            let extracted = crate::metadata::MetadataExtractor::extract(&asset.path);
            
            asset.exif_data = extracted.exif;
            
            if let Some(gps) = extracted.gps {
                asset.gps_coordinates = Some(format!(
                    "{:.6}, {:.6}{}",
                    gps.latitude,
                    gps.longitude,
                    gps.altitude.map(|a| format!(" (alt: {:.1}m)", a)).unwrap_or_default()
                ));
                
                asset.forensic_evidence.push(crate::models::ForensicEvidence {
                    evidence_type: "GPS Coordinates".to_string(),
                    description: format!(
                        "Location data found: {:.6}, {:.6}",
                        gps.latitude, gps.longitude
                    ),
                    confidence: 95,
                    technical_details: {
                        let mut details = std::collections::HashMap::new();
                        details.insert("latitude".to_string(), gps.latitude.to_string());
                        details.insert("longitude".to_string(), gps.longitude.to_string());
                        if let Some(alt) = gps.altitude {
                            details.insert("altitude".to_string(), alt.to_string());
                        }
                        details
                    },
                });
            }
            
            if let Some(device) = extracted.device {
                if let Some(make) = device.make {
                    asset.metadata_analysis.insert("Device Make".to_string(), make);
                }
                if let Some(model) = device.model {
                    asset.metadata_analysis.insert("Device Model".to_string(), model);
                }
                if let Some(software) = device.software {
                    asset.metadata_analysis.insert("Software".to_string(), software);
                }
            }
            
            for (key, value) in extracted.general {
                asset.metadata_analysis.insert(key, value);
            }
        }

        // Forensic artifacts analysis
        if let Some(forensics) = crate::forensics::ForensicAnalyzer::analyze(&asset.path) {
            if !forensics.event_logs.is_empty() {
                asset.forensic_evidence.push(crate::models::ForensicEvidence {
                    evidence_type: "Windows Event Logs".to_string(),
                    description: format!("Extracted {} event log entries", forensics.event_logs.len()),
                    confidence: 100,
                    technical_details: std::collections::HashMap::new(),
                });
            }
            if !forensics.browser_history.is_empty() {
                asset.forensic_evidence.push(crate::models::ForensicEvidence {
                    evidence_type: "Browser History".to_string(),
                    description: format!("Extracted {} browser history entries", forensics.browser_history.len()),
                    confidence: 100,
                    technical_details: std::collections::HashMap::new(),
                });
            }
            if !forensics.evidence.is_empty() {
                asset.forensic_evidence.extend(forensics.evidence.clone());
            }
            asset.forensic_analysis = Some(forensics);
            log::debug!("Forensic artifacts extracted from {:?}", asset.path);
        }

        // Steganography detection
        if crate::stego::StegoDetector::is_supported_format(&asset.path) {
            if let Some(stego_result) = crate::stego::StegoDetector::analyze_file(&asset.path) {
                if stego_result.detected {
                    asset.steganography_detected = true;
                    
                    asset.threat_indicators.push(crate::models::ThreatIndicator {
                        indicator_type: "Steganography".to_string(),
                        value: stego_result.detection_method.unwrap_or_else(|| "Unknown".to_string()),
                        confidence: stego_result.confidence,
                        description: format!("Potential hidden data detected: {}", stego_result.details.join("; ")),
                    });

                    asset.forensic_evidence.push(crate::models::ForensicEvidence {
                        evidence_type: "Steganography Analysis".to_string(),
                        description: format!(
                            "Steganography indicators detected with {}% confidence",
                            stego_result.confidence
                        ),
                        confidence: stego_result.confidence,
                        technical_details: {
                            let mut details = std::collections::HashMap::new();
                            if let Some(lsb) = stego_result.lsb_analysis {
                                details.insert("lsb_ratio".to_string(), format!("{:.4}", lsb.avg_lsb_ratio));
                                details.insert("chi_square_p".to_string(), format!("{:.4}", lsb.chi_square_pvalue));
                            }
                            if let Some(entropy) = stego_result.entropy_analysis {
                                details.insert("lsb_entropy".to_string(), format!("{:.2}", entropy.lsb_entropy));
                            }
                            details
                        },
                    });

                    log::debug!("Steganography detected in {:?}: {}% confidence", asset.path, stego_result.confidence);
                }
            }
        }

        // Network analysis for PCAP files
        if crate::network::NetworkAnalyzer::is_capture_file(&asset.path) {
            if let Some(net_analysis) = crate::network::NetworkAnalyzer::analyze_capture(&asset.path) {
                for url in &net_analysis.urls {
                    asset.network_artifacts.push(crate::models::NetworkArtifact {
                        artifact_type: "URL".to_string(),
                        value: url.clone(),
                        description: "Extracted from network traffic".to_string(),
                        source: "PCAP Analysis".to_string(),
                        confidence: 100,
                    });
                }
                
                for dns in &net_analysis.dns_queries {
                    asset.network_artifacts.push(crate::models::NetworkArtifact {
                        artifact_type: "DNS Query".to_string(),
                        value: dns.clone(),
                        description: "DNS resolution request".to_string(),
                        source: "PCAP Analysis".to_string(),
                        confidence: 100,
                    });
                }

                for suspicious in &net_analysis.suspicious_artifacts {
                    asset.threat_indicators.push(crate::models::ThreatIndicator {
                        indicator_type: "Suspicious Network Artifact".to_string(),
                        value: suspicious.clone(),
                        confidence: 80,
                        description: "Suspicious pattern in network traffic".to_string(),
                    });
                }

                log::debug!("Network analysis complete for {:?}: {} packets", asset.path, net_analysis.packet_count);
            }
        }

        // Extended Network Intelligence
        if let Some(ext) = asset.path.extension().and_then(|e| e.to_str()).map(|e| e.to_string()) {
            self.analyze_network_intel(asset, &ext)?;
        }

        Ok(())
    }

    /// Analyze network-related files (certs, emails, configs)
    fn analyze_network_intel(&self, asset: &mut AssetMetadata, ext: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match ext.to_lowercase().as_str() {
            "pem" | "crt" | "cer" | "der" => {
                if let Some(cert_info) = crate::network::NetworkAnalyzer::analyze_cert(&asset.path) {
                    for (key, val) in cert_info {
                        asset.network_artifacts.push(crate::models::NetworkArtifact {
                            artifact_type: format!("Certificate {}", key),
                            value: val.clone(),
                            description: format!("Certificate Metadata: {}", key),
                            source: "X.509 Analysis".to_string(),
                            confidence: 100,
                        });
                    }
                    log::debug!("Analyzed certificate: {:?}", asset.path);
                }
            },
            "eml" | "msg" | "mbox" => {
                let analysis = if ext.eq_ignore_ascii_case("mbox") {
                    crate::network::NetworkAnalyzer::analyze_mbox(&asset.path)
                } else {
                    crate::network::NetworkAnalyzer::analyze_email(&asset.path)
                };

                if let Some(email_info) = analysis {
                    for (key, val) in email_info {
                        asset.network_artifacts.push(crate::models::NetworkArtifact {
                            artifact_type: format!("Email {}", key),
                            value: val.clone(),
                            description: format!("Email Header/Info: {}", key),
                            source: "Email Analysis".to_string(),
                            confidence: 100,
                        });
                    }
                    log::debug!("Analyzed email/archive: {:?}", asset.path);
                }
            },
            "torrc" | "ovpn" | "conf" => {
                if let Some(config_info) = crate::network::NetworkAnalyzer::analyze_config(&asset.path) {
                    for (key, val) in config_info {
                        asset.network_artifacts.push(crate::models::NetworkArtifact {
                            artifact_type: format!("VPN/Tor {}", key),
                            value: val.clone(),
                            description: "Anonymization Network Config".to_string(),
                            source: "Config Analysis".to_string(),
                            confidence: 90,
                        });
                    }
                    log::debug!("Analyzed anonymization config: {:?}", asset.path);
                }
            },
            _ => {}
        }
        Ok(())
    }

    /// Comprehensive analysis - YARA, binary analysis, anti-evasion, code analysis
    pub(crate) fn perform_comprehensive_analysis(&self, asset: &mut AssetMetadata) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::trace!("Performing comprehensive analysis for: {:?}", asset.path);

        // YARA rule scanning
        let yara_matches = self.yara_engine.scan_file(&asset.path);
        if !yara_matches.is_empty() {
            log::debug!("YARA matches found in {:?}: {}", asset.path, yara_matches.len());
            
            asset.yara_matches = yara_matches.iter().map(|m| {
                asset.threat_indicators.push(crate::models::ThreatIndicator {
                    indicator_type: format!("YARA: {}", m.rule_name),
                    value: m.namespace.clone(),
                    confidence: m.confidence,
                    description: format!("YARA rule '{}' matched (namespace: {})", m.rule_name, m.namespace),
                });

                crate::models::YaraMatchResult {
                    rule_name: m.rule_name.clone(),
                    namespace: m.namespace.clone(),
                    tags: m.tags.clone(),
                    confidence: m.confidence,
                }
            }).collect();
        }

        // Binary analysis for executables
        if crate::binary::BinaryAnalyzer::is_executable(&asset.path) {
            self.analyze_binary(asset)?;
        }
        
        // Anti-Evasion & Environment Detection
        self.analyze_anti_evasion(asset)?;

        // Code analysis for source files
        if let Some(ext) = asset.path.extension().and_then(|e| e.to_str()) {
            let code_extensions = ["py", "js", "php", "rb", "pl", "sh", "bat", "ps1", "c", "cpp", "java", "rs"];
            
            if code_extensions.contains(&ext.to_lowercase().as_str()) {
                self.analyze_code_file(asset)?;
            }
        }

        Ok(())
    }

    /// Analyze binary executables (PE/ELF)
    fn analyze_binary(&self, asset: &mut AssetMetadata) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(bin_analysis) = crate::binary::BinaryAnalyzer::analyze(&asset.path) {
            for suspicious in &bin_analysis.suspicious {
                asset.threat_indicators.push(crate::models::ThreatIndicator {
                    indicator_type: "Suspicious API".to_string(),
                    value: suspicious.clone(),
                    confidence: 75,
                    description: "Potentially malicious API import detected".to_string(),
                });
            }

            for packing in &bin_analysis.packing_indicators {
                asset.threat_indicators.push(crate::models::ThreatIndicator {
                    indicator_type: "Packing".to_string(),
                    value: packing.clone(),
                    confidence: 70,
                    description: "Binary may be packed or encrypted".to_string(),
                });
            }

            asset.binary_info = Some(crate::models::BinaryInfo {
                format: bin_analysis.format.to_string(),
                architecture: bin_analysis.architecture,
                entry_point: bin_analysis.entry_point,
                imphash: bin_analysis.imphash,
                section_count: bin_analysis.sections.len(),
                high_entropy_sections: bin_analysis.sections.iter()
                    .filter(|s| s.entropy > 7.0)
                    .map(|s| format!("{} ({:.2})", s.name, s.entropy))
                    .collect(),
                import_count: bin_analysis.imports.iter().map(|i| i.functions.len()).sum(),
                export_count: bin_analysis.exports.len(),
                security_features: bin_analysis.security_features,
                suspicious_imports: bin_analysis.suspicious,
                packing_indicators: bin_analysis.packing_indicators,
                fuzzy_hash: bin_analysis.fuzzy_hash,
                disassembly: bin_analysis.disassembly,
            });

            log::debug!("Binary analysis complete for {:?}: {}", asset.path, bin_analysis.format);
        }
        Ok(())
    }

    /// Analyze anti-evasion techniques
    fn analyze_anti_evasion(&self, asset: &mut AssetMetadata) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut anti_evasion_result = crate::anti_evasion::AntiEvasionScanner::scan_artifact(&asset.path, &asset.name)
            .unwrap_or_default();
        
        if let Some(bin_info) = &asset.binary_info {
            let bin_checks = crate::anti_evasion::AntiEvasionScanner::analyze_binary_features(bin_info);
            anti_evasion_result.anti_debug_techniques.extend(bin_checks.anti_debug_techniques);
            anti_evasion_result.anti_vm_techniques.extend(bin_checks.anti_vm_techniques);
            if bin_checks.time_evasion {
                anti_evasion_result.time_evasion = true;
            }
        }

        if !anti_evasion_result.evidence.is_empty() 
            || !anti_evasion_result.anti_debug_techniques.is_empty() 
            || !anti_evasion_result.anti_vm_techniques.is_empty() 
            || anti_evasion_result.environment_type.is_some() 
        {
            if let Some(env) = &anti_evasion_result.environment_type {
                asset.threat_indicators.push(crate::models::ThreatIndicator {
                    indicator_type: "VM/Sandbox Artifact".to_string(),
                    value: env.clone(),
                    confidence: 90,
                    description: format!("Artifact indicating {} environment found", env),
                });
            }
            
            for tech in &anti_evasion_result.anti_debug_techniques {
                asset.threat_indicators.push(crate::models::ThreatIndicator {
                    indicator_type: "Anti-Debugging".to_string(),
                    value: tech.clone(),
                    confidence: 80,
                    description: "Anti-debugging technique detected".to_string(),
                });
            }
            
            for tech in &anti_evasion_result.anti_vm_techniques {
                asset.threat_indicators.push(crate::models::ThreatIndicator {
                    indicator_type: "Anti-VM".to_string(),
                    value: tech.clone(),
                    confidence: 80,
                    description: "Anti-VM technique detected".to_string(),
                });
            }

            asset.anti_evasion = Some(anti_evasion_result);
        }
        Ok(())
    }

    /// Analyze source code files
    fn analyze_code_file(&self, asset: &mut AssetMetadata) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Ok(content) = std::fs::read_to_string(&asset.path) {
            let lines_of_code = content.lines().count();
            let complexity = super::risk::calculate_cyclomatic_complexity(&content);
            let obfuscation = super::risk::calculate_obfuscation_score(self, &content);

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
}
