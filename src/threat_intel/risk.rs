//! Risk Scoring for Assets

use super::ThreatIntelEngine;

impl ThreatIntelEngine {
    /// Calculate composite risk score (0-100) based on all findings
    pub fn calculate_risk_score(&self, asset: &crate::models::AssetMetadata) -> u8 {
        let mut score: u32 = 0;

        // 1. Secrets detection
        if !asset.detected_secrets.is_empty() {
            score += 30 + (asset.detected_secrets.len() as u32 * 5);
        }

        // 2. YARA matches (Critical)
        if !asset.yara_matches.is_empty() {
             score += 40 + (asset.yara_matches.len() as u32 * 10);
        }

        // 2.5 Attribution (Critical)
        if !asset.yara_matches.is_empty() {
            for match_ in &asset.yara_matches {
                if self.get_attribution(&match_.rule_name).is_some() {
                    score += 50; 
                }
            }
        }

        // 2.6 CVE Indicators
        if !asset.threat_indicators.is_empty() {
             let indicators: Vec<String> = asset.threat_indicators.iter().map(|t| t.value.clone()).collect();
             let cves = self.get_related_cves(&indicators);
             if !cves.is_empty() {
                 score += 30;
             }
        }

        // 3. Threat indicators (Generic)
        if !asset.threat_indicators.is_empty() {
            score += asset.threat_indicators.len() as u32 * 10;
        }

        // 4. Steganography
        if asset.steganography_detected {
            score += 25;
        }

        // 5. Encrypted content (High entropy)
        if asset.encrypted_content {
            score += 10;
        }

        // 6. Binary anomalies
        if let Some(bin) = &asset.binary_info {
            if !bin.suspicious_imports.is_empty() {
                score += 15 + (bin.suspicious_imports.len() as u32 * 5);
            }
            if !bin.packing_indicators.is_empty() {
                score += 20;
            }
            if let Some(ae) = &asset.anti_evasion {
                 if !ae.anti_debug_techniques.is_empty() || !ae.anti_vm_techniques.is_empty() {
                      score += 40;
                 }
            }
        }
        
        // 7. Network Artifacts
        if !asset.network_artifacts.is_empty() {
             let unknown_artifacts = asset.network_artifacts.len(); 
             if unknown_artifacts > 0 {
                 score += 5;
             }
        }
        
        // 8. Forensic Artifacts
        if let Some(forensics) = &asset.forensic_analysis {
             if !forensics.recovered_files.is_empty() {
                 score += 20;
             }
        }

        score.min(100) as u8
    }
}
