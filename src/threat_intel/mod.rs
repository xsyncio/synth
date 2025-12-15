//! Threat Intelligence Module
//!
//! Provides MITRE ATT&CK framework mapping and IoC matching.
//! Correlates detected behaviors to known attack techniques.

mod ioc;
mod mitre;
mod risk;

use std::collections::HashMap;

/// MITRE ATT&CK technique mapping
#[derive(Debug, Clone)]
pub struct AttackTechnique {
    /// Technique ID (e.g., T1055)
    pub technique_id: String,
    /// Technique name
    pub name: String,
    /// Parent tactic (e.g., Defense Evasion)
    pub tactic: String,
    /// Description
    pub description: String,
    /// Platforms affected
    pub platforms: Vec<String>,
    /// Detection indicators
    pub detection_indicators: Vec<String>,
}

/// Mapped attack technique result
#[derive(Debug, Clone)]
pub struct AttackMapping {
    /// Matched technique
    pub technique: AttackTechnique,
    /// Confidence of mapping (0-100)
    pub confidence: u8,
    /// Evidence from analysis
    pub evidence: Vec<String>,
}

/// Threat intelligence engine
pub struct ThreatIntelEngine {
    /// MITRE ATT&CK technique database
    techniques: HashMap<String, AttackTechnique>,
    /// Known malicious hashes
    malware_hashes: HashMap<String, String>,
    /// Known malicious domains
    malicious_domains: Vec<String>,
    /// Known malicious IPs
    malicious_ips: Vec<String>,
    /// Maps YARA rule names / families to Actors/Tools
    attribution_map: HashMap<String, String>,
    /// Maps generic threats to likely CVEs
    cve_map: HashMap<String, String>,
}

impl ThreatIntelEngine {
    /// Create a new threat intelligence engine
    pub fn new() -> Self {
        let ioc_data = ioc::load_ioc_database();
        let mitre_techniques = mitre::get_mitre_techniques();
        
        let mut techniques = HashMap::new();
        for technique in mitre_techniques {
            techniques.insert(technique.technique_id.clone(), technique);
        }

        Self {
            techniques,
            malware_hashes: ioc_data.malware_hashes,
            malicious_domains: ioc_data.malicious_domains,
            malicious_ips: ioc_data.malicious_ips,
            attribution_map: ioc_data.attribution_map,
            cve_map: ioc_data.cve_map,
        }
    }

    /// Map detected behaviors to MITRE ATT&CK techniques
    pub fn map_to_attack(&self, indicators: &[String]) -> Vec<AttackMapping> {
        let mut mappings = Vec::new();

        for (_id, technique) in &self.techniques {
            let mut evidence = Vec::new();
            let mut match_count = 0;

            for indicator in indicators {
                let indicator_lower = indicator.to_lowercase();
                for detection in &technique.detection_indicators {
                    if indicator_lower.contains(&detection.to_lowercase()) {
                        evidence.push(format!("'{}' matches '{}'", indicator, detection));
                        match_count += 1;
                    }
                }
            }

            if match_count > 0 {
                let confidence = ((match_count as f64 / technique.detection_indicators.len() as f64) * 100.0)
                    .min(100.0) as u8;

                mappings.push(AttackMapping {
                    technique: technique.clone(),
                    confidence,
                    evidence,
                });
            }
        }

        mappings.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        mappings
    }

    /// Check if a hash is known malicious
    pub fn check_hash(&self, hash: &str) -> Option<String> {
        self.malware_hashes.get(&hash.to_lowercase()).cloned()
    }

    /// Check if a domain is known malicious
    pub fn check_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        self.malicious_domains.iter().any(|d| domain_lower.contains(d))
    }

    /// Check if an IP is known malicious
    pub fn check_ip(&self, ip: &str) -> bool {
        self.malicious_ips.contains(&ip.to_string())
    }
    
    /// Get attribution for a specific rule name
    pub fn get_attribution(&self, rule_name: &str) -> Option<String> {
        self.attribution_map.get(rule_name).cloned()
    }

    /// Get potential CVEs related to keywords found
    pub fn get_related_cves(&self, indicators: &[String]) -> Vec<String> {
        let mut cves = Vec::new();
        for indicator in indicators {
             let ind_lower = indicator.to_lowercase();
             for (key, val) in &self.cve_map {
                 if ind_lower.contains(key) {
                     cves.push(val.clone());
                 }
             }
        }
        cves.sort();
        cves.dedup();
        cves
    }

    /// Get technique by ID
    pub fn get_technique(&self, id: &str) -> Option<&AttackTechnique> {
        self.techniques.get(id)
    }

    /// Get all tactics
    pub fn get_tactics(&self) -> Vec<String> {
        let mut tactics: Vec<String> = self.techniques.values()
            .map(|t| t.tactic.clone())
            .collect();
        tactics.sort();
        tactics.dedup();
        tactics
    }

    /// Get techniques for a tactic
    pub fn get_techniques_for_tactic(&self, tactic: &str) -> Vec<&AttackTechnique> {
        self.techniques.values()
            .filter(|t| t.tactic == tactic)
            .collect()
    }
}

impl Default for ThreatIntelEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = ThreatIntelEngine::new();
        assert!(!engine.techniques.is_empty(), "Should have techniques loaded");
    }

    #[test]
    fn test_attack_mapping() {
        let engine = ThreatIntelEngine::new();
        let indicators = vec![
            "powershell.exe".to_string(),
            "Invoke-Expression".to_string(),
            "DownloadString".to_string(),
        ];
        let mappings = engine.map_to_attack(&indicators);
        assert!(!mappings.is_empty(), "Should find PowerShell technique");
        assert!(mappings.iter().any(|m| m.technique.technique_id.starts_with("T1059")));
    }

    #[test]
    fn test_hash_lookup() {
        let engine = ThreatIntelEngine::new();
        let result = engine.check_hash("44d88612fea8a8f36de82e1278abb02f");
        assert!(result.is_some(), "Should find EICAR hash");
        assert_eq!(result.unwrap(), "EICAR Test File");
    }

    #[test]
    fn test_risk_scoring() {
        let engine = ThreatIntelEngine::new();
        let mut asset = crate::models::AssetMetadata::new(std::path::PathBuf::from("test.exe"), "test.exe".to_string());
        
        assert_eq!(engine.calculate_risk_score(&asset), 0);

        asset.detected_secrets.push(crate::models::SecretFinding {
            secret_type: "Test Key".to_string(),
            provider: "TestProvider".to_string(),
            value_redacted: "123***".to_string(),
            line_number: Some(1),
            context: "key=123".to_string(),
            confidence: 100,
            severity: "critical".to_string(),
            validated: true,
        });
        let score = engine.calculate_risk_score(&asset);
        assert!(score >= 35, "Score should reflect secrets");

        asset.yara_matches.push(crate::models::YaraMatchResult {
            rule_name: "TestRule".to_string(),
            namespace: "Malware".to_string(),
            tags: vec![],
            confidence: 100,
        });
        let score_2 = engine.calculate_risk_score(&asset);
        assert!(score_2 > score, "Score should increase with YARA match");
        assert!(score_2 >= 85);
        
        asset.steganography_detected = true;
        assert_eq!(engine.calculate_risk_score(&asset), 100);
    }

    #[test]
    fn test_get_tactics() {
        let engine = ThreatIntelEngine::new();
        let tactics = engine.get_tactics();
        assert!(tactics.contains(&"Execution".to_string()));
        assert!(tactics.contains(&"Persistence".to_string()));
        assert!(tactics.contains(&"Credential Access".to_string()));
    }
}
