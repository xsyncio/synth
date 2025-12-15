//! YARA Rules Engine Module
//!
//! Integrates YARA-X (pure Rust) for malware and threat detection.
//! Uses free, open-source community rules.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use yara_x::Rules;
use yara_x::Scanner;

/// Result of a YARA scan
#[derive(Debug, Clone)]
pub struct YaraMatch {
    /// Rule name that matched
    pub rule_name: String,
    /// Rule namespace
    pub namespace: String,
    /// Rule tags
    pub tags: Vec<String>,
    /// Rule metadata
    pub metadata: HashMap<String, String>,
    /// Confidence based on rule source
    pub confidence: u8,
}

/// YARA rules engine
pub struct YaraEngine {
    /// Compiled rules
    rules: Option<Arc<Rules>>,
    /// Number of loaded rules
    rule_count: usize,
}

impl YaraEngine {
    /// Create a new YARA engine with bundled rules
    pub fn new() -> Self {
        let mut engine = Self {
            rules: None,
            rule_count: 0,
        };
        
        // Load bundled community rules
        if let Err(e) = engine.compile_bundled_rules() {
            log::warn!("Failed to compile bundled YARA rules: {}", e);
        }
        
        engine
    }

    /// Compile bundled community YARA rules
    fn compile_bundled_rules(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut compiler = yara_x::Compiler::new();
        
        // Add bundled malware detection rules
        let rules_source = Self::get_bundled_rules();
        let mut rule_count = 0;
        
        for (namespace, rule_text) in rules_source {
            // Use fluent API - new_namespace returns &mut Compiler
            let _ = compiler.new_namespace(namespace);
            if let Err(e) = compiler.add_source(rule_text.as_bytes()) {
                log::warn!("Failed to compile rules in '{}': {:?}", namespace, e);
            } else {
                // Count rules based on rule definitions in source
                rule_count += rule_text.matches("rule ").count();
            }
        }
        
        let rules = compiler.build();
        self.rule_count = rule_count;
        self.rules = Some(Arc::new(rules));
        
        log::info!("Loaded approximately {} YARA rules", self.rule_count);
        Ok(())
    }

    /// Load custom rules from a file or directory
    pub fn load_rules_from_path(&mut self, path: &Path) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let mut compiler = yara_x::Compiler::new();
        let mut loaded = 0;

        if path.is_file() {
            let content = std::fs::read_to_string(path)?;
            compiler.add_source(content.as_bytes())?;
            loaded += content.matches("rule ").count();
        } else if path.is_dir() {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let entry_path = entry.path();
                if entry_path.extension().map(|e| e == "yar" || e == "yara").unwrap_or(false) {
                    if let Ok(content) = std::fs::read_to_string(&entry_path) {
                        if compiler.add_source(content.as_bytes()).is_ok() {
                            loaded += content.matches("rule ").count();
                        }
                    }
                }
            }
        }

        let rules = compiler.build();
        self.rule_count = loaded;
        self.rules = Some(Arc::new(rules));
        
        Ok(loaded)
    }

    /// Scan file content for matches
    pub fn scan_bytes(&self, data: &[u8]) -> Vec<YaraMatch> {
        let mut matches = Vec::new();

        if let Some(ref rules) = self.rules {
            let mut scanner = Scanner::new(rules);
            
            if let Ok(results) = scanner.scan(data) {
                for matched_rule in results.matching_rules() {
                    let mut metadata = HashMap::new();
                    
                    // Extract rule metadata
                    for (key, value) in matched_rule.metadata() {
                        metadata.insert(
                            key.to_string(),
                            format!("{:?}", value),
                        );
                    }

                    matches.push(YaraMatch {
                        rule_name: matched_rule.identifier().to_string(),
                        namespace: matched_rule.namespace().to_string(),
                        tags: matched_rule.tags().map(|t| t.identifier().to_string()).collect(),
                        metadata,
                        confidence: 85, // Default confidence for YARA matches
                    });
                }
            }
        }

        matches
    }

    /// Scan a file
    pub fn scan_file(&self, path: &Path) -> Vec<YaraMatch> {
        if let Ok(data) = std::fs::read(path) {
            self.scan_bytes(&data)
        } else {
            Vec::new()
        }
    }

    /// Get number of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Get bundled community rules (free, open-source)
    fn get_bundled_rules() -> Vec<(&'static str, String)> {
        vec![
            // Suspicious file patterns
            ("suspicious", r#"
rule SuspiciousBase64EncodedExe {
    meta:
        description = "Detects base64 encoded Windows executable"
        author = "Synth Security"
        severity = "high"
    strings:
        $mz_base64 = "TVqQAAMAAAAEAAAA" ascii wide
        $mz_base64_2 = "TVpQAAIAAAAEAA8A" ascii wide
    condition:
        any of them
}

rule SuspiciousPowershellDownload {
    meta:
        description = "Suspicious PowerShell download cradle"
        author = "Synth Security"
        severity = "high"
    strings:
        $ps1 = "Invoke-WebRequest" nocase
        $ps2 = "DownloadString" nocase
        $ps3 = "DownloadFile" nocase
        $ps4 = "IEX" nocase
        $ps5 = "Invoke-Expression" nocase
        $ps6 = "WebClient" nocase
    condition:
        2 of them
}

rule SuspiciousShellcode {
    meta:
        description = "Potential shellcode patterns"
        author = "Synth Security"
        severity = "critical"
    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 }
        $int3_sled = { CC CC CC CC CC CC CC CC }
        $syscall = { 0F 05 }
        $sysenter = { 0F 34 }
    condition:
        ($nop_sled or $int3_sled) and ($syscall or $sysenter)
}
"#.to_string()),

            // Webshell detection
            ("webshells", r#"
rule PHPWebshell {
    meta:
        description = "Generic PHP webshell detection"
        author = "Synth Security"
        severity = "critical"
    strings:
        $php = "<?php" nocase
        $eval = "eval(" nocase
        $base64 = "base64_decode" nocase
        $exec = "exec(" nocase
        $system = "system(" nocase
        $passthru = "passthru(" nocase
        $shell = "shell_exec" nocase
        $cmd = "$_REQUEST" nocase
        $post = "$_POST" nocase
        $get = "$_GET" nocase
    condition:
        $php and (($eval and $base64) or (($exec or $system or $passthru or $shell) and ($cmd or $post or $get)))
}

rule JSPWebshell {
    meta:
        description = "JSP webshell detection"
        author = "Synth Security"
        severity = "critical"
    strings:
        $runtime = "Runtime.getRuntime()" ascii
        $exec = ".exec(" ascii
        $process = "Process" ascii
    condition:
        all of them
}
"#.to_string()),

            // Cryptominer detection
            ("cryptominers", r#"
rule CryptoMiner {
    meta:
        description = "Cryptocurrency miner detection"
        author = "Synth Security"
        severity = "high"
    strings:
        $xmr1 = "stratum+tcp://" ascii wide
        $xmr2 = "stratum+ssl://" ascii wide
        $pool1 = "pool.minergate" ascii wide nocase
        $pool2 = "xmrpool.eu" ascii wide nocase
        $pool3 = "supportxmr" ascii wide nocase
        $pool4 = "moneroocean" ascii wide nocase
        $mining1 = "cryptonight" ascii wide nocase
        $mining2 = "hashrate" ascii wide nocase
    condition:
        any of ($xmr*) or any of ($pool*) or 2 of ($mining*)
}
"#.to_string()),

            // Ransomware indicators
            ("ransomware", r#"
rule RansomwareIndicators {
    meta:
        description = "Common ransomware indicators"
        author = "Synth Security"
        severity = "critical"
    strings:
        $ransom1 = "Your files have been encrypted" ascii wide nocase
        $ransom2 = "bitcoin" ascii wide nocase
        $ransom3 = "decrypt" ascii wide nocase
        $ransom4 = "pay the ransom" ascii wide nocase
        $ransom5 = ".onion" ascii wide
        $ext1 = ".encrypted" ascii wide
        $ext2 = ".locked" ascii wide
        $ext3 = ".crypto" ascii wide
    condition:
        2 of ($ransom*) or (any of ($ext*) and any of ($ransom*))
}
"#.to_string()),

            // Credential harvesting
            ("credentials", r#"
rule CredentialHarvester {
    meta:
        description = "Credential harvesting tool indicators"
        author = "Synth Security"
        severity = "high"
    strings:
        $mimikatz1 = "mimikatz" ascii wide nocase
        $mimikatz2 = "sekurlsa" ascii wide nocase
        $lazagne = "lazagne" ascii wide nocase
        $creds1 = "lsass" ascii wide nocase
        $creds2 = "credential" ascii wide nocase
        $creds3 = "password" ascii wide nocase
        $dump = "dump" ascii wide nocase
    condition:
        any of ($mimikatz*) or $lazagne or (2 of ($creds*) and $dump)
}
"#.to_string()),

            // Persistence mechanisms
            ("persistence", r#"
rule PersistenceMechanism {
    meta:
        description = "Common persistence indicators"
        author = "Synth Security"
        severity = "medium"
    strings:
        $reg1 = "CurrentVersion\\Run" ascii wide nocase
        $reg2 = "CurrentVersion\\RunOnce" ascii wide nocase
        $schtask = "schtasks" ascii wide nocase
        $startup = "Startup" ascii wide nocase
        $cron = "crontab" ascii nocase
        $systemd = "systemctl enable" ascii nocase
    condition:
        any of them
}
"#.to_string()),

            // Data exfiltration
            ("exfiltration", r#"
rule DataExfiltration {
    meta:
        description = "Potential data exfiltration indicators"
        author = "Synth Security"
        severity = "high"
    strings:
        $dns_exfil = /[a-f0-9]{32,}\.[a-z]+\.(com|net|org)/ ascii wide
        $http_exfil = "multipart/form-data" ascii wide
        $curl = "curl -F" ascii wide
        $wget_post = "wget --post" ascii wide
    condition:
        any of them
}
"#.to_string()),
        ]
    }
}

impl Default for YaraEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = YaraEngine::new();
        assert!(engine.rule_count() > 0, "Should have rules loaded");
    }

    #[test]
    fn test_scan_clean_data() {
        let engine = YaraEngine::new();
        let clean_data = b"Hello, this is a normal text file with no threats.";
        let matches = engine.scan_bytes(clean_data);
        assert!(matches.is_empty(), "Clean data should have no matches");
    }

    #[test]
    fn test_scan_suspicious_data() {
        let engine = YaraEngine::new();
        // Contains base64-encoded MZ header
        let suspicious = b"The payload is TVqQAAMAAAAEAAAA hidden in the file";
        let matches = engine.scan_bytes(suspicious);
        assert!(!matches.is_empty(), "Should detect base64 encoded exe");
    }

    #[test]
    fn test_scan_webshell() {
        let engine = YaraEngine::new();
        let webshell = br#"<?php eval(base64_decode($_POST['cmd'])); ?>"#;
        let matches = engine.scan_bytes(webshell);
        assert!(!matches.is_empty(), "Should detect PHP webshell");
    }

    #[test]
    fn test_scan_ransomware_indicators() {
        let engine = YaraEngine::new();
        let ransom_note = b"Your files have been encrypted! Pay bitcoin to decrypt.";
        let matches = engine.scan_bytes(ransom_note);
        assert!(!matches.is_empty(), "Should detect ransomware indicators");
    }
}
