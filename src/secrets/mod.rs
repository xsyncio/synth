//! Comprehensive Secret Detection Module
//!
//! Detects API keys, tokens, passwords, and credentials from 50+ providers.
//! All patterns are free/open-source - no paid APIs required.

mod detection;
mod patterns;

use regex::Regex;

/// Detected secret with metadata
#[derive(Debug, Clone)]
pub struct DetectedSecret {
    /// Type of secret (e.g., "AWS Access Key", "GitHub Token")
    pub secret_type: String,
    /// Provider/service name
    pub provider: String,
    /// The detected value (may be partially redacted in reports)
    pub value: String,
    /// Surrounding context
    pub context: String,
    /// Confidence score 0-100
    pub confidence: u8,
    /// Severity: low, medium, high, critical
    pub severity: SecretSeverity,
    /// Whether the format was validated
    pub validated: bool,
    /// Line number if available
    pub line_number: Option<usize>,
}

/// Secret severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for SecretSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretSeverity::Low => write!(f, "low"),
            SecretSeverity::Medium => write!(f, "medium"),
            SecretSeverity::High => write!(f, "high"),
            SecretSeverity::Critical => write!(f, "critical"),
        }
    }
}

/// Pattern definition for secret detection
pub(crate) struct SecretPattern {
    pub name: &'static str,
    pub provider: &'static str,
    pub pattern: &'static str,
    pub severity: SecretSeverity,
    pub confidence: u8,
}

/// Comprehensive secret scanner
pub struct SecretScanner {
    patterns: Vec<(Regex, SecretPattern)>,
    /// Keywords that indicate a value might be a placeholder
    pub(crate) placeholder_keywords: Vec<&'static str>,
}

impl SecretScanner {
    /// Create a new secret scanner with all patterns compiled
    pub fn new() -> Self {
        let pattern_defs = patterns::get_pattern_definitions();
        let mut compiled_patterns = Vec::with_capacity(pattern_defs.len());

        for def in pattern_defs {
            match Regex::new(def.pattern) {
                Ok(re) => compiled_patterns.push((re, def)),
                Err(e) => {
                    log::warn!("Failed to compile secret pattern '{}': {}", def.name, e);
                }
            }
        }

        Self {
            patterns: compiled_patterns,
            placeholder_keywords: vec![
                "example", "test", "sample", "demo", "placeholder", "your_",
                "xxx", "yyy", "zzz", "insert", "replace", "todo", "fixme",
                "dummy", "fake", "mock", "temp",
            ],
        }
    }

    /// Scan content for secrets
    pub fn scan(&self, content: &str) -> Vec<DetectedSecret> {
        let mut secrets = Vec::new();

        for (regex, pattern) in &self.patterns {
            for mat in regex.find_iter(content) {
                let value = mat.as_str().to_string();
                
                // Skip obvious placeholders
                if self.is_placeholder(&value) {
                    continue;
                }

                // Calculate line number
                let line_number = content[..mat.start()]
                    .chars()
                    .filter(|c| *c == '\n')
                    .count() + 1;

                let secret = DetectedSecret {
                    secret_type: pattern.name.to_string(),
                    provider: pattern.provider.to_string(),
                    value: value.clone(),
                    context: Self::extract_context(content, mat.start(), mat.end()),
                    confidence: pattern.confidence,
                    severity: pattern.severity,
                    validated: self.validate_format(&value, pattern.name),
                    line_number: Some(line_number),
                };

                secrets.push(secret);
            }
        }

        // Deduplicate
        secrets.sort_by(|a, b| a.value.cmp(&b.value));
        secrets.dedup_by(|a, b| a.value == b.value);

        secrets
    }

    /// Get count of loaded patterns
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = SecretScanner::new();
        assert!(scanner.pattern_count() > 40, "Should have 40+ patterns loaded");
    }

    #[test]
    fn test_placeholder_filtering() {
        let scanner = SecretScanner::new();
        let content = r#"
            API_KEY = "your_api_key_here"
            SECRET = "example_secret_xxxxx"
        "#;
        
        let secrets = scanner.scan(content);
        // Placeholders should be filtered out
        assert!(secrets.is_empty() || secrets.iter().all(|s| s.confidence < 60));
    }

    #[test]
    fn test_private_key_detection() {
        let scanner = SecretScanner::new();
        // RSA private key header - this is safe because it's just the header, not a real key
        let content = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyf8UkDwP
-----END RSA PRIVATE KEY-----
        "#;
        
        let secrets = scanner.scan(content);
        let key = secrets.iter().find(|s| s.secret_type == "RSA Private Key");
        assert!(key.is_some(), "Should detect RSA private key header");
        assert_eq!(key.unwrap().severity, SecretSeverity::Critical);
    }

    #[test]
    fn test_database_connection_string() {
        let scanner = SecretScanner::new();
        // Database URL with generic credentials
        let content = "DATABASE_URL=postgres://user:pass@localhost:5432/db";
        
        let secrets = scanner.scan(content);
        let db = secrets.iter().find(|s| s.provider == "Database");
        assert!(db.is_some(), "Should detect database connection string");
    }

    #[test]
    fn test_generic_api_key_detection() {
        let scanner = SecretScanner::new();
        // Generic API key pattern
        let content = "api_key=abcdefghijklmnopqrstuvwxyz123456";
        
        let secrets = scanner.scan(content);
        let generic = secrets.iter().find(|s| s.secret_type == "Generic API Key");
        assert!(generic.is_some(), "Should detect generic API key pattern");
    }

    #[test]
    fn test_bearer_token_detection() {
        let scanner = SecretScanner::new();
        // Bearer token pattern
        let content = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz";
        
        let secrets = scanner.scan(content);
        let bearer = secrets.iter().find(|s| s.secret_type == "Bearer Token");
        assert!(bearer.is_some(), "Should detect bearer token");
    }
}

