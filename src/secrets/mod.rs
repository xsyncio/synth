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
    fn test_aws_key_detection() {
        let scanner = SecretScanner::new();
        // AKIA + 16 uppercase alphanumeric chars
        let content = "aws_access_key_id = AKIAIOSFODNN7ABCDEFG";
        
        let secrets = scanner.scan(content);
        let aws_key = secrets.iter().find(|s| s.secret_type == "AWS Access Key ID");
        assert!(aws_key.is_some(), "Should find AWS Access Key ID");
    }

    #[test]
    fn test_github_token_detection() {
        let scanner = SecretScanner::new();
        // ghp_ + 36 alphanumeric chars (no placeholders like xxxx)
        let content = "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
        
        let secrets = scanner.scan(content);
        let github = secrets.iter().find(|s| s.provider == "GitHub");
        assert!(github.is_some(), "Should detect GitHub token");
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
        let content = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyf8UkDwP
-----END RSA PRIVATE KEY-----
        "#;
        
        let secrets = scanner.scan(content);
        let key = secrets.iter().find(|s| s.secret_type == "RSA Private Key");
        assert!(key.is_some(), "Should detect RSA private key");
        assert_eq!(key.unwrap().severity, SecretSeverity::Critical);
    }

    #[test]
    fn test_database_connection_string() {
        let scanner = SecretScanner::new();
        let content = "DATABASE_URL=postgres://admin:MySecureP4ss@db.prod.internal:5432/production_db";
        
        let secrets = scanner.scan(content);
        let db = secrets.iter().find(|s| s.provider == "Database");
        assert!(db.is_some(), "Should detect database connection string");
    }

    #[test]
    fn test_stripe_key_detection() {
        let scanner = SecretScanner::new();
        // Use sk_test_ prefix which is for test keys, not sk_live_
        let content = "STRIPE_KEY=sk_test_EXAMPLE1234567890abcdef";
        
        let secrets = scanner.scan(content);
        let stripe = secrets.iter().find(|s| s.provider == "Stripe");
        assert!(stripe.is_some(), "Should detect Stripe key");
    }

    #[test]
    fn test_slack_token_detection() {
        let scanner = SecretScanner::new();
        // Use obviously fake token with placeholder-like values
        let content = "SLACK_TOKEN=xoxb-000000000000-000000000000-ExampleToken";
        
        let secrets = scanner.scan(content);
        let slack = secrets.iter().find(|s| s.provider == "Slack");
        assert!(slack.is_some(), "Should detect Slack token");
    }
}
