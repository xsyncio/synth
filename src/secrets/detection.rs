//! Secret Detection Helper Functions
//!
//! Contains placeholder filtering, context extraction, and format validation.

use super::SecretScanner;

impl SecretScanner {
    /// Check if a value looks like a placeholder
    pub(crate) fn is_placeholder(&self, value: &str) -> bool {
        let lower = value.to_lowercase();
        self.placeholder_keywords.iter().any(|kw| lower.contains(kw))
    }

    /// Extract surrounding context
    pub(crate) fn extract_context(content: &str, start: usize, end: usize) -> String {
        let context_size = 40;
        let ctx_start = start.saturating_sub(context_size);
        let ctx_end = (end + context_size).min(content.len());
        
        content[ctx_start..ctx_end]
            .replace('\n', " ")
            .replace('\r', "")
    }

    /// Validate format-specific rules
    pub(crate) fn validate_format(&self, value: &str, secret_type: &str) -> bool {
        match secret_type {
            "AWS Access Key ID" => {
                value.len() == 20 && value.starts_with("AKIA")
            }
            "GitHub Personal Access Token" => {
                value.starts_with("ghp_") && value.len() == 40
            }
            "GitHub OAuth Token" => {
                value.starts_with("gho_") && value.len() == 40
            }
            "Stripe Live Secret Key" | "Stripe Test Secret Key" => {
                value.starts_with("sk_live_") || value.starts_with("sk_test_")
            }
            "Slack Token" => {
                value.starts_with("xox")
            }
            "Discord Bot Token" => {
                value.contains('.') && value.len() > 50
            }
            _ => true,
        }
    }
}
