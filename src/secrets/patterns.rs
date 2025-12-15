//! Secret Pattern Definitions
//!
//! Contains 55+ pattern definitions for detecting API keys, tokens, passwords, and credentials.

use super::{SecretPattern, SecretSeverity};

/// Get all pattern definitions for secret detection
pub fn get_pattern_definitions() -> Vec<SecretPattern> {
    vec![
        // AWS
        SecretPattern {
            name: "AWS Access Key ID",
            provider: "AWS",
            pattern: r"(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}",
            severity: SecretSeverity::Critical,
            confidence: 95,
        },
        SecretPattern {
            name: "AWS Session Token",
            provider: "AWS",
            pattern: r"FwoGZXIvYXdzE[A-Za-z0-9/+=]{100,}",
            severity: SecretSeverity::Critical,
            confidence: 90,
        },

        // Google Cloud
        SecretPattern {
            name: "GCP API Key",
            provider: "Google Cloud",
            pattern: r"AIza[0-9A-Za-z_-]{35}",
            severity: SecretSeverity::High,
            confidence: 90,
        },
        SecretPattern {
            name: "GCP OAuth Client ID",
            provider: "Google Cloud",
            pattern: r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com",
            severity: SecretSeverity::Medium,
            confidence: 95,
        },

        // Azure
        SecretPattern {
            name: "Azure Storage Account Key",
            provider: "Azure",
            pattern: r"(?i)AccountKey\s*=\s*[A-Za-z0-9+/=]{88}",
            severity: SecretSeverity::Critical,
            confidence: 90,
        },
        SecretPattern {
            name: "Azure Connection String",
            provider: "Azure",
            pattern: r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
            severity: SecretSeverity::Critical,
            confidence: 95,
        },

        // GitHub
        SecretPattern {
            name: "GitHub Personal Access Token",
            provider: "GitHub",
            pattern: r"ghp_[a-zA-Z0-9]{36}",
            severity: SecretSeverity::Critical,
            confidence: 98,
        },
        SecretPattern {
            name: "GitHub OAuth Token",
            provider: "GitHub",
            pattern: r"gho_[a-zA-Z0-9]{36}",
            severity: SecretSeverity::Critical,
            confidence: 98,
        },
        SecretPattern {
            name: "GitHub App Token",
            provider: "GitHub",
            pattern: r"(?:ghu|ghs)_[a-zA-Z0-9]{36}",
            severity: SecretSeverity::Critical,
            confidence: 98,
        },
        SecretPattern {
            name: "GitHub Refresh Token",
            provider: "GitHub",
            pattern: r"ghr_[a-zA-Z0-9]{36}",
            severity: SecretSeverity::Critical,
            confidence: 98,
        },
        SecretPattern {
            name: "GitHub Fine-grained PAT",
            provider: "GitHub",
            pattern: r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
            severity: SecretSeverity::Critical,
            confidence: 99,
        },

        // GitLab
        SecretPattern {
            name: "GitLab Personal Access Token",
            provider: "GitLab",
            pattern: r"glpat-[a-zA-Z0-9_-]{20}",
            severity: SecretSeverity::Critical,
            confidence: 98,
        },
        SecretPattern {
            name: "GitLab Pipeline Token",
            provider: "GitLab",
            pattern: r"glptt-[a-zA-Z0-9_-]{40}",
            severity: SecretSeverity::High,
            confidence: 98,
        },
        SecretPattern {
            name: "GitLab Runner Token",
            provider: "GitLab",
            pattern: r"glrt-[a-zA-Z0-9_-]{20}",
            severity: SecretSeverity::High,
            confidence: 98,
        },

        // Slack
        SecretPattern {
            name: "Slack Bot Token",
            provider: "Slack",
            pattern: r"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
            severity: SecretSeverity::Critical,
            confidence: 95,
        },
        SecretPattern {
            name: "Slack User Token",
            provider: "Slack",
            pattern: r"xoxp-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
            severity: SecretSeverity::Critical,
            confidence: 95,
        },
        SecretPattern {
            name: "Slack Webhook URL",
            provider: "Slack",
            pattern: r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}",
            severity: SecretSeverity::Medium,
            confidence: 98,
        },

        // Discord
        SecretPattern {
            name: "Discord Bot Token",
            provider: "Discord",
            pattern: r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}",
            severity: SecretSeverity::Critical,
            confidence: 90,
        },
        SecretPattern {
            name: "Discord Webhook URL",
            provider: "Discord",
            pattern: r"https://discord(?:app)?\.com/api/webhooks/[0-9]{18,}/[A-Za-z0-9_-]{60,}",
            severity: SecretSeverity::Medium,
            confidence: 98,
        },

        // Stripe
        SecretPattern {
            name: "Stripe Live Secret Key",
            provider: "Stripe",
            pattern: r"sk_live_[0-9a-zA-Z]{24,}",
            severity: SecretSeverity::Critical,
            confidence: 98,
        },
        SecretPattern {
            name: "Stripe Test Secret Key",
            provider: "Stripe",
            pattern: r"sk_test_[0-9a-zA-Z]{24,}",
            severity: SecretSeverity::Low,
            confidence: 98,
        },
        SecretPattern {
            name: "Stripe Live Publishable Key",
            provider: "Stripe",
            pattern: r"pk_live_[0-9a-zA-Z]{24,}",
            severity: SecretSeverity::Medium,
            confidence: 98,
        },
        SecretPattern {
            name: "Stripe Restricted Key",
            provider: "Stripe",
            pattern: r"rk_live_[0-9a-zA-Z]{24,}",
            severity: SecretSeverity::High,
            confidence: 98,
        },

        // Twilio
        SecretPattern {
            name: "Twilio Account SID",
            provider: "Twilio",
            pattern: r"AC[a-f0-9]{32}",
            severity: SecretSeverity::Medium,
            confidence: 95,
        },
        SecretPattern {
            name: "Twilio API Key",
            provider: "Twilio",
            pattern: r"SK[a-f0-9]{32}",
            severity: SecretSeverity::High,
            confidence: 90,
        },

        // SendGrid
        SecretPattern {
            name: "SendGrid API Key",
            provider: "SendGrid",
            pattern: r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
            severity: SecretSeverity::High,
            confidence: 98,
        },

        // Mailgun
        SecretPattern {
            name: "Mailgun API Key",
            provider: "Mailgun",
            pattern: r"key-[a-zA-Z0-9]{32}",
            severity: SecretSeverity::High,
            confidence: 90,
        },

        // Telegram
        SecretPattern {
            name: "Telegram Bot Token",
            provider: "Telegram",
            pattern: r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}",
            severity: SecretSeverity::High,
            confidence: 85,
        },

        // Firebase
        SecretPattern {
            name: "Firebase Database URL",
            provider: "Firebase",
            pattern: r"https://[a-z0-9-]+\.firebaseio\.com",
            severity: SecretSeverity::Medium,
            confidence: 95,
        },
        SecretPattern {
            name: "Firebase Cloud Messaging Key",
            provider: "Firebase",
            pattern: r"AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}",
            severity: SecretSeverity::High,
            confidence: 90,
        },

        // npm
        SecretPattern {
            name: "npm Access Token",
            provider: "npm",
            pattern: r"npm_[a-zA-Z0-9]{36}",
            severity: SecretSeverity::High,
            confidence: 98,
        },

        // PyPI
        SecretPattern {
            name: "PyPI API Token",
            provider: "PyPI",
            pattern: r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}",
            severity: SecretSeverity::High,
            confidence: 98,
        },

        // Docker Hub
        SecretPattern {
            name: "Docker Hub Access Token",
            provider: "Docker",
            pattern: r"dckr_pat_[A-Za-z0-9_-]{27}",
            severity: SecretSeverity::High,
            confidence: 98,
        },

        // Heroku
        SecretPattern {
            name: "Heroku API Key",
            provider: "Heroku",
            pattern: r"[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
            severity: SecretSeverity::High,
            confidence: 85,
        },

        // DigitalOcean
        SecretPattern {
            name: "DigitalOcean Personal Access Token",
            provider: "DigitalOcean",
            pattern: r"dop_v1_[a-f0-9]{64}",
            severity: SecretSeverity::Critical,
            confidence: 98,
        },
        SecretPattern {
            name: "DigitalOcean OAuth Token",
            provider: "DigitalOcean",
            pattern: r"doo_v1_[a-f0-9]{64}",
            severity: SecretSeverity::Critical,
            confidence: 98,
        },
        SecretPattern {
            name: "DigitalOcean Refresh Token",
            provider: "DigitalOcean",
            pattern: r"dor_v1_[a-f0-9]{64}",
            severity: SecretSeverity::Critical,
            confidence: 98,
        },

        // PayPal
        SecretPattern {
            name: "PayPal Braintree Access Token",
            provider: "PayPal",
            pattern: r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
            severity: SecretSeverity::Critical,
            confidence: 95,
        },

        // Square
        SecretPattern {
            name: "Square Access Token",
            provider: "Square",
            pattern: r"sq0atp-[0-9A-Za-z_-]{22}",
            severity: SecretSeverity::Critical,
            confidence: 95,
        },
        SecretPattern {
            name: "Square OAuth Secret",
            provider: "Square",
            pattern: r"sq0csp-[0-9A-Za-z_-]{43}",
            severity: SecretSeverity::Critical,
            confidence: 95,
        },

        // Shopify
        SecretPattern {
            name: "Shopify Access Token",
            provider: "Shopify",
            pattern: r"shpat_[a-fA-F0-9]{32}",
            severity: SecretSeverity::Critical,
            confidence: 98,
        },
        SecretPattern {
            name: "Shopify Custom App Token",
            provider: "Shopify",
            pattern: r"shpca_[a-fA-F0-9]{32}",
            severity: SecretSeverity::Critical,
            confidence: 98,
        },
        SecretPattern {
            name: "Shopify Private App Token",
            provider: "Shopify",
            pattern: r"shppa_[a-fA-F0-9]{32}",
            severity: SecretSeverity::Critical,
            confidence: 98,
        },
        SecretPattern {
            name: "Shopify Shared Secret",
            provider: "Shopify",
            pattern: r"shpss_[a-fA-F0-9]{32}",
            severity: SecretSeverity::Critical,
            confidence: 98,
        },

        // OpenAI
        SecretPattern {
            name: "OpenAI API Key",
            provider: "OpenAI",
            pattern: r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}",
            severity: SecretSeverity::High,
            confidence: 95,
        },
        SecretPattern {
            name: "OpenAI Project Key",
            provider: "OpenAI",
            pattern: r"sk-proj-[a-zA-Z0-9]{48}",
            severity: SecretSeverity::High,
            confidence: 98,
        },

        // HashiCorp Vault
        SecretPattern {
            name: "HashiCorp Vault Token",
            provider: "HashiCorp",
            pattern: r"hvs\.[a-zA-Z0-9_-]{24,}",
            severity: SecretSeverity::Critical,
            confidence: 95,
        },
        SecretPattern {
            name: "HashiCorp Vault Batch Token",
            provider: "HashiCorp",
            pattern: r"hvb\.[a-zA-Z0-9_-]{24,}",
            severity: SecretSeverity::Critical,
            confidence: 95,
        },

        // SSH and Cryptographic Keys
        SecretPattern {
            name: "RSA Private Key",
            provider: "SSH/Crypto",
            pattern: r"-----BEGIN RSA PRIVATE KEY-----",
            severity: SecretSeverity::Critical,
            confidence: 99,
        },
        SecretPattern {
            name: "OpenSSH Private Key",
            provider: "SSH/Crypto",
            pattern: r"-----BEGIN OPENSSH PRIVATE KEY-----",
            severity: SecretSeverity::Critical,
            confidence: 99,
        },
        SecretPattern {
            name: "DSA Private Key",
            provider: "SSH/Crypto",
            pattern: r"-----BEGIN DSA PRIVATE KEY-----",
            severity: SecretSeverity::Critical,
            confidence: 99,
        },
        SecretPattern {
            name: "EC Private Key",
            provider: "SSH/Crypto",
            pattern: r"-----BEGIN EC PRIVATE KEY-----",
            severity: SecretSeverity::Critical,
            confidence: 99,
        },
        SecretPattern {
            name: "PGP Private Key",
            provider: "SSH/Crypto",
            pattern: r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            severity: SecretSeverity::Critical,
            confidence: 99,
        },
        SecretPattern {
            name: "Encrypted Private Key",
            provider: "SSH/Crypto",
            pattern: r"-----BEGIN ENCRYPTED PRIVATE KEY-----",
            severity: SecretSeverity::Critical,
            confidence: 99,
        },

        // JWT Tokens
        SecretPattern {
            name: "JSON Web Token",
            provider: "JWT",
            pattern: r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            severity: SecretSeverity::High,
            confidence: 90,
        },

        // Database Connection Strings
        SecretPattern {
            name: "PostgreSQL Connection String",
            provider: "Database",
            pattern: r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\S+",
            severity: SecretSeverity::Critical,
            confidence: 95,
        },
        SecretPattern {
            name: "MySQL Connection String",
            provider: "Database",
            pattern: r"mysql://[^:]+:[^@]+@[^/]+/\S+",
            severity: SecretSeverity::Critical,
            confidence: 95,
        },
        SecretPattern {
            name: "MongoDB Connection String",
            provider: "Database",
            pattern: r"mongodb(?:\+srv)?://[^:]+:[^@]+@\S+",
            severity: SecretSeverity::Critical,
            confidence: 95,
        },
        SecretPattern {
            name: "Redis Connection String",
            provider: "Database",
            pattern: r"redis://[^:]+:[^@]+@[^/]+(?:/[0-9]+)?",
            severity: SecretSeverity::Critical,
            confidence: 95,
        },

        // Generic Patterns
        SecretPattern {
            name: "Generic API Key",
            provider: "Generic",
            pattern: r"(?i)api[_-]?key[=:]\s*[a-zA-Z0-9_-]{20,}",
            severity: SecretSeverity::High,
            confidence: 70,
        },
        SecretPattern {
            name: "Generic Secret",
            provider: "Generic",
            pattern: r"(?i)secret[=:]\s*[a-zA-Z0-9_-]{20,}",
            severity: SecretSeverity::High,
            confidence: 65,
        },
        SecretPattern {
            name: "Generic Password",
            provider: "Generic",
            pattern: r"(?i)(?:password|passwd|pwd)[=:]\s*\S{8,}",
            severity: SecretSeverity::High,
            confidence: 60,
        },
        SecretPattern {
            name: "Bearer Token",
            provider: "Generic",
            pattern: r"(?i)bearer\s+[a-zA-Z0-9._-]{20,}",
            severity: SecretSeverity::High,
            confidence: 80,
        },
        SecretPattern {
            name: "Basic Auth Header",
            provider: "Generic",
            pattern: r"(?i)basic\s+[A-Za-z0-9+/=]{20,}",
            severity: SecretSeverity::High,
            confidence: 85,
        },
    ]
}
