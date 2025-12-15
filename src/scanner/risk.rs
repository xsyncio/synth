//! Risk Scoring Module
//!
//! Contains risk score calculation logic and related utilities.

use crate::models::AssetMetadata;
use super::AdvancedOsintScanner;

/// Calculate the breakdown of risk categories across assets
pub fn calculate_risk_breakdown(assets: &[AssetMetadata]) -> (usize, usize, usize, usize) {
    let mut low = 0;
    let mut medium = 0;
    let mut high = 0;
    let mut critical = 0;

    for asset in assets {
        match asset.risk_score {
            0..=25 => low += 1,
            26..=50 => medium += 1,
            51..=75 => high += 1,
            _ => critical += 1,
        }
    }

    (low, medium, high, critical)
}

/// Calculate risk score for an asset based on various factors
pub fn calculate_risk_score(scanner: &AdvancedOsintScanner, asset: &AssetMetadata) -> u8 {
    let mut score = 0u16;

    // Threat indicators scoring
    for indicator in &asset.threat_indicators {
        score += indicator.confidence as u16;
    }

    // Crypto artifacts scoring
    for crypto in &asset.crypto_artifacts {
        match crypto.crypto_type.as_str() {
            "Bitcoin Address" | "Ethereum Address" => score += 30,
            "PEM Certificate/Key" => score += 20,
            _ => score += 10,
        }
    }

    // Network artifacts scoring
    score += (asset.network_artifacts.len() as u16) * 5;

    // File characteristics
    if asset.is_hidden {
        score += 15;
    }

    if asset.encrypted_content {
        score += 25;
    }

    if asset.steganography_detected {
        score += 40;
    }

    // Entropy scoring
    if let Some(entropy) = asset.entropy {
        if entropy > 7.5 {
            score += 30;
        } else if entropy > 7.0 {
            score += 15;
        }
    }

    // Size-based scoring
    if let Some(size) = asset.size {
        if size == 0 {
            score += 10;
        } else if size > 100 * 1024 * 1024 {
            score += 20;
        }
    }

    // File extension scoring
    if let Some(ext) = asset.path.extension().and_then(|e| e.to_str()) {
        let high_risk_extensions = ["exe", "scr", "bat", "cmd", "ps1", "vbs", "js", "jar"];
        let medium_risk_extensions = ["dll", "sys", "bin", "com", "pif"];

        if high_risk_extensions.contains(&ext.to_lowercase().as_str()) {
            score += 30;
        } else if medium_risk_extensions.contains(&ext.to_lowercase().as_str()) {
            score += 15;
        }
    }

    // Code analysis scoring
    if let Some(obfuscation_str) = asset.code_analysis.get("obfuscation_score") {
        if let Ok(obfuscation_score) = obfuscation_str.parse::<f64>() {
            if obfuscation_score > 0.8 {
                score += 50;
            } else if obfuscation_score > 0.6 {
                score += 25;
            }
        }
    }

    // Detected secrets scoring
    for secret in &asset.detected_secrets {
        match secret.severity.as_str() {
            "critical" => score += 40,
            "high" => score += 25,
            "medium" => score += 15,
            "low" => score += 5,
            _ => score += 10,
        }
    }

    // Use analyzer's obfuscation pattern if available - suppress unused warning
    let _ = &scanner.analyzer;

    (score.min(100)) as u8
}

/// Calculate cyclomatic complexity of code
pub fn calculate_cyclomatic_complexity(code: &str) -> u32 {
    let complexity_keywords = [
        "if", "else", "elif", "while", "for", "switch", "case",
        "catch", "try", "&&", "||", "and", "or"
    ];

    let mut complexity = 1;
    let code_lower = code.to_lowercase();

    for keyword in &complexity_keywords {
        complexity += code_lower.matches(keyword).count() as u32;
    }

    complexity
}

/// Calculate obfuscation score for code
pub fn calculate_obfuscation_score(scanner: &AdvancedOsintScanner, code: &str) -> f64 {
    let mut score = 0.0;
    let total_chars = code.len() as f64;
    
    if total_chars == 0.0 {
        return 0.0;
    }

    // High ratio of non-alphanumeric characters
    let non_alnum = code.chars().filter(|c| !c.is_alphanumeric() && !c.is_whitespace()).count() as f64;
    score += (non_alnum / total_chars) * 0.3;

    // Very long lines (potential minification)
    let long_lines = code.lines().filter(|line| line.len() > 200).count() as f64;
    score += (long_lines / code.lines().count().max(1) as f64) * 0.2;

    // Base64-like patterns
    if let Some(ref pattern) = scanner.analyzer.obfuscation_pattern {
        score += pattern.find_iter(code).count() as f64 * 0.1;
    }

    score.min(1.0)
}
