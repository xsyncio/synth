use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_info: ScanInfo,
    pub assets: Vec<AssetMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanInfo {
    pub start_time: String,
    pub end_time: String,
    pub duration_seconds: f64,
    pub base_directory: String,
    pub search_pattern: String,
    pub mode: String,
    pub total_files_scanned: u64,
    pub total_bytes_analyzed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetMetadata {
    pub path: PathBuf,
    pub name: String,
    pub size: Option<u64>,
    pub is_file: bool,
    pub is_hidden: bool,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub accessed: Option<String>,
    pub permissions: String,
    pub owner: String,
    
    // Hash information
    pub md5_hash: Option<String>,
    pub sha256_hash: Option<String>,
    pub sha3_hash: Option<String>,
    pub blake3_hash: Option<String>,
    
    // File analysis
    pub mime_type: Option<String>,
    pub file_signature: Option<String>,
    pub entropy: Option<f64>,
    
    // Content analysis
    pub content_matches: Vec<String>,
    pub contains_urls: Vec<String>,
    pub contains_emails: Vec<String>,
    pub contains_credentials: Vec<String>,
    
    // Security artifacts
    pub crypto_artifacts: Vec<CryptoArtifact>,
    pub network_artifacts: Vec<NetworkArtifact>,
    pub threat_indicators: Vec<ThreatIndicator>,
    pub forensic_evidence: Vec<ForensicEvidence>,
    
    // Advanced analysis
    pub metadata_analysis: HashMap<String, String>,
    pub steganography_detected: bool,
    pub encrypted_content: bool,
    pub code_analysis: HashMap<String, String>,
    
    // Risk assessment
    pub risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkArtifact {
    pub artifact_type: String,
    pub value: String,
    pub context: String,
    pub confidence: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoArtifact {
    pub crypto_type: String,
    pub value: String,
    pub algorithm: Option<String>,
    pub strength: String,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicEvidence {
    pub evidence_type: String,
    pub description: String,
    pub confidence: u8,
    pub technical_details: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: String,
    pub value: String,
    pub confidence: u8,
    pub description: String,
}

impl AssetMetadata {
    pub fn new(path: PathBuf, name: String) -> Self {
        Self {
            path,
            name,
            size: None,
            is_file: false,
            is_hidden: false,
            created: None,
            modified: None,
            accessed: None,
            permissions: String::new(),
            owner: String::new(),
            md5_hash: None,
            sha256_hash: None,
            sha3_hash: None,
            blake3_hash: None,
            mime_type: None,
            file_signature: None,
            entropy: None,
            content_matches: Vec::new(),
            contains_urls: Vec::new(),
            contains_emails: Vec::new(),
            contains_credentials: Vec::new(),
            crypto_artifacts: Vec::new(),
            network_artifacts: Vec::new(),
            threat_indicators: Vec::new(),
            forensic_evidence: Vec::new(),
            metadata_analysis: HashMap::new(),
            steganography_detected: false,
            encrypted_content: false,
            code_analysis: HashMap::new(),
            risk_score: 0,
        }
    }
}