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
    pub scan_timestamp: String,
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
    pub entropy_map: Vec<f64>,
    
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
    
    // Secret detection
    pub detected_secrets: Vec<SecretFinding>,
    
    // EXIF/Metadata extraction
    pub exif_data: HashMap<String, String>,
    pub gps_coordinates: Option<String>,
    
    // YARA rule matches
    pub yara_matches: Vec<YaraMatchResult>,
    
    // Binary analysis (PE/ELF)
    pub binary_info: Option<BinaryInfo>,
    
    // Forensic analysis
    pub forensic_analysis: Option<ForensicAnalysis>,

    // Anti-Evasion / Environment
    pub anti_evasion: Option<crate::anti_evasion::AntiEvasionResult>,

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
    pub description: String,
    pub source: String,
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

/// Detected secret/credential finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    /// Type of secret (e.g., "AWS Access Key ID", "GitHub Token")
    pub secret_type: String,
    /// Provider/service name (e.g., "AWS", "GitHub", "Stripe")
    pub provider: String,
    /// The detected value (redacted in reports for security)
    pub value_redacted: String,
    /// Surrounding context
    pub context: String,
    /// Confidence score 0-100
    pub confidence: u8,
    /// Severity: low, medium, high, critical
    pub severity: String,
    /// Whether the format was validated
    pub validated: bool,
    /// Line number if available
    pub line_number: Option<usize>,
}

/// YARA rule match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatchResult {
    /// Rule name that matched
    pub rule_name: String,
    /// Rule namespace/category
    pub namespace: String,
    /// Rule tags
    pub tags: Vec<String>,
    /// Confidence score 0-100
    pub confidence: u8,
}

/// Binary analysis information for executables
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    /// Binary format (PE32, PE64, ELF32, ELF64, etc.)
    pub format: String,
    /// Architecture (x86, x64, ARM, etc.)
    pub architecture: String,
    /// Entry point address
    pub entry_point: u64,
    /// Import hash for malware classification
    pub imphash: Option<String>,
    /// Number of sections
    pub section_count: usize,
    /// High entropy sections (possibly packed)
    pub high_entropy_sections: Vec<String>,
    /// Imported libraries count
    pub import_count: usize,
    /// Exported symbols count  
    pub export_count: usize,
    /// Security features detected
    pub security_features: Vec<String>,
    /// Suspicious API calls detected
    pub suspicious_imports: Vec<String>,
    /// Packing indicators
    pub packing_indicators: Vec<String>,
    /// Fuzzy Hash (SSDeep)
    pub fuzzy_hash: Option<String>,
    /// Disassembly sample
    pub disassembly: Vec<String>,
}

/// Forensic analysis results to be stored in metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ForensicAnalysis {
    pub event_logs: Vec<EventLogEntry>,
    pub browser_history: Vec<BrowserHistoryEntry>,
    pub prefetch_info: Vec<PrefetchEntry>,
    /// Recovered/Carved files
    pub recovered_files: Vec<CarvedFile>,
    /// General forensic evidence (e.g. from PDF/Archive analysis)
    pub evidence: Vec<ForensicEvidence>,
    /// Windows Registry artifacts
    pub registry_keys: Vec<RegistryEntry>,
    /// LNK File artifacts
    pub lnk_files: Vec<LnkFileEntry>,
    /// Recycle Bin artifacts
    pub recycle_bin: Vec<RecycleBinEntry>,
    /// Linux Shell History
    pub shell_history: Vec<ShellHistoryEntry>,
    /// SSH Trust relationships
    pub ssh_keys: Vec<SshKeyEntry>,
    /// Cron Jobs
    pub cron_jobs: Vec<CronJobEntry>,
    /// System Logs of interest
    pub system_logs: Vec<SystemLogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogEntry {
    pub event_id: u32,
    pub timestamp: String,
    pub level: String,
    pub channel: String,
    pub computer: String,
    pub sid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserHistoryEntry {
    pub url: String,
    pub title: String,
    pub visit_count: i64,
    pub last_visit: String,
    pub browser: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchEntry {
    pub executable: String,
    pub hash: String,
    pub run_count: u32,
    pub last_run_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedFile {
    pub file_type: String,
    pub offset: u64,
    pub size: u64,
    pub recovered_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub hive: String,
    pub key: String,
    pub value_name: String,
    pub value_data: String,
    pub last_write: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnkFileEntry {
    pub path: String,
    pub target_path: String,
    pub arguments: String,
    pub working_dir: String,
    pub created: String,
    pub modified: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecycleBinEntry {
    pub original_path: String,
    pub deleted_time: String,
    pub file_size: u64,
    pub recycle_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellHistoryEntry {
    pub shell_type: String,
    pub command: String,
    pub timestamp: String, // If available
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyEntry {
    pub file_path: String,
    pub key_type: String, // RSA, ED25519
    pub comment: String,
    pub origin: String, // "authorized_keys" or "known_hosts"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronJobEntry {
    pub file_path: String,
    pub schedule: String,
    pub command: String,
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemLogEntry {
    pub service: String, // sshd, sudo
    pub message: String,
    pub timestamp: String,
    pub severity: String,
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
            entropy_map: Vec::new(),
            content_matches: Vec::new(),
            contains_urls: Vec::new(),
            contains_emails: Vec::new(),
            contains_credentials: Vec::new(),
            crypto_artifacts: Vec::new(),
            network_artifacts: Vec::new(),
            threat_indicators: Vec::new(),
            forensic_evidence: Vec::new(),
            detected_secrets: Vec::new(),
            exif_data: HashMap::new(),
            gps_coordinates: None,
            yara_matches: Vec::new(),
            binary_info: None,
            forensic_analysis: Some(ForensicAnalysis::default()),
            anti_evasion: None,
            metadata_analysis: HashMap::new(),
            steganography_detected: false,
            encrypted_content: false,
            code_analysis: HashMap::new(),
            risk_score: 0,
        }
    }
}