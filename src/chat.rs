use crate::models::{AssetMetadata, ForensicEvidence};
use std::path::Path;

#[derive(Default)]
pub struct ChatAnalyzer;

impl ChatAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, path: &Path, metadata: &mut AssetMetadata) {
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let path_str = path.to_string_lossy();

        // Signal
        if filename == "db.sqlite" && path_str.contains("Signal") {
            metadata.forensic_evidence.push(ForensicEvidence {
                evidence_type: "Chat Database".to_string(),
                description: "Signal Desktop Database detected (Encrypted)".to_string(),
                confidence: 100,
                technical_details: std::collections::HashMap::from([
                    ("app".to_string(), "Signal".to_string()),
                    ("path".to_string(), path_str.to_string()),
                ]),
            });
            // We could try to read config.json for the key if we were really aggressive,
            // but that's complex (decryption). Flagging is P0.
        }

        // Telegram
        // Telegram uses "tdata" folder, often has "key_datas" or "maps"
        if filename == "key_datas" && path_str.contains("tdata") {
             metadata.forensic_evidence.push(ForensicEvidence {
                evidence_type: "Chat Configuration".to_string(),
                description: "Telegram Desktop Key Data detected".to_string(),
                confidence: 90,
                technical_details: std::collections::HashMap::from([
                    ("app".to_string(), "Telegram".to_string()),
                ]),
            });
        }
        
        // Slack (LevelDB / Cache)
        if path_str.contains("Slack") && (filename == "Cookies" || filename.ends_with(".log")) {
             metadata.forensic_evidence.push(ForensicEvidence {
                evidence_type: "Chat Artifact".to_string(),
                description: format!("Slack Desktop Artifact: {}", filename),
                confidence: 80,
                technical_details: std::collections::HashMap::from([
                    ("app".to_string(), "Slack".to_string()),
                ]),
            });
        }
        
        // Skype (main.db)
        if filename == "main.db" && path_str.contains("Skype") {
             metadata.forensic_evidence.push(ForensicEvidence {
                evidence_type: "Chat Database".to_string(),
                description: "Skype Database detected".to_string(),
                confidence: 95,
                technical_details: std::collections::HashMap::from([
                    ("app".to_string(), "Skype".to_string()),
                ]),
            });
        }
    }
}
