//! Anti-Evasion and Sandbox Detection Module
//!
//! Identifies signs of potential evasion techniques or if the scan target
//! appears to be a virtualized/sandboxed environment (if scanning a system drive).
//! Also detects binaries that employ anti-debugging or anti-VM techniques.

use std::path::Path;
use serde::{Serialize, Deserialize};

/// Anti-Evasion analysis results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AntiEvasionResult {
    /// Detected environment (VM, Sandbox, etc.)
    pub environment_type: Option<String>,
    /// Evidence found (e.g., "VMware Tools file detected")
    pub evidence: Vec<String>,
    /// Anti-debugging techniques detected in binaries
    pub anti_debug_techniques: Vec<String>,
    /// Anti-VM techniques detected
    pub anti_vm_techniques: Vec<String>,
    /// Time-based evasion indicators
    pub time_evasion: bool,
}

pub struct AntiEvasionScanner;

impl AntiEvasionScanner {
    /// Analyze a file or path for anti-evasion artifacts
    pub fn scan_artifact(_path: &Path, filename: &str) -> Option<AntiEvasionResult> {
        let mut result = AntiEvasionResult::default();
        let mut detected = false;
        let lower_name = filename.to_lowercase();

        // 1. VM Artifacts (Files)
        // These are typically drivers or tools found in guest OS
        if lower_name.contains("vbox") || lower_name.contains("virtualbox") {
            result.evidence.push(format!("VirtualBox artifact detected: {}", filename));
            result.environment_type = Some("VirtualBox".to_string());
            detected = true;
        } else if lower_name.contains("vmware") || lower_name.contains("vmtools") {
            result.evidence.push(format!("VMware artifact detected: {}", filename));
            result.environment_type = Some("VMware".to_string());
            detected = true;
        } else if lower_name.contains("qemu") || lower_name.contains("virtio") {
            result.evidence.push(format!("QEMU/KVM artifact detected: {}", filename));
            result.environment_type = Some("QEMU/KVM".to_string());
            detected = true;
        }

        // 2. Sandbox Artifacts (Files)
        if lower_name.contains("cuckoo") {
             result.evidence.push(format!("Cuckoo Sandbox artifact detected: {}", filename));
             result.environment_type = Some("Sandbox (Cuckoo)".to_string());
             detected = true;
        } else if lower_name == "sample.exe" || lower_name == "artifact.exe" {
            // Generic sandbox names often used for submitted files
             result.evidence.push(format!("Generic sandbox filename detected: {}", filename));
             detected = true;
        }

        if detected {
            Some(result)
        } else {
            None
        }
    }

    /// Analyze binary imports/exports for Anti-Debugging/Anti-VM APIs
    /// This requires the checks from binary.rs to be passed in, or we re-scan.
    /// Ideally, we use the `BinaryInfo` from `models.rs`.
    pub fn analyze_binary_features(binary_info: &crate::models::BinaryInfo) -> AntiEvasionResult {
        let mut result = AntiEvasionResult::default();

        // Known Anti-Debugging APIs
        let anti_debug_apis = vec![
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "OutputDebugString",
            "NtQueryInformationProcess", // ProcessDebugPort
            "ZwQueryInformationProcess",
            "UnhandledExceptionFilter", // LdrRegisterDllNotification
        ];

        // Known Anti-VM APIs/Instructions (often imports or specialized calls)
        let anti_vm_apis = vec![
            "GetTickCount", // Timing attacks
            "QueryPerformanceCounter",
            "rdtsc", // Assembly, but if symbol exported/imported? Unlikely as import.
            "cpuid",
        ];

        for imp in &binary_info.suspicious_imports {
            if anti_debug_apis.iter().any(|api| imp.contains(api)) {
                result.anti_debug_techniques.push(imp.clone());
            }
            if anti_vm_apis.iter().any(|api| imp.contains(api)) {
                 result.anti_vm_techniques.push(imp.clone());
                 if imp.contains("GetTickCount") || imp.contains("QueryPerformanceCounter") {
                     result.time_evasion = true;
                 }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_artifact_detection() {
        let path = PathBuf::from("VBoxService.exe");
        let result = AntiEvasionScanner::scan_artifact(&path, "VBoxService.exe").unwrap();
        assert_eq!(result.environment_type, Some("VirtualBox".to_string()));
        assert!(!result.evidence.is_empty());

        let path_vm = PathBuf::from("vmtoolsd.exe");
        let result_vm = AntiEvasionScanner::scan_artifact(&path_vm, "vmtoolsd.exe").unwrap();
        assert_eq!(result_vm.environment_type, Some("VMware".to_string()));
    }

    #[test]
    fn test_binary_feature_detection() {
        // Mock BinaryInfo
        let bin_info = crate::models::BinaryInfo {
            format: "PE".to_string(),
            architecture: "x64".to_string(),
            entry_point: 0,
            imphash: None,
            section_count: 5,
            high_entropy_sections: vec![],
            import_count: 10,
            export_count: 0,
            security_features: vec![],
            suspicious_imports: vec!["IsDebuggerPresent".to_string(), "GetTickCount".to_string()],
            packing_indicators: vec![],
            fuzzy_hash: None,
            disassembly: Vec::new(),
        };

        let result = AntiEvasionScanner::analyze_binary_features(&bin_info);
        assert!(!result.anti_debug_techniques.is_empty());
        assert!(result.anti_debug_techniques.contains(&"IsDebuggerPresent".to_string()));
        assert!(!result.anti_vm_techniques.is_empty());
        assert!(result.time_evasion); // GetTickCount triggers time evasion
    }
}
