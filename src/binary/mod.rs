//! Binary Analysis Module
//!
//! Analyzes PE (Windows) and ELF (Linux) executable files.
//! Extracts headers, imports, exports, strings, and security features.

mod pe;
mod elf;
mod strings;

use goblin::Object;
use std::collections::HashMap;
use std::path::Path;
use capstone::prelude::*;

/// Result of binary file analysis
#[derive(Debug, Clone, Default)]
pub struct BinaryAnalysis {
    /// Binary format type
    pub format: BinaryFormat,
    /// Architecture (x86, x64, ARM, etc.)
    pub architecture: String,
    /// Entry point address
    pub entry_point: u64,
    /// Whether binary is 64-bit
    pub is_64bit: bool,
    /// Import hash (imphash) for PE files
    pub imphash: Option<String>,
    /// Section information
    pub sections: Vec<SectionInfo>,
    /// Imported libraries
    pub imports: Vec<ImportInfo>,
    /// Exported symbols
    pub exports: Vec<String>,
    /// Extracted strings
    pub strings: Vec<ExtractedString>,
    /// Security features detected
    pub security_features: Vec<String>,
    /// Compiler/linker information
    pub compiler_info: Option<String>,
    /// Packing indicators
    pub packing_indicators: Vec<String>,
    /// Suspicious characteristics
    pub suspicious: Vec<String>,
    /// Fuzzy Hash (SSDeep)
    pub fuzzy_hash: Option<String>,
    /// Disassembly sample
    pub disassembly: Vec<String>,
}

/// Binary format type
#[derive(Debug, Clone, Default, PartialEq)]
pub enum BinaryFormat {
    #[default]
    Unknown,
    PE32,
    PE64,
    ELF32,
    ELF64,
    MachO32,
    MachO64,
    Archive,
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryFormat::Unknown => write!(f, "Unknown"),
            BinaryFormat::PE32 => write!(f, "PE32 (Windows x86)"),
            BinaryFormat::PE64 => write!(f, "PE64 (Windows x64)"),
            BinaryFormat::ELF32 => write!(f, "ELF32 (Linux x86)"),
            BinaryFormat::ELF64 => write!(f, "ELF64 (Linux x64)"),
            BinaryFormat::MachO32 => write!(f, "Mach-O 32-bit (macOS)"),
            BinaryFormat::MachO64 => write!(f, "Mach-O 64-bit (macOS)"),
            BinaryFormat::Archive => write!(f, "Archive (static library)"),
        }
    }
}

/// Section information
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub entropy: f64,
    pub characteristics: Vec<String>,
}

/// Import information
#[derive(Debug, Clone)]
pub struct ImportInfo {
    pub library: String,
    pub functions: Vec<String>,
}

/// Extracted string with context
#[derive(Debug, Clone)]
pub struct ExtractedString {
    pub value: String,
    pub offset: usize,
    pub encoding: StringEncoding,
    pub category: StringCategory,
}

/// String encoding type
#[derive(Debug, Clone, PartialEq)]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
}

/// String category for classification
#[derive(Debug, Clone, PartialEq)]
pub enum StringCategory {
    Url,
    IpAddress,
    FilePath,
    RegistryKey,
    Command,
    Cryptocurrency,
    Email,
    Generic,
}

/// Binary analyzer
pub struct BinaryAnalyzer;

impl BinaryAnalyzer {
    /// Analyze a binary file
    pub fn analyze(path: &Path) -> Option<BinaryAnalysis> {
        let data = std::fs::read(path).ok()?;
        Self::analyze_bytes(&data)
    }

    /// Analyze binary data
    pub fn analyze_bytes(data: &[u8]) -> Option<BinaryAnalysis> {
        let mut analysis = BinaryAnalysis::default();

        match Object::parse(data).ok()? {
            Object::PE(pe) => pe::analyze_pe(&pe, data, &mut analysis),
            Object::Elf(elf) => elf::analyze_elf(&elf, data, &mut analysis),
            Object::Mach(mach) => Self::analyze_mach(&mach, &mut analysis),
            Object::Archive(_) => {
                analysis.format = BinaryFormat::Archive;
            }
            _ => return None,
        }

        // Extract strings from binary
        analysis.strings = strings::extract_strings(data);

        // Compute Fuzzy Hash
        analysis.fuzzy_hash = Self::compute_fuzzy_hash(data);

        Some(analysis)
    }

    /// Analyze Mach-O (macOS) executable
    fn analyze_mach(mach: &goblin::mach::Mach, analysis: &mut BinaryAnalysis) {
        match mach {
            goblin::mach::Mach::Binary(macho) => {
                analysis.format = if macho.is_64 {
                    BinaryFormat::MachO64
                } else {
                    BinaryFormat::MachO32
                };
                analysis.is_64bit = macho.is_64;
                analysis.entry_point = macho.entry;
                analysis.architecture = format!("{:?}", macho.header.cputype());
            }
            goblin::mach::Mach::Fat(_) => {
                analysis.format = BinaryFormat::MachO64;
            }
        }
    }

    /// Calculate import hash (imphash) for PE files
    pub(crate) fn calculate_imphash(imports: &[ImportInfo]) -> Option<String> {
        if imports.is_empty() {
            return None;
        }

        let mut import_string = String::new();
        for imp in imports {
            let dll_name = imp.library.to_lowercase().replace(".dll", "");
            for func in &imp.functions {
                if !import_string.is_empty() {
                    import_string.push(',');
                }
                import_string.push_str(&format!("{}.{}", dll_name, func.to_lowercase()));
            }
        }

        use md5::Digest;
        let mut hasher = md5::Md5::new();
        hasher.update(import_string.as_bytes());
        let result = hasher.finalize();
        Some(hex::encode(result))
    }

    /// Calculate entropy of data
    pub(crate) fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Detect suspicious imports that indicate malicious behavior
    pub(crate) fn detect_suspicious_imports(analysis: &mut BinaryAnalysis) {
        let suspicious_apis: HashMap<&str, &str> = [
            ("VirtualAlloc", "Memory allocation (shellcode)"),
            ("VirtualAllocEx", "Remote memory allocation"),
            ("VirtualProtect", "Memory permission change"),
            ("VirtualProtectEx", "Remote memory protection"),
            ("WriteProcessMemory", "Process injection"),
            ("ReadProcessMemory", "Process memory reading"),
            ("CreateRemoteThread", "Remote thread injection"),
            ("NtCreateThreadEx", "Native thread creation"),
            ("SetWindowsHookEx", "Keyboard/mouse hooking"),
            ("GetAsyncKeyState", "Keylogging"),
            ("CreateToolhelp32Snapshot", "Process enumeration"),
            ("OpenProcess", "Process manipulation"),
            ("AdjustTokenPrivileges", "Privilege escalation"),
            ("LookupPrivilegeValue", "Privilege lookup"),
            ("IsDebuggerPresent", "Anti-debugging"),
            ("CheckRemoteDebuggerPresent", "Anti-debugging"),
            ("NtQueryInformationProcess", "Process info (anti-debug)"),
            ("GetTickCount", "Timing check (sandbox evasion)"),
            ("QueryPerformanceCounter", "Timing check"),
            ("CryptEncrypt", "Encryption (ransomware)"),
            ("CryptDecrypt", "Decryption"),
            ("InternetOpen", "Network communication"),
            ("InternetConnect", "Network connection"),
            ("WSAStartup", "Socket initialization"),
            ("URLDownloadToFile", "File download"),
            ("ShellExecute", "Command execution"),
            ("WinExec", "Command execution"),
            ("CreateProcess", "Process creation"),
            ("RegSetValueEx", "Registry modification"),
            ("RegCreateKey", "Registry key creation"),
        ].iter().cloned().collect();

        for import in &analysis.imports {
            for func in &import.functions {
                if let Some(desc) = suspicious_apis.get(func.as_str()) {
                    analysis.suspicious.push(format!("{}: {} ({})", import.library, func, desc));
                }
            }
        }
    }

    /// Check if a file is a binary executable
    pub fn is_executable(path: &Path) -> bool {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            matches!(
                ext.to_lowercase().as_str(),
                "exe" | "dll" | "sys" | "ocx" | "so" | "dylib" | "bin" | "elf" | "o" | "ko"
            )
        } else {
            if let Ok(data) = std::fs::read(path) {
                if data.len() >= 4 {
                    if data.starts_with(b"MZ") { return true; }
                    if data.starts_with(b"\x7FELF") { return true; }
                    if data.starts_with(&[0xFE, 0xED, 0xFA, 0xCE]) 
                        || data.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])
                        || data.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
                        || data.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
                        return true;
                    }
                }
            }
            false
        }
    }

    /// Compute Fuzzy Hash (SSDeep)
    fn compute_fuzzy_hash(_data: &[u8]) -> Option<String> {
        None
    }

    /// Disassemble a chunk of code
    pub(crate) fn disassemble_chunk(data: &[u8], analysis: &mut BinaryAnalysis, arch: &str) {
        let cs_result = match arch {
            "x64" => Capstone::new().x86().mode(capstone::arch::x86::ArchMode::Mode64).build(),
            "x86" => Capstone::new().x86().mode(capstone::arch::x86::ArchMode::Mode32).build(),
            "ARM" => Capstone::new().arm().mode(capstone::arch::arm::ArchMode::Arm).build(),
            "ARM64" => Capstone::new().arm64().mode(capstone::arch::arm64::ArchMode::Arm).build(),
            _ => return,
        };

        if let Ok(cs) = cs_result {
            let limit = data.len().min(64);
            if let Ok(insns) = cs.disasm_all(&data[..limit], 0x1000) {
                for i in insns.iter() {
                    analysis.disassembly.push(format!("0x{:x}:  {} {}", i.address(), i.mnemonic().unwrap_or(""), i.op_str().unwrap_or("")));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let uniform = vec![0u8; 256];
        let entropy_low = BinaryAnalyzer::calculate_entropy(&uniform);
        assert!(entropy_low < 1.0, "Uniform data should have low entropy");

        let random: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let entropy_high = BinaryAnalyzer::calculate_entropy(&random);
        assert!(entropy_high > 7.0, "Random data should have high entropy");
    }

    #[test]
    fn test_string_categorization() {
        assert_eq!(
            strings::categorize_string("https://malware.com/payload.exe"),
            StringCategory::Url
        );
        assert_eq!(
            strings::categorize_string("192.168.1.1"),
            StringCategory::IpAddress
        );
        assert_eq!(
            strings::categorize_string("test@example.com"),
            StringCategory::Email
        );
        assert_eq!(
            strings::categorize_string("HKEY_LOCAL_MACHINE\\SOFTWARE"),
            StringCategory::RegistryKey
        );
    }

    #[test]
    fn test_ip_detection() {
        assert!(strings::looks_like_ip("192.168.1.1"));
        assert!(strings::looks_like_ip("10.0.0.1"));
        assert!(!strings::looks_like_ip("not.an.ip.address"));
        assert!(!strings::looks_like_ip("256.1.1.1"));
    }
}
