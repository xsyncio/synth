//! PE (Windows) Binary Analysis

use super::{BinaryAnalysis, BinaryAnalyzer, BinaryFormat, ImportInfo, SectionInfo};

/// Analyze PE (Windows) executable
pub fn analyze_pe(pe: &goblin::pe::PE, data: &[u8], analysis: &mut BinaryAnalysis) {
    // Set format
    analysis.format = if pe.is_64 {
        BinaryFormat::PE64
    } else {
        BinaryFormat::PE32
    };
    analysis.is_64bit = pe.is_64;
    analysis.architecture = if pe.is_64 { "x64".to_string() } else { "x86".to_string() };
    analysis.entry_point = pe.entry as u64;

    // Parse sections
    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name).trim_matches('\0').to_string();
        let entropy = BinaryAnalyzer::calculate_entropy(
            &data[section.pointer_to_raw_data as usize..
                (section.pointer_to_raw_data + section.size_of_raw_data) as usize]
        );

        let mut characteristics = Vec::new();
        if section.characteristics & 0x20000000 != 0 { characteristics.push("EXECUTE".to_string()); }
        if section.characteristics & 0x40000000 != 0 { characteristics.push("READ".to_string()); }
        if section.characteristics & 0x80000000 != 0 { characteristics.push("WRITE".to_string()); }

        if entropy > 7.0 {
            analysis.packing_indicators.push(format!("High entropy section: {} ({:.2})", name, entropy));
        }

        analysis.sections.push(SectionInfo {
            name,
            virtual_address: section.virtual_address as u64,
            virtual_size: section.virtual_size as u64,
            raw_size: section.size_of_raw_data as u64,
            entropy,
            characteristics,
        });
    }

    // Parse imports
    for import in &pe.imports {
        let lib_name = import.dll.to_string();
        
        if let Some(lib_info) = analysis.imports.iter_mut().find(|i| i.library == lib_name) {
            lib_info.functions.push(import.name.to_string());
        } else {
            analysis.imports.push(ImportInfo {
                library: lib_name,
                functions: vec![import.name.to_string()],
            });
        }
    }

    // Calculate imphash
    analysis.imphash = BinaryAnalyzer::calculate_imphash(&analysis.imports);

    // Parse exports
    for export in &pe.exports {
        if let Some(name) = export.name {
            analysis.exports.push(name.to_string());
        }
    }

    // Detect security features
    detect_pe_security_features(pe, analysis);

    // Detect suspicious imports
    BinaryAnalyzer::detect_suspicious_imports(analysis);

    // Disassemble Entry Point
    let mut entry_offset = 0;
    for section in &pe.sections {
         if pe.entry >= section.virtual_address as usize && pe.entry < (section.virtual_address + section.virtual_size) as usize {
             entry_offset = pe.entry - section.virtual_address as usize + section.pointer_to_raw_data as usize;
             break;
         }
    }
    if entry_offset > 0 && entry_offset < data.len() {
         BinaryAnalyzer::disassemble_chunk(&data[entry_offset..], analysis, if pe.is_64 { "x64" } else { "x86" });
    }
}

/// Detect PE security features
fn detect_pe_security_features(pe: &goblin::pe::PE, analysis: &mut BinaryAnalysis) {
    if let Some(optional) = pe.header.optional_header {
        let dll_chars = optional.windows_fields.dll_characteristics;
        
        if dll_chars & 0x0040 != 0 {
            analysis.security_features.push("DYNAMIC_BASE (ASLR)".to_string());
        }
        if dll_chars & 0x0100 != 0 {
            analysis.security_features.push("NX_COMPAT (DEP)".to_string());
        }
        if dll_chars & 0x0400 != 0 {
            analysis.security_features.push("NO_SEH".to_string());
        }
        if dll_chars & 0x1000 != 0 {
            analysis.security_features.push("APPCONTAINER".to_string());
        }
        if dll_chars & 0x4000 != 0 {
            analysis.security_features.push("GUARD_CF".to_string());
        }
        if dll_chars & 0x8000 != 0 {
            analysis.security_features.push("TERMINAL_SERVER_AWARE".to_string());
        }
    }
}
