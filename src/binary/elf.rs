//! ELF (Linux) Binary Analysis

use super::{BinaryAnalysis, BinaryAnalyzer, BinaryFormat, ImportInfo, SectionInfo};

/// Analyze ELF (Linux) executable
pub fn analyze_elf(elf: &goblin::elf::Elf, data: &[u8], analysis: &mut BinaryAnalysis) {
    analysis.format = if elf.is_64 {
        BinaryFormat::ELF64
    } else {
        BinaryFormat::ELF32
    };
    analysis.is_64bit = elf.is_64;
    analysis.entry_point = elf.entry;

    // Determine architecture
    analysis.architecture = match elf.header.e_machine {
        goblin::elf::header::EM_386 => "x86".to_string(),
        goblin::elf::header::EM_X86_64 => "x64".to_string(),
        goblin::elf::header::EM_ARM => "ARM".to_string(),
        goblin::elf::header::EM_AARCH64 => "ARM64".to_string(),
        goblin::elf::header::EM_MIPS => "MIPS".to_string(),
        goblin::elf::header::EM_PPC => "PowerPC".to_string(),
        goblin::elf::header::EM_PPC64 => "PowerPC64".to_string(),
        goblin::elf::header::EM_RISCV => "RISC-V".to_string(),
        _ => format!("Unknown ({})", elf.header.e_machine),
    };

    // Parse sections
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            let start = section.sh_offset as usize;
            let end = (section.sh_offset + section.sh_size) as usize;
            let section_data = if end <= data.len() && start < end {
                &data[start..end]
            } else {
                &[]
            };
            let entropy = BinaryAnalyzer::calculate_entropy(section_data);

            let mut characteristics = Vec::new();
            if section.sh_flags & goblin::elf::section_header::SHF_WRITE as u64 != 0 {
                characteristics.push("WRITE".to_string());
            }
            if section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0 {
                characteristics.push("EXECUTE".to_string());
            }
            if section.sh_flags & goblin::elf::section_header::SHF_ALLOC as u64 != 0 {
                characteristics.push("ALLOC".to_string());
            }

            analysis.sections.push(SectionInfo {
                name: name.to_string(),
                virtual_address: section.sh_addr,
                virtual_size: section.sh_size,
                raw_size: section.sh_size,
                entropy,
                characteristics,
            });
        }
    }

    // Parse dynamic libraries
    for lib in &elf.libraries {
        analysis.imports.push(ImportInfo {
            library: lib.to_string(),
            functions: Vec::new(),
        });
    }

    // Parse symbols for exports
    for sym in &elf.syms {
        if sym.st_bind() == goblin::elf::sym::STB_GLOBAL {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    analysis.exports.push(name.to_string());
                }
            }
        }
    }

    // Detect ELF security features
    detect_elf_security_features(elf, analysis);

    // Disassemble Entry Point
    let mut entry_offset = 0;
    for section in &elf.section_headers {
        if elf.entry >= section.sh_addr && elf.entry < (section.sh_addr + section.sh_size) {
             entry_offset = (elf.entry - section.sh_addr + section.sh_offset) as usize;
             break;
        }
    }
    if entry_offset > 0 && entry_offset < data.len() {
         let arch = analysis.architecture.clone();
         BinaryAnalyzer::disassemble_chunk(&data[entry_offset..], analysis, &arch);
    }
}

/// Detect ELF security features
fn detect_elf_security_features(elf: &goblin::elf::Elf, analysis: &mut BinaryAnalysis) {
    for phdr in &elf.program_headers {
        if phdr.p_type == goblin::elf::program_header::PT_GNU_RELRO {
            analysis.security_features.push("RELRO (Relocation Read-Only)".to_string());
        }
        if phdr.p_type == goblin::elf::program_header::PT_GNU_STACK {
            if phdr.p_flags & goblin::elf::program_header::PF_X == 0 {
                analysis.security_features.push("NX Stack (Non-Executable Stack)".to_string());
            }
        }
    }

    if elf.header.e_type == goblin::elf::header::ET_DYN {
        analysis.security_features.push("PIE (Position Independent)".to_string());
    }
}
