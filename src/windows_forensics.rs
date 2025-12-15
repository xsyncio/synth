use std::path::Path;
use crate::models::{AssetMetadata, RegistryEntry, LnkFileEntry, RecycleBinEntry, ForensicAnalysis};

#[derive(Default)]
pub struct WindowsForensics;

impl WindowsForensics {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, path: &Path, asset: &mut AssetMetadata) {
        if let Some(mut forensics) = asset.forensic_analysis.take() {
            let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();

            // 1. Registry Hives
            if name == "ntuser.dat" || name == "system" || name == "software" || name == "sam" || name == "amcache.hve" {
                self.analyze_registry_hive(path, &name, &mut forensics);
            }

            // 2. LNK Files
            if name.ends_with(".lnk") {
                self.analyze_lnk(path, &mut forensics);
            }

            // 3. Recycle Bin ($I files)
            // Windows Recycle Bin usually has $Ixxxxxx.ext and $Rxxxxxx.ext
            if name.starts_with("$i") {
                self.analyze_recycle_bin(path, &mut forensics);
            }

            asset.forensic_analysis = Some(forensics);
        }
    }

    fn analyze_registry_hive(&self, path: &Path, hive_name: &str, forensics: &mut ForensicAnalysis) {
        use nt_hive::Hive;
        use memmap2::Mmap;
        use std::fs::File;

        // Basic logging
        println!("DEBUG: Parsing Registry Hive: {:?}", path);

        if let Ok(file) = File::open(path) {
            // Safety: Mapping file is unsafe effectively, but standard for this operation
            if let Ok(mmap) = unsafe { Mmap::map(&file) } {
                if let Ok(hive) = Hive::new(mmap.as_ref()) {
                    if let Ok(root) = hive.root_key_node() {
                        let keys_to_check = match hive_name {
                            "ntuser.dat" => vec![
                                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            ],
                            "system" => vec![
                                "Select", 
                                "ControlSet001\\Control\\Session Manager\\AppCompatCache",
                            ],
                            "software" => vec![
                                "Microsoft\\Windows\\CurrentVersion\\Run"
                            ],
                            "amcache.hve" => vec![
                                "Root\\File",
                                "Root\\InventoryApplicationFile"
                            ],
                            _ => vec![]
                        };

                        for key_path in keys_to_check {
                            // nt-hive typical navigation:
                            // We need to implement manual path traversal or find subkey by path function
                            // simple implementation: just log root subkeys for now to verify it works
                            // as traversing deep paths in nt-hive requires recursive lookup
                             // Simplified: Try to find direct subkey if checking from root (won't work for deep paths directly)
                             // For Amcache/Shimcache deeper paths, we'd need traversal.
                             // For now, we print we started looking for it.
                             println!("DEBUG: Checking for key (simplified root scan): {}", key_path);
                             
                             if let Some(Ok(subkeys)) = root.subkeys() {
                                 for sub_key in subkeys {
                                     if let Ok(sub) = sub_key {
                                         let name = sub.name().ok().map(|n| n.to_string()).unwrap_or_default();
                                          forensics.registry_keys.push(RegistryEntry {
                                             hive: hive_name.to_string(),
                                             key: name.to_string(),
                                             value_name: "Subkey found".to_string(),
                                             value_data: "N/A".to_string(),
                                             last_write: "".to_string(),
                                         });
                                     }
                                 }
                             }
                        }
                    }
                }
            }
        }
    }

    fn analyze_lnk(&self, path: &Path, forensics: &mut ForensicAnalysis) {
        use parselnk::Lnk;

        if let Ok(lnk) = Lnk::try_from(path) {
            let target = lnk.link_info.local_base_path.clone()
                .unwrap_or_else(|| "Unknown".to_string());
            
            let args = lnk.string_data.command_line_arguments.clone().unwrap_or_default();

             let working_dir = lnk.string_data.working_dir.clone().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();

            forensics.lnk_files.push(LnkFileEntry {
                path: path.to_string_lossy().to_string(),
                target_path: target,
                arguments: args,
                working_dir: working_dir,
                created: "".to_string(), // parselnk might not expose easy timestamps directly in all versions, keeping simple
                modified: "".to_string(),
            });
        }
    }

    fn analyze_recycle_bin(&self, path: &Path, forensics: &mut ForensicAnalysis) {
        // $I files format:
        // Version 1 (Win98-XP): Not supported
        // Version 2 (Vista+):
        // Offset 0 (8 bytes): Header (0x1)
        // Offset 8 (8 bytes): Size
        // Offset 16 (8 bytes): Deleted Timestamp (FILETIME)
        // Offset 24 (520 bytes): Path (UTF-16)

        use std::io::Read;
        use std::fs::File;

        if let Ok(mut file) = File::open(path) {
            let mut header = [0u8; 8];
            if file.read_exact(&mut header).is_ok() {
                // Check version (0x1 or 0x2)
                // For now, simple heuristic reading
                
                let mut size_bytes = [0u8; 8];
                let _ = file.read_exact(&mut size_bytes);
                let size = u64::from_le_bytes(size_bytes);

                let mut time_bytes = [0u8; 8];
                let _ = file.read_exact(&mut time_bytes);
                // timestamp

                // Read path (UTF-16 encoded)
                // Just reading rest of file roughly
                let mut path_bytes = Vec::new();
                let _ = file.read_to_end(&mut path_bytes);
                
                // Convert UTF-16 to UTF-8 assuming little endian
                let u16_vec: Vec<u16> = path_bytes
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect();
                
                let original_path = String::from_utf16_lossy(&u16_vec).trim_matches(char::from(0)).to_string();

                forensics.recycle_bin.push(RecycleBinEntry {
                    original_path,
                    deleted_time: "Unknown".to_string(), // Need filetime conversion
                    file_size: size,
                    recycle_path: path.to_string_lossy().to_string(),
                });
            }
        }
    }
}
