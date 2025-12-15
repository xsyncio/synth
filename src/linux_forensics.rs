use std::path::Path;
use crate::models::{AssetMetadata, ShellHistoryEntry, SshKeyEntry, CronJobEntry, SystemLogEntry, ForensicAnalysis};
use std::fs::File;
use std::io::{BufReader, BufRead};
// use regex::Regex;

#[derive(Default)]
pub struct LinuxForensics;

impl LinuxForensics { // Linux forensics implementation
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, path: &Path, asset: &mut AssetMetadata) {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        let parent = path.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();

        if let Some(mut forensics) = asset.forensic_analysis.take() {
            // 1. Shell History
            if name == ".bash_history" || name == ".zsh_history" || name == ".pwn.conf" {
                 log::debug!("Analyzing Shell History: {}", name);
                 self.analyze_shell_history(path, &name, &mut forensics);
            }

            // 2. SSH Keys
            if name == "authorized_keys" || name == "known_hosts" || name.starts_with("id_") {
                 log::debug!("Analyzing SSH: {}", name);
                 self.analyze_ssh(path, &name, &mut forensics);
            }

            // 3. Cron Jobs
            if name == "crontab" || parent.contains("/cron.d") || parent.contains("/spool/cron") {
                 log::debug!("Analyzing Cron: {}", name);
                 self.analyze_cron(path, &mut forensics);
            }

            // 4. System Logs
            if name.ends_with(".log") && (name.contains("auth") || name.contains("syslog") || name.contains("secure")) {
                 log::debug!("Analyzing Logs: {}", name);
                 self.analyze_logs(path, &mut forensics);
            }

            asset.forensic_analysis = Some(forensics);
        }
    }

    fn analyze_shell_history(&self, path: &Path, shell_type: &str, forensics: &mut ForensicAnalysis) {
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(cmd) = line {
                    // Filter for interesting commands
                    if cmd.contains("sudo") || cmd.contains("ssh") || cmd.contains("scp") || cmd.contains("aws") || cmd.contains("mysql") {
                        forensics.shell_history.push(ShellHistoryEntry {
                            shell_type: shell_type.to_string(),
                            command: cmd,
                            timestamp: "".to_string(), // Bash history has no timestamp unless configured
                        });
                    }
                }
            }
        }
    }

    fn analyze_ssh(&self, path: &Path, name: &str, forensics: &mut ForensicAnalysis) {
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(content) = line {
                     if content.trim().is_empty() || content.starts_with('#') { continue; }

                     // Simple Parsing
                     let parts: Vec<&str> = content.split_whitespace().collect();
                     if parts.len() >= 2 {
                         let key_type = parts[0];
                         // Extract comment (usually last part or all parts after key blob)
                         let comment = if parts.len() > 2 {
                             parts[2..].join(" ")
                         } else {
                             "No Comment".to_string()
                         };

                         forensics.ssh_keys.push(SshKeyEntry {
                             file_path: path.to_string_lossy().to_string(),
                             key_type: key_type.to_string(),
                             comment,
                             origin: name.to_string(),
                         });
                     }
                }
            }
        }
    }

    fn analyze_cron(&self, path: &Path, forensics: &mut ForensicAnalysis) {
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            // Crontab format: m h dom mon dow user command (system)
            // or: m h dom mon dow command (user)
            
            for line in reader.lines() {
                if let Ok(content) = line {
                    if content.trim().is_empty() || content.starts_with('#') { continue; }
                    
                    // Very basic parsing to verify structure
                     forensics.cron_jobs.push(CronJobEntry {
                         file_path: path.to_string_lossy().to_string(),
                         schedule: "Parsed (See Command)".to_string(),
                         command: content.clone(),
                         user: "Unknown".to_string(),
                     });
                }
            }
        }
    }

    fn analyze_logs(&self, path: &Path, forensics: &mut ForensicAnalysis) {
        // Look for auth failures, sudo usage
        if let Ok(file) = File::open(path) {
             let reader = BufReader::new(file);
             for line in reader.lines() {
                 if let Ok(msg) = line {
                     if msg.contains("Failed password") || msg.contains("sudo:") || msg.contains("Accepted publickey") {
                         let severity = if msg.contains("Failed") { "High".to_string() } else { "Info".to_string() };
                         forensics.system_logs.push(SystemLogEntry {
                             service: "Auth".to_string(),
                             message: msg,
                             timestamp: "Unknown".to_string(),
                             severity,
                         });
                     }
                 }
             }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    // use std::path::PathBuf;
    use crate::models::{AssetMetadata, ForensicAnalysis};

    #[test]
    fn test_analyze_shell_history() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join(".bash_history");
        let mut file = std::fs::File::create(&file_path).unwrap();
        
        writeln!(file, "sudo apt update").unwrap();
        writeln!(file, "ls -la").unwrap();
        writeln!(file, "ssh user@host").unwrap();

        let mut asset = AssetMetadata::new(file_path.clone(), ".bash_history".to_string());
        asset.forensic_analysis = Some(ForensicAnalysis::default());

        let analyzer = LinuxForensics::new();
        analyzer.analyze(&file_path, &mut asset);

        if let Some(forensics) = asset.forensic_analysis {
            assert_eq!(forensics.shell_history.len(), 2, "Should find sudo and ssh commands");
            if !forensics.shell_history.is_empty() {
                assert_eq!(forensics.shell_history[0].command, "sudo apt update");
            }
        } else {
            panic!("Forensic analysis struct missing");
        }
    }

    #[test]
    fn test_analyze_ssh_keys() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("authorized_keys");
        let mut file = std::fs::File::create(&file_path).unwrap();
        
        writeln!(file, "ssh-rsa AAAAB3... user@host").unwrap();

        let mut asset = AssetMetadata::new(file_path.clone(), "authorized_keys".to_string());
        asset.forensic_analysis = Some(ForensicAnalysis::default());

        let analyzer = LinuxForensics::new();
        analyzer.analyze(&file_path, &mut asset);

        if let Some(forensics) = asset.forensic_analysis {
             assert_eq!(forensics.ssh_keys.len(), 1);
             if !forensics.ssh_keys.is_empty() {
                 assert_eq!(forensics.ssh_keys[0].comment, "user@host");
             }
        } else {
             panic!("Forensic analysis struct missing");
        }
    }
}
