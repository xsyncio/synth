//! MITRE ATT&CK Technique Definitions

use super::AttackTechnique;

/// Load MITRE ATT&CK techniques database
pub fn get_mitre_techniques() -> Vec<AttackTechnique> {
    vec![
        // Initial Access
        AttackTechnique {
            technique_id: "T1566".to_string(),
            name: "Phishing".to_string(),
            tactic: "Initial Access".to_string(),
            description: "Adversaries may send phishing messages to gain access".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["suspicious email attachment".to_string(), "macro-enabled document".to_string()],
        },
        // Execution
        AttackTechnique {
            technique_id: "T1059".to_string(),
            name: "Command and Scripting Interpreter".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may abuse command and script interpreters".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["powershell".to_string(), "cmd.exe".to_string(), "bash".to_string(), "python".to_string()],
        },
        AttackTechnique {
            technique_id: "T1059.001".to_string(),
            name: "PowerShell".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may abuse PowerShell commands and scripts".to_string(),
            platforms: vec!["Windows".to_string()],
            detection_indicators: vec!["Invoke-Expression".to_string(), "DownloadString".to_string(), "-enc".to_string(), "-EncodedCommand".to_string()],
        },
        // Persistence
        AttackTechnique {
            technique_id: "T1547".to_string(),
            name: "Boot or Logon Autostart Execution".to_string(),
            tactic: "Persistence".to_string(),
            description: "Adversaries may configure system settings to automatically execute a program".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["Run".to_string(), "RunOnce".to_string(), "Startup".to_string()],
        },
        AttackTechnique {
            technique_id: "T1053".to_string(),
            name: "Scheduled Task/Job".to_string(),
            tactic: "Persistence".to_string(),
            description: "Adversaries may abuse task scheduling functionality".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["schtasks".to_string(), "crontab".to_string(), "at".to_string()],
        },
        // Privilege Escalation
        AttackTechnique {
            technique_id: "T1055".to_string(),
            name: "Process Injection".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may inject code into processes".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["VirtualAllocEx".to_string(), "WriteProcessMemory".to_string(), "CreateRemoteThread".to_string()],
        },
        // Defense Evasion
        AttackTechnique {
            technique_id: "T1027".to_string(),
            name: "Obfuscated Files or Information".to_string(),
            tactic: "Defense Evasion".to_string(),
            description: "Adversaries may attempt to make files or information difficult to discover".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["base64".to_string(), "high entropy".to_string(), "packed".to_string()],
        },
        AttackTechnique {
            technique_id: "T1140".to_string(),
            name: "Deobfuscate/Decode Files or Information".to_string(),
            tactic: "Defense Evasion".to_string(),
            description: "Adversaries may use obfuscated files or information to hide artifacts".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["base64_decode".to_string(), "certutil -decode".to_string()],
        },
        AttackTechnique {
            technique_id: "T1562".to_string(),
            name: "Impair Defenses".to_string(),
            tactic: "Defense Evasion".to_string(),
            description: "Adversaries may maliciously modify components of a victim environment".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["disable antivirus".to_string(), "stop service".to_string()],
        },
        // Credential Access
        AttackTechnique {
            technique_id: "T1003".to_string(),
            name: "OS Credential Dumping".to_string(),
            tactic: "Credential Access".to_string(),
            description: "Adversaries may attempt to dump credentials".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["mimikatz".to_string(), "sekurlsa".to_string(), "lsass".to_string()],
        },
        AttackTechnique {
            technique_id: "T1056".to_string(),
            name: "Input Capture".to_string(),
            tactic: "Credential Access".to_string(),
            description: "Adversaries may use methods of capturing user input".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["keylogger".to_string(), "GetAsyncKeyState".to_string(), "SetWindowsHookEx".to_string()],
        },
        // Discovery
        AttackTechnique {
            technique_id: "T1082".to_string(),
            name: "System Information Discovery".to_string(),
            tactic: "Discovery".to_string(),
            description: "An adversary may attempt to get detailed information about the system".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["systeminfo".to_string(), "hostname".to_string(), "uname".to_string()],
        },
        // Lateral Movement
        AttackTechnique {
            technique_id: "T1021".to_string(),
            name: "Remote Services".to_string(),
            tactic: "Lateral Movement".to_string(),
            description: "Adversaries may use remote services to access and persist within an environment".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["ssh".to_string(), "rdp".to_string(), "psexec".to_string()],
        },
        // Collection
        AttackTechnique {
            technique_id: "T1005".to_string(),
            name: "Data from Local System".to_string(),
            tactic: "Collection".to_string(),
            description: "Adversaries may search local system sources for sensitive data".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["file enumeration".to_string(), "directory listing".to_string()],
        },
        AttackTechnique {
            technique_id: "T1113".to_string(),
            name: "Screen Capture".to_string(),
            tactic: "Collection".to_string(),
            description: "Adversaries may attempt to take screenshots".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["screenshot".to_string(), "CopyFromScreen".to_string()],
        },
        // Command and Control
        AttackTechnique {
            technique_id: "T1071".to_string(),
            name: "Application Layer Protocol".to_string(),
            tactic: "Command and Control".to_string(),
            description: "Adversaries may communicate using application layer protocols".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["http".to_string(), "https".to_string(), "dns".to_string()],
        },
        AttackTechnique {
            technique_id: "T1105".to_string(),
            name: "Ingress Tool Transfer".to_string(),
            tactic: "Command and Control".to_string(),
            description: "Adversaries may transfer tools or other files from an external system".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["DownloadFile".to_string(), "curl".to_string(), "wget".to_string()],
        },
        // Exfiltration
        AttackTechnique {
            technique_id: "T1041".to_string(),
            name: "Exfiltration Over C2 Channel".to_string(),
            tactic: "Exfiltration".to_string(),
            description: "Adversaries may steal data by exfiltrating it over an existing C2 channel".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["upload".to_string(), "exfil".to_string()],
        },
        // Impact
        AttackTechnique {
            technique_id: "T1486".to_string(),
            name: "Data Encrypted for Impact".to_string(),
            tactic: "Impact".to_string(),
            description: "Adversaries may encrypt data on target systems to interrupt availability".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["ransomware".to_string(), "encrypted".to_string(), "decrypt".to_string()],
        },
        AttackTechnique {
            technique_id: "T1496".to_string(),
            name: "Resource Hijacking".to_string(),
            tactic: "Impact".to_string(),
            description: "Adversaries may leverage resources of co-opted systems for crypto mining".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection_indicators: vec!["cryptominer".to_string(), "stratum".to_string(), "xmr".to_string()],
        },
    ]
}
