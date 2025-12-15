//! Advanced OSINT Scanner
//! 
//! A high-performance, memory-efficient asset scanner for intelligence gathering
//! and threat detection.

pub mod analyzer;
pub mod anti_evasion;
pub mod binary;
pub mod cli;
pub mod errors;
pub mod forensics;
pub mod metadata;
pub mod models;
pub mod network;
pub mod scanner;
pub mod secrets;
pub mod stego;
pub mod threat_intel;
pub mod ui;
pub mod utils;
pub mod yara;
pub mod reporter;
pub mod watcher;
pub mod exporter;
pub mod cloud;
pub mod windows_forensics;
pub mod linux_forensics;
pub mod mobile;
pub mod chat;

pub use errors::{SynthError, SynthResult};
pub use scanner::AdvancedOsintScanner;