use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "synth", 
    about = "Synth - High-performance OSINT scanner and intelligence analysis tool",
    version
)]

pub struct Args {
    /// Target directory to scan
    #[arg(short, long, default_value = ".")]
    pub directory: String,

    /// Asset name pattern to search for
    #[arg(short, long, default_value = "")]
    pub asset_name: String,

    /// Regular expression pattern for advanced matching
    #[arg(short, long)]
    pub regex_pattern: Option<String>,

    /// Scanning mode (performance vs depth trade-off)
    #[arg(short, long, default_value = "standard")]
    pub mode: SearchMode,

    /// Maximum directory traversal depth
    #[arg(long, default_value = "10")]
    pub max_depth: usize,

    /// Number of parallel scanning threads (0 = auto-detect)
    #[arg(short, long, default_value = "0")]
    pub threads: usize,

    /// Maximum file size to analyze in MB
    #[arg(long, default_value = "100")]
    pub max_file_size: u64,

    /// Minimum file size to consider in bytes
    #[arg(long, default_value = "0")]
    pub min_size: u64,

    /// Maximum file size to consider in bytes (optional)
    #[arg(long)]
    pub max_size: Option<u64>,

    /// Follow symbolic links during traversal
    #[arg(long)]
    pub follow_symlinks: bool,

    /// Case-sensitive pattern matching
    #[arg(long)]
    pub case_sensitive: bool,

    /// File types to include (extensions without dots)
    #[arg(long, value_delimiter = ',')]
    pub file_types: Vec<String>,

    /// Patterns to exclude from scanning
    #[arg(long, value_delimiter = ',')]
    pub exclude: Vec<String>,

    /// Output scan results to JSON file
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Enable verbose logging of all operations
    #[arg(short, long)]
    pub verbose: bool,

    /// Hide progress bars and use quiet output
    #[arg(short, long)]
    pub quiet: bool,

    /// Maximum memory usage in MB (0 = unlimited)
    #[arg(long, default_value = "1024")]
    pub max_memory: usize,

    /// Enable Watch Mode (monitor directory for changes)
    #[arg(long)]
    pub watch: bool,
}

#[derive(Debug, Clone, ValueEnum, PartialEq)]
pub enum SearchMode {
    /// Fast scanning with basic pattern matching
    Fast,
    /// Standard analysis with network/crypto detection
    Standard,
    /// Deep analysis with entropy and threat hunting
    Deep,
    /// Comprehensive analysis with all features enabled
    Comprehensive,
}

impl std::fmt::Display for SearchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SearchMode::Fast => write!(f, "Fast"),
            SearchMode::Standard => write!(f, "Standard"),
            SearchMode::Deep => write!(f, "Deep"),
            SearchMode::Comprehensive => write!(f, "Comprehensive"),
        }
    }
}