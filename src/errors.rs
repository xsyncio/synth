//! Custom error types for the Synth OSINT scanner.
//!
//! Provides a structured error hierarchy for better error handling
//! and more informative error messages.

use std::path::PathBuf;

/// The main error type for Synth operations.
#[derive(Debug, thiserror::Error)]
pub enum SynthError {
    /// I/O error (file read/write, permissions, etc.)
    #[error("I/O error at {path:?}: {source}")]
    Io {
        path: Option<PathBuf>,
        #[source]
        source: std::io::Error,
    },

    /// Regex compilation error
    #[error("Invalid regex pattern '{pattern}': {source}")]
    Regex {
        pattern: String,
        #[source]
        source: regex::Error,
    },

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Memory-mapped file error
    #[error("Failed to memory-map file {path:?}: {source}")]
    Mmap {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Invalid path error
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    /// Memory limit exceeded
    #[error("Memory limit exceeded: current {current_mb}MB > limit {limit_mb}MB")]
    MemoryLimit { current_mb: usize, limit_mb: usize },

    /// File too large for analysis
    #[error("File too large: {path:?} is {size_mb}MB (limit: {limit_mb}MB)")]
    FileTooLarge {
        path: PathBuf,
        size_mb: u64,
        limit_mb: u64,
    },

    /// UI channel error
    #[error("UI communication error: {0}")]
    UiChannel(String),

    /// Thread pool initialization error
    #[error("Failed to initialize thread pool: {0}")]
    ThreadPool(String),

    /// Tokio task join error
    #[error("Async task failed: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),

    /// Generic error for external library errors
    #[error("{context}: {message}")]
    External { context: String, message: String },
}

/// Result type alias using SynthError
pub type SynthResult<T> = Result<T, SynthError>;

impl SynthError {
    /// Create an I/O error with path context
    pub fn io(source: std::io::Error, path: impl Into<Option<PathBuf>>) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Create a regex error with pattern context
    pub fn regex(source: regex::Error, pattern: impl Into<String>) -> Self {
        Self::Regex {
            pattern: pattern.into(),
            source,
        }
    }

    /// Create an mmap error with path context
    pub fn mmap(source: std::io::Error, path: impl Into<PathBuf>) -> Self {
        Self::Mmap {
            path: path.into(),
            source,
        }
    }

    /// Create an external error with context
    pub fn external(context: impl Into<String>, message: impl Into<String>) -> Self {
        Self::External {
            context: context.into(),
            message: message.into(),
        }
    }
}

/// Convert from raw I/O errors (without path context)
impl From<std::io::Error> for SynthError {
    fn from(source: std::io::Error) -> Self {
        Self::Io { path: None, source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_error_display() {
        let err = SynthError::io(
            std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"),
            Some(PathBuf::from("/test/path")),
        );
        assert!(err.to_string().contains("/test/path"));
    }

    #[test]
    fn test_memory_limit_error() {
        let err = SynthError::MemoryLimit {
            current_mb: 2048,
            limit_mb: 1024,
        };
        assert!(err.to_string().contains("2048MB"));
        assert!(err.to_string().contains("1024MB"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let synth_err: SynthError = io_err.into();
        matches!(synth_err, SynthError::Io { .. });
    }
}
