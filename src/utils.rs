use bytes::Bytes;
use memmap2::Mmap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Zero-copy text reader that checks if content is likely text
pub fn is_likely_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    // Sample first 1KB to determine if it's text
    let sample_size = data.len().min(1024);
    let sample = &data[..sample_size];
    
    // Count control characters (excluding common whitespace)
    let control_chars = sample.iter()
        .filter(|&&b| b < 32 && !matches!(b, b'\n' | b'\r' | b'\t'))
        .count();
    
    // If more than 5% are control characters, probably binary
    (control_chars as f64) / (sample_size as f64) < 0.05
}

/// Zero-copy streaming text reader for memory efficiency
pub struct StreamingTextReader {
    reader: BufReader<File>,
    buffer: Vec<u8>,
    chunk_size: usize,
}

impl StreamingTextReader {
    pub fn new(file: File, chunk_size: usize) -> Self {
        Self {
            reader: BufReader::with_capacity(chunk_size, file),
            buffer: Vec::with_capacity(chunk_size),
            chunk_size,
        }
    }

    pub fn read_chunk(&mut self) -> std::io::Result<Option<Bytes>> {
        self.buffer.clear();
        
        let mut total_read = 0;
        while total_read < self.chunk_size {
            let bytes_read = self.reader.read_until(b'\n', &mut self.buffer)?;
            if bytes_read == 0 {
                break; // EOF
            }
            total_read += bytes_read;
        }

        if self.buffer.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Bytes::copy_from_slice(&self.buffer)))
        }
    }
}

/// Memory-efficient file signature detection
pub fn detect_file_signature(data: &[u8]) -> Option<&'static str> {
    if data.len() < 4 {
        return None;
    }

    match data {
        [0x4D, 0x5A, ..] => Some("PE Executable"),
        [0x7F, 0x45, 0x4C, 0x46, ..] => Some("ELF Binary"),
        [0xFF, 0xD8, 0xFF, ..] => Some("JPEG Image"),
        [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, ..] => Some("PNG Image"),
        [0x25, 0x50, 0x44, 0x46, ..] => Some("PDF Document"),
        [0x50, 0x4B, 0x03, 0x04, ..] => Some("ZIP Archive"),
        [0x50, 0x4B, 0x05, 0x06, ..] => Some("ZIP Archive (empty)"),
        [0x50, 0x4B, 0x07, 0x08, ..] => Some("ZIP Archive (spanned)"),
        [0x1F, 0x8B, 0x08, ..] => Some("GZIP Archive"),
        [0x42, 0x5A, 0x68, ..] => Some("BZIP2 Archive"),
        [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, ..] => Some("XZ Archive"),
        [b'R', b'a', b'r', b'!', 0x1A, 0x07, 0x00, ..] => Some("RAR Archive"),
        [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, ..] => Some("7-Zip Archive"),
        [0xCA, 0xFE, 0xBA, 0xBE, ..] => Some("Mach-O Binary (32-bit)"),
        [0xFE, 0xED, 0xFA, 0xCE, ..] => Some("Mach-O Binary (32-bit, reverse)"),
        [0xCF, 0xFA, 0xED, 0xFE, ..] => Some("Mach-O Binary (64-bit)"),
        [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, ..] => Some("Microsoft Office Document"),
        [b'G', b'I', b'F', b'8', b'7', b'a', ..] => Some("GIF Image"),
        [b'G', b'I', b'F', b'8', b'9', b'a', ..] => Some("GIF Image"),
        [b'B', b'M', ..] => Some("BMP Image"),
        [0x00, 0x00, 0x01, 0x00, ..] => Some("ICO File"),
        data if data.len() > 30 && data.starts_with(&[b'P', b'K', 0x03, 0x04]) => {
            // Check for Office documents (which are ZIP-based)
            let content = std::str::from_utf8(&data[30..data.len().min(100)]).unwrap_or("");
            if content.contains("word/") {
                Some("Microsoft Word Document")
            } else if content.contains("xl/") {
                Some("Microsoft Excel Document")
            } else if content.contains("ppt/") {
                Some("Microsoft PowerPoint Document")
            } else {
                Some("ZIP Archive")
            }
        },
        data if data.starts_with(b"SQLite format 3\0") => Some("SQLite Database"),
        _ => None,
    }
}

/// Calculate Shannon entropy for data analysis
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0u64; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    let data_len = data.len() as f64;
    let mut entropy = 0.0;

    for &freq in &frequency {
        if freq > 0 {
            let probability = freq as f64 / data_len;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/// Memory-efficient hash computation using memory mapping
pub struct HashComputer;

impl HashComputer {
    #[allow(unused_imports)]
    pub fn compute_hashes(mmap: &Mmap) -> Result<(String, String, String, String), Box<dyn std::error::Error + Send + Sync>> {
        use blake3::Hasher as Blake3Hasher;
        use md5::{Digest as Md5Digest, Md5};
        use sha2::{Digest as Sha2Digest, Sha256};
        use sha3::{Digest as Sha3Digest, Sha3_256};

        // Compute all hashes in one pass for efficiency
        let mut md5_hasher = Md5::new();
        let mut sha256_hasher = Sha256::new();
        let mut sha3_hasher = Sha3_256::new();
        let mut blake3_hasher = Blake3Hasher::new();

        // Process in chunks to avoid excessive memory usage
        const CHUNK_SIZE: usize = 8192;
        for chunk in mmap.chunks(CHUNK_SIZE) {
            md5_hasher.update(chunk);
            sha256_hasher.update(chunk);
            sha3_hasher.update(chunk);
            blake3_hasher.update(chunk);
        }

        let md5_hash = format!("{:x}", md5_hasher.finalize());
        let sha256_hash = hex::encode(sha256_hasher.finalize());
        let sha3_hash = hex::encode(sha3_hasher.finalize());
        let blake3_hash = hex::encode(blake3_hasher.finalize().as_bytes());

        Ok((md5_hash, sha256_hash, sha3_hash, blake3_hash))
    }
}

/// Format file timestamps safely
pub fn format_timestamp(time: Option<std::time::SystemTime>) -> Option<String> {
    time.map(|t| {
        let duration = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let datetime = chrono::DateTime::<chrono::Local>::from(
            chrono::DateTime::<chrono::Utc>::from_timestamp(duration.as_secs() as i64, 0)
                .unwrap_or_default()
        );
        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    })
}

/// Format file permissions in a cross-platform way
pub fn format_permissions(metadata: &std::fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        format!("{:o}", metadata.permissions().mode())
    }
    
    #[cfg(windows)]
    {
        let readonly = metadata.permissions().readonly();
        if readonly { 
            "r--r--r--".to_string() 
        } else { 
            "rw-rw-rw-".to_string() 
        }
    }
}

/// Check if a file is hidden (cross-platform)
pub fn is_hidden_file(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        // Unix-style hidden files
        if name.starts_with('.') {
            return true;
        }
    }

    // Windows hidden files
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
            return (metadata.file_attributes() & FILE_ATTRIBUTE_HIDDEN) != 0;
        }
    }

    false
}

/// Memory usage tracking utility
pub struct MemoryMonitor {
    max_memory_mb: usize,
}

impl MemoryMonitor {
    pub fn new(max_memory_mb: usize) -> Self {
        Self { max_memory_mb }
    }

    pub fn check_memory_usage(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        if self.max_memory_mb == 0 {
            return Ok(true); // No limit
        }

        // Simple memory check - in production you'd use a proper memory profiler
        let memory_info = get_memory_usage()?;
        let memory_mb = memory_info / (1024 * 1024);
        
        if memory_mb > self.max_memory_mb {
            log::warn!("Memory usage ({} MB) exceeds limit ({} MB)", memory_mb, self.max_memory_mb);
            return Ok(false);
        }

        Ok(true)
    }
}

fn get_memory_usage() -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    // Simplified memory usage - in production use proper system APIs
    #[cfg(unix)]
    {
        use std::fs;
        let status = fs::read_to_string("/proc/self/status")?;
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let kb: usize = parts[1].parse().unwrap_or(0);
                    return Ok(kb * 1024);
                }
            }
        }
    }
    
    #[cfg(windows)]
    {
        // Simplified for Windows - use proper Windows APIs in production
        return Ok(0);
    }
    
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let uniform_data = vec![0u8; 1000];
        let entropy = calculate_entropy(&uniform_data);
        assert!(entropy < 0.1); // Very low entropy for uniform data

        let random_data: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let entropy = calculate_entropy(&random_data);
        assert!(entropy > 7.0); // High entropy for varied data
    }

    #[test]
    fn test_file_signature_detection() {
        let pdf_header = b"%PDF-1.4";
        assert_eq!(detect_file_signature(pdf_header), Some("PDF Document"));

        let jpeg_header = &[0xFF, 0xD8, 0xFF, 0xE0];
        assert_eq!(detect_file_signature(jpeg_header), Some("JPEG Image"));

        let unknown_header = &[0x12, 0x34, 0x56, 0x78];
        assert_eq!(detect_file_signature(unknown_header), None);
    }

    #[test]
    fn test_text_detection() {
        let text_data = b"Hello, world! This is plain text.";
        assert!(is_likely_text(text_data));

        let binary_data = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(!is_likely_text(binary_data));

        let mixed_data = b"Some text\x00\x01\x02with binary";
        assert!(!is_likely_text(mixed_data));
    }
}