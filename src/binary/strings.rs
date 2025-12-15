//! String Extraction from Binary Data

use super::{ExtractedString, StringCategory, StringEncoding};

/// Extract printable strings from binary data
pub fn extract_strings(data: &[u8]) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let min_length = 6;

    let mut current_string = Vec::new();
    let mut start_offset = 0;

    for (i, &byte) in data.iter().enumerate() {
        if byte >= 0x20 && byte < 0x7F {
            if current_string.is_empty() {
                start_offset = i;
            }
            current_string.push(byte);
        } else if !current_string.is_empty() {
            if current_string.len() >= min_length {
                let value = String::from_utf8_lossy(&current_string).to_string();
                let category = categorize_string(&value);
                strings.push(ExtractedString {
                    value,
                    offset: start_offset,
                    encoding: StringEncoding::Ascii,
                    category,
                });
            }
            current_string.clear();
        }
    }

    // Limit to most interesting strings
    strings.sort_by(|a, b| {
        let priority_a = string_priority(&a.category);
        let priority_b = string_priority(&b.category);
        priority_b.cmp(&priority_a)
    });
    strings.truncate(100);

    strings
}

/// Categorize a string based on its content
pub fn categorize_string(s: &str) -> StringCategory {
    if s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://") {
        StringCategory::Url
    } else if looks_like_ip(s) {
        StringCategory::IpAddress
    } else if s.contains('@') && s.contains('.') {
        StringCategory::Email
    } else if s.starts_with("HKEY_") || s.starts_with("SOFTWARE\\") || s.contains("\\Registry\\") {
        StringCategory::RegistryKey
    } else if s.ends_with(".exe") || s.ends_with(".dll") || s.ends_with(".sys") 
        || s.starts_with("C:\\") || s.starts_with("/usr/") || s.starts_with("/etc/") {
        StringCategory::FilePath
    } else if s.starts_with("cmd") || s.starts_with("powershell") || s.starts_with("/bin/") {
        StringCategory::Command
    } else if s.len() == 34 || s.len() == 42 || s.len() == 64 {
        StringCategory::Cryptocurrency
    } else {
        StringCategory::Generic
    }
}

/// Check if string looks like an IP address
pub fn looks_like_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 {
        parts.iter().all(|p| p.parse::<u8>().is_ok())
    } else {
        false
    }
}

/// Get priority for string category
fn string_priority(category: &StringCategory) -> u8 {
    match category {
        StringCategory::Url => 10,
        StringCategory::IpAddress => 9,
        StringCategory::Cryptocurrency => 9,
        StringCategory::Email => 8,
        StringCategory::Command => 7,
        StringCategory::RegistryKey => 6,
        StringCategory::FilePath => 5,
        StringCategory::Generic => 1,
    }
}
