//! Metadata Extraction Module
//!
//! Extracts EXIF data from images and metadata from various file types.
//! Uses kamadak-exif (free, pure Rust) for EXIF extraction.

use exif::Exif;
use exif::In;
use exif::Tag;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

/// Extracted metadata from a file
#[derive(Debug, Clone, Default)]
pub struct ExtractedMetadata {
    /// General file metadata
    pub general: HashMap<String, String>,
    /// EXIF metadata (for images)
    pub exif: HashMap<String, String>,
    /// GPS coordinates if available
    pub gps: Option<GpsCoordinates>,
    /// Camera/device information
    pub device: Option<DeviceInfo>,
    /// Timestamps extracted from metadata
    pub timestamps: Vec<MetadataTimestamp>,
}

/// GPS coordinates extracted from EXIF
#[derive(Debug, Clone)]
pub struct GpsCoordinates {
    pub latitude: f64,
    pub longitude: f64,
    pub altitude: Option<f64>,
}

/// Device/camera information
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub make: Option<String>,
    pub model: Option<String>,
    pub software: Option<String>,
}

/// Timestamp from metadata
#[derive(Debug, Clone)]
pub struct MetadataTimestamp {
    pub timestamp_type: String,
    pub value: String,
}

/// Metadata extractor
pub struct MetadataExtractor;

impl MetadataExtractor {
    /// Extract metadata from a file based on its type
    pub fn extract(path: &Path) -> ExtractedMetadata {
        let mut metadata = ExtractedMetadata::default();

        // Determine file type and extract appropriate metadata
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext_lower = ext.to_lowercase();
            
            match ext_lower.as_str() {
                // Image formats that support EXIF
                "jpg" | "jpeg" | "tiff" | "tif" | "heic" | "heif" => {
                    if let Some(exif_data) = Self::extract_exif(path) {
                        metadata.exif = exif_data.exif;
                        metadata.gps = exif_data.gps;
                        metadata.device = exif_data.device;
                        metadata.timestamps = exif_data.timestamps;
                    }
                }
                // PNG - has its own metadata format
                "png" => {
                    Self::extract_png_metadata(path, &mut metadata);
                }
                // PDF metadata
                "pdf" => {
                    Self::extract_pdf_metadata(path, &mut metadata);
                }
                // Office documents
                "docx" | "xlsx" | "pptx" => {
                    Self::extract_office_metadata(path, &mut metadata);
                }
                _ => {}
            }
        }

        metadata
    }

    /// Extract EXIF data from an image file
    fn extract_exif(path: &Path) -> Option<ExtractedMetadata> {
        let file = File::open(path).ok()?;
        let mut buf_reader = BufReader::new(&file);
        
        let exif_reader = exif::Reader::new();
        let exif = exif_reader.read_from_container(&mut buf_reader).ok()?;

        let mut metadata = ExtractedMetadata::default();
        
        // Extract all EXIF fields
        Self::populate_exif_fields(&exif, &mut metadata);
        
        // Extract GPS coordinates
        metadata.gps = Self::extract_gps(&exif);
        
        // Extract device info
        metadata.device = Self::extract_device_info(&exif);
        
        // Extract timestamps
        Self::extract_timestamps(&exif, &mut metadata.timestamps);

        Some(metadata)
    }

    /// Populate EXIF fields from the parsed data
    fn populate_exif_fields(exif: &Exif, metadata: &mut ExtractedMetadata) {
        // Common EXIF tags to extract
        let tags = [
            (Tag::ImageWidth, "Image Width"),
            (Tag::ImageLength, "Image Height"),
            (Tag::BitsPerSample, "Bits Per Sample"),
            (Tag::Compression, "Compression"),
            (Tag::PhotometricInterpretation, "Photometric Interpretation"),
            (Tag::Orientation, "Orientation"),
            (Tag::XResolution, "X Resolution"),
            (Tag::YResolution, "Y Resolution"),
            (Tag::ResolutionUnit, "Resolution Unit"),
            (Tag::Software, "Software"),
            (Tag::DateTime, "Date/Time"),
            (Tag::Artist, "Artist"),
            (Tag::Copyright, "Copyright"),
            (Tag::ExifVersion, "EXIF Version"),
            (Tag::DateTimeOriginal, "Date/Time Original"),
            (Tag::DateTimeDigitized, "Date/Time Digitized"),
            (Tag::ShutterSpeedValue, "Shutter Speed"),
            (Tag::ApertureValue, "Aperture"),
            (Tag::BrightnessValue, "Brightness"),
            (Tag::ExposureBiasValue, "Exposure Bias"),
            (Tag::MeteringMode, "Metering Mode"),
            (Tag::Flash, "Flash"),
            (Tag::FocalLength, "Focal Length"),
            (Tag::ColorSpace, "Color Space"),
            (Tag::PixelXDimension, "Pixel X Dimension"),
            (Tag::PixelYDimension, "Pixel Y Dimension"),
            (Tag::ExposureMode, "Exposure Mode"),
            (Tag::WhiteBalance, "White Balance"),
            (Tag::DigitalZoomRatio, "Digital Zoom"),
            (Tag::FocalLengthIn35mmFilm, "Focal Length 35mm"),
            (Tag::SceneCaptureType, "Scene Type"),
            (Tag::ImageUniqueID, "Image Unique ID"),
            (Tag::Make, "Camera Make"),
            (Tag::Model, "Camera Model"),
        ];

        for (tag, name) in tags {
            if let Some(field) = exif.get_field(tag, In::PRIMARY) {
                metadata.exif.insert(
                    name.to_string(),
                    field.display_value().with_unit(exif).to_string(),
                );
            }
        }
    }

    /// Extract GPS coordinates from EXIF
    fn extract_gps(exif: &Exif) -> Option<GpsCoordinates> {
        let lat = Self::get_gps_coord(exif, Tag::GPSLatitude, Tag::GPSLatitudeRef)?;
        let lon = Self::get_gps_coord(exif, Tag::GPSLongitude, Tag::GPSLongitudeRef)?;
        
        let altitude = exif.get_field(Tag::GPSAltitude, In::PRIMARY)
            .and_then(|f| {
                if let exif::Value::Rational(ref v) = f.value {
                    v.first().map(|r| r.to_f64())
                } else {
                    None
                }
            });

        Some(GpsCoordinates {
            latitude: lat,
            longitude: lon,
            altitude,
        })
    }

    /// Parse GPS coordinate from EXIF data
    fn get_gps_coord(exif: &Exif, coord_tag: Tag, ref_tag: Tag) -> Option<f64> {
        let coord_field = exif.get_field(coord_tag, In::PRIMARY)?;
        let ref_field = exif.get_field(ref_tag, In::PRIMARY)?;

        if let exif::Value::Rational(ref coords) = coord_field.value {
            if coords.len() >= 3 {
                let degrees = coords[0].to_f64();
                let minutes = coords[1].to_f64();
                let seconds = coords[2].to_f64();
                
                let mut decimal = degrees + minutes / 60.0 + seconds / 3600.0;
                
                // Check reference (N/S for lat, E/W for lon)
                if let exif::Value::Ascii(ref refs) = ref_field.value {
                    if let Some(first) = refs.first() {
                        if !first.is_empty() {
                            let ref_char = first[0] as char;
                            if ref_char == 'S' || ref_char == 'W' {
                                decimal = -decimal;
                            }
                        }
                    }
                }
                
                return Some(decimal);
            }
        }
        None
    }

    /// Extract device/camera information
    fn extract_device_info(exif: &Exif) -> Option<DeviceInfo> {
        let make = exif.get_field(Tag::Make, In::PRIMARY)
            .map(|f| f.display_value().with_unit(exif).to_string());
        let model = exif.get_field(Tag::Model, In::PRIMARY)
            .map(|f| f.display_value().with_unit(exif).to_string());
        let software = exif.get_field(Tag::Software, In::PRIMARY)
            .map(|f| f.display_value().with_unit(exif).to_string());

        if make.is_some() || model.is_some() || software.is_some() {
            Some(DeviceInfo { make, model, software })
        } else {
            None
        }
    }

    /// Extract timestamp information
    fn extract_timestamps(exif: &Exif, timestamps: &mut Vec<MetadataTimestamp>) {
        let time_tags = [
            (Tag::DateTime, "Modified"),
            (Tag::DateTimeOriginal, "Original"),
            (Tag::DateTimeDigitized, "Digitized"),
        ];

        for (tag, ts_type) in time_tags {
            if let Some(field) = exif.get_field(tag, In::PRIMARY) {
                timestamps.push(MetadataTimestamp {
                    timestamp_type: ts_type.to_string(),
                    value: field.display_value().with_unit(exif).to_string(),
                });
            }
        }
    }

    /// Extract PNG metadata (basic - PNG doesn't have EXIF but has text chunks)
    fn extract_png_metadata(path: &Path, metadata: &mut ExtractedMetadata) {
        // PNG files can have tEXt, zTXt, and iTXt chunks
        // For now, just note that it's a PNG file
        if let Ok(file_meta) = std::fs::metadata(path) {
            metadata.general.insert("File Size".to_string(), 
                format!("{} bytes", file_meta.len()));
        }
        metadata.general.insert("Format".to_string(), "PNG".to_string());
    }

    /// Extract PDF metadata (basic parsing)
    fn extract_pdf_metadata(path: &Path, metadata: &mut ExtractedMetadata) {
        // Basic PDF metadata extraction
        // Full PDF parsing would require a PDF library
        if let Ok(content) = std::fs::read(path) {
            // Look for PDF version
            if content.starts_with(b"%PDF-") {
                if let Some(version_end) = content.iter().position(|&b| b == b'\n' || b == b'\r') {
                    if let Ok(version) = std::str::from_utf8(&content[5..version_end.min(10)]) {
                        metadata.general.insert("PDF Version".to_string(), version.to_string());
                    }
                }
            }

            // Look for common metadata markers
            let content_str = String::from_utf8_lossy(&content[..content.len().min(4096)]);
            
            Self::extract_pdf_field(&content_str, "/Title", "Title", metadata);
            Self::extract_pdf_field(&content_str, "/Author", "Author", metadata);
            Self::extract_pdf_field(&content_str, "/Subject", "Subject", metadata);
            Self::extract_pdf_field(&content_str, "/Creator", "Creator", metadata);
            Self::extract_pdf_field(&content_str, "/Producer", "Producer", metadata);
            Self::extract_pdf_field(&content_str, "/CreationDate", "Creation Date", metadata);
            Self::extract_pdf_field(&content_str, "/ModDate", "Modification Date", metadata);
        }
    }

    /// Extract a field from PDF content
    fn extract_pdf_field(content: &str, marker: &str, name: &str, metadata: &mut ExtractedMetadata) {
        if let Some(start) = content.find(marker) {
            let after_marker = &content[start + marker.len()..];
            // Find the value between parentheses or after the marker
            if let Some(paren_start) = after_marker.find('(') {
                if let Some(paren_end) = after_marker[paren_start..].find(')') {
                    let value = &after_marker[paren_start + 1..paren_start + paren_end];
                    if !value.is_empty() && value.len() < 256 {
                        metadata.general.insert(name.to_string(), value.to_string());
                    }
                }
            }
        }
    }

    /// Extract Office document metadata (basic - would need full ZIP parsing)
    fn extract_office_metadata(path: &Path, metadata: &mut ExtractedMetadata) {
        // Office Open XML files are ZIP archives
        // Full parsing would require unzipping and parsing XML
        if let Ok(file_meta) = std::fs::metadata(path) {
            metadata.general.insert("File Size".to_string(), 
                format!("{} bytes", file_meta.len()));
        }
        
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let format = match ext.to_lowercase().as_str() {
                "docx" => "Microsoft Word Document (OOXML)",
                "xlsx" => "Microsoft Excel Spreadsheet (OOXML)",
                "pptx" => "Microsoft PowerPoint Presentation (OOXML)",
                _ => "Office Document",
            };
            metadata.general.insert("Format".to_string(), format.to_string());
        }
    }

    /// Check if a file type supports metadata extraction
    pub fn supports_metadata(path: &Path) -> bool {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            matches!(
                ext.to_lowercase().as_str(),
                "jpg" | "jpeg" | "tiff" | "tif" | "heic" | "heif" | 
                "png" | "pdf" | "docx" | "xlsx" | "pptx"
            )
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_supports_metadata() {
        assert!(MetadataExtractor::supports_metadata(Path::new("test.jpg")));
        assert!(MetadataExtractor::supports_metadata(Path::new("test.JPEG")));
        assert!(MetadataExtractor::supports_metadata(Path::new("test.pdf")));
        assert!(MetadataExtractor::supports_metadata(Path::new("test.docx")));
        assert!(!MetadataExtractor::supports_metadata(Path::new("test.txt")));
        assert!(!MetadataExtractor::supports_metadata(Path::new("test.rs")));
    }

    #[test]
    fn test_pdf_metadata_extraction() {
        // Create a minimal PDF-like file
        let mut temp_file = NamedTempFile::with_suffix(".pdf").unwrap();
        writeln!(temp_file, "%PDF-1.4").unwrap();
        writeln!(temp_file, "/Title (Test Document)").unwrap();
        writeln!(temp_file, "/Author (Test Author)").unwrap();
        temp_file.flush().unwrap();

        let metadata = MetadataExtractor::extract(temp_file.path());
        
        assert_eq!(metadata.general.get("PDF Version"), Some(&"1.4".to_string()));
        assert_eq!(metadata.general.get("Title"), Some(&"Test Document".to_string()));
        assert_eq!(metadata.general.get("Author"), Some(&"Test Author".to_string()));
    }

    #[test]
    fn test_empty_file_handling() {
        let temp_file = NamedTempFile::with_suffix(".jpg").unwrap();
        let metadata = MetadataExtractor::extract(temp_file.path());
        
        // Should not crash on empty/invalid files
        assert!(metadata.exif.is_empty());
        assert!(metadata.gps.is_none());
    }
}
