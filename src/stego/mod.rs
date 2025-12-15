//! Steganography Detection Module
//!
//! Detects hidden data in images using multiple techniques:
//! - LSB (Least Significant Bit) analysis
//! - Chi-square statistical tests
//! - Entropy anomaly detection
//! - Pattern analysis
//!
//! All using free, open-source dependencies (image crate).

use std::path::Path;

/// Steganography detection result
#[derive(Debug, Clone, Default)]
pub struct StegoAnalysis {
    /// Whether steganography was likely detected
    pub detected: bool,
    /// Confidence score 0-100
    pub confidence: u8,
    /// Detection method that triggered
    pub detection_method: Option<String>,
    /// Analysis details
    pub details: Vec<String>,
    /// LSB analysis results
    pub lsb_analysis: Option<LsbAnalysis>,
    /// Entropy analysis
    pub entropy_analysis: Option<EntropyAnalysis>,
}

/// LSB analysis results
#[derive(Debug, Clone)]
pub struct LsbAnalysis {
    /// Average LSB ratio (should be near 0.5 for clean images)
    pub avg_lsb_ratio: f64,
    /// Chi-square test p-value
    pub chi_square_pvalue: f64,
    /// Pairs of values analysis
    pub pairs_anomaly: bool,
}

/// Entropy analysis results
#[derive(Debug, Clone)]
pub struct EntropyAnalysis {
    /// Overall image entropy
    pub overall_entropy: f64,
    /// LSB plane entropy
    pub lsb_entropy: f64,
    /// Entropy ratio (LSB/overall)
    pub entropy_ratio: f64,
}

/// Steganography detector
pub struct StegoDetector;

impl StegoDetector {
    /// Analyze an image file for steganography
    pub fn analyze_file(path: &Path) -> Option<StegoAnalysis> {
        // Check if it's a supported image format
        let ext = path.extension()?.to_str()?.to_lowercase();
        
        if ext == "wav" {
             return Self::analyze_audio(path);
        }

        if !matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "bmp") {
            return None;
        }

        let img = image::open(path).ok()?;
        let rgba = img.to_rgba8();
        
        Some(Self::analyze_image_data(&rgba))
    }

    /// Analyze image data for steganography indicators
    fn analyze_image_data(img: &image::RgbaImage) -> StegoAnalysis {
        let mut analysis = StegoAnalysis::default();
        let mut details = Vec::new();

        // LSB Analysis
        let lsb = Self::perform_lsb_analysis(img);
        
        // Check LSB ratio anomaly (should be close to 0.5 for natural images)
        if (lsb.avg_lsb_ratio - 0.5).abs() > 0.15 {
            details.push(format!("LSB ratio anomaly: {:.3} (expected ~0.5)", lsb.avg_lsb_ratio));
            analysis.confidence += 25;
        }

        // Chi-square test for randomness
        if lsb.chi_square_pvalue < 0.01 {
            details.push(format!("Chi-square test indicates non-random LSB: p={:.4}", lsb.chi_square_pvalue));
            analysis.confidence += 30;
        }

        // Pairs analysis
        if lsb.pairs_anomaly {
            details.push("Sample pairs analysis indicates potential LSB embedding".to_string());
            analysis.confidence += 20;
        }

        analysis.lsb_analysis = Some(lsb);

        // Entropy Analysis
        let entropy = Self::perform_entropy_analysis(img);
        
        // High LSB entropy relative to overall entropy suggests hidden data
        if entropy.entropy_ratio > 0.95 && entropy.lsb_entropy > 7.5 {
            details.push(format!("High LSB entropy: {:.2} (ratio: {:.3})", entropy.lsb_entropy, entropy.entropy_ratio));
            analysis.confidence += 25;
        }

        // Unusually uniform LSB distribution
        if entropy.lsb_entropy > 7.9 {
            details.push("Near-maximum LSB entropy suggests data embedding".to_string());
            analysis.confidence += 15;
        }

        analysis.entropy_analysis = Some(entropy);

        // Determine final detection status
        analysis.detected = analysis.confidence >= 50;
        analysis.details = details;
        
        if analysis.detected {
            analysis.detection_method = Some("Multiple LSB anomalies detected".to_string());
        }

        // Cap confidence
        analysis.confidence = analysis.confidence.min(100);

        analysis
    }

    /// Perform LSB (Least Significant Bit) analysis
    fn perform_lsb_analysis(img: &image::RgbaImage) -> LsbAnalysis {
        let pixels: Vec<_> = img.pixels().collect();
        let mut lsb_ones = 0u64;
        let mut total_bits = 0u64;
        let mut pairs_even = 0u64;
        let mut pairs_odd = 0u64;

        // Analyze RGB channels (skip alpha)
        for pixel in &pixels {
            for channel in 0..3 {
                let value = pixel[channel];
                
                // Count LSB ones
                if value & 1 == 1 {
                    lsb_ones += 1;
                }
                total_bits += 1;

                // Sample pairs analysis
                if value % 2 == 0 {
                    pairs_even += 1;
                } else {
                    pairs_odd += 1;
                }
            }
        }

        let avg_lsb_ratio = if total_bits > 0 {
            lsb_ones as f64 / total_bits as f64
        } else {
            0.5
        };

        // Chi-square test for LSB randomness
        let expected = total_bits as f64 / 2.0;
        let chi_square = if expected > 0.0 {
            let diff = lsb_ones as f64 - expected;
            (diff * diff) / expected + ((total_bits - lsb_ones) as f64 - expected).powi(2) / expected
        } else {
            0.0
        };

        // Approximate p-value (simplified)
        let chi_square_pvalue = Self::chi_square_pvalue(chi_square, 1);

        // Pairs analysis - check for anomalies in value pair distribution
        let pairs_ratio = if pairs_even + pairs_odd > 0 {
            pairs_even as f64 / (pairs_even + pairs_odd) as f64
        } else {
            0.5
        };
        let pairs_anomaly = (pairs_ratio - 0.5).abs() < 0.01; // Too perfect is suspicious

        LsbAnalysis {
            avg_lsb_ratio,
            chi_square_pvalue,
            pairs_anomaly,
        }
    }

    /// Perform entropy analysis
    fn perform_entropy_analysis(img: &image::RgbaImage) -> EntropyAnalysis {
        let pixels: Vec<_> = img.pixels().collect();
        
        // Calculate overall entropy
        let overall_entropy = Self::calculate_pixel_entropy(&pixels);
        
        // Calculate LSB plane entropy
        let lsb_entropy = Self::calculate_lsb_entropy(&pixels);

        let entropy_ratio = if overall_entropy > 0.0 {
            lsb_entropy / 8.0 // Normalize to 0-1 range (max entropy is 8 for byte)
        } else {
            0.0
        };

        EntropyAnalysis {
            overall_entropy,
            lsb_entropy,
            entropy_ratio,
        }
    }

    /// Calculate entropy of pixel data
    fn calculate_pixel_entropy(pixels: &[&image::Rgba<u8>]) -> f64 {
        let mut freq = [0u64; 256];
        let mut total = 0u64;

        for pixel in pixels {
            for channel in 0..3 {
                freq[pixel[channel] as usize] += 1;
                total += 1;
            }
        }

        let mut entropy = 0.0;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / total as f64;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Calculate entropy of LSB plane
    fn calculate_lsb_entropy(pixels: &[&image::Rgba<u8>]) -> f64 {
        // Group LSBs into bytes and calculate entropy
        let mut lsb_bytes = Vec::with_capacity(pixels.len() * 3 / 8);
        let mut current_byte = 0u8;
        let mut bit_count = 0;

        for pixel in pixels {
            for channel in 0..3 {
                current_byte = (current_byte << 1) | (pixel[channel] & 1);
                bit_count += 1;
                
                if bit_count == 8 {
                    lsb_bytes.push(current_byte);
                    current_byte = 0;
                    bit_count = 0;
                }
            }
        }

        // Calculate entropy of LSB byte stream
        let mut freq = [0u64; 256];
        for &b in &lsb_bytes {
            freq[b as usize] += 1;
        }

        let total = lsb_bytes.len() as f64;
        let mut entropy = 0.0;
        
        if total > 0.0 {
            for &count in &freq {
                if count > 0 {
                    let p = count as f64 / total;
                    entropy -= p * p.log2();
                }
            }
        }

        entropy
    }

    /// Simplified chi-square p-value calculation
    fn chi_square_pvalue(chi_square: f64, _df: u32) -> f64 {
        // Simplified approximation for df=1
        // A proper implementation would use a statistical library
        let x = chi_square / 2.0;
        (-x).exp()
    }

    /// Check if a file might contain steganography
    pub fn is_supported_format(path: &Path) -> bool {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            matches!(ext.to_lowercase().as_str(), "png" | "jpg" | "jpeg" | "bmp" | "gif" | "wav")
        } else {
            false
        }
    }

    /// Analyze audio file for steganography (WAV only)
    pub fn analyze_audio(path: &Path) -> Option<StegoAnalysis> {
        let ext = path.extension()?.to_str()?.to_lowercase();
        if ext != "wav" { return None; }

        let mut reader = hound::WavReader::open(path).ok()?;
        let samples: Vec<i32> = reader.samples::<i32>().filter_map(|s| s.ok()).collect();
        
        // Analyze samples for LSB
        Some(Self::analyze_audio_samples(&samples))
    }

    fn analyze_audio_samples(samples: &[i32]) -> StegoAnalysis {
        let mut analysis = StegoAnalysis::default();
        let mut details = Vec::new();
        let mut lsb_ones = 0u64;
        let total_samples = samples.len() as u64;

        if total_samples == 0 { return analysis; }

        // Audio LSB stats
        for &s in samples {
            if s & 1 == 1 { lsb_ones += 1; }
        }

        let lsb_ratio = lsb_ones as f64 / total_samples as f64;
        
        // LSB Ratio Check
        if (lsb_ratio - 0.5).abs() > 0.1 {
             details.push(format!("Audio LSB ratio anomaly: {:.3} (expected ~0.5)", lsb_ratio));
             analysis.confidence += 25;
        }

        // Entropy of LSBs
        // Group into bytes
        let mut lsb_bytes = Vec::with_capacity(samples.len() / 8);
        let mut current = 0u8;
        let mut bits = 0;
        for &s in samples {
            current = (current << 1) | ((s & 1) as u8);
            bits += 1;
            if bits == 8 {
                lsb_bytes.push(current);
                current = 0;
                bits = 0;
            }
        }

        // Calculate entropy
        let mut freq = [0u64; 256];
        for &b in &lsb_bytes { freq[b as usize] += 1; }
        let mut entropy = 0.0;
        let total_bytes = lsb_bytes.len() as f64;
        if total_bytes > 0.0 {
            for &c in &freq {
                if c > 0 {
                    let p = c as f64 / total_bytes;
                    entropy -= p * p.log2();
                }
            }
        }

        // Max entropy is 8.0. If it's too close to 8.0 (like > 7.95) it's suspicious for encrypted data.
        // If it's too low, it's just silence/patterns.
        // Stego often manifests as high entropy.
        if entropy > 7.9 {
            details.push(format!("High Audio LSB Entropy: {:.3} (Suspicious)", entropy));
            analysis.confidence += 35;
        }

        analysis.detected = analysis.confidence >= 50;
        analysis.details = details;
        if analysis.detected {
            analysis.detection_method = Some("Audio LSB Statistical Anomaly".to_string());
        }

        // Fill entropy analysis struct partially for reporting
        analysis.entropy_analysis = Some(EntropyAnalysis {
            lsb_entropy: entropy,
            overall_entropy: 0.0, // Not calculated for audio yet
            entropy_ratio: 0.0,
        });

        analysis
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_formats() {
        assert!(StegoDetector::is_supported_format(Path::new("test.png")));
        assert!(StegoDetector::is_supported_format(Path::new("test.jpg")));
        assert!(StegoDetector::is_supported_format(Path::new("test.JPEG")));
        assert!(!StegoDetector::is_supported_format(Path::new("test.txt")));
        assert!(!StegoDetector::is_supported_format(Path::new("test.pdf")));
    }

    #[test]
    fn test_chi_square_pvalue() {
        let p = StegoDetector::chi_square_pvalue(0.0, 1);
        assert!((p - 1.0).abs() < 0.01, "Chi-square 0 should give p~1");
        
        let p_high = StegoDetector::chi_square_pvalue(10.0, 1);
        assert!(p_high < 0.01, "High chi-square should give low p-value");
    }
}
