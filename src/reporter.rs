use crate::models::{ScanReport};

pub struct HtmlReporter;

impl HtmlReporter {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_report(&self, report: &ScanReport, output_base: &str) -> Result<(), Box<dyn std::error::Error>> {
        let html_content = self.generate_html(report);
        let filename = format!("{}.html", output_base);
        std::fs::write(&filename, html_content)?;
        println!("📄 HTML report generated: {}", filename);
        Ok(())
    }

    fn truncate_middle(s: &str, max_len: usize) -> String {
        let len = s.chars().count();
        if len <= max_len {
            return s.to_string();
        }
        let half = max_len / 2;
        let start: String = s.chars().take(half).collect();
        let end: String = s.chars()
                          .rev()
                          .take(half)
                          .collect::<String>()
                          .chars()
                          .rev()
                          .collect();
        format!("{}…{}", start, end)
    }

    fn generate_html(&self, report: &ScanReport) -> String {
        let mut asset_cards = String::new();
        
        for (index, asset) in report.assets.iter().enumerate() {
            let badge_class = if asset.is_file { "badge-file" } else { "badge-folder" };
            let badge_text = if asset.is_file { "📄 FILE" } else { "📁 DIR" };
            let asset_icon = if asset.is_file { "🔹" } else { "📂"};
            
            let size_display = asset.size
                .map(|s| self.format_file_size(s))
                .unwrap_or_else(|| "N/A".to_string());

            let (risk_color_class, risk_label, risk_emoji) = match asset.risk_score {
                0..=25 => ("text-green-400", "LOW", "🟢"),
                26..=50 => ("text-yellow-400", "MEDIUM", "🟡"), 
                51..=75 => ("text-orange-400", "HIGH", "🟠"),
                _ => ("text-red-400", "CRITICAL", "🔴"),
            };

            // Criticality text within the asset box
            let risk_summary_text = format!(r#"
                <div class="risk-summary">
                    <span class="risk-label-text {}">Risk Level: {} ({})</span>
                </div>
            "#, risk_color_class, risk_label, asset.risk_score);


            let matches_info = if !asset.content_matches.is_empty() {
                format!(r#"
                <div class="stat-pill bg-blue-500/20 border-blue-400/30">
                    <span class="stat-icon">🔍</span>
                    <span class="stat-text">{} Content Matches</span>
                </div>"#, asset.content_matches.len())
            } else {
                String::new()
            };

            let urls_info = if !asset.contains_urls.is_empty() {
                format!(r#"
                <div class="stat-pill bg-green-500/20 border-green-400/30">
                    <span class="stat-icon">🌐</span>
                    <span class="stat-text">{} URLs</span>
                </div>"#, asset.contains_urls.len())
            } else {
                String::new()
            };

            let emails_info = if !asset.contains_emails.is_empty() {
                format!(r#"
                <div class="stat-pill bg-purple-500/20 border-purple-400/30">
                    <span class="stat-icon">📧</span>
                    <span class="stat-text">{} Emails</span>
                </div>"#, asset.contains_emails.len())
            } else {
                String::new()
            };

            let credentials_info = if !asset.contains_credentials.is_empty() {
                format!(r#"
                <div class="stat-pill bg-red-500/20 border-red-400/30 pulse">
                    <span class="stat-icon">🔑</span>
                    <span class="stat-text">{} Credentials</span>
                </div>"#, asset.contains_credentials.len())
            } else {
                String::new()
            };

            // New: Hidden file info
            let hidden_info = if asset.is_hidden {
                format!(r#"
                <div class="stat-pill bg-gray-500/20 border-gray-400/30">
                    <span class="stat-icon">🕵️</span>
                    <span class="stat-text">Hidden File</span>
                </div>"#)
            } else {
                String::new()
            };

            // New: Encrypted content info
            let encrypted_info = if asset.encrypted_content {
                format!(r#"
                <div class="stat-pill bg-indigo-500/20 border-indigo-400/30 pulse">
                    <span class="stat-icon">🔒</span>
                    <span class="stat-text">Encrypted Content</span>
                </div>"#)
            } else {
                String::new()
            };

            // New: Steganography detected info
            let steganography_info = if asset.steganography_detected {
                format!(r#"
                <div class="stat-pill bg-pink-500/20 border-pink-400/30 pulse">
                    <span class="stat-icon">🎨</span>
                    <span class="stat-text">Steganography Detected</span>
                </div>"#)
            } else {
                String::new()
            };

            // New: Entropy info
            let entropy_info = if let Some(entropy) = asset.entropy {
                format!(r#"
                <div class="stat-pill bg-teal-500/20 border-teal-400/30">
                    <span class="stat-icon">🎲</span>
                    <span class="stat-text">Entropy: {:.2}</span>
                </div>"#, entropy)
            } else {
                String::new()
            };

            let hash_info = if asset.md5_hash.is_some() || asset.sha256_hash.is_some() || asset.sha3_hash.is_some() || asset.blake3_hash.is_some() {
                let mut hashes = String::new();
                if let Some(md5) = &asset.md5_hash {
                    let truncated_md5 = if md5.len() > 16 { format!("{}...", &md5[..16]) } else { md5.clone() };
                    hashes.push_str(&format!(r#"
                    <div class="hash-row">
                        <span class="hash-label">MD5</span>
                        <code class="hash-value" title="{}">{}</code>
                    </div>"#, md5, truncated_md5));
                }
                if let Some(sha256) = &asset.sha256_hash {
                    let truncated_sha256 = if sha256.len() > 16 { format!("{}...", &sha256[..16]) } else { sha256.clone() };
                    hashes.push_str(&format!(r#"
                    <div class="hash-row">
                        <span class="hash-label">SHA256</span>
                        <code class="hash-value" title="{}">{}</code>
                    </div>"#, sha256, truncated_sha256));
                }
                // New: SHA3 Hash
                if let Some(sha3) = &asset.sha3_hash {
                    let truncated_sha3 = if sha3.len() > 16 { format!("{}...", &sha3[..16]) } else { sha3.clone() };
                    hashes.push_str(&format!(r#"
                    <div class="hash-row">
                        <span class="hash-label">SHA3</span>
                        <code class="hash-value" title="{}">{}</code>
                    </div>"#, sha3, truncated_sha3));
                }
                // New: Blake3 Hash
                if let Some(blake3) = &asset.blake3_hash {
                    let truncated_blake3 = if blake3.len() > 16 { format!("{}...", &blake3[..16]) } else { blake3.clone() };
                    hashes.push_str(&format!(r#"
                    <div class="hash-row">
                        <span class="hash-label">BLAKE3</span>
                        <code class="hash-value" title="{}">{}</code>
                    </div>"#, blake3, truncated_blake3));
                }
                format!(r#"<div class="hash-container">{}</div>"#, hashes)
            } else {
                String::new()
            };

            // Get the absolute path for display
            let full_path = asset.path.canonicalize()
                .unwrap_or_else(|_| asset.path.to_path_buf())
                .display()
                .to_string();

            let display_path = Self::truncate_middle(
                    &asset.path
                        .canonicalize()
                        .unwrap_or_else(|_| asset.path.to_path_buf())
                        .display()
                        .to_string(),
                    25,
                );

            // New: Threat Indicators Details
            let threat_details = if !asset.threat_indicators.is_empty() {
                let mut list_items = String::new();
                for threat in &asset.threat_indicators {
                    list_items.push_str(&format!(r#"<li><strong>{} (Confidence: {}):</strong> {}</li>"#, 
                        threat.indicator_type, threat.confidence, threat.description));
                }
                format!(r#"
                <div class="details-container">
                    <div class="details-header" onclick="toggleDetails(this)">
                        <span class="details-title">🚨 Threat Indicators ({})</span>
                        <span class="toggle-icon">▼</span>
                    </div>
                    <div class="details-content hidden">
                        <ul>{}</ul>
                    </div>
                </div>"#, asset.threat_indicators.len(), list_items)
            } else {
                String::new()
            };

            // New: Crypto Artifacts Details
            let crypto_details = if !asset.crypto_artifacts.is_empty() {
                let mut list_items = String::new();
                for crypto in &asset.crypto_artifacts {
                    list_items.push_str(&format!(r#"<li><strong>{}:</strong> {}</li>"#, 
                        crypto.crypto_type, crypto.value));
                }
                format!(r#"
                <div class="details-container">
                    <div class="details-header" onclick="toggleDetails(this)">
                        <span class="details-title">🔐 Crypto Artifacts ({})</span>
                        <span class="toggle-icon">▼</span>
                    </div>
                    <div class="details-content hidden">
                        <ul>{}</ul>
                    </div>
                </div>"#, asset.crypto_artifacts.len(), list_items)
            } else {
                String::new()
            };

            // New: Forensic Evidence Details
            let forensic_details = if !asset.forensic_evidence.is_empty() {
                let mut list_items = String::new();
                for evidence in &asset.forensic_evidence {
                    // Changed 'evidence.value' to 'evidence.confidence' to match available fields
                    list_items.push_str(&format!(r#"<li><strong>{} (Confidence: {}):</strong> {}</li>"#, 
                        evidence.evidence_type, evidence.confidence, evidence.description));
                }
                format!(r#"
                <div class="details-container">
                    <div class="details-header" onclick="toggleDetails(this)">
                        <span class="details-title">🔬 Forensic Evidence ({})</span>
                        <span class="toggle-icon">▼</span>
                    </div>
                    <div class="details-content hidden">
                        <ul>{}</ul>
                    </div>
                </div>"#, asset.forensic_evidence.len(), list_items)
            } else {
                String::new()
            };

            // New: Code Analysis Details
            let code_analysis_details = if !asset.code_analysis.is_empty() {
                let mut list_items = String::new();
                for (key, value) in &asset.code_analysis {
                    list_items.push_str(&format!(r#"<li><strong>{}:</strong> {}</li>"#, key.replace("_", " ").to_uppercase(), value));
                }
                format!(r#"
                <div class="details-container">
                    <div class="details-header" onclick="toggleDetails(this)">
                        <span class="details-title">💻 Code Analysis</span>
                        <span class="toggle-icon">▼</span>
                    </div>
                    <div class="details-content hidden">
                        <ul>{}</ul>
                    </div>
                </div>"#, list_items)
            } else {
                String::new()
            };
            // Removed: let exampletxt: String="main".to_string();

            let card = format!(r#"
                <div class="asset-card" data-asset-name="{}" data-asset-path="{}" style="animation-delay: {}ms">
                    <div class="card-header">
                        <div class="asset-title">
                            <span class="asset-icon">{}</span>
                            <h3 class="asset-name" title="{}">{}</h3>
                        </div>
                        <div class="card-badges">
                            <span class="badge {}">{}</span>
                            <div class="risk-badge {} glow">
                                <span class="risk-emoji">{}</span>
                                <span class="risk-text">{}</span>
                                <span class="risk-score">{}</span>
                            </div>
                        </div>
                    </div>
                    {} <!-- Risk Summary Text -->
                    <div class="asset-metadata">
                        <div class="meta-grid">
                            <div class="meta-item">
                                <span class="meta-icon">📍</span>
                                <span class="meta-label">Path</span>
                                <a href="file://{}" class="meta-value path-link" title="Click to open location">{}</a>
                            </div>
                            <div class="meta-item">
                                <span class="meta-icon">📏</span>
                                <span class="meta-label">Size</span>
                                <span class="meta-value">{}</span>
                            </div>
                            <div class="meta-item">
                                <span class="meta-icon">⏰</span>
                                <span class="meta-label">Modified</span>
                                <span class="meta-value">{}</span>
                            </div>
                            <div class="meta-item">
                                <span class="meta-icon">➕</span>
                                <span class="meta-label">Created</span>
                                <span class="meta-value">{}</span>
                            </div>
                            <div class="meta-item">
                                <span class="meta-icon">👁️</span>
                                <span class="meta-label">Accessed</span>
                                <span class="meta-value">{}</span>
                            </div>
                            <div class="meta-item">
                                <span class="meta-icon">📄</span>
                                <span class="meta-label">MIME Type</span>
                                <span class="meta-value">{}</span>
                            </div>
                            <div class="meta-item">
                                <span class="meta-icon">✍️</span>
                                <span class="meta-label">Signature</span>
                                <span class="meta-value">{}</span>
                            </div>
                            <div class="meta-item">
                                <span class="meta-icon">🔐</span>
                                <span class="meta-label">Permissions</span>
                                <span class="meta-value">{}</span>
                            </div>
                            <div class="meta-item">
                                <span class="meta-icon">👤</span>
                                <span class="meta-label">Owner</span>
                                <span class="meta-value">{}</span>
                            </div>
                        </div>
                    </div>

                    <div class="findings-section">
                        <div class="findings-grid">
                            {}{}{}{}{}{}{}{}
                        </div>
                    </div>

                    {} <!-- Hash Info -->
                    {} <!-- Threat Details -->
                    {} <!-- Crypto Details -->
                    {} <!-- Forensic Details -->
                    {} <!-- Code Analysis Details -->
                </div>
            "#,
                asset.path.file_name().unwrap_or_default().to_string_lossy(), // data-asset-name
                full_path, // data-asset-path
                index * 100, // staggered animation delay
                asset_icon,
                asset.path.display(),
                asset.path.file_name().unwrap_or_default().to_string_lossy(),
                badge_class,
                badge_text,
                risk_color_class, // Use the new class name
                risk_emoji,
                risk_label,
                asset.risk_score,
                risk_summary_text, // Insert risk summary text here
                full_path, // Full absolute path for the file:// link
                display_path, // Full absolute path display text
                size_display,
                asset.modified.as_deref().unwrap_or("Unknown"),
                asset.created.as_deref().unwrap_or("Unknown"), // New: Created
                asset.accessed.as_deref().unwrap_or("Unknown"), // New: Accessed
                asset.mime_type.as_deref().unwrap_or("Unknown"), // New: MIME Type
                asset.file_signature.as_deref().unwrap_or("Unknown"), // New: File Signature
                asset.permissions,
                asset.owner,
                matches_info,
                urls_info,
                emails_info,
                credentials_info,
                hidden_info, // New: Hidden info
                encrypted_info, // New: Encrypted info
                steganography_info, // New: Steganography info
                entropy_info, // New: Entropy info
                hash_info,
                threat_details, // New: Threat details
                crypto_details, // New: Crypto details
                forensic_details, // New: Forensic details
                code_analysis_details
                // Removed: exampletxt
            );
            asset_cards.push_str(&card);
        }

        // Calculate some stats
        let _high_risk_count = report.assets.iter().filter(|a| a.risk_score > 50).count();
        let files_count = report.assets.iter().filter(|a| a.is_file).count();
        let _dirs_count = report.assets.len() - files_count;
        let _total_findings = report.assets.iter()
            .map(|a| a.content_matches.len() + a.contains_urls.len() + a.contains_emails.len() + a.contains_credentials.len())
            .sum::<usize>();

        format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Synth - Security Asset Report</title>
    <!-- Google Fonts: JetBrains Mono for code/tech, Inter for general text -->
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        /* CSS Variables for a consistent neon tech palette */
        :root {{
            --bg-primary: #020205; /* Deep dark background */
            --bg-secondary: #0c0c12; /* Slightly lighter dark for contrast */
            --bg-card: rgba(10, 10, 25, 0.7); /* Translucent dark blue for glass effect */
            --border-primary: rgba(0, 255, 157, 0.15); /* Subtle neon green border */
            --border-glow: rgba(0, 255, 157, 0.6); /* Stronger neon green for hover/focus */
            --text-primary: #e0e0ff; /* Soft blue-white text */
            --text-secondary: #a0a0c0; /* Muted blue-grey for secondary text */
            --text-muted: #606080; /* Even more muted for less important text */

            --neon-green: #00ff9d; /* Primary neon accent */
            --neon-blue: #00d4ff; /* Secondary neon accent */
            --neon-purple: #8b5cf6; /* Tertiary neon accent */
            --neon-pink: #ff00ff; /* Additional vibrant neon */
            --neon-red: #ff3131; /* Danger/critical neon */

            --gradient-primary: linear-gradient(135deg, var(--neon-green) 0%, var(--neon-blue) 100%);
            --gradient-secondary: linear-gradient(135deg, var(--neon-purple) 0%, var(--neon-pink) 100%);
            --gradient-danger: linear-gradient(135deg, var(--neon-red) 0%, #ff6b35 100%);
        }}

        /* Base styles for the entire document */
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Inter', sans-serif;
            line-height: 1.6;
            overflow-x: hidden; /* Prevent horizontal scroll */
            perspective: 1000px; /* Global perspective for 3D effects */
        }}

        /* Custom scrollbar for tech aesthetic */
        ::-webkit-scrollbar {{ width: 8px; }}
        ::-webkit-scrollbar-track {{ background: var(--bg-secondary); }}
        ::-webkit-scrollbar-thumb {{ background: var(--gradient-primary); border-radius: 4px; }}

        /* Background animation for tech pulse and hacker feel */
        .bg-animation {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -2; /* Ensures it's behind all content */
            background:
                radial-gradient(circle at 20% 80%, rgba(0, 255, 157, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(0, 212, 255, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(139, 92, 246, 0.1) 0%, transparent 50%);
            animation: backgroundShift 20s ease-in-out infinite;
            overflow: hidden;
        }}

        /* Subtle scanline overlay for hacker tech feel */
        .bg-animation::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: repeating-linear-gradient(
                0deg,
                rgba(0, 255, 157, 0.02),
                rgba(0, 255, 157, 0.02) 1px,
                transparent 1px,
                transparent 3px
            ); /* Faint horizontal lines */
            opacity: 0.3;
            animation: scanlineFade 15s linear infinite;
            pointer-events: none; /* Allows clicks/selection through overlay */
        }}

        /* Subtle background pulse effect */
        .bg-animation::after {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: radial-gradient(circle at center, rgba(0, 255, 255, 0.05) 0%, transparent 70%);
            animation: subtlePulse 10s ease-in-out infinite alternate;
            pointer-events: none;
        }}

        /* Keyframe animations for background and overlays */
        @keyframes backgroundShift {{
            0%, 100% {{ transform: translate(0, 0) rotate(0deg); }}
            33% {{ transform: translate(-10px, -10px) rotate(1deg); }}
            66% {{ transform: translate(10px, -5px) rotate(-1deg); }}
        }}

        @keyframes scanlineFade {{
            0% {{ background-position: 0 0; }}
            100% {{ background-position: 0 100%; }}
        }}

        @keyframes subtlePulse {{
            0% {{ transform: scale(1); opacity: 0.05; }}
            50% {{ transform: scale(1.1); opacity: 0.1; }}
            100% {{ transform: scale(1); opacity: 0.05; }}
        }}

        /* Grid background animation */
        .grid-background {{
            position: absolute; /* Changed to absolute for banner */
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image:
                linear-gradient(to right, rgba(0, 255, 255, 0.05) 1px, transparent 1px),
                linear-gradient(to bottom, rgba(0, 255, 255, 0.05) 1px, transparent 1px);
            background-size: 40px 40px; /* Updated size */
            animation: grid-pan 60s linear infinite; /* Updated animation name */
            opacity: 0.3; /* Updated opacity */
            z-index: 0; /* Ensures it's behind banner content but above main bg */
        }}

        @keyframes grid-pan {{ /* New animation for grid */
            from {{ background-position: 0 0; }}
            to {{ background-position: 100% 100%; }}
        }}


        /* Main content container */
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
            position: relative;
            z-index: 1; /* Bring content above background */
            transform-style: preserve-3d; /* Enable 3D for children elements */
            transform: translateZ(0); /* Establish a Z-plane for the container */
        }}

        /* Header styling with subtle 3D tilt */
        .header {{
            text-align: center;
            margin-bottom: 3rem;
            position: relative;
            transform: rotateX(5deg) translateZ(-50px); /* Initial subtle tilt and depth */
            transition: transform 0.5s ease-out;
            transform-origin: center top;
        }}
        .header:hover {{
            transform: rotateX(0deg) translateZ(0px); /* Straighten on hover */
        }}

        /* Main title with intense neon glow */
        .title {{
            font-size: 3.5rem;
            font-weight: 700;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
            text-shadow:
                0 0 10px var(--neon-green),
                0 0 20px var(--neon-blue),
                0 0 30px var(--neon-green),
                0 0 40px var(--neon-blue); /* Layered shadows for deep glow */
            animation: titleGlow 3s ease-in-out infinite alternate,
                       pulseText 2s infinite alternate; /* Combined animations */
        }}

        /* Keyframe animations for title glow and pulse */
        @keyframes titleGlow {{
            from {{ filter: drop-shadow(0 0 20px rgba(0, 255, 157, 0.3)); }}
            to {{ filter: drop-shadow(0 0 30px rgba(0, 212, 255, 0.5)); }}
        }}
        @keyframes pulseText {{
            0% {{ text-shadow: 0 0 10px var(--neon-green), 0 0 20px var(--neon-blue); }}
            100% {{ text-shadow: 0 0 15px var(--neon-green), 0 0 25px var(--neon-blue); }}
        }}

        /* Subtitle styling */
        .subtitle {{
            color: var(--text-secondary);
            font-size: 1.1rem;
            margin-bottom: 2rem;
        }}

        /* Timestamp styling with glass effect */
        .timestamp {{
            display: inline-block;
            background: rgba(255, 255, 255, 0.05); /* Very subtle transparency */
            backdrop-filter: blur(5px);
            -webkit-backdrop-filter: blur(5px);
            border: 1px solid rgba(0, 255, 157, 0.1);
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            color: var(--neon-green);
            box-shadow: 0 0 5px rgba(0, 255, 157, 0.2);
            transition: all 0.3s ease;
        }}
        .timestamp:hover {{
            box-shadow: 0 0 15px rgba(0, 255, 157, 0.4);
            transform: translateY(-2px);
        }}

        /* Grid for statistics cards */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }}

        /* Individual statistic card with glass and 3D hover effects */
        .stat-card {{
            background: var(--bg-card); /* Translucent background */
            border: 1px solid var(--border-primary);
            border-radius: 1rem;
            padding: 1.5rem;
            text-align: center;
            backdrop-filter: blur(15px); /* Frosted glass effect */
            -webkit-backdrop-filter: blur(15px);
            transition: all 0.5s ease; /* Smooth transition for 3D effects */
            position: relative;
            overflow: hidden;
            transform-style: preserve-3d; /* Enable 3D for internal elements if needed */
            transform: translateZ(0); /* Establish initial Z-plane */
            box-shadow:
                0 0 10px rgba(0, 255, 157, 0.1), /* Inner glow */
                0 0 20px rgba(0, 212, 255, 0.1), /* Outer glow */
                0 10px 30px rgba(0, 0, 0, 0.4); /* Drop shadow for depth */
        }}

        /* Hover effect for stat cards: lift, tilt, and stronger glow */
        .stat-card:hover {{
            border-color: var(--border-glow);
            transform: translateY(-5px) rotateX(2deg) rotateY(-2deg) translateZ(20px); /* Lift and subtle 3D tilt */
            box-shadow:
                0 0 15px rgba(0, 255, 157, 0.3),
                0 0 30px rgba(0, 212, 255, 0.3),
                0 15px 40px rgba(0, 0, 0, 0.6);
        }}

        /* Stat values with neon colors and JetBrains Mono font */
        .stat-value {{
            font-size: 2.5rem;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            margin-bottom: 0.5rem;
            display: block;
            text-shadow: 0 0 8px rgba(255, 255, 255, 0.5); /* Subtle text glow */
        }}

        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        /* Specific neon colors for stat values */
        .stat-green {{ color: var(--neon-green); }}
        .stat-cyan {{ color: var(--neon-blue); }}
        .stat-purple {{ color: var(--neon-purple); }}
        .stat-orange {{ color: #ff8c00; }} /* Keeping original orange for consistency */

        /* Assets section styling */
        .assets-container {{ margin-top: 3rem; }}
        .section-title {{
            font-size: 1.8rem; /* Slightly larger title */
            font-weight: 600;
            margin-bottom: 1.5rem;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            text-shadow: 0 0 10px rgba(0, 255, 157, 0.3); /* Glow for section title */
        }}

        /* Search input styling */
        .search-input {{
            width: 100%;
            padding: 0.75rem 1rem;
            margin-bottom: 2rem;
            background: rgba(10, 10, 25, 0.8); /* Match card background */
            border: 1px solid var(--border-primary);
            border-radius: 0.75rem;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 1rem;
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            box-shadow: 0 0 10px rgba(0, 255, 157, 0.1);
            transition: all 0.3s ease;
        }}

        .search-input::placeholder {{
            color: var(--text-muted);
            opacity: 0.7;
        }}

        .search-input:focus {{
            outline: none;
            border-color: var(--neon-green);
            box-shadow: 0 0 15px var(--neon-green);
        }}

        /* Asset card with glass and 3D hover effects, staggered animation */
        .asset-card {{
            background: var(--bg-card); /* Translucent background */
            border: 1px solid var(--border-primary);
            border-radius: 1rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            backdrop-filter: blur(15px); /* Frosted glass effect */
            -webkit-backdrop-filter: blur(15px);
            transition: all 0.5s ease; /* Smooth transition for 3D effects */
            animation: slideInUp 0.6s ease-out both; /* Staggered entry animation */
            position: relative;
            overflow: hidden;
            transform-style: preserve-3d;
            transform: translateZ(0);
            box-shadow:
                0 0 10px rgba(0, 255, 157, 0.1),
                0 0 20px rgba(0, 212, 255, 0.1),
                0 10px 30px rgba(0, 0, 0, 0.4);
        }}

        /* Keyframe for staggered slide-in animation */
        @keyframes slideInUp {{
            from {{ opacity: 0; transform: translateY(50px) translateZ(0); }}
            to {{ opacity: 1; transform: translateY(0) translateZ(0); }}
        }}

        /* Hover effect for asset cards: lift, tilt, and stronger glow */
        .asset-card:hover {{
            border-color: var(--border-glow);
            transform: translateY(-5px) rotateX(2deg) rotateY(2deg) translateZ(20px); /* Lift and subtle 3D tilt */
            box-shadow:
                0 0 15px rgba(0, 255, 157, 0.3),
                0 0 30px rgba(0, 212, 255, 0.3),
                0 15px 40px rgba(0, 0, 0, 0.6);
        }}

        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }}

        .asset-title {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex: 1;
            min-width: 0;
        }}

        .asset-icon {{ font-size: 1.5rem; flex-shrink: 0; text-shadow: 0 0 5px var(--neon-blue); }}
        .asset-name {{
            font-size: 1.2rem; /* Slightly larger asset name */
            font-weight: 500;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            overflow: hidden;
            white-space: nowrap;
            text-overflow: ellipsis;
            text-shadow: 0 0 5px rgba(255, 255, 255, 0.3);
        }}

        .card-badges {{
            display: flex;
            gap: 0.75rem;
            align-items: center;
            flex-shrink: 0;
        }}

        .badge {{
            padding: 0.3rem 0.8rem; /* Slightly larger padding */
            border-radius: 0.75rem; /* More rounded */
            font-size: 0.8rem;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            backdrop-filter: blur(5px); /* Glass effect on badges */
            -webkit-backdrop-filter: blur(5px);
            box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
        }}

        .badge-file {{
            background: rgba(34, 197, 94, 0.2);
            color: #22c55e;
            border: 1px solid rgba(34, 197, 94, 0.3);
        }}

        .badge-folder {{
            background: rgba(59, 130, 246, 0.2);
            color: #3b82f6;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }}

        /* Risk badge with glow and pulse */
        .risk-badge {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 0.75rem;
            border-radius: 0.75rem;
            font-size: 0.8rem;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            backdrop-filter: blur(5px);
            -webkit-backdrop-filter: blur(5px);
            box-shadow: 0 0 8px rgba(0, 0, 0, 0.3); /* Base shadow */
            transition: all 0.3s ease;
        }}
        .risk-badge.glow {{
            animation: badgeGlow 1.5s infinite alternate; /* Neon pulse for risk badges */
        }}

        @keyframes badgeGlow {{
            0% {{ box-shadow: 0 0 8px rgba(0, 0, 0, 0.3); }}
            100% {{ box-shadow: 0 0 15px rgba(0, 255, 157, 0.5); }} /* Example glow color */
        }}


        .text-green-400 {{
            background: rgba(34, 197, 94, 0.2);
            color: #22c55e;
            border: 1px solid rgba(34, 197, 94, 0.3);
        }}
        .text-yellow-400 {{
            background: rgba(245, 158, 11, 0.2);
            color: #f59e0b;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }}
        .text-orange-400 {{
            background: rgba(255, 140, 0, 0.2);
            color: #ff8c00;
            border: 1px solid rgba(255, 140, 0, 0.3);
        }}
        .text-red-400 {{
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}

        /* New: Risk Summary Text */
        .risk-summary {{
            margin-top: 0.5rem;
            padding: 0.5rem 0;
            text-align: left;
        }}
        .risk-label-text {{
            font-size: 0.95rem;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            text-shadow: 0 0 8px rgba(255, 255, 255, 0.5);
        }}


        .asset-metadata {{ margin: 1rem 0; }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }}

        .meta-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem;
            background: rgba(255, 255, 255, 0.02); /* Very subtle transparent background */
            border-radius: 0.5rem;
            border: 1px solid rgba(255, 255, 255, 0.05); /* Faint border */
            box-shadow: inset 0 0 5px rgba(0, 255, 157, 0.05); /* Subtle inner glow */
        }}

        .meta-icon {{ font-size: 1rem; opacity: 0.8; text-shadow: 0 0 3px rgba(255, 255, 255, 0.2); }}
        .meta-label {{ color: var(--text-secondary); font-size: 0.85rem; min-width: 70px; }}
        .meta-value {{
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            font-weight: 500;
            word-break: break-all; /* Ensure long paths break correctly */
        }}
        .path-link {{
            text-decoration: none;
            color: var(--neon-blue);
            transition: color 0.3s ease;
        }}
        .path-link:hover {{
            color: var(--neon-green);
            text-decoration: underline;
        }}

        .findings-section {{ margin-top: 1rem; }}
        .findings-grid {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
        }}

        /* Stat pills for findings with glass effect and hover */
        .stat-pill {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 0.75rem;
            border-radius: 0.75rem;
            font-size: 0.85rem;
            font-weight: 500;
            border: 1px solid;
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            transition: all 0.3s ease;
            box-shadow: 0 0 8px rgba(0, 0, 0, 0.3);
        }}

        .stat-pill:hover {{
            transform: scale(1.05) translateY(-2px);
            box-shadow: 0 0 15px rgba(0, 255, 255, 0.4); /* Cyan glow on hover */
        }}
        .stat-icon {{ font-size: 1rem; }}
        .pulse {{ animation: pulse 2s infinite; }} /* Existing pulse for critical */

        @keyframes pulse {{
            0%, 100% {{ opacity: 1; transform: scale(1); }}
            50% {{ opacity: 0.7; transform: scale(1.02); }}
        }}

        /* Hash container for MD5/SHA256 with hacker-tech styling */
        .hash-container {{
            margin-top: 1.5rem;
            padding: 1rem;
            background: rgba(0, 0, 0, 0.4); /* Darker background for code */
            border-radius: 0.75rem;
            border: 1px solid rgba(0, 255, 157, 0.1); /* Neon green border */
            box-shadow: inset 0 0 10px rgba(0, 255, 157, 0.1); /* Inner glow */
        }}

        .hash-row {{
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 0.75rem;
        }}

        .hash-row:last-child {{ margin-bottom: 0; }}
        .hash-label {{
            color: var(--text-secondary);
            font-size: 0.8rem;
            font-weight: 600;
            min-width: 70px;
            text-transform: uppercase;
            font-family: 'JetBrains Mono', monospace;
        }}

        .hash-value {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--neon-green); /* Hacker green text */
            background: rgba(0, 255, 157, 0.08); /* Subtle green background */
            padding: 0.3rem 0.6rem;
            border-radius: 0.3rem;
            cursor: pointer;
            transition: all 0.3s ease;
            word-break: break-all;
            text-shadow: 0 0 5px rgba(0, 255, 157, 0.4); /* Glowing text */
        }}

        .hash-value:hover {{
            background: rgba(0, 255, 157, 0.2);
            transform: scale(1.02);
            box-shadow: 0 0 15px rgba(0, 255, 157, 0.6); /* Stronger glow on hover */
        }}

        /* New: Collapsible Details Sections */
        .details-container {{
            margin-top: 1rem;
            background: rgba(0, 0, 0, 0.25); /* Slightly transparent background */
            border-radius: 0.75rem;
            border: 1px solid rgba(0, 255, 255, 0.1); /* Cyan border */
            overflow: hidden; /* Hide overflow when content is collapsed */
            box-shadow: inset 0 0 10px rgba(0, 255, 255, 0.05);
        }}

        .details-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem 1rem;
            background: rgba(0, 255, 255, 0.1); /* Cyan header background */
            cursor: pointer;
            font-family: 'JetBrains Mono', monospace;
            font-weight: 600;
            color: var(--neon-blue);
            text-shadow: 0 0 5px rgba(0, 255, 255, 0.3);
            transition: background 0.3s ease;
        }}

        .details-header:hover {{
            background: rgba(0, 255, 255, 0.2);
        }}

        .details-title {{
            flex-grow: 1;
        }}

        .toggle-icon {{
            transition: transform 0.3s ease;
        }}

        .details-content {{
            padding: 1rem;
            max-height: 500px; /* Max height for transition */
            overflow: hidden;
            transition: max-height 0.5s ease-out, padding 0.5s ease-out, opacity 0.5s ease-out;
            opacity: 1;
        }}

        .details-content.hidden {{
            max-height: 0;
            padding-top: 0;
            padding-bottom: 0;
            opacity: 0;
        }}

        .details-content ul {{
            list-style: none; /* Remove default bullet points */
            padding-left: 0;
        }}

        .details-content li {{
            margin-bottom: 0.5rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--text-primary);
            word-break: break-all;
        }}
        .details-content li:last-child {{
            margin-bottom: 0;
        }}
        .details-content li strong {{
            color: var(--neon-green);
        }}


        /* Footer styling */
        .footer {{
            text-align: center;
            margin-top: 4rem;
            padding: 2rem;
            border-top: 1px solid var(--border-primary);
            background: rgba(0, 0, 0, 0.2); /* Subtle transparent footer background */
            backdrop-filter: blur(5px);
            -webkit-backdrop-filter: blur(5px);
            box-shadow: inset 0 5px 15px rgba(0, 255, 157, 0.05); /* Inner glow */
        }}

        .footer-text {{ color: var(--text-muted); font-size: 0.9rem; }}
        .footer-brand {{ color: var(--neon-green); font-weight: 600; text-shadow: 0 0 5px var(--neon-green); }}

        /* Banner Container */
        .banner-container {{
            position: relative;
            width: 100%;
            max-width: 960px; /* Standard banner width for GitHub */
            height: 250px; /* Standard banner height */
            background: linear-gradient(135deg, #0A0A1F 0%, #1A1A2E 100%);
            border-radius: 1rem; /* Rounded corners */
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0, 255, 255, 0.2), 0 0 60px rgba(0, 255, 255, 0.1);
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            padding: 1rem;
            text-align: center;
            margin: 2rem auto; /* Center the banner */
            z-index: 1; /* Ensure it's above backgrounds */
        }}

        /* Responsive adjustments */
        @media (max-width: 1024px) {{
            .container {{ padding: 1.5rem; }}
            .title {{ font-size: 3rem; }}
        }}

        @media (max-width: 768px) {{
            .container {{ padding: 1rem; }}
            .title {{ font-size: 2.5rem; }}
            .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .card-header {{
                flex-direction: column;
                gap: 1rem;
                align-items: flex-start;
            }}
            .meta-grid {{ grid-template-columns: 1fr; }}
            .findings-grid {{ justify-content: center; }}
            .hash-value {{ font-size: 0.75rem; padding: 0.25rem 0.5rem; }}
            .section-title {{ font-size: 1.5rem; }}
            .banner-container {{
                height: 200px; /* Adjust banner height for smaller screens */
            }}
        }}

        @media (max-width: 480px) {{
            .stats-grid {{ grid-template-columns: 1fr; }}
            .stat-value {{ font-size: 2rem; }}
            .title {{ font-size: 2rem; }}
            .asset-name {{ font-size: 1rem; }}
            .badge, .risk-badge, .stat-pill {{ font-size: 0.7rem; padding: 0.3rem 0.6rem; }}
            .meta-label {{ min-width: unset; }}
            .banner-container {{
                height: 150px; /* Further adjust banner height for mobile */
                border-radius: 0.5rem;
            }}
        }}

        /* Accessibility: Reduce motion for users who prefer it */
        @media (prefers-reduced-motion) {{
            .bg-animation,
            .bg-animation::before,
            .bg-animation::after,
            .header,
            .title,
            .stat-card,
            .asset-card,
            .stat-pill,
            .hash-value,
            .pulse,
            .risk-badge.glow,
            .grid-background {{ /* Include grid-background here */
                animation: none !important;
                transition: none !important;
                transform: none !important;
                filter: none !important;
                box-shadow: none !important;
                text-shadow: none !important;
            }}
            .stat-card:hover, .asset-card:hover {{
                transform: translateY(-2px); /* Keep a simple lift */
            }}
        }}
    </style>
</head>
<body>
    <div class="bg-animation"></div>
    
    <div class="banner-container">
        <div class="grid-background"></div> <!-- Grid background inside the banner -->
        <h1 class="title">Synth</h1>
        <p class="subtitle">Comprehensive Security Asset Analysis Report</p>
        <div class="timestamp">🕒 Scan: {}</div>
    </div>

    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-value stat-green">{}</span>
                <span class="stat-label">Total Assets</span>
            </div>
            <div class="stat-card">
                <span class="stat-value stat-cyan">{}</span>
                <span class="stat-label">Files Scanned</span>
            </div >
            <div class="stat-card">
                <span class="stat-value stat-purple">{:.1} MB</span>
                <span class="stat-label">Data Analyzed</span>
            </div>
            <div class="stat-card">
                <span class="stat-value stat-orange">{} sec</span>
                <span class="stat-label">Scan Duration</span>
            </div>
        </div>

        <div class="assets-container">
            <h2 class="section-title">🔍 Discovered Assets</h2>
            <input type="text" id="assetSearch" placeholder="Search assets by name or path..." class="search-input">
            {}
        </div>

        <footer class="footer">
            <p class="footer-text">Generated by <span class="footer-brand">Synth Tool</span></p>
            <p class="footer-text">Report generated on {}</p>
        </footer>
    </div>

    <script>
        // Add click-to-copy functionality for hash values
        document.querySelectorAll('.hash-value').forEach(hash => {{
            hash.addEventListener('click', () => {{
                // Get the full hash from the title attribute, not the truncated text content
                const fullHash = hash.getAttribute('title');
                navigator.clipboard.writeText(fullHash).then(() => {{
                    const originalBackground = hash.style.background;
                    const originalBoxShadow = hash.style.boxShadow;
                    hash.style.background = 'rgba(0, 255, 157, 0.3)'; // Visual feedback for copy
                    hash.style.boxShadow = '0 0 20px rgba(0, 255, 157, 0.8)';
                    setTimeout(() => {{
                        hash.style.background = originalBackground;
                        hash.style.boxShadow = originalBoxShadow;
                    }}, 300);
                }}).catch(err => {{
                    console.error('Failed to copy text: ', err);
                }});
            }});
        }});

        // Animate cards on scroll using IntersectionObserver
        const observer = new IntersectionObserver((entries) => {{
            entries.forEach(entry => {{
                if (entry.isIntersecting) {{
                    // Only add 'animate' class if not already present to prevent re-triggering
                    if (!entry.target.classList.contains('animate')) {{
                        entry.target.classList.add('animate');
                    }}
                }} else {{
                    // Optionally remove 'animate' class when out of view for re-animation on scroll back
                    entry.target.classList.remove('animate');
                }}
            }});
        }}, {{
            threshold: 0.1 // Trigger when 10% of the element is visible
        }});

        document.querySelectorAll('.asset-card').forEach(card => {{
            observer.observe(card);
        }});

        // Search functionality for asset cards
        const assetSearchInput = document.getElementById('assetSearch');
        assetSearchInput.addEventListener('input', (event) => {{
            const searchTerm = event.target.value.toLowerCase();
            document.querySelectorAll('.asset-card').forEach(card => {{
                const assetName = card.getAttribute('data-asset-name').toLowerCase();
                const assetPath = card.getAttribute('data-asset-path').toLowerCase();

                if (assetName.includes(searchTerm) || assetPath.includes(searchTerm)) {{
                    card.style.display = 'block'; // Show the card
                }} else {{
                    card.style.display = 'none'; // Hide the card
                }}
            }});
        }});

        // New: Toggle details section visibility
        function toggleDetails(headerElement) {{
            const content = headerElement.nextElementSibling;
            const icon = headerElement.querySelector('.toggle-icon');
            if (content.classList.contains('hidden')) {{
                content.classList.remove('hidden');
                icon.style.transform = 'rotate(180deg)';
            }} else {{
                content.classList.add('hidden');
                icon.style.transform = 'rotate(0deg)';
            }}
        }}
    </script>
</body>
</html>"#,
    report.scan_info.base_directory,
    report.assets.len(),
    report.scan_info.total_files_scanned,
    report.scan_info.total_bytes_analyzed as f64 / 1_048_576.0,
    report.scan_info.duration_seconds,
    asset_cards,
    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
)
    }

    fn format_file_size(&self, size: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size_f = size as f64;
        let mut unit_index = 0;

        while size_f >= 1024.0 && unit_index < UNITS.len() - 1 {
            size_f /= 1024.0;
            unit_index += 1;
        }

        if unit_index == 0 {
            format!("{} {}", size, UNITS[unit_index])
        } else {
            format!("{:.1} {}", size_f, UNITS[unit_index])
        }
    }
}
