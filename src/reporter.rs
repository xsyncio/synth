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

            let (risk_color, risk_label, risk_emoji) = match asset.risk_score {
                0..=25 => ("text-green-400", "LOW", "🟢"),
                26..=50 => ("text-yellow-400", "MEDIUM", "🟡"), 
                51..=75 => ("text-orange-400", "HIGH", "🟠"),
                _ => ("text-red-400", "CRITICAL", "🔴"),
            };

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

            let hash_info = if asset.md5_hash.is_some() || asset.sha256_hash.is_some() {
                let mut hashes = String::new();
                if let Some(md5) = &asset.md5_hash {
                    hashes.push_str(&format!(r#"
                    <div class="hash-row">
                        <span class="hash-label">MD5</span>
                        <code class="hash-value" title="{}">{}</code>
                    </div>"#, md5, &md5[..16]));
                }
                if let Some(sha256) = &asset.sha256_hash {
                    hashes.push_str(&format!(r#"
                    <div class="hash-row">
                        <span class="hash-label">SHA256</span>
                        <code class="hash-value" title="{}">{}</code>
                    </div>"#, sha256, &sha256[..16]));
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

            let card = format!(r#"
                <div class="asset-card" style="animation-delay: {}ms">
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
                            {}{}{}{}
                        </div>
                    </div>

                    {}
                </div>
            "#,
                index * 100, // staggered animation delay
                asset_icon,
                asset.path.display(),
                asset.path.file_name().unwrap_or_default().to_string_lossy(),
                badge_class,
                badge_text,
                risk_color,
                risk_emoji,
                risk_label,
                asset.risk_score,
                full_path, // Full absolute path for the file:// link
                display_path, // Full absolute path display text
                size_display,
                asset.modified.as_deref().unwrap_or("Unknown"),
                asset.permissions,
                asset.owner,
                matches_info,
                urls_info,
                emails_info,
                credentials_info,
                hash_info
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
    <title>Synth</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #0a0a0a;
            --bg-secondary: #111111;
            --bg-card: rgba(20, 20, 20, 0.8);
            --border-primary: rgba(255, 255, 255, 0.1);
            --border-glow: rgba(0, 255, 157, 0.3);
            --text-primary: #ffffff;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --accent-green: #00ff9d;
            --accent-cyan: #00d4ff;
            --accent-purple: #8b5cf6;
            --gradient-primary: linear-gradient(135deg, #00ff9d 0%, #00d4ff 100%);
            --gradient-danger: linear-gradient(135deg, #ff3333 0%, #ff6b35 100%);
        }}

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
            overflow-x: hidden;
        }}

        .bg-animation {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            background: 
                radial-gradient(circle at 20% 80%, rgba(0, 255, 157, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(0, 212, 255, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(139, 92, 246, 0.1) 0%, transparent 50%);
            animation: backgroundShift 20s ease-in-out infinite;
        }}

        @keyframes backgroundShift {{
            0%, 100% {{ transform: translate(0, 0) rotate(0deg); }}
            33% {{ transform: translate(-10px, -10px) rotate(1deg); }}
            66% {{ transform: translate(10px, -5px) rotate(-1deg); }}
        }}

        ::-webkit-scrollbar {{ width: 8px; }}
        ::-webkit-scrollbar-track {{ background: var(--bg-secondary); }}
        ::-webkit-scrollbar-thumb {{ background: var(--gradient-primary); border-radius: 4px; }}

        .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}
        .header {{ text-align: center; margin-bottom: 3rem; position: relative; }}
        
        .title {{
            font-size: 3.5rem;
            font-weight: 700;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
            animation: titleGlow 3s ease-in-out infinite alternate;
        }}

        @keyframes titleGlow {{
            from {{ filter: drop-shadow(0 0 20px rgba(0, 255, 157, 0.3)); }}
            to {{ filter: drop-shadow(0 0 30px rgba(0, 212, 255, 0.5)); }}
        }}

        .subtitle {{ color: var(--text-secondary); font-size: 1.1rem; margin-bottom: 2rem; }}
        
        .timestamp {{
            display: inline-block;
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            color: var(--accent-green);
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }}

        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 1rem;
            padding: 1.5rem;
            text-align: center;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}

        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
            transition: left 0.5s;
        }}

        .stat-card:hover::before {{ left: 100%; }}
        .stat-card:hover {{
            border-color: var(--border-glow);
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(0, 255, 157, 0.1);
        }}

        .stat-value {{
            font-size: 2.5rem;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            margin-bottom: 0.5rem;
            display: block;
        }}

        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .stat-green {{ color: var(--accent-green); }}
        .stat-cyan {{ color: var(--accent-cyan); }}
        .stat-purple {{ color: var(--accent-purple); }}
        .stat-orange {{ color: #ff8c00; }}

        .assets-container {{ margin-top: 3rem; }}
        .section-title {{
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .asset-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 1rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
            animation: slideInUp 0.6s ease-out both;
            position: relative;
            overflow: hidden;
        }}

        @keyframes slideInUp {{
            from {{ opacity: 0; transform: translateY(30px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        .asset-card:hover {{
            border-color: var(--border-glow);
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
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

        .asset-icon {{ font-size: 1.2rem; flex-shrink: 0; }}
        .asset-name {{
            font-size: 1.1rem;
            font-weight: 500;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            overflow: hidden;
            white-space: nowrap;
            text-overflow: ellipsis;
        }}

        .card-badges {{
            display: flex;
            gap: 0.75rem;
            align-items: center;
            flex-shrink: 0;
        }}

        .badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 0.5rem;
            font-size: 0.75rem;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
            text-transform: uppercase;
            letter-spacing: 0.05em;
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

        .risk-badge {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 0.75rem;
            border-radius: 0.5rem;
            font-size: 0.75rem;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .risk-high {{
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}

        .risk-medium {{
            background: rgba(245, 158, 11, 0.2);
            color: #f59e0b;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }}

        .risk-low {{
            background: rgba(34, 197, 94, 0.2);
            color: #22c55e;
            border: 1px solid rgba(34, 197, 94, 0.3);
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
            background: rgba(255, 255, 255, 0.02);
            border-radius: 0.5rem;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }}

        .meta-icon {{ font-size: 0.9rem; opacity: 0.7; }}
        .meta-label {{ color: var(--text-secondary); font-size: 0.8rem; min-width: 60px; }}
        .meta-value {{
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            font-weight: 500;
        }}

        .findings-section {{ margin-top: 1rem; }}
        .findings-grid {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
        }}

        .stat-pill {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 0.75rem;
            border-radius: 0.75rem;
            font-size: 0.8rem;
            font-weight: 500;
            border: 1px solid;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
        }}

        .stat-pill:hover {{ transform: scale(1.05); }}
        .stat-icon {{ font-size: 0.9rem; }}
        .pulse {{ animation: pulse 2s infinite; }}

        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.7; }}
        }}

        .hash-container {{
            margin-top: 1rem;
            padding: 1rem;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 0.5rem;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }}

        .hash-row {{
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 0.5rem;
        }}

        .hash-row:last-child {{ margin-bottom: 0; }}
        .hash-label {{
            color: var(--text-secondary);
            font-size: 0.75rem;
            font-weight: 600;
            min-width: 60px;
            text-transform: uppercase;
        }}

        .hash-value {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            color: var(--accent-green);
            background: rgba(0, 255, 157, 0.1);
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            cursor: pointer;
            transition: all 0.3s ease;
            word-break: break-all;
        }}

        .hash-value:hover {{
            background: rgba(0, 255, 157, 0.2);
            transform: scale(1.02);
        }}

        .footer {{
            text-align: center;
            margin-top: 4rem;
            padding: 2rem;
            border-top: 1px solid var(--border-primary);
        }}

        .footer-text {{ color: var(--text-muted); font-size: 0.9rem; }}
        .footer-brand {{ color: var(--accent-green); font-weight: 600; }}

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
            .hash-value {{ font-size: 0.7rem; }}
        }}

        @media (max-width: 480px) {{
            .stats-grid {{ grid-template-columns: 1fr; }}
            .stat-value {{ font-size: 2rem; }}
            .title {{ font-size: 2rem; }}
        }}
    </style>
</head>
<body>
    <div class="bg-animation"></div>
    <div class="container">
        <header class="header">
            <h1 class="title">Synth</h1>
            <p class="subtitle">Comprehensive Security Asset Analysis Report</p>
            <div class="timestamp">🕒 Scan: {}</div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-value stat-green">{}</span>
                <span class="stat-label">Total Assets</span>
            </div>
            <div class="stat-card">
                <span class="stat-value stat-cyan">{}</span>
                <span class="stat-label">Files Scanned</span>
            </div>
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
                navigator.clipboard.writeText(hash.textContent).then(() => {{
                    const original = hash.style.background;
                    hash.style.background = 'rgba(0, 255, 157, 0.3)';
                    setTimeout(() => {{
                        hash.style.background = original;
                    }}, 200);
                }});
            }});
        }});

        // Animate cards on scroll
        const observer = new IntersectionObserver((entries) => {{
            entries.forEach(entry => {{
                if (entry.isIntersecting) {{
                    entry.target.style.animationDelay = `${{Math.random() * 0.3}}s`;
                    entry.target.classList.add('animate');
                }}
            }});
        }});

        document.querySelectorAll('.asset-card').forEach(card => {{
            observer.observe(card);
        }});
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