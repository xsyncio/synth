use crate::models::ScanReport;

/// HTML report generator for scan results.
/// Generates beautiful, interactive HTML reports with risk visualization.
#[derive(Debug, Clone, Copy, Default)]
pub struct HtmlReporter;

impl HtmlReporter {
    /// Create a new HTML reporter instance.
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

    fn generate_html(&self, report: &ScanReport) -> String {
        // Calculate risk distribution
        let mut risk_critical = 0;
        let mut risk_high = 0;
        let mut risk_medium = 0;
        let mut risk_low = 0;
        
        for asset in &report.assets {
            match asset.risk_score {
                76..=100 => risk_critical += 1,
                51..=75 => risk_high += 1,
                26..=50 => risk_medium += 1,
                _ => risk_low += 1,
            }
        }

        // Build asset rows for the table
        let mut table_rows = String::new();
        for (idx, asset) in report.assets.iter().enumerate() {
            let risk_class = match asset.risk_score {
                76..=100 => "risk-critical",
                51..=75 => "risk-high",
                26..=50 => "risk-medium",
                _ => "risk-low",
            };
            
            let size_str = asset.size.map(|s| Self::format_size(s)).unwrap_or_else(|| "-".to_string());
            let file_type = asset.mime_type.as_deref().unwrap_or("-");
            let modified = asset.modified.as_deref().unwrap_or("-");
            let threats = asset.threat_indicators.len();
            let name = asset.path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            let path = asset.path.display().to_string();
            
            // Prepare detail data as JSON for the drawer
            let md5 = asset.md5_hash.as_deref().unwrap_or("");
            let sha256 = asset.sha256_hash.as_deref().unwrap_or("");
            let sha3 = asset.sha3_hash.as_deref().unwrap_or("");
            let blake3 = asset.blake3_hash.as_deref().unwrap_or("");
            let entropy = asset.entropy.map(|e| format!("{:.2}", e)).unwrap_or_else(|| "-".to_string());
            let signature = asset.file_signature.as_deref().unwrap_or("-");
            let permissions = &asset.permissions;
            let owner = &asset.owner;
            let is_hidden = if asset.is_hidden { "Yes" } else { "No" };
            let is_encrypted = if asset.encrypted_content { "Yes" } else { "No" };
            let stego = if asset.steganography_detected { "Yes" } else { "No" };
            
            // Build threat JSON array
            let threat_json: Vec<serde_json::Value> = asset.threat_indicators.iter().map(|t| {
                serde_json::json!({
                    "type": t.indicator_type,
                    "value": t.value,
                    "confidence": t.confidence,
                    "description": t.description
                })
            }).collect();
            let threat_data = serde_json::to_string(&threat_json).unwrap_or_else(|_| "[]".to_string());

            // Build crypto JSON array
            let crypto_json: Vec<serde_json::Value> = asset.crypto_artifacts.iter().map(|c| {
                serde_json::json!({
                    "type": c.crypto_type,
                    "value": c.value
                })
            }).collect();
            let crypto_data = serde_json::to_string(&crypto_json).unwrap_or_else(|_| "[]".to_string());

            // Build network JSON array
            let network_json: Vec<serde_json::Value> = asset.network_artifacts.iter().map(|n| {
                serde_json::json!({
                    "type": n.artifact_type,
                    "value": n.value,
                    "source": n.source
                })
            }).collect();
            let network_data = serde_json::to_string(&network_json).unwrap_or_else(|_| "[]".to_string());
            
            // Build secrets JSON array
            let secrets_json: Vec<serde_json::Value> = asset.detected_secrets.iter().map(|s| {
                serde_json::json!({
                    "type": s.secret_type,
                    "provider": s.provider,
                    "value": s.value_redacted,
                    "line": s.line_number,
                    "severity": s.severity
                })
            }).collect();
            let secrets_data = serde_json::to_string(&secrets_json).unwrap_or_else(|_| "[]".to_string());

            // Build Anti-Evasion HTML
            let mut anti_evasion_html = String::new();
            if let Some(ae) = &asset.anti_evasion {
                if let Some(env) = &ae.environment_type {
                    anti_evasion_html.push_str(&format!(
                        r#"<div class="threat-item"><span class="threat-type" style="background:rgba(255,140,66,0.2);color:var(--high)">Environment</span><b>{}</b></div>"#,
                        Self::escape_html(env)
                    ));
                }
                for ev in &ae.evidence {
                    anti_evasion_html.push_str(&format!(
                        r#"<div class="threat-item"><span class="threat-type" style="background:rgba(255,140,66,0.2);color:var(--high)">Evidence</span>{}</div>"#,
                        Self::escape_html(ev)
                    ));
                }
                for t in &ae.anti_debug_techniques {
                     anti_evasion_html.push_str(&format!(
                        r#"<div class="threat-item"><span class="threat-type">Anti-Debug</span>{}</div>"#,
                        Self::escape_html(t)
                    ));
                }
                for t in &ae.anti_vm_techniques {
                     anti_evasion_html.push_str(&format!(
                        r#"<div class="threat-item"><span class="threat-type">Anti-VM</span>{}</div>"#,
                        Self::escape_html(t)
                    ));
                }
            }
            if anti_evasion_html.is_empty() {
                anti_evasion_html = r#"<p class="no-data">No evasion detected</p>"#.to_string();
            }

            // Build YARA matches JSON array
            let yara_json: Vec<serde_json::Value> = asset.yara_matches.iter().map(|y| {
                serde_json::json!({
                    "rule": y.rule_name,
                    "namespace": y.namespace,
                    "tags": y.tags,
                    "confidence": y.confidence
                })
            }).collect();
            let yara_data = serde_json::to_string(&yara_json).unwrap_or_else(|_| "[]".to_string());

            // Build binary info JSON
            let binary_data = if let Some(bin) = &asset.binary_info {
                serde_json::json!({
                    "format": bin.format,
                    "architecture": bin.architecture,
                    "entryPoint": format!("0x{:x}", bin.entry_point),
                    "imphash": bin.imphash,
                    "sectionCount": bin.section_count,
                    "importCount": bin.import_count,
                    "exportCount": bin.export_count,
                    "securityFeatures": bin.security_features,
                    "suspiciousImports": bin.suspicious_imports,
                    "packingIndicators": bin.packing_indicators,
                    "highEntropySections": bin.high_entropy_sections,
                    "fuzzyHash": bin.fuzzy_hash,
                    "disassembly": bin.disassembly
                }).to_string()
            } else {
                "null".to_string()
            };

            let forensic_json = serde_json::to_string(&asset.forensic_analysis)
                .unwrap_or_default()
                .replace("'", "&apos;"); // Basic escape for attribute
                
            table_rows.push_str(&format!(r#"
            <tr class="asset-row {}" data-idx="{}" 
                data-name="{}" data-path="{}" data-size="{}" data-risk="{}"
                data-md5="{}" data-sha256="{}" data-sha3="{}" data-blake3="{}"
                data-entropy="{}" data-entropy-map="{}" data-signature="{}" data-permissions="{}" data-owner="{}"
                data-hidden="{}" data-encrypted="{}" data-stego="{}"
                data-threats="{}" data-network="{}" data-crypto="{}" data-secrets="{}" data-anti-evasion="{}"
                data-yara="{}" data-binary='{}'
                data-forensics='{}'>
                <td class="col-name"><span class="file-icon">{}</span>{}</td>
                <td class="col-size">{}</td>
                <td class="col-type">{}</td>
                <td class="col-risk"><span class="risk-badge {}">{}</span></td>
                <td class="col-threats">{}</td>
                <td class="col-modified">{}</td>
            </tr>"#,
                risk_class,
                idx,
                Self::escape_html(name),
                Self::escape_html(&path),
                asset.size.unwrap_or(0),
                asset.risk_score,
                md5, sha256, sha3, blake3,
                entropy, 
                serde_json::to_string(&asset.entropy_map).unwrap_or_else(|_| "[]".to_string()),
                Self::escape_html(signature), Self::escape_html(permissions), Self::escape_html(owner),
                is_hidden, is_encrypted, stego,
                Self::escape_html(&threat_data),
                Self::escape_html(&network_data),
                Self::escape_html(&crypto_data),
                Self::escape_html(&secrets_data),
                Self::escape_html(&anti_evasion_html),
                Self::escape_html(&yara_data),
                binary_data, // Single-quoted attribute
                forensic_json, // Single-quoted attribute
                if asset.is_file { "📄" } else { "📁" },
                Self::escape_html(name),
                size_str,
                Self::escape_html(file_type),
                risk_class,
                asset.risk_score,
                threats,
                modified
            ));
        }


        let recs_html = self.generate_recommendations(report);
        let (file_labels, file_data) = self.generate_filetype_json(report);
        let (time_labels, time_data) = self.generate_timeline_json(report);

        format!(r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SYNTH // FORENSIC REPORT</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        :root {{
            --bg-dark: #050508;
            --bg-card: #0d0d14;
            --bg-hover: #151520;
            --border: #232333;
            --text-main: #e0e0e0;
            --text-dim: #707080;
            
            /* Cyber Palette */
            --neon-blue: #00f3ff;
            --neon-green: #00ff9d;
            --neon-pink: #ff0055;
            --neon-yellow: #fcee0a;
            --neon-purple: #bc13fe;
            
            --critical: #ff2a6d;
            --high: #ff9100;
            --medium: #fcee0a;
            --low: #05d9e8;
            
            --font-display: 'Share Tech Mono', monospace;
            --font-mono: 'JetBrains Mono', monospace;
        }}
        
        body {{
            background-color: var(--bg-dark);
            color: var(--text-main);
            font-family: var(--font-mono);
            font-size: 14px;
            line-height: 1.5;
            min-height: 100vh;
            overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 50% 50%, rgba(20, 20, 30, 0.5) 0%, transparent 100%),
                linear-gradient(rgba(0,0,0,0.1) 50%, rgba(0,0,0,0.2) 50%),
                linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px),
                linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px);
            background-size: 100% 100%, 100% 2px, 50px 50px, 50px 50px;
        }}

        /* Scanline Overlay */
        body::after {{
            content: " ";
            display: block;
            position: fixed;
            top: 0;
            left: 0;
            bottom: 0;
            right: 0;
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06));
            z-index: 999;
            background-size: 100% 2px, 3px 100%;
            pointer-events: none;
        }}
        
        ::-webkit-scrollbar {{ width: 8px; height: 8px; }}
        ::-webkit-scrollbar-track {{ background: var(--bg-dark); }}
        ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 4px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: var(--neon-blue); }}

        h1, h2, h3, h4, .logo-text, .stat-value, th {{
            font-family: var(--font-display);
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }}

        /* Glitch Animation for Logo */
        @keyframes glitch {{
            0% {{ text-shadow: 2px 2px var(--neon-pink), -2px -2px var(--neon-blue); }}
            20% {{ text-shadow: -2px 2px var(--neon-pink), 2px -2px var(--neon-blue); }}
            40% {{ text-shadow: 2px -2px var(--neon-pink), -2px 2px var(--neon-blue); }}
            60% {{ text-shadow: -2px -2px var(--neon-pink), 2px 2px var(--neon-blue); }}
            80% {{ text-shadow: 2px 2px var(--neon-pink), -2px -2px var(--neon-blue); }}
            100% {{ text-shadow: -2px 2px var(--neon-pink), 2px -2px var(--neon-blue); }}
        }}

        /* Header */
        .header {{
            background: rgba(13, 13, 20, 0.8);
            border-bottom: 2px solid var(--neon-blue);
            box-shadow: 0 0 20px rgba(0, 243, 255, 0.2);
            padding: 1rem 2rem;
            position: sticky;
            top: 0;
            z-index: 100;
            backdrop-filter: blur(12px);
        }}
        
        .header-content {{
            max-width: 1800px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .logo {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        
        .logo-text {{
            font-size: 2rem;
            font-weight: 700;
            color: var(--text-main);
            text-shadow: 0 0 5px var(--neon-blue);
            animation: glitch 5s infinite alternate-reverse;
        }}
        
        .scan-info {{
            display: flex;
            gap: 2rem;
            font-family: var(--font-mono);
            font-size: 0.8rem;
            color: var(--neon-blue);
        }}
        
        .scan-info span {{ color: var(--text-main); font-weight: bold; }}
        
        /* Layout */
        .container {{
            max-width: 1800px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: rgba(13, 13, 20, 0.6);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 1.5rem;
            text-align: center;
            position: relative;
            overflow: hidden;
            transition: all 0.3s;
        }}
        
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; width: 2px; height: 100%;
            background: var(--border);
            transition: background 0.3s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
            border-color: var(--neon-blue);
            box-shadow: 0 0 15px rgba(0, 243, 255, 0.1);
        }}

        .stat-card:hover::before {{ background: var(--neon-blue); }}
        
        .stat-value {{
            font-size: 3rem;
            font-weight: 700;
            display: block;
            margin-bottom: 0.25rem;
            line-height: 1;
            text-shadow: 0 0 10px currentColor;
        }}
        
        .stat-value.critical {{ color: var(--critical); }}
        .stat-value.high {{ color: var(--high); }}
        .stat-value.medium {{ color: var(--medium); }}
        .stat-value.low {{ color: var(--low); }}
        .stat-value.accent {{ color: var(--neon-blue); }}
        
        .stat-label {{
            color: var(--text-dim);
            font-size: 0.8rem;
            letter-spacing: 0.2em;
        }}

        /* Charts & Recommendations */
        .dashboard-grid {{
            display: grid;
            grid-template-columns: 350px 1fr 400px;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}

        .panel {{
            background: rgba(13, 13, 20, 0.6);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 1.5rem;
            position: relative;
        }}

        .panel-title {{
            color: var(--neon-blue);
            font-size: 1rem;
            margin-bottom: 1.2rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.5rem;
            display: flex;
            justify-content: space-between;
        }}

        /* Table */
        .table-container {{
            background: rgba(13, 13, 20, 0.6);
            border: 1px solid var(--border);
            border-radius: 4px;
        }}

        table {{ width: 100%; border-collapse: collapse; }}

        th {{
            background: rgba(20, 20, 30, 0.8);
            color: var(--neon-blue);
            padding: 1.2rem 1rem;
            text-align: left;
            font-size: 0.9rem;
            border-bottom: 2px solid var(--border);
            position: sticky; top: 0;
            cursor: pointer;
        }}
        
        th:hover {{ color: #fff; text-shadow: 0 0 5px var(--neon-blue); }}

        td {{
            padding: 1rem;
            border-bottom: 1px solid var(--border);
            font-size: 0.9rem;
            color: var(--text-dim);
            transition: color 0.2s;
        }}

        tr.asset-row:hover td {{
            color: #fff;
            background: rgba(0, 243, 255, 0.05);
        }}
        
        tr.asset-row.selected td {{
            background: rgba(0, 243, 255, 0.1);
            color: var(--neon-blue);
            border-bottom-color: var(--neon-blue);
        }}

        .risk-badge {{
            padding: 0.2rem 0.6rem;
            border-radius: 2px;
            font-size: 0.75rem;
            font-family: var(--font-display);
            font-weight: bold;
            text-shadow: 0 0 2px currentColor;
            border: 1px solid currentColor;
            background: rgba(0,0,0,0.3);
        }}

        .risk-critical {{ color: var(--critical); border-color: var(--critical); box-shadow: 0 0 5px var(--critical); }}
        .risk-high {{ color: var(--high); border-color: var(--high); }}
        .risk-medium {{ color: var(--medium); border-color: var(--medium); }}
        .risk-low {{ color: var(--low); border-color: var(--low); }}

        /* Detail Drawer */
        .drawer {{
            position: fixed;
            top: 0; right: -800px;
            width: 800px;
            height: 100vh;
            background: #08080c;
            border-left: 2px solid var(--neon-blue);
            box-shadow: -10px 0 50px rgba(0,0,0,0.8);
            z-index: 200;
            transition: right 0.4s cubic-bezier(0.16, 1, 0.3, 1);
            display: flex; flex-direction: column;
        }}

        .drawer.open {{ right: 0; }}
        
        .drawer-header {{
            padding: 1.5rem;
            background: rgba(0, 243, 255, 0.05);
            border-bottom: 1px solid var(--border);
            display: flex; justify-content: space-between; align-items: center;
        }}

        .drawer-title {{
            font-size: 1.4rem;
            color: var(--neon-blue);
            font-family: var(--font-display);
        }}

        .drawer-tabs {{
            display: flex;
            background: #0c0c12;
            padding: 0 1rem;
            border-bottom: 1px solid var(--border);
        }}

        .drawer-tab {{
            padding: 1rem 1.5rem;
            background: none; border: none;
            color: var(--text-dim);
            font-family: var(--font-display);
            font-size: 1rem;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s;
        }}

        .drawer-tab:hover {{ color: #fff; }}
        .drawer-tab.active {{
            color: var(--neon-blue);
            border-bottom-color: var(--neon-blue);
            text-shadow: 0 0 8px var(--neon-blue);
        }}

        .drawer-content {{ flex: 1; overflow-y: auto; padding: 2rem; }}
        .drawer-section {{ display: none; }}
        .drawer-section.active {{ display: block; animation: fadeIn 0.3s; }}

        @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(10px); }} to {{ opacity: 1; transform: translateY(0); }} }}

        /* JSON/Code Styling */
        pre {{
            background: #050508;
            border: 1px solid var(--border);
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            color: #a78bfa;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }}

        .key-val-grid {{
            display: grid;
            grid-template-columns: 140px 1fr;
            gap: 0.8rem;
            margin-bottom: 1rem;
        }}

        .kv-key {{ color: var(--text-dim); font-size: 0.9rem; }}
        .kv-val {{ color: var(--neon-green); font-family: var(--font-mono); }}

        /* Forensic Tables */
        .forensic-table {{ width: 100%; font-size: 0.85rem; margin-top: 1rem; }}
        .forensic-table th {{ padding: 0.5rem; background: rgba(255,255,255,0.05); color: var(--neon-blue); }}
        .forensic-table td {{ padding: 0.5rem; border-bottom: 1px solid #222; color: #ccc; }}
        
        .cmd-high {{ color: var(--critical); }}
        .cmd-med {{ color: var(--high); }}

        /* Charts Section */
        .charts-section {{
            display: grid;
            grid-template-columns: 280px 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}

        .chart-card {{
            background: rgba(13, 13, 20, 0.6);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
        }}

        .chart-card canvas {{
            max-height: 200px !important;
            width: 100% !important;
        }}

        .chart-title {{
            color: var(--neon-blue);
            font-size: 0.9rem;
            margin-bottom: 1rem;
            font-family: var(--font-display);
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }}

        .risk-legend {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.6rem;
            margin-top: 1rem;
            justify-content: center;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            gap: 0.4rem;
            font-size: 0.7rem;
            color: var(--text-dim);
        }}

        .legend-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }}

        /* Filter Bar */
        .filter-bar {{
            display: flex;
            gap: 1rem;
            align-items: center;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
            padding: 1rem;
            background: rgba(13, 13, 20, 0.4);
            border-radius: 4px;
            border: 1px solid var(--border);
        }}

        .search-box input {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 0.6rem 1rem;
            color: var(--text-main);
            font-family: var(--font-mono);
            width: 260px;
            transition: border-color 0.2s;
        }}

        .search-box input:focus {{
            outline: none;
            border-color: var(--neon-blue);
            box-shadow: 0 0 8px rgba(0, 243, 255, 0.2);
        }}

        .filter-group {{
            display: flex;
            gap: 0.4rem;
        }}

        .filter-btn {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 0.5rem 0.8rem;
            color: var(--text-dim);
            cursor: pointer;
            font-family: var(--font-display);
            font-size: 0.75rem;
            transition: all 0.2s;
            text-transform: uppercase;
        }}

        .filter-btn:hover {{
            border-color: var(--text-dim);
            color: var(--text-main);
        }}

        .filter-btn.active {{
            border-color: var(--neon-blue);
            color: var(--neon-blue);
            background: rgba(0, 243, 255, 0.1);
        }}

        .filter-btn.critical.active {{ border-color: var(--critical); color: var(--critical); background: rgba(255,42,109,0.1); }}
        .filter-btn.high.active {{ border-color: var(--high); color: var(--high); background: rgba(255,145,0,0.1); }}
        .filter-btn.medium.active {{ border-color: var(--medium); color: var(--medium); background: rgba(252,238,10,0.1); }}
        .filter-btn.low.active {{ border-color: var(--low); color: var(--low); background: rgba(5,217,232,0.1); }}

        .export-group {{
            margin-left: auto;
        }}

        .export-btn {{
            background: linear-gradient(135deg, rgba(0,243,255,0.2), rgba(188,19,254,0.2));
            border: 1px solid var(--neon-blue);
            border-radius: 4px;
            padding: 0.6rem 1.2rem;
            color: var(--neon-blue);
            cursor: pointer;
            font-family: var(--font-display);
            font-size: 0.8rem;
            transition: all 0.2s;
        }}

        .export-btn:hover {{
            background: linear-gradient(135deg, rgba(0,243,255,0.3), rgba(188,19,254,0.3));
            box-shadow: 0 0 15px rgba(0, 243, 255, 0.3);
        }}

        /* Pagination */
        .pagination {{
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 1.5rem;
            padding: 1.5rem;
            border-top: 1px solid var(--border);
        }}

        .page-btn {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 0.6rem 1.2rem;
            color: var(--text-dim);
            cursor: pointer;
            font-family: var(--font-display);
            transition: all 0.2s;
        }}

        .page-btn:hover {{
            border-color: var(--neon-blue);
            color: var(--neon-blue);
        }}

        .page-btn:disabled {{
            opacity: 0.4;
            cursor: not-allowed;
        }}

        .page-info {{
            color: var(--text-dim);
            font-family: var(--font-mono);
            font-size: 0.85rem;
        }}

        /* Footer */
        .footer {{
            text-align: center;
            padding: 2rem;
            margin-top: 2rem;
            border-top: 1px solid var(--border);
            color: var(--text-dim);
            font-size: 0.8rem;
        }}

        .footer-brand {{
            color: var(--neon-blue);
            font-family: var(--font-display);
        }}

        /* Drawer Close Button */
        .drawer-close {{
            background: none;
            border: 1px solid var(--border);
            border-radius: 4px;
            width: 36px;
            height: 36px;
            color: var(--text-dim);
            font-size: 1.5rem;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
        }}

        .drawer-close:hover {{
            border-color: var(--critical);
            color: var(--critical);
        }}

        /* Drawer Overlay */
        .drawer-overlay {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.6);
            z-index: 150;
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s;
        }}

        .drawer-overlay.open {{
            opacity: 1;
            visibility: visible;
        }}

        /* Info Grid in Drawer */
        .info-grid {{
            display: grid;
            grid-template-columns: 140px 1fr;
            gap: 0.6rem 1.2rem;
            font-size: 0.9rem;
        }}

        .info-grid .label {{
            color: var(--text-dim);
            font-size: 0.85rem;
        }}

        .info-grid .value {{
            color: var(--text-main);
            font-family: var(--font-mono);
            word-break: break-all;
        }}

        /* Threat/Crypto/Network Items */
        .threat-item, .crypto-item, .network-item {{
            background: rgba(255,255,255,0.02);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 0.8rem;
            margin-bottom: 0.6rem;
        }}

        .threat-type, .crypto-type, .net-type {{
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 2px;
            font-size: 0.7rem;
            font-family: var(--font-display);
            background: rgba(255,42,109,0.2);
            color: var(--critical);
            margin-right: 0.5rem;
        }}

        .crypto-type {{
            background: rgba(188,19,254,0.2);
            color: var(--neon-purple);
        }}

        .net-type {{
            background: rgba(0,243,255,0.2);
            color: var(--neon-blue);
        }}

        .threat-conf {{
            font-size: 0.75rem;
            color: var(--text-dim);
        }}

        .no-data {{
            color: var(--text-dim);
            font-style: italic;
            font-size: 0.9rem;
        }}

        /* Responsive */
        @media (max-width: 1200px) {{
            .charts-section {{
                grid-template-columns: 1fr;
            }}
            .chart-card canvas {{
                max-height: 180px !important;
            }}
        }}

        @media (max-width: 768px) {{
            .filter-bar {{
                flex-direction: column;
                align-items: stretch;
            }}
            .search-box input {{
                width: 100%;
            }}
            .export-group {{
                margin-left: 0;
            }}
            .drawer {{
                width: 100%;
                right: -100%;
            }}
        }}
    </style>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <div class="logo">
                <span class="logo-icon">⚡</span>
                <span class="logo-text">SYNTH</span>
            </div>
            <div class="scan-info">
                <div>Target: <span>{}</span></div>
                <div>Duration: <span>{:.2}s</span></div>
                <div>Generated: <span>{}</span></div>
            </div>
        </div>
    </header>

    <div class="container">
        <!-- Stats Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-value accent">{}</span>
                <span class="stat-label">Total Assets</span>
            </div>
            <div class="stat-card">
                <span class="stat-value critical">{}</span>
                <span class="stat-label">Critical</span>
            </div>
            <div class="stat-card">
                <span class="stat-value high">{}</span>
                <span class="stat-label">High Risk</span>
            </div>
            <div class="stat-card">
                <span class="stat-value medium">{}</span>
                <span class="stat-label">Medium</span>
            </div>
            <div class="stat-card">
                <span class="stat-value low">{}</span>
                <span class="stat-label">Low Risk</span>
            </div>
        </div>

        <!-- Recommendations Section -->
        <div class="stat-card" style="text-align: left; margin-bottom: 2rem; border-left: 4px solid var(--accent);">
            <h3 class="chart-title" style="margin-bottom: 0.5rem;">🛡️ Security Recommendations</h3>
            <ul style="padding-left: 1.5rem; color: var(--text);">
                {} 
            </ul>
        </div>

        <!-- Charts Section -->
        <div class="charts-section">
            <div class="chart-card">
                <h3 class="chart-title">Risk Distribution</h3>
                <canvas id="riskChart"></canvas>
                <div class="risk-legend">
                    <div class="legend-item"><span class="legend-dot" style="background: var(--critical)"></span> Critical</div>
                    <div class="legend-item"><span class="legend-dot" style="background: var(--high)"></span> High</div>
                    <div class="legend-item"><span class="legend-dot" style="background: var(--medium)"></span> Medium</div>
                    <div class="legend-item"><span class="legend-dot" style="background: var(--low)"></span> Low</div>
                </div>
            </div>
            
            <div class="chart-card">
                 <h3 class="chart-title">File Types</h3>
                 <canvas id="fileTypeChart"></canvas>
            </div>

            <div class="chart-card" style="grid-column: 1 / -1;">
                <h3 class="chart-title">Activity Timeline (Modified/Events)</h3>
                <canvas id="timelineChart" style="max-height: 200px;"></canvas>
            </div>
        </div>

        <!-- Filter Bar -->
        <div class="filter-bar">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Search by name or path...">
            </div>
            <div class="filter-group">
                <button class="filter-btn active" data-filter="all">All</button>
                <button class="filter-btn critical" data-filter="critical">Critical</button>
                <button class="filter-btn high" data-filter="high">High</button>
                <button class="filter-btn medium" data-filter="medium">Medium</button>
                <button class="filter-btn low" data-filter="low">Low</button>
            </div>
            <div class="export-group">
                <button class="export-btn" onclick="exportCSV()">📥 Export CSV</button>
            </div>
        </div>

        <!-- Table -->
        <div class="table-container">
            <table id="assetsTable">
                <thead>
                    <tr>
                        <th class="sortable" data-sort="name">Name <span class="sort-icon">↕</span></th>
                        <th class="sortable" data-sort="size">Size <span class="sort-icon">↕</span></th>
                        <th class="sortable" data-sort="type">Type <span class="sort-icon">↕</span></th>
                        <th class="sortable" data-sort="risk">Risk <span class="sort-icon">↕</span></th>
                        <th class="sortable" data-sort="threats">Threats <span class="sort-icon">↕</span></th>
                        <th class="sortable" data-sort="modified">Modified <span class="sort-icon">↕</span></th>
                    </tr>
                </thead>
                <tbody id="tableBody">
                    {}
                </tbody>
            </table>
            <div class="pagination">
                <button class="page-btn" id="prevPage">← Previous</button>
                <span class="page-info" id="pageInfo">Page 1 of 1</span>
                <button class="page-btn" id="nextPage">Next →</button>
            </div>
        </div>
    </div>

    <!-- Detail Drawer -->
    <div class="drawer-overlay" id="drawerOverlay"></div>
    <div class="drawer" id="drawer">
        <div class="drawer-header">
            <span class="drawer-title" id="drawerTitle">File Details</span>
            <button class="drawer-close" id="drawerClose">×</button>
            <button class="drawer-tab active" data-tab="info">Info</button>
            <button class="drawer-tab" data-tab="hashes">Hashes</button>
            <button class="drawer-tab" data-tab="threats">Threats</button>
            <button class="drawer-tab" data-tab="forensics">Forensics</button>
            <button class="drawer-tab" data-tab="artifacts">Network/Crypto</button>
            <button class="drawer-tab" data-tab="evasion">Anti-Evasion</button>
        </div>
        <div class="drawer-content">
            <div class="drawer-section active" id="tab-info">
                <div class="info-grid" id="infoContent"></div>
            </div>
            <div class="drawer-section" id="tab-hashes">
                <div id="hashesContent"></div>
            </div>
            <div class="drawer-section" id="tab-threats">
                <h4 style="margin-bottom: 1rem; color: var(--neon-pink);">Threat Indicators</h4>
                <div id="threatContent"></div>
                <h4 style="margin-top: 1.5rem; margin-bottom: 1rem; color: var(--neon-purple);">Detected Secrets</h4>
                <div id="secretContent"></div>
            </div>
            <div class="drawer-section" id="tab-forensics">
                <div id="forensicsContent"></div>
            </div>
            <div class="drawer-section" id="tab-artifacts">
                <h4 style="margin-bottom: 1rem; color: var(--text-dim);">Network Artifacts</h4>
                <div id="networkContent"></div>
                <h4 style="margin-top: 1.5rem; margin-bottom: 1rem; color: var(--text-dim);">Crypto Artifacts</h4>
                <div id="cryptoContent"></div>
            </div>
            <div class="drawer-section" id="tab-evasion">
                <div id="evasionContent"></div>
            </div>
        </div>
    </div>

    <footer class="footer">
        <p>GENERATED BY <span class="footer-brand">SYNTH // OSINT SCANNER</span></p>
    </footer>

    <script>
        // Data
        const riskData = {{ critical: {}, high: {}, medium: {}, low: {} }};
        const fileTypeData = {{ labels: {}, data: {} }};
        const timelineData = {{ labels: {}, data: {} }};

        const ITEMS_PER_PAGE = 50;
        let currentPage = 1;
        let currentFilter = 'all';
        let currentSort = {{ column: 'risk', direction: 'desc' }};
        let searchTerm = '';
        
        // Initialize Risk Chart
        const ctxRisk = document.getElementById('riskChart').getContext('2d');
        new Chart(ctxRisk, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [riskData.critical, riskData.high, riskData.medium, riskData.low],
                    backgroundColor: ['#ff2a6d', '#ff9100', '#fcee0a', '#05d9e8'],
                    borderWidth: 0,
                    hoverOffset: 10
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: true,
                cutout: '70%',
                plugins: {{ legend: {{ display: false }} }}
            }}
        }});

        // Initialize File Type Chart
        const ctxFiles = document.getElementById('fileTypeChart').getContext('2d');
        new Chart(ctxFiles, {{
            type: 'doughnut',
            data: {{
                labels: fileTypeData.labels,
                datasets: [{{
                    data: fileTypeData.data,
                    backgroundColor: ['#00f3ff', '#bc13fe', '#ff0055', '#00ff9d', '#fcee0a', '#ff9100', '#05d9e8', '#2a2a3a'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: true,
                cutout: '65%',
                plugins: {{ 
                    legend: {{ position: 'right', labels: {{ color: '#888899', boxWidth: 10, font: {{ family: 'Share Tech Mono' }} }} }} 
                }}
            }}
        }});

        // Initialize Timeline Chart
        const ctxTimeline = document.getElementById('timelineChart').getContext('2d');
        new Chart(ctxTimeline, {{
            type: 'bar',
            data: {{
                labels: timelineData.labels,
                datasets: [{{
                    label: 'Events',
                    data: timelineData.data,
                    backgroundColor: '#00f3ff',
                    borderRadius: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{ grid: {{ color: '#232333' }}, ticks: {{ color: '#707080', font: {{ family: 'JetBrains Mono' }} }} }},
                    x: {{ grid: {{ display: false }}, ticks: {{ color: '#707080', font: {{ family: 'JetBrains Mono' }} }} }}
                }},
                plugins: {{ legend: {{ display: false }} }}
            }}
        }});
        
        // Get all rows
        const allRows = Array.from(document.querySelectorAll('.asset-row'));
        const tbody = document.querySelector('.table-container tbody');
        
        // Search functionality
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {{
            searchInput.addEventListener('input', (e) => {{
                searchTerm = e.target.value.toLowerCase();
                currentPage = 1;
                renderTable();
            }});
        }}
        
        // Filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {{
            btn.addEventListener('click', () => {{
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                currentFilter = btn.dataset.filter || 'all';
                currentPage = 1;
                renderTable();
            }});
        }});
        
        // Sorting - click on headers
        document.querySelectorAll('th[data-sort]').forEach(th => {{
            th.addEventListener('click', () => {{
                const column = th.dataset.sort;
                if (currentSort.column === column) {{
                    currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
                }} else {{
                    currentSort.column = column;
                    currentSort.direction = 'desc';
                }}
                renderTable();
            }});
        }});
        
        // Get filtered rows
        function getFilteredRows() {{
            return allRows.filter(row => {{
                // Filter by risk level
                const risk = parseInt(row.dataset.risk);
                if (currentFilter !== 'all') {{
                    if (currentFilter === 'critical' && risk <= 75) return false;
                    if (currentFilter === 'high' && (risk <= 50 || risk > 75)) return false;
                    if (currentFilter === 'medium' && (risk <= 25 || risk > 50)) return false;
                    if (currentFilter === 'low' && risk > 25) return false;
                }}
                
                // Filter by search term
                if (searchTerm) {{
                    const name = (row.dataset.name || '').toLowerCase();
                    const path = (row.dataset.path || '').toLowerCase();
                    const type = row.querySelector('.col-type')?.textContent?.toLowerCase() || '';
                    if (!name.includes(searchTerm) && !path.includes(searchTerm) && !type.includes(searchTerm)) {{
                        return false;
                    }}
                }}
                
                return true;
            }});
        }}
        
        // Sort rows
        function sortRows(rows) {{
            return rows.sort((a, b) => {{
                let valA, valB;
                
                switch (currentSort.column) {{
                    case 'name':
                        valA = a.dataset.name || '';
                        valB = b.dataset.name || '';
                        break;
                    case 'size':
                        valA = parseInt(a.dataset.size) || 0;
                        valB = parseInt(b.dataset.size) || 0;
                        break;
                    case 'risk':
                        valA = parseInt(a.dataset.risk) || 0;
                        valB = parseInt(b.dataset.risk) || 0;
                        break;
                    case 'type':
                        valA = a.querySelector('.col-type')?.textContent || '';
                        valB = b.querySelector('.col-type')?.textContent || '';
                        break;
                    case 'modified':
                        valA = a.querySelector('.col-modified')?.textContent || '';
                        valB = b.querySelector('.col-modified')?.textContent || '';
                        break;
                    default:
                        valA = parseInt(a.dataset.risk) || 0;
                        valB = parseInt(b.dataset.risk) || 0;
                }}
                
                if (typeof valA === 'string') {{
                    const cmp = valA.localeCompare(valB);
                    return currentSort.direction === 'asc' ? cmp : -cmp;
                }} else {{
                    return currentSort.direction === 'asc' ? valA - valB : valB - valA;
                }}
            }});
        }}
        
        // Render table with pagination
        function renderTable() {{
            const filteredRows = getFilteredRows();
            const sortedRows = sortRows(filteredRows);
            const totalPages = Math.max(1, Math.ceil(sortedRows.length / ITEMS_PER_PAGE));
            
            // Ensure current page is valid
            if (currentPage > totalPages) currentPage = totalPages;
            if (currentPage < 1) currentPage = 1;
            
            const startIdx = (currentPage - 1) * ITEMS_PER_PAGE;
            const endIdx = startIdx + ITEMS_PER_PAGE;
            const pageRows = sortedRows.slice(startIdx, endIdx);
            
            // Clear tbody and add visible rows
            tbody.innerHTML = '';
            pageRows.forEach(row => tbody.appendChild(row.cloneNode(true)));
            
            // Re-attach click events to new rows
            tbody.querySelectorAll('.asset-row').forEach(row => {{
                row.addEventListener('click', () => openDrawer(row));
            }});
            
            // Update pagination info
            const pageInfo = document.getElementById('pageInfo');
            if (pageInfo) {{
                pageInfo.textContent = `Page ${{currentPage}} of ${{totalPages}} (${{sortedRows.length}} assets)`;
            }}
            
            // Update pagination buttons
            const prevBtn = document.getElementById('prevPage');
            const nextBtn = document.getElementById('nextPage');
            if (prevBtn) prevBtn.disabled = currentPage <= 1;
            if (nextBtn) nextBtn.disabled = currentPage >= totalPages;
        }}
        
        // Pagination controls
        document.getElementById('prevPage')?.addEventListener('click', () => {{
            if (currentPage > 1) {{
                currentPage--;
                renderTable();
            }}
        }});
        
        document.getElementById('nextPage')?.addEventListener('click', () => {{
            const filteredRows = getFilteredRows();
            const totalPages = Math.ceil(filteredRows.length / ITEMS_PER_PAGE);
            if (currentPage < totalPages) {{
                currentPage++;
                renderTable();
            }}
        }});
        
        // Drawer/Overlay
        const drawer = document.querySelector('.drawer');
        const overlay = document.querySelector('.drawer-overlay');
        
        function openDrawer(row) {{
            // Get ALL data from row attributes
            const name = row.dataset.name || '';
            const path = row.dataset.path || '';
            const size = row.dataset.size || '0';
            const risk = parseInt(row.dataset.risk) || 0;
            const modified = row.querySelector('.col-modified')?.textContent || '';
            const type = row.querySelector('.col-type')?.textContent || '';
            const permissions = row.dataset.permissions || '';
            const owner = row.dataset.owner || '';
            const hidden = row.dataset.hidden || 'No';
            const encrypted = row.dataset.encrypted || 'No';
            const stego = row.dataset.stego || 'No';
            
            // Hashes
            const md5 = row.dataset.md5 || '';
            const sha256 = row.dataset.sha256 || '';
            const sha3 = row.dataset.sha3 || '';
            const blake3 = row.dataset.blake3 || '';
            const entropy = row.dataset.entropy || '';
            const signature = row.dataset.signature || '';
            
            // JSON data
            const threats = row.dataset.threats || '';
            const secrets = row.dataset.secrets || '';
            const network = row.dataset.network || '';
            const crypto = row.dataset.crypto || '';
            const yaraData = row.dataset.yara || '';
            const binaryData = row.dataset.binary || '';
            const forensicsData = row.dataset.forensics || '';
            const antiEvasionHtml = row.dataset.antiEvasion || '';
            
            // Update drawer title
            document.querySelector('.drawer-title').textContent = name;
            
            // === TAB 1: INFO ===
            const infoContent = document.getElementById('infoContent');
            infoContent.innerHTML = `
                <span class="label">Full Path:</span>
                <span class="value" style="word-break:break-all;">${{escapeHtml(path)}}</span>
                <span class="label">File Size:</span>
                <span class="value">${{formatBytes(parseInt(size))}}</span>
                <span class="label">File Type:</span>
                <span class="value">${{escapeHtml(type)}}</span>
                <span class="label">Risk Score:</span>
                <span class="value"><span class="risk-badge risk-${{getRiskClass(risk)}}">${{risk}}</span></span>
                <span class="label">Modified:</span>
                <span class="value">${{escapeHtml(modified)}}</span>
                <span class="label">Permissions:</span>
                <span class="value">${{escapeHtml(permissions)}}</span>
                <span class="label">Owner:</span>
                <span class="value">${{escapeHtml(owner)}}</span>
                <span class="label">Signature:</span>
                <span class="value">${{escapeHtml(signature)}}</span>
                <span class="label">Entropy:</span>
                <span class="value">${{entropy || '-'}}</span>
                <span class="label">Hidden:</span>
                <span class="value">${{hidden}}</span>
                <span class="label">Encrypted:</span>
                <span class="value">${{encrypted}}</span>
                <span class="label">Steganography:</span>
                <span class="value">${{stego}}</span>
            `;
            
            // === TAB 2: HASHES ===
            const hashesContent = document.getElementById('hashesContent');
            hashesContent.innerHTML = `
                <div class="info-grid">
                    <span class="label">MD5:</span>
                    <span class="value" style="font-size:0.8rem;word-break:break-all;">${{md5 || 'N/A'}}</span>
                    <span class="label">SHA-256:</span>
                    <span class="value" style="font-size:0.8rem;word-break:break-all;">${{sha256 || 'N/A'}}</span>
                    <span class="label">SHA-3:</span>
                    <span class="value" style="font-size:0.8rem;word-break:break-all;">${{sha3 || 'N/A'}}</span>
                    <span class="label">BLAKE3:</span>
                    <span class="value" style="font-size:0.8rem;word-break:break-all;">${{blake3 || 'N/A'}}</span>
                </div>
            `;
            
            // === TAB 3: THREATS (Threats + Secrets + YARA) ===
            const threatContent = document.getElementById('threatContent');
            let threatHtml = '';
            
            // Threats
            if (threats) {{
                try {{
                    const threatList = JSON.parse(decodeHTMLEntities(threats));
                    if (threatList.length > 0) {{
                        threatHtml += threatList.map(t => `
                            <div class="threat-item">
                                <span class="threat-type">${{escapeHtml(t.type || 'Unknown')}}</span>
                                <strong>${{escapeHtml(t.value || '')}}</strong>
                                <div class="threat-conf">Confidence: ${{t.confidence || 0}}%</div>
                                <div style="color: var(--text-dim); font-size: 0.8rem;">${{escapeHtml(t.description || '')}}</div>
                            </div>
                        `).join('');
                    }}
                }} catch(e) {{}}
            }}
            
            // YARA matches
            if (yaraData) {{
                try {{
                    const yaraList = JSON.parse(decodeHTMLEntities(yaraData));
                    if (yaraList.length > 0) {{
                        threatHtml += '<h4 style="margin-top:1rem;color:var(--neon-pink);">YARA Matches</h4>';
                        threatHtml += yaraList.map(y => `
                            <div class="threat-item" style="border-color: var(--neon-pink);">
                                <span class="threat-type">${{escapeHtml(y.namespace || 'YARA')}}</span>
                                <strong>${{escapeHtml(y.rule || '')}}</strong>
                                <div class="threat-conf">Confidence: ${{y.confidence || 0}}%</div>
                                ${{y.tags && y.tags.length ? `<div style="color: var(--text-dim); font-size: 0.75rem;">Tags: ${{y.tags.join(', ')}}</div>` : ''}}
                            </div>
                        `).join('');
                    }}
                }} catch(e) {{}}
            }}
            
            threatContent.innerHTML = threatHtml || '<p class="no-data">No threat indicators detected.</p>';
            
            // Secrets
            const secretContent = document.getElementById('secretContent');
            if (secrets) {{
                try {{
                    const secretList = JSON.parse(decodeHTMLEntities(secrets));
                    if (secretList.length > 0) {{
                        secretContent.innerHTML = secretList.map(s => `
                            <div class="threat-item" style="border-color: var(--neon-purple);">
                                <span class="crypto-type">${{escapeHtml(s.type || 'Secret')}}</span>
                                <strong>${{escapeHtml(s.provider || '')}}</strong>
                                <div style="font-family: var(--font-mono); color: var(--neon-green); font-size: 0.8rem; word-break:break-all;">${{escapeHtml(s.value || '***')}}</div>
                                <div style="color: var(--text-dim); font-size: 0.75rem;">Line ${{s.line || '?'}} | Severity: ${{s.severity || 'unknown'}}</div>
                            </div>
                        `).join('');
                    }} else {{
                        secretContent.innerHTML = '<p class="no-data">No secrets detected.</p>';
                    }}
                }} catch(e) {{
                    secretContent.innerHTML = '<p class="no-data">No secrets detected.</p>';
                }}
            }} else {{
                secretContent.innerHTML = '<p class="no-data">No secrets detected.</p>';
            }}
            
            // === TAB 4: FORENSICS ===
            const forensicsContent = document.getElementById('forensicsContent');
            let forensicHtml = '';
            
            if (forensicsData && forensicsData !== 'null') {{
                try {{
                    const forensics = JSON.parse(forensicsData.replace(/&apos;/g, "'"));
                    
                    // Event Logs
                    if (forensics.event_logs && forensics.event_logs.length > 0) {{
                        forensicHtml += '<h4 style="color:var(--neon-yellow);">Event Logs</h4>';
                        forensicHtml += forensics.event_logs.slice(0, 10).map(e => `
                            <div class="threat-item" style="border-color: var(--neon-yellow);">
                                <span class="threat-type" style="background:rgba(252,238,10,0.2);color:var(--neon-yellow);">Event ${{e.event_id}}</span>
                                <strong>${{e.channel || ''}}</strong>
                                <div style="color: var(--text-dim); font-size: 0.75rem;">${{e.timestamp}} | ${{e.level}}</div>
                            </div>
                        `).join('');
                    }}
                    
                    // Browser History
                    if (forensics.browser_history && forensics.browser_history.length > 0) {{
                        forensicHtml += '<h4 style="margin-top:1rem;color:var(--neon-blue);">Browser History</h4>';
                        forensicHtml += forensics.browser_history.slice(0, 10).map(b => `
                            <div class="network-item">
                                <span class="net-type">${{b.browser}}</span>
                                <strong style="word-break:break-all;">${{escapeHtml(b.url)}}</strong>
                                <div style="color: var(--text-dim); font-size: 0.75rem;">${{b.title}} | Visits: ${{b.visit_count}}</div>
                            </div>
                        `).join('');
                    }}
                    
                    // Shell History
                    if (forensics.shell_history && forensics.shell_history.length > 0) {{
                        forensicHtml += '<h4 style="margin-top:1rem;color:var(--neon-green);">Shell History</h4>';
                        forensicHtml += forensics.shell_history.slice(0, 15).map(s => `
                            <div class="crypto-item" style="border-color:var(--neon-green);">
                                <span class="crypto-type" style="background:rgba(0,255,157,0.2);color:var(--neon-green);">${{s.shell_type}}</span>
                                <code style="font-size:0.8rem;">${{escapeHtml(s.command)}}</code>
                            </div>
                        `).join('');
                    }}
                    
                    // Evidence
                    if (forensics.evidence && forensics.evidence.length > 0) {{
                        forensicHtml += '<h4 style="margin-top:1rem;color:var(--accent);">Forensic Evidence</h4>';
                        forensicHtml += forensics.evidence.map(e => `
                            <div class="threat-item">
                                <span class="threat-type">${{e.evidence_type}}</span>
                                <div>${{escapeHtml(e.description)}}</div>
                                <div style="color: var(--text-dim); font-size: 0.75rem;">Confidence: ${{e.confidence}}%</div>
                            </div>
                        `).join('');
                    }}
                    
                }} catch(e) {{
                    console.error('Forensics parse error:', e);
                }}
            }}
            
            // Binary Info
            if (binaryData && binaryData !== 'null') {{
                try {{
                    const binary = JSON.parse(binaryData.replace(/&apos;/g, "'"));
                    forensicHtml += '<h4 style="margin-top:1rem;color:var(--neon-purple);">Binary Analysis</h4>';
                    forensicHtml += `
                        <div class="info-grid">
                            <span class="label">Format:</span><span class="value">${{binary.format}}</span>
                            <span class="label">Architecture:</span><span class="value">${{binary.architecture}}</span>
                            <span class="label">Entry Point:</span><span class="value">${{binary.entryPoint}}</span>
                            <span class="label">Sections:</span><span class="value">${{binary.sectionCount}}</span>
                            <span class="label">Imports:</span><span class="value">${{binary.importCount}}</span>
                            <span class="label">Exports:</span><span class="value">${{binary.exportCount}}</span>
                            ${{binary.imphash ? `<span class="label">ImpHash:</span><span class="value" style="font-size:0.75rem;">${{binary.imphash}}</span>` : ''}}
                        </div>
                    `;
                    
                    if (binary.suspiciousImports && binary.suspiciousImports.length > 0) {{
                        forensicHtml += '<h5 style="margin-top:0.8rem;color:var(--critical);">Suspicious Imports</h5>';
                        forensicHtml += binary.suspiciousImports.map(i => `<div class="threat-item"><span class="threat-type">API</span>${{escapeHtml(i)}}</div>`).join('');
                    }}
                    
                    if (binary.securityFeatures && binary.securityFeatures.length > 0) {{
                        forensicHtml += '<h5 style="margin-top:0.8rem;color:var(--neon-green);">Security Features</h5>';
                        forensicHtml += binary.securityFeatures.map(f => `<span style="display:inline-block;padding:0.2rem 0.5rem;margin:0.2rem;background:rgba(0,255,157,0.1);border-radius:3px;font-size:0.75rem;">${{f}}</span>`).join('');
                    }}
                }} catch(e) {{
                    console.error('Binary parse error:', e);
                }}
            }}
            
            forensicsContent.innerHTML = forensicHtml || '<p class="no-data">No forensic data available.</p>';
            
            // === TAB 5: NETWORK/CRYPTO ===
            const networkContent = document.getElementById('networkContent');
            if (network) {{
                try {{
                    const netList = JSON.parse(decodeHTMLEntities(network));
                    if (netList.length > 0) {{
                        networkContent.innerHTML = netList.map(n => `
                            <div class="network-item">
                                <span class="net-type">${{escapeHtml(n.type || 'Network')}}</span>
                                <strong style="word-break:break-all;">${{escapeHtml(n.value || '')}}</strong>
                                <div style="color: var(--text-dim); font-size: 0.75rem;">${{escapeHtml(n.source || '')}}</div>
                            </div>
                        `).join('');
                    }} else {{
                        networkContent.innerHTML = '<p class="no-data">No network artifacts found.</p>';
                    }}
                }} catch(e) {{
                    networkContent.innerHTML = '<p class="no-data">No network artifacts found.</p>';
                }}
            }} else {{
                networkContent.innerHTML = '<p class="no-data">No network artifacts found.</p>';
            }}
            
            const cryptoContent = document.getElementById('cryptoContent');
            if (crypto) {{
                try {{
                    const cryptoList = JSON.parse(decodeHTMLEntities(crypto));
                    if (cryptoList.length > 0) {{
                        cryptoContent.innerHTML = cryptoList.map(c => `
                            <div class="crypto-item">
                                <span class="crypto-type">${{escapeHtml(c.type || 'Crypto')}}</span>
                                <strong style="word-break:break-all;">${{escapeHtml(c.value || '')}}</strong>
                            </div>
                        `).join('');
                    }} else {{
                        cryptoContent.innerHTML = '<p class="no-data">No crypto artifacts found.</p>';
                    }}
                }} catch(e) {{
                    cryptoContent.innerHTML = '<p class="no-data">No crypto artifacts found.</p>';
                }}
            }} else {{
                cryptoContent.innerHTML = '<p class="no-data">No crypto artifacts found.</p>';
            }}
            
            // === TAB 6: ANTI-EVASION ===
            const evasionContent = document.getElementById('evasionContent');
            if (antiEvasionHtml && antiEvasionHtml.trim()) {{
                evasionContent.innerHTML = decodeHTMLEntities(antiEvasionHtml);
            }} else {{
                evasionContent.innerHTML = '<p class="no-data">No anti-evasion techniques detected.</p>';
            }}
            
            // Reset to first tab
            document.querySelectorAll('.drawer-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.drawer-section').forEach(s => s.classList.remove('active'));
            document.querySelector('.drawer-tab').classList.add('active');
            document.querySelector('.drawer-section').classList.add('active');
            
            // Show drawer
            drawer.classList.add('open');
            overlay.classList.add('open');
            
            // Mark row as selected
            document.querySelectorAll('.asset-row').forEach(r => r.classList.remove('selected'));
            row.classList.add('selected');
        }}

        
        function closeDrawer() {{
            drawer.classList.remove('open');
            overlay.classList.remove('open');
            document.querySelectorAll('.asset-row').forEach(r => r.classList.remove('selected'));
        }}
        
        function formatBytes(bytes) {{
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }}
        
        document.getElementById('drawerClose').addEventListener('click', closeDrawer);
        overlay.addEventListener('click', closeDrawer);
        
        // Tabs
        document.querySelectorAll('.drawer-tab').forEach(tab => {{
            tab.addEventListener('click', () => {{
                document.querySelectorAll('.drawer-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.drawer-section').forEach(s => s.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
            }});
        }});
        
        function getRiskClass(score) {{
            if (score > 75) return 'critical';
            if (score > 50) return 'high';
            if (score > 25) return 'medium';
            return 'low';
        }}

        function copyToClipboard(text) {{
            navigator.clipboard.writeText(text);
        }}
        
        function decodeHTMLEntities(text) {{
            const textarea = document.createElement('textarea');
            textarea.innerHTML = text;
            return textarea.value;
        }}

        function escapeHtml(text) {{
             if (!text) return '';
             return text
                 .replace(/&/g, "&amp;")
                 .replace(/</g, "&lt;")
                 .replace(/>/g, "&gt;")
                 .replace(/"/g, "&quot;")
                 .replace(/'/g, "&#039;");
         }}
        
        function exportCSV() {{
            const rows = getFilteredRows();
            let csv = 'Name,Path,Size,Risk,Type,Modified\\n';
            rows.forEach(r => {{
                csv += `"${{r.dataset.name}}","${{r.dataset.path}}","${{r.dataset.size}}","${{r.dataset.risk}}","${{r.querySelector('.col-type').textContent}}","${{r.querySelector('.col-modified').textContent}}"\\n`;
            }});
            const blob = new Blob([csv], {{ type: 'text/csv' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'synth_report.csv';
            a.click();
        }}
        
        // Initial render
        renderTable();
    </script>
</body>
</html>"##,
            // Header info
            Self::escape_html(&report.scan_info.base_directory),
            report.scan_info.duration_seconds,
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            // Stats cards
            report.assets.len(),
            risk_critical,
            risk_high,
            risk_medium,
            risk_low,
            // Recommendations
            recs_html,
            // Table rows
            table_rows,
            // Chart data (Risk)
            risk_critical,
            risk_high,
            risk_medium,
            risk_low,
            // Chart data (File Types)
            file_labels,
            file_data,
            // Chart data (Timeline)
            time_labels,
            time_data
        )
    }

    fn format_size(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_idx = 0;
        while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
            size /= 1024.0;
            unit_idx += 1;
        }
        if unit_idx == 0 {
            format!("{} B", bytes)
        } else {
            format!("{:.1} {}", size, UNITS[unit_idx])
        }
    }

    fn escape_html(s: &str) -> String {
        s.replace('&', "&amp;")
         .replace('<', "&lt;")
         .replace('>', "&gt;")
         .replace('"', "&quot;")
         .replace('\'', "&#x27;")
    }

    fn truncate(s: &str, max_len: usize) -> String {
        if s.chars().count() <= max_len {
            s.to_string()
        } else {
            let truncated: String = s.chars().take(max_len).collect();
            format!("{}...", truncated)
        }
    }

    fn generate_recommendations(&self, report: &ScanReport) -> String {
        let mut recs = Vec::new();
        let mut secrets_found = false;
        let mut evasion_found = false;
        let mut high_risk_assets = 0;

        for asset in &report.assets {
            if !asset.detected_secrets.is_empty() { secrets_found = true; }
            if asset.anti_evasion.is_some() { evasion_found = true; }
            if asset.risk_score > 70 { high_risk_assets += 1; }
        }

        if secrets_found {
            recs.push("<li><strong>Credential Leak:</strong> Detected sensitive API keys or passwords. Rotate exposed credentials immediately and revoke active sessions.</li>".to_string());
        }
        if evasion_found {
            recs.push("<li><strong>Evasion Detected:</strong> Evidence of analysis evasion (VM/Debugger checks) found. Isolate affected binaries and perform dynamic analysis in a hardened sandbox.</li>".to_string());
        }
        if high_risk_assets > 0 {
            recs.push(format!("<li><strong>High Risk Assets:</strong> {} assets identified with critical risk scores. Prioritize triage of these files.</li>", high_risk_assets));
        }
        if !report.assets.iter().any(|a| !a.yara_matches.is_empty()) {
             // Positive reinforcement if clean
             // recs.push("<li><strong>Clean Baseline:</strong> No known malware signatures matched. Continue monitoring.</li>".to_string());
        } else {
             recs.push("<li><strong>Malware Signatures:</strong> YARA rules triggered. Cross-reference with Threat Intelligence to identify Attribution/Campaign.</li>".to_string());
        }

        if recs.is_empty() {
             recs.push("<li>No immediate critical actions required. Maintain routine security posture.</li>".to_string());
        }

        recs.join("\n")
    }

    fn generate_timeline_json(&self, report: &ScanReport) -> (String, String) {
        use std::collections::BTreeMap;
        // Hour -> Count
        let mut timeline: BTreeMap<String, usize> = BTreeMap::new();
        
        for asset in &report.assets {
            if let Some(mod_time) = &asset.modified {
                // Format: YYYY-MM-DD HH:MM:SS
                if mod_time.len() >= 13 {
                    let hour_key = mod_time[0..13].to_string() + ":00";
                    *timeline.entry(hour_key).or_default() += 1;
                }
            }
            if let Some(forensics) = &asset.forensic_analysis {
                 for evt in &forensics.event_logs {
                     if evt.timestamp.len() >= 13 {
                        let hour_key = evt.timestamp[0..13].to_string() + ":00";
                        *timeline.entry(hour_key).or_default() += 1;
                     }
                 }
            }
        }

        // Take top 24 buckets or sorted buckets? BTreeMap sorts by key (Time).
        // Let's return arrays for Chart.js
        let labels: Vec<String> = timeline.keys().map(|k| format!("'{}'", k)).collect();
        let data: Vec<String> = timeline.values().map(|v| v.to_string()).collect();
        
        (format!("[{}]", labels.join(",")), format!("[{}]", data.join(",")))
    }

    fn generate_filetype_json(&self, report: &ScanReport) -> (String, String) {
        use std::collections::HashMap;
        let mut received: HashMap<String, usize> = HashMap::new();
        
        for asset in &report.assets {
            let ext = asset.path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("unknown")
                .to_lowercase();
            *received.entry(ext).or_default() += 1;
        }

        // Sort by count descending
        let mut sorted: Vec<_> = received.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(10); // Top 10

        let labels: Vec<String> = sorted.iter().map(|(k, _)| format!("'{}'", k)).collect();
        let data: Vec<String> = sorted.iter().map(|(_, v)| v.to_string()).collect();

        (format!("[{}]", labels.join(",")), format!("[{}]", data.join(",")))
    }
}
