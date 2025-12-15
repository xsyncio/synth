use rusqlite::{params, Connection, Result};
use crate::models::ScanReport;
use std::path::Path;

pub struct SqliteExporter;

impl SqliteExporter {
    pub fn export(report: &ScanReport, path: &Path) -> Result<()> {
        let mut conn = Connection::open(path)?;
        
        // Create tables
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scan_info (
                id INTEGER PRIMARY KEY,
                base_directory TEXT,
                total_files INTEGER,
                duration_seconds REAL,
                scan_timestamp TEXT
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY,
                path TEXT,
                name TEXT,
                size INTEGER,
                risk_score INTEGER,
                md5 TEXT,
                sha256 TEXT,
                is_file BOOLEAN
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY,
                asset_id INTEGER,
                indicator_type TEXT,
                description TEXT,
                confidence INTEGER,
                FOREIGN KEY(asset_id) REFERENCES assets(id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY,
                asset_id INTEGER,
                evidence_type TEXT,
                description TEXT,
                confidence INTEGER,
                FOREIGN KEY(asset_id) REFERENCES assets(id)
            )",
            [],
        )?;

        // Insert Scan Info
        conn.execute(
            "INSERT INTO scan_info (base_directory, total_files, duration_seconds, scan_timestamp)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                report.scan_info.base_directory,
                report.scan_info.total_files_scanned,
                report.scan_info.duration_seconds,
                report.scan_info.scan_timestamp,
            ],
        )?;

        // Use transaction for bulk insert
        let tx = conn.transaction()?;

        {
            let mut stmt_asset = tx.prepare(
                "INSERT INTO assets (path, name, size, risk_score, md5, sha256, is_file)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
            )?;
            let mut stmt_threat = tx.prepare(
                "INSERT INTO threats (asset_id, indicator_type, description, confidence)
                 VALUES (?1, ?2, ?3, ?4)"
            )?;
            let mut stmt_evidence = tx.prepare(
                "INSERT INTO evidence (asset_id, evidence_type, description, confidence)
                 VALUES (?1, ?2, ?3, ?4)"
            )?;

            for asset in &report.assets {
                let md5 = asset.md5_hash.as_deref().unwrap_or("");
                let sha256 = asset.sha256_hash.as_deref().unwrap_or("");
                
                let asset_id = stmt_asset.insert(params![
                    asset.path.to_string_lossy(),
                    asset.name,
                    asset.size,
                    asset.risk_score,
                    md5,
                    sha256,
                    asset.is_file
                ])?;

                // Insert Threats
                for threat in &asset.threat_indicators {
                    stmt_threat.execute(params![
                        asset_id,
                        threat.indicator_type,
                        threat.description,
                        threat.confidence
                    ])?;
                }

                // Insert Evidence
                for ev in &asset.forensic_evidence {
                    stmt_evidence.execute(params![
                        asset_id,
                        ev.evidence_type,
                        ev.description,
                        ev.confidence
                    ])?;
                }
            }
        }

        tx.commit()?;
        
        Ok(())
    }
}
