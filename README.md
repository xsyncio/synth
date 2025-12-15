<div align="center">

```
███████╗██╗   ██╗███╗   ██╗████████╗██╗  ██╗
██╔════╝╚██╗ ██╔╝████╗  ██║╚══██╔══╝██║  ██║
███████╗ ╚████╔╝ ██╔██╗ ██║   ██║   ███████║
╚════██║  ╚██╔╝  ██║╚██╗██║   ██║   ██╔══██║
███████║   ██║   ██║ ╚████║   ██║   ██║  ██║
╚══════╝   ╚═╝   ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝
```

### *"Search what you can't find"*

**High-Performance OSINT Scanner & Intelligence Analysis Framework**

[![CI](https://github.com/xsyncio/synth/actions/workflows/ci.yml/badge.svg)](https://github.com/xsyncio/synth/actions/workflows/ci.yml)
[![Release](https://github.com/xsyncio/synth/actions/workflows/release.yml/badge.svg)](https://github.com/xsyncio/synth/releases)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org)

---

**[Installation](#-installation)** · **[Quick Start](#-quick-start)** · **[Architecture](#-architecture)** · **[Features](#-feature-matrix)** · **[Configuration](#-configuration)** · **[API Reference](#-api-reference)** · **[Security](#-security-model)**

</div>

---

## ◉ PROJECT PHILOSOPHY

Synth exists to solve a specific problem: **extracting actionable intelligence from file systems at scale with zero external dependencies at runtime**.

### Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Zero Runtime Dependencies** | Pure Rust with all analysis engines embedded. No Python, no Java, no external binaries. |
| **Memory-Bounded Execution** | Hard limit enforcement. Will never consume more memory than configured. |
| **Parallel by Default** | CPU-bound analysis distributed across all available cores via Rayon. |
| **Forensic Integrity** | Read-only operations. Never modifies, moves, or deletes analyzed files. |
| **Structured Output** | Every finding is machine-parseable JSON with deterministic schema. |

### What Synth Does

- Recursively traverses filesystems identifying assets of interest
- Computes cryptographic hashes (MD5, SHA-256, SHA-3, BLAKE3) for integrity verification
- Detects secrets, credentials, and API keys using 55+ pattern definitions
- Analyzes binary executables (PE/ELF) for suspicious imports, packing, and security features
- Applies YARA rules for malware signature detection
- Extracts forensic artifacts (event logs, browser history, shell history, registry)
- Identifies steganography indicators via LSB analysis and entropy anomalies
- Maps threat indicators to MITRE ATT&CK framework
- Produces interactive HTML reports with risk visualization

### What Synth Does NOT Do

- **No network scanning** — operates exclusively on local filesystems
- **No active exploitation** — purely passive analysis
- **No cloud API calls** — all analysis is local (no VirusTotal, no Shodan)
- **No file modification** — read-only by design
- **No kernel-level access** — userspace only
- **No real-time monitoring** beyond watch mode — point-in-time analysis

---

## ◉ INSTALLATION

### Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Rust Toolchain | ≥ 1.75.0 | Compilation |
| Cargo | (bundled) | Package management |
| pkg-config | any | Linux: locate system libraries |
| OpenSSL dev headers | ≥ 1.1 | Linux: TLS primitives for optional features |

### From Source (Recommended)

```bash
# Clone repository
git clone https://github.com/yourusername/synth.git
cd synth

# Build optimized release binary
cargo build --release

# Binary location: ./target/release/synth
```

### Build Profile Characteristics

The release build applies aggressive optimizations:

| Setting | Value | Effect |
|---------|-------|--------|
| `lto` | `true` | Link-Time Optimization for smaller binary |
| `codegen-units` | `1` | Single codegen unit for maximum optimization |
| `panic` | `abort` | No unwinding, direct abort on panic |
| `strip` | `true` | Debug symbols removed |

Expected binary size: **8-12 MB** depending on target platform.

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/xsyncio/synth/releases):

| Platform | Architecture | Filename |
|----------|--------------|----------|
| Linux | x86_64 | `synth-linux-x86_64.tar.gz` |
| Linux | ARM64 | `synth-linux-aarch64.tar.gz` |
| Windows | x86_64 | `synth-windows-x86_64.zip` |
| Windows | ARM64 | `synth-windows-aarch64.zip` |

```bash
# Linux installation
tar -xzf synth-linux-x86_64.tar.gz
chmod +x synth
sudo mv synth /usr/local/bin/

# Verify installation
synth --version
```

---

## ◉ QUICK START

### Minimal Invocation

```bash
# Scan current directory with standard analysis
synth

# Scan specific directory
synth -d /path/to/target

# Scan with comprehensive analysis and output
synth -d /path/to/target -m comprehensive -o report
```

### Output Artifacts

When `-o <name>` is specified, three files are generated:

| File | Format | Contents |
|------|--------|----------|
| `<name>.json` | JSON | Complete structured scan results |
| `<name>.html` | HTML | Interactive visual report with charts |
| `<name>.db` | SQLite | Evidence database for forensic tools |

---

## ◉ ARCHITECTURE

### System Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                          SYNTH CORE                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │   CLI       │───▶│  Scanner    │───▶│  Analysis Pipeline  │  │
│  │   Parser    │    │  Engine     │    │                     │  │
│  └─────────────┘    └─────────────┘    │  ┌───────────────┐  │  │
│                            │           │  │ Hash Engine   │  │  │
│                            ▼           │  ├───────────────┤  │  │
│                     ┌─────────────┐    │  │ Secret Scanner│  │  │
│                     │  File       │    │  ├───────────────┤  │  │
│                     │  Traverser  │    │  │ Binary Analyzer│ │  │
│                     │  (walkdir)  │    │  ├───────────────┤  │  │
│                     └─────────────┘    │  │ YARA Engine   │  │  │
│                            │           │  ├───────────────┤  │  │
│                            ▼           │  │ Stego Detector│  │  │
│                     ┌─────────────┐    │  ├───────────────┤  │  │
│                     │  Memory     │    │  │ Forensic Analyzer│ │
│                     │  Manager    │    │  ├───────────────┤  │  │
│                     │  (1GB cap)  │    │  │ Threat Intel  │  │  │
│                     └─────────────┘    │  └───────────────┘  │  │
│                                        └─────────────────────┘  │
│                                                  │               │
│                            ┌─────────────────────┘               │
│                            ▼                                     │
│                     ┌─────────────┐    ┌─────────────────────┐  │
│                     │  Risk       │───▶│  Reporter           │  │
│                     │  Calculator │    │  (JSON/HTML/SQLite) │  │
│                     └─────────────┘    └─────────────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Module Dependency Graph

```
lib.rs (crate root)
├── scanner/           Core scanning engine
│   ├── mod.rs         AdvancedOsintScanner struct
│   ├── entry.rs       File entry processing
│   ├── analysis.rs    Analysis pipeline coordination
│   └── risk.rs        Risk score calculation
├── analyzer/          Content analysis
│   └── mod.rs         Pattern matching, entropy, artifact extraction
├── secrets/           Credential detection
│   ├── mod.rs         SecretScanner struct
│   ├── patterns.rs    55+ secret patterns (AWS, GitHub, Stripe, etc.)
│   └── detection.rs   Validation and context extraction
├── binary/            Executable analysis
│   ├── mod.rs         BinaryAnalyzer struct
│   ├── pe.rs          Windows PE parsing
│   ├── elf.rs         Linux ELF parsing
│   └── strings.rs     String extraction and categorization
├── yara/              Malware signature detection
│   └── mod.rs         YARA rule compilation and matching
├── threat_intel/      Threat intelligence
│   ├── mod.rs         ThreatIntelEngine struct
│   ├── mitre.rs       MITRE ATT&CK technique definitions
│   ├── ioc.rs         Indicators of Compromise database
│   └── risk.rs        Risk scoring algorithms
├── forensics/         Digital forensics
│   └── mod.rs         Event log, browser, archive analysis
├── stego/             Steganography detection
│   └── mod.rs         LSB analysis, chi-square tests
├── metadata/          Metadata extraction
│   └── mod.rs         EXIF, PDF, Office metadata
├── network/           Network artifact analysis
│   └── mod.rs         PCAP parsing, certificate analysis
├── reporter/          Output generation
│   └── mod.rs         HTML, JSON, SQLite export
├── models/            Data structures
│   └── mod.rs         AssetMetadata, ScanReport, etc.
├── windows_forensics.rs   Windows-specific artifacts
├── linux_forensics.rs     Linux-specific artifacts
├── anti_evasion.rs        Anti-analysis technique detection
├── cloud.rs               Cloud configuration analysis
└── watcher.rs             File system monitoring
```

### Data Flow

1. **CLI Parsing** → Args struct validated by Clap
2. **Scanner Initialization** → Thread pool sized, memory limits set
3. **Directory Traversal** → walkdir with depth/filter constraints
4. **Entry Processing** → Each file enters analysis pipeline
5. **Analysis Pipeline** → Parallel execution of enabled analyzers
6. **Risk Calculation** → Weighted scoring based on findings
7. **Report Generation** → Structured output to selected formats

### Memory Model

| Component | Allocation Strategy |
|-----------|---------------------|
| File buffers | Memory-mapped for files > 1MB |
| Hash computation | Streaming, constant memory |
| Regex patterns | Pre-compiled at startup |
| YARA rules | Compiled once, reused |
| Results accumulator | Bounded by `--max-memory` |

**Memory limit enforcement**: When the configured limit is approached, the scanner will skip remaining files and complete with partial results rather than OOM.

---

## ◉ FEATURE MATRIX

### Scan Modes

| Mode | Hash | Secrets | Binary | YARA | Forensics | Stego | Threat Intel |
|------|:----:|:-------:|:------:|:----:|:---------:|:-----:|:------------:|
| `fast` | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `standard` | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `deep` | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ |
| `comprehensive` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

### Hash Algorithms

| Algorithm | Output Size | Use Case |
|-----------|-------------|----------|
| MD5 | 128-bit | Legacy compatibility, VirusTotal lookups |
| SHA-256 | 256-bit | Primary integrity verification |
| SHA-3 | 256-bit | Post-quantum resistance |
| BLAKE3 | 256-bit | Performance-critical scenarios |

### Secret Detection Categories

| Category | Patterns | Example |
|----------|----------|---------|
| AWS | 4 | Access Key, Secret Key, Session Token |
| Google Cloud | 3 | API Key, OAuth Client ID, Service Account |
| Azure | 3 | Subscription Key, Storage Key, SAS Token |
| GitHub | 2 | Personal Access Token, OAuth Token |
| Slack | 2 | Bot Token, Webhook URL |
| Stripe | 2 | Secret Key, Publishable Key |
| Generic | 40+ | Private Keys, JWTs, Database URLs |

### Binary Analysis Capabilities

| Feature | PE (Windows) | ELF (Linux) |
|---------|:------------:|:-----------:|
| Architecture detection | ✓ | ✓ |
| Entry point extraction | ✓ | ✓ |
| Import/Export enumeration | ✓ | ✓ |
| Section analysis | ✓ | ✓ |
| High-entropy detection | ✓ | ✓ |
| Import hash (ImpHash) | ✓ | ✗ |
| Security feature detection | ✓ | ✓ |
| Suspicious API identification | ✓ | ✓ |

### YARA Rules (Built-in)

| Rule Name | Description |
|-----------|-------------|
| `SuspiciousBase64EncodedExe` | Base64-encoded PE headers |
| `SuspiciousPowershellDownload` | PowerShell download cradles |
| `SuspiciousShellcode` | x86/x64 shellcode patterns |
| `PHPWebshell` | PHP backdoor indicators |
| `JSPWebshell` | Java Server Page backdoors |
| `CryptoMiner` | Cryptocurrency mining software |
| `RansomwareIndicators` | Ransomware behavioral patterns |
| `CredentialHarvester` | Credential theft tools |
| `PersistenceMechanism` | Startup persistence techniques |
| `DataExfiltration` | Data exfiltration patterns |

### Forensic Artifacts

| Platform | Artifact Type | Source |
|----------|--------------|--------|
| Windows | Event Logs | `.evtx` files |
| Windows | Registry | Hive files |
| Windows | Prefetch | `C:\Windows\Prefetch` |
| Windows | LNK Files | Shortcut metadata |
| Windows | Recycle Bin | `$Recycle.Bin` |
| Linux | Shell History | `.bash_history`, `.zsh_history` |
| Linux | SSH Keys | `.ssh/authorized_keys` |
| Linux | Cron Jobs | `/etc/crontab`, cron.d |
| Linux | System Logs | `/var/log/auth.log` |
| Cross-platform | Browser History | Chrome, Firefox, Safari |

---

## ◉ CONFIGURATION

### Command-Line Interface

```
synth [OPTIONS]

OPTIONS:
    -d, --directory <PATH>       Target directory [default: .]
    -a, --asset-name <PATTERN>   Filename pattern filter
    -r, --regex-pattern <REGEX>  Advanced regex matching
    -m, --mode <MODE>            Scan mode [fast|standard|deep|comprehensive]
    -o, --output <NAME>          Output base name for reports
    -t, --threads <N>            Thread count [0 = auto-detect]
    -v, --verbose                Debug-level logging
    -q, --quiet                  Suppress progress output
        --max-depth <N>          Directory traversal limit [default: 10]
        --max-file-size <MB>     Skip files larger than [default: 100]
        --min-size <BYTES>       Skip files smaller than [default: 0]
        --max-size <BYTES>       Skip files larger than (bytes)
        --max-memory <MB>        Memory usage limit [default: 1024]
        --follow-symlinks        Follow symbolic links
        --case-sensitive         Case-sensitive pattern matching
        --file-types <EXT,...>   Include only these extensions
        --exclude <PATTERN,...>  Exclude matching paths
        --watch                  Enable continuous monitoring mode
    -h, --help                   Display help information
    -V, --version                Display version
```

### Configuration Precedence

All configuration is via CLI arguments. No configuration files. No environment variables. This is intentional:

1. **Reproducibility** — Command line is self-documenting
2. **Auditability** — Exact invocation is visible in shell history
3. **Simplicity** — No hidden configuration sources

### Default Behaviors

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| `mode` | `standard` | Balance of coverage and speed |
| `threads` | `0` (auto) | Uses all available CPU cores |
| `max_depth` | `10` | Prevents runaway in deep hierarchies |
| `max_file_size` | `100 MB` | Avoids memory exhaustion on large files |
| `max_memory` | `1024 MB` | Hard cap prevents OOM |
| `follow_symlinks` | `false` | Prevents infinite loops, security |

---

## ◉ API REFERENCE

### Primary Types

#### `ScanReport`

Root output structure containing all scan results.

```rust
pub struct ScanReport {
    pub scan_info: ScanInfo,      // Metadata about the scan
    pub assets: Vec<AssetMetadata> // All analyzed assets
}
```

#### `ScanInfo`

Scan execution metadata.

```rust
pub struct ScanInfo {
    pub start_time: String,
    pub end_time: String,
    pub duration_seconds: f64,
    pub base_directory: String,
    pub search_pattern: String,
    pub mode: String,
    pub total_files_scanned: u64,
    pub total_bytes_analyzed: u64,
    pub scan_timestamp: String
}
```

#### `AssetMetadata`

Complete analysis results for a single file.

```rust
pub struct AssetMetadata {
    // Identity
    pub path: PathBuf,
    pub name: String,
    pub size: Option<u64>,
    
    // Hashes
    pub md5_hash: Option<String>,
    pub sha256_hash: Option<String>,
    pub sha3_hash: Option<String>,
    pub blake3_hash: Option<String>,
    
    // Analysis
    pub entropy: Option<f64>,
    pub mime_type: Option<String>,
    pub file_signature: Option<String>,
    
    // Findings
    pub threat_indicators: Vec<ThreatIndicator>,
    pub crypto_artifacts: Vec<CryptoArtifact>,
    pub network_artifacts: Vec<NetworkArtifact>,
    pub detected_secrets: Vec<SecretFinding>,
    pub yara_matches: Vec<YaraMatchResult>,
    
    // Binary (if applicable)
    pub binary_info: Option<BinaryInfo>,
    
    // Forensics
    pub forensic_analysis: Option<ForensicAnalysis>,
    
    // Anti-evasion
    pub anti_evasion: Option<AntiEvasionResult>,
    
    // Scoring
    pub risk_score: u8  // 0-100
}
```

### Risk Score Calculation

Risk scores are computed as weighted sums with the following factors:

| Factor | Weight | Trigger |
|--------|--------|---------|
| Critical YARA match | +40 | Malware signature detected |
| High-severity secret | +35 | AWS keys, private keys |
| Suspicious binary imports | +25 | Process injection APIs |
| Anti-analysis techniques | +20 | Anti-debug, Anti-VM |
| High entropy sections | +15 | Packed/encrypted code |
| Network indicators | +10 | C2-like patterns |
| Medium-severity secret | +10 | Generic API keys |

Score is capped at 100. Risk levels:

| Score | Level | Interpretation |
|-------|-------|----------------|
| 76-100 | Critical | Immediate investigation required |
| 51-75 | High | Review within 24 hours |
| 26-50 | Medium | Review within 1 week |
| 0-25 | Low | Informational only |

---

## ◉ SECURITY MODEL

### Threat Model

Synth operates under the following assumptions:

1. **Attacker goal**: Prevent detection of malicious files
2. **Attacker capabilities**: Can craft files with evasion techniques
3. **Defender goal**: Identify suspicious files for human review

### Security Properties

| Property | Guarantee |
|----------|-----------|
| **Read-only operation** | Synth will never modify analyzed files |
| **No code execution** | Files are parsed, never executed |
| **Memory safety** | Rust's ownership model prevents buffer overflows |
| **No network egress** | Zero outbound connections |

### Limitations

| Limitation | Explanation |
|------------|-------------|
| **Static analysis only** | Cannot detect runtime-only behaviors |
| **Pattern-based detection** | Novel/zero-day malware may evade |
| **No unpacking** | Packed binaries analyzed as-is |
| **YARA rule quality** | Detection quality depends on rules |

### Safe Handling Recommendations

```bash
# Run in isolated environment for untrusted targets
docker run --rm -v /target:/scan:ro synth -d /scan -o results

# Restrict privileges
sudo -u nobody synth -d /target

# Network isolation
unshare --net synth -d /target
```

---

## ◉ PERFORMANCE

### Benchmarks

Tested on: AMD Ryzen 9 5900X, 32GB RAM, NVMe SSD

| Workload | Files | Size | Mode | Duration | Throughput |
|----------|-------|------|------|----------|------------|
| Source code | 10,000 | 50 MB | fast | 0.5s | 20K files/s |
| Source code | 10,000 | 50 MB | comprehensive | 8s | 1.2K files/s |
| Mixed media | 5,000 | 10 GB | standard | 15s | 666 MB/s |
| Binary dump | 1,000 | 5 GB | deep | 45s | 111 MB/s |

### Optimization Strategies

| Technique | Implementation |
|-----------|----------------|
| Parallel processing | Rayon work-stealing thread pool |
| Memory mapping | Large files mapped instead of buffered |
| Lazy evaluation | Analysis stages skip irrelevant files |
| Pre-compiled patterns | Regex and YARA compiled once at start |
| Streaming hashes | Constant-memory hash computation |

### Resource Constraints

| Constraint | Control | Behavior on Breach |
|------------|---------|-------------------|
| Memory | `--max-memory` | Skip remaining files, complete with results |
| File size | `--max-file-size` | Skip file, log warning |
| Depth | `--max-depth` | Stop traversal at limit |

---

## ◉ ERROR HANDLING

### Error Categories

| Category | Example | Recovery |
|----------|---------|----------|
| `IoError` | Permission denied | Skip file, continue |
| `ParseError` | Corrupt PE header | Skip analysis, report as unparseable |
| `MemoryError` | Allocation failure | Graceful degradation |
| `ConfigError` | Invalid regex | Abort with message |

### Failure Modes

| Scenario | Behavior |
|----------|----------|
| Directory not found | Exit with error code 1 |
| No read permission | Skip file, log warning |
| Corrupt file | Skip analysis, include in report with error |
| Memory limit hit | Generate partial report |
| YARA compilation failure | Log error, continue without YARA |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Configuration or input error |
| 2 | Runtime error |

---

## ◉ LOGGING & OBSERVABILITY

### Log Levels

| Flag | Level | Output |
|------|-------|--------|
| (default) | INFO | Progress, summaries, warnings |
| `-v` | DEBUG | All operations, timing data |
| `-q` | ERROR | Critical errors only |

### Log Format

```
[2024-01-15T10:30:45.123Z INFO  synth::scanner] Scan completed in 5.23s
[2024-01-15T10:30:45.124Z WARN  synth::scanner::entry] Memory limit exceeded, skipping file: /path/to/large.bin
```

### Structured Output

All findings are available in JSON format with deterministic schema:

```bash
synth -d /target -o results
cat results.json | jq '.assets[] | select(.risk_score > 75)'
```

---

## ◉ EXTENSION POINTS

### Custom YARA Rules

Synth includes built-in YARA rules but supports extension via the embedded rule engine:

```rust
// In yara/mod.rs, add rules to BUILTIN_RULES constant
pub const BUILTIN_RULES: &str = r#"
    rule CustomMalware {
        strings:
            $sig = { 4D 5A 90 00 }
        condition:
            $sig at 0
    }
"#;
```

### Custom Secret Patterns

Add patterns in `secrets/patterns.rs`:

```rust
SecretPattern {
    name: "Custom API Key",
    provider: "MyService",
    pattern: r"myservice_[a-zA-Z0-9]{32}",
    severity: SecretSeverity::High,
    confidence: 95,
}
```

---

## ◉ TESTING

### Test Execution

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific module tests
cargo test scanner::tests
```

### Test Categories

| Category | Location | Purpose |
|----------|----------|---------|
| Unit | `src/*/mod.rs` | Individual function correctness |
| Integration | `tests/` | End-to-end scan workflows |

### Coverage Expectations

| Module | Minimum Coverage | Critical Paths |
|--------|-----------------|----------------|
| Scanner | 80% | Entry processing, risk calculation |
| Secrets | 95% | Pattern matching, false positive prevention |
| Binary | 70% | PE/ELF parsing |
| YARA | 90% | Rule compilation, matching |

---

## ◉ VERSIONING

### Semantic Versioning

Synth follows [SemVer](https://semver.org/):

- **MAJOR**: Breaking changes to CLI or JSON output schema
- **MINOR**: New features, new analyzers, new patterns
- **PATCH**: Bug fixes, performance improvements

### Compatibility Guarantees

| Component | Stability |
|-----------|-----------|
| CLI flags | Stable across minor versions |
| JSON output schema | Additive changes only in minor versions |
| SQLite schema | Versioned, migrations provided |
| HTML report | Visual changes without notice |

### Upgrade Path

```bash
# Check current version
synth --version

# Pull latest
git pull origin main
cargo build --release

# Verify
synth --version
```

---

## ◉ CONTRIBUTING

### Code Standards

| Standard | Enforcement |
|----------|-------------|
| Formatting | `cargo fmt --all -- --check` |
| Lints | `cargo clippy -- -D warnings` |
| Tests | `cargo test` must pass |
| Documentation | Public items must have doc comments |

### Pull Request Checklist

- [ ] Code compiles without warnings
- [ ] All tests pass
- [ ] New features have tests
- [ ] Public API documented
- [ ] No sensitive data in commits

### Commit Message Format

```
<type>: <subject>

<body>

Types: feat, fix, refactor, docs, test, chore
```

---

## ◉ KNOWN LIMITATIONS

| Limitation | Reason | Workaround |
|------------|--------|------------|
| No macOS ARM binary | Cross-compilation complexity | Build from source |
| Limited archive depth | Memory safety | Extract then scan |
| No live memory analysis | Userspace only | Use dedicated tools |
| Fixed YARA rules | Embedded at compile time | Rebuild with custom rules |

---

## ◉ ROADMAP

### Planned Features

- [ ] Plugin system for custom analyzers
- [ ] Remote scanning via SSH
- [ ] Differential scan mode
- [ ] STIX/TAXII output format
- [ ] macOS-specific forensics

### Not Planned

- GUI application
- Cloud SaaS version  
- Real-time protection
- Quarantine functionality

---

## ◉ LICENSE

**GNU General Public License v3.0** — Free software license that requires derivative works to be open source.

Copyright (C) 2025 Xsyncio

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See [LICENSE](LICENSE) for full text.

---

<div align="center">

**Built with paranoia. Deployed with confidence.**

*Synth v0.2.0 — Created by [Xsyncio](https://github.com/xsyncio)*

</div>

