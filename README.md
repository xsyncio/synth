# synth - Advanced Asset Discovery Tool

![synth Banner](https://raw.githubusercontent.com/yourusername/synth/main/assets/synth_banner.png)

> **Tagline:** “Search what you can’t find.”

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Architecture & Modules](#architecture--modules)
4. [Installation](#installation)
5. [Usage](#usage)

   * [Basic Scan](#basic-scan)
   * [Advanced Options](#advanced-options)
   * [Examples](#examples)
6. [CLI Reference](#cli-reference)
7. [Reporting](#reporting)
8. [Performance & Memory Efficiency](#performance--memory-efficiency)
9. [Extending & Customization](#extending--customization)
10. [Testing](#testing)
11. [Contributing](#contributing)
12. [License](#license)
13. [Acknowledgements](#acknowledgements)

---

## Overview

**synth** is a high-performance, memory-efficient, comprehensive OSINT (Open-Source Intelligence) scanner and analysis tool designed for security researchers, digital forensics specialists, and threat hunters. It traverses file systems, applies heuristic and signature-based techniques, and produces detailed JSON and HTML reports of discovered assets, vulnerabilities, and potential threats.

Key goals:

* **Performance**: Parallel processing with `rayon` and async I/O with `tokio`.
* **Memory Efficiency**: Streaming analysis, memory-mapped file reads, chunk-based processing.
* **Comprehensiveness**: Multiple scanning modes from fast to deep, code analysis and steganography detection.
* **Usability**: Intuitive CLI via `clap`, progress UI with `indicatif` and `console`, detailed HTML report.

---

## Key Features

* 🔍 **Asset Discovery**: Recursively walk directories, filter by patterns, file types, sizes.
* 🧮 **Content Analysis**: Regex-based detection of network artifacts (IPs, domains, URLs), crypto artifacts (Bitcoin, Ethereum addresses, PEM keys), threat patterns (code injection, SQL queries).
* 🔐 **Forensics**: Entropy calculation, high-entropy (encrypted/compressed) detection, LSB steganography checks.
* 📊 **Risk Scoring**: Aggregates findings (threats, artifacts, hidden files, steganography) into a normalized \[0–100] risk score.
* 💾 **Hashing**: MD5, SHA256, SHA3-256, Blake3 computed in a single pass via memory mapping.
* 📝 **Code Analysis**: Cyclomatic complexity, obfuscation score, language-agnostic support for common file types.
* 📱 **Reporting**:

  * JSON output for automation and integration.
  * Beautiful, responsive HTML report with dynamic styling and copy-to-clipboard features.
* 🖥️ **Interactive UI**: Real-time progress with multi-bar, files/sec, MB/sec, ETA, threat alerts in terminal.

---

## Architecture & Modules

```
src/
├── analyzer/         # ContentAnalyzer - regex patterns, entropy, steganography
├── cli/              # Args, SearchMode - CLI parsing via clap
├── models/           # Data models: ScanReport, AssetMetadata, artifacts, indicators
├── scanner/          # AdvancedOsintScanner - orchestration, parallel processing
├── ui/               # HackerTerminalUI - terminal progress & alerts
├── reporter/         # HtmlReporter - HTML template generation
├── utils/            # Helpers: is_likely_text, StreamingTextReader, HashComputer, MemoryMonitor
└── lib.rs            # Re-exports, crate root
```

* **Dependencies**:

  * `tokio` & `rayon` for concurrency.
  * `clap` for CLI.
  * `regex`, `mime_guess` for content detection.
  * `indicatif`, `console` for UI.
  * `serde`, `serde_json`, `chrono` for serialization & timestamps.
  * `memmap2`, `bytes` for zero-copy and streaming.
  * Hash crates: `md-5`, `sha2`, `sha3`, `blake3`.

---

## Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/synth.git
cd synth

# Build in release mode for maximum performance
cargo build --release

# Optionally run tests
cargo test
```

---

## Usage

Invoke the binary `synth`.

### Basic Scan

```bash
./target/release/synth --directory /path/to/target
```

Scans with default `standard` mode, depth=10, max file size=100MB, all file types.

### Advanced Options

* **Asset Name**: `-a, --asset-name <pattern>`
* **Regex Filtering**: `-r, --regex-pattern <regex>`
* **Mode Selection**: `-m, --mode [fast|standard|deep|comprehensive]`
* **Depth**: `--max-depth <n>`
* **Threads**: `-t, --threads <n>` (0 = auto-detect)
* **Size Filters**: `--min-size <bytes>`, `--max-size <bytes>`
* **File Types**: `--file-types jpg,png,txt`
* **Exclusions**: `--exclude node_modules,*.tmp`
* **Memory Limit**: `--max-memory <MB>`
* **Quiet/Verbose**: `-q, --quiet`, `-v, --verbose`
* **Output**: `-o, --output report.json` (also generates `report.html`)

### Examples

```bash
# Fast depth-limited scan for PDF files under 50MB
synth -d ./docs --file-types pdf --mode fast --max-depth 5 --max-file-size 50

# Deep scan of home directory, with credentials search and custom regex
synth -d ~ --mode deep -r "(?i)password[:=]\s*['\"][^'\"]{6,}" --min-size 1024

# Comprehensive audit, output to JSON and HTML
synth -d /var/www -m comprehensive -o web_audit_report.json
```

---

## CLI Reference

For full options, run:

```bash
synth --help
```

This displays detailed descriptions for all flags.

---

## Reporting

* **JSON**: Machine-readable, includes `ScanInfo` and full `AssetMetadata`.
* **HTML**: Responsive, visually engaging report:

  * Collapsible asset cards
  * Copy-to-clipboard hash values
  * Animated background & cards
  * Risk badges (LOW/MEDIUM/HIGH/CRITICAL)
  * Stats panel: total assets, files scanned, data analyzed, scan duration

Generated alongside JSON when `--output` is provided.

---

## Performance & Memory Efficiency

* **StreamingTextReader** reads large files in 64KB chunks.
* **Memory-mapped I/O** for hashing & content scanning.
* **MemoryMonitor** enforces MB limits, gracefully skips large files.
* **Parallel Processing** with `rayon` thread pool.
* **Asynchronous UI** with `tokio` tasks for non-blocking progress updates.

Benchmark with `criterion` in `benches/scan_bench.rs`:

```bash
cargo bench
```

---

## Extending & Customization

* **Add new artifact detectors**: Extend `ContentAnalyzer::compile_*_patterns` and handle in `analyze_chunk`.
* **Custom report templates**: Modify `reporter/HtmlReporter::generate_html`.
* **Integrate additional scoring rules**: Update `calculate_risk_score` in scanner module.

---

## Testing

Unit & integration tests cover:

* Regex detection (`analyzer` module).
* Utility functions (`utils`).
* Scanner end-to-end (`scanner` tests).

Run tests:

```bash
cargo test -- --nocapture
```

---

## Contributing

1. Fork the repo.
2. Create a feature branch: `git checkout -b feature/my-feature`.
3. Write code & tests.
4. Run `cargo fmt` & `cargo clippy`.
5. Submit a Pull Request.

Please follow the existing coding style and update this README with any new features.

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## Acknowledgements

* Rust ecosystem: `tokio`, `rayon`, `clap`, `indicatif`.
* OSINT & forensics tools inspiration.
* Contributors and the open-source community.
