# GitHub Copilot Instructions — James

## Project Description

James is a Rust agentic security research platform built for **authorized security research only**. It provides a multi-engine security assessment platform featuring:

- **Red Team** — Adversary emulation, APT simulation, recon, exploitation (authorized only)
- **Blue Team** — Detection rule generation, threat hunting, malware analysis, SIEM/SOAR
- **Exploit Engine** — Fuzzing, crash analysis, payload generation, vulnerability research
- **Pentest** — Scoping, CVSS scoring, web/network/cloud/mobile security testing
- **Blockchain Security** — Smart contract auditing, DeFi analysis, formal verification, MEV
- **Meta Agent** — Self-extension, skill generation, capability analysis, orchestration

Single binary. No server dependencies. Runs on Tokio. All data lives in embedded databases.

**Stack:** Rust (edition 2024), Tokio, Rig (v0.30.0), SQLite (sqlx), LanceDB, redb.

## Build Instructions

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get install -y protobuf-compiler
pip3 install onnxruntime

# Set up onnxruntime for the build (required by fastembed → ort-sys)
# The CI workflow (.github/workflows/ci.yml) automates this fully.
# For local development, run the same steps:
#   pip3 install onnxruntime
#   ORT_VERSION=$(python3 -c 'import onnxruntime; print(onnxruntime.__version__)')
#   ORT_LIB=$(python3 -c "import onnxruntime, os; print(os.path.dirname(onnxruntime.__file__))")/capi
#   sudo ln -sf "${ORT_LIB}/libonnxruntime.so.${ORT_VERSION}" /usr/local/lib/libonnxruntime.so
#   sudo ldconfig
#   mkdir -p /tmp/pkgconfig && <create libonnxruntime.pc pointing at /usr/local/lib>
export ORT_STRATEGY=system
export PKG_CONFIG_PATH=/tmp/pkgconfig   # directory containing libonnxruntime.pc

# Build
cargo build

# Run tests
cargo test --lib
cargo test --test security_modules
cargo test --test security_integration

# Lint
cargo clippy --all-targets

# Format
cargo fmt --all
```

## Module Layout

```
src/
├── main.rs              — CLI entry point (Clap subcommands)
├── lib.rs               — Re-exports for all modules
├── red_team/            — Adversary emulation framework
│   ├── recon.rs         — Reconnaissance methodology
│   ├── exploitation.rs  — Exploit execution (simulation only)
│   ├── apt_emulation.rs — APT group profiles and TTP emulation
│   ├── exfiltration.rs  — Data exfiltration simulation
│   └── ...
├── blue_team/           — Defensive operations framework
│   ├── detection.rs     — YARA/Sigma/KQL/SPL rule generation
│   ├── malware_analysis.rs — Static + behavioral analysis
│   ├── threat_intel.rs  — IOC management and correlation
│   ├── siem_soar.rs     — Query builder and alert correlation
│   └── ...
├── exploit_engine/      — Exploit research framework
│   ├── fuzzing.rs       — Fuzzer configuration and corpus management
│   ├── crash_analysis.rs — Crash classification and exploitability
│   ├── payload_gen.rs   — Payload encoding and staging
│   └── ...
├── pentest/             — Penetration testing orchestration
│   ├── scoping.rs       — Engagement scope and authorization
│   ├── reporting.rs     — CVSS v3.1 scoring and report generation
│   ├── web_security.rs  — XSS/SQLi payload generation
│   ├── enumeration.rs   — Service fingerprinting
│   └── ...
├── blockchain_security/ — Smart contract security
│   ├── contract_analysis.rs — Vulnerability detection (reentrancy, tx.origin, …)
│   ├── defi.rs          — DeFi protocol analysis
│   ├── mev_protection.rs — MEV attack vector analysis
│   ├── token_security.rs — ERC token security analysis
│   └── ...
├── meta_agent/          — Self-extension and orchestration
│   ├── skill_generator.rs — Auto-generate SKILL.md files
│   ├── capability_analysis.rs — Coverage gap detection
│   ├── skill_router.rs  — Route tasks to registered skills
│   └── ...
├── agent/               — LLM process types (channel, branch, worker, cortex)
├── memory/              — Vector + graph memory system (LanceDB + SQLite)
├── messaging/           — Adapters: Discord, Telegram, Slack, Webhook
└── ...
```

## Coding Conventions

### Structs and Enums

```rust
// Security domain structs (data objects, findings, configs): all fields pub.
// This is the dominant pattern in the security modules; it keeps the API
// flexible and avoids accessor boilerplate for simple data containers.
#[derive(Debug, Clone)]
pub struct MyStruct {
    pub field: String,
    pub count: u32,
}

// Enums: derive Debug + Clone + PartialEq
#[derive(Debug, Clone, PartialEq)]
pub enum MyEnum {
    VariantA,
    VariantB,
}

// Serializable types: add Serialize + Deserialize
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Config { ... }
```

### Timestamps

Always use `chrono::DateTime<chrono::Utc>` for timestamps:

```rust
pub created_at: chrono::DateTime<chrono::Utc>,
// Initialized with:
created_at: chrono::Utc::now(),
```

### Error Handling

- Use `anyhow::Result<T>` for fallible public functions
- Use `thiserror` for domain-specific error types
- Never silently discard `Result` with `let _ =`; handle, log, or propagate

### Async

- All async functions use `async fn` with Tokio
- No `#[async_trait]`; use native RPITIT for async traits
- Add a `Dyn` companion trait only when `dyn Trait` is actually needed

### Variable Naming

- No abbreviations: `message` not `msg`, `channel` not `ch`, `config` is fine
- Module roots use `src/module_name.rs` (never `src/module_name/mod.rs`)

## Testing Conventions

### Test Location

- Unit tests: `#[cfg(test)] mod tests { ... }` inside the module file
- Integration tests: `tests/` directory as separate `.rs` files

### Test Naming

Use descriptive `snake_case` names:

```rust
#[test]
fn test_contract_analyzer_detects_reentrancy() { ... }

#[test]
fn test_cvss_score_critical_network_no_auth() { ... }
```

### Test Structure

```rust
#[test]
fn test_feature_scenario() {
    // Arrange
    let input = ...;

    // Act
    let result = function_under_test(&input);

    // Assert
    assert_eq!(result.field, expected, "descriptive failure message");
    assert!(!result.list.is_empty(), "list should be non-empty");
}
```

### Running Tests

```bash
# All lib unit tests
cargo test --lib

# Specific integration test file
cargo test --test security_modules
cargo test --test security_integration

# Single test by name
cargo test --test security_modules test_cvss_score_critical
```

## Security Notes

- All security modules simulate operations for **authorized engagements only**
- Never commit real credentials, API keys, or exploit payloads
- The `secrets/` module provides AES-256-GCM encrypted storage for all credentials
- File tools enforce workspace path guards — reject writes outside authorized paths
- Leak detection scans tool output for credential patterns (regex in JamesHook)
