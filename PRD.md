# Product Requirements Document: Crypt Tools

## 1. Executive Summary

| Attribute | Details |
|-----------|---------|
| **Product Name** | Crypt Tools |
| **Version** | 2.6.2 |
| **Type** | Command-Line Encryption Utility |
| **Platform** | Cross-platform (Windows, Linux, macOS) |
| **Language** | Python 3.13+ (reference) + Node.js 18+ edition |
| **Author** | Center For Cyber Intelligence |
| **License** | Proprietary |

---

## 2. Product Overview

**Crypt Tools** is a secure command-line utility for encrypting and decrypting files and text using industry-standard AES-256-GCM authenticated encryption. It features PBKDF2-HMAC-SHA256 key derivation, streamed processing for large files, optional compression, a versioned `CT02` encrypted file format, and an intuitive CLI with visual feedback.

### 2.1 Purpose
Provide users with a lightweight, secure, and efficient tool for protecting sensitive data at rest through encryption.

### 2.2 Target Users
- Security-conscious individuals
- IT professionals handling sensitive data
- Organizations requiring file-level encryption
- Developers needing CLI-based encryption utilities

---

## 3. Features & Capabilities

### 3.1 Core Features

| Feature | Description |
|---------|-------------|
| **AES-256-GCM Encryption** | Authenticated encryption ensuring confidentiality and integrity |
| **PBKDF2 Key Derivation** | 100,000 iterations with HMAC-SHA256 and random 16-byte salt |
| **Argon2id Support** | Modern KDF alternative (3 iterations, 64MB memory, 4 parallelism) |
| **Streamed File Processing** | 64KB chunk-based processing for minimal memory footprint |
| **Optional Compression** | Zlib compression (level 9) before encryption |
| **Versioned File Format** | `CT02` header with embedded flags and KDF parameters |
| **Text Encryption** | Encrypt/decrypt strings directly from CLI |
| **File Encryption** | Encrypt/decrypt individual files |
| **Inspect Mode** | View encrypted file metadata without decrypting |
| **Recursive Directory Processing** | Batch encrypt/decrypt entire directory trees |
| **File Pattern Expansion** | Encrypt/decrypt file groups via wildcards (e.g., `*.md`, `crypt*.*`) |
| **Secure Password Handling** | Interactive prompts with verification (encrypt mode) |
| **Password Strength Indicator** | Live strength and character-class feedback during input |
| **Visual Feedback** | Progress bars, color-coded logs with emojis, ASCII banners |
| **File Logging** | Optional timestamped log file for audit trail |
| **Configuration File Defaults** | Load common defaults from `.crypt_tools.conf`, `.crypt_tools.json`, `.crypt_tools.yml`, or `.crypt_tools.yaml` |
| **Environment Variable Defaults** | Support `CRYPT_TOOLS_PASSWORD`, `CRYPT_TOOLS_KDF`, `CRYPT_TOOLS_ITERATIONS`, and related CLI defaults |
| **Interactive File Selection** | Browse and choose a file or directory from a terminal UI with `--select` |
| **QR Code Output** | Render encrypted text as a terminal QR code with `--qr` |
| **Key File Support** | Generate and use key files for two-factor encryption |
| **Hidden volumes (containers)** | Optional two-layer file: decoy payload (outer password) + real payload (hidden password); `CTHV` footer marks split; file-only, not full-disk VeraCrypt semantics |

### 3.2 Security Features

| Feature | Specification |
|---------|--------------|
| **Key Size** | 256 bits (32 bytes) |
| **Salt** | 16 bytes (128 bits), random per encryption |
| **Nonce** | 12 bytes (96 bits), random per encryption |
| **Authentication Tag** | 16 bytes (128 bits) GCM tag |
| **PBKDF2 Iterations** | 100,000 |
| **Argon2id Iterations** | 3 (time cost) |
| **Argon2id Memory** | 64 MB |
| **Argon2id Parallelism** | 4 |
| **Password Verification** | Required for encryption (double-entry) |
| **Integrity Verification** | Automatic GCM tag verification on decryption |
| **Key File Support** | 32-byte random key files for two-factor encryption |
| **Hidden-volume container** | Two concatenated `CT02` blobs plus plaintext `CTHV` + 8-byte big-endian outer length footer; wrong password on outer decrypt fails; hidden decrypt uses inner range only |

---

## 4. Technical Specifications

### 4.1 Encryption Format

**File Format:**
```
[Magic: 4 bytes] + [Version: 1 byte] + [Flags: 1 byte] + [KDF ID: 1 byte] + [Reserved: 1 byte] +
[Salt Length: 1 byte] + [Nonce Length: 1 byte] + [Tag Length: 1 byte] + [KDF Param Length: 1 byte] +
[KDF Params: variable] + [Salt: 16 bytes] + [Nonce: 12 bytes] + [Ciphertext: variable] + [GCM Tag: 16 bytes]
```

**In-Memory Format:**
```
[Header] + [Salt: 16 bytes] + [Nonce: 12 bytes] + [Ciphertext] + [GCM Tag: 16 bytes]
```

**Current Overhead (PBKDF2 / CT02):** 60 bytes per encrypted file

**Hidden-volume container (optional, file mode only):**

```text
[CT02_outer][CT02_hidden][FOOTER_MAGIC "CTHV" (4 bytes)][uint64_be outer_total_len]
```

- `outer_total_len` is the byte length of the entire first `CT02` object (header through outer GCM tag). The second `CT02` (hidden) immediately follows; the 12-byte footer is appended last.
- This is **not** identical to VeraCrypt: the footer and extra file length are visible; plausible deniability is “coercion / wrong password opens decoy,” not “analyst thinks the file is a single ciphertext only.”
- Text/Base64 mode does not support hidden containers.

### 4.2 Architecture

| Component | Responsibility |
|-----------|---------------|
| `Config` | Constants for crypto parameters |
| `CryptoEngine` | Core encryption/decryption logic |
| `Banner` | ASCII art display on startup |
| `ConsoleLogger` | Unified console and file logging with emojis |
| `TerminalColors` | ANSI color codes |
| `main()` | CLI entry point and argument handling |

### 4.3 Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `blessed` | ≥1.38.0 | Terminal UI for interactive file selection |
| `pycryptodome` | ≥3.21.0 | AES-GCM cryptography |
| `qrcode` | ≥8.2 | QR code generation for text encryption output |
| `tqdm` | ≥4.66.0 | Progress bars |
| `zlib` | (stdlib) | Compression |

### 4.4 System Requirements

| Requirement | Specification |
|-------------|--------------|
| **Python** | 3.13 or higher |
| **Memory** | Minimal (streaming architecture) |
| **Storage** | Depends on file sizes |
| **OS** | Windows, Linux, macOS |

---

## 5. User Interface

### 5.1 Command-Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--encrypt` | `-e` | Encrypt mode | Yes (default) |
| `--decrypt` | `-d` | Decrypt mode | No |
| `--inspect` | — | Inspect encrypted file metadata | No |
| `--generate-keyfile` | — | Generate a MEGA-style textual recovery key (default: `key.txt`) | `key.txt` |
| `--text` | `-t` | Text to process | None |
| `--file` | `-f` | Input file/directory path or wildcard pattern (e.g., `*.md`, `tests\\*.pyc`) | Required |
| `--output` | `-o` | Output file path | Auto-generated |
| `--config` | — | Config file path for CLI defaults | Auto-discover in current working directory |
| `--select` | — | Launch interactive file/directory selection | Disabled |
| `--password` | `-p` | Password | Interactive prompt |
| `--keyfile` | — | Key file path for encryption/decryption | None |
| `--compress` | `-c` | Enable zlib compression | Disabled |
| `--recursive` | `-r` | Process directories or wildcard patterns recursively | Disabled |
| `--kdf` | — | Key derivation function: `pbkdf2` (default) or `argon2` | `pbkdf2` |
| `--iterations` | — | Number of iterations for KDF (default: 100000 for PBKDF2, 3 for Argon2) | varies |
| `--qr` | — | Render encrypted text output as a QR code | Disabled |
| `--log` | — | Enable file logging to `crypt_tools.log` | Disabled |
| `--debug` | — | Enable debug logging | Disabled |
| `--version` | `-V` | Show version | — |
| `--help` | `-h` | Show help | — |
| `--hidden-vol` | — | Encrypt decoy (`-f`) + hidden (`--hidden-file`) into one container | No |
| `--hidden-file` | — | Path to hidden payload (requires `--hidden-vol`) | None |
| `--hidden` | — | With `-d -f`, decrypt inner volume (password is hidden password) | No |
| `--password-outer` | — | Decoy password for `--hidden-vol` (optional; CLI exposure is insecure) | None |
| `--password-hidden` | — | Hidden password for `--hidden-vol`; with `-d --hidden` can replace `-p` | None |

### 5.2 Example Commands

```bash
# Encrypt text
uv run crypt_tools.py --encrypt -t "Secret Message" -p "password"

# Encrypt text and print a QR code
uv run crypt_tools.py --encrypt -t "Secret Message" -p "password" --qr

# Decrypt text
uv run crypt_tools.py --decrypt -t "base64_encrypted_string" -p "password"

# Encrypt file (interactive password)
uv run crypt_tools.py --encrypt -f document.txt

# Encrypt file with compression
uv run crypt_tools.py --encrypt -f document.txt -p "password" -c

# Encrypt directory recursively
uv run crypt_tools.py --encrypt -f ./my_folder -r -p "password"

# Decrypt directory recursively
uv run crypt_tools.py --decrypt -f ./my_folder -r -p "password"

# Inspect encrypted file metadata
uv run crypt_tools.py --inspect -f document.enc

# Enable file logging
uv run crypt_tools.py --encrypt -f document.txt -p "password" --log

# Encrypt using a discovered config file in the current directory
uv run crypt_tools.py --encrypt -f document.txt

# Encrypt using an explicit config file
uv run crypt_tools.py --config .\team-defaults.json --encrypt -f document.txt

# Encrypt using environment variable defaults
$env:CRYPT_TOOLS_PASSWORD="password"
$env:CRYPT_TOOLS_KDF="argon2"
$env:CRYPT_TOOLS_ITERATIONS="3"
uv run crypt_tools.py --encrypt -t "Secret Message"

# Choose a file interactively from a terminal UI
uv run crypt_tools.py --encrypt --select -p "password"

# Encrypt a group of files by pattern
uv run crypt_tools.py --encrypt -f "*.md" -p "password"

# Recursive wildcard inside a directory
uv run crypt_tools.py --encrypt -r -f ".\\tests\\*.pyc" -p "password"

# Generate a key file (uses default name: key.txt)
uv run crypt_tools.py --generate-keyfile

# Generate a key file with custom name
uv run crypt_tools.py --generate-keyfile mykey.txt

# Encrypt with key file only (no password)
uv run crypt_tools.py --encrypt -f document.txt --keyfile mykey.txt -p ""

# Encrypt with password AND key file (two-factor)
uv run crypt_tools.py --encrypt -f document.txt -p "password" --keyfile mykey.txt

# Decrypt with key file
uv run crypt_tools.py --decrypt -f document.enc --keyfile mykey.txt -p "password"

# Encrypt with Argon2 (more secure, recommended)
uv run crypt_tools.py --encrypt -f document.txt -p "password" --kdf argon2

# Encrypt with Argon2 and custom iterations
uv run crypt_tools.py --encrypt -f document.txt -p "password" --kdf argon2 --iterations 5

# Decrypt file encrypted with Argon2 (auto-detected from file header)
uv run crypt_tools.py --decrypt -f document.enc -p "password"

# Hidden volume: encrypt decoy + secret into one container (single decoy file, no wildcards/recursive)
uv run crypt_tools.py --encrypt -f decoy.txt --hidden-vol --hidden-file secret.bin --password-outer "decoy_pw" --password-hidden "real_pw"

# Decrypt decoy (outer) only
uv run crypt_tools.py --decrypt -f decoy.txt.enc -p "decoy_pw" -o recovered_decoy.txt

# Decrypt hidden (inner) payload
uv run crypt_tools.py --decrypt --hidden -f decoy.txt.enc -p "real_pw" -o recovered_secret.bin
```

---

## 6. Quality Assurance

### 6.1 Test Coverage

| Test Category | Coverage |
|---------------|----------|
| Key Derivation | ✓ Deterministic, correct length |
| Data Encryption/Decryption | ✓ Round-trip integrity |
| Tamper Detection | ✓ GCM tag verification |
| Wrong Password Handling | ✓ Returns `None` on failure |
| File Streaming | ✓ Large file handling |
| Compression | ✓ Size reduction verification |
| CLI Integration | ✓ Argument parsing, password prompts |
| Password Mismatch | ✓ Exit on verification failure |
| Config file defaults | ✓ Auto-discovery, explicit `--config`, and precedence behavior |
| Environment variable defaults | ✓ Password/KDF/iteration defaults for non-interactive usage |
| QR code output | ✓ Text encryption can render a terminal QR code |
| Interactive file selection | ✓ Selector populates the file path for CLI flows |
| Recursive Processing | ✓ Directory tree handling |
| Hidden-volume containers | ✓ Round-trip outer/hidden, footer parse, inspect metadata |

### 6.2 Testing Commands

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=crypt_tools

# View coverage report
uv run pytest --cov=crypt_tools --cov-report=html
```

---

## 7. Error Handling

| Scenario | Behavior |
|----------|----------|
| **Wrong Password** | Decryption fails, output file deleted |
| **Tampered File** | GCM verification fails, integrity error |
| **File Too Small** | ValueError raised, graceful exit |
| **Legacy Compressed File** | May require `--compress` during decryption |
| **Missing Input** | Error logged, exit code 1 |
| **Password Empty** | Error logged, exit code 1 |
| **Password Mismatch** | Verification fails, exit code 1 |

---

## 8. Limitations & Constraints

| Limitation | Details |
|------------|---------|
| **Version Compatibility** | v2.2.0 reads `CT02` and legacy v2.1 files; still not compatible with v1.x (MD5-based) |
| **File Extension** | Encrypted files use `.enc` by default; decrypted files use `.dec` |
| **Output Override** | `--output` applies only to single-file operations |
| **Interactive Mode** | Requires terminal for password prompts |
| **File Selector** | `--select` requires an interactive terminal and is intentionally single-selection |
| **Memory** | Chunk-based but requires ~64KB buffer |
| **Log File** | Log file accumulates entries; manual cleanup required |
| **Config Parser Scope** | YAML support is intentionally limited to flat `key: value` pairs; nested YAML is not supported |
| **Hidden volumes** | `--hidden-vol` is single-file only; no wildcards or `--recursive`; footer is visible forensically |

---

## 9. Future Enhancements (Proposed)

| Feature | Priority | Description |
|---------|----------|-------------|
| GUI Interface | Low | Desktop application wrapper |
| Multi-threading | Low | Parallel file processing |
| Cloud Integration | Low | Direct S3/Drive encryption |

---

## 10. Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.6.2 | 2026-04-10 | Fixed recursive decrypt output filename to match non-recursive behavior (files like `test.txt.enc` now decrypt to `test.txt` instead of `test.txt.dec`), fixed missing `UIHelpers.file_selector` reference in Python CLI |
| 2.6.1 | 2026-04-10 | Added tests for default keyfile name (`key.txt`) when `--generate-keyfile` is called without a path, ensuring consistent behavior and documentation alignment |
| 2.6.0 | 2026-04-09 | Added default filename (`key.txt`) for `--generate-keyfile` when no path is provided, switched `--generate-keyfile` to emit MEGA-style textual recovery keys, kept backward compatibility with legacy binary key files, compacted Python QR output to match Node more closely, cleaned up duplicate error lines, and ensured session end logging appears on failure paths |
| 2.5.0 | 2026-04-03 | Added interactive file selection (`--select`) using a terminal UI, QR code output for text encryption (`--qr`), new Python/Node QR and TUI dependencies, and test coverage for the new flows |
| 2.4.3 | 2026-04-03 | Added grouped/colorized CLI help, expanded `--help` with environment variables and config keys, and normalized release versions across scripts, docs, and package metadata |
| 2.4.2 | 2026-04-03 | Added configuration-file defaults (`--config`, `.crypt_tools.{conf,json,yml,yaml}`), environment-variable defaults (`CRYPT_TOOLS_*`), README examples, and sample config templates |
| 2.4.1 | 2026-04-03 | Inlined Shamir logic into the CLI scripts, fixed threshold password prompting and compressed threshold decryption, and expanded inspect output for threshold files and hidden containers |
| 2.4.0 | 2026-03-28 | Hidden-volume containers (`--hidden-vol`, `--hidden-file`, `-d --hidden`, `CTHV` footer), `decrypt_file` byte-range slices, inspect reports container metadata; Python and Node parity |
| 2.3.0 | 2026-03-27 | Version bump for development |
| 2.2.0 | 2026-03-27 | Added Argon2id key derivation (`--kdf argon2`, `--iterations`), key file support (`--generate-keyfile`, `--keyfile`), `CT02` format header, inspect mode, and automatic compression detection for new files |
| 2.1.0 | 2026-03-16 | Minor version update, encoding fixes |
| 2.0.0 | 2026 | AES-GCM, PBKDF2, streaming, compression, OutputManager, file logging |
| 1.x | — | Legacy MD5-based (deprecated) |

---

## 11. Appendix

### 11.1 File Structure
```
crypt_tools/
├── crypt_tools.py          # Main application (Python)
├── crypt_tools.js          # Node.js edition (parity CLI)
├── tests/
│   ├── test_crypt_tools.py # Python test suite
│   └── crypt_tools_cli.test.js # Node CLI tests
├── pyproject.toml          # Project configuration
├── README.md               # User documentation
├── README_NODEJS.md        # Node.js user documentation
└── pytest.ini              # Test configuration
```

### 11.2 Contact & Support
- **Author:** Center For Cyber Intelligence
- **Repository:** https://github.com/kelevramad/crypt_tools

---

**Document Version:** 1.8
**Last Updated:** April 10, 2026
