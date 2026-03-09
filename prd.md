# Product Requirements Document: Crypt Tools

## 1. Executive Summary

| Attribute | Details |
|-----------|---------|
| **Product Name** | Crypt Tools |
| **Version** | 2.0.0 |
| **Type** | Command-Line Encryption Utility |
| **Platform** | Cross-platform (Windows, Linux, macOS) |
| **Language** | Python 3.13+ |
| **Author** | Center For Cyber Intelligence |
| **License** | Proprietary |

---

## 2. Product Overview

**Crypt Tools** is a secure command-line utility for encrypting and decrypting files and text using industry-standard AES-256-GCM authenticated encryption. It features PBKDF2-HMAC-SHA256 key derivation, streamed processing for large files, optional compression, and an intuitive CLI with visual feedback.

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
| **Streamed File Processing** | 64KB chunk-based processing for minimal memory footprint |
| **Optional Compression** | Zlib compression (level 9) before encryption |
| **Text Encryption** | Encrypt/decrypt strings directly from CLI |
| **File Encryption** | Encrypt/decrypt individual files |
| **Recursive Directory Processing** | Batch encrypt/decrypt entire directory trees |
| **Secure Password Handling** | Interactive prompts with verification (encrypt mode) |
| **Visual Feedback** | Progress bars, color-coded logs, ASCII banners |

### 3.2 Security Features

| Feature | Specification |
|---------|--------------|
| **Key Size** | 256 bits (32 bytes) |
| **Salt** | 16 bytes (128 bits), random per encryption |
| **Nonce** | 12 bytes (96 bits), random per encryption |
| **Authentication Tag** | 16 bytes (128 bits) GCM tag |
| **PBKDF2 Iterations** | 100,000 |
| **Password Verification** | Required for encryption (double-entry) |
| **Integrity Verification** | Automatic GCM tag verification on decryption |

---

## 4. Technical Specifications

### 4.1 Encryption Format

**File Format:**
```
[Salt: 16 bytes] + [Nonce: 12 bytes] + [Ciphertext: variable] + [GCM Tag: 16 bytes]
```

**In-Memory Format:**
```
[Salt: 16 bytes] + [Nonce: 12 bytes] + [GCM Tag: 16 bytes] + [Ciphertext]
```

**Total Overhead:** 44 bytes per encrypted file

### 4.2 Architecture

| Component | Responsibility |
|-----------|---------------|
| `Config` | Constants for crypto parameters |
| `CryptoEngine` | Core encryption/decryption logic |
| `Banner` | ASCII art display on startup |
| `Logger` | Color-coded console output |
| `TerminalColors` | ANSI color codes |
| `main()` | CLI entry point and argument handling |

### 4.3 Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `pycryptodome` | ≥3.21.0 | AES-GCM cryptography |
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
| `--text` | `-t` | Text to process | None |
| `--input` | `-i` | Input file/directory path | Required |
| `--output` | `-o` | Output file path | Auto-generated |
| `--password` | `-p` | Password | Interactive prompt |
| `--compress` | `-c` | Enable zlib compression | Disabled |
| `--recursive` | `-r` | Process directories recursively | Disabled |
| `--debug` | — | Enable debug logging | Disabled |
| `--version` | `-v` | Show version | — |

### 5.2 Example Commands

```bash
# Encrypt text
uv run crypt_tools.py --encrypt -t "Secret Message" -p "password"

# Decrypt text
uv run crypt_tools.py --decrypt -t "base64_encrypted_string" -p "password"

# Encrypt file (interactive password)
uv run crypt_tools.py --encrypt -i document.txt

# Encrypt file with compression
uv run crypt_tools.py --encrypt -i document.txt -p "password" -c

# Encrypt directory recursively
uv run crypt_tools.py --encrypt -i ./my_folder -r -p "password"

# Decrypt directory recursively
uv run crypt_tools.py --decrypt -i ./my_folder -r -p "password"
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
| Recursive Processing | ✓ Directory tree handling |

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
| **Missing Input** | Error logged, exit code 1 |
| **Password Empty** | Error logged, exit code 1 |
| **Password Mismatch** | Verification fails, exit code 1 |

---

## 8. Limitations & Constraints

| Limitation | Details |
|------------|---------|
| **Version Compatibility** | v2.0.0 not compatible with v1.x (MD5-based) |
| **File Extension** | Encrypted files use `.enc` by default |
| **Interactive Mode** | Requires terminal for password prompts |
| **Memory** | Chunk-based but requires ~64KB buffer |

---

## 9. Future Enhancements (Proposed)

| Feature | Priority | Description |
|---------|----------|-------------|
| GUI Interface | Low | Desktop application wrapper |
| Key File Support | Medium | Alternative to password-based encryption |
| Multi-threading | Low | Parallel file processing |
| Cloud Integration | Low | Direct S3/Drive encryption |
| Argon2 Support | Medium | Modern key derivation alternative |

---

## 10. Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.0.0 | 2026 | AES-GCM, PBKDF2, streaming, compression |
| 1.x | — | Legacy MD5-based (deprecated) |

---

## 11. Appendix

### 11.1 File Structure
```
crypt_tools/
├── crypt_tools.py          # Main application
├── tests/
│   └── test_crypt_tools.py # Test suite
├── pyproject.toml          # Project configuration
├── README.md               # User documentation
└── pytest.ini              # Test configuration
```

### 11.2 Contact & Support
- **Author:** Center For Cyber Intelligence
- **Repository:** https://github.com/kelevramad/crypt_tools

---

**Document Version:** 1.0  
**Last Updated:** March 9, 2026
