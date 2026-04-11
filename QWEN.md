# Crypt Tools - Project Context

## Project Overview

**Crypt Tools** is a cross-platform command-line encryption utility (Python 3.13+ and Node.js 18+) that provides secure AES-256-GCM authenticated encryption for files and text. It features:

- **AES-256-GCM encryption** with PBKDF2-HMAC-SHA256 (100k iterations) or Argon2id (3 iterations, 64MB memory)
- **Streamed processing** (64KB chunks) for large files
- **Versioned CT02 file format** with embedded metadata (compression flag, KDF type, parameters)
- **Hidden-volume containers** for plausible deniability (decoy + hidden payload with `CTHV` footer)
- **Key file support** for two-factor encryption (password + 32-byte key file)
- **Shamir's Secret Sharing** for threshold-based key splitting
- **Rich CLI** with password strength indicators, progress bars, emojis, and optional file logging

**Author:** Center For Cyber Intelligence  
**Current Version:** 2.4.0  
**License:** Proprietary

---

## Repository Structure

```
crypt_tools/
├── crypt_tools.py          # Main Python CLI (~2550 lines)
├── crypt_tools.js          # Node.js CLI (feature parity)
├── shamir.py               # Shamir's Secret Sharing (Python)
├── shamir.js               # Shamir's Secret Sharing (Node.js)
├── tests/
│   ├── test_crypt_tools.py # Python pytest suite (~1640 lines)
│   ├── keyfile.test.js     # Node.js key file tests
│   └── crypt_tools_cli.test.js # Node.js CLI tests
├── pyproject.toml          # Python project config (uv/pip)
├── package.json            # Node.js project config
├── pytest.ini              # Pytest configuration
├── README.md               # Python user documentation
├── README_NODEJS.md        # Node.js user documentation
├── PRD.md                  # Product Requirements Document
├── favicon.ico             # Executable icon
├── version_info.txt        # PyInstaller version metadata
└── QWEN.md                 # This file (AI context)
```

---

## Building and Running

### Python Edition

**Setup:**
```bash
# Using uv (recommended)
uv sync

# Using pip
pip install -r requirements.txt  # if available
# Or install dependencies manually:
pip install pycryptodome tqdm argon2-cffi
```

**Run:**
```bash
uv run crypt_tools.py --help
uv run crypt_tools.py --encrypt -f document.txt -p "password"
```

**Test:**
```bash
uv run pytest                    # Run all tests
uv run pytest --cov=crypt_tools  # With coverage
uv run pytest -v                 # Verbose output
```

**Build Executable:**
```bash
# Using uvx (temporary environment)
uvx --with pycryptodome --with tqdm pyinstaller \
  --onefile --icon=favicon.ico --version-file=version_info.txt \
  crypt_tools.py

# Or using global pyinstaller
pyinstaller --onefile --icon=favicon.ico --version-file=version_info.txt crypt_tools.py
```

### Node.js Edition

**Setup:**
```bash
npm install
```

**Run:**
```bash
node crypt_tools.js --help
node crypt_tools.js --encrypt -f document.txt -p "password"
npm start  # Alias for above
```

**Test:**
```bash
npm test                              # Run tests
npm run coverage                      # With coverage report
```

**Build Executable:**
```bash
# Using pkg
npm install -g pkg
pkg crypt_tools.js --targets node18-win,node18-linux,node18-macos

# Using ncc
npm install -g @vercel/ncc
ncc build crypt_tools.js -o dist
```

---

## Development Conventions

### Python Code Style

- **Line length:** 100 characters (configured in `pyproject.toml`)
- **Quotes:** Single quotes (`'string'`)
- **Indentation:** Tabs (not spaces)
- **Type hints:** Used throughout (`typing.Optional`, `typing.List`)
- **Docstrings:** Google-style for classes and public methods

**Linting/Formatting:**
```bash
uv run ruff check .      # Lint
uv run ruff format .     # Format
uv run ruff format --diff .  # Preview changes
```

### Testing Practices

- **Python:** `pytest` with fixtures (`@pytest.fixture`)
- **Node.js:** Native `node:test` with `spec` reporter
- **Coverage:** HTML reports in `htmlcov/` and `coverage/`
- **Test files:** `test_*.py` in `tests/` directory
- **Fixtures:** Reusable fixtures like `engine()` for `CryptoEngine`

**Test Categories:**
- Key derivation (deterministic, correct length)
- Encryption/decryption round-trip integrity
- Tamper detection (GCM tag verification)
- Wrong password handling (returns `None`)
- File streaming (large file handling)
- Compression verification
- CLI integration (argument parsing, password prompts)
- Hidden-volume containers (outer/hidden decrypt, footer parse)

### Commit Style

- Clear, concise messages focused on **why** not **what**
- Reference version changes when applicable
- Include emoji icons for visual categorization (optional)

---

## Key Architecture Components

### Python (`crypt_tools.py`)

| Class/Function | Responsibility |
|----------------|----------------|
| `GaloisField` | GF(2^8) arithmetic for Shamir's Secret Sharing: `mul()`, `exp()`, `inv()`, `div()` |
| `ShamirSecretSharing` | Secret sharing: `generate_shares()`, `recover_secret()` |
| `Config` | Constants: key size (32), salt (16), nonce (12), tag (16), chunk size (64KB), PBKDF2 iterations (100k), Argon2 params, magic bytes (`CT02`, `CTHV`) |
| `ConfigParser` | Config file loading & CLI defaults: `load_defaults()`, `detect_cli_overrides()`, `apply_defaults()`, `parse_yaml()`, `parse_conf()` |
| `HeaderParser` | CT02 header building/parsing: `build_header()`, `parse_ct02()`, `parse_format()`, `parse_hidden_footer()`, `inspect_blob()` |
| `KeyFileUtils` | Key file operations: `generate()`, `read()`, `combine_password_and_keyfile()` |
| `UIHelpers` | Terminal UI: `render_qr()`, `show_qr()`, `file_selector()`, `should_use_color()`, `style()`, `heading()` |
| `PasswordUtils` | Password handling: `prompt_with_strength()`, `verify_with_strength()`, `normalize_single()` |
| `PasswordStrength` | Password strength analysis: `get_level()`, `get_indicator()`, `get_char_types()` |
| `CryptoEngine` | Core encryption/decryption: `_derive_key()`, `encrypt_data()`, `decrypt_data()`, `encrypt_file()`, `decrypt_file()`, `encrypt_hidden_container()`, `decrypt_hidden_container()`, `inspect_file()` |
| `ConsoleLogger` | Unified console/file logging with emojis and colors via `show()` method |
| `TerminalColors` | ANSI color codes (StrEnum) |
| `Banner` | ASCII art banners on startup |

**Backward Compatibility:** All old function names are preserved as module-level aliases (e.g., `generate_keyfile = KeyFileUtils.generate`, `build_header = HeaderParser.build_header`).

### File Formats

**CT02 Header (16 bytes fixed):**
```
[Magic "CT02" (4)] [Version (1)] [Flags (1)] [KDF ID (1)] [Reserved (1)]
[Salt Len (1)] [Nonce Len (1)] [Tag Len (1)] [KDF Param Len (1)]
[KDF Params (4)] [Salt (16)] [Nonce (12)] [Ciphertext] [GCM Tag (16)]
```

**Flags:**
- `0x01`: Compression enabled
- `0x02`: Text mode
- `0x04`: Key file used
- `0x08`: Threshold (Shamir) enabled

**KDF IDs:**
- `0x01`: PBKDF2-HMAC-SHA256
- `0x02`: Argon2id

**Hidden-Volume Container:**
```
[CT02_outer] [CT02_hidden] [CTHV (4)] [uint64_be outer_total_len (8)]
```

---

## CLI Arguments Reference

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--encrypt` | `-e` | Encrypt mode | Yes |
| `--decrypt` | `-d` | Decrypt mode | No |
| `--inspect` | — | Inspect encrypted file metadata | No |
| `--generate-keyfile` | — | Generate 32-byte random key file (default: `key.txt`) | — |
| `--text` | `-t` | Text to process | — |
| `--file` | `-f` | Input file/path/wildcard (e.g., `*.md`, `tests\*.pyc`) | Required |
| `--output` | `-o` | Output file path | Auto-generated (`.enc`/`.dec`) |
| `--password` | `-p` | Password (prompts if missing) | Interactive |
| `--keyfile` | — | Key file for two-factor encryption | — |
| `--compress` | `-c` | Enable zlib compression | Disabled |
| `--recursive` | `-r` | Process directories recursively | Disabled |
| `--kdf` | — | `pbkdf2` (default) or `argon2` | `pbkdf2` |
| `--iterations` | — | KDF iterations (100k PBKDF2, 3 Argon2) | Auto |
| `--log` | — | Enable file logging (`crypt_tools.log`) | Disabled |
| `--debug` | — | Enable debug logging | Disabled |
| `--version` | `-V` | Show version | — |
| `--hidden-vol` | — | Create hidden-volume container | No |
| `--hidden-file` | — | Hidden payload path (requires `--hidden-vol`) | — |
| `--hidden` | — | Decrypt inner volume (password = hidden password) | No |
| `--password-outer` | — | Decoy password for `--hidden-vol` | — |
| `--password-hidden` | — | Hidden password for `--hidden-vol` | — |

**Wildcard tip (Windows/PowerShell):** Quote patterns like `"*.md"` to prevent shell expansion.

---

## Common Tasks

### Encrypt/Decrypt Text
```bash
uv run crypt_tools.py --encrypt -t "Secret Message" -p "password"
uv run crypt_tools.py --decrypt -t "<base64_string>" -p "password"
```

### Encrypt/Decrypt File
```bash
uv run crypt_tools.py --encrypt -f document.txt -p "password" -c  # With compression
uv run crypt_tools.py --decrypt -f document.enc -p "password"
```

### Encrypt with Argon2 (More Secure)
```bash
uv run crypt_tools.py --encrypt -f document.txt -p "password" --kdf argon2
```

### Generate and Use Key File
```bash
uv run crypt_tools.py --generate-keyfile  # Uses default name: key.txt
uv run crypt_tools.py --generate-keyfile mykey.bin  # Custom name
uv run crypt_tools.py --encrypt -f document.txt --keyfile mykey.bin -p ""
uv run crypt_tools.py --encrypt -f document.txt -p "password" --keyfile mykey.bin  # Two-factor
```

### Hidden Volume (Plausible Deniability)
```bash
# Create container with decoy + hidden payload
uv run crypt_tools.py --encrypt -f decoy.txt --hidden-vol --hidden-file secret.bin \
  --password-outer "decoy_pw" --password-hidden "real_pw"

# Decrypt decoy (outer)
uv run crypt_tools.py --decrypt -f decoy.txt.enc -p "decoy_pw" -o out_decoy.txt

# Decrypt hidden (inner)
uv run crypt_tools.py --decrypt --hidden -f decoy.txt.enc -p "real_pw" -o out_secret.bin
```

### Inspect Encrypted File
```bash
uv run crypt_tools.py --inspect -f document.enc
```

### Batch Operations with Wildcards
```bash
uv run crypt_tools.py --encrypt -f "*.md" -p "password"
uv run crypt_tools.py --encrypt -r -f ".\tests\*.pyc" -p "password"  # Recursive
```

---

## Dependencies

### Python
- `pycryptodome` ≥3.21.0 (AES-GCM)
- `tqdm` ≥4.66.0 (Progress bars)
- `argon2-cffi` ≥25.1.0 (Argon2id, optional)
- `zlib` (stdlib, compression)

### Node.js
- `argon2` ^0.44.0
- `commander` ^12.0.0
- `progress` ^2.0.3
- `c8` ^10.1.2 (dev, coverage)

---

## Known Limitations

- **v1.x incompatibility:** MD5-based legacy files not supported (must decrypt with old tool first)
- **Output override:** `--output` only applies to single-file operations (not patterns/recursive)
- **Hidden volumes:** Single-file only (no wildcards/recursive); `CTHV` footer is forensically visible
- **Legacy compressed files:** May require `--compress` flag during decryption (compression not stored in old format)
- **Log file:** Accumulates entries; manual cleanup required

---

## Testing Commands Summary

```bash
# Python
uv run pytest
uv run pytest -v
uv run pytest --cov=crypt_tools
uv run pytest --cov=crypt_tools --cov-report=html

# Node.js
npm test
npm run coverage
npm run test:all  # Both tests and coverage
```

---

## Release Automation

When creating GitHub releases, always follow this structure:

### 1. Title:
- Format: `v<version> - <short summary>`

### 2. Overview:
- 1–2 sentences explaining the purpose of this release.

### 3. 🚀 Features
- List new features with concise bullet points.

### 4. 🛠 Improvements
- Enhancements or optimizations.

### 5. 🐛 Bug Fixes
- Clearly describe fixes.

### 6. 🔐 Security
- Mention any cryptography/security updates.

### 7. ⚠️ Breaking Changes (if any)
- Clearly warn users.

### 8. 📦 CLI Usage (if relevant)
- Show updated commands or examples.

### 9. 📊 Full Changelog
- Format: `<previous_version>...<current_version>`

### 10. 👥 Contributors (optional)

**Rules:**
- Keep it concise but professional.
- Use emojis for sections.
- Use markdown formatting.
- Always maintain the same structure.
- Never omit sections (write "None" if empty).

Use `gh release create v<version> --title "v<version> - <summary>" --notes "<markdown>"` to create releases.

---

## Related Files

| File | Purpose |
|------|---------|
| `PRD.md` | Product Requirements Document (features, specs, version history) |
| `README.md` | Python user documentation |
| `README_NODEJS.md` | Node.js user documentation |
| `pytest.ini` | Pytest configuration (testpaths, addopts) |
| `pyproject.toml` | Python project config (dependencies, ruff, taskipy) |
| `package.json` | Node.js project config (scripts, dependencies) |
| `.python-version` | pyenv Python version (3.13) |
| `version_info.txt` | PyInstaller Windows version metadata |
| `favicon.ico` | Executable icon |
