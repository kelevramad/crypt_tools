# Crypt Tools

## Overview
`crypt_tools.py` is a robust command-line tool for encrypting and decrypting files and text using the AES (Advanced Encryption Standard) algorithm. This updated version features enhanced security using **PBKDF2** (Password-Based Key Derivation Function 2) with HMAC-SHA256 for key derivation and a random 16-byte salt, making it significantly more secure against brute-force and dictionary attacks than previous versions. It also supports optional zlib compression, a versioned `CT02` file format, and encrypted-file inspection via CLI.

## Key Features
- **AES-256 Encryption**: Uses AES in **GCM (Galois/Counter Mode)** for authenticated encryption, ensuring both confidentiality and integrity.
- **Dual Key Derivation**: Supports **PBKDF2-HMAC-SHA256** (default, 100k iterations) and **Argon2id** (more secure, 3 iterations, 64MB memory).
- **Streamed Processing**: Processes files in 64KB chunks, allowing encryption of large files with minimal memory usage.
- **Data Compression**: Optional Zlib compression to reduce file size before encryption.
- **CLI Interface**: Easy-to-use command line interface for quick operations.
- **Visual Feedback**: Colorful terminal output with emojis, color-coded status messages, and ASCII art banners.
- **File Logging**: Optional timestamped log file (`crypt_tools.log`) for audit trails.
- **Configurable Defaults**: Load common CLI defaults from `.crypt_tools.conf`, `.crypt_tools.json`, `.crypt_tools.yml`, or `.crypt_tools.yaml`.
- **Secure Defaults**: Automatically handles Nonce generation and Salt management.
- **File Pattern Expansion**: Encrypt/decrypt groups of files via wildcards (e.g., `*.md`, `crypt*.*`).
- **Password Strength Indicator**: Live strength and character-class feedback during input.
- **Versioned File Format (`CT02`)**: New encrypted files include embedded metadata such as format version, compression flag, and KDF parameters.
- **Inspect Mode**: View encrypted file metadata without decrypting it.
- **Key File Support**: Generate and use key files for two-factor encryption (password + key file).
- **Argon2 Support**: Modern Argon2id key derivation alternative with configurable iterations via `--kdf` and `--iterations` flags.
- **Interactive File Selection**: Launch a terminal file picker with `--select` to browse and choose a file or directory.
- **QR Code Output**: Render encrypted text as a terminal QR code with `--qr` for air-gapped transfer.
- **Hidden volumes (containers)**: Optional two-password file container—decoy content with the outer password, sensitive content with the hidden password; similar in *goal* to VeraCrypt’s hidden volume, implemented as two `CT02` blobs plus a small `CTHV` footer (see limitations below).
- **Recovery Key Support**: Optionally generate a separate recovery key file during encryption and use it later to decrypt without the original password.

## Installation

### Prerequisites
- Python 3.13+
- Dependencies (managed via `uv` or `pip`):
  - `blessed`
  - `pycryptodome`
  - `qrcode`
  - `tqdm` (Progress Bar)
  - `zlib` (Standard Library)

### Setup
Clone the repository and install dependencies:
```bash
git clone https://github.com/kelevramad/crypt_tools.git
cd crypt_tools
uv sync  # or pip install -r requirements.txt if available
```

## Usage

### Encrypt a String
Encrypt a plain text string directly from the terminal.
```bash
uv run crypt_tools.py --encrypt -t "Secret Message" -p "your_password"
```

### Decrypt a String
Decrypt a base64 encoded string.
```bash
uv run crypt_tools.py --decrypt -t "encrypted_base64_string" -p "your_password"
```

### Encrypt a String as QR Code
Render the encrypted Base64 payload as a terminal QR code for scanning on another device.
```bash
uv run crypt_tools.py --encrypt -t "secret" -p "your_password" --qr
```

### Encrypt a File
Encrypt a file (e.g., `document.txt`) to an encrypted output (default `.enc`).
```bash
# Basic encryption (Password Prompt + Verification)
uv run crypt_tools.py --encrypt -f document.txt

# Non-interactive (password provided)
uv run crypt_tools.py --encrypt -f document.txt -p "your_password"

# With compression
uv run crypt_tools.py --encrypt -f document.txt -p "your_password" -c
```

### Decrypt a File
Decrypt an encrypted file (e.g., `document.enc`) back to its original form.
```bash
# Basic decryption
uv run crypt_tools.py --decrypt -f document.enc -p "your_password"

# Legacy files encrypted with compression may still require -c
uv run crypt_tools.py --decrypt -f document.enc -p "your_password" -c
```

For new `CT02` files, compression is detected automatically during decryption. The `-c/--compress` flag is only needed for legacy files created before the versioned header was introduced.

### Configuration File Defaults
Store repeated defaults in a config file in the current working directory, or pass one explicitly with `--config`.

Supported filenames:
- `.crypt_tools.conf`
- `.crypt_tools.json`
- `.crypt_tools.yml`
- `.crypt_tools.yaml`

Supported keys:
- `compress`
- `compression`
- `default_compression`
- `kdf`
- `default_kdf`
- `iterations`
- `default_iterations`
- `log`
- `logging`
- `log_enabled`
- `debug`
- `debug_enabled`
- `password`
- `default_password`
- `password_outer`
- `default_password_outer`
- `password_hidden`
- `default_password_hidden`
- `keyfile`
- `default_keyfile`
- `threshold`

Example YAML:
```yaml
default_compression: true
default_kdf: pbkdf2
iterations: 100000
log_enabled: true
```

Example JSON:
```json
{
  "default_password": "ci-secret",
  "default_kdf": "argon2",
  "iterations": 3
}
```

Example usage:
```bash
# Auto-discover .crypt_tools.yml in the current folder
uv run crypt_tools.py --encrypt -f document.txt

# Use an explicit config file
uv run crypt_tools.py --config .\team-defaults.json --encrypt -f document.txt
```

Ready-to-copy examples are included at [`.crypt_tools.yml.example`](C:/Git/KelevraMad/crypt_tools/.crypt_tools.yml.example) and [`.crypt_tools.conf.example`](C:/Git/KelevraMad/crypt_tools/.crypt_tools.conf.example).

### Environment Variables
Environment variables are useful for CI/CD or shell sessions where you do not want to repeat common flags.

Common variables:
- `CRYPT_TOOLS_PASSWORD`
- `CRYPT_TOOLS_COMPRESS`
- `CRYPT_TOOLS_COMPRESSION`
- `CRYPT_TOOLS_KDF`
- `CRYPT_TOOLS_ITERATIONS`
- `CRYPT_TOOLS_LOG`
- `CRYPT_TOOLS_LOG_ENABLED`
- `CRYPT_TOOLS_DEBUG`
- `CRYPT_TOOLS_DEBUG_ENABLED`
- `CRYPT_TOOLS_KEYFILE`
- `CRYPT_TOOLS_THRESHOLD`
- `CRYPT_TOOLS_PASSWORD_OUTER`
- `CRYPT_TOOLS_PASSWORD_HIDDEN`

Example:
```bash
$env:CRYPT_TOOLS_PASSWORD="build-secret"
$env:CRYPT_TOOLS_KDF="argon2"
$env:CRYPT_TOOLS_ITERATIONS="3"
uv run crypt_tools.py --encrypt -t "Secret Message"
```

Precedence order:
- Explicit CLI flags
- Environment variables
- Config file defaults
- Built-in defaults

### Inspect an Encrypted File
Inspect metadata stored in an encrypted file without prompting for a password.
```bash
uv run crypt_tools.py --inspect -f document.enc
```

### Encrypt a Directory (Recursive)
Encrypt all files in a folder recursively.
```bash
uv run crypt_tools.py --encrypt -f ./my_folder -r
```

### Decrypt a Directory (Recursive)
Decrypt all `.enc` files in a folder recursively.
```bash
uv run crypt_tools.py --decrypt -f ./my_folder -r
```

### Encrypt by Pattern (Wildcard)
```bash
# Encrypt all markdown files in the current directory
uv run crypt_tools.py --encrypt -f "*.md" -p "your_password"

# Encrypt files matching a prefix and any extension
uv run crypt_tools.py --encrypt -f "crypt*.*" -p "your_password"

# Recursive wildcard inside a directory
uv run crypt_tools.py --encrypt -r -f ".\\tests\\*.pyc" -p "your_password"
```

**Note (Windows/Powershell):** Quote wildcard patterns like `"*.md"` to avoid shell expansion.
**Recursive wildcard note:** With `-r`, patterns like `.\\tests\\*.pyc` are expanded recursively (equivalent to `.\\tests\\**\\*.pyc`).

### Interactive File Selection
Use the built-in terminal file picker to choose a file or directory interactively.
```bash
# Choose a file or directory from the current folder
uv run crypt_tools.py --encrypt --select -p "your_password"

# Start browsing from a specific directory
uv run crypt_tools.py --decrypt --select -f .\\documents -p "your_password"
```

`--select` requires an interactive terminal and cannot be combined with `--text`.

### Key File Support
Generate and use key files for two-factor encryption (password + key file):
```bash
# Generate a key file (uses default name: key.txt)
uv run crypt_tools.py --generate-keyfile

# Generate a key file with custom name
uv run crypt_tools.py --generate-keyfile mykey.txt

# Encrypt with key file only (no password)
uv run crypt_tools.py --encrypt -f document.txt --keyfile mykey.txt -p ""

# Encrypt with password AND key file (two-factor authentication)
uv run crypt_tools.py --encrypt -f document.txt -p "your_password" --keyfile mykey.txt

# Decrypt with key file
uv run crypt_tools.py --decrypt -f document.enc --keyfile mykey.txt -p "your_password"

# Encrypt text with key file
uv run crypt_tools.py --encrypt -t "Secret message" -p "password" --keyfile mykey.txt

# Encrypt with Argon2 (more secure, recommended)
uv run crypt_tools.py --encrypt -f document.txt -p "your_password" --kdf argon2

# Encrypt with Argon2 and custom iterations
uv run crypt_tools.py --encrypt -f document.txt -p "your_password" --kdf argon2 --iterations 5

# Decrypt file encrypted with Argon2 (auto-detected from file header)
uv run crypt_tools.py --decrypt -f document.enc -p "your_password"
```

### Recovery Key Support
Generate a recovery key during encryption, then use that recovery key later for emergency decryption.
```bash
# Encrypt and generate recovery_key.txt automatically
uv run crypt_tools.py --encrypt -f document.txt -p "your_password" --recovery-key

# Encrypt and write the recovery key to a custom path
uv run crypt_tools.py --encrypt -f document.txt -p "your_password" --recovery-key my_recovery.txt

# Decrypt with the recovery key file
uv run crypt_tools.py --decrypt -f document.enc --recovery-key recovery_key.txt

# If both are supplied, the CLI tries the recovery key first and falls back to the password
uv run crypt_tools.py --decrypt -f document.enc -p "your_password" --recovery-key recovery_key.txt
```

Notes:
- `--recovery-key` generates a MEGA-style URL-safe Base64 recovery key file during encryption.
- The encrypted file stores an encrypted recovery blob inside the `CT02` payload; the recovery key itself is not embedded in the file.
- `--inspect` reports whether recovery-key support is enabled for a file.
- `--recovery-key` cannot be combined with `--hidden-vol`.

### Threshold passwords

Threshold mode splits a file key into password-protected Shamir shares.

- Encrypt threshold files by repeating `-p` and supplying `--threshold`, for example `-p 1 -p 2 -p 3 --threshold 2`.
- Repeated passwords are allowed. If you encrypt with `-p 1 -p 1 -p 1 --threshold 2`, then decrypting with `-p 1 -p 1` is valid because those password attempts unlock two distinct stored shares.
- Encrypt mode rejects multiple `-p` values unless `--threshold` is present.
- Decrypt mode does not require `--threshold`; the CLI auto-detects threshold-encrypted files from the header.
- Duplicate password attempts only count if they unlock distinct shares. Reusing the same password against the same share twice does not satisfy the threshold.

### Hidden volumes (plausible deniability)

Create a single encrypted file that contains **two** independent AES-GCM payloads: an **outer/decoy** file (opened with the decoy password) and a **hidden** file (opened with the hidden password). On disk the layout is:

`[CT02_outer][CT02_hidden][CTHV][8-byte big-endian outer length]`

**Important:** This is **not** full-disk VeraCrypt semantics. The file is longer than a single-message ciphertext, and the `CTHV` footer is visible to anyone with the bytes. Deniability here means: under coercion, you can decrypt only the decoy with the decoy password; the real data needs the hidden password. It does **not** mean a forensic analyst cannot infer that a second blob may exist.

- **Encrypt:** `-f` points to the **decoy** file; `--hidden-file` points to the **secret** payload. Use `--hidden-vol`. You will be prompted for two passwords (or use `--password-outer` and `--password-hidden`; passing secrets on the command line is convenient but exposes them in shell history).
- **Decrypt decoy:** `-d -f <container> -p <decoy_password>` (default: decrypts only the outer blob when the file has a valid `CTHV` footer).
- **Decrypt hidden:** `-d --hidden -f <container> -p <hidden_password>` (or `--password-hidden` instead of `-p`).
- **Inspect:** `--inspect` reports `container: hidden`, outer/hidden blob sizes, and a short caveat when a footer is present.
- **Restrictions:** Hidden mode applies to **one decoy file** at a time—no `--recursive`, no wildcard batches for `--hidden-vol`. Text mode does not support hidden containers.

```bash
# Encrypt decoy.txt + secret.bin → decoy.txt.enc (prompts for two passwords if omitted)
uv run crypt_tools.py --encrypt -f decoy.txt --hidden-vol --hidden-file secret.bin

# Decrypt outer only
uv run crypt_tools.py --decrypt -f decoy.txt.enc -p "decoy_pw" -o out_decoy.txt

# Decrypt hidden only
uv run crypt_tools.py --decrypt --hidden -f decoy.txt.enc -p "hidden_pw" -o out_secret.bin
```

### CLI Arguments

| Argument | Short | Description |
|----------|-------|-------------|
| `--encrypt` | `-e` | Encrypt mode (default) |
| `--decrypt` | `-d` | Decrypt mode |
| `--inspect` | — | Inspect encrypted file metadata |
| `--generate-keyfile` | — | Generate a MEGA-style textual key file (default: `key.txt`) |
| `--text` | `-t` | Text to process |
| `--file` | `-f` | Input file path or wildcard pattern |
| `--output` | `-o` | Output file path |
| `--config` | — | Config file path for CLI defaults |
| `--select` | — | Browse and choose a file or directory interactively |
| `--password` | `-p` | Password (optional, will prompt if missing) |
| `--keyfile` | — | Key file path for encryption/decryption |
| `--recovery-key` | — | Generate/use recovery key file (default: `recovery_key.txt`) |
| `--compress` | `-c` | Enable compression |
| `--recursive` | `-r` | Recursively process directories |
| `--kdf` | — | Key derivation function: `pbkdf2` (default) or `argon2` |
| `--iterations` | — | Number of iterations for KDF (default: 100000 for PBKDF2, 3 for Argon2) |
| `--qr` | — | Render encrypted text output as a QR code (text encrypt mode only) |
| `--log` | — | Enable logging to file (`crypt_tools.log`) |
| `--debug` | — | Enable debug mode |
| `--version` | `-V` | Show version |
| `--help` | `-h` | Show help |
| `--hidden-vol` | — | Encrypt decoy (`-f`) + hidden (`--hidden-file`) into one container |
| `--hidden-file` | — | Path to hidden payload (requires `--hidden-vol`) |
| `--hidden` | — | With `-d -f`, decrypt inner volume (`-p` = hidden password) |
| `--password-outer` | — | Decoy password for `--hidden-vol` (optional) |
| `--password-hidden` | — | Hidden password; with `-d --hidden` can be used instead of `-p` |

**Wildcard tip (Windows/Powershell):** Use quotes like `"*.md"` to pass patterns without shell expansion.

### Password Security
- If no password is provided via `-p`, the tool will prompt securely using `getpass`
- When encrypting, password verification is required (must enter twice)
- Passwords are never stored or displayed
- Password prompts include a live strength indicator and character-class hints

### File Logging
- Use `--log` flag to enable logging to `crypt_tools.log`
- Or set `log_enabled: true` in config / `CRYPT_TOOLS_LOG_ENABLED=true` in the environment
- Log entries include timestamps, log level, emoji icons, and operation details
- Useful for audit trails and debugging
- Log file accumulates entries; manual cleanup may be required
- `--output` is only honored when processing a single file (patterns/multiple files ignore custom output)

### Recovery Keys
- `--recovery-key` creates a separate MEGA-style URL-safe Base64 recovery key file during encryption.
- Decryption can use the recovery key file without the original password.
- If both `-p/--password` and `--recovery-key` are supplied for decrypt, the CLI tries the recovery key first and falls back to password-based decryption.
- `--inspect` shows `Recovery key: enabled` when a file contains a recovery blob.
- `--recovery-key` cannot be used with `--hidden-vol`.

### Key File Format (--generate-keyfile)
- `--generate-keyfile` now creates a text recovery key, not a raw binary blob.
- The generated format is a URL-safe Base64 string similar to MEGA recovery keys.
- `--keyfile` accepts both the new textual recovery-key format and older binary key files for backward compatibility.
- If a session starts, the CLI now prints both Session started and Session ended, including failure paths.

### Format Compatibility
- New encrypted files use the versioned `CT02` format.
- `CT02` stores compression and PBKDF2 metadata in the file header.
- Legacy v2.1 files remain readable.
- Legacy compressed files may still require `--compress` during decryption because compression was not stored in the old format.

## Technical Details

### Version 2.9.0 Specifications
This tool improves upon older implementations by:
1.  **Key Size**: Utilizing a **32-byte (256-bit)** key derived from the password.
2.  **Salt**: Prepending a **16-byte random salt** to the encrypted data.
3.  **Nonce**: Using a **12-byte random nonce** (GCM standard).
4.  **Authentication**: Using AES-GCM provides a **16-byte Tag** to verify data integrity.
5.  **Chunk Size**: **64 KB** for streaming large files efficiently.
6.  **PBKDF2 Iterations**: **100,000** iterations for key derivation (default).
7.  **Argon2id Support**: Modern KDF with **3** iterations, **64 MB** memory, and **4** parallelism (configurable via `--iterations`).
8.  **Header Format**: New encrypted files include a fixed `CT02` header with flags, KDF ID, and KDF parameters.
9.  **Recovery-key support** (optional): files can include a recovery blob that stores the derived encryption key encrypted under a separate 32-byte recovery key.
10.  **Hidden-volume containers** (optional): Two `CT02` blobs back-to-back, then a `CTHV` magic (4 bytes) plus 64-bit big-endian outer blob length (8 bytes). Same KDF/compression/keyfile options apply to both inner encrypts when creating a container.
11.  **Secure file deletion** (`--shred`): Overwrites files with random data before deletion using DoD 5220.22-M standard (3 passes by default), configurable via `--passes`.

### File Formats

**Encrypted File Format (`CT02`)**:
```
[Magic "CT02" (4 bytes)] + [Version (1 byte)] + [Flags (1 byte)] + [KDF ID (1 byte)] + [Reserved (1 byte)] +
[Salt Length (1 byte)] + [Nonce Length (1 byte)] + [Tag Length (1 byte)] + [KDF Param Length (1 byte)] +
[KDF Params (4 bytes for PBKDF2 iterations)] + [Salt (16 bytes)] + [Nonce (12 bytes)] +
[Recovery Blob Length (2 bytes, optional)] + [Recovery Blob (optional)] +
[Encrypted Content (Chunks)] + [GCM Tag (16 bytes)]
```

**In-Memory Data Format (`CT02`)**:
```
[Header] + [Salt (16 bytes)] + [Nonce (12 bytes)] + [Recovery Blob Length (2 bytes, optional)] +
[Recovery Blob (optional)] + [Ciphertext] + [GCM Tag (16 bytes)]
```

**Recovery Blob Format (when recovery is enabled)**:
```
[Recovery Nonce (12 bytes)] + [Encrypted Derived Key (32 bytes)] + [Recovery Tag (16 bytes)]
```

**Legacy File Format (still readable)**:
```
[Salt (16 bytes)] + [Nonce (12 bytes)] + [Encrypted Content (Chunks)] + [GCM Tag (16 bytes)]
```

**Hidden-volume container (optional, file encryption only)**:
```
[CT02_outer] + [CT02_hidden] + [Magic "CTHV" (4 bytes)] + [uint64_be outer_total_len (8 bytes)]
```

> **Note**: Files encrypted with the old MD5-based 1.x tool are still **not compatible** with this version. You must decrypt them using the old tool before migrating.

## Code Structure

### Main Classes
| Class | Description |
|-------|-------------|
| `GaloisField` | GF(2^8) arithmetic for Shamir's Secret Sharing |
| `Config` | Stores constants like key size, salt, nonce, tag sizes, and PBKDF2 iterations |
| `ConfigParser` | Config file loading, CLI defaults, environment variable handling |
| `HeaderParser` | CT02 header building/parsing, format detection, hidden footer inspection |
| `KeyFileUtils` | Key file generation, reading, and password combination |
| `RecoveryKeyUtils` | Recovery key generation, file I/O, and wrapping/unwrapping the derived key |
| `UIHelpers` | Terminal UI helpers: QR codes, file selection, color output |
| `PasswordUtils` | Password prompting with strength indicators and verification |
| `PasswordStrength` | Password strength analysis and classification |
| `CryptoEngine` | Core of the application. Manages key derivation, encryption, and decryption |
| `Banner` | Displays random ASCII art banners on startup |
| `ConsoleLogger` | Unified console and file logging with emojis and colors |
| `TerminalColors` | ANSI color codes for terminal output |

### CryptoEngine Methods
| Method | Description |
|--------|-------------|
| `_derive_key(password, salt, kdf_type, iterations)` | Derives 256-bit key using PBKDF2-HMAC-SHA256 or Argon2id |
| `_format_size(size)` | Converts bytes to human-readable format |
| `encrypt_data(data, password)` | Encrypts bytes in memory |
| `decrypt_data(enc_data, password)` | Decrypts bytes in memory |
| `encrypt_file(input_path, output_path, password, compress)` | Encrypts file using streaming |
| `decrypt_file(..., slice_start=0, slice_end=None)` | Decrypts file using streaming; optional byte range for blobs inside a larger file |
| `encrypt_hidden_container(...)` | Builds `[CT02_outer][CT02_hidden][CTHV][length]` |
| `decrypt_hidden_container(..., hidden=False)` | Decrypts outer or inner blob after footer validation |
| `inspect_file(input_path)` | Reads encrypted file metadata without decrypting (includes hidden-container fields when applicable) |

## Error Handling
- **Integrity Check**: Failed decryption indicates wrong password or corrupted file
- **File Operations**: Partial output files are removed on failure
- **Memory Efficiency**: Large files are processed in chunks to minimize memory usage
- **Logging**: All operations logged to `crypt_tools.log` when `--log` flag is enabled

## Testing
The project includes a comprehensive test suite covering CLI arguments, encryption logic, and error handling.

Run tests using:
```bash
uv run pytest
```

## Building Executable

You can compile `crypt_tools.py` into a standalone executable file (.exe) using **PyInstaller**. This allows you to run the tool on systems without Python installed.

### Using `uv` (Recommended)
If you are using `uv`, you can run PyInstaller in a temporary environment with all required dependencies:

```bash
uvx --with pycryptodome --with tqdm --with qrcode --with blessed pyinstaller --onefile --icon=favicon.ico --version-file=version_info.txt crypt_tools.py
```

### Using `pipx`
If you prefer `pipx`, you need to install PyInstaller and then inject the extra dependencies into its environment:

```bash
# 1. Install PyInstaller
pipx install pyinstaller

# 2. Inject dependencies
pipx inject pyinstaller pycryptodome tqdm

# 3. Create the executable
pyinstaller --onefile --icon=favicon.ico --version-file=version_info.txt crypt_tools.py
```

### Global Installation
If you prefer to have `pyinstaller` available globally on your system, you can install it using `uv` or `pip`:

```bash
# Using uv
uv tool install pyinstaller --with pycryptodome --with tqdm

# Using pip
pip install -g pyinstaller pycryptodome tqdm
```

Once installed globally, you can generate the EXE directly:
```bash
pyinstaller --onefile --icon=favicon.ico --version-file=version_info.txt crypt_tools.py
```

---

## Version History

### 2.9.0
- Added secure file deletion (`--shred`) implementing DoD 5220.22-M standard (3 passes by default), configurable via `--passes`.
- Progress bars for each overwrite pass, session timestamps, file info (name + size), and total time display.
- Cross-platform secure deletion with proper fsync.

### 2.8.0
- Added new "Key File Format (--generate-keyfile)" section documenting the text-based key file format.
- `--generate-keyfile` now creates a URL-safe Base64 text recovery key (not raw binary).
- `--keyfile` accepts both new textual format and older binary key files for backward compatibility.
- Added `--recovery-key` support: generate a recovery key during encryption and use it later to decrypt without the original password.
- CLI now prints both "Session started" and "Session ended" messages, including failure paths.

### 2.7.0
- Initial release with AES-256-GCM encryption, PBKDF2/Argon2id key derivation, hidden volumes, and recovery key support.

---

**Author**: Center For Cyber Intelligence  
**Version**: 2.9.0
