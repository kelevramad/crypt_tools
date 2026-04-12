# Crypt Tools (Node.js Edition)

## Overview
`crypt_tools.js` is a robust command-line tool for encrypting and decrypting files and text using the AES (Advanced Encryption Standard) algorithm. This Node.js version features enhanced security using **PBKDF2** (Password-Based Key Derivation Function 2) with HMAC-SHA256 for key derivation and a random 16-byte salt, making it significantly more secure against brute-force and dictionary attacks. It also supports optional zlib compression, a versioned `CT02` file format, and encrypted-file inspection via CLI.

## Key Features
- **AES-256 Encryption**: Uses AES in **GCM (Galois/Counter Mode)** for authenticated encryption, ensuring both confidentiality and integrity.
- **Dual Key Derivation**: Supports **PBKDF2-HMAC-SHA256** (default, 100k iterations) and **Argon2id** (more secure, 3 iterations, 64MB memory).
- **Streamed Processing**: Processes files in 64KB chunks, allowing encryption of large files with minimal memory usage.
- **Data Compression**: Optional Zlib compression to reduce file size before encryption.
- **CLI Interface**: Easy-to-use command line interface for quick operations.
- **Visual Feedback**: Colorful terminal output with emojis, color-coded status messages, and ASCII art banners.
- **tqdm-style Progress Bar**: Dynamic progress with sizes, ETA, and throughput in a single line.
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
- **Hidden volumes (containers)**: Optional two-password file container—decoy content with the outer password, sensitive content with the hidden password; two `CT02` blobs plus a `CTHV` footer (see limitations in [README.md](README.md) hidden-volume section).
- **Recovery Key Support**: Optionally generate a separate recovery key file during encryption and use it later to decrypt without the original password.

## Installation

### Prerequisites
- Node.js 18.0+
- npm or yarn
- Packages: `blessed`, `qrcode-terminal`

### Setup
Clone the repository and install dependencies:
```bash
git clone https://github.com/kelevramad/crypt_tools.git
cd crypt_tools
npm install
```

## Usage

### Encrypt a String
Encrypt a plain text string directly from the terminal.
```bash
node crypt_tools.js --encrypt -t "Secret Message" -p "your_password"
```

### Decrypt a String
Decrypt a base64 encoded string.
```bash
node crypt_tools.js --decrypt -t "encrypted_base64_string" -p "your_password"
```

### Encrypt a String as QR Code
Render the encrypted Base64 payload as a terminal QR code for scanning on another device.
```bash
node crypt_tools.js --encrypt -t "secret" -p "your_password" --qr
```

### Encrypt a File
Encrypt a file (e.g., `document.txt`) to an encrypted output (default `.enc`).
```bash
# Basic encryption (Password Prompt + Verification)
node crypt_tools.js --encrypt -f document.txt

# Non-interactive (password provided)
node crypt_tools.js --encrypt -f document.txt -p "your_password"

# With compression
node crypt_tools.js --encrypt -f document.txt -p "your_password" -c
```

### Decrypt a File
Decrypt an encrypted file (e.g., `document.enc`) back to its original form.
```bash
# Basic decryption
node crypt_tools.js --decrypt -f document.enc -p "your_password"

# Legacy files encrypted with compression may still require -c
node crypt_tools.js --decrypt -f document.enc -p "your_password" -c
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
node crypt_tools.js --encrypt -f document.txt

# Use an explicit config file
node crypt_tools.js --config .\team-defaults.json --encrypt -f document.txt
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
node crypt_tools.js --encrypt -t "Secret Message"
```

Precedence order:
- Explicit CLI flags
- Environment variables
- Config file defaults
- Built-in defaults

### Inspect an Encrypted File
Inspect metadata stored in an encrypted file without prompting for a password.
```bash
node crypt_tools.js --inspect -f document.enc
```

### Encrypt a Directory (Recursive)
Encrypt all files in a folder recursively.
```bash
node crypt_tools.js --encrypt -f ./my_folder -r -p "your_password"
```

### Decrypt a Directory (Recursive)
Decrypt all `.enc` files in a folder recursively.
```bash
node crypt_tools.js --decrypt -f ./my_folder -r -p "your_password"
```

### Encrypt by Pattern (Wildcard)
```bash
# Encrypt all markdown files in the current directory
node crypt_tools.js --encrypt -f "*.md" -p "your_password"

# Encrypt files matching a prefix and any extension
node crypt_tools.js --encrypt -f "crypt*.*" -p "your_password"

# Recursive wildcard inside a directory
node crypt_tools.js --encrypt -r -f ".\\tests\\*.pyc" -p "your_password"
```

**Note (Windows/Powershell):** Quote wildcard patterns like `"*.md"` to avoid shell expansion.
**Recursive wildcard note:** With `-r`, patterns like `.\\tests\\*.pyc` are expanded recursively (equivalent to `.\\tests\\**\\*.pyc`).

### Interactive File Selection
Use the built-in terminal file picker to choose a file or directory interactively.
```bash
# Choose a file or directory from the current folder
node crypt_tools.js --encrypt --select -p "your_password"

# Start browsing from a specific directory
node crypt_tools.js --decrypt --select -f .\\documents -p "your_password"
```

`--select` requires an interactive terminal and cannot be combined with `--text`.

### Key File Support
Generate and use key files for two-factor encryption (password + key file):
```bash
# Generate a key file (uses default name: key.txt)
node crypt_tools.js --generate-keyfile

# Generate a key file with custom name
node crypt_tools.js --generate-keyfile mykey.txt

# Encrypt with key file only (no password)
node crypt_tools.js --encrypt -f document.txt --keyfile mykey.txt -p ""

# Encrypt with password AND key file (two-factor authentication)
node crypt_tools.js --encrypt -f document.txt -p "your_password" --keyfile mykey.txt

# Decrypt with key file
node crypt_tools.js --decrypt -f document.enc --keyfile mykey.txt -p "your_password"

# Encrypt text with key file
node crypt_tools.js --encrypt -t "Secret message" -p "password" --keyfile mykey.txt

# Encrypt with Argon2 (more secure, recommended)
node crypt_tools.js --encrypt -f document.txt -p "your_password" --kdf argon2

# Encrypt with Argon2 and custom iterations
node crypt_tools.js --encrypt -f document.txt -p "your_password" --kdf argon2 --iterations 5

# Decrypt file encrypted with Argon2 (auto-detected from file header)
node crypt_tools.js --decrypt -f document.enc -p "your_password"
```

### Recovery Key Support
Generate a recovery key during encryption, then use that recovery key later for emergency decryption.
```bash
# Encrypt and generate recovery_key.txt automatically
node crypt_tools.js --encrypt -f document.txt -p "your_password" --recovery-key

# Encrypt and write the recovery key to a custom path
node crypt_tools.js --encrypt -f document.txt -p "your_password" --recovery-key my_recovery.txt

# Decrypt with the recovery key file
node crypt_tools.js --decrypt -f document.enc --recovery-key recovery_key.txt

# If both are supplied, the CLI tries the recovery key first and falls back to the password
node crypt_tools.js --decrypt -f document.enc -p "your_password" --recovery-key recovery_key.txt
```

Notes:
- `--recovery-key` generates a MEGA-style URL-safe Base64 recovery key file during encryption.
- The encrypted file stores an encrypted recovery blob inside the `CT02` payload; the recovery key itself is not embedded in the file.
- `--inspect` reports whether recovery-key support is enabled for a file.
- `--recovery-key` cannot be combined with `--hidden-vol`.

### Threshold passwords

Threshold mode stores one Shamir share per `-p` value and requires `--threshold` during encryption.

- Encrypt with repeated `-p` plus `--threshold`, for example `node crypt_tools.js -f README.md -p 1 -p 2 -p 3 --threshold 2`.
- Repeated passwords are valid. If multiple shares were encrypted with the same password, decrypting with that same repeated password works as long as each attempt unlocks a distinct stored share.
- Encrypt mode rejects multiple `-p` values without `--threshold`.
- Decrypt mode auto-detects threshold files from the header, so `--threshold` is optional there.
- Duplicate password attempts do not count twice unless they recover different share IDs.

### Hidden volumes (plausible deniability)

Behavior matches the Python CLI: outer and hidden payloads are separate `CT02` messages; the file ends with `CTHV` plus the outer blob length. This is a **file** feature, not full-disk VeraCrypt; the footer and file length are visible. Use `--hidden-vol` with `-f` (decoy) and `--hidden-file` (secret). Decrypt outer with `-d -p`; decrypt hidden with `-d --hidden -p`. No `--recursive`/wildcards for `--hidden-vol`. See [README.md](README.md) for the full format diagram and caveats.

```bash
node crypt_tools.js --encrypt -f decoy.txt --hidden-vol --hidden-file secret.bin --password-outer "decoy_pw" --password-hidden "real_pw"
node crypt_tools.js --decrypt -f decoy.txt.enc -p "decoy_pw" -o out_decoy.txt
node crypt_tools.js --decrypt --hidden -f decoy.txt.enc -p "real_pw" -o out_secret.bin
node crypt_tools.js --inspect -f decoy.txt.enc
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
- If no password is provided via `-p`, the tool will prompt securely (password input is hidden)
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

### Version 2.7.0 Specifications
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
10.  **Hidden-volume containers** (optional): Two `CT02` blobs, then `CTHV` + 64-bit big-endian outer length; same options apply to both layers when creating a container.

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
| `GaloisField` | GF(2^8) arithmetic for Shamir's Secret Sharing (Python edition only; Node.js uses inline static methods) |
| `Config` | Stores constants like key size, salt, nonce, tag sizes, and PBKDF2 iterations |
| `RecoveryKeyUtils` | Recovery key generation, file I/O, and wrapping/unwrapping the derived key |
| `CryptoEngine` | Core of the application. Manages key derivation, encryption, and decryption |
| `Banner` | Displays random ASCII art banners on startup |
| `ConsoleLogger` | Unified console and file logging with emojis and colors |
| `TerminalColors` | ANSI color codes for terminal output |

**Note:** The Python edition has been refactored into utility classes (`ConfigParser`, `HeaderParser`, `KeyFileUtils`, `UIHelpers`, `PasswordUtils`) for better organization. The Node.js edition retains its current structure but will be refactored in a future update.

### CryptoEngine Methods
| Method | Description |
|--------|-------------|
| `_deriveKey(password, salt, kdfType, iterations)` | Derives 256-bit key using PBKDF2-HMAC-SHA256 or Argon2id |
| `_formatSize(size)` | Converts bytes to human-readable format |
| `encryptData(data, password)` | Encrypts bytes in memory |
| `decryptData(encData, password)` | Decrypts bytes in memory |
| `encryptFile(inputPath, outputPath, password, compress)` | Encrypts file using streaming |
| `decryptFile(..., sliceStart, sliceEnd)` | Decrypts a blob; optional byte range for containers |
| `encryptHiddenContainer(...)` | Builds `[CT02_outer][CT02_hidden][CTHV][length]` |
| `decryptHiddenContainer(..., { hidden })` | Decrypts outer or inner after footer validation |
| `inspectFile(inputPath)` | Metadata without decrypting (hidden-container fields when applicable) |

## Error Handling
- **Integrity Check**: Failed decryption indicates wrong password or corrupted file
- **File Operations**: Partial output files are removed on failure
- **Memory Efficiency**: Large files are processed in chunks to minimize memory usage
- **Logging**: All operations logged to `crypt_tools.log` when `--log` flag is enabled

## Testing
Run tests using:
```bash
npm test
```

## Building Executable

You can compile `crypt_tools.js` into a standalone executable file using **pkg** or **ncc**.

### Using pkg
```bash
# Install pkg globally
npm install -g pkg

# Create executable for current platform
pkg crypt_tools.js

# Create executables for multiple platforms
pkg crypt_tools.js --targets node18-win,node18-linux,node18-macos
```

### Using ncc (Node.js Compile)
```bash
# Install ncc
npm install -g @vercel/ncc

# Compile to a single file
ncc build crypt_tools.js -o dist
```

---

**Author**: Center For Cyber Intelligence
**Version**: 2.7.0
