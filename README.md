# Crypt Tools

## Overview
`crypt_tools.py` is a robust command-line tool for encrypting and decrypting files and text using the AES (Advanced Encryption Standard) algorithm. This updated version features enhanced security using **PBKDF2** (Password-Based Key Derivation Function 2) with HMAC-SHA256 for key derivation and a random 16-byte salt, making it significantly more secure against brute-force and dictionary attacks than previous versions. It also supports optional zlib compression, a versioned `CT02` file format, and encrypted-file inspection via CLI.

## Key Features
- **AES-256 Encryption**: Uses AES in **GCM (Galois/Counter Mode)** for authenticated encryption, ensuring both confidentiality and integrity.
- **Robust Key Derivation**: Implements **PBKDF2-HMAC-SHA256** with 100,000 iterations and a random salt, ensuring strong key protection.
- **Streamed Processing**: Processes files in 64KB chunks, allowing encryption of large files with minimal memory usage.
- **Data Compression**: Optional Zlib compression to reduce file size before encryption.
- **CLI Interface**: Easy-to-use command line interface for quick operations.
- **Visual Feedback**: Colorful terminal output with emojis, color-coded status messages, and ASCII art banners.
- **File Logging**: Optional timestamped log file (`crypt_tools.log`) for audit trails.
- **Secure Defaults**: Automatically handles Nonce generation and Salt management.
- **File Pattern Expansion**: Encrypt/decrypt groups of files via wildcards (e.g., `*.md`, `crypt*.*`).
- **Password Strength Indicator**: Live strength and character-class feedback during input.
- **Versioned File Format (`CT02`)**: New encrypted files include embedded metadata such as format version, compression flag, and KDF parameters.
- **Inspect Mode**: View encrypted file metadata without decrypting it.
- **Key File Support**: Generate and use key files for two-factor encryption (password + key file).

## Installation

### Prerequisites
- Python 3.13+
- Dependencies (managed via `uv` or `pip`):
  - `pycryptodome`
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

### Key File Support
Generate and use key files for two-factor encryption (password + key file):
```bash
# Generate a random 32-byte key file
uv run crypt_tools.py --generate-keyfile mykey.bin

# Encrypt with key file only (no password)
uv run crypt_tools.py --encrypt -f document.txt --keyfile mykey.bin -p ""

# Encrypt with password AND key file (two-factor authentication)
uv run crypt_tools.py --encrypt -f document.txt -p "your_password" --keyfile mykey.bin

# Decrypt with key file
uv run crypt_tools.py --decrypt -f document.enc --keyfile mykey.bin -p "your_password"

# Encrypt text with key file
uv run crypt_tools.py --encrypt -t "Secret message" -p "password" --keyfile mykey.bin
```

### CLI Arguments

| Argument | Short | Description |
|----------|-------|-------------|
| `--encrypt` | `-e` | Encrypt mode (default) |
| `--decrypt` | `-d` | Decrypt mode |
| `--inspect` | — | Inspect encrypted file metadata |
| `--generate-keyfile` | — | Generate a random key file (32 bytes) |
| `--text` | `-t` | Text to process |
| `--file` | `-f` | Input file path or wildcard pattern |
| `--output` | `-o` | Output file path |
| `--password` | `-p` | Password (optional, will prompt if missing) |
| `--keyfile` | — | Key file path for encryption/decryption |
| `--compress` | `-c` | Enable compression |
| `--recursive` | `-r` | Recursively process directories |
| `--log` | — | Enable logging to file (`crypt_tools.log`) |
| `--debug` | — | Enable debug mode |
| `--version` | `-V` | Show version |
| `--help` | `-h` | Show help |

**Wildcard tip (Windows/Powershell):** Use quotes like `"*.md"` to pass patterns without shell expansion.

### Password Security
- If no password is provided via `-p`, the tool will prompt securely using `getpass`
- When encrypting, password verification is required (must enter twice)
- Passwords are never stored or displayed
- Password prompts include a live strength indicator and character-class hints

### File Logging
- Use `--log` flag to enable logging to `crypt_tools.log`
- Log entries include timestamps, log level, emoji icons, and operation details
- Useful for audit trails and debugging
- Log file accumulates entries; manual cleanup may be required
- `--output` is only honored when processing a single file (patterns/multiple files ignore custom output)

### Format Compatibility
- New encrypted files use the versioned `CT02` format.
- `CT02` stores compression and PBKDF2 metadata in the file header.
- Legacy v2.1 files remain readable.
- Legacy compressed files may still require `--compress` during decryption because compression was not stored in the old format.

## Technical Details

### Version 2.2.0 Specifications
This tool improves upon older implementations by:
1.  **Key Size**: Utilizing a **32-byte (256-bit)** key derived from the password.
2.  **Salt**: Prepending a **16-byte random salt** to the encrypted data.
3.  **Nonce**: Using a **12-byte random nonce** (GCM standard).
4.  **Authentication**: Using AES-GCM provides a **16-byte Tag** to verify data integrity.
5.  **Chunk Size**: **64 KB** for streaming large files efficiently.
6.  **PBKDF2 Iterations**: **100,000** iterations for key derivation.
7.  **Header Format**: New encrypted files include a fixed `CT02` header with flags and KDF parameters.

### File Formats

**Encrypted File Format (`CT02`)**:
```
[Magic "CT02" (4 bytes)] + [Version (1 byte)] + [Flags (1 byte)] + [KDF ID (1 byte)] + [Reserved (1 byte)] +
[Salt Length (1 byte)] + [Nonce Length (1 byte)] + [Tag Length (1 byte)] + [KDF Param Length (1 byte)] +
[KDF Params (4 bytes for PBKDF2 iterations)] + [Salt (16 bytes)] + [Nonce (12 bytes)] +
[Encrypted Content (Chunks)] + [GCM Tag (16 bytes)]
```

**In-Memory Data Format (`CT02`)**:
```
[Header] + [Salt (16 bytes)] + [Nonce (12 bytes)] + [Ciphertext] + [GCM Tag (16 bytes)]
```

**Legacy File Format (still readable)**:
```
[Salt (16 bytes)] + [Nonce (12 bytes)] + [Encrypted Content (Chunks)] + [GCM Tag (16 bytes)]
```

> **Note**: Files encrypted with the old MD5-based 1.x tool are still **not compatible** with this version. You must decrypt them using the old tool before migrating.

## Code Structure

### Main Classes
| Class | Description |
|-------|-------------|
| `Config` | Stores constants like key size, salt, nonce, tag sizes, and PBKDF2 iterations |
| `CryptoEngine` | Core of the application. Manages key derivation, encryption, and decryption |
| `Banner` | Displays random ASCII art banners on startup |
| `ConsoleLogger` | Unified console and file logging with emojis and colors |
| `TerminalColors` | ANSI color codes for terminal output |

### CryptoEngine Methods
| Method | Description |
|--------|-------------|
| `_derive_key(password, salt)` | Derives 256-bit key using PBKDF2-HMAC-SHA256 |
| `_format_size(size)` | Converts bytes to human-readable format |
| `encrypt_data(data, password)` | Encrypts bytes in memory |
| `decrypt_data(enc_data, password)` | Decrypts bytes in memory |
| `encrypt_file(input_path, output_path, password, compress)` | Encrypts file using streaming |
| `decrypt_file(input_path, output_path, password, compress)` | Decrypts file using streaming |
| `inspect_file(input_path)` | Reads encrypted file metadata without decrypting |

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
uvx --with pycryptodome --with tqdm pyinstaller --onefile --icon=favicon.ico --version-file=version_info.txt crypt_tools.py
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

**Author**: Center For Cyber Intelligence  
**Version**: 2.2.0
