
# Crypt Tools

## Overview
`crypt_tools.py` is a robust command-line tool for encrypting and decrypting files and text using the AES (Advanced Encryption Standard) algorithm. This updated version features enhanced security using **PBKDF2** (Password-Based Key Derivation Function 2) with HMAC-SHA256 for key derivation and a random 16-byte salt, making it significantly more secure against brute-force and dictionary attacks than previous versions. It also supports optional zlib compression.

## Key Features
- **AES-256 Encryption**: Uses AES in **GCM (Galois/Counter Mode)** for authenticated encryption, ensuring both confidentiality and integrity.
- **Robust Key Derivation**: Implements **PBKDF2-HMAC-SHA256** with 100,000 iterations and a random salt, ensuring strong key protection.
- **Streamed Processing**: Processes files in 64KB chunks, allowing encryption of large files with minimal memory usage.
- **Data Compression**: Optional Zlib compression to reduce file size before encryption.
- **CLI Interface**: Easy-to-use command line interface for quick operations.
- **Visual Feedback**: Colorful terminal output and clear status messages.
- **Secure Defaults**: Automatically handles Nonce generation and Salt management.

## Installation

### Prerequisites
- Python 3.13+
- Dependencies (managed via `uv` or `pip`):
  - `pycryptodome`
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
uv run crypt_tools.py --encrypt -i document.txt

# Non-interactive (password provided)
uv run crypt_tools.py --encrypt -i document.txt -p "your_password"

# With compression
uv run crypt_tools.py --encrypt -i document.txt -p "your_password" -c
```

### Decrypt a File
Decrypt an encrypted file (e.g., `document.enc`) back to its original form.
```bash
# Basic decryption
uv run crypt_tools.py --decrypt -i document.enc -p "your_password"

# With decompression
uv run crypt_tools.py --decrypt -i document.enc -p "your_password" -c

### Encrypt a Directory (Recursive)
Encrypt all files in a folder recursively.
```bash
uv run crypt_tools.py --encrypt -i ./my_folder -r
```
```

## Technical Details
This tool improves upon older implementations by:
1.  **Key Size**: Utilizing a **32-byte (256-bit)** key derived from the password.
2.  **Salt**: Prepending a **16-byte random salt** to the encrypted data.
3.  **Authentication**: Using AES-GCM provides a **16-byte Tag** to verify data integrity.
4.  **Structure**:
    - **Encrypted File Format**: `[Salt (16 bytes)] + [Nonce (12 bytes)] + [Encrypted Content] + [Tag (16 bytes)]`

> **Note**: Files encrypted with the old version (MD5-based) are **not compatible** with this version. You must decrypt them using the old tool before migrating.

## Testing
The project includes a comprehensive test suite covering CLI arguments, encryption logic, and error handling.

Run tests using:
```bash
uv run pytest
```
