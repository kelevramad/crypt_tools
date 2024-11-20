# Cryptographic Tool Documentation

## Overview
This is a Python-based cryptographic tool that provides file and text encryption/decryption capabilities using AES encryption in CFB mode. The tool supports file compression, password-based encryption, and includes a command-line interface.

## Core Classes

### Arguments
Handles command-line argument parsing with the following options:
- `-m/--mode`: Select between 'crypt' or 'decrypt' modes [default: crypt]
- `-t/--text`: Plain-text input for encryption/decryption
- `-i/--input`: Input file(s) for encryption/decryption
- `-o/--output`: Output file for the result
- `-p/--password`: Password for encryption/decryption (required)
- `-c/--compress`: Enable compression before encryption/decompression after decryption
- `-d/--debug`: Enable debugging information
- `-v/--version`: Display version information

### Colors
Provides ANSI color codes for terminal output formatting:
- Supports text styles (bold, underline, strikethrough)
- Foreground colors (black, red, green, etc.)
- Background colors (black, red, green, etc.)

### Banner
Manages the application's ASCII art banners:
- Contains multiple banner designs
- Randomly selects one banner for display
- Supports different ASCII art styles

### Message
Handles formatted message output with different severity levels:
- `LIVE`: Success messages (green)
- `DEAD`: Failure messages (red)
- `DEBUG`: Debug information (yellow)
- `ERROR`: Error messages (yellow)
- `WARNING`: Warning messages (pink)
- `INFO`: Information messages (blue)

### Crypt
Core encryption/decryption functionality:

#### Key Methods:
1. `trans(key)`:
   - Converts password into MD5 hash digest for encryption key

2. `humansize(nbytes)`:
   - Converts byte sizes to human-readable format (KB, MB, GB, etc.)

3. `encryption(plain_text, password)`:
   - Encrypts data using AES-CFB mode
   - Generates random IV (Initialization Vector)
   - Returns base64 encoded encrypted data

4. `decryption(encrypted, password)`:
   - Decodes base64 encrypted data
   - Extracts IV and decrypts using AES-CFB
   - Returns original plaintext

5. `compress(content)` / `decompress(content)`:
   - Handles zlib compression/decompression
   - Compression level 9 (maximum)

6. `encrypt_file(file_input, file_output, password, compress)`:
   - Loads file content
   - Optionally compresses
   - Encrypts content
   - Writes to output file

7. `decrypt_file(file_input, file_output, password, compress)`:
   - Loads encrypted file
   - Decrypts content
   - Optionally decompresses
   - Writes to output file

## Security Features
- Uses AES encryption in CFB (Cipher Feedback) mode
- 16-byte block size
- Random IV generation for each encryption
- Password hashing using MD5
- Base64 encoding for encrypted output
- Optional compression using zlib

## Usage Examples

### Text Encryption
```bash
python crypt_tools.py -m crypt -t "secret text" -p mypassword
```

### File Encryption
```bash
python crypt_tools.py -m crypt -i file.txt -o encrypted.enc -p mypassword
```

### File Encryption with Compression
```bash
python crypt_tools.py -m crypt -i file.txt -o encrypted.enc -p mypassword -c
```

### Text Decryption
```bash
python crypt_tools.py -m decrypt -t "encrypted_text" -p mypassword
```

### File Decryption
```bash
python crypt_tools.py -m decrypt -i encrypted.enc -o decrypted.txt -p mypassword
```

## Performance Features
- Progress animation during operations
- Execution time tracking
- File size reporting
- Memory-efficient file handling

## Error Handling
- Comprehensive exception handling for encryption/decryption operations
- Detailed error messages with line numbers and exception details
- Debug mode for additional information
- Validation of input parameters

## Platform Support
- Cross-platform compatibility (Windows/Linux)
- Terminal clearing based on platform
- ANSI color support for terminal output

## Notes
- Default encryption mode if not specified
- Supports batch file processing
- Automatic output file naming (.enc/.dec extensions)
- Command-line help documentation