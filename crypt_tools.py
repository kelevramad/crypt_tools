#!/usr/bin/env python3
"""
Cryptographic Tool for File and Text Encryption/Decryption.
Refactored version with AES-GCM and Streaming I/O.
"""

import argparse
import base64
import hashlib
import os
import random
import sys
import time
import zlib
import getpass
import io
from enum import StrEnum
from typing import Optional

# Third-party imports
try:
    from tqdm import tqdm
    from Crypto.Cipher import AES
except ImportError:
    print("Error: Missing dependencies. Please install 'pycryptodome' and 'tqdm'.")
    sys.exit(1)

# Reconfigure stdout/stderr to use UTF-8 encoding (supports emojis)
def ensure_utf8(stream):
    if stream.encoding != 'utf-8':
        return io.TextIOWrapper(stream.buffer, encoding='utf-8', errors='replace')
    return stream

sys.stdout = ensure_utf8(sys.stdout)
sys.stderr = ensure_utf8(sys.stderr)

# =========================
# Configuration
# =========================

class Config:
    """Configuration constants."""
    AUTHOR = 'Center For Cyber Intelligence'
    DESCRIPTION = 'Crypt Tools (AES-GCM Edition)'
    VERSION = "2.1.0"
    
    # AES-GCM Constants
    KEY_SIZE = 32           # 256 bits
    SALT_SIZE = 16          # 128 bits
    NONCE_SIZE = 12         # 96 bits (Standard for GCM)
    TAG_SIZE = 16           # 128 bits (Standard for GCM)
    
    # Streaming
    CHUNK_SIZE = 64 * 1024  # 64KB chunks
    PBKDF2_ITERATIONS = 100000

# =========================
# Logging & UI
# =========================

class TerminalColors:
    RESET = '\033[0m'
    
    class Foreground(StrEnum):
        GREEN = '\033[92m'
        RED = '\033[91m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        CYAN = '\033[96m'
        MAGENTA = '\033[95m'
        WHITE = '\033[97m'

class ConsoleLogger:
    """
    Unified console and file logging with emojis and colors.
    All output goes through a single 'show' method.
    """
    DEBUG_ENABLED = False
    LOG_ENABLED = False
    LOG_FILE = "crypt_tools.log"

    # Output style definitions: icon + color for each level
    STYLES = {
        'info': {'icon': 'ℹ️', 'color': TerminalColors.Foreground.BLUE},
        'success': {'icon': '✅', 'color': TerminalColors.Foreground.GREEN},
        'error': {'icon': '❌', 'color': TerminalColors.Foreground.RED},
        'warning': {'icon': '⚠️', 'color': TerminalColors.Foreground.YELLOW},
        'debug': {'icon': '🐞', 'color': TerminalColors.Foreground.MAGENTA},
    }

    @staticmethod
    def show(level: str, message: str, icon: str = None, show_console: bool = True, log_file: bool = True) -> None:
        """
        Unified output method - writes to console and/or log file with emoji and colors.

        Args:
            level: Output level ('info', 'success', 'error', 'warning', 'debug')
            message: Message to display/log
            icon: Optional custom emoji (overrides default for level)
            show_console: If True, display on console with emoji and colors
            log_file: If True and logging enabled, write to log file with emoji (default: True)
        """
        # Skip debug if not enabled
        if level == 'debug' and not ConsoleLogger.DEBUG_ENABLED:
            return

        # Get style for this level
        style = ConsoleLogger.STYLES.get(level, ConsoleLogger.STYLES['info'])
        # Use custom icon if provided, otherwise use default from style
        used_icon = icon if icon is not None else style['icon']
        color = style['color']

        # Write to log file if enabled (with emoji)
        if log_file and ConsoleLogger.LOG_ENABLED:
            ConsoleLogger._write_to_file(level, used_icon, message)

        # Print to console if enabled (with emoji and colors)
        if show_console:
            ConsoleLogger._print_to_console(used_icon, message, color)

    @staticmethod
    def _print_to_console(icon: str, message: str, color: TerminalColors.Foreground) -> None:
        """Print formatted message to console with emoji and colors."""
        white = TerminalColors.Foreground.WHITE
        reset = TerminalColors.RESET
        print(f"{white}[{reset}{icon}{white}]{reset} {color}{message}{reset}")

    @staticmethod
    def _write_to_file(level: str, icon: str, message: str) -> None:
        """Write timestamped log entry to file with level and emoji."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level.upper()}] [{icon}] {message}\n"
        with open(ConsoleLogger.LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_entry)

class Banner:
    """
    Provides ASCII art banners for program display.
    Randomly selects one banner from available options.
    """
    __BANNER = [
        r"""
      /$$$$$$                                  /$$           /$$$$$$$$                  /$$
     /$$__  $$                                | $$          |__  $$__/                 | $$
    | $$  \__/  /$$$$$$  /$$   /$$  /$$$$$$  /$$$$$$           | $$  /$$$$$$   /$$$$$$ | $$  /$$$$$$$
    | $$       /$$__  $$| $$  | $$ /$$__  $$|_  $$_/           | $$ /$$__  $$ /$$__  $$| $$ /$$_____/
    | $$      | $$  \__/| $$  | $$| $$  \ $$  | $$             | $$| $$  \ $$| $$  \ $$| $$|  $$$$$$
    | $$    $$| $$      | $$  | $$| $$  | $$  | $$ /$$         | $$| $$  | $$| $$  | $$| $$ \____  $$
    |  $$$$$$/| $$      |  $$$$$$$| $$$$$$$/  |  $$$$/         | $$|  $$$$$$/|  $$$$$$/| $$ /$$$$$$$/
     \______/ |__/       \____  $$| $$____/    \___/           |__/ \______/  \______/ |__/|_______/
                         /$$  | $$| $$
                        |  $$$$$$/| $$
                         \______/ |__/
    """,
        r"""
      ÛÛÛÛÛÛÛÛÛ                                  ÛÛÛÛÛ       ÛÛÛÛÛÛÛÛÛÛÛ                   ÛÛÛÛ
      ÛÛÛ°°°°°ÛÛÛ                                °°ÛÛÛ       °Û°°°ÛÛÛ°°°Û                  °°ÛÛÛ
     ÛÛÛ     °°°  ÛÛÛÛÛÛÛÛ  ÛÛÛÛÛ ÛÛÛÛ ÛÛÛÛÛÛÛÛ  ÛÛÛÛÛÛÛ     °   °ÛÛÛ  °   ÛÛÛÛÛÛ   ÛÛÛÛÛÛ  °ÛÛÛ   ÛÛÛÛÛ
    °ÛÛÛ         °°ÛÛÛ°°ÛÛÛ°°ÛÛÛ °ÛÛÛ °°ÛÛÛ°°ÛÛÛ°°°ÛÛÛ°          °ÛÛÛ     ÛÛÛ°°ÛÛÛ ÛÛÛ°°ÛÛÛ °ÛÛÛ  ÛÛÛ°°
    °ÛÛÛ          °ÛÛÛ °°°  °ÛÛÛ °ÛÛÛ  °ÛÛÛ °ÛÛÛ  °ÛÛÛ           °ÛÛÛ    °ÛÛÛ °ÛÛÛ°ÛÛÛ °ÛÛÛ °ÛÛÛ °°ÛÛÛÛÛ
    °°ÛÛÛ     ÛÛÛ °ÛÛÛ      °ÛÛÛ °ÛÛÛ  °ÛÛÛ °ÛÛÛ  °ÛÛÛ ÛÛÛ       °ÛÛÛ    °ÛÛÛ °ÛÛÛ°ÛÛÛ °ÛÛÛ °ÛÛÛ  °°°°ÛÛÛ
     °°ÛÛÛÛÛÛÛÛÛ  ÛÛÛÛÛ     °°ÛÛÛÛÛÛÛ  °ÛÛÛÛÛÛÛ   °°ÛÛÛÛÛ        ÛÛÛÛÛ   °°ÛÛÛÛÛÛ °°ÛÛÛÛÛÛ  ÛÛÛÛÛ ÛÛÛÛÛÛ
      °°°°°°°°°  °°°°°       °°°°°ÛÛÛ  °ÛÛÛ°°°     °°°°°        °°°°°     °°°°°°   °°°°°°  °°°°° °°°°°°
                             ÛÛÛ °ÛÛÛ  °ÛÛÛ
                            °°ÛÛÛÛÛÛ   ÛÛÛÛÛ
                             °°°°°°   °°°°°
    """,
        r"""
      ,ad8888ba,                                               888888888888                    88
     d8"'    `"8b                                     ,d            88                         88
    d8'                                               88            88                         88
    88            8b,dPPYba, 8b       d8 8b,dPPYba, MM88MMM         88  ,adPPYba,   ,adPPYba,  88 ,adPPYba,
    88            88P'   "Y8 `8b     d8' 88P'    "8a  88            88 a8"     "8a a8"     "8a 88 I8[    ""
    Y8,           88          `8b,  d8'  88       d8  88            88 8b       d8 8b       d8 88  `"Y8ba,
     Y8a.    .a8P 88           `8b,d8'   88b,   ,a8"  88,           88 "8a,   ,a8" "8a,   ,a8" 88 aa    ]8I
      `"Y8888Y"'  88             Y88'    88`YbbdP"'   "Y888         88  `"YbbdP"'   `"YbbdP"'  88 `"YbbdP"'
                                 d8'     88
                                d8'      88
    """,
        r"""
     ██████╗██████╗ ██╗   ██╗██████╗ ████████╗    ████████╗ ██████╗  ██████╗ ██╗     ███████╗
    ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝
    ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║          ██║   ██║   ██║██║   ██║██║     ███████╗
    ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║          ██║   ██║   ██║██║   ██║██║     ╚════██║
    ╚██████╗██║  ██║   ██║   ██║        ██║          ██║   ╚██████╔╝╚██████╔╝███████╗███████║
     ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝          ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
    """
    ]

    @classmethod
    def show(cls):
        """Displays a random banner."""
        banner = cls.__BANNER[random.randint(0, len(cls.__BANNER) - 1)]
        cyan = TerminalColors.Foreground.CYAN
        reset = TerminalColors.RESET
        print(f"{cyan}{banner}{reset}")
        print(f"{cyan}{Config.DESCRIPTION} v{Config.VERSION}{reset}")
        print(f"{cyan}Author: {Config.AUTHOR}{reset}\n")

# =========================
# Core Logic (Engine)
# =========================

class CryptoEngine:
    """
    Handles cryptographic operations using AES-GCM.
    Includes methods for key derivation, chunk processing, and file handling.
    """

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a 256-bit key from password and salt using PBKDF2."""
        ConsoleLogger.show('debug', f"Deriving key with PBKDF2 ({Config.PBKDF2_ITERATIONS} iterations)")
        return hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode('utf-8'), 
            salt, 
            Config.PBKDF2_ITERATIONS, 
            dklen=Config.KEY_SIZE
        )

    def _format_size(self, size: int) -> str:
        """Human readable file size."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f}{unit}"
            size /= 1024
        return f"{size:.2f}PB"

    def encrypt_data(self, data: bytes, password: str) -> bytes:
        """
        Encrypt bytes in memory.
        Format: [SALT(16)] + [NONCE(12)] + [TAG(16)] + [CIPHERTEXT]
        """
        ConsoleLogger.show('debug', f"Starting in-memory data encryption ({len(data)} bytes input)")
        salt = os.urandom(Config.SALT_SIZE)
        nonce = os.urandom(Config.NONCE_SIZE)
        ConsoleLogger.show('debug', f"Generated salt ({Config.SALT_SIZE} bytes) and nonce ({Config.NONCE_SIZE} bytes)")
        key = self._derive_key(password, salt)
        
        ConsoleLogger.show('debug', "Initializing AES-GCM cipher")
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        ConsoleLogger.show('debug', f"Encryption complete. Ciphertext size: {len(ciphertext)} bytes, Tag size: {len(tag)} bytes")
        
        return salt + nonce + tag + ciphertext

    def decrypt_data(self, enc_data: bytes, password: str) -> Optional[bytes]:
        """
        Decrypt bytes in memory.
        Expects: [SALT(16)] + [NONCE(12)] + [TAG(16)] + [CIPHERTEXT]
        """
        try:
            ConsoleLogger.show('debug', f"Starting in-memory data decryption. Total input size: {len(enc_data)} bytes")
            overhead = Config.SALT_SIZE + Config.NONCE_SIZE + Config.TAG_SIZE
            if len(enc_data) < overhead:
                ConsoleLogger.show('debug', "Input data is smaller than minimum overhead")
                raise ValueError("Data too short")

            salt = enc_data[:Config.SALT_SIZE]
            nonce = enc_data[Config.SALT_SIZE : Config.SALT_SIZE + Config.NONCE_SIZE]
            tag = enc_data[Config.SALT_SIZE + Config.NONCE_SIZE : overhead]
            ciphertext = enc_data[overhead:]
            ConsoleLogger.show('debug', f"Extracted salt, nonce, tag, and ciphertext ({len(ciphertext)} bytes)")

            key = self._derive_key(password, salt)
            ConsoleLogger.show('debug', "Initializing AES-GCM cipher for decryption")
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            ConsoleLogger.show('debug', "Verifying tag and decrypting ciphertext")
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            ConsoleLogger.show('debug', f"Decryption successful. Plaintext size: {len(decrypted)} bytes")
            return decrypted
            
        except (ValueError, KeyError) as e:
            ConsoleLogger.show('error', f"Decryption failed: {str(e)}")
            return None

    def encrypt_file(self, input_path: str, output_path: str, password: str, compress: bool = False) -> bool:
        """
        Encrypts a file using streaming (low memory usage).
        Format: [SALT] + [NONCE] + [CIPHERTEXT] + [TAG]
        """
        try:
            ConsoleLogger.show('debug', f"Starting file encryption: {input_path} -> {output_path}")
            file_size = os.path.getsize(input_path)
            
            ConsoleLogger.show('debug', f"Generating {Config.SALT_SIZE} bytes salt and {Config.NONCE_SIZE} bytes nonce")
            salt = os.urandom(Config.SALT_SIZE)
            nonce = os.urandom(Config.NONCE_SIZE)
            key = self._derive_key(password, salt)
            ConsoleLogger.show('debug', "Initializing AES-GCM cipher")
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                # Write Header: SALT + NONCE
                fout.write(salt)
                fout.write(nonce)
                
                compressor = zlib.compressobj(level=9) if compress else None
                if compress:
                    ConsoleLogger.show('debug', "Compression enabled (zlib level 9)")
                
                with tqdm(total=file_size, unit='B', unit_scale=True, desc="[🔒] Encrypting") as pbar:
                    while True:
                        chunk = fin.read(Config.CHUNK_SIZE)
                        if not chunk:
                            break
                        
                        if compressor:
                            compressed_chunk = compressor.compress(chunk)
                            if compressed_chunk:
                                fout.write(cipher.encrypt(compressed_chunk))
                        else:
                            fout.write(cipher.encrypt(chunk))
                        
                        pbar.update(len(chunk))
                
                ConsoleLogger.show('debug', "Reached end of input file")
                
                if compressor:
                    remaining = compressor.flush()
                    if remaining:
                        ConsoleLogger.show('debug', f"Writing remaining compressed data ({len(remaining)} bytes)")
                        fout.write(cipher.encrypt(remaining))
                
                # Calculate and write Tag at the end
                tag = cipher.digest()
                ConsoleLogger.show('debug', f"Writing authentication tag ({len(tag)} bytes)")
                fout.write(tag)

            # Log encryption progress completion
            ConsoleLogger.show('info', f"Encrypting: {file_size}B encrypted successfully", icon='🔒')
            return True

        except Exception as e:
            ConsoleLogger.show('error', f"File encryption error: {e}")
            ConsoleLogger.show('error', f"Failed to encrypt: {input_path}")
            if os.path.exists(output_path):
                os.remove(output_path)
            return False

    def decrypt_file(self, input_path: str, output_path: str, password: str, compress: bool = False) -> bool:
        """
        Decrypts a file using streaming.
        Expects: [SALT] + [NONCE] + [CIPHERTEXT] + [TAG]
        """
        try:
            file_size = os.path.getsize(input_path)
            ConsoleLogger.show('debug', f"Starting file decryption: {input_path} (size: {self._format_size(file_size)}) -> {output_path}")
            header_size = Config.SALT_SIZE + Config.NONCE_SIZE
            footer_size = Config.TAG_SIZE
            
            if file_size < header_size + footer_size:
                ConsoleLogger.show('debug', "File size is smaller than required header + footer overhead")
                raise ValueError("File too small")

            with open(input_path, 'rb') as fin:
                salt = fin.read(Config.SALT_SIZE)
                nonce = fin.read(Config.NONCE_SIZE)
                
                ConsoleLogger.show('debug', f"Read salt ({len(salt)} bytes) and nonce ({len(nonce)} bytes)")
                key = self._derive_key(password, salt)
                ConsoleLogger.show('debug', "Initializing AES-GCM cipher for decryption")
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                
                ciphertext_len = file_size - header_size - footer_size
                ConsoleLogger.show('debug', f"Ciphertext length to decrypt: {self._format_size(ciphertext_len)}")
                
                with open(output_path, 'wb') as fout, tqdm(total=ciphertext_len, unit='B', unit_scale=True, desc="[🔓] Decrypting") as pbar:
                    decompressor = zlib.decompressobj() if compress else None
                    bytes_read = 0

                    while bytes_read < ciphertext_len:
                        read_size = min(Config.CHUNK_SIZE, ciphertext_len - bytes_read)
                        chunk = fin.read(read_size)
                        if not chunk:
                            break

                        decrypted_chunk = cipher.decrypt(chunk)

                        if decompressor:
                            decompressed_chunk = decompressor.decompress(decrypted_chunk)
                            if decompressed_chunk:
                                fout.write(decompressed_chunk)
                        else:
                            fout.write(decrypted_chunk)

                        bytes_read += len(chunk)
                        pbar.update(len(chunk))

                if bytes_read < ciphertext_len:
                    ConsoleLogger.show('warning', "Unexpected end of file while reading ciphertext")

                    if decompressor:
                        ConsoleLogger.show('debug', "Flushing decompressor buffers")
                        fout.write(decompressor.flush())

                # Verify Tag (always, regardless of bytes_read)
                tag = fin.read(Config.TAG_SIZE)
                ConsoleLogger.show('debug', f"Read authentication tag ({len(tag)} bytes)")
                try:
                    ConsoleLogger.show('debug', "Verifying authentication tag")
                    cipher.verify(tag)
                except ValueError:
                    ConsoleLogger.show('error', "INTEGRITY CHECK FAILED! Password wrong or file corrupted.")
                    ConsoleLogger.show('error', f"Decryption failed for: {input_path}")
                    fout.close()
                    os.remove(output_path)
                    return False

            ConsoleLogger.show('success', "Integrity Verified. Decryption successful.")
            # Log decryption progress completion
            ConsoleLogger.show('info', f"Decrypting: {file_size}B decrypted successfully", icon='🔓')
            return True

        except Exception as e:
            ConsoleLogger.show('error', f"File decryption error: {e}")
            ConsoleLogger.show('error', f"Failed to decrypt: {input_path}")
            if os.path.exists(output_path):
                try: os.remove(output_path)
                except: pass
            return False

# =========================
# CLI Logic
# =========================

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=Config.DESCRIPTION)
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('-e', '--encrypt', action='store_true', help='Encrypt mode (default)')
    mode_group.add_argument('-d', '--decrypt', action='store_true', help='Decrypt mode')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--text', help='Text to process')
    group.add_argument('-f', '--file', help='File path to process')
    
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-p', '--password', required=False, help='Password (optional, will prompt if missing)')
    parser.add_argument('-c', '--compress', action='store_true', help='Enable compression')
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursively process directories')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--log', action='store_true', help='Enable logging to file')
    parser.add_argument('-v', '--version', action='version', version=Config.VERSION)
    
    return parser.parse_args(argv)

def main(argv=None):
    Banner.show()
    # If argv is None, argparse uses sys.argv[1:] automatically.
    # If argv is passed (from tests), it uses that list.
    args = parse_args(argv)
    engine = CryptoEngine()

    # Enable logging FIRST if --log flag is set
    if args.log:
        ConsoleLogger.LOG_ENABLED = True

    # Enable debug mode if --debug flag is set
    if args.debug:
        ConsoleLogger.DEBUG_ENABLED = True
        ConsoleLogger.show('debug', "Debug Mode Enabled. Verbose logging activated.")
        ConsoleLogger.show('info', "Debug mode: Enabled")

    # Show log file info (after LOG_ENABLED is set)
    if args.log:
        ConsoleLogger.show('debug', f"Logging enabled. Writing to: {ConsoleLogger.LOG_FILE}")
        ConsoleLogger.show('info', f"Log file: {ConsoleLogger.LOG_FILE}")
        ConsoleLogger.show('info', "Logging to file: Enabled")

    # Secure Password Input
    if not args.password:
        ConsoleLogger.show('info', "Enter Password: ", icon='🔑', log_file=False)
        args.password = getpass.getpass()
        ConsoleLogger.show('info', "Password entered by user", icon='🔑')
        if not args.password:
             ConsoleLogger.show('error', "Password cannot be empty.")
             ConsoleLogger.show('error', "Operation aborted: No password provided")
             sys.exit(1)

        # Verify password if encrypting
        if not args.decrypt:
            ConsoleLogger.show('debug', "Prompting for verification password")
            ConsoleLogger.show('info', "Verify Password: ", icon='🔄', log_file=False)
            verify_pass = getpass.getpass()
            ConsoleLogger.show('info', "Password verification entered", icon='🔄')
            if args.password != verify_pass:
                ConsoleLogger.show('error', "Passwords do not match!")
                ConsoleLogger.show('error', "Operation aborted due to password mismatch")
                sys.exit(1)
    else:
        ConsoleLogger.show('debug', "Password provided via command line")

    if args.text:
        # Display formatted status with emojis for text mode
        mode_str = "decrypt" if args.decrypt else "encrypt"
        compression_str = "disabled"  # Compression not available for text mode
        lock_emoji = "🔓" if args.decrypt else "🔐"
        green = TerminalColors.Foreground.GREEN
        blue = TerminalColors.Foreground.BLUE

        ConsoleLogger.show('info', f"Mode: {mode_str}", icon='🔐' if not args.decrypt else '🔓')
        ConsoleLogger.show('info', f"Compression: {compression_str}", icon='📦')
        ConsoleLogger.show('info', "Processing text...", icon='💬')
        ConsoleLogger.show('info', f"Input text length: {len(args.text)} characters", log_file=False)

        start_time = time.time()

        # Default to encrypt if decrypt is not explicitly set
        if not args.decrypt:
            ConsoleLogger.show('info', "Encrypting text...")
            result = engine.encrypt_data(args.text.encode('utf-8'), args.password)
            b64_result = base64.b64encode(result).decode('utf-8')
            ConsoleLogger.show('success', f"Encrypted (Base64): {b64_result}")
            elapsed_time = time.time() - start_time
            ConsoleLogger.show('info', f"Output encrypted text length: {len(b64_result)} characters")
            ConsoleLogger.show('success', "Encryption completed successfully", icon='✅')
            ConsoleLogger.show('info', f"Operations completed: 1/1", icon='✔️')
            ConsoleLogger.show('info', f"Total time: {elapsed_time:.2f}s", icon='⏱️')
        else:
            ConsoleLogger.show('info', "Decrypting text...")
            try:
                ConsoleLogger.show('debug', "Decoding Base64 text input")
                raw_data = base64.b64decode(args.text)
                result = engine.decrypt_data(raw_data, args.password)
                if result:
                    ConsoleLogger.show('success', f"Decrypted: {result.decode('utf-8')}", log_file=False)
                    elapsed_time = time.time() - start_time
                    ConsoleLogger.show('info', f"Output decrypted text length: {len(result)} characters", log_file=False)
                    ConsoleLogger.show('success', "Decryption completed successfully", icon='✅')
                    ConsoleLogger.show('info', f"Operations completed: 1/1", icon='✔️')
                    ConsoleLogger.show('info', f"Total time: {elapsed_time:.2f}s", icon='⏱️')
            except Exception as e:
                ConsoleLogger.show('error', f"Failed: {e}")
                ConsoleLogger.show('error', "Operation failed: Decryption error")

    elif args.file:
        ConsoleLogger.show('debug', f"File specified: {args.file}")

        # Recursive Directory Processing
        if args.recursive and os.path.isdir(args.file):
            input_dir = args.file
            mode_str = "decrypt" if args.decrypt else "encrypt"
            compression_str = "enabled" if args.compress else "disabled"
            lock_emoji = "🔓" if args.decrypt else "🔐"
            green = TerminalColors.Foreground.GREEN
            yellow = TerminalColors.Foreground.YELLOW
            blue = TerminalColors.Foreground.BLUE

            ConsoleLogger.show('info', f"Processing directory: {input_dir}", icon='📁')
            ConsoleLogger.show('debug', "Recursive mode enabled")
            ConsoleLogger.show('info', f"Mode: {mode_str}", icon='🔐' if not args.decrypt else '🔓')
            ConsoleLogger.show('info', f"Compression: {compression_str}", icon='📦')
            ConsoleLogger.show('info', f"{'Encrypting' if not args.decrypt else 'Decrypting'} directory: {input_dir}", icon='🔒' if not args.decrypt else '🔓')
            ConsoleLogger.show('info', "Recursive mode: enabled", icon='🔄')

            success_count = 0
            fail_count = 0
            start_time = time.time()

            for root, dirs, files in os.walk(input_dir):
                for file in files:
                    file_path = os.path.join(root, file)

                    if not args.decrypt:
                        # Skip already encrypted files if in crypt mode
                        if file.endswith('.enc'): continue

                        out_path = file_path + '.enc'
                        ConsoleLogger.show('info', f"Processing: {file_path}", icon='📄')
                        if engine.encrypt_file(file_path, out_path, args.password, args.compress):
                            success_count += 1
                        else:
                            fail_count += 1
                    else:
                        # Decrypt mode: Only process .enc files (or whatever convention, here simplistic)
                        if not file.endswith('.enc'): continue

                        out_path = os.path.splitext(file_path)[0] # Strip .enc
                         # If extension was removed and no extension remains, might be an issue, but standard restore.
                        if os.path.splitext(file_path)[0] == file_path:
                             out_path = file_path + '.dec'

                        ConsoleLogger.show('info', f"Processing: {file_path}", icon='📄')
                        if engine.decrypt_file(file_path, out_path, args.password, args.compress):
                            success_count += 1
                        else:
                             fail_count += 1

            elapsed_time = time.time() - start_time
            total_ops = success_count + fail_count

            ConsoleLogger.show('info', f"Batch complete. Success: {success_count}, Failed: {fail_count}")
            if fail_count > 0:
                ConsoleLogger.show('warning', f"Some files failed to process: {fail_count} failed")
            ConsoleLogger.show('info', f"Total files processed: {total_ops}")
            ConsoleLogger.show('info', f"Successful: {success_count}")
            ConsoleLogger.show('info', f"Failed: {fail_count}")

            # Display completion summary
            ConsoleLogger.show('success', f"{'Decryption' if args.decrypt else 'Encryption'} completed successfully", icon='✅')
            ConsoleLogger.show('info', f"Operations completed: {success_count}/{total_ops}", icon='✔️')
            ConsoleLogger.show('info', f"Total time: {elapsed_time:.2f}s", icon='⏱️')

        elif os.path.exists(args.file):
            if os.path.isdir(args.file):
                 ConsoleLogger.show('error', f"Path is a directory. Use -r/--recursive to process directories.")
                 ConsoleLogger.show('error', "Operation aborted: Directory specified without --recursive flag")
                 sys.exit(1)

            default_ext = '.enc' if not args.decrypt else '.dec'
            output_file = args.output or (os.path.splitext(args.file)[0] + default_ext)

            # Display formatted status with emojis
            mode_str = "decrypt" if args.decrypt else "encrypt"
            compression_str = "enabled" if args.compress else "disabled"
            lock_emoji = "🔓" if args.decrypt else "🔐"
            green = TerminalColors.Foreground.GREEN
            blue = TerminalColors.Foreground.BLUE

            input_size = os.path.getsize(args.file)
            ConsoleLogger.show('info', f"Mode: {mode_str}", icon='🔐' if not args.decrypt else '🔓')
            ConsoleLogger.show('info', f"Compression: {compression_str}", icon='📦')
            ConsoleLogger.show('info', f"Processing file: {args.file} ({engine._format_size(input_size)})", icon='📄')

            start_time = time.time()

            if not args.decrypt:
                success = engine.encrypt_file(args.file, output_file, args.password, args.compress)
            else:
                success = engine.decrypt_file(args.file, output_file, args.password, args.compress)

            elapsed_time = time.time() - start_time

            if success:
                # Display completion summary
                ConsoleLogger.show('success', f"{'Decryption' if args.decrypt else 'Encryption'} completed successfully", icon='✅')
                ConsoleLogger.show('success', f"File {'encrypted' if not args.decrypt else 'decrypted'}: {output_file} ({engine._format_size(os.path.getsize(output_file))})", icon='📄')
                ConsoleLogger.show('info', "Operations completed: 1/1", icon='✔️')
                ConsoleLogger.show('info', f"Total time: {elapsed_time:.2f}s", icon='⏱️')
            else:
                ConsoleLogger.show('error', f"{'Decryption' if args.decrypt else 'Encryption'} failed!")
                sys.exit(1)
        else:
            ConsoleLogger.show('error', f"File not found: {args.file}")
            ConsoleLogger.show('error', f"Operation failed: File does not exist")
            ConsoleLogger.show('error', "Please check the file path and try again")
            sys.exit(1)

if __name__ == '__main__':
    main()
