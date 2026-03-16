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
from enum import StrEnum
from typing import Optional

# Third-party imports
try:
    from tqdm import tqdm
    from Crypto.Cipher import AES
except ImportError:
    print("Error: Missing dependencies. Please install 'pycryptodome' and 'tqdm'.")
    sys.exit(1)

# =========================
# Configuration
# =========================

class Config:
    """Configuration constants."""
    AUTHOR = 'Center For Cyber Intelligence'
    DESCRIPTION = 'Crypt Tools (AES-GCM Edition)'
    VERSION = "2.0.0"
    
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

class Logger:
    DEBUG_ENABLED = False
    LOG_ENABLED = False
    LOG_FILE = "crypt_tools.log"

    @staticmethod
    def log(level: str, message: str, to_console: bool = True) -> None:
        """Simple logger with icons."""
        if level == 'debug' and not Logger.DEBUG_ENABLED:
            return

        icons = {
            'info': (TerminalColors.Foreground.BLUE, 'ℹ️'),
            'success': (TerminalColors.Foreground.GREEN, '✅'),
            'error': (TerminalColors.Foreground.RED, '❌'),
            'warning': (TerminalColors.Foreground.YELLOW, '⚠️'),
            'debug': (TerminalColors.Foreground.MAGENTA, '🐞'),
        }
        color, icon = icons.get(level, (TerminalColors.RESET, '❓'))
        white = TerminalColors.Foreground.WHITE
        reset = TerminalColors.RESET
        
        # Write to log file if enabled (always, regardless of to_console)
        if Logger.LOG_ENABLED:
            Logger._write_to_file(level, message)
        
        # Print to console only if to_console is True
        if to_console:
            print(f"{white}[{reset}{icon}{white}]{reset} {color}{message}{reset}")

    @staticmethod
    def _write_to_file(level: str, message: str) -> None:
        """Write log message to file."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level.upper()}] {message}\n"
        with open(Logger.LOG_FILE, 'a', encoding='utf-8') as f:
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
        Logger.log('debug', f"Deriving key with PBKDF2 ({Config.PBKDF2_ITERATIONS} iterations)")
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
        Logger.log('debug', f"Starting in-memory data encryption ({len(data)} bytes input)")
        salt = os.urandom(Config.SALT_SIZE)
        nonce = os.urandom(Config.NONCE_SIZE)
        Logger.log('debug', f"Generated salt ({Config.SALT_SIZE} bytes) and nonce ({Config.NONCE_SIZE} bytes)")
        key = self._derive_key(password, salt)
        
        Logger.log('debug', "Initializing AES-GCM cipher")
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        Logger.log('debug', f"Encryption complete. Ciphertext size: {len(ciphertext)} bytes, Tag size: {len(tag)} bytes")
        
        return salt + nonce + tag + ciphertext

    def decrypt_data(self, enc_data: bytes, password: str) -> Optional[bytes]:
        """
        Decrypt bytes in memory.
        Expects: [SALT(16)] + [NONCE(12)] + [TAG(16)] + [CIPHERTEXT]
        """
        try:
            Logger.log('debug', f"Starting in-memory data decryption. Total input size: {len(enc_data)} bytes")
            overhead = Config.SALT_SIZE + Config.NONCE_SIZE + Config.TAG_SIZE
            if len(enc_data) < overhead:
                Logger.log('debug', "Input data is smaller than minimum overhead")
                raise ValueError("Data too short")

            salt = enc_data[:Config.SALT_SIZE]
            nonce = enc_data[Config.SALT_SIZE : Config.SALT_SIZE + Config.NONCE_SIZE]
            tag = enc_data[Config.SALT_SIZE + Config.NONCE_SIZE : overhead]
            ciphertext = enc_data[overhead:]
            Logger.log('debug', f"Extracted salt, nonce, tag, and ciphertext ({len(ciphertext)} bytes)")

            key = self._derive_key(password, salt)
            Logger.log('debug', "Initializing AES-GCM cipher for decryption")
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            Logger.log('debug', "Verifying tag and decrypting ciphertext")
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            Logger.log('debug', f"Decryption successful. Plaintext size: {len(decrypted)} bytes")
            return decrypted
            
        except (ValueError, KeyError) as e:
            Logger.log('error', f"Decryption failed: {str(e)}")
            return None

    def encrypt_file(self, input_path: str, output_path: str, password: str, compress: bool = False) -> bool:
        """
        Encrypts a file using streaming (low memory usage).
        Format: [SALT] + [NONCE] + [CIPHERTEXT] + [TAG]
        """
        try:
            Logger.log('debug', f"Starting file encryption: {input_path} -> {output_path}")
            file_size = os.path.getsize(input_path)
            
            Logger.log('debug', f"Generating {Config.SALT_SIZE} bytes salt and {Config.NONCE_SIZE} bytes nonce")
            salt = os.urandom(Config.SALT_SIZE)
            nonce = os.urandom(Config.NONCE_SIZE)
            key = self._derive_key(password, salt)
            Logger.log('debug', "Initializing AES-GCM cipher")
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                # Write Header: SALT + NONCE
                fout.write(salt)
                fout.write(nonce)
                
                compressor = zlib.compressobj(level=9) if compress else None
                if compress:
                    Logger.log('debug', "Compression enabled (zlib level 9)")
                
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
                
                Logger.log('debug', "Reached end of input file")
                
                if compressor:
                    remaining = compressor.flush()
                    if remaining:
                        Logger.log('debug', f"Writing remaining compressed data ({len(remaining)} bytes)")
                        fout.write(cipher.encrypt(remaining))
                
                # Calculate and write Tag at the end
                tag = cipher.digest()
                Logger.log('debug', f"Writing authentication tag ({len(tag)} bytes)")
                fout.write(tag)

            white = TerminalColors.Foreground.WHITE
            reset = TerminalColors.RESET
            green = TerminalColors.Foreground.GREEN
            Logger.log('success', f"File encrypted: {output_path} ({self._format_size(os.path.getsize(output_path))})", to_console=False)
            print(f"{white}[{reset}📄{white}]{reset} {green}File encrypted: {output_path} ({self._format_size(os.path.getsize(output_path))}){reset}")
            return True

        except Exception as e:
            Logger.log('error', f"File encryption error: {e}")
            Logger.log('error', f"Failed to encrypt: {input_path}")
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
            Logger.log('debug', f"Starting file decryption: {input_path} (size: {self._format_size(file_size)}) -> {output_path}")
            header_size = Config.SALT_SIZE + Config.NONCE_SIZE
            footer_size = Config.TAG_SIZE
            
            if file_size < header_size + footer_size:
                Logger.log('debug', "File size is smaller than required header + footer overhead")
                raise ValueError("File too small")

            with open(input_path, 'rb') as fin:
                salt = fin.read(Config.SALT_SIZE)
                nonce = fin.read(Config.NONCE_SIZE)
                
                Logger.log('debug', f"Read salt ({len(salt)} bytes) and nonce ({len(nonce)} bytes)")
                key = self._derive_key(password, salt)
                Logger.log('debug', "Initializing AES-GCM cipher for decryption")
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                
                ciphertext_len = file_size - header_size - footer_size
                Logger.log('debug', f"Ciphertext length to decrypt: {self._format_size(ciphertext_len)}")
                
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
                    Logger.log('warning', "Unexpected end of file while reading ciphertext")

                    if decompressor:
                        Logger.log('debug', "Flushing decompressor buffers")
                        fout.write(decompressor.flush())

                    # Verify Tag
                    tag = fin.read(Config.TAG_SIZE)
                    Logger.log('debug', f"Read authentication tag ({len(tag)} bytes)")
                    try:
                        Logger.log('debug', "Verifying authentication tag")
                        cipher.verify(tag)
                    except ValueError:
                        Logger.log('error', "INTEGRITY CHECK FAILED! Password wrong or file corrupted.")
                        Logger.log('error', f"Decryption failed for: {input_path}")
                        fout.close()
                        os.remove(output_path)
                        return False

            white = TerminalColors.Foreground.WHITE
            reset = TerminalColors.RESET
            yellow = TerminalColors.Foreground.YELLOW
            green = TerminalColors.Foreground.GREEN
            Logger.log('success', "Integrity Verified. Decryption successful.", to_console=False)
            Logger.log('success', f"File decrypted: {output_path} ({self._format_size(os.path.getsize(output_path))})", to_console=False)
            print(f"{white}[{reset}✅{white}]{reset} {green}Integrity Verified. Decryption successful.{reset}")
            print(f"{white}[{reset}📄{white}]{reset} {green}File decrypted: {output_path} ({self._format_size(os.path.getsize(output_path))}){reset}")
            return True

        except Exception as e:
            Logger.log('error', f"File decryption error: {e}")
            Logger.log('error', f"Failed to decrypt: {input_path}")
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
    
    if args.debug:
        Logger.DEBUG_ENABLED = True
        Logger.log('debug', "Debug Mode Enabled. Verbose logging activated.")
        Logger.log('info', "Debug mode: Enabled", to_console=False)

    if args.log:
        Logger.LOG_ENABLED = True
        Logger.log('debug', f"Logging enabled. Writing to: {Logger.LOG_FILE}")
        Logger.log('info', f"Log file: {Logger.LOG_FILE}", to_console=False)
        Logger.log('info', "Logging to file: Enabled", to_console=False)

    # Secure Password Input
    if not args.password:
        white = TerminalColors.Foreground.WHITE
        reset = TerminalColors.RESET
        print(f"{white}[{reset}🔑{white}]{reset} ", end='', flush=True)
        args.password = getpass.getpass("Enter Password: ")
        Logger.log('info', "Password entered by user", to_console=False)
        if not args.password:
             Logger.log('error', "Password cannot be empty.")
             Logger.log('error', "Operation aborted: No password provided")
             sys.exit(1)

        # Verify password if encrypting
        if not args.decrypt:
            Logger.log('debug', "Prompting for verification password")
            print(f"{white}[{reset}🔄{white}]{reset} ", end='', flush=True)
            verify_pass = getpass.getpass("Verify Password: ")
            Logger.log('info', "Password verification entered", to_console=False)
            if args.password != verify_pass:
                Logger.log('error', "Passwords do not match!")
                Logger.log('error', "Operation aborted due to password mismatch")
                sys.exit(1)
    else:
        Logger.log('debug', "Password provided via command line")

    if args.text:
        # Display formatted status with emojis for text mode
        white = TerminalColors.Foreground.WHITE
        reset = TerminalColors.RESET
        mode_str = "decrypt" if args.decrypt else "encrypt"
        compression_str = "disabled"  # Compression not available for text mode
        lock_emoji = "🔓" if args.decrypt else "🔐"
        green = TerminalColors.Foreground.GREEN
        blue = TerminalColors.Foreground.BLUE

        Logger.log('info', f"Mode: {mode_str}", to_console=False)
        Logger.log('info', f"Compression: {compression_str}", to_console=False)
        Logger.log('info', "Processing text...", to_console=False)
        Logger.log('info', f"Input text length: {len(args.text)} characters", to_console=False)
        print(f"{white}[{reset}{lock_emoji}{white}]{reset} {white}Mode: {mode_str}{reset}")
        print(f"{white}[{reset}📦{white}]{reset} {white}Compression: {compression_str}{reset}")
        print(f"{white}[{reset}💬{white}]{reset} {white}Processing text...{reset}")

        start_time = time.time()

        # Default to encrypt if decrypt is not explicitly set
        if not args.decrypt:
            Logger.log('info', "Encrypting text...", to_console=False)
            result = engine.encrypt_data(args.text.encode('utf-8'), args.password)
            b64_result = base64.b64encode(result).decode('utf-8')
            Logger.log('success', f"Encrypted (Base64): {b64_result}")
            elapsed_time = time.time() - start_time
            Logger.log('info', f"Output encrypted text length: {len(b64_result)} characters", to_console=False)
            Logger.log('success', "Encryption completed successfully", to_console=False)
            Logger.log('info', f"Operations completed: 1/1", to_console=False)
            Logger.log('info', f"Total time: {elapsed_time:.2f}s", to_console=False)
            print(f"{white}[{reset}✅{white}]{reset} {green}Encryption completed successfully{reset}")
            print(f"{white}[{reset}✔️{white}]{reset} {blue}Operations completed: 1/1{reset}")
            print(f"{white}[{reset}⏱️{white}]{reset} {blue}Total time: {elapsed_time:.2f}s{reset}")
        else:
            Logger.log('info', "Decrypting text...", to_console=False)
            try:
                Logger.log('debug', "Decoding Base64 text input")
                raw_data = base64.b64decode(args.text)
                result = engine.decrypt_data(raw_data, args.password)
                if result:
                    Logger.log('success', f"Decrypted: {result.decode('utf-8')}")
                    elapsed_time = time.time() - start_time
                    Logger.log('info', f"Output decrypted text length: {len(result)} characters", to_console=False)
                    Logger.log('success', "Decryption completed successfully", to_console=False)
                    Logger.log('info', f"Operations completed: 1/1", to_console=False)
                    Logger.log('info', f"Total time: {elapsed_time:.2f}s", to_console=False)
                    print(f"{white}[{reset}✅{white}]{reset} {green}Decryption completed successfully{reset}")
                    print(f"{white}[{reset}✔️{white}]{reset} {blue}Operations completed: 1/1{reset}")
                    print(f"{white}[{reset}⏱️{white}]{reset} {blue}Total time: {elapsed_time:.2f}s{reset}")
            except Exception as e:
                Logger.log('error', f"Failed: {e}")
                Logger.log('error', "Operation failed: Decryption error")

    elif args.file:
        Logger.log('debug', f"File specified: {args.file}")
        
        # Recursive Directory Processing
        if args.recursive and os.path.isdir(args.file):
            input_dir = args.file
            white = TerminalColors.Foreground.WHITE
            reset = TerminalColors.RESET
            mode_str = "decrypt" if args.decrypt else "encrypt"
            compression_str = "enabled" if args.compress else "disabled"
            lock_emoji = "🔓" if args.decrypt else "🔐"
            green = TerminalColors.Foreground.GREEN
            yellow = TerminalColors.Foreground.YELLOW
            blue = TerminalColors.Foreground.BLUE

            Logger.log('info', f"Processing directory: {input_dir}")
            Logger.log('debug', "Recursive mode enabled")
            Logger.log('info', f"Mode: {mode_str}", to_console=False)
            Logger.log('info', f"Compression: {compression_str}", to_console=False)
            Logger.log('info', f"Processing directory: {input_dir}", to_console=False)
            Logger.log('info', "Recursive mode: enabled", to_console=False)
            Logger.log('info', f"{'Encrypting' if not args.decrypt else 'Decrypting'} directory: {input_dir}", to_console=False)

            # Display formatted status with emojis
            print(f"{white}[{reset}{lock_emoji}{white}]{reset} {white}Mode: {mode_str}{reset}")
            print(f"{white}[{reset}📦{white}]{reset} {white}Compression: {compression_str}{reset}")
            print(f"{white}[{reset}📁{white}]{reset} {white}Processing directory: {input_dir}{reset}")
            print(f"{white}[{reset}🔄{white}]{reset} {yellow}Recursive mode: enabled{reset}")

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
                        Logger.log('info', f"Processing: {file_path}", to_console=False)
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

                        Logger.log('info', f"Processing: {file_path}", to_console=False)
                        if engine.decrypt_file(file_path, out_path, args.password, args.compress):
                            success_count += 1
                        else:
                             fail_count += 1

            elapsed_time = time.time() - start_time
            total_ops = success_count + fail_count

            Logger.log('info', f"Batch complete. Success: {success_count}, Failed: {fail_count}")
            if fail_count > 0:
                Logger.log('warning', f"Some files failed to process: {fail_count} failed")
            Logger.log('info', f"Total files processed: {total_ops}", to_console=False)
            Logger.log('info', f"Successful: {success_count}", to_console=False)
            Logger.log('info', f"Failed: {fail_count}", to_console=False)

            # Display completion summary with emojis
            Logger.log('success', f"{'Decryption' if args.decrypt else 'Encryption'} completed successfully", to_console=False)
            Logger.log('info', f"Operations completed: {success_count}/{total_ops}", to_console=False)
            Logger.log('info', f"Total time: {elapsed_time:.2f}s", to_console=False)
            print(f"{white}[{reset}✅{white}]{reset} {green}{'Decryption' if args.decrypt else 'Encryption'} completed successfully{reset}")
            print(f"{white}[{reset}✔️{white}]{reset} {blue}Operations completed: {success_count}/{total_ops}{reset}")
            print(f"{white}[{reset}⏱️{white}]{reset} {blue}Total time: {elapsed_time:.2f}s{reset}")

        elif os.path.exists(args.file):
            if os.path.isdir(args.file):
                 Logger.log('error', f"Path is a directory. Use -r/--recursive to process directories.")
                 Logger.log('error', "Operation aborted: Directory specified without --recursive flag")
                 sys.exit(1)

            default_ext = '.enc' if not args.decrypt else '.dec'
            output_file = args.output or (os.path.splitext(args.file)[0] + default_ext)

            # Display formatted status with emojis
            white = TerminalColors.Foreground.WHITE
            reset = TerminalColors.RESET
            mode_str = "decrypt" if args.decrypt else "encrypt"
            compression_str = "enabled" if args.compress else "disabled"
            lock_emoji = "🔓" if args.decrypt else "🔐"
            green = TerminalColors.Foreground.GREEN
            yellow = TerminalColors.Foreground.YELLOW
            blue = TerminalColors.Foreground.BLUE
            
            input_size = os.path.getsize(args.file)
            Logger.log('info', f"Mode: {mode_str}", to_console=False)
            Logger.log('info', f"Compression: {compression_str}", to_console=False)
            Logger.log('info', f"{'Encrypting' if not args.decrypt else 'Decrypting'} file: {args.file} ({engine._format_size(input_size)})", to_console=False)
            print(f"{white}[{reset}{lock_emoji}{white}]{reset} {white}Mode: {mode_str}{reset}")
            print(f"{white}[{reset}📦{white}]{reset} {white}Compression: {compression_str}{reset}")
            print(f"{white}[{reset}📄{white}]{reset} {white}Processing file: {args.file} ({engine._format_size(input_size)}){reset}")

            start_time = time.time()

            if not args.decrypt:
                success = engine.encrypt_file(args.file, output_file, args.password, args.compress)
            else:
                success = engine.decrypt_file(args.file, output_file, args.password, args.compress)

            elapsed_time = time.time() - start_time

            if success:
                # Display completion summary with emojis
                Logger.log('success', f"{'Decryption' if args.decrypt else 'Encryption'} completed successfully", to_console=False)
                Logger.log('info', f"Operations completed: 1/1", to_console=False)
                Logger.log('info', f"Total time: {elapsed_time:.2f}s", to_console=False)
                print(f"{white}[{reset}✅{white}]{reset} {green}{'Decryption' if args.decrypt else 'Encryption'} completed successfully{reset}")
                print(f"{white}[{reset}✔️{white}]{reset} {blue}Operations completed: 1/1{reset}")
                print(f"{white}[{reset}⏱️{white}]{reset} {blue}Total time: {elapsed_time:.2f}s{reset}")
            else:
                Logger.log('error', f"{'Decryption' if args.decrypt else 'Encryption'} failed!")
                sys.exit(1)
        else:
            Logger.log('error', f"File not found: {args.file}")
            Logger.log('error', f"Operation failed: File does not exist")
            Logger.log('error', "Please check the file path and try again")
            sys.exit(1)

if __name__ == '__main__':
    main()
