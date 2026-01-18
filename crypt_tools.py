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

class Logger:
    @staticmethod
    def log(level: str, message: str) -> None:
        """Simple logger with icons."""
        icons = {
            'info': (TerminalColors.Foreground.BLUE, '[*]'),
            'success': (TerminalColors.Foreground.GREEN, '[+]'),
            'error': (TerminalColors.Foreground.RED, '[-]'),
            'warning': (TerminalColors.Foreground.YELLOW, '[!]'),
        }
        color, icon = icons.get(level, (TerminalColors.RESET, '[?]'))
        print(f"{color}{icon} {message}{TerminalColors.RESET}")

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
        print(f"{TerminalColors.Foreground.CYAN}{banner}{TerminalColors.RESET}")
        print(f"{TerminalColors.Foreground.CYAN}{Config.DESCRIPTION} v{Config.VERSION}{TerminalColors.RESET}")
        print(f"{TerminalColors.Foreground.CYAN}Author: {Config.AUTHOR}{TerminalColors.RESET}\n")

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
        salt = os.urandom(Config.SALT_SIZE)
        nonce = os.urandom(Config.NONCE_SIZE)
        key = self._derive_key(password, salt)
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        return salt + nonce + tag + ciphertext

    def decrypt_data(self, enc_data: bytes, password: str) -> Optional[bytes]:
        """
        Decrypt bytes in memory.
        Expects: [SALT(16)] + [NONCE(12)] + [TAG(16)] + [CIPHERTEXT]
        """
        try:
            overhead = Config.SALT_SIZE + Config.NONCE_SIZE + Config.TAG_SIZE
            if len(enc_data) < overhead:
                raise ValueError("Data too short")

            salt = enc_data[:Config.SALT_SIZE]
            nonce = enc_data[Config.SALT_SIZE : Config.SALT_SIZE + Config.NONCE_SIZE]
            tag = enc_data[Config.SALT_SIZE + Config.NONCE_SIZE : overhead]
            ciphertext = enc_data[overhead:]

            key = self._derive_key(password, salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            return cipher.decrypt_and_verify(ciphertext, tag)
            
        except (ValueError, KeyError) as e:
            Logger.log('error', f"Decryption failed: {str(e)}")
            return None

    def encrypt_file(self, input_path: str, output_path: str, password: str, compress: bool = False) -> bool:
        """
        Encrypts a file using streaming (low memory usage).
        Format: [SALT] + [NONCE] + [CIPHERTEXT] + [TAG]
        """
        try:
            file_size = os.path.getsize(input_path)
            Logger.log('info', f"Processing {input_path} ({self._format_size(file_size)})")
            
            salt = os.urandom(Config.SALT_SIZE)
            nonce = os.urandom(Config.NONCE_SIZE)
            key = self._derive_key(password, salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                # Write Header: SALT + NONCE
                fout.write(salt)
                fout.write(nonce)
                
                compressor = zlib.compressobj(level=9) if compress else None
                
                with tqdm(total=file_size, unit='B', unit_scale=True, desc="Encrypting", leave=False) as pbar:
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
                
                if compressor:
                    remaining = compressor.flush()
                    if remaining:
                        fout.write(cipher.encrypt(remaining))
                
                # Calculate and write Tag at the end
                tag = cipher.digest()
                fout.write(tag)
                
            Logger.log('success', f"File encrypted: {output_path}")
            return True

        except Exception as e:
            Logger.log('error', f"File encryption error: {e}")
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
            header_size = Config.SALT_SIZE + Config.NONCE_SIZE
            footer_size = Config.TAG_SIZE
            
            if file_size < header_size + footer_size:
                raise ValueError("File too small")

            with open(input_path, 'rb') as fin:
                salt = fin.read(Config.SALT_SIZE)
                nonce = fin.read(Config.NONCE_SIZE)
                
                key = self._derive_key(password, salt)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                
                ciphertext_len = file_size - header_size - footer_size
                
                with open(output_path, 'wb') as fout, tqdm(total=ciphertext_len, unit='B', unit_scale=True, desc="Decrypting", leave=False) as pbar:
                    decompressor = zlib.decompressobj() if compress else None
                    bytes_read = 0
                    
                    while bytes_read < ciphertext_len:
                        read_size = min(Config.CHUNK_SIZE, ciphertext_len - bytes_read)
                        chunk = fin.read(read_size)
                        if not chunk: break
                        
                        decrypted_chunk = cipher.decrypt(chunk)
                        
                        if decompressor:
                            decompressed_chunk = decompressor.decompress(decrypted_chunk)
                            if decompressed_chunk:
                                fout.write(decompressed_chunk)
                        else:
                            fout.write(decrypted_chunk)
                            
                        bytes_read += len(chunk)
                        pbar.update(len(chunk))

                    if decompressor:
                        fout.write(decompressor.flush())

                    # Verify Tag
                    tag = fin.read(Config.TAG_SIZE)
                    try:
                        cipher.verify(tag)
                        Logger.log('success', "Integrity Verified. Decryption successful.")
                    except ValueError:
                        Logger.log('error', "INTEGRITY CHECK FAILED! Password wrong or file corrupted.")
                        fout.close()
                        os.remove(output_path)
                        return False
            
            return True

        except Exception as e:
            Logger.log('error', f"File decryption error: {e}")
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
    group.add_argument('-i', '--input', help='Input file path')
    
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-p', '--password', required=False, help='Password (optional, will prompt if missing)')
    parser.add_argument('-c', '--compress', action='store_true', help='Enable compression')
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursively process directories')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('-v', '--version', action='version', version=Config.VERSION)
    
    return parser.parse_args(argv)

def main(argv=None):
    Banner.show()
    # If argv is None, argparse uses sys.argv[1:] automatically.
    # If argv is passed (from tests), it uses that list.
    args = parse_args(argv)
    engine = CryptoEngine()
    
    if args.debug:
        Logger.log('info', "Debug Mode Enabled")

    # Secure Password Input
    if not args.password:
        args.password = getpass.getpass("Enter Password: ")
        if not args.password:
             Logger.log('error', "Password cannot be empty.")
             sys.exit(1)
        
        # Verify password if encrypting
        if not args.decrypt:
            verify_pass = getpass.getpass("Verify Password: ")
            if args.password != verify_pass:
                Logger.log('error', "Passwords do not match!")
                sys.exit(1)

    if args.text:
        # Default to encrypt if decrypt is not explicitly set
        if not args.decrypt:
            Logger.log('info', "Encrypting text...")
            result = engine.encrypt_data(args.text.encode('utf-8'), args.password)
            b64_result = base64.b64encode(result).decode('utf-8')
            Logger.log('success', f"Encrypted (Base64): {b64_result}")
        else:
            Logger.log('info', "Decrypting text...")
            try:
                raw_data = base64.b64decode(args.text)
                result = engine.decrypt_data(raw_data, args.password)
                if result:
                    Logger.log('success', f"Decrypted: {result.decode('utf-8')}")
            except Exception as e:
                Logger.log('error', f"Failed: {e}")

    elif args.input:
        
        # Recursive Directory Processing
        if args.recursive and os.path.isdir(args.input):
            input_dir = args.input
            Logger.log('info', f"Processing directory: {input_dir}")
            
            success_count = 0
            fail_count = 0
            
            for root, dirs, files in os.walk(input_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    if not args.decrypt:
                        # Skip already encrypted files if in crypt mode
                        if file.endswith('.enc'): continue
                        
                        out_path = file_path + '.enc'
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

                        if engine.decrypt_file(file_path, out_path, args.password, args.compress):
                            success_count += 1
                        else:
                             fail_count += 1
            
            Logger.log('info', f"Batch complete. Success: {success_count}, Failed: {fail_count}")

        elif os.path.exists(args.input):
            if os.path.isdir(args.input):
                 Logger.log('error', f"Input is a directory. Use -r/--recursive to process directories.")
                 sys.exit(1)

            default_ext = '.enc' if not args.decrypt else '.dec'
            output_file = args.output or (os.path.splitext(args.input)[0] + default_ext)
            
            if not args.decrypt:
                success = engine.encrypt_file(args.input, output_file, args.password, args.compress)
            else:
                success = engine.decrypt_file(args.input, output_file, args.password, args.compress)
                
            if not success:
                sys.exit(1)
        else:
            Logger.log('error', f"File not found: {args.input}")
            sys.exit(1)

if __name__ == '__main__':
    main()
