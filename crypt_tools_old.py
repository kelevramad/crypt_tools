#!/usr/bin/env python3
"""
Cryptographic Tool for File and Text Encryption/Decryption.
Refactored version with AES-GCM and Streaming I/O.
"""

import argparse
import base64
import hashlib
import os
import sys
import time
import zlib
import shutil
from enum import StrEnum
from typing import Optional, Union, BinaryIO, Generator

# Third-party imports
try:
    import animation
    from Crypto import Random
    from Crypto.Cipher import AES
except ImportError:
    print("Error: Missing dependencies. Please install 'pycryptodome' and 'animation'.")
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
    @staticmethod
    def show():
        """Displays a simple banner."""
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
        key = self._derive_key(password, salt)
        
        cipher = AES.new(key, AES.MODE_GCM) # GCM generates a random nonce by default if not provided? 
                                            # No, typically best to generate explicitly or let library do it and read access.
                                            # PyCryptodome AES.new(key, AES.MODE_GCM) creates a random nonce if not supplied. 
        
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        # We need the nonce to decrypt.
        return salt + cipher.nonce + tag + ciphertext

    def decrypt_data(self, enc_data: bytes, password: str) -> Optional[bytes]:
        """
        Decrypt bytes in memory.
        Expects: [SALT(16)] + [NONCE(12)] + [TAG(16)] + [CIPHERTEXT]
        """
        try:
            if len(enc_data) < Config.SALT_SIZE + Config.NONCE_SIZE + Config.TAG_SIZE:
                raise ValueError("Data too short")

            salt = enc_data[:Config.SALT_SIZE]
            nonce = enc_data[Config.SALT_SIZE : Config.SALT_SIZE + Config.NONCE_SIZE]
            tag = enc_data[Config.SALT_SIZE + Config.NONCE_SIZE : Config.SALT_SIZE + Config.NONCE_SIZE + Config.TAG_SIZE]
            ciphertext = enc_data[Config.SALT_SIZE + Config.NONCE_SIZE + Config.TAG_SIZE :]

            key = self._derive_key(password, salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            return cipher.decrypt_and_verify(ciphertext, tag)
            
        except (ValueError, KeyError) as e:
            # GCM verify failed or other error
            Logger.log('error', f"Decryption failed: {str(e)}")
            return None

    def encrypt_file(self, input_path: str, output_path: str, password: str, compress: bool = False) -> bool:
        """
        Encrypts a file using streaming (low memory usage).
        Format: [SALT(16)] + [NONCE(12)] + [TAG(16)... placeholders?]
        
        Wait, GCM tag is generated AFTER processing all data.
        Streaming GCM is tricky because Tag is at the end.
        But we can put Tag at the END of the file easily.
        Structure: [SALT] + [NONCE] + [CIPHERTEXT] + [TAG]
        """
        try:
            file_size = os.path.getsize(input_path)
            Logger.log('info', f"Processing {input_path} ({self._format_size(file_size)})")
            
            salt = os.urandom(Config.SALT_SIZE)
            key = self._derive_key(password, salt)
            cipher = AES.new(key, AES.MODE_GCM)
            nonce = cipher.nonce

            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                # Write Header: SALT + NONCE
                fout.write(salt)
                fout.write(nonce)
                
                # If compression is on, we can't easily stream perfectly without chunking protocol or temp file.
                # Standard zlib stream object could work (zlib.compressobj).
                compressor = zlib.compressobj(level=9) if compress else None
                
                while True:
                    chunk = fin.read(Config.CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    if compressor:
                        # Feed chunk to compressor
                        compressed_chunk = compressor.compress(chunk)
                        if compressed_chunk:
                            # Encrypt compressed data
                            # Note: encrypt() in GCM mode updates the internal state for tag.
                            fout.write(cipher.encrypt(compressed_chunk))
                    else:
                        fout.write(cipher.encrypt(chunk))
                
                # Flush remaining data
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
        Expects: [SALT(16)] + [NONCE(12)] + [CIPHERTEXT] + [TAG(16)]
        """
        try:
            file_size = os.path.getsize(input_path)
            header_size = Config.SALT_SIZE + Config.NONCE_SIZE
            footer_size = Config.TAG_SIZE
            
            if file_size < header_size + footer_size:
                raise ValueError("File too small to be a valid archive.")

            with open(input_path, 'rb') as fin:
                # Read Header
                salt = fin.read(Config.SALT_SIZE)
                nonce = fin.read(Config.NONCE_SIZE)
                
                # Initialize Cipher
                key = self._derive_key(password, salt)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                
                # Determine ciphertext length
                ciphertext_len = file_size - header_size - footer_size
                
                # Prepare output
                with open(output_path, 'wb') as fout:
                    decompressor = zlib.decompressobj() if compress else None
                    
                    # Read loop for ciphertext
                    bytes_read = 0
                    while bytes_read < ciphertext_len:
                        # Calculate read size (don't read into tag)
                        read_size = min(Config.CHUNK_SIZE, ciphertext_len - bytes_read)
                        chunk = fin.read(read_size)
                        if not chunk: break
                        
                        # Decrypt
                        # Note: GCM decrypt() doesn't verify until `verify()` is called with tag.
                        # We must process everything first? 
                        # WARNING: In streaming GCM, you technically shouldn't use the data until verified.
                        # But for large files, we must write it out. 
                        # If verification fails, we should delete the output file.
                        
                        decrypted_chunk = cipher.decrypt(chunk)
                        
                        if decompressor:
                            decompressed_chunk = decompressor.decompress(decrypted_chunk)
                            if decompressed_chunk:
                                fout.write(decompressed_chunk)
                        else:
                            fout.write(decrypted_chunk)
                            
                        bytes_read += len(chunk)

                    # Flush decompressor
                    if decompressor:
                        fout.write(decompressor.flush())

                    # Verify Tag
                    tag = fin.read(Config.TAG_SIZE)
                    try:
                        cipher.verify(tag)
                        Logger.log('success', "Integrity Verified. Decryption successful.")
                    except ValueError:
                        Logger.log('error', "INTEGRITY CHECK FAILED! Password wrong or file corrupted.")
                        # Security: Delete the output file because it contains potentially malicious/garbage data.
                        fout.close() # Ensure bad file is closed before removal
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

def parse_args():
    parser = argparse.ArgumentParser(description=Config.DESCRIPTION)
    
    parser.add_argument('-m', '--mode', choices=['crypt', 'decrypt'], default='crypt', help='Operation mode')
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--text', help='Text to process')
    group.add_argument('-i', '--input', help='Input file path')
    
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-p', '--password', required=True, help='Password')
    parser.add_argument('-c', '--compress', action='store_true', help='Enable compression')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('-v', '--version', action='version', version=Config.VERSION)
    
    return parser.parse_args()

def main():
    Banner.show()
    args = parse_args()
    engine = CryptoEngine()
    
    if args.debug:
        Logger.log('info', "Debug Mode Enabled")

    start_time = time.time()

    # TEXT MODE
    if args.text:
        if args.mode == 'crypt':
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

    # FILE MODE
    elif args.input:
        if not os.path.exists(args.input):
            Logger.log('error', f"File not found: {args.input}")
            sys.exit(1)
            
        default_ext = '.enc' if args.mode == 'crypt' else '.dec'
        output_file = args.output or (os.path.splitext(args.input)[0] + default_ext)
        
        if args.mode == 'crypt':
            success = engine.encrypt_file(args.input, output_file, args.password, args.compress)
        else:
            success = engine.decrypt_file(args.input, output_file, args.password, args.compress)
            
        if not success:
            sys.exit(1)

    elapsed = time.time() - start_time
    Logger.log('info', f"Time elapsed: {elapsed:.2f}s")

if __name__ == '__main__':
    main()
