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
import re
import glob
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

    # File format
    MAGIC = b"CT02"
    FORMAT_VERSION = 2
    FLAG_COMPRESS = 0x01
    FLAG_TEXT = 0x02
    FLAG_KEYFILE = 0x04
    KDF_PBKDF2 = 0x01
    FIXED_HEADER_SIZE = 16
    
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


def _uint32_to_bytes(value: int) -> bytes:
    return value.to_bytes(4, byteorder='big', signed=False)


def _bytes_to_uint32(raw: bytes) -> int:
    return int.from_bytes(raw, byteorder='big', signed=False)


def _build_header(
    *,
    compress: bool = False,
    is_text: bool = False,
    kdf_id: int = Config.KDF_PBKDF2,
    iterations: int = Config.PBKDF2_ITERATIONS,
) -> bytes:
    flags = 0
    if compress:
        flags |= Config.FLAG_COMPRESS
    if is_text:
        flags |= Config.FLAG_TEXT

    kdf_params = _uint32_to_bytes(iterations)
    return b"".join(
        [
            Config.MAGIC,
            bytes([Config.FORMAT_VERSION]),
            bytes([flags]),
            bytes([kdf_id]),
            b"\x00",
            bytes([Config.SALT_SIZE]),
            bytes([Config.NONCE_SIZE]),
            bytes([Config.TAG_SIZE]),
            bytes([len(kdf_params)]),
            kdf_params,
        ]
    )


def _parse_ct02_header_from_bytes(data: bytes) -> dict:
    if len(data) < 12:
        raise ValueError("CT02 header too short")
    if data[:4] != Config.MAGIC:
        raise ValueError("Invalid CT02 magic")

    version = data[4]
    flags = data[5]
    kdf_id = data[6]
    salt_len = data[8]
    nonce_len = data[9]
    tag_len = data[10]
    kdf_param_len = data[11]
    header_len = 12 + kdf_param_len

    if len(data) < header_len:
        raise ValueError("Incomplete CT02 header")

    kdf_params = data[12:header_len]
    iterations = _bytes_to_uint32(kdf_params) if kdf_param_len == 4 else Config.PBKDF2_ITERATIONS

    return {
        'format': Config.MAGIC.decode('ascii'),
        'version': version,
        'flags': flags,
        'compress': bool(flags & Config.FLAG_COMPRESS),
        'is_text': bool(flags & Config.FLAG_TEXT),
        'kdf_id': kdf_id,
        'iterations': iterations,
        'salt_len': salt_len,
        'nonce_len': nonce_len,
        'tag_len': tag_len,
        'kdf_param_len': kdf_param_len,
        'header_len': header_len,
        'is_legacy': False,
    }


def _parse_legacy_header(*, text_payload: bool = False) -> dict:
    return {
        'format': 'legacy-v2.1',
        'version': 'legacy',
        'flags': 0,
        'compress': None,
        'is_text': text_payload,
        'kdf_id': Config.KDF_PBKDF2,
        'iterations': Config.PBKDF2_ITERATIONS,
        'salt_len': Config.SALT_SIZE,
        'nonce_len': Config.NONCE_SIZE,
        'tag_len': Config.TAG_SIZE,
        'kdf_param_len': 4,
        'header_len': 0,
        'is_legacy': True,
    }


def _parse_format_from_bytes(data: bytes, *, text_payload: bool = False) -> dict:
    if len(data) >= 4 and data[:4] == Config.MAGIC:
        return _parse_ct02_header_from_bytes(data)
    return _parse_legacy_header(text_payload=text_payload)

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
        Format v2.2: [HEADER] + [SALT] + [NONCE] + [CIPHERTEXT] + [TAG]
        """
        ConsoleLogger.show('debug', f"Starting in-memory data encryption ({len(data)} bytes input)")
        salt = os.urandom(Config.SALT_SIZE)
        nonce = os.urandom(Config.NONCE_SIZE)
        header = _build_header(is_text=True)
        ConsoleLogger.show('debug', f"Generated salt ({Config.SALT_SIZE} bytes) and nonce ({Config.NONCE_SIZE} bytes)")
        key = self._derive_key(password, salt)
        
        ConsoleLogger.show('debug', "Initializing AES-GCM cipher")
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        ConsoleLogger.show('debug', f"Encryption complete. Ciphertext size: {len(ciphertext)} bytes, Tag size: {len(tag)} bytes")

        return header + salt + nonce + ciphertext + tag

    def decrypt_data(self, enc_data: bytes, password: str) -> Optional[bytes]:
        """
        Decrypt bytes in memory.
        Supports:
        - v2.2: [HEADER] + [SALT] + [NONCE] + [CIPHERTEXT] + [TAG]
        - legacy text payload: [SALT] + [NONCE] + [TAG] + [CIPHERTEXT]
        """
        try:
            ConsoleLogger.show('debug', f"Starting in-memory data decryption. Total input size: {len(enc_data)} bytes")
            metadata = _parse_format_from_bytes(enc_data, text_payload=True)
            overhead = metadata['header_len'] + metadata['salt_len'] + metadata['nonce_len'] + metadata['tag_len']
            if len(enc_data) < overhead:
                ConsoleLogger.show('debug', "Input data is smaller than minimum overhead")
                raise ValueError("Data too short")

            if metadata['is_legacy']:
                salt = enc_data[:metadata['salt_len']]
                nonce = enc_data[metadata['salt_len'] : metadata['salt_len'] + metadata['nonce_len']]
                tag_start = metadata['salt_len'] + metadata['nonce_len']
                tag_end = tag_start + metadata['tag_len']
                tag = enc_data[tag_start:tag_end]
                ciphertext = enc_data[tag_end:]
            else:
                start = metadata['header_len']
                salt = enc_data[start : start + metadata['salt_len']]
                nonce_start = start + metadata['salt_len']
                nonce_end = nonce_start + metadata['nonce_len']
                nonce = enc_data[nonce_start:nonce_end]
                tag = enc_data[-metadata['tag_len']:]
                ciphertext = enc_data[nonce_end:-metadata['tag_len']]
            ConsoleLogger.show('debug', f"Extracted salt, nonce, tag, and ciphertext ({len(ciphertext)} bytes)")

            key = self._derive_key(password, salt)
            ConsoleLogger.show('debug', "Initializing AES-GCM cipher for decryption")
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            ConsoleLogger.show('debug', "Verifying tag and decrypting ciphertext")
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            ConsoleLogger.show('debug', f"Decryption successful. Plaintext size: {len(decrypted)} bytes")
            return decrypted

        except (ValueError, KeyError):
            ConsoleLogger.show('error', "Decryption failed!")
            return None

    def encrypt_file(self, input_path: str, output_path: str, password: str, compress: bool = False) -> bool:
        """
        Encrypts a file using streaming (low memory usage).
        Format v2.2: [HEADER] + [SALT] + [NONCE] + [CIPHERTEXT] + [TAG]
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
            header = _build_header(compress=compress, is_text=False)

            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                # Write Header: CT02 + metadata + SALT + NONCE
                fout.write(header)
                fout.write(salt)
                fout.write(nonce)
                
                compressor = zlib.compressobj(level=9) if compress else None
                if compress:
                    ConsoleLogger.show('debug', "Compression enabled (zlib level 9)")

                desc = "[🔒] Compressing & Encrypting" if compress else "[🔒] Encrypting"
                with tqdm(total=file_size, unit='B', unit_scale=True, desc=desc) as pbar:
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
        Supports:
        - v2.2: [HEADER] + [SALT] + [NONCE] + [CIPHERTEXT] + [TAG]
        - legacy file: [SALT] + [NONCE] + [CIPHERTEXT] + [TAG]
        """
        try:
            file_size = os.path.getsize(input_path)
            ConsoleLogger.show('debug', f"Starting file decryption: {input_path} (size: {self._format_size(file_size)}) -> {output_path}")
            minimum_overhead = Config.SALT_SIZE + Config.NONCE_SIZE + Config.TAG_SIZE

            if file_size < minimum_overhead:
                ConsoleLogger.show('debug', "File size is smaller than required header + footer overhead")
                raise ValueError("File too small")

            with open(input_path, 'rb') as fin:
                prefix = fin.read(Config.FIXED_HEADER_SIZE)
                metadata = _parse_format_from_bytes(prefix, text_payload=False)
                if metadata['is_legacy']:
                    fin.seek(0)
                    effective_compress = compress
                else:
                    if len(prefix) < metadata['header_len']:
                        prefix += fin.read(metadata['header_len'] - len(prefix))
                    metadata = _parse_ct02_header_from_bytes(prefix)
                    effective_compress = metadata['compress']

                salt = fin.read(metadata['salt_len'])
                nonce = fin.read(metadata['nonce_len'])

                ConsoleLogger.show('debug', f"Read salt ({len(salt)} bytes) and nonce ({len(nonce)} bytes)")
                key = self._derive_key(password, salt)
                ConsoleLogger.show('debug', "Initializing AES-GCM cipher for decryption")
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

                ciphertext_len = file_size - metadata['header_len'] - metadata['salt_len'] - metadata['nonce_len'] - metadata['tag_len']
                ConsoleLogger.show('debug', f"Ciphertext length to decrypt: {self._format_size(ciphertext_len)}")

                desc = "[🔓] Decrypting & Decompressing" if effective_compress else "[🔓] Decrypting"
                with open(output_path, 'wb') as fout, tqdm(total=ciphertext_len, unit='B', unit_scale=True, desc=desc) as pbar:
                    decompressor = zlib.decompressobj() if effective_compress else None
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
                tag = fin.read(metadata['tag_len'])
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
            return True

        except Exception as e:
            ConsoleLogger.show('error', f"File decryption error: {e}")
            ConsoleLogger.show('error', f"Failed to decrypt: {input_path}")
            if os.path.exists(output_path):
                try: os.remove(output_path)
                except: pass
            return False

    def inspect_file(self, input_path: str) -> dict:
        if not os.path.isfile(input_path):
            raise FileNotFoundError(input_path)

        file_size = os.path.getsize(input_path)
        with open(input_path, 'rb') as fin:
            prefix = fin.read(Config.FIXED_HEADER_SIZE)

        if len(prefix) < Config.FIXED_HEADER_SIZE:
            raise ValueError("File is too small to inspect")

        if prefix[:4] != Config.MAGIC:
            raise ValueError("Unrecognized file format. Only CT02 encrypted files can be inspected reliably.")

        metadata = _parse_format_from_bytes(prefix, text_payload=False)
        if len(prefix) < metadata['header_len']:
            with open(input_path, 'rb') as fin:
                prefix = fin.read(metadata['header_len'])
            metadata = _parse_ct02_header_from_bytes(prefix)

        ciphertext_size = file_size - metadata['header_len'] - metadata['salt_len'] - metadata['nonce_len'] - metadata['tag_len']
        if ciphertext_size < 0:
            raise ValueError("Invalid encrypted file structure")

        return {
            'format': metadata['format'],
            'version': metadata['version'],
            'legacy': metadata['is_legacy'],
            'compression': 'enabled' if metadata['compress'] else ('unknown' if metadata['compress'] is None else 'disabled'),
            'kdf': 'PBKDF2-SHA256' if metadata['kdf_id'] == Config.KDF_PBKDF2 else f"unknown({metadata['kdf_id']})",
            'iterations': metadata['iterations'],
            'salt_length': metadata['salt_len'],
            'nonce_length': metadata['nonce_len'],
            'tag_length': metadata['tag_len'],
            'header_length': metadata['header_len'],
            'file_size': file_size,
            'ciphertext_size': max(ciphertext_size, 0),
        }

# =========================
# Password Strength Validator
# =========================

class PasswordStrength:
    """Password strength validator with real-time feedback."""
    
    STRENGTHS = {
        'VERY_WEAK': {'label': 'Very Weak', 'color': '\033[91m\033[1m', 'reset': '\033[0m', 'icon': '❌'},  # Red Bold
        'WEAK': {'label': 'Weak', 'color': '\033[91m', 'reset': '\033[0m', 'icon': '⚠️'},                   # Red
        'MEDIUM': {'label': 'Medium', 'color': '\033[93m', 'reset': '\033[0m', 'icon': '⚡'},                # Yellow
        'STRONG': {'label': 'Strong', 'color': '\033[92m', 'reset': '\033[0m', 'icon': '✅'},                # Green
        'VERY_STRONG': {'label': 'Very Strong', 'color': '\033[92m\033[1m', 'reset': '\033[0m', 'icon': '🔒'} # Green Bold
    }
    
    @classmethod
    def check(cls, password: str) -> dict:
        """Check password strength and return detailed results."""
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_number = bool(re.search(r'[0-9]', password))
        has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))
        length = len(password)
        
        score = 0
        
        # Length scoring
        if length >= 8:
            score += 1
        if length >= 12:
            score += 1
        if length >= 16:
            score += 1
        
        # Character type scoring
        if has_lower:
            score += 1
        if has_upper:
            score += 1
        if has_number:
            score += 1
        if has_symbol:
            score += 1
        
        # Determine strength
        if score <= 2 or length < 6:
            strength = 'VERY_WEAK'
        elif score <= 3 or length < 8:
            strength = 'WEAK'
        elif score <= 5:
            strength = 'MEDIUM'
        elif score <= 6:
            strength = 'STRONG'
        else:
            strength = 'VERY_STRONG'
        
        return {
            'score': score,
            'strength': strength,
            'has_lower': has_lower,
            'has_upper': has_upper,
            'has_number': has_number,
            'has_symbol': has_symbol,
            'length': length
        }
    
    @classmethod
    def get_indicator(cls, password: str) -> str:
        """Get formatted strength indicator with colors."""
        result = cls.check(password)
        strength = cls.STRENGTHS[result['strength']]
        return f"{strength['color']}{strength['icon']} {strength['label']}{strength['reset']}"
    
    @classmethod
    def get_char_types(cls, password: str) -> str:
        """Get formatted character types present in password."""
        result = cls.check(password)
        types = []
        check_icon = '✓'
        cross_icon = '✗'
        green = TerminalColors.Foreground.GREEN
        red = TerminalColors.Foreground.RED
        reset = TerminalColors.RESET
        
        if result['has_lower']:
            types.append(f"{green}{check_icon} Lower{reset}")
        else:
            types.append(f"{red}{cross_icon} Lower{reset}")
        
        if result['has_upper']:
            types.append(f"{green}{check_icon} Upper{reset}")
        else:
            types.append(f"{red}{cross_icon} Upper{reset}")
        
        if result['has_number']:
            types.append(f"{green}{check_icon} Number{reset}")
        else:
            types.append(f"{red}{cross_icon} Number{reset}")
        
        if result['has_symbol']:
            types.append(f"{green}{check_icon} Symbol{reset}")
        else:
            types.append(f"{red}{cross_icon} Symbol{reset}")
        
        return ' '.join(types)


def getpass_with_strength(prompt: str = "Enter Password: ") -> str:
    """Get password with real-time strength indicator."""
    import sys
    
    # Fallback for non-interactive stdin (e.g., tests/CI).
    if not sys.stdin.isatty():
        return getpass.getpass(prompt)
    
    # Write prompt
    white = TerminalColors.Foreground.WHITE
    reset = TerminalColors.RESET
    sys.stdout.write(f"{white}[{reset}🔑{white}]{reset} {prompt}")
    sys.stdout.flush()
    
    # Hide cursor
    sys.stdout.write('\033[?25l')
    sys.stdout.flush()
    
    password = ''
    
    # Check if running on Windows
    if sys.platform == 'win32':
        import msvcrt
        
        while True:
            char = msvcrt.getch().decode('utf-8', errors='ignore')
            
            if char == '\r' or char == '\n':
                # Enter pressed - show cursor and newline
                sys.stdout.write('\033[?25h\n')
                sys.stdout.flush()
                break
            elif char == '\x03':
                # Ctrl+C - show cursor
                sys.stdout.write('\033[?25h\n')
                sys.stdout.flush()
                sys.exit(0)
            elif char == '\x00' or char == '\xe0':
                # Special key prefix, read next char
                char2 = msvcrt.getch().decode('utf-8', errors='ignore')
                if char2 == 'H':  # Up arrow
                    pass
                elif char2 == 'P':  # Down arrow
                    pass
                elif char2 == 'K':  # Left arrow
                    pass
                elif char2 == 'M':  # Right arrow
                    pass
                elif char2 == '\x53':  # Delete
                    pass
            elif char == '\b' or char == '\x08':
                # Backspace
                if password:
                    password = password[:-1]
                    # Clear line and rewrite
                    strength_indicator = PasswordStrength.get_indicator(password)
                    char_types = PasswordStrength.get_char_types(password)
                    asterisks = '*' * len(password)
                    sys.stdout.write(f'\r{white}[{reset}🔑{white}]{reset} {prompt}{asterisks}  {strength_indicator}  {char_types}\033[K')
                    sys.stdout.flush()
            elif char >= ' ' and len(char) == 1:
                # Regular character
                password += char
                # Update display with strength indicator
                strength_indicator = PasswordStrength.get_indicator(password)
                char_types = PasswordStrength.get_char_types(password)
                asterisks = '*' * len(password)
                sys.stdout.write(f'\r{white}[{reset}🔑{white}]{reset} {prompt}{asterisks}  {strength_indicator}  {char_types}\033[K')
                sys.stdout.flush()
    else:
        # Unix/Linux/Mac - use termios
        import tty
        import termios
        
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        
        try:
            tty.setraw(fd)
            
            while True:
                char = sys.stdin.read(1)
                
                if char == '\r' or char == '\n':
                    # Enter pressed - show cursor
                    sys.stdout.write('\033[?25h\n')
                    sys.stdout.flush()
                    break
                elif char == '\x03':
                    # Ctrl+C - show cursor
                    sys.stdout.write('\033[?25h\n')
                    sys.stdout.flush()
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                    sys.exit(0)
                elif char == '\x04':
                    # Ctrl+D - show cursor
                    sys.stdout.write('\033[?25h\n')
                    sys.stdout.flush()
                    break
                elif char == '\x7f' or char == '\b':
                    # Backspace
                    if password:
                        password = password[:-1]
                        # Clear line and rewrite
                        strength_indicator = PasswordStrength.get_indicator(password)
                        char_types = PasswordStrength.get_char_types(password)
                        asterisks = '*' * len(password)
                        sys.stdout.write(f'\r{white}[{reset}🔑{white}]{reset} {prompt}{asterisks}  {strength_indicator}  {char_types}\033[K')
                        sys.stdout.flush()
                elif char >= ' ' and len(char) == 1:
                    # Regular character
                    password += char
                    # Update display with strength indicator
                    strength_indicator = PasswordStrength.get_indicator(password)
                    char_types = PasswordStrength.get_char_types(password)
                    asterisks = '*' * len(password)
                    sys.stdout.write(f'\r{white}[{reset}🔑{white}]{reset} {prompt}{asterisks}  {strength_indicator}  {char_types}\033[K')
                    sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    
    return password


def getpass_verify_with_strength(prompt1: str = "Enter Password: ", prompt2: str = "Verify Password: ") -> str:
    """Get password with verification and strength indicator."""
    # Fallback for non-interactive stdin (e.g., tests/CI).
    if not sys.stdin.isatty():
        password = getpass.getpass(prompt1)
        if not password:
            ConsoleLogger.show('error', 'Password cannot be empty.')
            ConsoleLogger.show('error', 'Operation aborted: No password provided')
            sys.exit(1)
        password2 = getpass.getpass(prompt2)
        if password != password2:
            ConsoleLogger.show('error', 'Passwords do not match!')
            ConsoleLogger.show('error', 'Operation aborted due to password mismatch')
            sys.exit(1)
        return password

    password = getpass_with_strength(prompt1)
    if not password:
        ConsoleLogger.show('error', 'Password cannot be empty.')
        ConsoleLogger.show('error', 'Operation aborted: No password provided')
        sys.exit(1)

    ConsoleLogger.show('info', 'Password entered by user', icon='🔑')

    white = TerminalColors.Foreground.WHITE
    reset = TerminalColors.RESET
    sys.stdout.write(f"{white}[{reset}🔄{white}]{reset} {prompt2}")
    sys.stdout.flush()

    # Hide cursor
    sys.stdout.write('\033[?25l')
    sys.stdout.flush()

    password2 = ''

    # Check if running on Windows
    if sys.platform == 'win32':
        import msvcrt

        while True:
            char = msvcrt.getch().decode('utf-8', errors='ignore')

            if char == '\r' or char == '\n':
                sys.stdout.write('\033[?25h\n')
                sys.stdout.flush()
                break
            elif char == '\x03':
                sys.stdout.write('\033[?25h\n')
                sys.stdout.flush()
                sys.exit(0)
            elif char == '\x00' or char == '\xe0':
                char2 = msvcrt.getch().decode('utf-8', errors='ignore')
                if char2 == 'H':  # Up arrow
                    pass
                elif char2 == 'P':  # Down arrow
                    pass
                elif char2 == 'K':  # Left arrow
                    pass
                elif char2 == 'M':  # Right arrow
                    pass
                elif char2 == '\x53':  # Delete
                    pass
            elif char == '\b' or char == '\x08':
                if password2:
                    password2 = password2[:-1]
                    strength_indicator = PasswordStrength.get_indicator(password2)
                    char_types = PasswordStrength.get_char_types(password2)
                    asterisks = '*' * len(password2)
                    sys.stdout.write(f'\r{white}[{reset}🔄{white}]{reset} {prompt2}{asterisks}  {strength_indicator}  {char_types}\033[K')
                    sys.stdout.flush()
            elif char >= ' ' and len(char) == 1:
                password2 += char
                strength_indicator = PasswordStrength.get_indicator(password2)
                char_types = PasswordStrength.get_char_types(password2)
                asterisks = '*' * len(password2)
                sys.stdout.write(f'\r{white}[{reset}🔄{white}]{reset} {prompt2}{asterisks}  {strength_indicator}  {char_types}\033[K')
                sys.stdout.flush()
    else:
        # Unix/Linux/Mac - use termios
        import tty
        import termios

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)

        try:
            tty.setraw(fd)

            while True:
                char = sys.stdin.read(1)

                if char == '\r' or char == '\n':
                    sys.stdout.write('\033[?25h\n')
                    sys.stdout.flush()
                    break
                elif char == '\x03':
                    sys.stdout.write('\033[?25h\n')
                    sys.stdout.flush()
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                    sys.exit(0)
                elif char == '\x04':
                    sys.stdout.write('\033[?25h\n')
                    sys.stdout.flush()
                    break
                elif char == '\x7f' or char == '\b':
                    if password2:
                        password2 = password2[:-1]
                        strength_indicator = PasswordStrength.get_indicator(password2)
                        char_types = PasswordStrength.get_char_types(password2)
                        asterisks = '*' * len(password2)
                        sys.stdout.write(f'\r{white}[{reset}🔄{white}]{reset} {prompt2}{asterisks}  {strength_indicator}  {char_types}\033[K')
                        sys.stdout.flush()
                elif char >= ' ' and len(char) == 1:
                    password2 += char
                    strength_indicator = PasswordStrength.get_indicator(password2)
                    char_types = PasswordStrength.get_char_types(password2)
                    asterisks = '*' * len(password2)
                    sys.stdout.write(f'\r{white}[{reset}🔄{white}]{reset} {prompt2}{asterisks}  {strength_indicator}  {char_types}\033[K')
                    sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    if password != password2:
        ConsoleLogger.show('error', 'Passwords do not match!')
        ConsoleLogger.show('error', 'Operation aborted due to password mismatch')
        sys.exit(1)

    return password


# =========================
# CLI Logic
# =========================

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=Config.DESCRIPTION,
        epilog=(
            "Notes:\n"
            "  - Wildcards are supported; with -r, patterns like .\\temp\\*.txt are expanded recursively\n"
            "    (equivalent to .\\temp\\**\\*.txt).\n"
            "  - Password prompts show a live strength indicator."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('-e', '--encrypt', action='store_true', help='Encrypt mode (default)')
    mode_group.add_argument('-d', '--decrypt', action='store_true', help='Decrypt mode')
    mode_group.add_argument('--inspect', action='store_true', help='Inspect encrypted file metadata')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--text', help='Text to process')
    group.add_argument('-f', '--file', help='File path, directory, or wildcard pattern (e.g., "*.md", "temp\\*.txt")')
    
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-p', '--password', required=False, help='Password (optional; prompt includes strength indicator)')
    parser.add_argument('-c', '--compress', action='store_true', help='Enable compression')
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursively process directories or wildcard patterns (uses ** for subfolders)')
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

    if args.inspect and args.text:
        ConsoleLogger.show('error', '--inspect only supports --file input')
        sys.exit(1)

    # Enable logging FIRST if --log flag is set
    if args.log:
        ConsoleLogger.LOG_ENABLED = True

    # Record start time
    start_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    ConsoleLogger.show('info', f"Session started at {start_timestamp}", icon='🕐')

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

    file_list = None
    if args.file:
        has_wildcard = any(ch in args.file for ch in ['*', '?', '[', ']'])
        if has_wildcard:
            if args.recursive:
                if '**' in args.file:
                    pattern = args.file
                else:
                    dir_part = os.path.dirname(args.file)
                    base_part = os.path.basename(args.file)
                    if dir_part in ['', '.']:
                        pattern = os.path.join('**', base_part)
                    else:
                        pattern = os.path.join(dir_part, '**', base_part)
                file_list = glob.glob(pattern, recursive=True)
            else:
                file_list = glob.glob(args.file, recursive=False)
            file_list = [f for f in file_list if os.path.isfile(f)]
            if not file_list:
                ConsoleLogger.show('error', f"No files matched pattern: {args.file}")
                ConsoleLogger.show('error', "Operation failed: No matching files")
                sys.exit(1)
        else:
            file_list = [args.file]

    if args.inspect and args.file:
        target = file_list[0] if file_list else args.file
        try:
            details = engine.inspect_file(target)
        except FileNotFoundError:
            ConsoleLogger.show('error', f"File not found: {target}")
            ConsoleLogger.show('error', "Operation failed: File does not exist")
            sys.exit(1)
        except ValueError as exc:
            ConsoleLogger.show('error', f"Inspect failed: {exc}")
            ConsoleLogger.show('error', f"File is not a supported encrypted file: {target}")
            sys.exit(1)

        ConsoleLogger.show('info', f"Format: {details['format']}", icon='🔍')
        ConsoleLogger.show('info', f"Version: {details['version']}", icon='📜')
        ConsoleLogger.show('info', f"Legacy: {'yes' if details['legacy'] else 'no'}", icon='🕰️')
        ConsoleLogger.show('info', f"Compression: {details['compression']}", icon='🗜️')
        ConsoleLogger.show('info', f"KDF: {details['kdf']}", icon='🧬')
        ConsoleLogger.show('info', f"Iterations: {details['iterations']}", icon='🔁')
        ConsoleLogger.show('info', f"Salt length: {details['salt_length']}", icon='🧂')
        ConsoleLogger.show('info', f"Nonce length: {details['nonce_length']}", icon='🎲')
        ConsoleLogger.show('info', f"Tag length: {details['tag_length']}", icon='🏷️')
        ConsoleLogger.show('info', f"Header length: {details['header_length']}", icon='🧱')
        ConsoleLogger.show('info', f"File size: {details['file_size']} bytes", icon='📦')
        ConsoleLogger.show('info', f"Ciphertext size: {details['ciphertext_size']} bytes", icon='🔐')
        end_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        ConsoleLogger.show('info', f"Session ended at {end_timestamp}", icon='🏁')
        if ConsoleLogger.LOG_ENABLED:
            ConsoleLogger.show('info', "="*80, show_console=False, log_file=True)
        return

    if args.text:
        mode_str = "decrypt" if args.decrypt else "encrypt"
        compression_str = "disabled"  # Compression not available for text mode
        ConsoleLogger.show('info', f"Mode: {mode_str}", icon='🔐' if not args.decrypt else '🔓')
        ConsoleLogger.show('info', f"Compression: {compression_str}", icon='📦')
        ConsoleLogger.show('info', "Processing text...", icon='💬')
        ConsoleLogger.show('info', f"Input text length: {len(args.text)} characters", log_file=False)
    elif args.file:
        ConsoleLogger.show('debug', f"File specified: {args.file}")
        if not os.path.exists(args.file) and not any(ch in args.file for ch in ['*', '?', '[', ']']):
            ConsoleLogger.show('error', f"File not found: {args.file}")
            ConsoleLogger.show('error', "Operation failed: File does not exist")
            ConsoleLogger.show('error', "Please check the file path and try again")
            sys.exit(1)

        is_dir = os.path.isdir(args.file)
        if is_dir and not args.recursive:
            ConsoleLogger.show('error', "Path is a directory. Use -r/--recursive to process directories.")
            ConsoleLogger.show('error', "Operation aborted: Directory specified without --recursive flag")
            sys.exit(1)

        mode_str = "decrypt" if args.decrypt else "encrypt"
        compression_str = "enabled" if args.compress else "disabled"
        ConsoleLogger.show('info', f"Mode: {mode_str}", icon='🔐' if not args.decrypt else '🔓')
        ConsoleLogger.show('info', f"Compression: {compression_str}", icon='📦')
        if is_dir and args.recursive:
            ConsoleLogger.show('info', f"Processing directory: {args.file}", icon='📁')
            ConsoleLogger.show('info', f"{'Encrypting' if not args.decrypt else 'Decrypting'} directory: {args.file}", icon='🔒' if not args.decrypt else '🔓')
            ConsoleLogger.show('info', "Recursive mode: enabled", icon='🔄')
        elif not is_dir:
            if file_list and len(file_list) > 1:
                ConsoleLogger.show('info', f"Processing files: {len(file_list)}", icon='📄')
            else:
                target = file_list[0] if file_list else args.file
                input_size = os.path.getsize(target)
                ConsoleLogger.show('info', f"Processing file: {target} ({engine._format_size(input_size)})", icon='📄')

    # Secure Password Input with Strength Indicator
    if not args.inspect and not args.password:
        # Only verify password when encrypting (not needed for decrypting)
        if not args.decrypt:
            args.password = getpass_verify_with_strength()
            ConsoleLogger.show('info', 'Password verification entered', icon='🔄')
        else:
            args.password = getpass_with_strength()
            ConsoleLogger.show('info', 'Password entered by user', icon='🔑')
    elif not args.inspect:
        ConsoleLogger.show('debug', "Password provided via command line")

    if args.text:
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

    elif args.file:
        # Recursive Directory Processing
        if args.recursive and os.path.isdir(args.file):
            input_dir = args.file
            mode_str = "decrypt" if args.decrypt else "encrypt"
            compression_str = "enabled" if args.compress else "disabled"
            lock_emoji = "🔓" if args.decrypt else "🔐"
            green = TerminalColors.Foreground.GREEN
            yellow = TerminalColors.Foreground.YELLOW
            blue = TerminalColors.Foreground.BLUE

            ConsoleLogger.show('debug', "Recursive mode enabled")

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
                            ConsoleLogger.show('success', f"File encrypted: {out_path} ({engine._format_size(os.path.getsize(out_path))})", icon='📄')
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
                            ConsoleLogger.show('success', f"File decrypted: {out_path} ({engine._format_size(os.path.getsize(out_path))})", icon='📄')
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

        elif os.path.exists(args.file) or (file_list and len(file_list) > 0):
            targets = file_list if file_list else [args.file]
            success_count = 0
            fail_count = 0
            start_time = time.time()

            for target in targets:
                if os.path.isdir(target):
                    continue
                if args.output and len(targets) == 1:
                    output_file = args.output
                else:
                    if not args.decrypt:
                        output_file = target + '.enc'
                    else:
                        output_file = os.path.splitext(target)[0] + '.dec'
                ok = engine.encrypt_file(target, output_file, args.password, args.compress) if not args.decrypt else engine.decrypt_file(target, output_file, args.password, args.compress)
                if ok:
                    success_count += 1
                    ConsoleLogger.show('success', f"File {'encrypted' if not args.decrypt else 'decrypted'}: {output_file} ({engine._format_size(os.path.getsize(output_file))})", icon='📄')
                else:
                    fail_count += 1

            elapsed_time = time.time() - start_time
            total_ops = success_count + fail_count

            ConsoleLogger.show('success', f"{'Decryption' if args.decrypt else 'Encryption'} completed successfully", icon='✅')
            if total_ops == 1 and success_count == 1:
                ConsoleLogger.show('info', "Operations completed: 1/1", icon='✔️')
            else:
                ConsoleLogger.show('info', f"Operations completed: {success_count}/{total_ops}", icon='✔️')
            ConsoleLogger.show('info', f"Total time: {elapsed_time:.2f}s", icon='⏱️')

            if fail_count > 0:
                sys.exit(1)
        else:
            ConsoleLogger.show('error', f"File not found: {args.file}")
            ConsoleLogger.show('error', f"Operation failed: File does not exist")
            ConsoleLogger.show('error', "Please check the file path and try again")
            sys.exit(1)

    # Record end time
    end_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    ConsoleLogger.show('info', f"Session ended at {end_timestamp}", icon='🏁')

    # Write separator line and end timestamp to log file at the end of session
    if ConsoleLogger.LOG_ENABLED:
        ConsoleLogger.show('info', "="*80, show_console=False, log_file=True)

if __name__ == '__main__':
    main()
