#!/usr/bin/env python3
"""
Cryptographic Tool for File and Text Encryption/Decryption.
Refactored version with AES-GCM and Streaming I/O.
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import random
import sys
import time
import zlib
import getpass
import io
import re
import glob
import tempfile
from enum import StrEnum
from typing import Optional, List

# Third-party imports
try:
	from tqdm import tqdm
	from Crypto.Cipher import AES
except ImportError:
	print("Error: Missing dependencies. Please install 'pycryptodome' and 'tqdm'.")
	sys.exit(1)

try:
	import argon2.low_level as argon2_low

	ARGON2_AVAILABLE = True
except ImportError:
	ARGON2_AVAILABLE = False

try:
	import qrcode

	QRCODE_AVAILABLE = True
except ImportError:
	QRCODE_AVAILABLE = False

try:
	from blessed import Terminal

	BLESSED_AVAILABLE = True
except ImportError:
	BLESSED_AVAILABLE = False


# Reconfigure stdout/stderr to use UTF-8 encoding (supports emojis)
def ensure_utf8(stream):
	if stream.encoding != 'utf-8':
		return io.TextIOWrapper(stream.buffer, encoding='utf-8', errors='replace')
	return stream


sys.stdout = ensure_utf8(sys.stdout)
sys.stderr = ensure_utf8(sys.stderr)

# =========================
# Shamir's Secret Sharing
# =========================


def gf256_mul(a, b):
	result = 0
	while b:
		if b & 1:
			result ^= a
		a = (a << 1) ^ (0x11B if a & 0x80 else 0)
		b >>= 1
	return result & 0xFF


def gf256_exp(base, exp):
	result = 1
	for _ in range(exp):
		result = gf256_mul(result, base)
	return result


def gf256_inv(a):
	if a == 0:
		return 0
	return gf256_exp(a, 254)


def gf256_div(a, b):
	if b == 0:
		raise ValueError('Division by zero')
	return gf256_mul(a, gf256_inv(b))


class ShamirSecretSharing:
	@classmethod
	def generate_shares(cls, secret, num_shares, threshold):
		if threshold > num_shares:
			raise ValueError('Threshold cannot exceed number of shares')
		if threshold < 2:
			raise ValueError('Threshold must be at least 2')
		if len(secret) == 0:
			raise ValueError('Secret cannot be empty')

		coeffs = [os.urandom(1)[0] for _ in range(threshold - 1)]

		shares = []
		for i in range(num_shares):
			share = bytearray(len(secret) + 1)
			share[0] = i + 1
			x = i + 1

			for j in range(len(secret)):
				y = secret[j]
				for deg in range(1, threshold):
					y ^= gf256_mul(coeffs[deg - 1], gf256_exp(x, deg))
				share[j + 1] = y

			shares.append(bytes(share))

		return shares

	@classmethod
	def recover_secret(cls, shares):
		if len(shares) < 2:
			raise ValueError('At least 2 shares required for recovery')
		if len({share[0] for share in shares}) != len(shares):
			raise ValueError('Duplicate shares are not allowed for recovery')

		secret_length = len(shares[0]) - 1
		secret = bytearray(secret_length)

		for j in range(secret_length):
			x_vals = [s[0] for s in shares]
			y_vals = [s[j + 1] for s in shares]

			result = 0
			for i in range(len(shares)):
				num = 1
				den = 1
				for m in range(len(shares)):
					if m != i:
						num = gf256_mul(num, x_vals[m])
						den = gf256_mul(den, x_vals[m] ^ x_vals[i])
				li = gf256_div(num, den)
				result ^= gf256_mul(y_vals[i], li)

			secret[j] = result

		return bytes(secret)


# =========================
# Configuration
# =========================


class Config:
	"""Configuration constants."""

	AUTHOR = 'Center For Cyber Intelligence'
	DESCRIPTION = 'Crypt Tools (AES-GCM Edition)'
	VERSION = '2.6.0'

	# File format
	MAGIC = b'CT02'
	FORMAT_VERSION = 2
	FLAG_COMPRESS = 0x01
	FLAG_TEXT = 0x02
	FLAG_KEYFILE = 0x04
	FLAG_THRESHOLD = 0x08
	THRESHOLD_MAGIC = b'CTTH'
	KDF_PBKDF2 = 0x01
	KDF_ARGON2 = 0x02
	FIXED_HEADER_SIZE = 16

	# Hidden-volume container: [CT02_outer][CT02_hidden][FOOTER_MAGIC][uint64_be outer_total_len]
	CONTAINER_FOOTER_MAGIC = b'CTHV'
	CONTAINER_FOOTER_SIZE = 12

	# Argon2id defaults (recommended for password hashing)
	ARGON2_MEMORY_COST = 65536  # 64 MB
	ARGON2_TIME_COST = 3  # iterations
	ARGON2_PARALLELISM = 4

	# AES-GCM Constants
	KEY_SIZE = 32  # 256 bits
	SALT_SIZE = 16  # 128 bits
	NONCE_SIZE = 12  # 96 bits (Standard for GCM)
	TAG_SIZE = 16  # 128 bits (Standard for GCM)

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


def _help_use_color() -> bool:
	return sys.stdout.isatty()


def _help_style(text: str, color: str) -> str:
	if not _help_use_color():
		return text
	return f'{color}{text}{TerminalColors.RESET}'


def _help_heading(icon: str, title: str, color: str = TerminalColors.Foreground.CYAN) -> str:
	return _help_style(f'{icon} {title}', color)


def render_qr_code(data: str) -> str:
	"""Render a string as a terminal-friendly QR code."""
	if not QRCODE_AVAILABLE:
		raise RuntimeError('QR code support is not available. Please install the qrcode package.')

	qr = qrcode.QRCode(border=1)
	qr.add_data(data)
	qr.make(fit=True)
	matrix = qr.get_matrix()
	lines = []
	for row_index in range(0, len(matrix), 2):
		top_row = matrix[row_index]
		bottom_row = matrix[row_index + 1] if row_index + 1 < len(matrix) else [False] * len(top_row)
		line = []
		for top_cell, bottom_cell in zip(top_row, bottom_row):
			if top_cell and bottom_cell:
				line.append('█')
			elif top_cell:
				line.append('▀')
			elif bottom_cell:
				line.append('▄')
			else:
				line.append(' ')
		lines.append(''.join(line).rstrip())
	return '\n'.join(lines)


def show_qr_code(data: str) -> None:
	"""Print a rendered QR code to stdout."""
	ConsoleLogger.show('info', 'QR Code Output:', icon='🔳', log_file=False)
	print(render_qr_code(data))


def interactive_file_selector(start_path: str = '.') -> Optional[str]:
	"""Open a simple terminal file selector and return the chosen path."""
	if not BLESSED_AVAILABLE:
		raise RuntimeError(
			'Interactive file selection is not available. Please install the blessed package.'
		)
	if not sys.stdin.isatty() or not sys.stdout.isatty():
		raise RuntimeError('Interactive file selection requires an interactive terminal.')

	term = Terminal()
	current_dir = os.path.abspath(start_path if os.path.isdir(start_path) else os.path.dirname(start_path) or '.')
	selected_index = 0
	scroll_offset = 0
	entries = []

	def build_entries(directory: str):
		parent_dir = os.path.dirname(directory)
		items = [
			{
				'label': f'📁 [.] Select current directory: {directory}',
				'path': directory,
				'action': 'select',
			},
			{'label': '⬆️  [..] Go to parent directory', 'path': parent_dir, 'action': 'up'},
		]
		for name in sorted(os.listdir(directory), key=lambda item: (not os.path.isdir(os.path.join(directory, item)), item.lower())):
			full_path = os.path.join(directory, name)
			if os.path.isdir(full_path):
				items.append({'label': f'📁 {name}', 'path': full_path, 'action': 'enter'})
			else:
				items.append({'label': f'📄 {name}', 'path': full_path, 'action': 'select'})
		return items

	def render_screen():
		nonlocal scroll_offset
		height = max(term.height - 6, 5)
		scroll_offset = min(scroll_offset, max(len(entries) - height, 0))
		if selected_index < scroll_offset:
			scroll_offset = selected_index
		if selected_index >= scroll_offset + height:
			scroll_offset = selected_index - height + 1

		lines = [
			term.clear,
			term.bold_cyan('Crypt Tools Interactive File Selection'),
			term.white(f'Current directory: {current_dir}'),
			term.yellow('Use ↑/↓ to move, Enter to open/select, Backspace/← for parent, q to cancel.'),
			'',
		]
		visible_entries = entries[scroll_offset : scroll_offset + height]
		for idx, entry in enumerate(visible_entries, start=scroll_offset):
			prefix = '➜ ' if idx == selected_index else '  '
			style = term.black_on_cyan if idx == selected_index else (lambda text: text)
			lines.append(style(f'{prefix}{entry["label"]}'))
		print('\n'.join(lines), end='', flush=True)

	with term.fullscreen(), term.cbreak(), term.hidden_cursor():
		while True:
			entries = build_entries(current_dir)
			selected_index = max(0, min(selected_index, len(entries) - 1))
			render_screen()
			key = term.inkey()
			if key.name in ['KEY_UP'] and selected_index > 0:
				selected_index -= 1
			elif key.name in ['KEY_DOWN'] and selected_index < len(entries) - 1:
				selected_index += 1
			elif key.name in ['KEY_LEFT', 'KEY_BACKSPACE']:
				current_dir = os.path.dirname(current_dir)
				selected_index = 0
				scroll_offset = 0
			elif key.name == 'KEY_ENTER' or key == '\n' or key == '\r':
				entry = entries[selected_index]
				if entry['action'] == 'up':
					current_dir = entry['path']
					selected_index = 0
					scroll_offset = 0
				elif entry['action'] == 'enter':
					current_dir = entry['path']
					selected_index = 0
					scroll_offset = 0
				else:
					print(term.clear, end='', flush=True)
					return entry['path']
			elif str(key).lower() in ['q', '\x1b']:
				print(term.clear, end='', flush=True)
				return None


class ConsoleLogger:
	"""
	Unified console and file logging with emojis and colors.
	All output goes through a single 'show' method.
	"""

	DEBUG_ENABLED = False
	LOG_ENABLED = False
	LOG_FILE = 'crypt_tools.log'

	# Output style definitions: icon + color for each level
	STYLES = {
		'info': {'icon': 'ℹ️', 'color': TerminalColors.Foreground.BLUE},
		'success': {'icon': '✅', 'color': TerminalColors.Foreground.GREEN},
		'error': {'icon': '❌', 'color': TerminalColors.Foreground.RED},
		'warning': {'icon': '⚠️', 'color': TerminalColors.Foreground.YELLOW},
		'debug': {'icon': '🐞', 'color': TerminalColors.Foreground.MAGENTA},
		'important': {'icon': '📌', 'color': TerminalColors.Foreground.MAGENTA},
	}

	@staticmethod
	def show(
		level: str, message: str, icon: str = None, show_console: bool = True, log_file: bool = True
	) -> None:
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
		print(f'{white}[{reset}{icon}{white}]{reset} {color}{message}{reset}')

	@staticmethod
	def _write_to_file(level: str, icon: str, message: str) -> None:
		"""Write timestamped log entry to file with level and emoji."""
		timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
		log_entry = f'[{timestamp}] [{level.upper()}] [{icon}] {message}\n'
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
    """,
	]

	@classmethod
	def show(cls):
		"""Displays a random banner."""
		banner = cls.__BANNER[random.randint(0, len(cls.__BANNER) - 1)]
		cyan = TerminalColors.Foreground.CYAN
		reset = TerminalColors.RESET
		print(f'{cyan}{banner}{reset}')
		print(f'{cyan}{Config.DESCRIPTION} v{Config.VERSION}{reset}')
		print(f'{cyan}Author: {Config.AUTHOR}{reset}\n')


def _uint32_to_bytes(value: int) -> bytes:
	return value.to_bytes(4, byteorder='big', signed=False)


def _bytes_to_uint32(raw: bytes) -> int:
	return int.from_bytes(raw, byteorder='big', signed=False)


def _single_password_arg(password_value) -> str:
	"""Normalize a CLI password argument to a single password string."""
	if isinstance(password_value, list):
		return password_value[0] if password_value else ''
	return password_value or ''


CONFIG_FILENAMES = (
	'.crypt_tools.conf',
	'.crypt_tools.json',
	'.crypt_tools.yml',
	'.crypt_tools.yaml',
)

CONFIG_KEY_ALIASES = {
	'compress': 'compress',
	'compression': 'compress',
	'default_compression': 'compress',
	'kdf': 'kdf',
	'default_kdf': 'kdf',
	'iterations': 'iterations',
	'default_iterations': 'iterations',
	'log': 'log',
	'logging': 'log',
	'log_enabled': 'log',
	'debug': 'debug',
	'debug_enabled': 'debug',
	'password': 'password',
	'default_password': 'password',
	'password_outer': 'password_outer',
	'default_password_outer': 'password_outer',
	'password_hidden': 'password_hidden',
	'default_password_hidden': 'password_hidden',
	'keyfile': 'keyfile',
	'default_keyfile': 'keyfile',
	'threshold': 'threshold',
}

ENV_KEY_ALIASES = {
	'CRYPT_TOOLS_COMPRESS': 'compress',
	'CRYPT_TOOLS_COMPRESSION': 'compress',
	'CRYPT_TOOLS_KDF': 'kdf',
	'CRYPT_TOOLS_ITERATIONS': 'iterations',
	'CRYPT_TOOLS_LOG': 'log',
	'CRYPT_TOOLS_LOG_ENABLED': 'log',
	'CRYPT_TOOLS_DEBUG': 'debug',
	'CRYPT_TOOLS_DEBUG_ENABLED': 'debug',
	'CRYPT_TOOLS_PASSWORD': 'password',
	'CRYPT_TOOLS_PASSWORD_OUTER': 'password_outer',
	'CRYPT_TOOLS_PASSWORD_HIDDEN': 'password_hidden',
	'CRYPT_TOOLS_KEYFILE': 'keyfile',
	'CRYPT_TOOLS_THRESHOLD': 'threshold',
}

CLI_OPTION_ALIASES = {
	'--compress': 'compress',
	'-c': 'compress',
	'--kdf': 'kdf',
	'--iterations': 'iterations',
	'--log': 'log',
	'--debug': 'debug',
	'-p': 'password',
	'--password': 'password',
	'--password-outer': 'password_outer',
	'--password-hidden': 'password_hidden',
	'--keyfile': 'keyfile',
	'--threshold': 'threshold',
	'--config': 'config',
}


def _normalize_config_key(raw_key: str) -> Optional[str]:
	return CONFIG_KEY_ALIASES.get(raw_key.strip().lower().replace('-', '_'))


def _parse_bool(value):
	if isinstance(value, bool):
		return value
	if isinstance(value, int):
		return bool(value)
	normalized = str(value).strip().lower()
	if normalized in {'1', 'true', 'yes', 'on'}:
		return True
	if normalized in {'0', 'false', 'no', 'off'}:
		return False
	raise ValueError(f'Invalid boolean value: {value}')


def _coerce_config_value(key: str, value):
	if key in {'compress', 'log', 'debug'}:
		return _parse_bool(value)
	if key in {'iterations', 'threshold'}:
		return int(value)
	if key == 'kdf':
		return str(value).strip().lower()
	if key in {'password', 'password_outer', 'password_hidden', 'keyfile'}:
		return str(value)
	return value


def _parse_simple_yaml(content: str):
	data = {}
	for line in content.splitlines():
		stripped = line.strip()
		if not stripped or stripped.startswith('#'):
			continue
		if ':' not in stripped:
			raise ValueError(f'Invalid YAML line: {line}')
		key, raw_value = stripped.split(':', 1)
		data[key.strip()] = raw_value.strip()
	return data


def _parse_simple_conf(content: str):
	data = {}
	for line in content.splitlines():
		stripped = line.strip()
		if not stripped or stripped.startswith('#') or stripped.startswith(';'):
			continue
		separator = '=' if '=' in stripped else ':'
		if separator not in stripped:
			raise ValueError(f'Invalid config line: {line}')
		key, raw_value = stripped.split(separator, 1)
		data[key.strip()] = raw_value.strip()
	return data


def _read_config_file(config_path: str):
	_, ext = os.path.splitext(config_path.lower())
	with open(config_path, encoding='utf-8') as f:
		content = f.read()

	if ext == '.json':
		parsed = json.loads(content)
	elif ext in {'.yml', '.yaml'}:
		parsed = _parse_simple_yaml(content)
	else:
		parsed = _parse_simple_conf(content)

	if not isinstance(parsed, dict):
		raise ValueError('Configuration file must contain a top-level object')

	normalized = {}
	for raw_key, raw_value in parsed.items():
		key = _normalize_config_key(str(raw_key))
		if not key:
			continue
		normalized[key] = _coerce_config_value(key, raw_value)
	return normalized


def _discover_config_path(explicit_path: Optional[str] = None):
	if explicit_path:
		return explicit_path, True

	for filename in CONFIG_FILENAMES:
		candidate = os.path.join(os.getcwd(), filename)
		if os.path.exists(candidate) and os.path.isfile(candidate):
			return candidate, False
	return None, False


def _load_runtime_defaults(explicit_config_path: Optional[str] = None):
	config_path, explicit = _discover_config_path(explicit_config_path)
	config_defaults = {}
	if config_path:
		try:
			config_defaults = _read_config_file(config_path)
		except Exception as e:
			raise ValueError(f'Failed to load config file {config_path}: {e}') from e
	elif explicit:
		raise ValueError(f'Config file not found: {explicit_config_path}')

	env_defaults = {}
	for env_key, normalized_key in ENV_KEY_ALIASES.items():
		raw_value = os.environ.get(env_key)
		if raw_value in [None, '']:
			continue
		env_defaults[normalized_key] = _coerce_config_value(normalized_key, raw_value)

	return config_path, config_defaults, env_defaults


def _detect_cli_overrides(argv=None):
	tokens = sys.argv[1:] if argv is None else list(argv)
	overrides = set()
	for token in tokens:
		if token.startswith('--'):
			flag = token.split('=', 1)[0]
			normalized = CLI_OPTION_ALIASES.get(flag)
			if normalized:
				overrides.add(normalized)
		elif token in CLI_OPTION_ALIASES:
			overrides.add(CLI_OPTION_ALIASES[token])
	return overrides


def _apply_runtime_defaults(args, cli_overrides, config_defaults, env_defaults):
	merged_defaults = dict(config_defaults)
	merged_defaults.update(env_defaults)

	if 'password' not in cli_overrides and not args.password and 'password' in merged_defaults:
		password_value = merged_defaults['password']
		args.password = password_value if isinstance(password_value, list) else [password_value]

	for attr in ['password_outer', 'password_hidden', 'keyfile', 'threshold']:
		if attr in cli_overrides:
			continue
		if getattr(args, attr) is None and attr in merged_defaults:
			setattr(args, attr, merged_defaults[attr])

	for attr in ['compress', 'log', 'debug']:
		if attr in cli_overrides:
			continue
		if attr in merged_defaults:
			setattr(args, attr, bool(merged_defaults[attr]))

	if 'kdf' not in cli_overrides and args.kdf is None and 'kdf' in merged_defaults:
		args.kdf = merged_defaults['kdf']

	if 'iterations' not in cli_overrides and args.iterations is None and 'iterations' in merged_defaults:
		args.iterations = merged_defaults['iterations']

	return args


def _build_header(
	*,
	compress: bool = False,
	is_text: bool = False,
	use_keyfile: bool = False,
	kdf_id: int = Config.KDF_PBKDF2,
	iterations: int = Config.PBKDF2_ITERATIONS,
) -> bytes:
	flags = 0
	if compress:
		flags |= Config.FLAG_COMPRESS
	if is_text:
		flags |= Config.FLAG_TEXT
	if use_keyfile:
		flags |= Config.FLAG_KEYFILE

	kdf_params = _uint32_to_bytes(iterations)
	return b''.join(
		[
			Config.MAGIC,
			bytes([Config.FORMAT_VERSION]),
			bytes([flags]),
			bytes([kdf_id]),
			b'\x00',
			bytes([Config.SALT_SIZE]),
			bytes([Config.NONCE_SIZE]),
			bytes([Config.TAG_SIZE]),
			bytes([len(kdf_params)]),
			kdf_params,
		]
	)


def _parse_ct02_header_from_bytes(data: bytes) -> dict:
	if len(data) < 12:
		raise ValueError('CT02 header too short')
	if data[:4] != Config.MAGIC:
		raise ValueError('Invalid CT02 magic')

	version = data[4]
	flags = data[5]
	kdf_id = data[6]
	salt_len = data[8]
	nonce_len = data[9]
	tag_len = data[10]
	kdf_param_len = data[11]
	header_len = 12 + kdf_param_len

	if len(data) < header_len:
		raise ValueError('Incomplete CT02 header')

	kdf_params = data[12:header_len]
	iterations = _bytes_to_uint32(kdf_params) if kdf_param_len == 4 else Config.PBKDF2_ITERATIONS

	return {
		'format': Config.MAGIC.decode('ascii'),
		'version': version,
		'flags': flags,
		'compress': bool(flags & Config.FLAG_COMPRESS),
		'is_text': bool(flags & Config.FLAG_TEXT),
		'use_keyfile': bool(flags & Config.FLAG_KEYFILE),
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
		'use_keyfile': False,
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


def parse_hidden_container_footer_from_path(path: str) -> Optional[dict]:
	"""
	Parse hidden-volume container footer from the end of a file.
	Layout: ... [CT02_outer][CT02_hidden][CTHV][uint64_be outer_total_len]
	Returns dict with outerTotalLen, hiddenStart, hiddenLen, fileSize or None.
	"""
	try:
		file_size = os.path.getsize(path)
	except OSError:
		return None

	min_blob = Config.FIXED_HEADER_SIZE + Config.SALT_SIZE + Config.NONCE_SIZE + Config.TAG_SIZE
	if file_size < min_blob * 2 + Config.CONTAINER_FOOTER_SIZE:
		return None

	with open(path, 'rb') as f:
		f.seek(-Config.CONTAINER_FOOTER_SIZE, os.SEEK_END)
		footer = f.read(Config.CONTAINER_FOOTER_SIZE)

	if len(footer) != Config.CONTAINER_FOOTER_SIZE:
		return None
	if footer[:4] != Config.CONTAINER_FOOTER_MAGIC:
		return None

	outer_total_len = int.from_bytes(footer[4:12], byteorder='big', signed=False)
	if outer_total_len <= 0 or outer_total_len >= file_size - Config.CONTAINER_FOOTER_SIZE:
		return None

	hidden_start = outer_total_len
	hidden_len = file_size - Config.CONTAINER_FOOTER_SIZE - outer_total_len
	if hidden_len < min_blob:
		return None

	with open(path, 'rb') as f:
		f.seek(hidden_start)
		magic_check = f.read(4)
		if magic_check != Config.MAGIC:
			return None

	return {
		'outerTotalLen': outer_total_len,
		'hiddenStart': hidden_start,
		'hiddenLen': hidden_len,
		'fileSize': file_size,
	}


def inspect_threshold_requirements_from_path(path: str) -> Optional[dict]:
	"""Return threshold metadata for a CT02 threshold-encrypted file, or None."""
	if not os.path.isfile(path):
		return None

	with open(path, 'rb') as fin:
		prefix = fin.read(Config.FIXED_HEADER_SIZE)

	if len(prefix) < Config.FIXED_HEADER_SIZE or prefix[:4] != Config.MAGIC:
		return None

	metadata = _parse_format_from_bytes(prefix, text_payload=False)
	if metadata['is_legacy'] or not (metadata['flags'] & Config.FLAG_THRESHOLD):
		return None

	share_counts_offset = metadata['header_len'] + metadata['salt_len'] + metadata['nonce_len']

	with open(path, 'rb') as fin:
		fin.seek(share_counts_offset)
		num_and_thresh = fin.read(2)

	if len(num_and_thresh) != 2:
		raise ValueError('Threshold metadata is incomplete')

	return {'num_passwords': num_and_thresh[0], 'threshold': num_and_thresh[1]}


def _inspect_ct02_blob_from_path(input_path: str, *, blob_start: int = 0, blob_span: Optional[int] = None) -> dict:
	"""Inspect a single CT02 blob at a given offset."""
	file_size = os.path.getsize(input_path)
	span = file_size - blob_start if blob_span is None else blob_span
	if span <= 0:
		raise ValueError('Invalid encrypted file structure')

	with open(input_path, 'rb') as fin:
		fin.seek(blob_start)
		prefix = fin.read(min(span, Config.FIXED_HEADER_SIZE))

	if len(prefix) < Config.FIXED_HEADER_SIZE:
		raise ValueError('File is too small to inspect')
	if prefix[:4] != Config.MAGIC:
		raise ValueError('Unrecognized file format. Only CT02 encrypted files can be inspected reliably.')

	metadata = _parse_format_from_bytes(prefix, text_payload=False)
	if not metadata['is_legacy'] and len(prefix) < metadata['header_len']:
		with open(input_path, 'rb') as fin:
			fin.seek(blob_start)
			prefix = fin.read(metadata['header_len'])
		metadata = _parse_ct02_header_from_bytes(prefix)

	header_len = metadata['header_len']
	salt_len = metadata['salt_len']
	nonce_len = metadata['nonce_len']
	tag_len = metadata['tag_len']

	result = {
		'format': metadata['format'],
		'version': metadata['version'],
		'legacy': metadata['is_legacy'],
		'compression': 'enabled' if metadata['compress'] else 'disabled',
		'keyfile': 'enabled' if metadata.get('use_keyfile', False) else 'disabled',
		'kdf': 'PBKDF2-SHA256'
		if metadata['kdf_id'] == Config.KDF_PBKDF2
		else (
			'Argon2id'
			if metadata['kdf_id'] == Config.KDF_ARGON2
			else f'unknown({metadata["kdf_id"]})'
		),
		'iterations': metadata['iterations'],
		'saltLength': salt_len,
		'nonceLength': nonce_len,
		'tagLength': tag_len,
		'headerLength': header_len,
		'blobSize': span,
		'thresholdMode': 'enabled' if metadata['flags'] & Config.FLAG_THRESHOLD else 'disabled',
	}

	metadata_bytes = header_len + salt_len + nonce_len + tag_len
	if metadata['flags'] & Config.FLAG_THRESHOLD:
		with open(input_path, 'rb') as fin:
			fin.seek(blob_start + header_len + salt_len + nonce_len)
			num_and_thresh = fin.read(2)
		if len(num_and_thresh) != 2:
			raise ValueError('Threshold metadata is incomplete')

		num_passwords = num_and_thresh[0]
		threshold_required = num_and_thresh[1]
		share_size = Config.SALT_SIZE + Config.NONCE_SIZE + Config.KEY_SIZE + 1 + Config.TAG_SIZE
		share_metadata_size = 2 + (num_passwords * share_size)
		metadata_bytes += share_metadata_size
		result['numPasswords'] = num_passwords
		result['thresholdRequired'] = threshold_required
		result['shareMetadataSize'] = share_metadata_size

	ciphertext_size = span - metadata_bytes
	if ciphertext_size < 0:
		raise ValueError('Invalid encrypted file structure')

	result['ciphertextSize'] = ciphertext_size
	return result


# =========================
# Key File Functions
# =========================


def generate_keyfile(output_path: str, key_size: int = 16) -> bool:
	"""Generate a MEGA-style textual recovery key securely."""
	try:
		key = os.urandom(key_size)
		recovery_key = base64.urlsafe_b64encode(key).decode('ascii').rstrip('=')
		with open(output_path, 'w', encoding='utf-8', newline='\n') as f:
			f.write(f'{recovery_key}\n')
		ConsoleLogger.show('success', f'Recovery key file generated: {output_path}')
		ConsoleLogger.show('info', f'Key size: {key_size} bytes ({key_size * 8} bits)')
		return True
	except Exception as e:
		ConsoleLogger.show('error', f'Failed to generate key file: {e}')
		return False


def read_keyfile(keyfile_path: str) -> Optional[bytes]:
	"""Read and validate a key file or textual recovery key."""
	try:
		if not os.path.exists(keyfile_path):
			raise FileNotFoundError(f'Key file not found: {keyfile_path}')

		with open(keyfile_path, 'rb') as f:
			raw_data = f.read()

		if len(raw_data) > 4096:
			raise ValueError(f'Key file too large: {len(raw_data)} bytes (maximum 4096)')

		key_data = raw_data
		try:
			text_data = raw_data.decode('utf-8').strip()
			if text_data:
				if not re.fullmatch(r'[A-Za-z0-9_-]+', text_data):
					raise ValueError('Recovery key contains invalid characters')
				padding = '=' * ((4 - len(text_data) % 4) % 4)
				key_data = base64.b64decode(text_data + padding, altchars=b'-_', validate=True)
		except UnicodeDecodeError:
			key_data = raw_data
		except binascii.Error as e:
			raise ValueError(f'Invalid recovery key format: {e}') from e

		if len(key_data) < 16:
			raise ValueError(f'Key file too small: {len(key_data)} bytes (minimum 16)')

		if len(key_data) > 1024:
			raise ValueError(f'Key file too large: {len(key_data)} bytes (maximum 1024)')

		ConsoleLogger.show('debug', f'Read key file: {keyfile_path} ({len(key_data)} bytes)')
		return key_data

	except Exception as e:
		ConsoleLogger.show('error', f'Failed to read key file: {e}')
		return None


def combine_password_and_keyfile(password: str, keyfile_data: bytes) -> str:
	"""Combine password and keyfile data for two-factor encryption."""
	combined = password.encode('utf-8') + keyfile_data
	hashed = hashlib.sha256(combined).digest()
	return hashed.hex()


# =========================
# Core Logic (Engine)
# =========================


class CryptoEngine:
	"""
	Handles cryptographic operations using AES-GCM.
	Includes methods for key derivation, chunk processing, and file handling.
	"""

	def _derive_key(
		self,
		password: str,
		salt: bytes,
		keyfile_data: Optional[bytes] = None,
		kdf_type: int = Config.KDF_PBKDF2,
		iterations: int = Config.PBKDF2_ITERATIONS,
	) -> bytes:
		"""Derive a 256-bit key from password (and optional keyfile) and salt using PBKDF2 or Argon2."""
		if kdf_type == Config.KDF_ARGON2:
			if not ARGON2_AVAILABLE:
				ConsoleLogger.show(
					'error',
					'Argon2 is not available. Please install argon2-cffi: pip install argon2-cffi',
				)
				raise RuntimeError('Argon2 support not installed')
			ConsoleLogger.show('debug', f'Deriving key with Argon2id ({iterations} iterations)')

			if keyfile_data:
				ConsoleLogger.show('debug', 'Using key file for key derivation')
				derived_from = combine_password_and_keyfile(password, keyfile_data)
			else:
				derived_from = password

			key = argon2_low.hash_secret_raw(
				derived_from.encode('utf-8'),
				salt,
				time_cost=iterations,
				memory_cost=Config.ARGON2_MEMORY_COST,
				parallelism=Config.ARGON2_PARALLELISM,
				hash_len=Config.KEY_SIZE,
				type=argon2_low.Type.ID,
			)
			return key

		ConsoleLogger.show('debug', f'Deriving key with PBKDF2 ({iterations} iterations)')

		if keyfile_data:
			ConsoleLogger.show('debug', 'Using key file for key derivation')
			derived_from = combine_password_and_keyfile(password, keyfile_data)
		else:
			derived_from = password

		return hashlib.pbkdf2_hmac(
			'sha256',
			derived_from.encode('utf-8'),
			salt,
			iterations,
			dklen=Config.KEY_SIZE,
		)

	def _format_size(self, size: int) -> str:
		"""Human readable file size."""
		for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
			if size < 1024:
				return f'{size:.2f}{unit}'
			size /= 1024
		return f'{size:.2f}PB'

	def encrypt_data(
		self,
		data: bytes,
		password: str,
		keyfile_data: Optional[bytes] = None,
		kdf_type: int = Config.KDF_PBKDF2,
		iterations: int = Config.PBKDF2_ITERATIONS,
	) -> bytes:
		"""
		Encrypt bytes in memory.
		Format v2.2: [HEADER] + [SALT] + [NONCE] + [CIPHERTEXT] + [TAG]
		"""
		ConsoleLogger.show('debug', f'Starting in-memory data encryption ({len(data)} bytes input)')
		salt = os.urandom(Config.SALT_SIZE)
		nonce = os.urandom(Config.NONCE_SIZE)
		use_keyfile = keyfile_data is not None
		header = _build_header(
			is_text=True, use_keyfile=use_keyfile, kdf_id=kdf_type, iterations=iterations
		)
		ConsoleLogger.show(
			'debug',
			f'Generated salt ({Config.SALT_SIZE} bytes) and nonce ({Config.NONCE_SIZE} bytes)',
		)
		key = self._derive_key(password, salt, keyfile_data, kdf_type, iterations)

		ConsoleLogger.show('debug', 'Initializing AES-GCM cipher')
		cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
		ciphertext, tag = cipher.encrypt_and_digest(data)
		ConsoleLogger.show(
			'debug',
			f'Encryption complete. Ciphertext size: {len(ciphertext)} bytes, Tag size: {len(tag)} bytes',
		)

		return header + salt + nonce + ciphertext + tag

	def decrypt_data(
		self, enc_data: bytes, password: str, keyfile_data: Optional[bytes] = None
	) -> Optional[bytes]:
		"""
		Decrypt bytes in memory.
		Supports:
		- v2.2: [HEADER] + [SALT] + [NONCE] + [CIPHERTEXT] + [TAG]
		- legacy text payload: [SALT] + [NONCE] + [TAG] + [CIPHERTEXT]
		"""
		try:
			ConsoleLogger.show(
				'debug',
				f'Starting in-memory data decryption. Total input size: {len(enc_data)} bytes',
			)
			metadata = _parse_format_from_bytes(enc_data, text_payload=True)
			overhead = (
				metadata['header_len']
				+ metadata['salt_len']
				+ metadata['nonce_len']
				+ metadata['tag_len']
			)
			if len(enc_data) < overhead:
				ConsoleLogger.show('debug', 'Input data is smaller than minimum overhead')
				raise ValueError('Data too short')

			if metadata['is_legacy']:
				salt = enc_data[: metadata['salt_len']]
				nonce = enc_data[
					metadata['salt_len'] : metadata['salt_len'] + metadata['nonce_len']
				]
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
				tag = enc_data[-metadata['tag_len'] :]
				ciphertext = enc_data[nonce_end : -metadata['tag_len']]
			ConsoleLogger.show(
				'debug', f'Extracted salt, nonce, tag, and ciphertext ({len(ciphertext)} bytes)'
			)

			use_keyfile = metadata.get('use_keyfile', False)
			kdf_type = metadata.get('kdf_id', Config.KDF_PBKDF2)
			iterations = metadata.get('iterations', Config.PBKDF2_ITERATIONS)

			if use_keyfile and not keyfile_data:
				ConsoleLogger.show(
					'warning',
					'Encrypted with key file but none provided. Attempting password-only decryption.',
				)

			key = self._derive_key(
				password, salt, keyfile_data if use_keyfile else None, kdf_type, iterations
			)
			ConsoleLogger.show('debug', 'Initializing AES-GCM cipher for decryption')
			cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

			ConsoleLogger.show('debug', 'Verifying tag and decrypting ciphertext')
			decrypted = cipher.decrypt_and_verify(ciphertext, tag)
			ConsoleLogger.show(
				'debug', f'Decryption successful. Plaintext size: {len(decrypted)} bytes'
			)
			return decrypted

		except (ValueError, KeyError):
			ConsoleLogger.show('error', 'Decryption failed!')
			return None

	def encrypt_file(
		self,
		input_path: str,
		output_path: str,
		password: str,
		compress: bool = False,
		keyfile_data: Optional[bytes] = None,
		kdf_type: int = Config.KDF_PBKDF2,
		iterations: int = Config.PBKDF2_ITERATIONS,
	) -> bool:
		"""
		Encrypts a file using streaming (low memory usage).
		Format v2.2: [HEADER] + [SALT] + [NONCE] + [CIPHERTEXT] + [TAG]
		"""
		try:
			ConsoleLogger.show('debug', f'Starting file encryption: {input_path} -> {output_path}')
			file_size = os.path.getsize(input_path)

			ConsoleLogger.show(
				'debug',
				f'Generating {Config.SALT_SIZE} bytes salt and {Config.NONCE_SIZE} bytes nonce',
			)
			salt = os.urandom(Config.SALT_SIZE)
			nonce = os.urandom(Config.NONCE_SIZE)
			use_keyfile = keyfile_data is not None
			key = self._derive_key(password, salt, keyfile_data, kdf_type, iterations)
			ConsoleLogger.show('debug', 'Initializing AES-GCM cipher')
			cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
			header = _build_header(
				compress=compress,
				is_text=False,
				use_keyfile=use_keyfile,
				kdf_id=kdf_type,
				iterations=iterations,
			)

			with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
				# Write Header: CT02 + metadata + SALT + NONCE
				fout.write(header)
				fout.write(salt)
				fout.write(nonce)

				compressor = zlib.compressobj(level=9) if compress else None
				if compress:
					ConsoleLogger.show('debug', 'Compression enabled (zlib level 9)')

				desc = '[🔒] Compressing & Encrypting' if compress else '[🔒] Encrypting'
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

				ConsoleLogger.show('debug', 'Reached end of input file')

				if compressor:
					remaining = compressor.flush()
					if remaining:
						ConsoleLogger.show(
							'debug', f'Writing remaining compressed data ({len(remaining)} bytes)'
						)
						fout.write(cipher.encrypt(remaining))

				# Calculate and write Tag at the end
				tag = cipher.digest()
				ConsoleLogger.show('debug', f'Writing authentication tag ({len(tag)} bytes)')
				fout.write(tag)

			return True

		except Exception as e:
			ConsoleLogger.show('error', f'File encryption error: {e}')
			ConsoleLogger.show('error', f'Failed to encrypt: {input_path}')
			if os.path.exists(output_path):
				os.remove(output_path)
			return False

	def decrypt_file(
		self,
		input_path: str,
		output_path: str,
		password: str,
		compress: bool = False,
		keyfile_data: Optional[bytes] = None,
		*,
		slice_start: int = 0,
		slice_end: Optional[int] = None,
	) -> bool:
		"""
		Decrypts a file using streaming.
		Supports:
		- v2.2: [HEADER] + [SALT] + [NONCE] + [CIPHERTEXT] + [TAG]
		- legacy file: [SALT] + [NONCE] + [CIPHERTEXT] + [TAG]
		Optional slice_start/slice_end decrypt one CT02 blob inside a larger file (hidden volume).
		"""
		try:
			file_size_on_disk = os.path.getsize(input_path)
			end = file_size_on_disk if slice_end is None else slice_end
			if slice_start < 0 or end > file_size_on_disk or slice_start >= end:
				raise ValueError('Invalid decrypt byte range')

			file_size = end - slice_start
			ConsoleLogger.show(
				'debug',
				f'Starting file decryption: {input_path} (blob size: {self._format_size(file_size)}) -> {output_path}',
			)
			minimum_overhead = Config.SALT_SIZE + Config.NONCE_SIZE + Config.TAG_SIZE

			if file_size < minimum_overhead:
				ConsoleLogger.show(
					'debug', 'File size is smaller than required header + footer overhead'
				)
				raise ValueError('File too small')

			with open(input_path, 'rb') as fin:
				fin.seek(slice_start)
				prefix = fin.read(Config.FIXED_HEADER_SIZE)
				metadata = _parse_format_from_bytes(prefix, text_payload=False)
				if metadata['is_legacy']:
					if slice_start != 0:
						raise ValueError('Legacy format does not support container slices')
					fin.seek(slice_start)
					effective_compress = compress
				else:
					if len(prefix) < metadata['header_len']:
						prefix += fin.read(metadata['header_len'] - len(prefix))
					metadata = _parse_ct02_header_from_bytes(prefix)
					effective_compress = metadata['compress']

				use_keyfile = metadata.get('use_keyfile', False)
				kdf_type = metadata.get('kdf_id', Config.KDF_PBKDF2)
				iterations = metadata.get('iterations', Config.PBKDF2_ITERATIONS)

				salt = fin.read(metadata['salt_len'])
				nonce = fin.read(metadata['nonce_len'])

				ConsoleLogger.show(
					'debug', f'Read salt ({len(salt)} bytes) and nonce ({len(nonce)} bytes)'
				)

				if use_keyfile and not keyfile_data:
					ConsoleLogger.show(
						'warning',
						'Encrypted with key file but none provided. Attempting password-only decryption.',
					)

				key = self._derive_key(
					password, salt, keyfile_data if use_keyfile else None, kdf_type, iterations
				)
				ConsoleLogger.show('debug', 'Initializing AES-GCM cipher for decryption')
				cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

				ciphertext_len = (
					file_size
					- metadata['header_len']
					- metadata['salt_len']
					- metadata['nonce_len']
					- metadata['tag_len']
				)
				ConsoleLogger.show(
					'debug', f'Ciphertext length to decrypt: {self._format_size(ciphertext_len)}'
				)

				desc = (
					'[🔓] Decrypting & Decompressing' if effective_compress else '[🔓] Decrypting'
				)
				with (
					open(output_path, 'wb') as fout,
					tqdm(total=ciphertext_len, unit='B', unit_scale=True, desc=desc) as pbar,
				):
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
					ConsoleLogger.show('warning', 'Unexpected end of file while reading ciphertext')

					if decompressor:
						ConsoleLogger.show('debug', 'Flushing decompressor buffers')
						fout.write(decompressor.flush())

				# Verify Tag (always, regardless of bytes_read)
				tag = fin.read(metadata['tag_len'])
				ConsoleLogger.show('debug', f'Read authentication tag ({len(tag)} bytes)')
				try:
					ConsoleLogger.show('debug', 'Verifying authentication tag')
					cipher.verify(tag)
				except ValueError:
					ConsoleLogger.show(
						'error', 'INTEGRITY CHECK FAILED! Password wrong or file corrupted.'
					)
					ConsoleLogger.show('error', f'Decryption failed for: {input_path}')
					fout.close()
					os.remove(output_path)
					return False

			ConsoleLogger.show('success', 'Integrity Verified. Decryption successful.')
			return True

		except Exception as e:
			ConsoleLogger.show('error', f'File decryption error: {e}')
			ConsoleLogger.show('error', f'Failed to decrypt: {input_path}')
			if os.path.exists(output_path):
				try:
					os.remove(output_path)
				except:
					pass
			return False

	def encrypt_hidden_container(
		self,
		decoy_input_path: str,
		hidden_input_path: str,
		output_path: str,
		password_outer: str,
		password_hidden: str,
		compress: bool = False,
		keyfile_data: Optional[bytes] = None,
		kdf_type: int = Config.KDF_PBKDF2,
		iterations: int = Config.PBKDF2_ITERATIONS,
	) -> bool:
		"""Create [CT02_outer][CT02_hidden][CTHV][uint64 outer_len]."""
		tmp_outer = None
		tmp_hidden = None
		try:
			fd_o, tmp_outer = tempfile.mkstemp(prefix='ct_outer_', suffix='.enc')
			os.close(fd_o)
			fd_h, tmp_hidden = tempfile.mkstemp(prefix='ct_hidden_', suffix='.enc')
			os.close(fd_h)

			if not self.encrypt_file(
				decoy_input_path,
				tmp_outer,
				password_outer,
				compress,
				keyfile_data,
				kdf_type,
				iterations,
			):
				return False
			if not self.encrypt_file(
				hidden_input_path,
				tmp_hidden,
				password_hidden,
				compress,
				keyfile_data,
				kdf_type,
				iterations,
			):
				return False

			outer_len = os.path.getsize(tmp_outer)
			hidden_len = os.path.getsize(tmp_hidden)
			with (
				open(tmp_outer, 'rb') as fo,
				open(tmp_hidden, 'rb') as fh,
				open(output_path, 'wb') as out,
			):
				while True:
					blk = fo.read(Config.CHUNK_SIZE)
					if not blk:
						break
					out.write(blk)
				while True:
					blk = fh.read(Config.CHUNK_SIZE)
					if not blk:
						break
					out.write(blk)
				out.write(Config.CONTAINER_FOOTER_MAGIC)
				out.write(outer_len.to_bytes(8, byteorder='big', signed=False))

			ConsoleLogger.show(
				'success',
				f'Hidden container written ({self._format_size(outer_len + hidden_len + Config.CONTAINER_FOOTER_SIZE)})',
			)
			return True
		except Exception as e:
			ConsoleLogger.show('error', f'Hidden container encryption error: {e}')
			if os.path.exists(output_path):
				try:
					os.remove(output_path)
				except OSError:
					pass
			return False
		finally:
			for p in (tmp_outer, tmp_hidden):
				if p and os.path.exists(p):
					try:
						os.remove(p)
					except OSError:
						pass

	def decrypt_hidden_container(
		self,
		input_path: str,
		output_path: str,
		password: str,
		*,
		hidden: bool = False,
		compress: bool = False,
		keyfile_data: Optional[bytes] = None,
	) -> bool:
		info = parse_hidden_container_footer_from_path(input_path)
		if not info:
			ConsoleLogger.show(
				'error',
				'Not a hidden-volume container (missing or invalid CTHV footer).',
			)
			return False

		if hidden:
			return self.decrypt_file(
				input_path,
				output_path,
				password,
				compress,
				keyfile_data,
				slice_start=info['hiddenStart'],
				slice_end=info['fileSize'] - Config.CONTAINER_FOOTER_SIZE,
			)

		return self.decrypt_file(
			input_path,
			output_path,
			password,
			compress,
			keyfile_data,
			slice_start=0,
			slice_end=info['outerTotalLen'],
		)

	def inspect_file(self, input_path: str) -> dict:
		"""
		Inspect an encrypted file and return metadata without decrypting.
		Raises ValueError if the file is not a valid CT02 encrypted file.
		"""
		if not os.path.exists(input_path) or not os.path.isfile(input_path):
			raise FileNotFoundError(f"ENOENT: no such file or directory, stat '{input_path}'")

		file_size = os.path.getsize(input_path)
		footer_info = parse_hidden_container_footer_from_path(input_path)
		outer_span = footer_info['outerTotalLen'] if footer_info else file_size
		result = _inspect_ct02_blob_from_path(input_path, blob_start=0, blob_span=outer_span)
		result['fileSize'] = file_size
		result['container'] = 'hidden' if footer_info else 'standard'

		if footer_info:
			result['outerBlobSize'] = footer_info['outerTotalLen']
			result['hiddenBlobSize'] = footer_info['hiddenLen']
			result['hiddenMetadata'] = _inspect_ct02_blob_from_path(
				input_path,
				blob_start=footer_info['hiddenStart'],
				blob_span=footer_info['hiddenLen'],
			)
			result['footerNote'] = (
				'CTHV/Ciphertext. This file embeds a second encrypted blob; '
				'deniability vs forensic analysis is limited versus full-disk hidden volumes.'
			)

		return result

	def encrypt_with_threshold(
		self,
		input_path: str,
		output_path: str,
		passwords: List[str],
		threshold: int,
		compress: bool = False,
		keyfile_data: Optional[bytes] = None,
		kdf_type: int = Config.KDF_PBKDF2,
		iterations: int = Config.PBKDF2_ITERATIONS,
	) -> bool:
		"""Encrypt a file using threshold (Shamir's Secret Sharing) encryption."""
		try:
			num_passwords = len(passwords)
			if threshold > num_passwords:
				raise ValueError('Threshold cannot exceed number of passwords')
			if threshold < 2:
				raise ValueError('Threshold must be at least 2')

			ConsoleLogger.show(
				'debug',
				f'Starting threshold file encryption: {num_passwords} passwords, threshold {threshold}',
			)

			master_key = os.urandom(Config.KEY_SIZE)
			ConsoleLogger.show('debug', 'Generated master key for threshold encryption')

			shares = ShamirSecretSharing.generate_shares(master_key, num_passwords, threshold)
			ConsoleLogger.show(
				'debug',
				f"Generated {num_passwords} shares using Shamir's Secret Sharing",
			)

			file_size = os.path.getsize(input_path)
			salt = os.urandom(Config.SALT_SIZE)
			nonce = os.urandom(Config.NONCE_SIZE)
			key = self._derive_key('threshold-dummy', salt, None, kdf_type, iterations)

			header = _build_header(
				compress=compress,
				use_keyfile=keyfile_data is not None,
				kdf_id=kdf_type,
				iterations=iterations,
			)
			header_bytes = bytearray(header)
			header_bytes[5] |= Config.FLAG_THRESHOLD
			header = bytes(header_bytes)

			cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

			desc = '[🔒] Compressing & Encrypting' if compress else '[🔒] Encrypting'

			with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
				fout.write(header)
				fout.write(salt)
				fout.write(nonce)
				fout.write(bytes([num_passwords, threshold]))

				for i in range(num_passwords):
					password_salt = os.urandom(Config.SALT_SIZE)
					password_key = self._derive_key(
						passwords[i], password_salt, keyfile_data, kdf_type, iterations
					)
					ConsoleLogger.show(
						'debug',
						f'Encrypting share {i} with password {passwords[i][:4]}... salt={password_salt.hex()[:8]}..., key={password_key.hex()[:16]}...',
					)
					encrypted_share = self._encrypt_share_with_password(shares[i], password_key)
					fout.write(password_salt)
					fout.write(encrypted_share)

				with tqdm(total=file_size, unit='B', unit_scale=True, desc=desc) as pbar:
					while True:
						chunk = fin.read(Config.CHUNK_SIZE)
						if not chunk:
							break

						if compress:
							compressed_chunk = zlib.compress(chunk)
							fout.write(cipher.encrypt(compressed_chunk))
						else:
							fout.write(cipher.encrypt(chunk))

						pbar.update(len(chunk))

				tag = cipher.digest()
				fout.write(tag)

			ConsoleLogger.show(
				'success',
				f'Threshold encryption complete ({num_passwords} passwords, {threshold} required)',
			)
			return True

		except Exception as e:
			ConsoleLogger.show('error', f'Threshold encryption error: {e}')
			if os.path.exists(output_path):
				os.remove(output_path)
			return False

	def _encrypt_share_with_password(self, share: bytes, password_key: bytes) -> bytes:
		"""Encrypt a share with a password-derived key."""
		nonce = os.urandom(Config.NONCE_SIZE)
		cipher = AES.new(password_key, AES.MODE_GCM, nonce=nonce)
		ciphertext, tag = cipher.encrypt_and_digest(share)
		return nonce + ciphertext + tag

	def _decrypt_share_with_password(self, encrypted_data: bytes, password_key: bytes) -> bytes:
		"""Decrypt a share with a password-derived key."""
		nonce = encrypted_data[: Config.NONCE_SIZE]
		ciphertext = encrypted_data[Config.NONCE_SIZE : -Config.TAG_SIZE]
		tag = encrypted_data[-Config.TAG_SIZE :]
		cipher = AES.new(password_key, AES.MODE_GCM, nonce=nonce)
		return cipher.decrypt_and_verify(ciphertext, tag)

	def decrypt_with_threshold(
		self,
		input_path: str,
		output_path: str,
		passwords: List[str],
		compress: bool = False,
		keyfile_data: Optional[bytes] = None,
		slice_start: int = 0,
		slice_end: Optional[int] = None,
	) -> bool:
		"""Decrypt a file using threshold encryption."""
		try:
			file_size_on_disk = os.path.getsize(input_path)
			end = file_size_on_disk if slice_end is None else slice_end
			if slice_start < 0 or end > file_size_on_disk or slice_start >= end:
				raise ValueError('Invalid decrypt byte range')

			file_size = end - slice_start
			ConsoleLogger.show('debug', f'Starting threshold file decryption: {input_path}')

			with open(input_path, 'rb') as fin:
				fin.seek(slice_start)
				prefix = fin.read(Config.FIXED_HEADER_SIZE)

				metadata = _parse_format_from_bytes(prefix, text_payload=False)
				if not (metadata['flags'] & Config.FLAG_THRESHOLD):
					raise ValueError('File is not encrypted with threshold mode')

				if len(prefix) < metadata['header_len']:
					prefix += fin.read(metadata['header_len'] - len(prefix))

				salt = fin.read(metadata['salt_len'])
				nonce = fin.read(metadata['nonce_len'])

				num_and_thresh = fin.read(2)
				num_passwords = num_and_thresh[0]
				threshold = num_and_thresh[1]

				ConsoleLogger.show(
					'info',
					f'Threshold encrypted: {num_passwords} passwords, {threshold} required to decrypt',
				)

				share_data_offset = (
					slice_start
					+ metadata['header_len']
					+ metadata['salt_len']
					+ metadata['nonce_len']
					+ 2
				)
				encrypted_shares = []

				for _ in range(num_passwords):
					fin.seek(share_data_offset)
					password_salt = fin.read(Config.SALT_SIZE)
					share_data_offset += Config.SALT_SIZE

					encrypted_share_len = Config.NONCE_SIZE + Config.KEY_SIZE + 1 + Config.TAG_SIZE
					encrypted_share = fin.read(encrypted_share_len)
					share_data_offset += encrypted_share_len

					encrypted_shares.append({'salt': password_salt, 'data': encrypted_share})

			master_key = self._try_reconstruct_master_key(
				input_path,
				output_path,
				encrypted_shares,
				passwords,
				threshold,
				keyfile_data,
				metadata,
			)
			if master_key is None:
				raise ValueError('Failed to decrypt with provided passwords')

			key = self._derive_key(
				'threshold-dummy',
				salt,
				None,
				metadata.get('kdf_id', Config.KDF_PBKDF2),
				metadata.get('iterations', Config.PBKDF2_ITERATIONS),
			)

			decipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

			ciphertext_len = (
				file_size
				- metadata['header_len']
				- metadata['salt_len']
				- metadata['nonce_len']
				- metadata['tag_len']
				- 2
				- (
					num_passwords
					* (Config.SALT_SIZE + Config.NONCE_SIZE + Config.KEY_SIZE + 1 + Config.TAG_SIZE)
				)
			)
			effective_compress = metadata['compress']
			desc = '[🔓] Decrypting & Decompressing' if effective_compress else '[🔓] Decrypting'

			with (
				open(output_path, 'wb') as fout,
				open(input_path, 'rb') as fin,
				tqdm(total=ciphertext_len, unit='B', unit_scale=True, desc=desc) as pbar,
			):
				decompressor = zlib.decompressobj() if effective_compress else None
				bytes_read = 0

				fin.seek(share_data_offset)
				while bytes_read < ciphertext_len:
					read_size = min(Config.CHUNK_SIZE, ciphertext_len - bytes_read)
					chunk = fin.read(read_size)
					if not chunk:
						break

					decrypted_chunk = decipher.decrypt(chunk)

					if decompressor:
						decompressed_chunk = decompressor.decompress(decrypted_chunk)
						if decompressed_chunk:
							fout.write(decompressed_chunk)
					else:
						fout.write(decrypted_chunk)

					bytes_read += len(chunk)
					pbar.update(len(chunk))

				tag = fin.read(metadata['tag_len'])
				try:
					decipher.verify(tag)
				except ValueError:
					ConsoleLogger.show('error', 'INTEGRITY CHECK FAILED!')
					os.remove(output_path)
					return False

			ConsoleLogger.show('success', 'Threshold decryption successful')
			return True

		except Exception as e:
			ConsoleLogger.show('error', f'Threshold decryption error: {e}')
			if os.path.exists(output_path):
				try:
					os.remove(output_path)
				except:
					pass
			return False

	def _try_reconstruct_master_key(
		self,
		input_path: str,
		output_path: str,
		encrypted_shares: List[dict],
		passwords: List[str],
		threshold: int,
		keyfile_data: Optional[bytes],
		metadata: dict,
	) -> Optional[bytes]:
		"""Try to reconstruct the master key from passwords."""
		kdf_type = metadata.get('kdf_id', Config.KDF_PBKDF2)
		iterations = metadata.get('iterations', Config.PBKDF2_ITERATIONS)

		ConsoleLogger.show(
			'debug',
			f'Trying to reconstruct with {len(passwords)} passwords and {len(encrypted_shares)} encrypted shares',
		)

		share_data_list = []
		used_share_indexes = set()
		recovered_share_ids = set()
		for pw in passwords:
			ConsoleLogger.show('debug', f'Trying password: {pw[:4]}...')
			for idx, enc_share in enumerate(encrypted_shares):
				if idx in used_share_indexes:
					continue
				try:
					password_key = self._derive_key(
						pw, enc_share['salt'], keyfile_data, kdf_type, iterations
					)
					ConsoleLogger.show(
						'debug',
						f'  Share {idx}: salt={enc_share["salt"].hex()[:8]}..., key={password_key.hex()[:16]}...',
					)
					share = self._decrypt_share_with_password(enc_share['data'], password_key)
					ConsoleLogger.show('debug', f'  Share {idx} decrypted successfully!')
					share_id = share[0]
					if share_id in recovered_share_ids:
						ConsoleLogger.show(
							'debug',
							f'  Share {idx} ignored because share id {share_id} is duplicated',
						)
						break
					recovered_share_ids.add(share_id)
					used_share_indexes.add(idx)
					share_data_list.append(share)
					break
				except Exception as e:
					ConsoleLogger.show('debug', f'  Failed share {idx}: {e}')
					continue

		if len(share_data_list) < threshold:
			ConsoleLogger.show(
				'error',
				f'Not enough valid passwords provided. Need {threshold}, got {len(share_data_list)}',
			)
			return None

		try:
			master_key = ShamirSecretSharing.recover_secret(share_data_list[:threshold])
			ConsoleLogger.show('debug', 'Successfully reconstructed master key')
			return master_key
		except Exception as e:
			ConsoleLogger.show('error', f'Failed to reconstruct master key: {e}')
			return None


# =========================
# Password Strength Validator
# =========================


class PasswordStrength:
	"""Password strength validator with real-time feedback."""

	STRENGTHS = {
		'VERY_WEAK': {
			'label': 'Very Weak',
			'color': '\033[91m\033[1m',
			'reset': '\033[0m',
			'icon': '❌',
		},  # Red Bold
		'WEAK': {'label': 'Weak', 'color': '\033[91m', 'reset': '\033[0m', 'icon': '⚠️'},  # Red
		'MEDIUM': {
			'label': 'Medium',
			'color': '\033[93m',
			'reset': '\033[0m',
			'icon': '⚡',
		},  # Yellow
		'STRONG': {
			'label': 'Strong',
			'color': '\033[92m',
			'reset': '\033[0m',
			'icon': '✅',
		},  # Green
		'VERY_STRONG': {
			'label': 'Very Strong',
			'color': '\033[92m\033[1m',
			'reset': '\033[0m',
			'icon': '🔒',
		},  # Green Bold
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
			'length': length,
		}

	@classmethod
	def get_indicator(cls, password: str) -> str:
		"""Get formatted strength indicator with colors."""
		result = cls.check(password)
		strength = cls.STRENGTHS[result['strength']]
		return f'{strength["color"]}{strength["icon"]} {strength["label"]}{strength["reset"]}'

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
			types.append(f'{green}{check_icon} Lower{reset}')
		else:
			types.append(f'{red}{cross_icon} Lower{reset}')

		if result['has_upper']:
			types.append(f'{green}{check_icon} Upper{reset}')
		else:
			types.append(f'{red}{cross_icon} Upper{reset}')

		if result['has_number']:
			types.append(f'{green}{check_icon} Number{reset}')
		else:
			types.append(f'{red}{cross_icon} Number{reset}')

		if result['has_symbol']:
			types.append(f'{green}{check_icon} Symbol{reset}')
		else:
			types.append(f'{red}{cross_icon} Symbol{reset}')

		return ' '.join(types)


def getpass_with_strength(prompt: str = 'Enter Password: ') -> str:
	"""Get password with real-time strength indicator."""
	import sys

	# Fallback for non-interactive stdin (e.g., tests/CI).
	if not sys.stdin.isatty():
		return getpass.getpass(prompt)

	# Write prompt
	white = TerminalColors.Foreground.WHITE
	reset = TerminalColors.RESET
	sys.stdout.write(f'{white}[{reset}🔑{white}]{reset} {prompt}')
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
					sys.stdout.write(
						f'\r{white}[{reset}🔑{white}]{reset} {prompt}{asterisks}  {strength_indicator}  {char_types}\033[K'
					)
					sys.stdout.flush()
			elif char >= ' ' and len(char) == 1:
				# Regular character
				password += char
				# Update display with strength indicator
				strength_indicator = PasswordStrength.get_indicator(password)
				char_types = PasswordStrength.get_char_types(password)
				asterisks = '*' * len(password)
				sys.stdout.write(
					f'\r{white}[{reset}🔑{white}]{reset} {prompt}{asterisks}  {strength_indicator}  {char_types}\033[K'
				)
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
						sys.stdout.write(
							f'\r{white}[{reset}🔑{white}]{reset} {prompt}{asterisks}  {strength_indicator}  {char_types}\033[K'
						)
						sys.stdout.flush()
				elif char >= ' ' and len(char) == 1:
					# Regular character
					password += char
					# Update display with strength indicator
					strength_indicator = PasswordStrength.get_indicator(password)
					char_types = PasswordStrength.get_char_types(password)
					asterisks = '*' * len(password)
					sys.stdout.write(
						f'\r{white}[{reset}🔑{white}]{reset} {prompt}{asterisks}  {strength_indicator}  {char_types}\033[K'
					)
					sys.stdout.flush()
		finally:
			termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

	return password


def getpass_verify_with_strength(
	prompt1: str = 'Enter Password: ', prompt2: str = 'Verify Password: '
) -> str:
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
	sys.stdout.write(f'{white}[{reset}🔄{white}]{reset} {prompt2}')
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
					sys.stdout.write(
						f'\r{white}[{reset}🔄{white}]{reset} {prompt2}{asterisks}  {strength_indicator}  {char_types}\033[K'
					)
					sys.stdout.flush()
			elif char >= ' ' and len(char) == 1:
				password2 += char
				strength_indicator = PasswordStrength.get_indicator(password2)
				char_types = PasswordStrength.get_char_types(password2)
				asterisks = '*' * len(password2)
				sys.stdout.write(
					f'\r{white}[{reset}🔄{white}]{reset} {prompt2}{asterisks}  {strength_indicator}  {char_types}\033[K'
				)
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
						sys.stdout.write(
							f'\r{white}[{reset}🔄{white}]{reset} {prompt2}{asterisks}  {strength_indicator}  {char_types}\033[K'
						)
						sys.stdout.flush()
				elif char >= ' ' and len(char) == 1:
					password2 += char
					strength_indicator = PasswordStrength.get_indicator(password2)
					char_types = PasswordStrength.get_char_types(password2)
					asterisks = '*' * len(password2)
					sys.stdout.write(
						f'\r{white}[{reset}🔄{white}]{reset} {prompt2}{asterisks}  {strength_indicator}  {char_types}\033[K'
					)
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
		prog='crypt_tools.py',
		description=(
			f'{_help_heading("🔐", "Crypt Tools Help")}\n'
			f'{_help_style("Beautiful, secure AES-GCM encryption for files and text.", TerminalColors.Foreground.WHITE)}'
		),
		epilog=(
			f'{_help_heading("✨", "Tips")}\n'
			'  - Wildcards are supported; with -r, patterns like .\\temp\\*.txt are expanded recursively\n'
			'    (equivalent to .\\temp\\**\\*.txt).\n'
			'  - Password prompts show a live strength indicator.\n'
			'  - Key file support: Use --keyfile to encrypt/decrypt with a key file.\n'
			'    Combining password + keyfile provides two-factor encryption.\n'
			'  - Use --select to browse for a file or directory in an interactive terminal UI.\n'
			'  - Use --qr with text encryption to print the encrypted Base64 payload as a QR code.\n'
			'  - Hidden volumes (--hidden-vol / -d --hidden): two CT02 blobs plus a CTHV footer.\n'
			'    This is not identical to VeraCrypt: the footer and extra length are visible forensically;\n'
			'    deniability is “wrong password opens decoy,” not “file looks like a single ciphertext only.”\n\n'
			f'{_help_heading("🌍", "Environment Variables")}\n'
			'  CRYPT_TOOLS_PASSWORD, CRYPT_TOOLS_KDF, CRYPT_TOOLS_ITERATIONS,\n'
			'  CRYPT_TOOLS_COMPRESS, CRYPT_TOOLS_COMPRESSION, CRYPT_TOOLS_LOG,\n'
			'  CRYPT_TOOLS_LOG_ENABLED, CRYPT_TOOLS_DEBUG, CRYPT_TOOLS_DEBUG_ENABLED,\n'
			'  CRYPT_TOOLS_KEYFILE, CRYPT_TOOLS_THRESHOLD,\n'
			'  CRYPT_TOOLS_PASSWORD_OUTER, CRYPT_TOOLS_PASSWORD_HIDDEN\n\n'
			f'{_help_heading("⚙️", "Config Keys")}\n'
			'  compress, compression, default_compression, kdf, default_kdf,\n'
			'  iterations, default_iterations, log, logging, log_enabled,\n'
			'  debug, debug_enabled, password, default_password,\n'
			'  password_outer, default_password_outer,\n'
			'  password_hidden, default_password_hidden,\n'
			'  keyfile, default_keyfile, threshold'
		),
		formatter_class=argparse.RawTextHelpFormatter,
		add_help=False,
	)
	utility_group = parser.add_argument_group(_help_heading('🛠️', 'Utility'))
	utility_group.add_argument(
		'--generate-keyfile', dest='generate_keyfile', help='Generate a random key file and exit'
	)
	utility_group.add_argument('--debug', action='store_true', help='Enable debug mode')
	utility_group.add_argument('--log', action='store_true', help='Enable logging to file')
	utility_group.add_argument('-v', '--version', action='version', version=Config.VERSION)
	utility_group.add_argument('-h', '--help', action='help', help='Show this help message and exit')

	mode_group = parser.add_argument_group(_help_heading('🎯', 'Modes')).add_mutually_exclusive_group()
	mode_group.add_argument('-e', '--encrypt', action='store_true', help='Encrypt mode (default)')
	mode_group.add_argument('-d', '--decrypt', action='store_true', help='Decrypt mode')
	mode_group.add_argument(
		'--inspect', action='store_true', help='Inspect encrypted file metadata'
	)

	input_group = parser.add_argument_group(_help_heading('📥', 'Input & Output'))
	group = input_group.add_mutually_exclusive_group()
	group.add_argument('-t', '--text', help='Text to process')
	group.add_argument(
		'-f',
		'--file',
		help='File path, directory, or wildcard pattern (e.g., "*.md", "temp\\*.txt")',
	)
	input_group.add_argument('-o', '--output', help='Output file path')
	input_group.add_argument(
		'--config',
		help='Path to a config file (.conf, .json, .yml, .yaml); defaults are auto-discovered',
	)
	input_group.add_argument(
		'--select',
		action='store_true',
		help='Browse and choose a file or directory interactively',
	)

	secret_group = parser.add_argument_group(_help_heading('🔑', 'Passwords & Secrets'))
	secret_group.add_argument(
		'-p',
		'--password',
		action='append',
		default=[],
		help='Password (can be specified multiple times for threshold mode)',
	)
	secret_group.add_argument(
		'--threshold',
		type=int,
		help='Threshold for multi-signature mode (e.g., 2 for 2 of 3)',
	)
	secret_group.add_argument(
		'--keyfile',
		required=False,
		help='Key file path for encryption/decryption (use with or without password)',
	)
	secret_group.add_argument(
		'--password-outer',
		default=None,
		help='Decoy password for --hidden-vol (optional; exposing via CLI is insecure)',
	)
	secret_group.add_argument(
		'--password-hidden',
		default=None,
		help='Hidden password for --hidden-vol; with -d --hidden can be used instead of -p',
	)

	file_group = parser.add_argument_group(_help_heading('📦', 'File & Container Behavior'))
	file_group.add_argument('-c', '--compress', action='store_true', help='Enable compression')
	file_group.add_argument(
		'--hidden-vol',
		action='store_true',
		help='Encrypt decoy (-f) and hidden (--hidden-file) into one container (single file only)',
	)
	file_group.add_argument(
		'--hidden-file',
		help='Hidden payload path (requires --hidden-vol on encrypt)',
	)
	file_group.add_argument(
		'--hidden',
		action='store_true',
		help='With -d -f, decrypt inner/hidden volume (password is the hidden password)',
	)
	file_group.add_argument(
		'-r',
		'--recursive',
		action='store_true',
		help='Recursively process directories or wildcard patterns (uses ** for subfolders)',
	)

	crypto_group = parser.add_argument_group(_help_heading('🧬', 'Crypto Tuning'))
	crypto_group.add_argument(
		'--kdf',
		choices=['pbkdf2', 'argon2'],
		default=None,
		help='Key derivation function: pbkdf2 (default) or argon2 (more secure)',
	)
	crypto_group.add_argument(
		'--iterations',
		type=int,
		help='Number of iterations for KDF (default: 100000 for PBKDF2, 3 for Argon2)',
	)
	crypto_group.add_argument(
		'--qr',
		action='store_true',
		help='Render encrypted text output as a QR code (text encrypt mode only)',
	)

	return parser.parse_args(argv)


def _log_completion_summary(
	is_decrypt: bool, success_count: int, total_ops: int, elapsed_time: float
):
	"""Log a success or failure summary for CLI file operations."""
	action = 'Decryption' if is_decrypt else 'Encryption'
	if total_ops > 0 and success_count == total_ops:
		ConsoleLogger.show('success', f'{action} completed successfully', icon='✅')
	elif success_count == 0:
		pass
	else:
		ConsoleLogger.show('warning', f'{action} completed with failures', icon='⚠️')

	ConsoleLogger.show('info', f'Operations completed: {success_count}/{total_ops}', icon='✔️')
	ConsoleLogger.show('info', f'Total time: {elapsed_time:.2f}s', icon='⏱️')


def main(argv=None):
	Banner.show()
	# If argv is None, argparse uses sys.argv[1:] automatically.
	# If argv is passed (from tests), it uses that list.
	cli_overrides = _detect_cli_overrides(argv)
	args = parse_args(argv)
	try:
		config_path, config_defaults, env_defaults = _load_runtime_defaults(args.config)
	except ValueError as e:
		ConsoleLogger.show('error', str(e))
		sys.exit(1)
	args = _apply_runtime_defaults(args, cli_overrides, config_defaults, env_defaults)
	engine = CryptoEngine()

	# Handle key file generation
	if args.generate_keyfile:
		if generate_keyfile(args.generate_keyfile):
			sys.exit(0)
		else:
			sys.exit(1)

	if args.select and args.text:
		ConsoleLogger.show('error', '--select cannot be used with --text')
		sys.exit(1)
	if args.qr and (args.decrypt or not args.text):
		ConsoleLogger.show('error', '--qr is only supported with text encryption')
		sys.exit(1)
	if args.select:
		try:
			selected_path = interactive_file_selector(args.file or '.')
		except RuntimeError as e:
			ConsoleLogger.show('error', str(e))
			sys.exit(1)
		if not selected_path:
			ConsoleLogger.show('error', 'Interactive file selection cancelled')
			sys.exit(1)
		args.file = selected_path
		ConsoleLogger.show('info', f'Selected path: {selected_path}', icon='🧭')

	# Validate text or file is provided (required for non-generate-keyfile operations)
	if not args.text and not args.file:
		ConsoleLogger.show('error', 'Either --text or --file is required')
		sys.exit(1)

	if args.inspect and args.text:
		ConsoleLogger.show('error', '--inspect only supports --file input')
		sys.exit(1)

	if args.hidden_vol and args.text:
		ConsoleLogger.show('error', '--hidden-vol applies only to file encryption')
		sys.exit(1)
	if args.hidden_vol and args.decrypt:
		ConsoleLogger.show('error', '--hidden-vol is for encryption only')
		sys.exit(1)
	if args.hidden_vol and args.inspect:
		ConsoleLogger.show('error', '--hidden-vol cannot be used with --inspect')
		sys.exit(1)
	if args.hidden_file and not args.hidden_vol:
		ConsoleLogger.show('error', '--hidden-file requires --hidden-vol')
		sys.exit(1)
	if args.hidden_vol and not args.hidden_file:
		ConsoleLogger.show('error', '--hidden-vol requires --hidden-file')
		sys.exit(1)
	if args.hidden and not args.decrypt:
		ConsoleLogger.show('error', '--hidden requires decrypt mode (-d)')
		sys.exit(1)
	if args.hidden and args.text:
		ConsoleLogger.show('error', '--hidden applies only to file decryption')
		sys.exit(1)
	if len(args.password) > 1 and not args.threshold and not args.decrypt:
		ConsoleLogger.show(
			'error',
			'Multiple -p/--password values require --threshold',
		)
		sys.exit(1)
	if args.threshold:
		if args.threshold < 2:
			ConsoleLogger.show('error', '--threshold must be at least 2')
			sys.exit(1)
		if args.threshold > len(args.password):
			ConsoleLogger.show(
				'warning',
				f'--threshold is {args.threshold} but only {len(args.password)} passwords provided via -p',
			)
		if args.text:
			ConsoleLogger.show('error', '--threshold applies only to file encryption/decryption')
			sys.exit(1)
		if args.hidden_vol:
			ConsoleLogger.show('error', '--threshold cannot be used with --hidden-vol')
			sys.exit(1)

	# Enable logging FIRST if --log flag is set
	if args.log:
		ConsoleLogger.LOG_ENABLED = True

	# Record start time
	start_timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
	ConsoleLogger.show('info', f'Session started at {start_timestamp}', icon='🕐')
	if config_path:
		ConsoleLogger.show('info', f'Config file: {config_path}', icon='⚙️')
	session_ended = False

	def finish_session():
		nonlocal session_ended
		if session_ended:
			return
		session_ended = True
		end_timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
		ConsoleLogger.show('info', f'Session ended at {end_timestamp}', icon='🏁')
		if ConsoleLogger.LOG_ENABLED:
			ConsoleLogger.show('info', '=' * 80, show_console=False, log_file=True)

	def abort(code: int = 1):
		finish_session()
		raise SystemExit(code)

	# Enable debug mode if --debug flag is set
	if args.debug:
		ConsoleLogger.DEBUG_ENABLED = True
		ConsoleLogger.show('debug', 'Debug Mode Enabled. Verbose logging activated.')
		ConsoleLogger.show('info', 'Debug mode: Enabled')

	# Show log file info (after LOG_ENABLED is set)
	if args.log:
		ConsoleLogger.show('debug', f'Logging enabled. Writing to: {ConsoleLogger.LOG_FILE}')
		ConsoleLogger.show('info', f'Log file: {ConsoleLogger.LOG_FILE}')
		ConsoleLogger.show('info', 'Logging to file: Enabled')

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
				ConsoleLogger.show('error', f'No files matched pattern: {args.file}')
				ConsoleLogger.show('error', 'Operation failed: No matching files')
				abort(1)
		else:
			file_list = [args.file]

	if args.hidden_vol:
		if not args.file:
			ConsoleLogger.show('error', '--hidden-vol requires -f/--file (decoy path)')
			abort(1)
		if args.recursive:
			ConsoleLogger.show('error', '--hidden-vol cannot be used with --recursive')
			abort(1)
		wc = any(ch in args.file for ch in ['*', '?', '[', ']'])
		if wc or (file_list and len(file_list) != 1):
			ConsoleLogger.show(
				'error',
				'--hidden-vol requires a single decoy file (no wildcards or multi-file batch)',
			)
			abort(1)
		decoy_p = file_list[0]
		if not os.path.isfile(decoy_p):
			ConsoleLogger.show('error', 'Decoy path must be a regular file for --hidden-vol')
			abort(1)
		if not os.path.isfile(args.hidden_file):
			ConsoleLogger.show('error', f'Hidden file not found: {args.hidden_file}')
			abort(1)

	if args.inspect:
		target_file = (file_list and file_list[0]) if file_list else args.file

		if not target_file:
			ConsoleLogger.show('error', 'No file specified for inspection')
			ConsoleLogger.show('error', 'Operation failed: No file to inspect')
			abort(1)

		details = None
		try:
			details = engine.inspect_file(target_file)
		except FileNotFoundError:
			ConsoleLogger.show('error', f'File not found: {target_file}')
			ConsoleLogger.show('error', 'Operation failed: File does not exist')
			abort(1)
		except ValueError as e:
			ConsoleLogger.show('error', f'Inspect failed: {e}')
			ConsoleLogger.show('error', f'File is not a supported encrypted file: {target_file}')
			abort(1)
		except Exception as e:
			ConsoleLogger.show('error', f'Inspect failed: {e}')
			ConsoleLogger.show('error', f'File is not a supported encrypted file: {target_file}')
			abort(1)

		ConsoleLogger.show('info', f'Format: {details["format"]}', icon='🔍')
		ConsoleLogger.show('info', f'Version: {details["version"]}', icon='📜')
		ConsoleLogger.show('info', f'Legacy: {"yes" if details["legacy"] else "no"}', icon='🕰️')
		ConsoleLogger.show('info', f'Compression: {details["compression"]}', icon='🗜️')
		ConsoleLogger.show('info', f'Keyfile: {details.get("keyfile", "disabled")}', icon='🔑')
		ConsoleLogger.show('info', f'KDF: {details["kdf"]}', icon='🧬')
		ConsoleLogger.show('info', f'Iterations: {details["iterations"]}', icon='🔁')
		ConsoleLogger.show('info', f'Threshold mode: {details["thresholdMode"]}', icon='🧩')
		if details.get('numPasswords') is not None:
			ConsoleLogger.show('info', f'Shares: {details["numPasswords"]}', icon='🔢')
			ConsoleLogger.show(
				'info',
				f'Threshold required: {details["thresholdRequired"]}',
				icon='🎯',
			)
		ConsoleLogger.show('info', f'Salt length: {details["saltLength"]}', icon='🧂')
		ConsoleLogger.show('info', f'Nonce length: {details["nonceLength"]}', icon='🎲')
		ConsoleLogger.show('info', f'Tag length: {details["tagLength"]}', icon='🏷️')
		ConsoleLogger.show('info', f'Header length: {details["headerLength"]}', icon='🧱')
		ConsoleLogger.show('info', f'File size: {details["fileSize"]} bytes', icon='📦')
		ConsoleLogger.show('info', f'Ciphertext size: {details["ciphertextSize"]} bytes', icon='🔐')
		if details.get('container') == 'hidden':
			ConsoleLogger.show(
				'info',
				'Container: hidden (outer CT02 + inner CT02 + CTHV footer)',
				icon='🫥',
			)
			ConsoleLogger.show(
				'info',
				f'Outer blob size: {details["outerBlobSize"]} bytes',
				icon='📦',
			)
			ConsoleLogger.show(
				'info',
				f'Hidden blob size: {details["hiddenBlobSize"]} bytes',
				icon='📦',
			)
			inner = details.get('hiddenMetadata')
			if inner:
				ConsoleLogger.show('info', 'Hidden blob metadata:', icon='🫥')
				ConsoleLogger.show('info', f'Inner compression: {inner["compression"]}', icon='🗜️')
				ConsoleLogger.show('info', f'Inner keyfile: {inner["keyfile"]}', icon='🔑')
				ConsoleLogger.show('info', f'Inner KDF: {inner["kdf"]}', icon='🧬')
				ConsoleLogger.show('info', f'Inner iterations: {inner["iterations"]}', icon='🔁')
				ConsoleLogger.show(
					'info',
					f'Inner threshold mode: {inner["thresholdMode"]}',
					icon='🧩',
				)
				if inner.get('numPasswords') is not None:
					ConsoleLogger.show('info', f'Inner shares: {inner["numPasswords"]}', icon='🔢')
					ConsoleLogger.show(
						'info',
						f'Inner threshold required: {inner["thresholdRequired"]}',
						icon='🎯',
					)
			if details.get('footerNote'):
				ConsoleLogger.show('warning', details['footerNote'])
		end_timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
		ConsoleLogger.show('info', f'Session ended at {end_timestamp}', icon='🏁')
		if ConsoleLogger.LOG_ENABLED:
			ConsoleLogger.show('info', '=' * 80, show_console=False, log_file=True)
		return

		target_file = file_list[0]
		ConsoleLogger.show('info', f'Inspecting file: {target_file}', icon='🔍')

		try:
			details = engine.inspect_file(target_file)
			ConsoleLogger.show('success', 'File inspection complete', icon='✅')
			ConsoleLogger.show('info', f'Format: {details["format"]}', icon='📋')
			ConsoleLogger.show('info', f'Version: {details["version"]}', icon='📋')
			ConsoleLogger.show('info', f'Compression: {details["compression"]}', icon='📋')
			ConsoleLogger.show('info', f'KDF: {details["kdf"]}', icon='🧬')
			ConsoleLogger.show('info', f'Iterations: {details["iterations"]}', icon='📋')
			ConsoleLogger.show('info', f'Header Length: {details["headerLength"]} bytes', icon='📋')
			ConsoleLogger.show(
				'info', f'File Size: {engine._format_size(details["fileSize"])}', icon='📋'
			)
			ConsoleLogger.show(
				'info',
				f'Ciphertext Size: {engine._format_size(details["ciphertextSize"])}',
				icon='📋',
			)
			return
		except Exception as e:
			ConsoleLogger.show('error', 'Inspect failed')
			ConsoleLogger.show('error', f'Inspection failed: {e}')
			if 'supported encrypted file' in str(e):
				ConsoleLogger.show('error', 'Only CT02 supported encrypted file')
			ConsoleLogger.show('error', 'Operation failed: Cannot inspect file')
			abort(1)

		target_file = file_list[0]
		ConsoleLogger.show('info', f'Inspecting file: {target_file}', icon='🔍')

		try:
			details = engine.inspect_file(target_file)
			ConsoleLogger.show('success', 'File inspection complete', icon='✅')
			ConsoleLogger.show('info', f'Format: {details["format"]}', icon='📋')
			ConsoleLogger.show('info', f'Version: {details["version"]}', icon='📋')
			ConsoleLogger.show('info', f'Compression: {details["compression"]}', icon='📋')
			ConsoleLogger.show('info', f'KDF: {details["kdf"]}', icon='🧬')
			ConsoleLogger.show('info', f'Iterations: {details["iterations"]}', icon='📋')
			ConsoleLogger.show('info', f'Header Length: {details["headerLength"]} bytes', icon='📋')
			ConsoleLogger.show(
				'info', f'File Size: {engine._format_size(details["fileSize"])}', icon='📋'
			)
			ConsoleLogger.show(
				'info',
				f'Ciphertext Size: {engine._format_size(details["ciphertextSize"])}',
				icon='📋',
			)
			abort(0)
		except Exception as e:
			ConsoleLogger.show('error', f'Inspection failed: {e}')
			ConsoleLogger.show('error', 'Operation failed: Cannot inspect file')
			abort(1)

	if args.text:
		mode_str = 'decrypt' if args.decrypt else 'encrypt'
		compression_str = 'disabled'  # Compression not available for text mode
		ConsoleLogger.show('info', f'Mode: {mode_str}', icon='🔐' if not args.decrypt else '🔓')
		ConsoleLogger.show('info', f'Compression: {compression_str}', icon='📦')
		ConsoleLogger.show('info', 'Processing text...', icon='💬')
		ConsoleLogger.show(
			'info', f'Input text length: {len(args.text)} characters', log_file=False
		)
	elif args.file:
		ConsoleLogger.show('debug', f'File specified: {args.file}')
		if not os.path.exists(args.file) and not any(
			ch in args.file for ch in ['*', '?', '[', ']']
		):
			ConsoleLogger.show('error', f'File not found: {args.file}')
			ConsoleLogger.show('error', 'Operation failed: File does not exist')
			ConsoleLogger.show('error', 'Please check the file path and try again')
			abort(1)

		is_dir = os.path.isdir(args.file)
		if is_dir and not args.recursive:
			ConsoleLogger.show(
				'error', 'Path is a directory. Use -r/--recursive to process directories.'
			)
			ConsoleLogger.show(
				'error', 'Operation aborted: Directory specified without --recursive flag'
			)
			abort(1)

		mode_str = 'decrypt' if args.decrypt else 'encrypt'
		compression_str = 'enabled' if args.compress else 'disabled'
		if (
			args.decrypt
			and not is_dir
			and not glob.has_magic(args.file)
			and os.path.isfile(args.file)
		):
			try:
				details = engine.inspect_file(args.file)
				compression_str = details['compression']
			except Exception as e:
				ConsoleLogger.show('debug', f'Could not inspect compression metadata: {e}')
		ConsoleLogger.show('info', f'Mode: {mode_str}', icon='🔐' if not args.decrypt else '🔓')
		ConsoleLogger.show('info', f'Compression: {compression_str}', icon='📦')

		if is_dir and args.recursive:
			ConsoleLogger.show('info', f'Processing directory: {args.file}', icon='📁')
			ConsoleLogger.show(
				'info',
				f'{"Encrypting" if not args.decrypt else "Decrypting"} directory: {args.file}',
				icon='🔒' if not args.decrypt else '🔓',
			)
			ConsoleLogger.show('info', 'Recursive mode: enabled', icon='🔄')
		elif not is_dir:
			if file_list and len(file_list) > 1:
				ConsoleLogger.show('info', f'Processing files: {len(file_list)}', icon='📄')
			else:
				target = file_list[0] if file_list else args.file
				input_size = os.path.getsize(target)
				ConsoleLogger.show(
					'info',
					f'Processing file: {target} ({engine._format_size(input_size)})',
					icon='📄',
				)

	# Handle key file
	keyfile_data = None
	if args.keyfile:
		ConsoleLogger.show('info', f'Using key file: {args.keyfile}', icon='🔐')
		keyfile_data = read_keyfile(args.keyfile)
		if keyfile_data is None:
			ConsoleLogger.show('error', 'Operation aborted: Could not load key file')
			abort(1)
		ConsoleLogger.show('success', 'Key file loaded successfully')
	else:
		ConsoleLogger.show('debug', 'No key file provided')

	args.kdf = args.kdf or 'pbkdf2'
	if args.kdf not in ['pbkdf2', 'argon2']:
		ConsoleLogger.show('error', 'Invalid --kdf value. Must be "pbkdf2" or "argon2"')
		abort(1)
	kdf_type = Config.KDF_ARGON2 if args.kdf == 'argon2' else Config.KDF_PBKDF2
	if args.kdf == 'argon2' and not ARGON2_AVAILABLE:
		ConsoleLogger.show(
			'error', 'Argon2 is not available. Please install argon2-cffi: pip install argon2-cffi'
		)
		abort(1)

	iterations = args.iterations
	if iterations is None:
		iterations = Config.ARGON2_TIME_COST if args.kdf == 'argon2' else Config.PBKDF2_ITERATIONS

	ConsoleLogger.show('important', f'KDF: {args.kdf} ({iterations} iterations)', icon='🧬')

	pw_outer = args.password_outer
	pw_hidden = args.password_hidden
	threshold_requirements = None

	if (
		args.decrypt
		and args.file
		and not args.inspect
		and not args.hidden
		and not args.hidden_vol
		and not glob.has_magic(args.file)
		and os.path.isfile(args.file)
	):
		try:
			threshold_requirements = inspect_threshold_requirements_from_path(args.file)
		except Exception as e:
			ConsoleLogger.show('debug', f'Could not inspect threshold requirements: {e}')

	# Secure Password Input with Strength Indicator
	# Only prompt for password if not provided (None), not if empty string was explicitly passed
	if args.hidden_vol:
		if pw_outer is None:
			pw_outer = getpass_verify_with_strength(
				'Enter decoy (outer) password: ',
				'Verify decoy (outer) password: ',
			)
			ConsoleLogger.show('info', 'Decoy password entered', icon='🔑')
		else:
			ConsoleLogger.show('debug', 'Decoy password provided via command line')
		if pw_hidden is None:
			pw_hidden = getpass_verify_with_strength(
				'Enter hidden volume password: ',
				'Verify hidden volume password: ',
			)
			ConsoleLogger.show('info', 'Hidden volume password entered', icon='🔑')
		else:
			ConsoleLogger.show('debug', 'Hidden password provided via command line')
	elif threshold_requirements and len(args.password) < threshold_requirements['threshold']:
		num_passwords_needed = threshold_requirements['threshold']
		ConsoleLogger.show(
			'info',
			f'Threshold-encrypted file detected: {num_passwords_needed} password(s) required',
		)
		for i in range(len(args.password), num_passwords_needed):
			pw = getpass_with_strength(f'Enter password {i + 1}/{num_passwords_needed}: ')
			if not pw:
				ConsoleLogger.show('error', 'Password cannot be empty')
				abort(1)
			args.password.append(pw)
	elif args.threshold:
		num_passwords_needed = args.threshold
		if len(args.password) < num_passwords_needed:
			ConsoleLogger.show('info', f'Threshold mode: need {num_passwords_needed} passwords')
			for i in range(len(args.password), num_passwords_needed):
				pw = getpass_with_strength(f'Enter password {i + 1}/{num_passwords_needed}: ')
				if not pw:
					ConsoleLogger.show('error', 'Password cannot be empty')
					abort(1)
				args.password.append(pw)
		else:
			ConsoleLogger.show(
				'debug',
				f'Using all {len(args.password)} provided passwords for threshold encryption',
			)
	elif not args.inspect:
		# For non-threshold mode, only convert to string if exactly one password provided
		if args.password and len(args.password) == 1:
			args.password = args.password[0]
			ConsoleLogger.show('debug', 'Password provided via command line')
		elif args.password and len(args.password) > 1:
			ConsoleLogger.show(
				'debug',
				f'Using {len(args.password)} provided passwords for decrypt auto-detection',
			)
		else:
			if args.decrypt and args.hidden and args.password_hidden is not None:
				args.password = args.password_hidden
				ConsoleLogger.show('debug', 'Using --password-hidden for inner decrypt')
			elif not args.decrypt:
				args.password = getpass_verify_with_strength()
				ConsoleLogger.show('info', 'Password verification entered', icon='🔄')
			else:
				args.password = getpass_with_strength()
				ConsoleLogger.show('info', 'Password entered by user', icon='🔑')

	if args.text:
		start_time = time.time()

		# Default to encrypt if decrypt is not explicitly set
		if not args.decrypt:
			ConsoleLogger.show('info', 'Encrypting text...')
			result = engine.encrypt_data(
				args.text.encode('utf-8'), args.password, keyfile_data, kdf_type, iterations
			)
			b64_result = base64.b64encode(result).decode('utf-8')
			ConsoleLogger.show('success', f'Encrypted (Base64): {b64_result}')
			if args.qr:
				show_qr_code(b64_result)
			elapsed_time = time.time() - start_time
			ConsoleLogger.show(
				'info', f'Output encrypted text length: {len(b64_result)} characters'
			)
			ConsoleLogger.show('success', 'Encryption completed successfully', icon='✅')
			ConsoleLogger.show('info', 'Operations completed: 1/1', icon='✔️')
			ConsoleLogger.show('info', f'Total time: {elapsed_time:.2f}s', icon='⏱️')
		else:
			ConsoleLogger.show('info', 'Decrypting text...')
			ConsoleLogger.show('debug', 'Decoding Base64 text input')
			raw_data = base64.b64decode(args.text)
			result = engine.decrypt_data(raw_data, args.password, keyfile_data)
			if result:
				ConsoleLogger.show(
					'success', f'Decrypted: {result.decode("utf-8")}', log_file=False
				)
				elapsed_time = time.time() - start_time
				ConsoleLogger.show(
					'info',
					f'Output decrypted text length: {len(result)} characters',
					log_file=False,
				)
				ConsoleLogger.show('success', 'Decryption completed successfully', icon='✅')
				ConsoleLogger.show('info', 'Operations completed: 1/1', icon='✔️')
				ConsoleLogger.show('info', f'Total time: {elapsed_time:.2f}s', icon='⏱️')

	elif args.file:
		# Recursive Directory Processing
		if args.recursive and os.path.isdir(args.file):
			input_dir = args.file
			mode_str = 'decrypt' if args.decrypt else 'encrypt'
			compression_str = 'enabled' if args.compress else 'disabled'
			lock_emoji = '🔓' if args.decrypt else '🔐'
			green = TerminalColors.Foreground.GREEN
			yellow = TerminalColors.Foreground.YELLOW
			blue = TerminalColors.Foreground.BLUE

			ConsoleLogger.show('debug', 'Recursive mode enabled')

			success_count = 0
			fail_count = 0
			start_time = time.time()

			for root, dirs, files in os.walk(input_dir):
				for file in files:
					file_path = os.path.join(root, file)

					if not args.decrypt:
						# Skip already encrypted files if in crypt mode
						if file.endswith('.enc'):
							continue

						out_path = file_path + '.enc'
						ConsoleLogger.show('info', f'Processing: {file_path}', icon='📄')
						if engine.encrypt_file(
							file_path,
							out_path,
							args.password,
							args.compress,
							keyfile_data,
							kdf_type,
							iterations,
						):
							success_count += 1
							ConsoleLogger.show(
								'success',
								f'File encrypted: {out_path} ({engine._format_size(os.path.getsize(out_path))})',
								icon='📄',
							)
						else:
							fail_count += 1
					else:
						# Decrypt mode: Only process .enc files (or whatever convention, here simplistic)
						if not file.endswith('.enc'):
							continue

						out_path = os.path.splitext(file_path)[0]  # Strip .enc
						# If extension was removed and no extension remains, might be an issue, but standard restore.
						if os.path.splitext(file_path)[0] == file_path:
							out_path = file_path + '.dec'

						ConsoleLogger.show('info', f'Processing: {file_path}', icon='📄')
						foot = parse_hidden_container_footer_from_path(file_path)
						if foot:
							ok_batch = engine.decrypt_hidden_container(
								file_path,
								out_path,
								args.password,
								hidden=args.hidden,
								compress=args.compress,
								keyfile_data=keyfile_data,
							)
						elif args.hidden:
							ConsoleLogger.show(
								'error',
								f'--hidden only applies to CTHV containers: {file_path}',
								icon='❌',
							)
							ok_batch = False
						else:
							ok_batch = engine.decrypt_file(
								file_path, out_path, args.password, args.compress, keyfile_data
							)
						if ok_batch:
							success_count += 1
							ConsoleLogger.show(
								'success',
								f'File decrypted: {out_path} ({engine._format_size(os.path.getsize(out_path))})',
								icon='📄',
							)
						else:
							fail_count += 1

			elapsed_time = time.time() - start_time
			total_ops = success_count + fail_count

			ConsoleLogger.show(
				'info', f'Batch complete. Success: {success_count}, Failed: {fail_count}'
			)
			if fail_count > 0:
				ConsoleLogger.show('warning', f'Some files failed to process: {fail_count} failed')
			ConsoleLogger.show('info', f'Total files processed: {total_ops}')
			ConsoleLogger.show('info', f'Successful: {success_count}')
			ConsoleLogger.show('info', f'Failed: {fail_count}')

			# Display completion summary
			ConsoleLogger.show(
				'success',
				f'{"Decryption" if args.decrypt else "Encryption"} completed successfully',
				icon='✅',
			)
			ConsoleLogger.show(
				'info', f'Operations completed: {success_count}/{total_ops}', icon='✔️'
			)
			ConsoleLogger.show('info', f'Total time: {elapsed_time:.2f}s', icon='⏱️')

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
				if not args.decrypt:
					if args.hidden_vol:
						ok = engine.encrypt_hidden_container(
							target,
							args.hidden_file,
							output_file,
							pw_outer,
							pw_hidden,
							args.compress,
							keyfile_data,
							kdf_type,
							iterations,
						)
					elif args.threshold:
						ok = engine.encrypt_with_threshold(
							target,
							output_file,
							args.password,
							args.threshold,
							args.compress,
							keyfile_data,
							kdf_type,
							iterations,
						)
					else:
						# For non-threshold encryption, extract single password from list
						single_password = _single_password_arg(args.password)
						ok = engine.encrypt_file(
							target,
							output_file,
							single_password,
							args.compress,
							keyfile_data,
							kdf_type,
							iterations,
						)
				else:
					foot = parse_hidden_container_footer_from_path(target)
					if foot:
						ok = engine.decrypt_hidden_container(
							target,
							output_file,
							args.password,
							hidden=args.hidden,
							compress=args.compress,
							keyfile_data=keyfile_data,
						)
					elif args.hidden:
						ConsoleLogger.show(
							'error',
							'--hidden only applies to files with a CTHV hidden-volume footer.',
						)
						ok = False
					else:
						# Check if file is threshold-encrypted by reading its header
						is_threshold_file = False
						try:
							with open(target, 'rb') as f:
								header = f.read(16)
								if header[:4] == Config.MAGIC:
									flags = header[5]
									is_threshold_file = bool(flags & Config.FLAG_THRESHOLD)
						except Exception:
							pass

						if args.threshold or is_threshold_file:
							ConsoleLogger.show(
								'debug', f'Decrypting with threshold, passwords: {args.password}'
							)
							ok = engine.decrypt_with_threshold(
								target,
								output_file,
								args.password,
								args.compress,
								keyfile_data,
							)
						else:
							# For non-threshold files, extract single password from list
							single_password = _single_password_arg(args.password)
							ok = engine.decrypt_file(
								target, output_file, single_password, args.compress, keyfile_data
							)
				if ok:
					success_count += 1
					ConsoleLogger.show(
						'success',
						f'File {"encrypted" if not args.decrypt else "decrypted"}: {output_file} ({engine._format_size(os.path.getsize(output_file))})',
						icon='📄',
					)
				else:
					fail_count += 1

			elapsed_time = time.time() - start_time
			total_ops = success_count + fail_count

			_log_completion_summary(args.decrypt, success_count, total_ops, elapsed_time)

			if fail_count > 0:
				abort(1)
		else:
			ConsoleLogger.show('error', f'File not found: {args.file}')
			ConsoleLogger.show('error', 'Operation failed: File does not exist')
			ConsoleLogger.show('error', 'Please check the file path and try again')
			abort(1)

	# Record end time
	finish_session()


if __name__ == '__main__':
	main()
