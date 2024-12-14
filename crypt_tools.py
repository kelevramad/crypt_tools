#!/usr/bin/python
# coding: utf-8
"""
Cryptographic Tool for File and Text Encryption/Decryption.

This script provides functionality for encrypting and decrypting text 
and files using AES encryption with optional compression.

Author: Central Intelligence Agency
Dependencies: 
- pycryptodome
- zlib
"""

import argparse
import base64
import hashlib
import os
import random
import sys
import time
import zlib

from typing import Optional
from typing import Union
from enum import StrEnum

# Third-party imports
import animation
from Crypto import Random
from Crypto.Cipher import AES

class CryptToolConfig:
    """Configuration constants for the Crypt Tools application."""
    
    AUTHOR: str = 'Center For Cyber Intelligence - Central Intelligence Agency'
    DESCRIPTION: str = 'Crypt Tools'
    VERSION: str = f"{AUTHOR}\n{DESCRIPTION} 1.1.0"
    BLOCK_SIZE: int = 16


class Arguments:
	"""
	Handles command line argument parsing for the cryptographic tool.
    Provides options for encryption/decryption modes, input/output specifications,
	and additional features like compression.
    """
	def __init__(self):
		pass

	def get_args(self):
		"""
        Sets up and processes command line arguments.
        
        Returns:
            argparse.Namespace: Parsed command line arguments
        """
		parser = argparse.ArgumentParser(description=CryptToolConfig.DESCRIPTION)
		parser.add_argument(
			'-m',
			'--mode',
			dest='mode',
			help='Option crypt or decrypt [default: crypt]',
			default='crypt',
			choices=['crypt', 'decrypt'],
		)
		group = parser.add_mutually_exclusive_group(required=True)
		group.add_argument('-t', '--text', dest='text', help='Plain-text for crypt/decrypt')
		group.add_argument(
			'-i',
			'--input',
			dest='input',
			help='Input file for crypt/decrypt.',
			type=argparse.FileType('r'),
			nargs='*',
		)
		parser.add_argument(
			'-o',
			'--output',
			dest='output',
			help='Output file for crypt/decrypt.',
			type=argparse.FileType('w'),
		)
		parser.add_argument(
			'-p',
			'--password',
			dest='password',
			help='Password for crypt.',
			required=True,
		)
		parser.add_argument(
			'-c',
			'--compress',
			dest='compress',
			help='Compress file before crypt/decompress after decrypt.',
			action='store_true',
		)
		parser.add_argument(
			'-d',
			'--debug',
			dest='debug',
			help='This argument allows debugging information.',
			action='store_true',
		)
		parser.add_argument(
			'-v',
			'--version',
			dest='version',
			help='This argument show version.',
			action='version',
			version=CryptToolConfig.VERSION,
		)

		# If no arguments were provided, then print help and exit.
		if len(sys.argv) == 1:
			parser.print_help()
			sys.exit(1)

		return parser.parse_args()


class TerminalColors(StrEnum):
	"""
	Provides ANSI escape codes for terminal color formatting.
	Includes foreground and background colors, as well as text styles.
	"""

	RESET: str = '\033[0m'
	BOLD: str = '\033[01m'
	DISABLE: str = '\033[02m'
	UNDERLINE: str = '\033[04m'
	REVERSE: str = '\033[07m'
	STRIKE_THROUGH: str = '\033[09m'
	INVISIBLE: str = '\033[08m'

	class Foreground(StrEnum):
		"""
		Foreground color codes for terminal text
		"""
		RED: str = '\033[31m'
		GREEN: str = '\033[32m'
		ORANGE: str = '\033[33m'
		BLUE: str = '\033[34m'
		PURPLE: str = '\033[35m'
		CYAN: str = '\033[36m'
		YELLOW: str = '\033[93m'
		PINK: str = '\033[95m'
		DARK_GREY: str = '\033[90m'
		LIGHT_GREY: str = '\033[37m'
		LIGHT_RED: str = '\033[91m'
		LIGHT_GREEN: str = '\033[92m'
		LIGHT_BLUE: str = '\033[94m'
		LIGHT_CYAN: str = '\033[96m'
		BLACK: str = '\033[30m'

	class Background(StrEnum):
		"""
		Background color codes for terminal text
		"""
		BLACK: str = '\033[40m'
		RED: str = '\033[41m'
		GREEN: str = '\033[42m'
		ORANGE: str = '\033[43m'
		BLUE: str = '\033[44m'
		PURPLE: str = '\033[45m'
		CYAN: str = '\033[46m'
		LIGHT_GREY: str = '\033[47m'


class Banner:
	"""
	Provides ASCII art banners for program display.
	Randomly selects one banner from available options.
	"""
	__BANNER: str = [
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
		"""
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
		"""

      ,ad8888ba,                                               888888888888                    88
     d8"'    `"8b                                     ,d            88                         88
    d8'                                               88            88                         88
    88            8b,dPPYba, 8b       d8 8b,dPPYba, MM88MMM         88  ,adPPYba,   ,adPPYba,  88 ,adPPYba,
    88            88P'   "Y8 `8b     d8' 88P'    "8a  88            88 a8"     "8a a8"     "8a 88 I8[    ""
    Y8,           88          `8b   d8'  88       d8  88            88 8b       d8 8b       d8 88  `"Y8ba,
     Y8a.    .a8P 88           `8b,d8'   88b,   ,a8"  88,           88 "8a,   ,a8" "8a,   ,a8" 88 aa    ]8I
      `"Y8888Y"'  88             Y88'    88`YbbdP"'   "Y888         88  `"YbbdP"'   `"YbbdP"'  88 `"YbbdP"'
                                 d8'     88
                                d8'      88
    """,
		"""
     ██████╗██████╗ ██╗   ██╗██████╗ ████████╗    ████████╗ ██████╗  ██████╗ ██╗     ███████╗
    ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝
    ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║          ██║   ██║   ██║██║   ██║██║     ███████╗
    ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║          ██║   ██║   ██║██║   ██║██║     ╚════██║
    ╚██████╗██║  ██║   ██║   ██║        ██║          ██║   ╚██████╔╝╚██████╔╝███████╗███████║
     ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝          ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
    """,
	]

	def __init__(self):
		pass

	@classmethod
	def get_banner(cls) -> str:
		"""
		Randomly selects and returns an ASCII art banner.

		Returns:
			str: Random ASCII art banner
		"""
		return cls.__BANNER[random.randint(0, len(cls.__BANNER) - 1)]

class MessageLevel:
    """
	Enumeration of message levels for logging.
	"""
    
    LIVE = 1
    DEAD = 2
    DEBUG = 3
    ERROR = 4
    WARNING = 5
    INFO = 6

class Logger:
	"""
	Handles formatted message output with different level indicators.
	Provides consistent formatting for various types of program messages.
	"""

	@staticmethod
	def _get_icon_level(level: int) -> str:
		"""
		Get the icon and color for a specific message level.

		Args:
			level (int): Message level from MessageLevel

		Returns:
			str: Colored icon for the message level
		"""
		level_icons = {
            MessageLevel.LIVE: (TerminalColors.Foreground.LIGHT_GREEN, '[+] '),
            MessageLevel.DEAD: (TerminalColors.Foreground.LIGHT_RED, '[-] '),
            MessageLevel.DEBUG: (TerminalColors.Foreground.YELLOW, '[!] '),
            MessageLevel.ERROR: (TerminalColors.Foreground.YELLOW, '[#] '),
            MessageLevel.WARNING: (TerminalColors.Foreground.PINK, '[*] '),
            MessageLevel.INFO: (TerminalColors.Foreground.LIGHT_BLUE, '[*] ')
        }

		color, icon = level_icons.get(level, (TerminalColors.Foreground.LIGHT_CYAN, '[%] '))
		return f"{color}{icon}{TerminalColors.RESET}"
        		
	@classmethod
	def log(cls, level: int, message: str) -> None:
		"""
		Log a message with the specified level to the console.

		Args:
			level (int): Message level from MessageLevel
			message (str): Message to log
		"""
		formatted_message = f'{cls._get_icon_level(level)}{message}'
		if not formatted_message.endswith('\n'):
			formatted_message = formatted_message + '\n'

		# sys.stdout.write(time.strftime('%H:%M:%S', time.localtime()) + '\n')
		sys.stdout.write(formatted_message)
		sys.stdout.flush()


class CryptTool:
	"""
	Handles encryption and decryption of text and files using AES encryption.

	Supports optional compression and provides utility methods for file handling.
	"""

	def __init__(self):
		pass

	@staticmethod
	def generate_key_hash(key: str) -> bytes:
		"""
		Generate an MD5 hash of the provided key.

		Args:
			key (str): Password or encryption key

		Returns:
			bytes: MD5 hash of the key
		"""
		return hashlib.md5(key.encode()).digest()

	@staticmethod
	def _format_file_size(num_bytes: int) -> str:
		"""
        Convert file size to human-readable format.
        
        Args:
            num_bytes (int): File size in bytes
        
        Returns:
            str: Formatted file size with appropriate unit
        """
		suffixes = [' bytes', 'KB', 'MB', 'GB', 'TB', 'PB']
		i: int = 0
		while num_bytes >= 1024 and i < len(suffixes) - 1:
			num_bytes /= 1024.0
			i += 1
		f = ('%.2f' % num_bytes).rstrip('0').rstrip('.')
		return f'{f}{suffixes[i]}'

	@animation.wait(animation='bar', text='Processing...')
	def encrypt(self, plain_text: Union[str, bytes], password: str) -> Optional[bytes]:
		"""
        Encrypt text using AES encryption in CFB mode.
        
        Args:
            plain_text (Union[str, bytes]): Text to encrypt
            password (str): Encryption password
        
        Returns:
            Optional[bytes]: Encrypted and base64 encoded text
        """
		try:
			# Ensure plain_text is bytes
			if isinstance(plain_text, str):
				plain_text = plain_text.encode()

			iv = Random.new().read(CryptToolConfig.BLOCK_SIZE)

			# Generate key hash
			key = self.generate_key_hash(password)

			# Create cipher
			cipher = AES.new(key, AES.MODE_CFB, iv)
			
			# Attempt encryption
			encrypted = base64.b64encode(iv + cipher.encrypt(plain_text))
			return encrypted
		except Exception as ex:
			line = sys.exc_info()[-1].tb_lineno
			Logger.log(MessageLevel.DEAD, 'Error encryption message')
			Logger.log(MessageLevel.DEAD, f'Line: {line} / Exception: {ex}')
			return None

	@animation.wait(animation='bar', text='Waiting...')
	def decrypt(self, encrypted_text: Union[str, bytes], password: str) -> Optional[bytes]:
		"""
        Decrypt AES-encrypted text.
        
        Args:
            encrypted_text (Union[str, bytes]): Base64 encoded encrypted text
            password (str): Decryption password
        
        Returns:
            Optional[bytes]: Decrypted text
        """
		# Ensure encrypted_text is bytes
		if isinstance(encrypted_text, str):
			encrypted_text = encrypted_text.encode()

		try:
			encrypted_bytes = base64.b64decode(encrypted_text)
			iv = encrypted_bytes[:CryptToolConfig.BLOCK_SIZE]

			# Generate key hash
			key = self.generate_key_hash(password)

			# Create cipher
			cipher = AES.new(key, AES.MODE_CFB, iv)

			# Attempt decryption
			decrypted = cipher.decrypt(encrypted_bytes[CryptToolConfig.BLOCK_SIZE:])
			return decrypted
		except Exception as ex:
			line = sys.exc_info()[-1].tb_lineno
			Logger.log(MessageLevel.DEAD, 'Error decryption message')
			Logger.log(MessageLevel.DEAD, f'Line: {line} / Exception: {ex}')
			return None

	@animation.wait(animation='bar', text='Loading File...')
	def _load_file(self, file_input: str) -> str:
		"""
		Reads binary content from a file.

		Args:
			file_input (str): Input file path
			
		Returns:
			str: Binary content of the file
		"""
		with open(file_input, 'rb') as f:
			content = f.read()
		return content

	@animation.wait(animation='bar', text='Compress File...')
	def _compress_content(self, content: str) -> str:
		"""
		Compresses content using zlib.

		Args:
			content (str): Content to compress
			
		Returns:
			str: Compressed content
		"""
		return zlib.compress(content, 9)

	@animation.wait(animation='bar', text='Decompress File...')
	def _decompress__content(self, content: str) -> str:
		"""
		Decompresses zlib compressed content.

		Args:
			content (str): Compressed content
			
		Returns:
			str: Decompressed content
		"""
		return zlib.decompress(content)

	@animation.wait(animation='bar', text='Writing File...')
	def _write_file(self, file_output: str, content: str):
		"""
		Writes binary content to a file.

		Args:
			file_output (str): Output file path
			content (str): Content to write
		"""
		with open(file_output, 'wb') as f:
			f.write(content)

	def encrypt_file(self, file_input: str, file_output: str, password: str, compress: str) -> None:
		"""
		Encrypts a file with optional compression.

		Args:
			file_input (str): Input file path
			file_output (str): Output file path
			password (str): Encryption password
			compress (str): Whether to compress the file before encryption
		"""
		file_size = self._format_file_size(os.path.getsize(file_input))
		
		Logger.log(MessageLevel.LIVE, f'Loading file: {file_input} (Size: {file_size})')
		content = self._load_file(file_input)

		if compress:
			try:
				Logger.log(MessageLevel.LIVE, f'Compress content file: {file_input}')
				content = self._compress_content(content)
			except Exception as ex:
				Logger.log(MessageLevel.DEAD, f'Error compress content file: {file_output}')
				Logger.log(MessageLevel.DEAD, f'Unexpected Exception: {ex} / Error: {sys.exc_info()}')
				return None

		Logger.log(MessageLevel.LIVE, 'Encryption content - OK')
		encrypted_content = self.encrypt(content, password)

		Logger.log(MessageLevel.LIVE, f'Write encryption file: {file_output}')
		self._write_file(file_output, encrypted_content)
		return None

	def decrypt_file(self, file_input: str, file_output: str, password: str, compress: str) -> None:
		"""
		Decrypts a file with optional decompression.

		Args:
			file_input (str): Input file path
			file_output (str): Output file path
			password (str): Decryption password
			compress (str): Whether to decompress after decryption
		"""
		file_size = self._format_file_size(os.path.getsize(file_input))

		Logger.log(MessageLevel.LIVE, f'Loading file: {file_input} (Size: {file_size})')
		content = self._load_file(file_input)

		Logger.log(MessageLevel.LIVE, 'Decryption content - OK')
		decrypted_content = self.decrypt(content, password)

		if compress:
			try:
				Logger.log(MessageLevel.LIVE, f'Decompress content file: {file_input}')
				decrypted_content = self._decompress__content(decrypted_content)
			except Exception as ex:
				Logger.log(MessageLevel.DEAD, f'Error decompress content file: {file_output} or incorrect password!')
				Logger.log(MessageLevel.DEAD, f'Unexpected Exception: {ex} / Error: {sys.exc_info()}')
				return None

		Logger.log(MessageLevel.LIVE, f'Write plain-text file: {file_output}')
		self._write_file(file_output, decrypted_content)
		return None


def main():
	"""
	Main function that orchestrates the encryption/decryption process.
	Handles program initialization, argument processing, and execution flow.
	"""
	# Clear screen based on platform
	os.system('clear' if sys.platform == 'linux' else 'cls')

	# Log start time
	start_time = time.time()

	# Initialize Class
	banner = Banner()
	crypt_tool = CryptTool()

	# Display random colored banner
	random_fg = random.choice(list(TerminalColors.Foreground)[:-1])
	print(random_fg + banner.get_banner() + TerminalColors.RESET)

	# Parse command line arguments
	args = Arguments().get_args()

	# Initialize Program
	# Enable debug mode if requested
	if args.debug:
		Logger.log(MessageLevel.DEBUG, 'Mode Debug On')

	# Generate encrypted password
	password_encrypted = crypt_tool.generate_key_hash(args.password).hex()

	# Handle encryption mode
	if args.mode == 'crypt':
		Logger.log(MessageLevel.LIVE, 'Encryption Start')
		Logger.log(MessageLevel.LIVE, f'Password: {args.password}')
		Logger.log(
			MessageLevel.LIVE,
			f'Password Encrypted: {password_encrypted}',
		)

		if args.text:
			encrypted = crypt_tool.encrypt(args.text, args.password)
			Logger.log(MessageLevel.LIVE, f'Message Plain-Text: {args.text}')
			Logger.log(MessageLevel.LIVE, f'Message Encrypted: {encrypted.decode('utf8')}')
		elif args.input:
			for input_file in args.input:
				output_file = (
					args.output.name if args.output 
					else os.path.splitext(input_file.name)[0] + '.enc'
				)
				crypt_tool.encrypt_file(input_file.name, output_file, args.password, args.compress)
	else:
		Logger.log(MessageLevel.LIVE, 'Decryption Start')
		Logger.log(MessageLevel.LIVE, f'Password: {args.password}')
		Logger.log(
			MessageLevel.LIVE,
			f'Password Encrypted: {password_encrypted}',
		)

		if args.text:
			msg_dec = crypt_tool.decrypt(args.text, args.password)
			Logger.log(MessageLevel.LIVE, f'Message Encrypted: {args.text}')
			Logger.log(MessageLevel.LIVE, f'Message Plain-Text: {msg_dec.decode('utf-8')}')
		elif args.input:
			for input_file in args.input:
				output_file = (
					args.output.name if args.output 
					else os.path.splitext(input_file.name)[0] + '.dec'
				)
				crypt_tool.decrypt_file(input_file.name, output_file, args.password, args.compress)

	# Log elapsed time
	end_time = time.time()
	elapsed_hours, remainder = divmod(end_time - start_time, 3600)
	elapsed_minutes, elapsed_seconds = divmod(remainder, 60)

	Logger.log(
		MessageLevel.INFO,
        f'Time Elapsed: {int(elapsed_hours):0>2}:{int(elapsed_minutes):0>2}:{elapsed_seconds:05.2f}'
	)


if __name__ == '__main__':
	main()
