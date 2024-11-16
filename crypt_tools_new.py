#!/usr/bin/python
# coding: utf-8

import argparse
import base64
import hashlib
import os
import random
import sys
import time
import zlib


import animation
from Crypto import Random
from Crypto.Cipher import AES

__AUTHOR: str = 'Center For Cyber Intelligence - Central Intelligence Agency'
_DESCRIPTION: str = 'Crypt Tools'
_VERSION: str = __AUTHOR + '\n' + _DESCRIPTION + ' 1.0.0'

_BLOCK_SIZE: int = 16


class Arguments:
	def __init__(self):
		pass

	def get_args(self):
		parser = argparse.ArgumentParser(description=_DESCRIPTION)
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
			version=_VERSION,
		)

		# If no arguments were provided, then print help and exit.
		if len(sys.argv) == 1:
			parser.print_help()
			sys.exit(1)

		return parser.parse_args()


class Colors:
	reset: str = '\033[0m'
	bold: str = '\033[01m'
	disable: str = '\033[02m'
	underline: str = '\033[04m'
	reverse: str = '\033[07m'
	strikethrough: str = '\033[09m'
	invisible: str = '\033[08m'

	class fg:
		black: str = '\033[30m'
		red: str = '\033[31m'
		green: str = '\033[32m'
		orange: str = '\033[33m'
		blue: str = '\033[34m'
		purple: str = '\033[35m'
		cyan: str = '\033[36m'
		lightgrey: str = '\033[37m'
		darkgrey: str = '\033[90m'
		lightred: str = '\033[91m'
		lightgreen: str = '\033[92m'
		yellow: str = '\033[93m'
		lightblue: str = '\033[94m'
		pink: str = '\033[95m'
		lightcyan: str = '\033[96m'

	class bg:
		black: str = '\033[40m'
		red: str = '\033[41m'
		green: str = '\033[42m'
		orange: str = '\033[43m'
		blue: str = '\033[44m'
		purple: str = '\033[45m'
		cyan: str = '\033[46m'
		lightgrey: str = '\033[47m'


class Banner:
	banner: str = [
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

	def get_banner(self):
		return self.__class__.banner[random.randint(0, len(self.__class__.banner) - 1)]


class Message:
	class Level:
		LIVE: int = 1
		DEAD: int = 2
		DEBUG: int = 3
		ERROR: int = 4
		WARNING: int = 5
		INFO: int = 6

	def icon_level(self, level: Level) -> str:
		if level == self.Level.LIVE:
			return Colors.fg.lightgreen + '[+] ' + Colors.reset
		if level == self.Level.DEAD:
			return Colors.fg.lightred + '[-] ' + Colors.reset
		if level == self.Level.DEBUG:
			return Colors.fg.yellow + '[!] ' + Colors.reset
		if level == self.Level.ERROR:
			return Colors.fg.yellow + '[#] ' + Colors.reset
		if level == self.Level.WARNING:
			return Colors.fg.pink + '[*] ' + Colors.reset
		if level == self.Level.INFO:
			return Colors.fg.lightblue + '[*] ' + Colors.reset

		return Colors.fg.lightcyan + '[%] ' + Colors.reset

	def show(self, level: Level, msg: str) -> None:
		msg = self.icon_level(level) + msg
		if not msg.endswith('\n'):
			msg = msg + '\n'

		# sys.stdout.write(time.strftime('%H:%M:%S', time.localtime()) + '\n')
		sys.stdout.write(msg)
		sys.stdout.flush()


class Crypt:
	def __init__(self):
		pass

	def trans(self, key: str) -> str:
		return hashlib.md5(key.encode()).digest()

	def humansize(self, nbytes: int) -> str:
		suffixes = [' bytes', 'KB', 'MB', 'GB', 'TB', 'PB']
		i: int = 0
		while nbytes >= 1024 and i < len(suffixes) - 1:
			nbytes /= 1024.0
			i += 1
		f = ('%.2f' % nbytes).rstrip('0').rstrip('.')
		return f'{f}{suffixes[i]}'

	@animation.wait(animation='bar', text='Waiting...')
	def encryption(self, plain_text: str, password: str) -> str:
		message = Message()
		try:
			iv = Random.new().read(_BLOCK_SIZE)
			aes = AES.new(self.trans(password), AES.MODE_CFB, iv)
			encode = base64.b64encode(iv + aes.encrypt(plain_text))
			return encode
		except Exception as ex:
			line = sys.exc_info()[-1].tb_lineno
			message.show(message.Level.DEAD, 'Error encryption message')
			message.show(message.Level.DEAD, f'Line: {line} / Exception: {ex} / Error: {sys.exc_info()}')
			return None

	@animation.wait(animation='bar', text='Waiting...')
	def decryption(self, encrypted: str, password: str) -> str:
		message = Message()
		try:
			encrypted = base64.b64decode(encrypted)
			iv = encrypted[:_BLOCK_SIZE]
			aes = AES.new(self.trans(password), AES.MODE_CFB, iv)
			decode = aes.decrypt(encrypted[_BLOCK_SIZE:])
			return decode
		except Exception as ex:
			message.show(message.Level.DEAD, 'Error decryption message')
			message.show(message.Level.DEAD, f'Unexpected Exception: {ex} / Error: {sys.exc_info()}')
			return None

	@animation.wait(animation='bar', text='Waiting...')
	def load_file(self, file_input: str) -> str:
		return open(file_input, 'rb').read()

	@animation.wait(animation='bar', text='Waiting...')
	def compress(self, content: str) -> str:
		return zlib.compress(content, 9)

	@animation.wait(animation='bar', text='Waiting...')
	def decompress(self, content: str) -> str:
		return zlib.decompress(content)

	@animation.wait(animation='bar', text='Waiting...')
	def write_file(self, file_output: str, content: str) -> None:
		file_write = open(file_output, 'wb')
		file_write.write(content)
		file_write.close()
		return

	def encrypt_file(self, file_input: str, file_output: str, password: str, compress: str) -> None:
		message = Message()
		size = self.humansize(os.path.getsize(file_input))
		message.show(message.Level.LIVE, f'Loading file / size: {file_input} / {size}')
		file_load = self.load_file(file_input)

		if compress:
			message.show(message.Level.LIVE, f'Compress content file: {file_input}')
			file_load = self.compress(file_load)
		message.show(message.Level.LIVE, 'Encryption content - OK')
		file_encrypt = self.encryption(file_load, password)

		message.show(message.Level.LIVE, f'Write encryption file: {file_output}')
		self.write_file(file_output, file_encrypt)
		return None

	def decrypt_file(self, file_input: str, file_output: str, password: str, compress: str) -> None:
		size = self.humansize(os.path.getsize(file_input))
		message = Message()
		message.show(message.Level.LIVE, f'Loading file / size: {file_input} / {size}')
		file_load = self.load_file(file_input)

		message.show(message.Level.LIVE, 'Decryption content - OK')
		file_decrypt = self.decryption(file_load, password)

		if compress:
			try:
				message.show(
					message.Level.LIVE,
					f'Decompress content file: {file_input}',
				)
				file_decrypt = self.decompress(file_decrypt)
			except Exception as ex:
				message.show(
					message.Level.DEAD,
					f'Error decompress content file: {file_output}',
				)
				message.show(message.Level.DEAD, f'Unexpected Exception: {ex} / Error: {sys.exc_info()}')
				return None

		message.show(message.Level.LIVE, f'Write plain-text file: {file_output}')
		self.write_file(file_output, file_decrypt)
		return None


def main():
	if sys.platform == 'linux':
		os.system('clear')
	else:
		os.system('cls')

	# Initialize Class
	tstart = time.time()

	color = Colors()
	banner = Banner()
	message = Message()
	crypt = Crypt()

	random_fg = random.choice(list(color.fg.__dict__.values())[1:-3])
	print(str(random_fg) + banner.get_banner() + color.reset)

	args = Arguments().get_args()

	# Initialize Program
	if args.output:
		_file_output = open(args.output.name, 'w')

	if args.debug:
		message.show(message.Level.DEBUG, 'Mode Debug On')

	password_encrypted = crypt.trans(args.password).hex()

	if args.mode == 'crypt':
		message.show(message.Level.LIVE, 'Encryption Start')
		message.show(message.Level.LIVE, f'Password: {args.password}')
		message.show(
			message.Level.LIVE,
			f'Password Encrypted: {password_encrypted}',
		)

		if args.text:
			msg_enc = crypt.encryption(args.text.encode(), args.password).decode('utf8')
			message.show(message.Level.LIVE, f'Message Plain-Text: {args.text}')
			message.show(message.Level.LIVE, f'Message Encrypted: {msg_enc}')
		elif args.input:
			for f in args.input:
				if len(args.input) > 1 or args.output is None:
					file_output = os.path.splitext(f.name)[0] + '.enc'
				else:
					file_output = args.output.name
				crypt.encrypt_file(f.name, file_output, args.password, args.compress)
	else:
		message.show(message.Level.LIVE, 'Decryption Start')
		message.show(message.Level.LIVE, f'Password: {args.password}')
		message.show(
			message.Level.LIVE,
			f'Password Encrypted: {password_encrypted}',
		)

		if args.text:
			msg_dec = crypt.decryption(args.text, args.password)
			message.show(message.Level.LIVE, f'Message Encrypted: {args.text}')
			message.show(message.Level.LIVE, f'Message Plain-Text: {msg_dec}')
		elif args.input:
			for f in args.input:
				if len(args.input) > 1 or args.output is None:
					file_output = os.path.splitext(f.name)[0] + '.dec'
				else:
					file_output = args.output.name
				crypt.decrypt_file(f.name, file_output, args.password, args.compress)

	tend = time.time()
	hours, rem = divmod(tend - tstart, 3600)
	minutes, seconds = divmod(rem, 60)

	message.show(
		message.Level.INFO,
		f'Time Elapsed: {int(hours):0>2}:{int(minutes):0>2}:{seconds:05.2f}',
	)


if __name__ == '__main__':
	main()
