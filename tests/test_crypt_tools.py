import os
import pytest
import tempfile
import base64
import crypt_tools
import io
import runpy
import types
import sys
import builtins
from crypt_tools import CryptoEngine, Config, ConsoleLogger, TerminalColors, main


@pytest.fixture
def engine():
	"""Fixture to create a CryptoEngine instance for tests."""
	return CryptoEngine()


def test_derive_key(engine):
	"""Test key derivation."""
	password = 'test_password'
	salt = os.urandom(16)
	key = engine._derive_key(password, salt)
	assert len(key) == 32
	assert isinstance(key, bytes)

	# Deterministic check
	key2 = engine._derive_key(password, salt)
	assert key == key2


def test_data_encryption_decryption(engine):
	"""Test authenticated encryption flow."""
	password = 'secure_password'
	data = b'Hello World AES-GCM'

	# Encrypt
	encrypted = engine.encrypt_data(data, password)
	assert len(encrypted) > len(data)

	# Structure check: HEADER(16) + SALT(16) + NONCE(12) + TAG(16) + DATA
	OVERHEAD = Config.FIXED_HEADER_SIZE + 16 + 12 + 16
	assert encrypted.startswith(Config.MAGIC)
	assert len(encrypted) == len(data) + OVERHEAD

	# Decrypt
	decrypted = engine.decrypt_data(encrypted, password)
	assert decrypted == data


def test_decryption_tampered_fails(engine):
	"""Test that tampering with ciphertext fails GCM verification."""
	password = 'pass'
	data = b'Sensitive Data'
	encrypted = bytearray(engine.encrypt_data(data, password))

	# Tamper with the last byte (content)
	encrypted[-1] ^= 0xFF

	result = engine.decrypt_data(bytes(encrypted), password)
	assert result is None  # Should fail integrity check


def test_decryption_wrong_password(engine):
	"""Test decryption with wrong password."""
	password = 'pass'
	data = b'Data'
	encrypted = engine.encrypt_data(data, password)

	result = engine.decrypt_data(encrypted, 'WRONG_PASS')
	assert result is None


def test_file_encryption_decryption(engine):
	"""Test file streaming encryption/decryption."""
	password = 'file_pass'
	content = b'Streamed file content' * 1000

	fd, input_path = tempfile.mkstemp()
	os.close(fd)

	with open(input_path, 'wb') as f:
		f.write(content)

	enc_path = input_path + '.enc'
	dec_path = input_path + '.dec'

	try:
		# Encrypt
		assert engine.encrypt_file(input_path, enc_path, password)
		assert os.path.exists(enc_path)

		# Verify overhead
		# HEADER(16) + SALT(16) + NONCE(12) + TAG(16) = 60 bytes overhead
		with open(enc_path, 'rb') as f:
			assert f.read(4) == Config.MAGIC
		assert os.path.getsize(enc_path) == len(content) + Config.FIXED_HEADER_SIZE + 44

		# Decrypt
		assert engine.decrypt_file(enc_path, dec_path, password)
		assert os.path.exists(dec_path)

		# Check content
		with open(dec_path, 'rb') as f:
			assert f.read() == content

	finally:
		for p in [input_path, enc_path, dec_path]:
			if os.path.exists(p):
				os.remove(p)


def test_file_compression(engine):
	"""Test compression flag."""
	password = 'compress_pass'
	# Compressible data (repeating pattern)
	content = b'A' * 10000

	with tempfile.NamedTemporaryFile(delete=False) as tmp_in:
		tmp_in.write(content)
		input_path = tmp_in.name

	enc_path = input_path + '.enc'
	dec_path = input_path + '.dec'

	try:
		# Encrypt with compression
		engine.encrypt_file(input_path, enc_path, password, compress=True)

		# Encrypted file should be much smaller than content (~44 bytes + tiny compressed size)
		enc_size = os.path.getsize(enc_path)
		assert enc_size < len(content)

		# Decrypt
		engine.decrypt_file(enc_path, dec_path, password, compress=True)
		with open(dec_path, 'rb') as f:
			assert f.read() == content

	finally:
		for p in [input_path, enc_path, dec_path]:
			if os.path.exists(p):
				os.remove(p)


def test_file_decryption_wrong_password_removes_output(engine):
	"""Test that a failed file decryption cleans up the partial output file."""
	password = 'correct_password'
	content = b'Sensitive data block'

	fd, input_path = tempfile.mkstemp()
	os.close(fd)

	with open(input_path, 'wb') as f:
		f.write(content)

	enc_path = input_path + '.enc'
	dec_path = input_path + '.dec'

	try:
		# 1. Encrypt with valid password
		assert engine.encrypt_file(input_path, enc_path, password)
		assert os.path.exists(enc_path)

		# 2. Decrypt with wrong password
		result = engine.decrypt_file(enc_path, dec_path, 'wrong_password')

		# 3. Verify it failed
		assert result is False

		# 4. Verify the generated output file is deleted
		assert not os.path.exists(dec_path)

	finally:
		for p in [input_path, enc_path, dec_path]:
			if os.path.exists(p):
				os.remove(p)


@pytest.fixture
def mock_getpass(monkeypatch):
	# Simple mock: Always returns 'cli_pass' for both prompt styles.
	monkeypatch.setattr(crypt_tools, 'getpass_with_strength', lambda prompt='': 'cli_pass')
	monkeypatch.setattr(
		crypt_tools,
		'getpass_verify_with_strength',
		lambda prompt1='Enter Password: ', prompt2='Verify Password: ': 'cli_pass',
	)


def test_cli_integration(monkeypatch, capsys, mock_getpass):
	"""Test main() CLI wrapper."""

	# Encrypt Text (Default mode) - No password arg provided, relies on getpass
	# Pass arguments explicitly, skipping the program name (argparse expects args list not including prog if passed explicitly?
	# Wait, existing main calls parse_args(argv). parser.parse_args(argv) usually expects full list OR arguments only?
	# If argv is passed to parse_args, it is used INSTEAD of sys.argv[1:].
	# So if I pass ['-t', '...'] it works.
	# If I pass ['prog', '-t', '...'] argparse might treat 'prog' as a positional arg?
	# NO: parser.parse_args(args) takes a list of strings to parse. The default is sys.argv[1:].
	# So I should NOT include 'prog' in the list I pass.

	main(['-t', 'CLI Test'])

	captured = capsys.readouterr()
	assert 'Encrypted (Base64):' in captured.out

	# Version
	# Version action prints and then exits using sys.exit()
	with pytest.raises(SystemExit):
		main(['-v'])
	captured = capsys.readouterr()
	assert Config.VERSION in captured.out or ''

	# Debug
	main(['--encrypt', '-t', 'A', '-p', 'B', '--debug'])
	captured = capsys.readouterr()
	assert 'Debug Mode Enabled' in captured.out


def test_cli_password_mismatch(monkeypatch, capsys):
	"""Test that password verification failure exits."""
	import getpass
	import sys

	# Mock getpass to return different passwords
	# First call: "pass1", Second call: "pass2"
	passwords = iter(['pass1', 'pass2'])
	monkeypatch.setattr(getpass, 'getpass', lambda prompt='': next(passwords))

	# Run encrypt (will prompt twice)
	with pytest.raises(SystemExit) as excinfo:
		main(['--encrypt', '-t', 'Verify Fail'])

	assert excinfo.value.code == 1
	captured = capsys.readouterr()
	assert 'Passwords do not match!' in captured.out


def test_recursive_directory(engine):
	"""Test recursive directory encryption."""
	password = 'dir_pass'

	with tempfile.TemporaryDirectory() as tmpdir:
		# Create structure
		subdir = os.path.join(tmpdir, 'subdir')
		os.makedirs(subdir)

		with open(os.path.join(tmpdir, 'file1.txt'), 'w') as f:
			f.write('content1')
		with open(os.path.join(subdir, 'file2.txt'), 'w') as f:
			f.write('content2')

		# Recursive Encrypt (use -f for file/directory path)
		main(['--encrypt', '-r', '-f', tmpdir, '-p', password])

		# Check files exist
		assert os.path.exists(os.path.join(tmpdir, 'file1.txt.enc'))
		assert os.path.exists(os.path.join(subdir, 'file2.txt.enc'))

		# Test Decrypt Recursively
		main(['--decrypt', '-r', '-f', tmpdir, '-p', password])

		# Check restored files
		with open(os.path.join(tmpdir, 'file1.txt'), 'r') as f:
			assert f.read() == 'content1'
		with open(os.path.join(subdir, 'file2.txt'), 'r') as f:
			assert f.read() == 'content2'


def test_cli_file_not_found(monkeypatch, capsys):
	"""Test error when file does not exist."""
	with pytest.raises(SystemExit) as excinfo:
		main(['-f', 'nonexistent_file.txt', '-p', 'pass'])

	assert excinfo.value.code == 1
	captured = capsys.readouterr()
	assert 'File not found' in captured.out


def test_cli_wildcard_encrypt_decrypt(monkeypatch, capsys, mock_getpass):
	"""Test wildcard pattern expansion for file groups."""
	password = 'wild_pass'
	with tempfile.TemporaryDirectory() as tmpdir:
		cwd = os.getcwd()
		monkeypatch.chdir(tmpdir)
		try:
			with open(os.path.join(tmpdir, 'a.md'), 'w') as f:
				f.write('alpha')
			with open(os.path.join(tmpdir, 'b.md'), 'w') as f:
				f.write('bravo')
			with open(os.path.join(tmpdir, 'c.txt'), 'w') as f:
				f.write('charlie')

			# Encrypt only .md files
			main(['--encrypt', '-f', '*.md', '-p', password])
			assert os.path.exists(os.path.join(tmpdir, 'a.md.enc'))
			assert os.path.exists(os.path.join(tmpdir, 'b.md.enc'))
			assert not os.path.exists(os.path.join(tmpdir, 'c.txt.enc'))

			# Decrypt only encrypted md files
			main(['--decrypt', '-f', '*.md.enc', '-p', password])
			with open(os.path.join(tmpdir, 'a.md.dec'), 'r') as f:
				assert f.read() == 'alpha'
			with open(os.path.join(tmpdir, 'b.md.dec'), 'r') as f:
				assert f.read() == 'bravo'
		finally:
			monkeypatch.chdir(cwd)


def test_cli_wildcard_no_match(monkeypatch, capsys, mock_getpass):
	"""Test wildcard pattern with no matches."""
	with tempfile.TemporaryDirectory() as tmpdir:
		cwd = os.getcwd()
		monkeypatch.chdir(tmpdir)
		try:
			with pytest.raises(SystemExit) as excinfo:
				main(['--encrypt', '-f', '*.nomatch', '-p', 'pass'])
			assert excinfo.value.code == 1
			captured = capsys.readouterr()
			assert 'No files matched pattern' in captured.out
		finally:
			monkeypatch.chdir(cwd)


def test_cli_directory_without_recursive(monkeypatch, capsys, mock_getpass):
	"""Test error when directory is provided without -r flag."""
	import tempfile

	with tempfile.TemporaryDirectory() as tmpdir:
		with pytest.raises(SystemExit) as excinfo:
			main(['-f', tmpdir, '-p', 'pass'])

		assert excinfo.value.code == 1
		captured = capsys.readouterr()
		assert 'Use -r/--recursive' in captured.out


def test_file_compression_encrypt_decrypt(engine):
	"""Test compression with encrypt and decrypt round-trip."""
	password = 'compress_test'
	# Highly compressible data
	content = b'AAAAAAAAAA' * 1000

	fd, input_path = tempfile.mkstemp()
	os.close(fd)

	with open(input_path, 'wb') as f:
		f.write(content)

	enc_path = input_path + '.enc'
	dec_path = input_path + '.dec'

	try:
		# Encrypt with compression
		assert engine.encrypt_file(input_path, enc_path, password, compress=True)

		# Decrypt with compression
		assert engine.decrypt_file(enc_path, dec_path, password, compress=True)

		# Verify content
		with open(dec_path, 'rb') as f:
			assert f.read() == content
	finally:
		for p in [input_path, enc_path, dec_path]:
			if os.path.exists(p):
				os.remove(p)


def test_console_logger_file_only(monkeypatch, tmp_path):
	"""Test ConsoleLogger writing to file only (no console)."""
	log_file = tmp_path / 'test.log'
	monkeypatch.setattr(ConsoleLogger, 'LOG_ENABLED', True)
	monkeypatch.setattr(ConsoleLogger, 'LOG_FILE', str(log_file))

	# Show with console disabled
	ConsoleLogger.show('info', 'Test message', show_console=False, log_file=True)

	# Verify file was written (read with UTF-8 encoding)
	content = log_file.read_text(encoding='utf-8')
	assert 'Test message' in content


def test_cli_with_log_flag(monkeypatch, capsys, mock_getpass):
	"""Test CLI with --log flag enabled."""
	import tempfile

	# Create a temp file
	fd, tmpfile = tempfile.mkstemp()
	os.close(fd)

	try:
		# Run with log flag
		main(['-f', tmpfile, '-p', 'testpass', '--log'])

		# Verify log file was created
		assert os.path.exists('crypt_tools.log')

		# Clean up log
		if os.path.exists('crypt_tools.log'):
			os.remove('crypt_tools.log')
	finally:
		if os.path.exists(tmpfile):
			os.remove(tmpfile)


def test_cli_debug_mode(monkeypatch, capsys, mock_getpass):
	"""Test CLI with --debug flag."""
	import tempfile

	fd, tmpfile = tempfile.mkstemp()
	os.close(fd)

	try:
		main(['-f', tmpfile, '-p', 'testpass', '--debug'])

		captured = capsys.readouterr()
		assert 'Debug Mode Enabled' in captured.out
	finally:
		if os.path.exists(tmpfile):
			os.remove(tmpfile)
		# Clean up any generated files
		if os.path.exists(tmpfile + '.enc'):
			os.remove(tmpfile + '.enc')


def test_decrypt_data_error_handling(engine):
	"""Test decrypt_data with tampered data."""
	password = 'test'
	data = b'Test data'

	encrypted = engine.encrypt_data(data, password)

	# Tamper with the data
	tampered = bytearray(encrypted)
	tampered[20] ^= 0xFF  # Flip a bit in the ciphertext

	result = engine.decrypt_data(bytes(tampered), password)
	assert result is None


def test_decrypt_data_too_short(engine):
	"""Test decrypt_data with too-short input."""
	result = engine.decrypt_data(b'short', 'pass')
	assert result is None


def test_format_size_pb(engine):
	"""Test _format_size for very large sizes."""
	size = 1024**5
	assert engine._format_size(size).endswith('PB')


def test_ensure_utf8_wrap_and_passthrough():
	"""Test ensure_utf8 wrapping and passthrough behavior."""

	class FakeStream:
		def __init__(self):
			self.encoding = 'cp1252'
			self.buffer = io.BytesIO()

	stream = FakeStream()
	wrapped = crypt_tools.ensure_utf8(stream)
	assert wrapped.encoding == 'utf-8'

	utf8_stream = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
	assert crypt_tools.ensure_utf8(utf8_stream) is utf8_stream


def test_import_error_missing_deps(monkeypatch, capsys):
	"""Simulate missing dependencies and ensure ImportError path executes."""
	real_import = builtins.__import__
	orig_stdout = sys.stdout
	orig_stderr = sys.stderr

	def fake_import(name, *args, **kwargs):
		if name == 'tqdm':
			raise ImportError('no tqdm')
		return real_import(name, *args, **kwargs)

	monkeypatch.setattr(builtins, '__import__', fake_import)
	with pytest.raises(SystemExit) as excinfo:
		runpy.run_path(
			os.path.join(os.path.dirname(crypt_tools.__file__), 'crypt_tools.py'),
			run_name='__main__',
		)
	assert excinfo.value.code == 1
	captured = capsys.readouterr()
	assert 'Missing dependencies' in captured.out
	sys.stdout = orig_stdout
	sys.stderr = orig_stderr


@pytest.mark.parametrize(
	'password,expected_strength',
	[
		('a', 'VERY_WEAK'),
		('abcdef', 'VERY_WEAK'),
		('Abc123!', 'WEAK'),
		('Abcdef12', 'MEDIUM'),
		('Abcdef12!', 'MEDIUM'),
		('Abcdef12!XyZ9#', 'STRONG'),
		('Abcdef12!XyZ9#QW', 'VERY_STRONG'),
	],
)
def test_password_strength_levels(password, expected_strength):
	result = crypt_tools.PasswordStrength.check(password)
	assert result['strength'] == expected_strength


def test_password_strength_indicator_and_types():
	strong_pw = 'Abcdef12!XyZ9#'
	weak_pw = ''
	assert 'Strong' in crypt_tools.PasswordStrength.get_indicator(strong_pw)
	types_strong = crypt_tools.PasswordStrength.get_char_types(strong_pw)
	types_weak = crypt_tools.PasswordStrength.get_char_types(weak_pw)
	assert (
		'Lower' in types_strong
		and 'Upper' in types_strong
		and 'Number' in types_strong
		and 'Symbol' in types_strong
	)
	assert (
		'Lower' in types_weak
		and 'Upper' in types_weak
		and 'Number' in types_weak
		and 'Symbol' in types_weak
	)


def test_getpass_with_strength_fallback(monkeypatch):
	monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
	monkeypatch.setattr(crypt_tools.getpass, 'getpass', lambda prompt='': 'pw')
	assert crypt_tools.getpass_with_strength() == 'pw'


def _make_win_getch(seq):
	it = iter(seq)

	def _getch():
		return next(it)

	return _getch


def test_getpass_with_strength_win32_sequence(monkeypatch):
	seq = [
		b'\x00',
		b'H',
		b'\x00',
		b'P',
		b'\x00',
		b'K',
		b'\x00',
		b'M',
		b'\x00',
		b'\x53',
		b'a',
		b'\b',
		b'B',
		b'\r',
	]
	import msvcrt

	monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
	monkeypatch.setattr(sys, 'platform', 'win32')
	monkeypatch.setattr(msvcrt, 'getch', _make_win_getch(seq))
	monkeypatch.setattr(sys, 'stdout', io.StringIO())
	assert crypt_tools.getpass_with_strength() == 'B'


def test_getpass_with_strength_win32_ctrl_c(monkeypatch):
	import msvcrt

	monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
	monkeypatch.setattr(sys, 'platform', 'win32')
	monkeypatch.setattr(msvcrt, 'getch', _make_win_getch([b'\x03']))
	monkeypatch.setattr(sys, 'stdout', io.StringIO())
	with pytest.raises(SystemExit):
		crypt_tools.getpass_with_strength()


def test_getpass_with_strength_unix_sequence(monkeypatch):
	class FakeStdin:
		def __init__(self, chars):
			self._it = iter(chars)

		def isatty(self):
			return True

		def fileno(self):
			return 0

		def read(self, n):
			return next(self._it)

	fake_termios = types.SimpleNamespace(
		TCSADRAIN=1,
		tcgetattr=lambda fd: 'old',
		tcsetattr=lambda fd, when, settings: None,
	)
	fake_tty = types.SimpleNamespace(setraw=lambda fd: None)
	monkeypatch.setattr(sys, 'platform', 'linux')
	monkeypatch.setattr(sys, 'stdin', FakeStdin(['a', '\b', 'B', '\r']))
	monkeypatch.setitem(sys.modules, 'termios', fake_termios)
	monkeypatch.setitem(sys.modules, 'tty', fake_tty)
	monkeypatch.setattr(sys, 'stdout', io.StringIO())
	assert crypt_tools.getpass_with_strength() == 'B'


def test_getpass_with_strength_unix_ctrl_c(monkeypatch):
	class FakeStdin:
		def __init__(self, chars):
			self._it = iter(chars)

		def isatty(self):
			return True

		def fileno(self):
			return 0

		def read(self, n):
			return next(self._it)

	fake_termios = types.SimpleNamespace(
		TCSADRAIN=1,
		tcgetattr=lambda fd: 'old',
		tcsetattr=lambda fd, when, settings: None,
	)
	fake_tty = types.SimpleNamespace(setraw=lambda fd: None)
	monkeypatch.setattr(sys, 'platform', 'linux')
	monkeypatch.setattr(sys, 'stdin', FakeStdin(['\x03']))
	monkeypatch.setitem(sys.modules, 'termios', fake_termios)
	monkeypatch.setitem(sys.modules, 'tty', fake_tty)
	monkeypatch.setattr(sys, 'stdout', io.StringIO())
	with pytest.raises(SystemExit):
		crypt_tools.getpass_with_strength()


def test_getpass_with_strength_unix_ctrl_d(monkeypatch):
	class FakeStdin:
		def __init__(self, chars):
			self._it = iter(chars)

		def isatty(self):
			return True

		def fileno(self):
			return 0

		def read(self, n):
			return next(self._it)

	fake_termios = types.SimpleNamespace(
		TCSADRAIN=1,
		tcgetattr=lambda fd: 'old',
		tcsetattr=lambda fd, when, settings: None,
	)
	fake_tty = types.SimpleNamespace(setraw=lambda fd: None)
	monkeypatch.setattr(sys, 'platform', 'linux')
	monkeypatch.setattr(sys, 'stdin', FakeStdin(['\x04']))
	monkeypatch.setitem(sys.modules, 'termios', fake_termios)
	monkeypatch.setitem(sys.modules, 'tty', fake_tty)
	monkeypatch.setattr(sys, 'stdout', io.StringIO())
	assert crypt_tools.getpass_with_strength() == ''


def test_getpass_verify_with_strength_fallback_empty(monkeypatch):
	monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
	monkeypatch.setattr(crypt_tools.getpass, 'getpass', lambda prompt='': '')
	with pytest.raises(SystemExit):
		crypt_tools.getpass_verify_with_strength()


def test_getpass_verify_with_strength_fallback_mismatch(monkeypatch):
	monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
	answers = iter(['pw1', 'pw2'])
	monkeypatch.setattr(crypt_tools.getpass, 'getpass', lambda prompt='': next(answers))
	with pytest.raises(SystemExit):
		crypt_tools.getpass_verify_with_strength()


def test_getpass_verify_with_strength_fallback_success(monkeypatch):
	monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
	answers = iter(['pw', 'pw'])
	monkeypatch.setattr(crypt_tools.getpass, 'getpass', lambda prompt='': next(answers))
	assert crypt_tools.getpass_verify_with_strength() == 'pw'


def test_getpass_verify_with_strength_win32_sequence(monkeypatch):
	seq = [
		b'\x00',
		b'H',
		b'\x00',
		b'P',
		b'\x00',
		b'K',
		b'\x00',
		b'M',
		b'\x00',
		b'\x53',
		b'a',
		b'\b',
		b'B',
		b'\r',
	]
	import msvcrt

	monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
	monkeypatch.setattr(sys, 'platform', 'win32')
	monkeypatch.setattr(crypt_tools, 'getpass_with_strength', lambda prompt='': 'B')
	monkeypatch.setattr(msvcrt, 'getch', _make_win_getch(seq))
	monkeypatch.setattr(sys, 'stdout', io.StringIO())
	assert crypt_tools.getpass_verify_with_strength() == 'B'


def test_getpass_verify_with_strength_interactive_empty(monkeypatch):
	monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
	monkeypatch.setattr(crypt_tools, 'getpass_with_strength', lambda prompt='': '')
	with pytest.raises(SystemExit):
		crypt_tools.getpass_verify_with_strength()


def test_getpass_verify_with_strength_win32_ctrl_c(monkeypatch):
	import msvcrt

	monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
	monkeypatch.setattr(sys, 'platform', 'win32')
	monkeypatch.setattr(crypt_tools, 'getpass_with_strength', lambda prompt='': 'B')
	monkeypatch.setattr(msvcrt, 'getch', _make_win_getch([b'\x03']))
	monkeypatch.setattr(sys, 'stdout', io.StringIO())
	with pytest.raises(SystemExit):
		crypt_tools.getpass_verify_with_strength()


def test_getpass_verify_with_strength_unix_sequence(monkeypatch):
	class FakeStdin:
		def __init__(self, chars):
			self._it = iter(chars)

		def isatty(self):
			return True

		def fileno(self):
			return 0

		def read(self, n):
			return next(self._it)

	fake_termios = types.SimpleNamespace(
		TCSADRAIN=1,
		tcgetattr=lambda fd: 'old',
		tcsetattr=lambda fd, when, settings: None,
	)
	fake_tty = types.SimpleNamespace(setraw=lambda fd: None)
	monkeypatch.setattr(sys, 'platform', 'linux')
	monkeypatch.setattr(sys, 'stdin', FakeStdin(['a', '\b', 'B', '\r']))
	monkeypatch.setitem(sys.modules, 'termios', fake_termios)
	monkeypatch.setitem(sys.modules, 'tty', fake_tty)
	monkeypatch.setattr(crypt_tools, 'getpass_with_strength', lambda prompt='': 'B')
	monkeypatch.setattr(sys, 'stdout', io.StringIO())
	assert crypt_tools.getpass_verify_with_strength() == 'B'


def test_getpass_verify_with_strength_unix_ctrl_c(monkeypatch):
	class FakeStdin:
		def __init__(self, chars):
			self._it = iter(chars)

		def isatty(self):
			return True

		def fileno(self):
			return 0

		def read(self, n):
			return next(self._it)

	fake_termios = types.SimpleNamespace(
		TCSADRAIN=1,
		tcgetattr=lambda fd: 'old',
		tcsetattr=lambda fd, when, settings: None,
	)
	fake_tty = types.SimpleNamespace(setraw=lambda fd: None)
	monkeypatch.setattr(sys, 'platform', 'linux')
	monkeypatch.setattr(sys, 'stdin', FakeStdin(['\x03']))
	monkeypatch.setitem(sys.modules, 'termios', fake_termios)
	monkeypatch.setitem(sys.modules, 'tty', fake_tty)
	monkeypatch.setattr(crypt_tools, 'getpass_with_strength', lambda prompt='': 'B')
	monkeypatch.setattr(sys, 'stdout', io.StringIO())
	with pytest.raises(SystemExit):
		crypt_tools.getpass_verify_with_strength()


def test_getpass_verify_with_strength_unix_ctrl_d_mismatch(monkeypatch):
	class FakeStdin:
		def __init__(self, chars):
			self._it = iter(chars)

		def isatty(self):
			return True

		def fileno(self):
			return 0

		def read(self, n):
			return next(self._it)

	fake_termios = types.SimpleNamespace(
		TCSADRAIN=1,
		tcgetattr=lambda fd: 'old',
		tcsetattr=lambda fd, when, settings: None,
	)
	fake_tty = types.SimpleNamespace(setraw=lambda fd: None)
	monkeypatch.setattr(sys, 'platform', 'linux')
	monkeypatch.setattr(sys, 'stdin', FakeStdin(['\x04']))
	monkeypatch.setitem(sys.modules, 'termios', fake_termios)
	monkeypatch.setitem(sys.modules, 'tty', fake_tty)
	monkeypatch.setattr(crypt_tools, 'getpass_with_strength', lambda prompt='': 'B')
	monkeypatch.setattr(sys, 'stdout', io.StringIO())
	with pytest.raises(SystemExit):
		crypt_tools.getpass_verify_with_strength()


def test_cli_text_decrypt_no_password(monkeypatch, capsys):
	password = 'pw'
	engine = CryptoEngine()
	enc = engine.encrypt_data(b'hello', password)
	b64 = base64.b64encode(enc).decode('utf-8')
	monkeypatch.setattr(crypt_tools, 'getpass_with_strength', lambda prompt='': password)
	main(['--decrypt', '-t', b64])
	captured = capsys.readouterr()
	assert 'Decrypted: hello' in captured.out


def test_inspect_file_reports_ct02_metadata(engine, tmp_path):
	password = 'pw'
	infile = tmp_path / 'data.txt'
	infile.write_text('secret')
	encfile = tmp_path / 'data.txt.enc'

	assert engine.encrypt_file(str(infile), str(encfile), password, compress=True)

	details = engine.inspect_file(str(encfile))
	assert details['format'] == 'CT02'
	assert details['legacy'] is False
	assert details['compression'] == 'enabled'
	assert details['iterations'] == Config.PBKDF2_ITERATIONS


def test_cli_inspect_file(capsys, tmp_path):
	password = 'pw'
	engine = CryptoEngine()
	infile = tmp_path / 'data.txt'
	infile.write_text('secret')
	encfile = tmp_path / 'data.txt.enc'

	assert engine.encrypt_file(str(infile), str(encfile), password)

	main(['--inspect', '-f', str(encfile)])
	captured = capsys.readouterr()
	assert 'Format: CT02' in captured.out
	assert 'Compression: disabled' in captured.out


def test_inspect_file_rejects_plaintext_file(engine, tmp_path):
	infile = tmp_path / 'plain.txt'
	infile.write_text('this is not encrypted')

	with pytest.raises(
		ValueError,
		match='Unrecognized file format. Only CT02 encrypted files can be inspected reliably',
	):
		engine.inspect_file(str(infile))


def test_cli_inspect_missing_file(capsys, tmp_path):
	missing = tmp_path / 'missing.txt'

	with pytest.raises(SystemExit) as excinfo:
		main(['--inspect', '-f', str(missing)])

	assert excinfo.value.code == 1
	captured = capsys.readouterr()
	assert 'File not found' in captured.out


def test_cli_inspect_plaintext_file(capsys, tmp_path):
	infile = tmp_path / 'plain.txt'
	infile.write_text('not encrypted')

	with pytest.raises(SystemExit) as excinfo:
		main(['--inspect', '-f', str(infile)])

	assert excinfo.value.code == 1
	captured = capsys.readouterr()
	assert 'Inspect failed' in captured.out
	assert 'supported encrypted file' in captured.out


def test_recursive_wildcard_glob_recursive(monkeypatch, tmp_path):
	password = 'pw'
	(tmp_path / 'a.txt').write_text('a')
	nested = tmp_path / 'nested'
	nested.mkdir()
	(nested / 'b.txt').write_text('b')
	cwd = os.getcwd()
	monkeypatch.chdir(tmp_path)
	try:
		main(['--encrypt', '-r', '-f', '*.txt', '-p', password])
		assert (tmp_path / 'a.txt.enc').exists()
		assert (nested / 'b.txt.enc').exists()
	finally:
		monkeypatch.chdir(cwd)


def test_recursive_wildcard_with_directory(monkeypatch, tmp_path):
	password = 'pw'
	tests_dir = tmp_path / 'tests'
	nested = tests_dir / 'nested'
	nested.mkdir(parents=True)
	(nested / 'b.txt').write_text('b')
	pattern = os.path.join('.', 'tests', '*.txt')
	cwd = os.getcwd()
	monkeypatch.chdir(tmp_path)
	try:
		main(['--encrypt', '-r', '-f', pattern, '-p', password])
		assert (nested / 'b.txt.enc').exists()
	finally:
		monkeypatch.chdir(cwd)


def test_recursive_encrypt_fail_count(monkeypatch, tmp_path):
	password = 'pw'
	(tmp_path / 'a.txt').write_text('a')
	monkeypatch.setattr(
		crypt_tools.CryptoEngine, 'encrypt_file', lambda self, i, o, p, compress=False: False
	)
	main(['--encrypt', '-r', '-f', str(tmp_path), '-p', password])


def test_recursive_decrypt_no_ext_file(monkeypatch, tmp_path):
	password = 'pw'
	(tmp_path / '.enc').write_text('not_encrypted')
	monkeypatch.setattr(
		crypt_tools.CryptoEngine, 'decrypt_file', lambda self, i, o, p, compress=False: False
	)
	main(['--decrypt', '-r', '-f', str(tmp_path), '-p', password])


def test_non_recursive_output_arg(tmp_path):
	password = 'pw'
	infile = tmp_path / 'a.txt'
	infile.write_text('data')
	outfile = tmp_path / 'custom.out'
	main(['--encrypt', '-f', str(infile), '-o', str(outfile), '-p', password])
	assert outfile.exists()


def test_non_recursive_fail_exit(monkeypatch, tmp_path):
	password = 'pw'
	infile = tmp_path / 'a.txt'
	infile.write_text('data')
	monkeypatch.setattr(
		crypt_tools.CryptoEngine, 'encrypt_file', lambda self, i, o, p, compress=False: False
	)
	with pytest.raises(SystemExit):
		main(['--encrypt', '-f', str(infile), '-p', password])


def test_non_recursive_skips_directory(monkeypatch, tmp_path):
	password = 'pw'
	d = tmp_path / 'dir1'
	d.mkdir()
	cwd = os.getcwd()
	monkeypatch.chdir(tmp_path)
	monkeypatch.setattr(os.path, 'isfile', lambda p: True)
	try:
		main(['--encrypt', '-f', '*', '-p', password])
	finally:
		monkeypatch.chdir(cwd)


def test_file_not_found_end_branch(monkeypatch):
	password = 'pw'
	messages = []

	def fake_show(level, message, **kwargs):
		messages.append(message)

	monkeypatch.setattr(crypt_tools.ConsoleLogger, 'show', fake_show)
	monkeypatch.setattr(os.path, 'getsize', lambda p: 1)
	monkeypatch.setattr(sys, 'exit', lambda code=0: None)
	main(['--encrypt', '-f', '*.nomatch', '-p', password])
	assert any('File not found' in m for m in messages)


def test_encrypt_file_exception_cleanup(monkeypatch, tmp_path):
	engine = CryptoEngine()
	infile = tmp_path / 'in.txt'
	infile.write_text('data')
	outfile = tmp_path / 'out.enc'

	class FakeCipher:
		def encrypt(self, data):
			raise RuntimeError('boom')

	monkeypatch.setattr(crypt_tools.AES, 'new', lambda *args, **kwargs: FakeCipher())
	assert engine.encrypt_file(str(infile), str(outfile), 'pw') is False
	assert not outfile.exists()


def test_decrypt_file_truncated_compress(monkeypatch, tmp_path):
	engine = CryptoEngine()
	infile = tmp_path / 'in.txt'
	infile.write_text('data' * 100)
	encfile = tmp_path / 'in.txt.enc'
	decfile = tmp_path / 'out.txt'
	assert engine.encrypt_file(str(infile), str(encfile), 'pw', compress=True)

	real_getsize = os.path.getsize
	monkeypatch.setattr(os.path, 'getsize', lambda p: real_getsize(p) + 10)
	assert engine.decrypt_file(str(encfile), str(decfile), 'pw', compress=True) is False


def test_decrypt_file_exception_cleanup(monkeypatch, tmp_path):
	engine = CryptoEngine()
	infile = tmp_path / 'in.txt'
	infile.write_text('data')
	encfile = tmp_path / 'in.txt.enc'
	decfile = tmp_path / 'out.txt'
	assert engine.encrypt_file(str(infile), str(encfile), 'pw')

	class FakeCipher:
		def decrypt(self, data):
			raise RuntimeError('boom')

		def verify(self, tag):
			return None

	monkeypatch.setattr(crypt_tools.AES, 'new', lambda *args, **kwargs: FakeCipher())

	def fake_remove(path):
		raise OSError('nope')

	monkeypatch.setattr(os, 'remove', fake_remove)
	assert engine.decrypt_file(str(encfile), str(decfile), 'pw') is False
	assert decfile.exists()


def test_decrypt_file_unexpected_eof_warning(monkeypatch, tmp_path):
	engine = CryptoEngine()
	infile = tmp_path / 'in.txt'
	infile.write_text('data' * 50)
	encfile = tmp_path / 'in.txt.enc'
	decfile = tmp_path / 'out.txt'
	assert engine.encrypt_file(str(infile), str(encfile), 'pw', compress=True)

	real_getsize = os.path.getsize
	monkeypatch.setattr(os.path, 'getsize', lambda p: real_getsize(p) + 100)
	warnings = []

	def fake_show(level, message, **kwargs):
		if level == 'warning':
			warnings.append(message)

	monkeypatch.setattr(crypt_tools.ConsoleLogger, 'show', fake_show)
	assert engine.decrypt_file(str(encfile), str(decfile), 'pw', compress=True) is False
	assert any('Unexpected end of file' in w for w in warnings)


def test_run_as_script(monkeypatch, capsys):
	argv = ['crypt_tools.py', '-t', 'hi', '-p', 'pw']
	orig_stdout = sys.stdout
	orig_stderr = sys.stderr
	buf_bytes = io.BytesIO()
	monkeypatch.setattr(sys, 'argv', argv)
	sys.stdout = io.TextIOWrapper(buf_bytes, encoding='utf-8', write_through=True)
	sys.stderr = io.TextIOWrapper(io.BytesIO(), encoding='utf-8', write_through=True)
	runpy.run_module('crypt_tools', run_name='__main__')
	assert 'Encrypted (Base64):' in buf_bytes.getvalue().decode('utf-8', errors='ignore')
	sys.stdout = orig_stdout
	sys.stderr = orig_stderr


def test_encrypt_file_error_handling(engine, monkeypatch):
	"""Test encrypt_file handles errors gracefully."""
	password = 'test'

	# Try to encrypt a non-existent file
	result = engine.encrypt_file('nonexistent.txt', 'out.enc', password)
	assert result is False


def test_decrypt_file_error_handling(engine, monkeypatch):
	"""Test decrypt_file handles errors gracefully."""
	password = 'test'

	# Create a too-small file
	fd, tmpfile = tempfile.mkstemp()
	os.close(fd)
	with open(tmpfile, 'wb') as f:
		f.write(b'small')  # Too small to be valid

	try:
		result = engine.decrypt_file(tmpfile, 'out.dec', password)
		assert result is False
	finally:
		if os.path.exists(tmpfile):
			os.remove(tmpfile)
		if os.path.exists('out.dec'):
			os.remove('out.dec')
