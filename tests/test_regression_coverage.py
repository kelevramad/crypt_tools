"""Regression tests covering paths that lacked direct coverage prior to v2.10.0.

Focus areas:
- RecoveryKeyUtils unit + roundtrip behavior
- CryptoEngine.encrypt_data/encrypt_file with recovery key end-to-end
- ConfigParser.parse_yaml / parse_conf / parse_bool / read_file
- CryptoEngine threshold encrypt-decrypt roundtrip
- CLI validation error paths (recovery-key + hidden-vol, hidden-vol misuse, invalid --kdf)
- Hidden container with key file
"""

from __future__ import annotations

import json
import os

import pytest

import crypt_tools
from crypt_tools import (
	Config,
	ConfigParser,
	CryptoEngine,
	KeyFileUtils,
	RecoveryKeyUtils,
	main,
)


# ---------------------------------------------------------------------------
# RecoveryKeyUtils — unit behavior
# ---------------------------------------------------------------------------


def test_recovery_key_generate_size_and_uniqueness():
	a = RecoveryKeyUtils.generate()
	b = RecoveryKeyUtils.generate()
	assert len(a) == Config.RECOVERY_KEY_SIZE == 32
	assert isinstance(a, bytes)
	assert a != b, 'two generated recovery keys must differ'


def test_recovery_key_encrypt_decrypt_roundtrip():
	derived = os.urandom(Config.KEY_SIZE)
	rkey = RecoveryKeyUtils.generate()
	blob = RecoveryKeyUtils.encrypt_derived_key(derived, rkey)

	# nonce(12) + ciphertext(32) + tag(16) == 60
	assert len(blob) == Config.NONCE_SIZE + Config.KEY_SIZE + Config.TAG_SIZE
	assert RecoveryKeyUtils.decrypt_derived_key(blob, rkey) == derived


def test_recovery_key_decrypt_wrong_key_returns_none():
	derived = os.urandom(Config.KEY_SIZE)
	rkey = RecoveryKeyUtils.generate()
	blob = RecoveryKeyUtils.encrypt_derived_key(derived, rkey)
	other = RecoveryKeyUtils.generate()
	assert RecoveryKeyUtils.decrypt_derived_key(blob, other) is None


def test_recovery_key_decrypt_short_blob_returns_none():
	short = b'\x00' * (Config.NONCE_SIZE + Config.KEY_SIZE + Config.TAG_SIZE - 1)
	assert RecoveryKeyUtils.decrypt_derived_key(short, RecoveryKeyUtils.generate()) is None


def test_recovery_key_decrypt_tampered_blob_returns_none():
	derived = os.urandom(Config.KEY_SIZE)
	rkey = RecoveryKeyUtils.generate()
	blob = bytearray(RecoveryKeyUtils.encrypt_derived_key(derived, rkey))
	blob[-1] ^= 0xFF  # corrupt GCM tag
	assert RecoveryKeyUtils.decrypt_derived_key(bytes(blob), rkey) is None


def test_recovery_key_write_then_read_roundtrip(tmp_path):
	path = str(tmp_path / 'recovery.txt')
	rkey = RecoveryKeyUtils.generate()
	assert RecoveryKeyUtils.write_recovery_key(path, rkey)
	assert RecoveryKeyUtils.read_recovery_key(path) == rkey


def test_recovery_key_read_missing_file(tmp_path):
	assert RecoveryKeyUtils.read_recovery_key(str(tmp_path / 'does_not_exist.txt')) is None


def test_recovery_key_read_empty_file(tmp_path):
	path = tmp_path / 'empty.txt'
	path.write_text('')
	assert RecoveryKeyUtils.read_recovery_key(str(path)) is None


def test_recovery_key_read_invalid_chars(tmp_path):
	path = tmp_path / 'bad.txt'
	path.write_text('not!a@valid#recovery$key')
	assert RecoveryKeyUtils.read_recovery_key(str(path)) is None


def test_recovery_key_read_wrong_size(tmp_path):
	path = tmp_path / 'short.txt'
	# 'AAAA' decodes to 3 bytes — far less than RECOVERY_KEY_SIZE.
	path.write_text('AAAA')
	assert RecoveryKeyUtils.read_recovery_key(str(path)) is None


# ---------------------------------------------------------------------------
# Engine — recovery key end-to-end
# ---------------------------------------------------------------------------


def test_engine_encrypt_data_recovery_key_path_extends_payload(tmp_path, capsys):
	"""encrypt_data with recovery_key_path writes the key file and embeds the recovery blob."""
	engine = CryptoEngine()
	rkey_path = str(tmp_path / 'rk.txt')

	plaintext = b'recover-me'
	ct = engine.encrypt_data(plaintext, 'pw', recovery_key_path=rkey_path)
	capsys.readouterr()  # drain status output

	# Recovery key file was written and is a valid 32-byte key.
	rkey = RecoveryKeyUtils.read_recovery_key(rkey_path)
	assert rkey is not None and len(rkey) == Config.RECOVERY_KEY_SIZE

	# Decrypting via the recovery key only (no password) yields the plaintext.
	assert engine.decrypt_data(ct, password='', recovery_key_data=rkey) == plaintext


def test_engine_encrypt_file_recovery_key_decrypt_without_password(tmp_path, capsys):
	"""encrypt_file → decrypt_file using recovery key only (empty password)."""
	engine = CryptoEngine()
	src = tmp_path / 'doc.txt'
	src.write_bytes(b'hello recovery world')
	enc = tmp_path / 'doc.enc'
	out = tmp_path / 'doc.out'
	rkey_path = str(tmp_path / 'doc.recovery.txt')

	assert engine.encrypt_file(
		str(src), str(enc), 'real-password', recovery_key_path=rkey_path
	)
	capsys.readouterr()

	rkey = RecoveryKeyUtils.read_recovery_key(rkey_path)
	assert rkey is not None

	# Use the recovery key without the original password.
	assert engine.decrypt_file(str(enc), str(out), password='', recovery_key_data=rkey)
	assert out.read_bytes() == b'hello recovery world'


# ---------------------------------------------------------------------------
# ConfigParser — yaml/conf/bool/read_file
# ---------------------------------------------------------------------------


def test_config_parse_yaml_basic_and_comments():
	content = """
# leading comment
password: pw1
kdf: argon2   # inline comment kept as part of value
iterations: 5
"""
	parsed = ConfigParser.parse_yaml(content)
	assert parsed['password'] == 'pw1'
	assert parsed['iterations'] == '5'
	# parse_yaml does not strip inline comments; coercion later handles that.
	assert 'argon2' in parsed['kdf']


def test_config_parse_yaml_invalid_line_raises():
	with pytest.raises(ValueError):
		ConfigParser.parse_yaml('this_line_has_no_colon')


def test_config_parse_conf_supports_equals_and_colon():
	parsed_eq = ConfigParser.parse_conf('password = pw1\nkdf = pbkdf2')
	parsed_col = ConfigParser.parse_conf('password: pw1\nkdf: pbkdf2')
	assert parsed_eq == {'password': 'pw1', 'kdf': 'pbkdf2'}
	assert parsed_col == {'password': 'pw1', 'kdf': 'pbkdf2'}


def test_config_parse_conf_skips_comments_and_semicolons():
	content = """
# hash comment
; semicolon comment
password = pw
"""
	assert ConfigParser.parse_conf(content) == {'password': 'pw'}


def test_config_parse_conf_invalid_line_raises():
	with pytest.raises(ValueError):
		ConfigParser.parse_conf('just_a_bare_word')


@pytest.mark.parametrize(
	'value,expected',
	[
		(True, True),
		(False, False),
		(1, True),
		(0, False),
		('true', True),
		('YES', True),
		('on', True),
		('1', True),
		('false', False),
		('No', False),
		('off', False),
		('0', False),
	],
)
def test_config_parse_bool_variants(value, expected):
	assert ConfigParser.parse_bool(value) is expected


def test_config_parse_bool_rejects_invalid():
	with pytest.raises(ValueError):
		ConfigParser.parse_bool('maybe')


def test_config_read_file_yaml(tmp_path):
	cfg = tmp_path / 'config.yml'
	cfg.write_text('password: yaml-pw\nkdf: argon2\niterations: 3\n')
	parsed = ConfigParser.read_file(str(cfg))
	assert parsed == {'password': 'yaml-pw', 'kdf': 'argon2', 'iterations': 3}


def test_config_read_file_conf(tmp_path):
	cfg = tmp_path / '.crypt_tools.conf'
	cfg.write_text('password = conf-pw\ncompress = yes\n')
	parsed = ConfigParser.read_file(str(cfg))
	assert parsed == {'password': 'conf-pw', 'compress': True}


def test_config_read_file_unknown_keys_silently_ignored(tmp_path):
	cfg = tmp_path / 'cfg.json'
	cfg.write_text(json.dumps({'password': 'pw', 'unknown_key': 'x'}))
	parsed = ConfigParser.read_file(str(cfg))
	assert parsed == {'password': 'pw'}


def test_config_load_defaults_explicit_missing_path_raises(tmp_path):
	missing = str(tmp_path / 'absent.json')
	with pytest.raises(ValueError):
		ConfigParser.load_defaults(missing)


# ---------------------------------------------------------------------------
# Threshold encrypt/decrypt roundtrip via the engine
# ---------------------------------------------------------------------------


def test_engine_threshold_encrypt_decrypt_roundtrip(tmp_path, capsys):
	"""Full Shamir threshold encrypt-then-decrypt cycle with the minimum quorum."""
	engine = CryptoEngine()
	src = tmp_path / 'plain.txt'
	plaintext = b'top-secret threshold payload' * 16
	src.write_bytes(plaintext)
	enc = tmp_path / 'plain.enc'
	out = tmp_path / 'plain.out'

	passwords = ['alpha-pw', 'bravo-pw', 'charlie-pw']
	threshold = 2

	assert engine.encrypt_with_threshold(
		str(src), str(enc), passwords, threshold
	)
	capsys.readouterr()

	# Decrypt with exactly the threshold number of (correct) passwords.
	assert engine.decrypt_with_threshold(
		str(enc), str(out), passwords[:threshold]
	)
	assert out.read_bytes() == plaintext


def test_engine_threshold_decrypt_with_insufficient_passwords_fails(tmp_path, capsys):
	engine = CryptoEngine()
	src = tmp_path / 'plain.txt'
	src.write_bytes(b'data')
	enc = tmp_path / 'plain.enc'
	out = tmp_path / 'plain.out'

	passwords = ['p1', 'p2', 'p3']
	assert engine.encrypt_with_threshold(str(src), str(enc), passwords, threshold=2)
	capsys.readouterr()

	# Only one password supplied — below the threshold quorum, must fail.
	assert not engine.decrypt_with_threshold(str(enc), str(out), passwords[:1])
	assert not out.exists()


# ---------------------------------------------------------------------------
# Hidden container + keyfile combination
# ---------------------------------------------------------------------------


def test_hidden_container_with_keyfile_roundtrip(tmp_path, capsys):
	engine = CryptoEngine()
	keyfile_path = tmp_path / 'kf.bin'
	assert KeyFileUtils.generate(str(keyfile_path))
	keyfile_data = KeyFileUtils.read(str(keyfile_path))
	assert keyfile_data is not None

	decoy = tmp_path / 'decoy.txt'
	secret = tmp_path / 'secret.bin'
	decoy.write_bytes(b'benign decoy')
	secret.write_bytes(b'REAL_SECRET_PAYLOAD')
	container = tmp_path / 'container.enc'
	out_decoy = tmp_path / 'out_decoy.bin'
	out_secret = tmp_path / 'out_secret.bin'

	assert engine.encrypt_hidden_container(
		str(decoy),
		str(secret),
		str(container),
		'outer-pw',
		'hidden-pw',
		False,
		keyfile_data,
		Config.KDF_PBKDF2,
		Config.PBKDF2_ITERATIONS,
	)
	capsys.readouterr()

	assert engine.decrypt_hidden_container(
		str(container),
		str(out_decoy),
		'outer-pw',
		hidden=False,
		compress=False,
		keyfile_data=keyfile_data,
	)
	assert out_decoy.read_bytes() == b'benign decoy'

	assert engine.decrypt_hidden_container(
		str(container),
		str(out_secret),
		'hidden-pw',
		hidden=True,
		compress=False,
		keyfile_data=keyfile_data,
	)
	assert out_secret.read_bytes() == b'REAL_SECRET_PAYLOAD'


# ---------------------------------------------------------------------------
# CLI validation — error paths
# ---------------------------------------------------------------------------


def test_cli_recovery_key_conflicts_with_hidden_vol(tmp_path, capsys):
	decoy = tmp_path / 'd.txt'
	hidden = tmp_path / 'h.bin'
	decoy.write_text('x')
	hidden.write_text('y')

	with pytest.raises(SystemExit):
		main(
			[
				'-f', str(decoy),
				'--hidden-vol',
				'--hidden-file', str(hidden),
				'--password-outer', 'a',
				'--password-hidden', 'b',
				'--recovery-key',
			]
		)
	captured = capsys.readouterr()
	assert '--recovery-key cannot be used with --hidden-vol' in captured.out


def test_cli_hidden_vol_requires_file_arg(capsys):
	# Without -f, the generic "--text or --file required" check fires first; either way the CLI must exit.
	with pytest.raises(SystemExit):
		main(['--hidden-vol', '--hidden-file', 'whatever.bin', '-p', 'x'])
	captured = capsys.readouterr()
	assert '--text or --file is required' in captured.out


def test_cli_hidden_vol_conflicts_with_recursive(tmp_path, capsys):
	decoy = tmp_path / 'd.txt'
	hidden = tmp_path / 'h.bin'
	decoy.write_text('x')
	hidden.write_text('y')
	with pytest.raises(SystemExit):
		main(
			[
				'-r',
				'-f', str(decoy),
				'--hidden-vol',
				'--hidden-file', str(hidden),
				'--password-outer', 'a',
				'--password-hidden', 'b',
			]
		)
	captured = capsys.readouterr()
	assert '--hidden-vol cannot be used with --recursive' in captured.out


def test_cli_invalid_kdf_value(tmp_path, capsys):
	"""argparse enforces --kdf choices itself; the CLI must exit with the argparse error on stderr."""
	infile = tmp_path / 'x.txt'
	infile.write_text('payload')
	with pytest.raises(SystemExit):
		main(['--encrypt', '-f', str(infile), '-p', 'pw', '--kdf', 'bogus'])
	captured = capsys.readouterr()
	assert "invalid choice: 'bogus'" in captured.err


def test_cli_threshold_with_text_mode_rejected(capsys):
	with pytest.raises(SystemExit):
		main(['-t', 'msg', '-p', 'a', '-p', 'b', '--threshold', '2'])
	captured = capsys.readouterr()
	assert '--threshold applies only to file encryption' in captured.out


# ---------------------------------------------------------------------------
# CLI recovery-key full roundtrip
# ---------------------------------------------------------------------------


def test_cli_encrypt_with_recovery_key_then_decrypt_via_recovery(tmp_path, capsys, monkeypatch):
	infile = tmp_path / 'doc.txt'
	infile.write_bytes(b'cli recovery payload')
	enc = tmp_path / 'doc.enc'
	out = tmp_path / 'doc.out'
	rk = tmp_path / 'doc.rkey.txt'

	# Encrypt with recovery key generated to a specific path.
	main(
		[
			'--encrypt',
			'-f', str(infile),
			'-o', str(enc),
			'-p', 'original-pw',
			'--recovery-key', str(rk),
		]
	)
	captured = capsys.readouterr()
	assert enc.exists() and rk.exists()
	assert 'Recovery key will be saved to' in captured.out

	# Decrypt using the recovery key file. CLI still requires a password arg,
	# but the engine should prefer the recovery key blob.
	main(
		[
			'-d',
			'-f', str(enc),
			'-o', str(out),
			'-p', 'wrong-password-but-ignored',
			'--recovery-key', str(rk),
		]
	)
	capsys.readouterr()
	assert out.read_bytes() == b'cli recovery payload'


# ---------------------------------------------------------------------------
# Smoke test: shred with custom passes count via the utility directly
# ---------------------------------------------------------------------------


def test_shred_utility_with_two_passes(tmp_path, capsys):
	target = tmp_path / 'doomed.bin'
	target.write_bytes(b'destroy me')
	assert crypt_tools.SecureDeleteUtils.shred(str(target), passes=2)
	capsys.readouterr()
	assert not target.exists()
