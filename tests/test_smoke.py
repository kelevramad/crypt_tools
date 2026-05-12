import re
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / 'crypt_tools.py'


def strip_ansi(value):
	return re.sub(r'\x1b\[[0-9;]*m', '', value)


def run_cli(*args):
	result = subprocess.run(
		[sys.executable, str(BIN), *args],
		cwd=ROOT,
		capture_output=True,
		encoding='utf-8',
		errors='replace',
		check=False,
	)
	return result.returncode, strip_ansi(result.stdout), strip_ansi(result.stderr)


@pytest.mark.smoke
def test_python_cli_text_roundtrip_smoke():
	plain_text = 'smoke test'

	code, stdout, stderr = run_cli('-t', plain_text, '-p', 'pw')
	assert code == 0, stdout + stderr

	match = re.search(r'Encrypted \(Base64\):\s*([A-Za-z0-9+/=]+)', stdout)
	assert match, stdout

	code, stdout, stderr = run_cli('-d', '-t', match.group(1), '-p', 'pw')
	assert code == 0, stdout + stderr
	assert 'Decrypted: smoke test' in stdout
