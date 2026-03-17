import os
import pytest
import tempfile
import base64
from crypt_tools import (
    CryptoEngine,
    Config,
    ConsoleLogger,
    TerminalColors,
    main
)

@pytest.fixture
def engine():
    """Fixture to create a CryptoEngine instance for tests."""
    return CryptoEngine()

def test_derive_key(engine):
    """Test key derivation."""
    password = "test_password"
    salt = os.urandom(16)
    key = engine._derive_key(password, salt)
    assert len(key) == 32
    assert isinstance(key, bytes)
    
    # Deterministic check
    key2 = engine._derive_key(password, salt)
    assert key == key2

def test_data_encryption_decryption(engine):
    """Test authenticated encryption flow."""
    password = "secure_password"
    data = b"Hello World AES-GCM"
    
    # Encrypt
    encrypted = engine.encrypt_data(data, password)
    assert len(encrypted) > len(data)
    
    # Structure check: SALT(16) + NONCE(12) + TAG(16) + DATA
    OVERHEAD = 16 + 12 + 16
    assert len(encrypted) == len(data) + OVERHEAD
    
    # Decrypt
    decrypted = engine.decrypt_data(encrypted, password)
    assert decrypted == data

def test_decryption_tampered_fails(engine):
    """Test that tampering with ciphertext fails GCM verification."""
    password = "pass"
    data = b"Sensitive Data"
    encrypted = bytearray(engine.encrypt_data(data, password))
    
    # Tamper with the last byte (content)
    encrypted[-1] ^= 0xFF 
    
    result = engine.decrypt_data(bytes(encrypted), password)
    assert result is None  # Should fail integrity check

def test_decryption_wrong_password(engine):
    """Test decryption with wrong password."""
    password = "pass"
    data = b"Data"
    encrypted = engine.encrypt_data(data, password)
    
    result = engine.decrypt_data(encrypted, "WRONG_PASS")
    assert result is None

def test_file_encryption_decryption(engine):
    """Test file streaming encryption/decryption."""
    password = "file_pass"
    content = b"Streamed file content" * 1000 
    
    fd, input_path = tempfile.mkstemp()
    os.close(fd)
    
    with open(input_path, 'wb') as f:
        f.write(content)
        
    enc_path = input_path + ".enc"
    dec_path = input_path + ".dec"
        
    try:
        # Encrypt
        assert engine.encrypt_file(input_path, enc_path, password)
        assert os.path.exists(enc_path)
        
        # Verify overhead
        # SALT(16) + NONCE(12) + TAG(16) = 44 bytes overhead
        assert os.path.getsize(enc_path) == len(content) + 44
        
        # Decrypt
        assert engine.decrypt_file(enc_path, dec_path, password)
        assert os.path.exists(dec_path)
        
        # Check content
        with open(dec_path, 'rb') as f:
            assert f.read() == content
            
    finally:
        for p in [input_path, enc_path, dec_path]:
            if os.path.exists(p): os.remove(p)

def test_file_compression(engine):
    """Test compression flag."""
    password = "compress_pass"
    # Compressible data (repeating pattern)
    content = b"A" * 10000 
    
    with tempfile.NamedTemporaryFile(delete=False) as tmp_in:
        tmp_in.write(content)
        input_path = tmp_in.name
            
    enc_path = input_path + ".enc"
    dec_path = input_path + ".dec"
        
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
            if os.path.exists(p): os.remove(p)

def test_file_decryption_wrong_password_removes_output(engine):
    """Test that a failed file decryption cleans up the partial output file."""
    password = "correct_password"
    content = b"Sensitive data block"
    
    fd, input_path = tempfile.mkstemp()
    os.close(fd)
    
    with open(input_path, 'wb') as f:
        f.write(content)
        
    enc_path = input_path + ".enc"
    dec_path = input_path + ".dec"
    
    try:
        # 1. Encrypt with valid password
        assert engine.encrypt_file(input_path, enc_path, password)
        assert os.path.exists(enc_path)
        
        # 2. Decrypt with wrong password
        result = engine.decrypt_file(enc_path, dec_path, "wrong_password")
        
        # 3. Verify it failed
        assert result is False
        
        # 4. Verify the generated output file is deleted
        assert not os.path.exists(dec_path)
        
    finally:
        for p in [input_path, enc_path, dec_path]:
            if os.path.exists(p): os.remove(p)

@pytest.fixture
def mock_getpass(monkeypatch):
    import getpass
    # Simple Mock: Always returns 'cli_pass'
    # This satisfies "Enter Password" and "Verify Password" as checking p1 == p2 will pass ('cli_pass' == 'cli_pass')
    monkeypatch.setattr(getpass, 'getpass', lambda prompt="": 'cli_pass')

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
    assert "Encrypted (Base64):" in captured.out
    
    # Version
    # Version action prints and then exits using sys.exit()
    with pytest.raises(SystemExit):
        main(['-v'])
    captured = capsys.readouterr()
    assert Config.VERSION in captured.out or "" 
    
    # Debug
    main(['--encrypt', '-t', 'A', '-p', 'B', '--debug'])
    captured = capsys.readouterr()
    assert "Debug Mode Enabled" in captured.out

def test_cli_password_mismatch(monkeypatch, capsys):
    """Test that password verification failure exits."""
    import getpass
    import sys
    
    # Mock getpass to return different passwords
    # First call: "pass1", Second call: "pass2"
    passwords = iter(["pass1", "pass2"])
    monkeypatch.setattr(getpass, 'getpass', lambda prompt="": next(passwords))
    
    # Run encrypt (will prompt twice)
    with pytest.raises(SystemExit) as excinfo:
        main(['--encrypt', '-t', 'Verify Fail'])
    
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "Passwords do not match!" in captured.out

def test_recursive_directory(engine):
    """Test recursive directory encryption."""
    password = "dir_pass"

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create structure
        subdir = os.path.join(tmpdir, "subdir")
        os.makedirs(subdir)

        with open(os.path.join(tmpdir, "file1.txt"), "w") as f: f.write("content1")
        with open(os.path.join(subdir, "file2.txt"), "w") as f: f.write("content2")

        # Recursive Encrypt (use -f for file/directory path)
        main(['--encrypt', '-r', '-f', tmpdir, '-p', password])

        # Check files exist
        assert os.path.exists(os.path.join(tmpdir, "file1.txt.enc"))
        assert os.path.exists(os.path.join(subdir, "file2.txt.enc"))

        # Test Decrypt Recursively
        main(['--decrypt', '-r', '-f', tmpdir, '-p', password])

        # Check restored files
        with open(os.path.join(tmpdir, "file1.txt"), "r") as f: assert f.read() == "content1"
        with open(os.path.join(subdir, "file2.txt"), "r") as f: assert f.read() == "content2"


def test_cli_file_not_found(monkeypatch, capsys):
    """Test error when file does not exist."""
    with pytest.raises(SystemExit) as excinfo:
        main(['-f', 'nonexistent_file.txt', '-p', 'pass'])
    
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "File not found" in captured.out


def test_cli_directory_without_recursive(monkeypatch, capsys, mock_getpass):
    """Test error when directory is provided without -r flag."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        with pytest.raises(SystemExit) as excinfo:
            main(['-f', tmpdir, '-p', 'pass'])
        
        assert excinfo.value.code == 1
        captured = capsys.readouterr()
        assert "Use -r/--recursive" in captured.out


def test_file_compression_encrypt_decrypt(engine):
    """Test compression with encrypt and decrypt round-trip."""
    password = "compress_test"
    # Highly compressible data
    content = b"AAAAAAAAAA" * 1000

    fd, input_path = tempfile.mkstemp()
    os.close(fd)

    with open(input_path, 'wb') as f:
        f.write(content)

    enc_path = input_path + ".enc"
    dec_path = input_path + ".dec"

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
            if os.path.exists(p): os.remove(p)


def test_console_logger_file_only(monkeypatch, tmp_path):
    """Test ConsoleLogger writing to file only (no console)."""
    log_file = tmp_path / "test.log"
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
        assert "Debug Mode Enabled" in captured.out
    finally:
        if os.path.exists(tmpfile):
            os.remove(tmpfile)
        # Clean up any generated files
        if os.path.exists(tmpfile + '.enc'):
            os.remove(tmpfile + '.enc')


def test_decrypt_data_error_handling(engine):
    """Test decrypt_data with tampered data."""
    password = "test"
    data = b"Test data"
    
    encrypted = engine.encrypt_data(data, password)
    
    # Tamper with the data
    tampered = bytearray(encrypted)
    tampered[20] ^= 0xFF  # Flip a bit in the ciphertext
    
    result = engine.decrypt_data(bytes(tampered), password)
    assert result is None


def test_encrypt_file_error_handling(engine, monkeypatch):
    """Test encrypt_file handles errors gracefully."""
    password = "test"
    
    # Try to encrypt a non-existent file
    result = engine.encrypt_file('nonexistent.txt', 'out.enc', password)
    assert result is False


def test_decrypt_file_error_handling(engine, monkeypatch):
    """Test decrypt_file handles errors gracefully."""
    password = "test"
    
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


