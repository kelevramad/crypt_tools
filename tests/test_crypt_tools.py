import os
import pytest
import tempfile
import base64
from crypt_tools import (
    CryptoEngine, 
    Config, 
    Logger, 
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
            
        # Recursive Encrypt
        main(['--encrypt', '-r', '-i', tmpdir, '-p', password])
            
        # Check files exist
        assert os.path.exists(os.path.join(tmpdir, "file1.txt.enc"))
        assert os.path.exists(os.path.join(subdir, "file2.txt.enc"))
        
        # Test Decrypt Recursively
        main(['--decrypt', '-r', '-i', tmpdir, '-p', password])
        
        # Check restored files
        with open(os.path.join(tmpdir, "file1.txt"), "r") as f: assert f.read() == "content1"
        with open(os.path.join(subdir, "file2.txt"), "r") as f: assert f.read() == "content2"


