import os
import pytest
import tempfile

from crypt_tools import (
    CryptTool, 
    CryptToolConfig, 
    Logger, 
    MessageLevel,
    TerminalColors
)

@pytest.fixture
def crypt_tool():
    """Fixture to create a CryptTool instance for tests."""
    return CryptTool()

def test_generate_key_hash(crypt_tool):
    """Test the key hash generation method."""
    key = "test_password"
    key_hash = crypt_tool.generate_key_hash(key)
    
    assert len(key_hash) == 16  # MD5 hash is always 16 bytes
    assert isinstance(key_hash, bytes)
    #assert key_hash == b'\xccP\xf2\xaf\x88\xe1\xc5\xa0\x9e\xc6\x1c\xaa\x9c\xf6E'
    assert key_hash == b'\x16\xec\x1e\xbb\x01\xfe\x02\xde\xd9\xb7\xd5D}=\xfce'

def test_format_file_size(crypt_tool):
    """Test file size formatting method."""
    test_cases = [
        (500, '500 bytes'),
        (1024, '1KB'),
        (1536, '1.5KB'),
        (1048576, '1MB'),
        (1572864, '1.5MB')
    ]
    
    for input_bytes, expected_output in test_cases:
        assert crypt_tool._format_file_size(input_bytes) == expected_output

def test_encryption_decryption(crypt_tool):
    """Test encryption and decryption of text."""
    password = "secret_key"
    plain_texts = [
        "Hello, World!",
        "This is a test message",
        "Special characters: !@#$%^&*()"
    ]
    
    for plain_text in plain_texts:
        # Encrypt
        encrypted = crypt_tool.encrypt(plain_text, password)
        assert encrypted is not None
        assert isinstance(encrypted, bytes)
        assert encrypted != plain_text.encode()
        
        # Decrypt
        decrypted = crypt_tool.decrypt(encrypted, password)
        assert decrypted is not None
        assert decrypted.decode() == plain_text

def test_encryption_decryption_with_incorrect_password(crypt_tool):
    """Test decryption with an incorrect password."""
    input_text = "Secure Message"
    correct_password = "correct_password"
    wrong_password = "incorrect_password"

    encrypted = crypt_tool.encrypt(input_text, correct_password)
    decrypted = crypt_tool.decrypt(encrypted, wrong_password)
    
    assert encrypted != decrypted

def test_encryption_decryption_bytes(crypt_tool):
    """Test encryption and decryption of byte data."""
    password = "secret_key"
    plain_bytes = b'\x00\x01\x02\x03\x04\x05'
    
    # Encrypt
    encrypted = crypt_tool.encrypt(plain_bytes, password)
    assert encrypted is not None
    assert encrypted != plain_bytes
    
    # Decrypt
    decrypted = crypt_tool.decrypt(encrypted, password)
    assert decrypted is not None
    assert decrypted == plain_bytes

def test_file_encryption_decryption(crypt_tool):
    """Test file encryption and decryption with and without compression."""
    password = "secret_key"
    test_modes = [True, False]
    
    for compress in test_modes:
        # Create a temporary test file
        with tempfile.NamedTemporaryFile(delete=False) as temp_input:
            test_content = b"This is a test file content for encryption"
            temp_input.write(test_content)
            temp_input.flush()
            input_path = temp_input.name
        
        try:
            # Create output file paths
            encrypted_path = input_path + '.enc'
            decrypted_path = input_path + '.dec'
            
            # Encrypt file
            crypt_tool.encrypt_file(
                file_input=input_path, 
                file_output=encrypted_path, 
                password=password, 
                compress=compress
            )
            
            # Verify encrypted file exists
            assert os.path.exists(encrypted_path), f"Encrypted file not created: {encrypted_path}"
                        
            # Decrypt file
            crypt_tool.decrypt_file(
                file_input=encrypted_path, 
                file_output=decrypted_path, 
                password=password, 
                compress=compress
            )
            
            # Verify decrypted file exists
            assert os.path.exists(decrypted_path), f"Decrypted file not created: {decrypted_path}"

            # Check decrypted content
            with open(decrypted_path, 'rb') as decrypted_file:
                decrypted_content = decrypted_file.read()
            
            assert decrypted_content == test_content, "Decrypted content does not match original"
        
        finally:
            ...
            # Clean up temporary files
            for path in [input_path, encrypted_path, decrypted_path]:
                if os.path.exists(path):
                    os.unlink(path)

def test_logger_message_levels():
    """Test logger level icons."""
    level_tests = {
        MessageLevel.LIVE: ('\033[92m[+] \033[0m', '[+]'),
        MessageLevel.DEAD: ('\033[91m[-] \033[0m', '[-]'),
        MessageLevel.DEBUG: ('\033[93m[!] \033[0m', '[!]'),
        MessageLevel.ERROR: ('\033[93m[#] \033[0m', '[#]'),
        MessageLevel.WARNING: ('\033[95m[*] \033[0m', '[*]'),
        MessageLevel.INFO: ('\033[94m[*] \033[0m', '[*]')
    }
    
    for level, (expected_colored_icon, icon_text) in level_tests.items():
        result = Logger._get_icon_level(level)
        assert result == expected_colored_icon

def test_terminal_colors():
    """Verify terminal color constant values."""
    # Red color code
    assert TerminalColors.Foreground.RED == '\033[31m'
    
    # Reset all color formatting
    assert TerminalColors.RESET == '\033[0m'

def test_crypt_tool_config():
    """Test CryptToolConfig class constants."""
    assert CryptToolConfig.BLOCK_SIZE == 16
    assert isinstance(CryptToolConfig.AUTHOR, str)
    assert isinstance(CryptToolConfig.DESCRIPTION, str)
    assert isinstance(CryptToolConfig.VERSION, str)