from crypt_tools_new import Crypt


def test_password_encrypted():
    crypt: Crypt = Crypt()
    password_encrypted = crypt.trans('password').hex()
    assert password_encrypted == '5f4dcc3b5aa765d61d8327deb882cf99'

def test_encryption():
    crypt: Crypt = Crypt()
    msg_enc = crypt.encryption('text'.encode(), 'password').decode('utf-8')
    assert msg_enc is not None

def test_encryption_none():
    crypt: Crypt = Crypt()
    msg_enc = crypt.encryption('text', 'password')
    assert msg_enc is None

def test_decryption():
    crypt: Crypt = Crypt()
    msg_dec = crypt.decryption('DzBzw+JDMS8P+qjGWmTL4EafoQ8=', 'password')
    assert msg_dec.decode('utf-8') == 'text'

def test_decryption_none():
    crypt: Crypt = Crypt()
    msg_dec = crypt.decryption('text', 'password')
    assert msg_dec is None


