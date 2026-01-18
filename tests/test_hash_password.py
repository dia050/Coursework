import os
from securecrypt_pki_gui_master import hash_password

def test_hash_password_same_input_same_output():
    salt = os.urandom(16)
    assert hash_password("pass", salt) == hash_password("pass", salt)

def test_hash_password_different_password():
    salt = os.urandom(16)
    assert hash_password("a", salt) != hash_password("b", salt)
