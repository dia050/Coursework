import os
from securecrypt_pki_gui_master import (
    hash_password,
    derive_aes_key,
    check_lock_state,
    LOCK_STATE_FILE
)

def test_hash_password_same_input_same_output():
    salt = os.urandom(16)
    assert hash_password("pass", salt) == hash_password("pass", salt)

def test_hash_password_different_password():
    salt = os.urandom(16)
    assert hash_password("a", salt) != hash_password("b", salt)

def test_derive_aes_key_length():
    salt = os.urandom(16)
    key = derive_aes_key("password", salt)
    assert len(key) == 32

def test_check_lock_state_true(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert check_lock_state() is True

def test_check_lock_state_false(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    LOCK_STATE_FILE.write_text("LOCKED")
    assert check_lock_state() is False
