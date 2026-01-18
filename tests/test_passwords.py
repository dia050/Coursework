import os
import tempfile
import pytest
from securecrypt_pki_gui_master import hash_password, derive_aes_key, check_lock_state

# ----------------------------
# hash_password tests
# ----------------------------
def test_hash_password_output_length():
    pwd = "mypassword"
    salt = os.urandom(16)
    hashed = hash_password(pwd, salt)
    assert isinstance(hashed, bytes)
    assert len(hashed) == 32

# ----------------------------
# derive_aes_key tests
# ----------------------------
def test_derive_aes_key_consistency():
    pwd = "mypassword"
    salt = os.urandom(16)
    key1 = derive_aes_key(pwd, salt)
    key2 = derive_aes_key(pwd, salt)
    assert key1 == key2

def test_derive_aes_key_diff_salts():
    pwd = "mypassword"
    key1 = derive_aes_key(pwd, os.urandom(16))
    key2 = derive_aes_key(pwd, os.urandom(16))
    assert key1 != key2

# ----------------------------
# check_lock_state tests
# ----------------------------
def test_check_lock_state_locked(tmp_path):
    lock_file = tmp_path / "lock.json"
    lock_file.write_text("LOCKED")
    # patch the LOCK_STATE_FILE
    import securecrypt_pki_gui_master as sc
    orig = sc.LOCK_STATE_FILE
    sc.LOCK_STATE_FILE = lock_file
    assert not check_lock_state()
    sc.LOCK_STATE_FILE = orig

def test_check_lock_state_unlocked(tmp_path):
    import securecrypt_pki_gui_master as sc
    orig = sc.LOCK_STATE_FILE
    sc.LOCK_STATE_FILE = tmp_path / "nonexistent.lock"
    assert check_lock_state()
    sc.LOCK_STATE_FILE = orig
