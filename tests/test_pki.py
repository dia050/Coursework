import os
import pytest
from pathlib import Path
from securecrypt_pki_gui_master import generate_rsa_keypair, rsa_encrypt_key, rsa_decrypt_key, PUB_KEY, PRIV_KEY

@pytest.fixture
def cleanup_keys():
    # Delete any pre-existing keys
    if PUB_KEY.exists(): PUB_KEY.unlink()
    if PRIV_KEY.exists(): PRIV_KEY.unlink()
    yield
    if PUB_KEY.exists(): PUB_KEY.unlink()
    if PRIV_KEY.exists(): PRIV_KEY.unlink()

def test_generate_rsa_keypair(cleanup_keys):
    generate_rsa_keypair()
    assert PUB_KEY.exists()
    assert PRIV_KEY.exists()

def test_rsa_encrypt_decrypt_roundtrip(cleanup_keys):
    generate_rsa_keypair()
    key = os.urandom(32)
    enc = rsa_encrypt_key(key)
    dec = rsa_decrypt_key(enc)
    assert key == dec
