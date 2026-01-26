import os
import json
import pytest
from pathlib import Path

from securecrypt_core import (
    hash_password,
    derive_aes_key,
    check_lock_state,
    generate_rsa_keypair,
    rsa_encrypt_key,
    rsa_decrypt_key,
    append_audit,
    decrypt_audit_log,
    encrypt_bytes,
    decrypt_bytes,
    encrypt_file,
    decrypt_file,
    PUB_KEY,
    PRIV_KEY
)

# -----------------------------
# Password & AES key tests
# -----------------------------
def test_hash_password_length():
    salt = os.urandom(16)
    h = hash_password("mypassword", salt)
    assert isinstance(h, bytes)
    assert len(h) == 32


def test_derive_aes_key_consistency():
    salt = os.urandom(16)
    key1 = derive_aes_key("mypassword", salt)
    key2 = derive_aes_key("mypassword", salt)
    assert key1 == key2


# -----------------------------
# Lock state tests
# -----------------------------
def test_check_lock_state(tmp_path, monkeypatch):
    import securecrypt_core as sc

    fake_lock = tmp_path / ".lock_state.json"
    monkeypatch.setattr(sc, "LOCK_STATE_FILE", fake_lock)

    assert sc.check_lock_state() is True

    fake_lock.write_text("LOCKED")
    assert sc.check_lock_state() is False


# -----------------------------
# PKI tests
# -----------------------------
@pytest.fixture
def cleanup_keys():
    if PUB_KEY.exists():
        PUB_KEY.unlink()
    if PRIV_KEY.exists():
        PRIV_KEY.unlink()
    yield
    if PUB_KEY.exists():
        PUB_KEY.unlink()
    if PRIV_KEY.exists():
        PRIV_KEY.unlink()


def test_generate_rsa_keypair(cleanup_keys):
    generate_rsa_keypair()
    assert PUB_KEY.exists()
    assert PRIV_KEY.exists()


def test_rsa_encrypt_decrypt(cleanup_keys):
    generate_rsa_keypair()
    key = os.urandom(32)
    enc = rsa_encrypt_key(key)
    dec = rsa_decrypt_key(enc)
    assert dec == key


# -----------------------------
# Audit log tests
# -----------------------------
@pytest.fixture
def temp_audit_file(tmp_path, monkeypatch):
    import securecrypt_core as sc
    audit_file = tmp_path / "audit.log.enc"
    monkeypatch.setattr(sc, "AUDIT_LOG_FILE", audit_file)
    return audit_file


def test_append_and_decrypt_audit(temp_audit_file):
    password = "auditpass"
    append_audit(
        {"operation": "encrypt", "type": "file", "output": "x"},
        password
    )

    data, meta = decrypt_audit_log(password)
    entries = json.loads(data.decode())

    assert entries[0]["operation"] == "encrypt"
    assert "timestamp" in entries[0]


# -----------------------------
# Bytes encryption/decryption
# -----------------------------
def test_encrypt_decrypt_bytes_password():
    data = b"hello world"
    metadata = {"type": "text"}

    blob = encrypt_bytes(data, metadata, password="pwd")
    dec, meta = decrypt_bytes(blob, password="pwd")

    assert dec == data
    assert meta["type"] == "text"


def test_encrypt_decrypt_bytes_pki(cleanup_keys):
    generate_rsa_keypair()

    data = b"secret data"
    metadata = {"type": "file"}

    blob = encrypt_bytes(data, metadata)
    dec, meta = decrypt_bytes(blob)

    assert dec == data
    assert meta["type"] == "file"


# -----------------------------
# File encryption/decryption
# -----------------------------
def test_encrypt_decrypt_file(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("file content")

    password = "filepass"

    enc_file = encrypt_file(f, password)
    assert enc_file.exists()

    dec_file = decrypt_file(enc_file, password)
    assert dec_file.exists()
    assert dec_file.read_text() == "file content"
