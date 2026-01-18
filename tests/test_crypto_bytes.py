import os
from securecrypt_pki_gui_master import encrypt_bytes, decrypt_bytes

def test_encrypt_decrypt_bytes_with_password():
    data = b"hello world"
    password = "mypassword"
    metadata = {"type": "text"}
    blob = encrypt_bytes(data, metadata, password=password)
    decrypted, meta = decrypt_bytes(blob, password=password)
    assert decrypted == data
    assert meta["type"] == "text"

def test_encrypt_decrypt_bytes_with_pki():
    data = b"secret data"
    metadata = {"type": "file"}
    blob = encrypt_bytes(data, metadata)
    decrypted, meta = decrypt_bytes(blob)
    assert decrypted == data
    assert meta["type"] == "file"
    assert "wrapped_key" in meta
