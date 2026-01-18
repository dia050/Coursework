import os
from pathlib import Path
import tempfile
from securecrypt_pki_gui_master import encrypt_file, decrypt_file

def test_encrypt_decrypt_file(tmp_path):
    # Create a test file
    f = tmp_path / "test.txt"
    f.write_text("file contents")
    password = "filepass"

    # Encrypt
    enc_file = encrypt_file(f, password=password)
    assert enc_file.exists()

    # Decrypt
    dec_file = decrypt_file(enc_file, password=password)
    assert dec_file.exists()
    assert dec_file.read_text() == "file contents"
