import os
import json
import tempfile
import pytest
from securecrypt_pki_gui_master import append_audit, decrypt_audit_log, AUDIT_LOG_FILE, derive_aes_key

@pytest.fixture
def audit_file(tmp_path):
    f = tmp_path / "audit.log.enc"
    import securecrypt_pki_gui_master as sc
    orig = sc.AUDIT_LOG_FILE
    sc.AUDIT_LOG_FILE = f
    yield f
    sc.AUDIT_LOG_FILE = orig

def test_append_and_decrypt_audit(audit_file):
    password = "auditpass"
    entry = {"operation": "encrypt", "type": "file", "output": "test.enc"}
    append_audit(entry, password)
    data, meta = decrypt_audit_log(password)
    entries = json.loads(data.decode())
    assert len(entries) == 1
    assert entries[0]["operation"] == "encrypt"
