#!/usr/bin/env python3
"""
securecrypt_core.py – Core cryptography logic (NO GUI)

Includes:
- AES-256-GCM encryption
- RSA PKI for AES key wrapping
- Password-based AES
- Encrypted audit log
- File & byte encryption/decryption
"""

import os
import json
import struct
from pathlib import Path
from datetime import datetime
from typing import Tuple

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# -------------------------
# Constants & Files
# -------------------------
SALT_SIZE = 16
NONCE_SIZE = 12
PBKDF2_ITERS = 200_000
MAGIC = b"SCry"
VERSION = 1

AUDIT_LOG_FILE = Path("audit.log.enc")
PUB_KEY = Path("public_key.pem")
PRIV_KEY = Path("private_key.pem")
LOCK_STATE_FILE = Path(".lock_state.json")


# -------------------------
# Password & Key Derivation
# -------------------------
def hash_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(password.encode())


def derive_aes_key(password: str, salt: bytes) -> bytes:
    return hash_password(password, salt)


# -------------------------
# Lock State (NO GUI)
# -------------------------
def check_lock_state() -> bool:
    return not LOCK_STATE_FILE.exists()


# -------------------------
# PKI Utilities
# -------------------------
def generate_rsa_keypair():
    if PUB_KEY.exists() or PRIV_KEY.exists():
        raise FileExistsError("RSA keypair already exists")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    PRIV_KEY.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )
    )

    PUB_KEY.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    os.chmod(PRIV_KEY, 0o600)


def rsa_encrypt_key(key: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(PUB_KEY.read_bytes())
    return public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt_key(enc_key: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(
        PRIV_KEY.read_bytes(),
        password=None
    )
    return private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# -------------------------
# Audit Log
# -------------------------
def append_audit(entry: dict, password: str):
    entries = []

    if AUDIT_LOG_FILE.exists():
        try:
            data, _ = decrypt_audit_log(password)
            entries = json.loads(data.decode())
        except Exception:
            entries = []

    entry["timestamp"] = datetime.now().isoformat()
    entries.append(entry)

    salt = os.urandom(SALT_SIZE)
    aes_key = derive_aes_key(password, salt)
    meta = {"type": "audit"}
    meta_bytes = json.dumps(meta).encode()

    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(aes_key).encrypt(
        nonce,
        json.dumps(entries).encode(),
        meta_bytes
    )

    blob = (
        MAGIC +
        struct.pack("B", VERSION) +
        salt +
        nonce +
        struct.pack(">H", len(meta_bytes)) +
        meta_bytes +
        struct.pack(">Q", len(ciphertext)) +
        ciphertext
    )

    AUDIT_LOG_FILE.write_bytes(blob)


def decrypt_audit_log(password: str) -> Tuple[bytes, dict]:
    blob = AUDIT_LOG_FILE.read_bytes()
    mv = memoryview(blob)

    if mv[:4].tobytes() != MAGIC:
        raise ValueError("Invalid audit log format")

    off = 4
    off += 1  # version
    salt = mv[off:off + SALT_SIZE].tobytes()
    off += SALT_SIZE
    nonce = mv[off:off + NONCE_SIZE].tobytes()
    off += NONCE_SIZE

    meta_len = struct.unpack(">H", mv[off:off + 2])[0]
    off += 2
    meta = json.loads(mv[off:off + meta_len].tobytes())
    off += meta_len

    ct_len = struct.unpack(">Q", mv[off:off + 8])[0]
    off += 8
    ciphertext = mv[off:off + ct_len].tobytes()

    aes_key = derive_aes_key(password, salt)
    plaintext = AESGCM(aes_key).decrypt(
        nonce,
        ciphertext,
        json.dumps(meta).encode()
    )

    return plaintext, meta


# -------------------------
# Core Encrypt / Decrypt
# -------------------------
def encrypt_bytes(data: bytes, metadata: dict, password: str = None) -> bytes:
    if password:
        salt = os.urandom(SALT_SIZE)
        aes_key = derive_aes_key(password, salt)
        wrapped_key = None
    else:
        salt = b""
        aes_key = os.urandom(32)
        wrapped_key = rsa_encrypt_key(aes_key).hex()

    metadata["wrapped_key"] = wrapped_key
    metadata["timestamp"] = datetime.now().isoformat()
    meta_bytes = json.dumps(metadata).encode()

    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(aes_key).encrypt(nonce, data, meta_bytes)

    blob = MAGIC + struct.pack("B", VERSION)
    if password:
        blob += salt
    blob += (
        nonce +
        struct.pack(">H", len(meta_bytes)) +
        meta_bytes +
        struct.pack(">Q", len(ciphertext)) +
        ciphertext
    )
    return blob


def decrypt_bytes(blob: bytes, password: str = None) -> Tuple[bytes, dict]:
    mv = memoryview(blob)

    if mv[:4].tobytes() != MAGIC:
        raise ValueError("Invalid file format")

    off = 4
    off += 1  # version

    if password:
        salt = mv[off:off + SALT_SIZE].tobytes()
        off += SALT_SIZE
        aes_key = derive_aes_key(password, salt)

    nonce = mv[off:off + NONCE_SIZE].tobytes()
    off += NONCE_SIZE

    meta_len = struct.unpack(">H", mv[off:off + 2])[0]
    off += 2
    meta = json.loads(mv[off:off + meta_len].tobytes())
    off += meta_len

    ct_len = struct.unpack(">Q", mv[off:off + 8])[0]
    off += 8
    ciphertext = mv[off:off + ct_len].tobytes()

    if not password:
        aes_key = rsa_decrypt_key(bytes.fromhex(meta["wrapped_key"]))

    plaintext = AESGCM(aes_key).decrypt(
        nonce,
        ciphertext,
        json.dumps(meta).encode()
    )

    return plaintext, meta


def encrypt_file(path: Path, password: str = None) -> Path:
    blob = encrypt_bytes(
        path.read_bytes(),
        {"filename": path.name, "type": "file"},
        password
    )
    out = path.with_suffix(path.suffix + ".enc")
    out.write_bytes(blob)
    return out


def decrypt_file(path: Path, password: str = None) -> Path:
    data, meta = decrypt_bytes(path.read_bytes(), password)
    out = path.parent / ("dec_" + meta["filename"])
    out.write_bytes(data)
    return out
