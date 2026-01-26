#!/usr/bin/env python3
"""
securecrypt_pki_gui_master.py - Hybrid PKI + optional password AES with GUI
Features:
- AES-256-GCM encryption for files/text
- PKI RSA protects AES keys
- Audit log with password protection
- Multi-line text input and GUI decryption display
- Master password and failed-attempt lockout
- Timeline view for audit log
"""

import os
import json
import struct
from pathlib import Path
from datetime import datetime
from typing import Tuple
from tkinter import Tk, Button, Label, filedialog, simpledialog, messagebox, Text, Scrollbar, END, Toplevel
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# -------------------------
# Constants and Files
# -------------------------
SALT_SIZE = 16
NONCE_SIZE = 12
PBKDF2_ITERS = 200_000
MAGIC = b"SCry"
VERSION = 1

AUDIT_LOG_FILE = Path("audit.log.enc")
PUB_KEY = Path("public_key.pem")
PRIV_KEY = Path("private_key.pem")
MASTER_PASS_FILE = Path(".master_pass.json")
LOCK_STATE_FILE = Path(".lock_state.json")

MAX_FAILED = 3

# -------------------------
# Master password functions
# -------------------------
def hash_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, PBKDF2_ITERS)
    return kdf.derive(password.encode())

def set_master_password():
    pwd = simpledialog.askstring("Set Master Password", "Enter new master password:", show="*")
    if not pwd: return False
    confirm = simpledialog.askstring("Confirm Password", "Confirm master password:", show="*")
    if pwd != confirm:
        messagebox.showerror("Error", "Passwords do not match")
        return False
    salt = os.urandom(SALT_SIZE)
    hashed = hash_password(pwd, salt)
    MASTER_PASS_FILE.write_bytes(json.dumps({"salt": salt.hex(), "hash": hashed.hex()}).encode())
    return True

def verify_master_password():
    if not MASTER_PASS_FILE.exists():
        return set_master_password()
    
    with open(MASTER_PASS_FILE, "rb") as f:
        data = json.loads(f.read())
        salt = bytes.fromhex(data["salt"])
        stored_hash = bytes.fromhex(data["hash"])
    
    failed = 0
    while failed < MAX_FAILED:
        pwd = simpledialog.askstring("Master Password", "Enter master password:", show="*")
        if not pwd: continue
        try:
            if hash_password(pwd, salt) == stored_hash:
                return True
        except Exception:
            pass
        failed += 1
        messagebox.showerror("Error", f"Incorrect password ({failed}/{MAX_FAILED})")
    # Lockout
    LOCK_STATE_FILE.write_text("LOCKED")
    messagebox.showerror("Locked", "Too many failed attempts. Program locked.")
    return False

def check_lock_state():
    if LOCK_STATE_FILE.exists():
        messagebox.showerror("Locked", "Program is locked due to previous failed attempts.")
        return False
    return True

# -------------------------
# PKI Utilities
# -------------------------
def generate_rsa_keypair():
    if PUB_KEY.exists() or PRIV_KEY.exists():
        messagebox.showerror("Error", "RSA keypair already exists!")
        return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    PRIV_KEY.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    PUB_KEY.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    os.chmod(PRIV_KEY, 0o600)
    messagebox.showinfo("Success", f"RSA keypair generated.")

def rsa_encrypt_key(key: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(PUB_KEY.read_bytes())
    return public_key.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt_key(enc_key: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(PRIV_KEY.read_bytes(), password=None)
    return private_key.decrypt(
        enc_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# -------------------------
# Password AES
# -------------------------
def derive_aes_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, PBKDF2_ITERS)
    return kdf.derive(password.encode())

# -------------------------
# Audit log functions
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
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, json.dumps(entries).encode(), meta_bytes)

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
    version = mv[off]
    off += 1
    salt = mv[off:off+SALT_SIZE].tobytes()
    off += SALT_SIZE
    nonce = mv[off:off+NONCE_SIZE].tobytes()
    off += NONCE_SIZE
    meta_len = struct.unpack(">H", mv[off:off+2])[0]
    off += 2
    meta = json.loads(mv[off:off+meta_len].tobytes())
    off += meta_len
    ct_len = struct.unpack(">Q", mv[off:off+8])[0]
    off += 8
    ciphertext = mv[off:off+ct_len].tobytes()
    aes_key = derive_aes_key(password, salt)
    plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, json.dumps(meta).encode())
    return plaintext, meta

# -------------------------
# Core encrypt/decrypt
# -------------------------
def encrypt_bytes(data: bytes, metadata: dict, password: str = None) -> bytes:
    if password:
        salt = os.urandom(SALT_SIZE)
        aes_key = derive_aes_key(password, salt)
        wrapped_key_hex = None
    else:
        salt = b""
        aes_key = os.urandom(32)
        wrapped_key_hex = rsa_encrypt_key(aes_key).hex()
    metadata["wrapped_key"] = wrapped_key_hex
    metadata["timestamp"] = datetime.now().isoformat()
    meta_bytes = json.dumps(metadata).encode()
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(aes_key).encrypt(nonce, data, meta_bytes)
    blob = MAGIC + struct.pack("B", VERSION)
    if password: blob += salt
    blob += nonce + struct.pack(">H", len(meta_bytes)) + meta_bytes + struct.pack(">Q", len(ciphertext)) + ciphertext
    return blob

def decrypt_bytes(blob: bytes, password: str = None) -> Tuple[bytes, dict]:
    mv = memoryview(blob)
    if mv[:4].tobytes() != MAGIC:
        raise ValueError("Invalid file format")
    off = 4
    version = mv[off]
    off += 1
    if password:
        salt = mv[off:off+SALT_SIZE].tobytes()
        off += SALT_SIZE
        aes_key = derive_aes_key(password, salt)
    nonce = mv[off:off+NONCE_SIZE].tobytes()
    off += NONCE_SIZE
    meta_len = struct.unpack(">H", mv[off:off+2])[0]
    off += 2
    meta = json.loads(mv[off:off+meta_len].tobytes())
    off += meta_len
    ct_len = struct.unpack(">Q", mv[off:off+8])[0]
    off += 8
    ciphertext = mv[off:off+ct_len].tobytes()
    if not password:
        wrapped_key = bytes.fromhex(meta["wrapped_key"])
        aes_key = rsa_decrypt_key(wrapped_key)
    plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, json.dumps(meta).encode())
    return plaintext, meta

def encrypt_file(path: Path, password: str = None) -> Path:
    blob = encrypt_bytes(path.read_bytes(), {"filename": path.name, "type": "file"}, password)
    out = path.with_suffix(path.suffix + ".enc")
    out.write_bytes(blob)
    return out

def decrypt_file(path: Path, password: str = None) -> Path:
    data, meta = decrypt_bytes(path.read_bytes(), password)
    out = path.parent / ("dec_" + meta["filename"])
    out.write_bytes(data)
    return out

# -------------------------
# GUI Functions
# -------------------------
def encrypt_text_gui():
    win = Toplevel(root)
    win.title("Encrypt Text")
    win.geometry("500x400")
    Label(win, text="Enter text (multiple lines allowed):").pack()
    txt = Text(win, width=60, height=15)
    txt.pack(pady=5)
    def encrypt_action():
        text_data = txt.get("1.0", END).strip()
        if not text_data:
            messagebox.showerror("Error", "No text entered!")
            return
        pwd = simpledialog.askstring("Password", "Enter password for encryption (or leave empty for PKI):", show="*")
        blob = encrypt_bytes(text_data.encode(), {"type": "text"}, pwd if pwd else None)
        out_file = Path("text.enc")
        out_file.write_bytes(blob)
        audit_pwd = simpledialog.askstring("Audit Log Password", "Enter audit log password:", show="*")
        append_audit({"operation": "encrypt", "type": "text", "output": str(out_file)}, audit_pwd)
        messagebox.showinfo("Success", f"Text encrypted to: {out_file}")
        win.destroy()
    Button(win, text="Encrypt", command=encrypt_action).pack(pady=10)

def decrypt_text_gui():
    path = filedialog.askopenfilename(title="Select encrypted text file")
    if not path: return
    pwd = simpledialog.askstring("Password", "Enter password (if used, else leave empty):", show="*")
    failed = 0
    while failed < 3:
        try:
            data, _ = decrypt_bytes(Path(path).read_bytes(), pwd if pwd else None)
            break
        except Exception:
            failed += 1
            if failed >=3:
                messagebox.showerror("Error", "Too many failed attempts. Program exiting.")
                root.destroy()
                return
            pwd = simpledialog.askstring("Password", f"Wrong password ({failed}/3). Try again:", show="*")
    win = Toplevel(root)
    win.title("Decrypted Text")
    win.geometry("500x400")
    Label(win, text="Decrypted Text:").pack()
    txt = Text(win, width=60, height=20)
    txt.pack(pady=5)
    txt.insert("1.0", data.decode())
    txt.config(state="disabled")
    audit_pwd = simpledialog.askstring("Audit Log Password", "Enter audit log password:", show="*")
    append_audit({"operation": "decrypt", "type": "text", "input": path}, audit_pwd)

def encrypt_file_gui():
    path = filedialog.askopenfilename(title="Select file to encrypt")
    if not path: return
    pwd = simpledialog.askstring("Password", "Enter password for encryption (or leave empty for PKI):", show="*")
    out = encrypt_file(Path(path), pwd if pwd else None)
    audit_pwd = simpledialog.askstring("Audit Log Password", "Enter audit log password:", show="*")
    append_audit({"operation": "encrypt", "type": "file", "input": path, "output": str(out)}, audit_pwd)
    messagebox.showinfo("Success", f"File encrypted to: {out}")

def decrypt_file_gui():
    path = filedialog.askopenfilename(title="Select encrypted file")
    if not path: return
    pwd = simpledialog.askstring("Password", "Enter password (if used, else leave empty):", show="*")
    failed = 0
    while failed < 3:
        try:
            out = decrypt_file(Path(path), pwd if pwd else None)
            break
        except Exception:
            failed += 1
            if failed >=3:
                messagebox.showerror("Error", "Too many failed attempts. Program exiting.")
                root.destroy()
                return
            pwd = simpledialog.askstring("Password", f"Wrong password ({failed}/3). Try again:", show="*")
    audit_pwd = simpledialog.askstring("Audit Log Password", "Enter audit log password:", show="*")
    append_audit({"operation": "decrypt", "type": "file", "input": path, "output": str(out)}, audit_pwd)
    messagebox.showinfo("Success", f"File decrypted to: {out}")

def view_audit_gui():
    if not AUDIT_LOG_FILE.exists():
        messagebox.showinfo("Audit Log", "No audit log exists yet.")
        return
    pwd = simpledialog.askstring("Audit Log Password", "Enter audit log password:", show="*")
    try:
        data, _ = decrypt_audit_log(pwd)
        entries = json.loads(data.decode())
        win = Toplevel(root)
        win.title("Audit Timeline")
        win.geometry("500x400")
        scroll = Scrollbar(win)
        scroll.pack(side="right", fill="y")
        txt = Text(win, yscrollcommand=scroll.set)
        txt.pack(fill="both", expand=True)
        for entry in sorted(entries, key=lambda x: x.get("timestamp", "")):
            ts = entry.get("timestamp","N/A")
            txt.insert(END, f"[{ts}] {entry}\n\n")
        txt.config(state="disabled")
        scroll.config(command=txt.yview)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt audit log: {e}")

# -------------------------
# GUI Main Window
# -------------------------
def launch_gui():
    global root
    root = Tk()
    root.title("SecureCrypt GUI")
    root.geometry("400x450")
    Label(root, text="SecureCrypt - Hybrid PKI Encryption", font=("Arial", 14)).pack(pady=10)
    Button(root, text="1) Generate RSA Keypair", width=30, command=generate_rsa_keypair).pack(pady=5)
    Button(root, text="2) Encrypt Text", width=30, command=encrypt_text_gui).pack(pady=5)
    Button(root, text="3) Decrypt Text", width=30, command=decrypt_text_gui).pack(pady=5)
    Button(root, text="4) Encrypt File", width=30, command=encrypt_file_gui).pack(pady=5)
    Button(root, text="5) Decrypt File", width=30, command=decrypt_file_gui).pack(pady=5)
    Button(root, text="6) View Audit Timeline", width=30, command=view_audit_gui).pack(pady=5)
    Button(root, text="7) Quit", width=30, command=root.destroy).pack(pady=20)
    root.mainloop()

# -------------------------
# Program Start
# -------------------------
if check_lock_state() and verify_master_password():
    launch_gui()
#test
