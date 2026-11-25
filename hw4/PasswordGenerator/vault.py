"""
vault.py - secure local password storage for the generator.

Saved passwords are encrypted at rest. The user picks a master password; we
derive an encryption key from it with PBKDF2-HMAC-SHA256 (200,000 iterations
over a random 16-byte salt) and encrypt each saved password with Fernet
(AES-128 in CBC mode, authenticated with HMAC-SHA256). The master password is
never written to disk, so without it the vault file is just unreadable
ciphertext.
"""
import os
import json
import time
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 200_000


def _derive_key(master: str, salt: bytes) -> bytes:
    """Turn the master password + salt into a 32-byte Fernet key."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master.encode("utf-8")))


class Vault:
    def __init__(self, path: str):
        self.path = path

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def _read(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _write(self, data: dict) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def create(self, master: str) -> None:
        """Start a brand-new vault protected by the given master password."""
        salt = os.urandom(16)
        f = Fernet(_derive_key(master, salt))
        self._write({
            "version": 1,
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "cipher": "Fernet (AES-128-CBC + HMAC-SHA256)",
            "salt": base64.b64encode(salt).decode(),
            # a known token we can try to decrypt later to check the master password
            "verifier": f.encrypt(b"vault-ok").decode(),
            "entries": [],
        })

    def _unlock(self, master: str):
        """Return (data, Fernet) if the master password is right, else raise."""
        if not self.exists():
            raise ValueError("No vault has been created yet.")
        data = self._read()
        salt = base64.b64decode(data["salt"])
        f = Fernet(_derive_key(master, salt))
        try:
            f.decrypt(data["verifier"].encode())
        except InvalidToken:
            raise ValueError("Wrong master password.")
        return data, f

    def add(self, master: str, label: str, password: str) -> int:
        """Encrypt and store one password. Creates the vault on first use."""
        if not self.exists():
            self.create(master)
        data, f = self._unlock(master)
        data["entries"].append({
            "label": label,
            "password": f.encrypt(password.encode("utf-8")).decode(),
            "created": time.strftime("%Y-%m-%d %H:%M"),
        })
        self._write(data)
        return len(data["entries"])

    def unlock_and_list(self, master: str):
        """Return the decrypted entries (label, password, created)."""
        data, f = self._unlock(master)
        out = []
        for e in data["entries"]:
            out.append({
                "label": e["label"],
                "password": f.decrypt(e["password"].encode()).decode(),
                "created": e.get("created", ""),
            })
        return out
