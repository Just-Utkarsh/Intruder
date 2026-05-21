"""
AES-256-GCM encryption with PBKDF2-HMAC-SHA256 key derivation.

Security decisions:
- AES-256-GCM provides authenticated encryption (integrity + confidentiality).
- Random 16-byte salt per encryption context; 12-byte nonce per blob.
- PBKDF2 with 600k iterations resists offline brute-force on stolen vaults.
- Master key never written to disk; derived in memory from password only.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # AES-256
DEFAULT_ITERATIONS = 600_000


@dataclass(frozen=True)
class EncryptedBlob:
    salt: bytes
    nonce: bytes
    ciphertext: bytes

    def pack(self) -> bytes:
        """Format: salt(16) || nonce(12) || ciphertext."""
        return self.salt + self.nonce + self.ciphertext

    @classmethod
    def unpack(cls, data: bytes) -> "EncryptedBlob":
        if len(data) < SALT_SIZE + NONCE_SIZE + 1:
            raise ValueError("Invalid encrypted blob: too short")
        salt = data[:SALT_SIZE]
        nonce = data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
        ciphertext = data[SALT_SIZE + NONCE_SIZE :]
        return cls(salt=salt, nonce=nonce, ciphertext=ciphertext)


class CryptoManager:
    """Password-based encrypt/decrypt for evidence and profile data."""

    def __init__(self, iterations: int = DEFAULT_ITERATIONS) -> None:
        self._iterations = iterations
        self._master_salt: Optional[bytes] = None

    def set_master_salt(self, salt: bytes) -> None:
        if len(salt) != SALT_SIZE:
            raise ValueError(f"Master salt must be {SALT_SIZE} bytes")
        self._master_salt = salt

    def generate_master_salt(self) -> bytes:
        self._master_salt = secrets.token_bytes(SALT_SIZE)
        return self._master_salt

    @property
    def master_salt(self) -> Optional[bytes]:
        return self._master_salt

    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=self._iterations,
            backend=default_backend(),
        )
        return kdf.derive(password.encode("utf-8"))

    def encrypt(self, plaintext: bytes, password: str, salt: Optional[bytes] = None) -> EncryptedBlob:
        use_salt = salt if salt is not None else secrets.token_bytes(SALT_SIZE)
        key = self.derive_key(password, use_salt)
        nonce = secrets.token_bytes(NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return EncryptedBlob(salt=use_salt, nonce=nonce, ciphertext=ciphertext)

    def decrypt(self, blob: EncryptedBlob, password: str) -> bytes:
        key = self.derive_key(password, blob.salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(blob.nonce, blob.ciphertext, None)

    def encrypt_with_master(self, plaintext: bytes, password: str) -> EncryptedBlob:
        if self._master_salt is None:
            raise RuntimeError("Master salt not initialized")
        return self.encrypt(plaintext, password, salt=self._master_salt)

    def decrypt_with_master(self, blob: EncryptedBlob, password: str) -> bytes:
        if self._master_salt is None:
            raise RuntimeError("Master salt not initialized")
        return self.decrypt(blob, password)

    def encrypt_with_raw_key(self, plaintext: bytes, key: bytes) -> EncryptedBlob:
        """Encrypt using a pre-derived 32-byte key (daemon session mode)."""
        if len(key) != KEY_SIZE:
            raise ValueError("Raw key must be 32 bytes")
        nonce = secrets.token_bytes(NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        # salt field holds master salt for blob format compatibility
        salt = self._master_salt or secrets.token_bytes(SALT_SIZE)
        return EncryptedBlob(salt=salt, nonce=nonce, ciphertext=ciphertext)

    def decrypt_with_raw_key(self, blob: EncryptedBlob, key: bytes) -> bytes:
        if len(key) != KEY_SIZE:
            raise ValueError("Raw key must be 32 bytes")
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(blob.nonce, blob.ciphertext, None)

    @staticmethod
    def secure_random_bytes(n: int) -> bytes:
        return secrets.token_bytes(n)
