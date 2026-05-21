"""
Password verification with Argon2id-style approach using PBKDF2 for verifier storage.

Security decisions:
- Never store plaintext passwords; only salted verifier hash.
- Brute-force lockout after N failed attempts (configurable).
- Verifier stored separately from encrypted vault salt.
"""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from security.secure_storage.storage import SecureStorage


VERIFIER_ITERATIONS = 600_000
VERIFIER_KEY_LEN = 32


class PasswordManager:
    def __init__(
        self,
        storage: SecureStorage,
        max_attempts: int = 5,
        lockout_sec: int = 300,
    ) -> None:
        self._storage = storage
        self._max_attempts = max_attempts
        self._lockout_sec = lockout_sec
        self._verifier_path = storage.data_dir / "auth" / "verifier.json"
        self._failed_attempts = 0
        self._lockout_until: float = 0.0

    @property
    def is_initialized(self) -> bool:
        return self._verifier_path.exists()

    def _hash_password(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=VERIFIER_KEY_LEN,
            salt=salt,
            iterations=VERIFIER_ITERATIONS,
            backend=default_backend(),
        )
        return kdf.derive(password.encode("utf-8"))

    def create_password(self, password: str) -> None:
        if len(password) < 10:
            raise ValueError("Password must be at least 10 characters")
        salt = secrets.token_bytes(16)
        verifier = self._hash_password(password, salt)
        payload = {
            "salt": salt.hex(),
            "verifier": verifier.hex(),
            "version": 1,
        }
        self._storage.write_json(self._verifier_path, payload)
        self._failed_attempts = 0

    def _load_verifier(self) -> dict:
        return self._storage.read_json(self._verifier_path)

    def verify(self, password: str) -> bool:
        if time.time() < self._lockout_until:
            raise PermissionError(
                f"Account locked. Try again in {int(self._lockout_until - time.time())} seconds."
            )
        if not self.is_initialized:
            raise FileNotFoundError("Password not configured. Run setup first.")

        data = self._load_verifier()
        salt = bytes.fromhex(data["salt"])
        expected = bytes.fromhex(data["verifier"])
        computed = self._hash_password(password, salt)

        if secrets.compare_digest(computed, expected):
            self._failed_attempts = 0
            return True

        self._failed_attempts += 1
        if self._failed_attempts >= self._max_attempts:
            self._lockout_until = time.time() + self._lockout_sec
            self._failed_attempts = 0
        return False

    def require_verify(self, password: str) -> None:
        if not self.verify(password):
            raise PermissionError("Invalid password")
