"""
Runtime session key management for daemon operation.

The daemon cannot prompt for passwords in the background. After login, the user
(or systemd user unit) runs `intruder-detector unlock` to derive the master key
and place it in $XDG_RUNTIME_DIR (tmpfs, cleared on logout/reboot).

Security: session key file is mode 0600, wiped on lock/unlock commands.
"""

from __future__ import annotations

import os
from pathlib import Path

from security.encryption.crypto import CryptoManager, KEY_SIZE


def runtime_key_path() -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    return Path(runtime) / "intruder-detector" / "session.key"


class SessionManager:
    def __init__(self, crypto: CryptoManager) -> None:
        self._crypto = crypto

    @property
    def key_path(self) -> Path:
        return runtime_key_path()

    def is_unlocked(self) -> bool:
        return self.key_path.exists()

    def unlock(self, password: str) -> None:
        if self._crypto.master_salt is None:
            raise RuntimeError("Master salt not loaded")
        key = self._crypto.derive_key(password, self._crypto.master_salt)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path.write_bytes(key)
        os.chmod(self.key_path, 0o600)

    def lock(self) -> None:
        if self.key_path.exists():
            # Overwrite before delete
            size = self.key_path.stat().st_size
            with self.key_path.open("r+b") as f:
                f.write(os.urandom(max(size, KEY_SIZE)))
            self.key_path.unlink()

    def load_session_key(self) -> bytes:
        """Load derived 32-byte key from tmpfs session store."""
        if not self.is_unlocked():
            raise PermissionError("Vault locked. Run: intruder-detector unlock")
        key = self.key_path.read_bytes()
        if len(key) != KEY_SIZE:
            raise ValueError("Invalid session key")
        return key
