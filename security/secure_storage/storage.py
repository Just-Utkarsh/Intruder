"""
Secure filesystem operations with restrictive permissions and secure deletion.

Linux integration:
- Directories 0700, files 0600 (owner-only).
- Hidden storage under ~/.local/share/intruder-detector/
- Secure wipe overwrites before unlink for sensitive temp data.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, Union

from security.encryption.crypto import CryptoManager, EncryptedBlob


class SecureStorage:
    def __init__(self, data_dir: Path, file_mode: int = 0o600, dir_mode: int = 0o700) -> None:
        self.data_dir = Path(data_dir)
        self._file_mode = file_mode
        self._dir_mode = dir_mode
        self._ensure_layout()

    def _ensure_layout(self) -> None:
        for sub in ("auth", "profile", "incidents", "temp", "exports"):
            self._mkdir(self.data_dir / sub)

    def _mkdir(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, self._dir_mode)

    def _set_file_mode(self, path: Path) -> None:
        os.chmod(path, self._file_mode)

    def write_bytes(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, self._dir_mode)
        path.write_bytes(data)
        self._set_file_mode(path)

    def read_bytes(self, path: Path) -> bytes:
        return path.read_bytes()

    def write_encrypted(
        self,
        path: Path,
        plaintext: bytes,
        crypto: CryptoManager,
        password: str,
        use_master: bool = True,
        raw_key: bytes | None = None,
    ) -> None:
        if raw_key is not None:
            blob = crypto.encrypt_with_raw_key(plaintext, raw_key)
        elif use_master and crypto.master_salt is not None:
            blob = crypto.encrypt_with_master(plaintext, password)
        else:
            blob = crypto.encrypt(plaintext, password)
        self.write_bytes(path, blob.pack())

    def read_encrypted(
        self,
        path: Path,
        crypto: CryptoManager,
        password: str,
        use_master: bool = True,
        raw_key: bytes | None = None,
    ) -> bytes:
        raw = self.read_bytes(path)
        blob = EncryptedBlob.unpack(raw)
        if raw_key is not None:
            return crypto.decrypt_with_raw_key(blob, raw_key)
        if use_master and crypto.master_salt is not None:
            return crypto.decrypt_with_master(blob, password)
        return crypto.decrypt(blob, password)

    def write_json(self, path: Path, obj: Any) -> None:
        self.write_bytes(path, json.dumps(obj, indent=2).encode("utf-8"))

    def read_json(self, path: Path) -> Any:
        return json.loads(self.read_bytes(path).decode("utf-8"))

    def incident_dir(self, incident_id: str) -> Path:
        d = self.data_dir / "incidents" / incident_id
        self._mkdir(d)
        return d

    @staticmethod
    def secure_wipe(path: Path, passes: int = 3) -> None:
        if not path.exists() or not path.is_file():
            if path.exists():
                path.unlink()
            return
        size = path.stat().st_size
        with path.open("r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        path.unlink()

    def temp_file(self, suffix: str = ".tmp") -> Path:
        import uuid

        temp_dir = self.data_dir / "temp"
        self._mkdir(temp_dir)
        return temp_dir / f"{uuid.uuid4().hex}{suffix}"
