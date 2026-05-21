"""Background daemon service orchestration."""

from __future__ import annotations

import logging
import signal
import sys
import time
from pathlib import Path
from typing import Any

from intruder_detector.config import load_config
from intruder_detector.logging_setup import setup_logging
from intruder_detector.pipeline import IntruderPipeline
from intruder_detector.session import SessionManager
from profile.embeddings.manager import ProfileManager
from security.encryption.crypto import CryptoManager
from security.password.manager import PasswordManager
from security.secure_storage.storage import SecureStorage


class DaemonService:
    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        storage_cfg = config.get("storage", {})
        self._storage = SecureStorage(
            Path(storage_cfg["data_dir"]),
            file_mode=int(storage_cfg.get("file_mode", "0600"), 8),
            dir_mode=int(storage_cfg.get("dir_mode", "0700"), 8),
        )
        sec = config.get("security", {})
        self._crypto = CryptoManager(iterations=sec.get("kdf_iterations", 600_000))
        self._session = SessionManager(self._crypto)
        self._profiles = ProfileManager(self._storage, self._crypto)
        self._passwords = PasswordManager(
            self._storage,
            max_attempts=sec.get("brute_force_max_attempts", 5),
            lockout_sec=sec.get("brute_force_lockout_sec", 300),
        )
        self._running = True
        self._pipeline: IntruderPipeline | None = None

    def _load_master_salt(self) -> None:
        salt_path = self._storage.data_dir / "auth" / "master.salt"
        if not salt_path.exists():
            raise FileNotFoundError("Not configured. Run: intruder-setup")
        self._crypto.set_master_salt(salt_path.read_bytes())

    def _session_key(self) -> bytes:
        return self._session.load_session_key()

    def start(self) -> None:
        daemon_cfg = self._config.get("daemon", {})
        logger = setup_logging(
            level=daemon_cfg.get("log_level", "INFO"),
            silent=daemon_cfg.get("silent_mode", True),
        )

        if not self._passwords.is_initialized:
            logger.error("Setup required: intruder-setup")
            sys.exit(1)
        if not self._profiles.exists():
            logger.error("Face profile missing. Run: intruder-setup")
            sys.exit(1)
        if not self._session.is_unlocked():
            logger.error("Vault locked. Run: intruder-detector unlock")
            sys.exit(1)

        self._load_master_salt()
        poll = daemon_cfg.get("poll_interval_sec", 0.5)

        self._pipeline = IntruderPipeline(
            self._config,
            self._storage,
            self._crypto,
            self._profiles,
            session_key=self._session_key(),
        )

        signal.signal(signal.SIGTERM, self._shutdown)
        signal.signal(signal.SIGINT, self._shutdown)
        logger.info("Intruder detector daemon started")

        while self._running:
            try:
                if self._pipeline:
                    self._pipeline.run_cycle()
            except Exception:
                logger.exception("Error in monitoring cycle")
            time.sleep(poll)

        self._session.lock()
        logger.info("Daemon stopped")

    def _shutdown(self, signum: int, frame: object) -> None:
        logging.getLogger("intruder-detector").info("Signal %s received — shutting down", signum)
        self._running = False
