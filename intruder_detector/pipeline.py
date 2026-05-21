"""
Intruder detection pipeline — core runtime loop.

Flow:
1. Lockscreen active → open camera
2. Motion gate (optional) → face detect → recognize
3. Unauthorized → burst capture → encrypt → store → log
4. Unlock → release camera, reset motion
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any, Optional

import cv2
import numpy as np

from database.models import init_db
from database.repository import IncidentRepository
from detector.camera.manager import CameraManager
from detector.face_detection.engine import FaceDetectionEngine
from detector.lockscreen.monitor import LockscreenMonitor, LockscreenConfig
from detector.motion.detector import MotionDetector
from detector.recognition.engine import RecognitionEngine, RecognitionConfig, IdentityLabel
from logs.alerts import AlertManager
from profile.embeddings.manager import ProfileManager
from security.encryption.crypto import CryptoManager
from security.secure_storage.storage import SecureStorage

logger = logging.getLogger(__name__)


class IntruderPipeline:
    def __init__(
        self,
        config: dict[str, Any],
        storage: SecureStorage,
        crypto: CryptoManager,
        profile_manager: ProfileManager,
        *,
        session_key: Optional[bytes] = None,
        vault_password: Optional[str] = None,
    ) -> None:
        self._config = config
        self._storage = storage
        self._crypto = crypto
        self._profiles = profile_manager
        self._session_key = session_key
        self._vault_password = vault_password

        cam = config.get("camera", {})
        self._camera = CameraManager(
            device_index=cam.get("device_index", 0),
            width=cam.get("width", 640),
            height=cam.get("height", 480),
            fps=cam.get("fps", 15),
            reconnect_delay_sec=cam.get("reconnect_delay_sec", 2.0),
            max_reconnect_attempts=cam.get("max_reconnect_attempts", 10),
        )

        motion = config.get("motion", {})
        self._motion = MotionDetector(
            min_area=motion.get("min_area", 800),
            cooldown_sec=motion.get("cooldown_sec", 1.0),
            enabled=motion.get("enabled", True),
        )

        fd = config.get("face_detection", {})
        rec = config.get("recognition", {})
        self._face = FaceDetectionEngine(
            backend=fd.get("backend", "insightface"),
            model_name=rec.get("model", "buffalo_l"),
            detection_threshold=fd.get("detection_threshold", 0.5),
            min_detection_score=rec.get("min_detection_score", 0.6),
        )

        self._recognition = RecognitionEngine(
            RecognitionConfig(
                similarity_threshold=rec.get("similarity_threshold", 0.42),
                unknown_threshold=rec.get("unknown_threshold", 0.32),
                compare_metric=rec.get("compare_metric", "cosine"),
            )
        )

        ls = config.get("lockscreen", {})
        self._lockscreen = LockscreenMonitor(
            LockscreenConfig(
                use_loginctl=ls.get("use_loginctl", True),
                use_dbus_screensaver=ls.get("use_dbus_screensaver", True),
                process_names=tuple(ls.get("process_names", [])),
            )
        )

        self._intruder_cfg = config.get("intruder", {})
        self._alerts = AlertManager(config)
        self._monitoring = False
        self._last_incident_time = 0.0
        self._profile_cache = None

        db_path = storage.data_dir / "events.db"
        init_db(db_path)

        asp = config.get("anti_spoofing", {})
        if asp.get("enabled"):
            self._face.prepare_anti_spoofing_hook(asp.get("hook_module"))

    def _load_profile(self) -> None:
        if not self._profiles.exists():
            return
        if self._vault_password:
            self._profile_cache = self._profiles.load(self._vault_password)
        elif self._session_key:
            raw = self._storage.read_encrypted(
                self._profiles.profile_path,
                self._crypto,
                "",
                raw_key=self._session_key,
            )
            import json
            from profile.embeddings.manager import EmbeddingProfile

            self._profile_cache = EmbeddingProfile.from_serializable(
                json.loads(raw.decode("utf-8"))
            )

    def _session_factory(self):
        from database.models import _SessionLocal

        if _SessionLocal is None:
            raise RuntimeError("DB not initialized")
        return _SessionLocal()

    def run_cycle(self) -> None:
        """Single poll iteration — called by daemon main loop."""
        if (not self._session_key and not self._vault_password) or not self._profiles.exists():
            return

        locked = self._lockscreen.is_locked()

        if locked and not self._monitoring:
            logger.info("Lockscreen active — starting monitoring")
            self._monitoring = True
            self._motion.reset()
            if not self._camera.open():
                logger.error("Cannot open camera for monitoring")
                return
            self._load_profile()

        if not locked and self._monitoring:
            logger.info("Session unlocked — stopping monitoring")
            self._monitoring = False
            self._camera.close()
            self._profile_cache = None
            return

        if not self._monitoring:
            return

        self._process_frame()

    def _process_frame(self) -> None:
        frame = self._camera.read()
        if frame is None or self._profile_cache is None:
            return

        require_motion = self._intruder_cfg.get("require_motion_first", True)
        if require_motion and not self._motion.detect(frame):
            return

        result = self._face.extract_primary_embedding(frame)
        if result is None:
            return

        embedding, det_score = result
        identity = self._recognition.identify(embedding, self._profile_cache)

        if identity.label == IdentityLabel.AUTHORIZED:
            logger.debug("Authorized user detected (sim=%.3f)", identity.confidence)
            return

        if identity.label == IdentityLabel.UNKNOWN:
            cooldown = self._intruder_cfg.get("cooldown_between_incidents_sec", 30.0)
            if time.time() - self._last_incident_time < cooldown:
                return
            logger.warning("Unauthorized face detected — capturing evidence")
            self._handle_intrusion(frame, identity.confidence, det_score)

    def _handle_intrusion(self, frame: np.ndarray, confidence: float, det_score: float) -> None:
        incident_id = str(uuid.uuid4())
        incident_dir = self._storage.incident_dir(incident_id)
        burst_count = self._intruder_cfg.get("burst_count", 4)
        interval_ms = self._intruder_cfg.get("burst_interval_ms", 150)

        encrypted_images: list[str] = []
        for i in range(burst_count):
            if i > 0:
                time.sleep(interval_ms / 1000.0)
                new_frame = self._camera.read()
                if new_frame is not None:
                    frame = new_frame

            _, buf = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 85])
            plaintext = buf.tobytes()
            enc_path = incident_dir / f"img_{i:02d}.enc"
            self._storage.write_encrypted(
                enc_path,
                plaintext,
                self._crypto,
                self._vault_password or "",
                raw_key=self._session_key,
            )
            encrypted_images.append(enc_path.name)
            del plaintext, buf

        meta = {
            "detection_score": det_score,
            "recognition_confidence": confidence,
            "images": encrypted_images,
            "timestamp_utc": time.time(),
        }
        meta_path = incident_dir / "meta.enc"
        self._storage.write_encrypted(
            meta_path,
            json.dumps(meta).encode("utf-8"),
            self._crypto,
            self._vault_password or "",
            raw_key=self._session_key,
        )

        session = self._session_factory()
        try:
            repo = IncidentRepository(session)
            record = repo.create(
                confidence=confidence,
                image_count=burst_count,
                storage_path=str(incident_dir),
                metadata=meta,
                lockscreen_source=self._lockscreen.last_state.value,
            )
            self._alerts.notify_intrusion(record.id, confidence)
        finally:
            session.close()

        self._last_incident_time = time.time()
        logger.warning("Incident recorded: %s", incident_id)
