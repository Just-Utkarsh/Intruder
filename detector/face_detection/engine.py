"""
Face detection abstraction: InsightFace RetinaFace (preferred) or MediaPipe fallback.

RetinaFace provides superior accuracy in low light and varied angles — critical
for lockscreen monitoring where lighting is uncontrolled.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class DetectedFace:
    bbox: tuple[int, int, int, int]  # x1, y1, x2, y2
    confidence: float
    embedding: Optional[np.ndarray] = None
    landmarks: Optional[np.ndarray] = None


class FaceDetectionEngine:
    def __init__(
        self,
        backend: str = "insightface",
        model_name: str = "buffalo_l",
        detection_threshold: float = 0.5,
        min_detection_score: float = 0.6,
    ) -> None:
        self._backend = backend.lower()
        self._model_name = model_name
        self._det_threshold = detection_threshold
        self._min_det_score = min_detection_score
        self._app: Any = None
        self._mp_detector: Any = None
        self._load()

    def _load(self) -> None:
        if self._backend == "insightface":
            try:
                from insightface.app import FaceAnalysis

                self._app = FaceAnalysis(name=self._model_name, providers=["CPUExecutionProvider"])
                self._app.prepare(ctx_id=-1, det_size=(640, 640))
                logger.info("InsightFace RetinaFace+ArcFace loaded (%s)", self._model_name)
            except Exception as e:
                logger.warning("InsightFace failed (%s), falling back to mediapipe", e)
                self._backend = "mediapipe"
                self._load_mediapipe()
        else:
            self._load_mediapipe()

    def _load_mediapipe(self) -> None:
        import mediapipe as mp

        self._mp_detector = mp.solutions.face_detection.FaceDetection(
            model_selection=1,
            min_detection_confidence=self._det_threshold,
        )
        logger.info("MediaPipe face detection loaded")

    def detect_faces(self, frame: np.ndarray, with_embedding: bool = True) -> list[DetectedFace]:
        if self._backend == "insightface" and self._app is not None:
            return self._detect_insightface(frame, with_embedding)
        return self._detect_mediapipe(frame)

    def _detect_insightface(self, frame: np.ndarray, with_embedding: bool) -> list[DetectedFace]:
        faces = self._app.get(frame)
        results: list[DetectedFace] = []
        for f in faces:
            score = float(getattr(f, "det_score", 0.0))
            if score < self._min_det_score:
                continue
            bbox = tuple(int(x) for x in f.bbox.astype(int).tolist())
            emb = None
            if with_embedding and hasattr(f, "embedding") and f.embedding is not None:
                emb = np.array(f.embedding, dtype=np.float32)
                norm = np.linalg.norm(emb)
                if norm > 0:
                    emb = emb / norm
            results.append(
                DetectedFace(
                    bbox=(bbox[0], bbox[1], bbox[2], bbox[3]),
                    confidence=score,
                    embedding=emb,
                    landmarks=getattr(f, "kps", None),
                )
            )
        return results

    def _detect_mediapipe(self, frame: np.ndarray) -> list[DetectedFace]:
        import cv2

        h, w = frame.shape[:2]
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        det = self._mp_detector.process(rgb)
        results: list[DetectedFace] = []
        if not det.detections:
            return results
        for d in det.detections:
            if d.score is None or d.score[0] < self._det_threshold:
                continue
            loc = d.location_data.relative_bounding_box
            x1 = max(0, int(loc.xmin * w))
            y1 = max(0, int(loc.ymin * h))
            x2 = min(w, int((loc.xmin + loc.width) * w))
            y2 = min(h, int((loc.ymin + loc.height) * h))
            results.append(
                DetectedFace(
                    bbox=(x1, y1, x2, y2),
                    confidence=float(d.score[0]),
                )
            )
        return results

    def extract_primary_embedding(self, frame: np.ndarray) -> Optional[tuple[np.ndarray, float]]:
        faces = self.detect_faces(frame, with_embedding=True)
        if not faces:
            return None
        best = max(faces, key=lambda f: f.confidence)
        if best.embedding is None:
            return None
        return best.embedding, best.confidence

    def prepare_anti_spoofing_hook(self, module_path: Optional[str]) -> None:
        """Placeholder for future liveness / anti-spoofing module."""
        if module_path:
            logger.info("Anti-spoofing hook reserved: %s", module_path)
