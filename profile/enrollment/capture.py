"""
Guided face enrollment with quality validation.

Rejects blurry, poorly lit, or inconsistent captures to minimize false
positives during lockscreen monitoring.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

import cv2
import numpy as np

from profile.embeddings.manager import EmbeddingSample


class PoseGuide(str, Enum):
    FRONT = "front"
    LEFT = "left"
    RIGHT = "right"
    UP = "up"
    DOWN = "down"

    @property
    def instruction(self) -> str:
        return {
            PoseGuide.FRONT: "Look straight at the camera",
            PoseGuide.LEFT: "Turn your head slightly left",
            PoseGuide.RIGHT: "Turn your head slightly right",
            PoseGuide.UP: "Tilt your head slightly up",
            PoseGuide.DOWN: "Tilt your head slightly down",
        }[self]


@dataclass
class CaptureQuality:
    ok: bool
    blur_variance: float
    brightness: float
    face_detected: bool
    message: str


class EnrollmentCapture:
    def __init__(
        self,
        max_blur_variance: float = 80.0,
        min_brightness: float = 40.0,
        max_brightness: float = 220.0,
        min_samples_per_pose: int = 2,
    ) -> None:
        self._max_blur = max_blur_variance
        self._min_brightness = min_brightness
        self._max_brightness = max_brightness
        self._min_samples = min_samples_per_pose

    @staticmethod
    def laplacian_blur_score(frame: np.ndarray) -> float:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        return float(cv2.Laplacian(gray, cv2.CV_64F).var())

    @staticmethod
    def mean_brightness(frame: np.ndarray) -> float:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        return float(np.mean(gray))

    def assess_frame(self, frame: np.ndarray, face_detected: bool) -> CaptureQuality:
        blur = self.laplacian_blur_score(frame)
        brightness = self.mean_brightness(frame)

        if not face_detected:
            return CaptureQuality(False, blur, brightness, False, "No face detected")
        if blur < self._max_blur:
            return CaptureQuality(False, blur, brightness, True, "Image too blurry — hold still")
        if brightness < self._min_brightness:
            return CaptureQuality(False, blur, brightness, True, "Too dark — improve lighting")
        if brightness > self._max_brightness:
            return CaptureQuality(False, blur, brightness, True, "Too bright — reduce backlight")
        return CaptureQuality(True, blur, brightness, True, "Quality OK")

    def collect_pose_samples(
        self,
        pose: PoseGuide,
        get_frame: Callable[[], Optional[np.ndarray]],
        extract_embedding: Callable[[np.ndarray], Optional[tuple[np.ndarray, float]]],
        on_status: Callable[[str], None],
        *,
        target_count: Optional[int] = None,
    ) -> list[EmbeddingSample]:
        target = target_count or self._min_samples
        samples: list[EmbeddingSample] = []
        on_status(f"{pose.instruction} — need {target} good capture(s)")

        while len(samples) < target:
            frame = get_frame()
            if frame is None:
                on_status("Camera unavailable")
                continue

            result = extract_embedding(frame)
            face_ok = result is not None
            quality = self.assess_frame(frame, face_ok)

            if not quality.ok:
                on_status(quality.message)
                continue

            embedding, det_score = result  # type: ignore[misc]
            samples.append(
                EmbeddingSample(
                    pose=pose.value,
                    embedding=embedding,
                    quality_score=det_score,
                )
            )
            on_status(f"Captured {len(samples)}/{target} for {pose.value}")

        return samples
