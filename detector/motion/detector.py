"""
Motion-triggered frame gating to reduce CPU usage.

Only runs full face pipeline when motion exceeds threshold (MOG2 background
subtraction). Cooldown prevents repeated triggers on static scenes.
"""

from __future__ import annotations

import time
from typing import Optional

import cv2
import numpy as np


class MotionDetector:
    def __init__(
        self,
        min_area: int = 800,
        cooldown_sec: float = 1.0,
        enabled: bool = True,
    ) -> None:
        self._min_area = min_area
        self._cooldown_sec = cooldown_sec
        self._enabled = enabled
        self._bg = cv2.createBackgroundSubtractorMOG2(history=120, detectShadows=False)
        self._last_trigger = 0.0

    def reset(self) -> None:
        self._bg = cv2.createBackgroundSubtractorMOG2(history=120, detectShadows=False)

    def detect(self, frame: np.ndarray) -> bool:
        if not self._enabled:
            return True
        now = time.time()
        if now - self._last_trigger < self._cooldown_sec:
            return False

        small = cv2.resize(frame, (320, 240))
        fg = self._bg.apply(small)
        _, thresh = cv2.threshold(fg, 200, 255, cv2.THRESH_BINARY)
        contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        for c in contours:
            if cv2.contourArea(c) >= self._min_area:
                self._last_trigger = now
                return True
        return False
