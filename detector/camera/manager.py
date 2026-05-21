"""
Webcam manager with auto-reconnect and resource-efficient capture.

Opens V4L2 device only when needed; supports silent background operation.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import cv2
import numpy as np

logger = logging.getLogger(__name__)


class CameraManager:
    def __init__(
        self,
        device_index: int = 0,
        width: int = 640,
        height: int = 480,
        fps: int = 15,
        reconnect_delay_sec: float = 2.0,
        max_reconnect_attempts: int = 10,
    ) -> None:
        self._device_index = device_index
        self._width = width
        self._height = height
        self._fps = fps
        self._reconnect_delay = reconnect_delay_sec
        self._max_reconnect = max_reconnect_attempts
        self._cap: Optional[cv2.VideoCapture] = None
        self._reconnect_count = 0

    @property
    def is_open(self) -> bool:
        return self._cap is not None and self._cap.isOpened()

    def open(self) -> bool:
        self.close()
        cap = cv2.VideoCapture(self._device_index)
        if not cap.isOpened():
            logger.warning("Failed to open camera index %s", self._device_index)
            return False
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, self._width)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self._height)
        cap.set(cv2.CAP_PROP_FPS, self._fps)
        self._cap = cap
        self._reconnect_count = 0
        logger.info("Camera opened (device %s)", self._device_index)
        return True

    def close(self) -> None:
        if self._cap is not None:
            self._cap.release()
            self._cap = None

    def read(self) -> Optional[np.ndarray]:
        if not self.is_open:
            if not self._try_reconnect():
                return None
        assert self._cap is not None
        ok, frame = self._cap.read()
        if not ok or frame is None:
            logger.warning("Frame read failed — reconnecting")
            self.close()
            if self._try_reconnect():
                return self.read()
            return None
        return frame

    def _try_reconnect(self) -> bool:
        if self._reconnect_count >= self._max_reconnect:
            return False
        self._reconnect_count += 1
        time.sleep(self._reconnect_delay)
        return self.open()

    def __enter__(self) -> "CameraManager":
        self.open()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
