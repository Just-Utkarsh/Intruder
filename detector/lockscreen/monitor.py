"""
Multi-source Linux lockscreen detection.

Integration strategy (layered, first match wins):
1. loginctl LockedHint — reliable on systemd/logind sessions
2. DBus ScreenSaver Active — X11/Wayland screensaver APIs
3. Process monitor — hyprlock, swaylock, i3lock, etc.

Supports Hyprland, Sway, i3, and generic systemd sessions.
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class LockState(str, Enum):
    UNKNOWN = "unknown"
    LOCKED = "locked"
    UNLOCKED = "unlocked"


@dataclass
class LockscreenConfig:
    use_loginctl: bool = True
    use_dbus_screensaver: bool = True
    process_names: tuple[str, ...] = (
        "hyprlock",
        "swaylock",
        "i3lock",
        "xsecurelock",
        "light-locker",
        "slock",
    )
    poll_interval_sec: float = 0.5


class LockscreenMonitor:
    def __init__(self, config: Optional[LockscreenConfig] = None) -> None:
        self._config = config or LockscreenConfig()
        self._last_state = LockState.UNKNOWN
        self._dbus_iface = None
        self._init_dbus()

    def _init_dbus(self) -> None:
        if not self._config.use_dbus_screensaver:
            return
        try:
            import dbus  # type: ignore[import-untyped]

            bus = dbus.SessionBus()
            self._dbus_iface = bus.get_object(
                "org.freedesktop.ScreenSaver",
                "/org/freedesktop/ScreenSaver",
            )
        except Exception as e:
            logger.debug("DBus screensaver unavailable: %s", e)
            self._dbus_iface = None

    def _loginctl_locked(self) -> Optional[bool]:
        if not self._config.use_loginctl:
            return None
        try:
            uid = os.getuid()
            result = subprocess.run(
                ["loginctl", "show-user", str(uid), "--property=LockedHint", "--value"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            if result.returncode != 0:
                return None
            val = result.stdout.strip().lower()
            if val == "yes":
                return True
            if val == "no":
                return False
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.debug("loginctl check failed: %s", e)
        return None

    def _dbus_locked(self) -> Optional[bool]:
        if self._dbus_iface is None:
            return None
        try:
            import dbus  # type: ignore[import-untyped]

            iface = dbus.Interface(self._dbus_iface, "org.freedesktop.ScreenSaver")
            active = bool(iface.GetActive())
            return active
        except Exception as e:
            logger.debug("DBus lock check failed: %s", e)
        return None

    def _process_locked(self) -> bool:
        try:
            result = subprocess.run(
                ["ps", "-eo", "comm="],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            if result.returncode != 0:
                return False
            running = {line.strip().lower() for line in result.stdout.splitlines()}
            for name in self._config.process_names:
                if name.lower() in running:
                    return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return False

    def get_state(self) -> LockState:
        locked_hint = self._loginctl_locked()
        if locked_hint is True:
            return LockState.LOCKED
        if locked_hint is False:
            return LockState.UNLOCKED

        dbus_state = self._dbus_locked()
        if dbus_state is True:
            return LockState.LOCKED

        if self._process_locked():
            return LockState.LOCKED

        if dbus_state is False and locked_hint is False:
            return LockState.UNLOCKED
        if locked_hint is False:
            return LockState.UNLOCKED

        return LockState.UNLOCKED

    def is_locked(self) -> bool:
        state = self.get_state()
        self._last_state = state
        return state == LockState.LOCKED

    @property
    def last_state(self) -> LockState:
        return self._last_state
