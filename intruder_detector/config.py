"""Configuration loader with user override support."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_CONFIG = _PACKAGE_ROOT / "configs" / "default.yaml"


def expand_path(path: str) -> Path:
    return Path(os.path.expanduser(path)).resolve()


def get_config_dir() -> Path:
    return expand_path("~/.config/intruder-detector")


def get_data_dir() -> Path:
    return expand_path("~/.local/share/intruder-detector")


def load_config() -> dict[str, Any]:
    """Load default config merged with user overrides."""
    with _DEFAULT_CONFIG.open(encoding="utf-8") as f:
        config: dict[str, Any] = yaml.safe_load(f) or {}

    user_path = get_config_dir() / "config.yaml"
    if user_path.exists():
        with user_path.open(encoding="utf-8") as f:
            user_cfg = yaml.safe_load(f) or {}
        config = _deep_merge(config, user_cfg)

    storage = config.setdefault("storage", {})
    storage["data_dir"] = str(expand_path(storage.get("data_dir", "~/.local/share/intruder-detector")))
    storage["config_dir"] = str(expand_path(storage.get("config_dir", "~/.config/intruder-detector")))
    return config


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
