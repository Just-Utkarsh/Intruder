#!/usr/bin/env python3
"""Face profile update and retraining CLI."""

from __future__ import annotations

import sys
from getpass import getpass
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import click
from rich.console import Console

from intruder_detector.config import load_config
from detector.camera.manager import CameraManager
from detector.face_detection.engine import FaceDetectionEngine
from detector.recognition.engine import RecognitionEngine, RecognitionConfig
from profile.enrollment.capture import EnrollmentCapture, PoseGuide
from profile.embeddings.manager import ProfileManager
from profile.retraining.updater import ProfileUpdater
from security.encryption.crypto import CryptoManager
from security.password.manager import PasswordManager
from security.secure_storage.storage import SecureStorage

console = Console()


def _deps():
    config = load_config()
    storage = SecureStorage(Path(config["storage"]["data_dir"]))
    crypto = CryptoManager(iterations=config["security"]["kdf_iterations"])
    salt_path = storage.data_dir / "auth" / "master.salt"
    crypto.set_master_salt(salt_path.read_bytes())
    pm = PasswordManager(storage)
    profiles = ProfileManager(storage, crypto)
    rec_cfg = config["recognition"]
    recognition = RecognitionEngine(
        RecognitionConfig(
            similarity_threshold=rec_cfg.get("similarity_threshold", 0.42),
            unknown_threshold=rec_cfg.get("unknown_threshold", 0.32),
        )
    )
    return config, storage, crypto, pm, profiles, recognition


@click.group()
def main() -> None:
    """Manage authorized face profile."""


@main.command("add-samples")
@click.option("--pose", default="front", type=click.Choice([p.value for p in PoseGuide]))
def add_samples(pose: str) -> None:
    config, storage, crypto, pm, profiles, recognition = _deps()
    password = getpass("Vault password: ")
    if not pm.verify(password):
        raise click.ClickException("Invalid password")

    updater = ProfileUpdater(profiles, pm, recognition)
    enroll_cfg = config["enrollment"]
    capture = EnrollmentCapture(min_samples_per_pose=1)
    cam = CameraManager(**{k: config["camera"].get(k) for k in ("device_index", "width", "height")})
    cam.open()
    fd = FaceDetectionEngine(
        model_name=config["recognition"].get("model", "buffalo_l"),
    )
    pose_enum = PoseGuide(pose)

    samples = capture.collect_pose_samples(
        pose_enum,
        cam.read,
        lambda f: fd.extract_primary_embedding(f),
        lambda m: console.print(m),
        target_count=2,
    )
    cam.close()
    profile = updater.add_samples(password, samples)
    console.print(f"[green]Profile updated: {len(profile.samples)} samples[/green]")


@main.command("reset")
def reset() -> None:
    _, _, _, pm, profiles, recognition = _deps()
    password = getpass("Vault password: ")
    if not pm.verify(password):
        raise click.ClickException("Invalid password")
    ProfileUpdater(profiles, pm, recognition).reset_profile(password)
    console.print("[yellow]Profile reset. Run intruder-setup to re-enroll.[/yellow]")


if __name__ == "__main__":
    main()
