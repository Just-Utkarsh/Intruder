#!/usr/bin/env python3
"""First-time setup: password + multi-pose face enrollment."""

from __future__ import annotations

import sys
from getpass import getpass
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from rich.console import Console
from rich.panel import Panel

from intruder_detector.config import load_config
from detector.camera.manager import CameraManager
from detector.face_detection.engine import FaceDetectionEngine
from profile.enrollment.capture import EnrollmentCapture, PoseGuide
from profile.embeddings.manager import ProfileManager
from security.encryption.crypto import CryptoManager
from security.password.manager import PasswordManager
from security.secure_storage.storage import SecureStorage

console = Console()


def _prompt_password() -> str:
    while True:
        p1 = getpass("Create vault password (min 10 chars): ")
        p2 = getpass("Confirm password: ")
        if p1 != p2:
            console.print("[red]Passwords do not match[/red]")
            continue
        if len(p1) < 10:
            console.print("[red]Password too short[/red]")
            continue
        return p1


def main() -> None:
    console.print(Panel.fit("Intruder Detector — First-Time Setup", style="bold cyan"))
    config = load_config()
    data_dir = Path(config["storage"]["data_dir"])
    storage = SecureStorage(data_dir)
    pm = PasswordManager(storage)

    if pm.is_initialized:
        console.print("[yellow]Already configured. Use intruder-profile to update face.[/yellow]")
        sys.exit(0)

    password = _prompt_password()
    pm.create_password(password)

    crypto = CryptoManager(iterations=config["security"]["kdf_iterations"])
    salt = crypto.generate_master_salt()
    salt_path = storage.data_dir / "auth" / "master.salt"
    storage.write_bytes(salt_path, salt)
    crypto.set_master_salt(salt)

    cam_cfg = config["camera"]
    camera = CameraManager(
        device_index=cam_cfg.get("device_index", 0),
        width=cam_cfg.get("width", 640),
        height=cam_cfg.get("height", 480),
    )
    if not camera.open():
        console.print("[red]Cannot open webcam. Check permissions (video group).[/red]")
        sys.exit(1)

    fd_cfg = config["face_detection"]
    rec_cfg = config["recognition"]
    face_engine = FaceDetectionEngine(
        backend=fd_cfg.get("backend", "insightface"),
        model_name=rec_cfg.get("model", "buffalo_l"),
        detection_threshold=fd_cfg.get("detection_threshold", 0.5),
        min_detection_score=rec_cfg.get("min_detection_score", 0.6),
    )

    enroll_cfg = config["enrollment"]
    capture = EnrollmentCapture(
        max_blur_variance=enroll_cfg.get("max_blur_variance", 80.0),
        min_brightness=enroll_cfg.get("min_brightness", 40),
        max_brightness=enroll_cfg.get("max_brightness", 220),
        min_samples_per_pose=enroll_cfg.get("min_samples_per_pose", 2),
    )

    all_samples = []
    pose_names = enroll_cfg.get("poses", ["front", "left", "right", "up", "down"])
    pose_map = {p.value: p for p in PoseGuide}

    for pose_name in pose_names:
        pose = pose_map.get(pose_name, PoseGuide.FRONT)
        console.print(f"\n[bold]Pose: {pose.value}[/bold] — {pose.instruction}")

        def get_frame():
            return camera.read()

        def extract(frame):
            return face_engine.extract_primary_embedding(frame)

        def status(msg: str):
            console.print(f"  {msg}")

        samples = capture.collect_pose_samples(pose, get_frame, extract, status)
        all_samples.extend(samples)

    camera.close()
    from profile.embeddings.manager import EmbeddingProfile

    profiles = ProfileManager(storage, crypto)
    profiles.save(EmbeddingProfile(version=1, samples=all_samples), password)

    console.print(Panel.fit(
        f"Setup complete.\n\nData: {data_dir}\n\nNext steps:\n"
        "  1. intruder-detector unlock\n"
        "  2. systemctl --user enable --now intruder-detector\n",
        style="green",
    ))


if __name__ == "__main__":
    main()
