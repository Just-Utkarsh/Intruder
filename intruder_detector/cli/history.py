#!/usr/bin/env python3
"""Terminal history viewer with password-protected decryption."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from getpass import getpass
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import click
from rich.console import Console
from rich.table import Table

from intruder_detector.config import load_config
from database.models import init_db
from database.repository import IncidentRepository
from security.encryption.crypto import CryptoManager, EncryptedBlob
from security.password.manager import PasswordManager
from security.secure_storage.storage import SecureStorage

console = Console()


def _get_deps():
    config = load_config()
    data_dir = Path(config["storage"]["data_dir"])
    storage = SecureStorage(data_dir)
    crypto = CryptoManager(iterations=config["security"]["kdf_iterations"])
    salt_path = storage.data_dir / "auth" / "master.salt"
    crypto.set_master_salt(salt_path.read_bytes())
    init_db(data_dir / "events.db")
    return config, storage, crypto, PasswordManager(storage)


@click.group()
def main() -> None:
    """Browse and manage intrusion event history."""


@main.command("list")
@click.option("--limit", default=20)
def list_events(limit: int) -> None:
    _, storage, _, _ = _get_deps()
    from database.models import _SessionLocal

    session = _SessionLocal()
    try:
        repo = IncidentRepository(session)
        records = repo.list_all(limit=limit)
    finally:
        session.close()

    table = Table(title="Intrusion Events")
    table.add_column("ID")
    table.add_column("Timestamp")
    table.add_column("Confidence")
    table.add_column("Images")
    for r in records:
        table.add_row(
            r.id[:8] + "…",
            r.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            f"{r.confidence:.2%}",
            str(r.image_count),
        )
    console.print(table)


@main.command("view")
@click.argument("incident_id")
def view_event(incident_id: str) -> None:
    _, storage, crypto, pm = _get_deps()
    password = getpass("Vault password: ")
    if not pm.verify(password):
        console.print("[red]Invalid password[/red]")
        sys.exit(1)

    from database.models import _SessionLocal

    session = _SessionLocal()
    try:
        repo = IncidentRepository(session)
        record = repo.get(incident_id)
        if not record:
            console.print("[red]Incident not found[/red]")
            sys.exit(1)
    finally:
        session.close()

    incident_dir = Path(record.storage_path)
    meta_path = incident_dir / "meta.enc"
    meta_raw = storage.read_encrypted(meta_path, crypto, password)
    meta = json.loads(meta_raw.decode("utf-8"))

    console.print(f"[bold]Incident[/bold] {record.id}")
    console.print(f"Time: {record.timestamp}")
    console.print(f"Confidence: {record.confidence:.2%}")

    temp_dir = storage.data_dir / "temp" / record.id
    temp_dir.mkdir(parents=True, exist_ok=True)
    try:
        for img_name in meta.get("images", []):
            enc_path = incident_dir / img_name
            data = storage.read_encrypted(enc_path, crypto, password)
            out = temp_dir / img_name.replace(".enc", ".jpg")
            out.write_bytes(data)
            console.print(f"Decrypted (temporary): {out}")
        console.print("[dim]Temporary files will be wiped on exit.[/dim]")
        input("Press Enter to securely wipe decrypted files…")
    finally:
        import shutil

        if temp_dir.exists():
            for f in temp_dir.iterdir():
                SecureStorage.secure_wipe(f)
            shutil.rmtree(temp_dir, ignore_errors=True)


@main.command("delete")
@click.argument("incident_id")
def delete_event(incident_id: str) -> None:
    _, storage, _, pm = _get_deps()
    password = getpass("Vault password: ")
    if not pm.verify(password):
        console.print("[red]Invalid password[/red]")
        sys.exit(1)

    from database.models import _SessionLocal
    import shutil

    session = _SessionLocal()
    try:
        repo = IncidentRepository(session)
        record = repo.get(incident_id)
        if not record:
            console.print("[red]Not found[/red]")
            sys.exit(1)
        incident_dir = Path(record.storage_path)
        repo.delete(incident_id)
    finally:
        session.close()

    if incident_dir.exists():
        for f in incident_dir.iterdir():
            SecureStorage.secure_wipe(f)
        shutil.rmtree(incident_dir, ignore_errors=True)
    console.print("[green]Incident deleted[/green]")


if __name__ == "__main__":
    main()
