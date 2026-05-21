"""CLI entry point for intruder-detector (unlock, lock, daemon)."""

from __future__ import annotations

from pathlib import Path

import click

from intruder_detector.config import load_config
from intruder_detector.daemon import DaemonService
from intruder_detector.session import SessionManager
from security.encryption.crypto import CryptoManager
from security.password.manager import PasswordManager
from security.secure_storage.storage import SecureStorage


@click.group()
def cli() -> None:
    """Linux AI Intruder Detection System."""


@cli.command()
def daemon() -> None:
    """Run background monitoring daemon."""
    config = load_config()
    DaemonService(config).start()


@cli.command()
@click.option("--password", "-p", prompt=True, hide_input=True, confirmation_prompt=True)
def unlock(password: str) -> None:
    """Unlock vault for daemon (stores session key in XDG_RUNTIME_DIR)."""
    config = load_config()
    storage = SecureStorage(Path(config["storage"]["data_dir"]))
    crypto = CryptoManager(iterations=config["security"]["kdf_iterations"])
    salt_path = storage.data_dir / "auth" / "master.salt"
    if not salt_path.exists():
        raise click.ClickException("Not configured. Run intruder-setup first.")
    crypto.set_master_salt(salt_path.read_bytes())
    pm = PasswordManager(
        storage,
        max_attempts=config["security"]["brute_force_max_attempts"],
        lockout_sec=config["security"]["brute_force_lockout_sec"],
    )
    if not pm.verify(password):
        raise click.ClickException("Invalid password")
    SessionManager(crypto).unlock(password)
    click.echo("Vault unlocked for this session.")


@cli.command()
def lock() -> None:
    """Remove runtime session key."""
    crypto = CryptoManager()
    SessionManager(crypto).lock()
    click.echo("Session locked.")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
