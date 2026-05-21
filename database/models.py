"""SQLite event log schema for searchable intrusion history."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Generator

from sqlalchemy import DateTime, Float, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session


class Base(DeclarativeBase):
    pass


class IncidentRecord(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    confidence: Mapped[float] = mapped_column(Float)
    image_count: Mapped[int] = mapped_column(default=0)
    storage_path: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    lockscreen_source: Mapped[str] = mapped_column(String(64), default="unknown")
    notified: Mapped[int] = mapped_column(default=0)


_engine = None
_SessionLocal = None


def init_db(db_path: Path) -> None:
    global _engine, _SessionLocal
    db_path.parent.mkdir(parents=True, exist_ok=True)
    _engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Base.metadata.create_all(_engine)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)


def get_session() -> Generator[Session, None, None]:
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized")
    session = _SessionLocal()
    try:
        yield session
    finally:
        session.close()
