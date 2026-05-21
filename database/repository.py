"""Incident CRUD and search operations."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select, delete
from sqlalchemy.orm import Session

from database.models import IncidentRecord


class IncidentRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(
        self,
        *,
        confidence: float,
        image_count: int,
        storage_path: str,
        metadata: Optional[dict[str, Any]] = None,
        lockscreen_source: str = "unknown",
    ) -> IncidentRecord:
        record = IncidentRecord(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            confidence=confidence,
            image_count=image_count,
            storage_path=storage_path,
            metadata_json=json.dumps(metadata or {}),
            lockscreen_source=lockscreen_source,
        )
        self._session.add(record)
        self._session.commit()
        self._session.refresh(record)
        return record

    def get(self, incident_id: str) -> Optional[IncidentRecord]:
        return self._session.get(IncidentRecord, incident_id)

    def list_all(
        self,
        *,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[IncidentRecord]:
        q = select(IncidentRecord).order_by(IncidentRecord.timestamp.desc())
        if start:
            q = q.where(IncidentRecord.timestamp >= start)
        if end:
            q = q.where(IncidentRecord.timestamp <= end)
        q = q.limit(limit)
        return list(self._session.scalars(q).all())

    def delete(self, incident_id: str) -> bool:
        record = self.get(incident_id)
        if not record:
            return False
        self._session.delete(record)
        self._session.commit()
        return True

    def mark_notified(self, incident_id: str) -> None:
        record = self.get(incident_id)
        if record:
            record.notified = 1
            self._session.commit()
