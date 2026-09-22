"""Security event model (parsed log lines, detections, telemetry)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(64), index=True, nullable=False, default="system")
    event_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    category: Mapped[str] = mapped_column(String(32), index=True, nullable=False, default="system")
    severity: Mapped[str] = mapped_column(String(16), index=True, nullable=False, default="INFO")
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    raw_event: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="NEW")
    threat_intel_hits: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<SecurityEvent {self.id} {self.event_type} [{self.severity}]>"
