"""Authorized host model."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    operating_system: Mapped[str | None] = mapped_column(String(255), nullable=True)
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="lab")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Host {self.hostname} ({self.ip_address}) [{self.status}]>"
