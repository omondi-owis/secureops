"""System resource snapshots captured by the background monitor."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SystemSnapshot(Base):
    __tablename__ = "system_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False, default=utcnow
    )
    host: Mapped[str] = mapped_column(String(255), nullable=False, default="localhost")
    uptime_seconds: Mapped[float] = mapped_column(Float, nullable=True)
    cpu_percent: Mapped[float] = mapped_column(Float, nullable=True)
    mem_percent: Mapped[float] = mapped_column(Float, nullable=True)
    mem_used_mb: Mapped[float] = mapped_column(Float, nullable=True)
    disk_percent: Mapped[float] = mapped_column(Float, nullable=True)
    disk_used_gb: Mapped[float] = mapped_column(Float, nullable=True)
    load_1: Mapped[float] = mapped_column(Float, nullable=True)
    load_5: Mapped[float] = mapped_column(Float, nullable=True)
    load_15: Mapped[float] = mapped_column(Float, nullable=True)
    net_sent_kb: Mapped[float] = mapped_column(Float, nullable=True)
    net_recv_kb: Mapped[float] = mapped_column(Float, nullable=True)
    interfaces: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
