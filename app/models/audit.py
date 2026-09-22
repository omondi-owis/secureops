"""Immutable audit trail for SecureOps itself."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_timestamp", "timestamp"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    role: Mapped[str | None] = mapped_column(String(16), nullable=True)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    resource: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result: Mapped[str] = mapped_column(String(16), nullable=False, default="SUCCESS")
    details: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AuditLog {self.id} {self.username} {self.action}>"
