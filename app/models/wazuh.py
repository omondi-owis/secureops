"""Wazuh alert model (mirror of alerts fetched from the Wazuh API)."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class WazuhAlert(Base):
    __tablename__ = "wazuh_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    external_id: Mapped[str] = mapped_column(String(64), index=True, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String(16), index=True, nullable=True)
    agent_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(16), index=True, nullable=True)
    level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rule_description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    srcip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    dstip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<WazuhAlert {self.id} rule={self.rule_id} level={self.level}>"
