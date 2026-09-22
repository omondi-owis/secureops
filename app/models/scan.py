"""Nmap scan and parsed service models."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    scan_type: Mapped[str] = mapped_column(String(16), nullable=False, default="quick")
    ports: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    initiated_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    services: Mapped[list["ScanService"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Scan {self.id} {self.target} [{self.status}]>"


class ScanService(Base):
    __tablename__ = "scan_services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    service: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="services")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ScanService {self.port}/{self.protocol} {self.service} ({self.state})>"
