"""Incident management models: incidents, timeline events, analyst notes."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# Many-to-many between incidents and the security events attached as evidence.
incident_events = Table(
    "incident_events",
    Base.metadata,
    Column("incident_id", Integer, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", Integer, ForeignKey("security_events.id", ondelete="CASCADE"), primary_key=True),
)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_number: Mapped[str] = mapped_column(String(16), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), index=True, nullable=False, default="MEDIUM")
    status: Mapped[str] = mapped_column(String(16), index=True, nullable=False, default="OPEN")
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    events: Mapped[list["SecurityEvent"]] = relationship(  # noqa: F821
        secondary=incident_events, lazy="selectin"
    )
    notes: Mapped[list["IncidentNote"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="selectin",
        order_by="IncidentNote.timestamp",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Incident {self.incident_number} {self.title} [{self.status}]>"


class IncidentNote(Base):
    """Analyst investigation note. Timestamps form the incident timeline."""

    __tablename__ = "incident_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    analyst: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False, default="NOTE")
    note: Mapped[str] = mapped_column(Text, nullable=False)

    incident: Mapped["Incident"] = relationship(back_populates="notes")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<IncidentNote {self.id} {self.action}>"
