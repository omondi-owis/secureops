"""Generated reports (PDF marker rows + rendered content)."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_number: Mapped[str] = mapped_column(String(16), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    format: Mapped[str] = mapped_column(String(8), nullable=False, default="pdf")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="COMPLETED")
    content_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    host_ids: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Report {self.report_number} {self.title}>"
