"""Report generation endpoints (HTML preview + PDF download)."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.deps import CurrentUser, DbSession, require_capability
from app.models import Report, User
from app.schemas import ReportCreate, ReportOut
from app.services import report_generator
from app.services.audit import record

router = APIRouter(prefix="/api/reports", tags=["Reports"])


def _next_number(db: Session) -> str:
    last = db.query(Report).order_by(Report.id.desc()).first()
    return f"RPT-{(last.id + 1) if last else 1:04d}"


@router.get("", response_model=list[ReportOut])
def list_reports(db: DbSession, user: CurrentUser, limit: int = Query(default=50, le=200)) -> list[ReportOut]:
    reports = db.query(Report).order_by(Report.created_at.desc()).limit(limit).all()
    out = []
    for r in reports:
        creator = db.get(User, r.created_by_id) if r.created_by_id else None
        out.append(
            ReportOut(
                id=r.id,
                report_number=r.report_number,
                title=r.title,
                scope=r.scope,
                summary=r.summary,
                format=r.format,
                status=r.status,
                created_by_id=r.created_by_id,
                created_by_name=creator.username if creator else None,
                created_at=r.created_at,
            )
        )
    return out


@router.post("", response_model=ReportOut, status_code=201)
def create_report(
    db: DbSession,
    body: ReportCreate,
    user: CurrentUser,
    request: Request,
    _: None = require_capability("reports:write"),
) -> ReportOut:
    payload = report_generator.build_report_payload(
        db, user, body.title, body.scope, body.summary, body.host_ids or None
    )
    report = Report(
        report_number=_next_number(db),
        title=body.title,
        scope=body.scope,
        summary=body.summary,
        format="pdf",
        status="COMPLETED",
        content_html=_payload_to_html(payload),
        host_ids=",".join(str(i) for i in body.host_ids) if body.host_ids else None,
        created_by_id=user.id,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    record(db, "generated report", resource="report", user=user,
           ip_address=request.client.host if request.client else None,
           details=f"{report.report_number} '{report.title}'", commit=True)

    payload["report_number"] = report.report_number
    return ReportOut(
        id=report.id,
        report_number=report.report_number,
        title=report.title,
        scope=report.scope,
        summary=report.summary,
        format="pdf",
        status="COMPLETED",
        created_by_id=user.id,
        created_by_name=user.username,
        created_at=report.created_at,
    )


def _payload_to_html(payload: dict) -> str:
    parts = [f"<h1>{payload['title']}</h1>",
             f"<p class='muted'>Report ID {payload.get('report_number', 'RPT-XXXX')} · "
             f"Generated {payload['generated_at']} · Analyst {payload['analyst']} ({payload['analyst_role']})</p>"]
    for section in payload["sections"]:
        parts.append(f"<h2>{section['name']}</h2>")
        parts.append(section["html"])
    return "".join(parts)


@router.get("/{report_id}")
def get_report(db: DbSession, report_id: int, user: CurrentUser) -> dict:
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(404, detail="Report not found")
    return {
        "id": report.id,
        "report_number": report.report_number,
        "title": report.title,
        "scope": report.scope,
        "summary": report.summary,
        "created_at": report.created_at.isoformat(),
        "html": report.content_html,
    }


@router.get("/{report_id}/preview", response_class=HTMLResponse)
def preview_report(db: DbSession, report_id: int, user: CurrentUser) -> str:
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(404, detail="Report not found")
    css = """
    <style>
      body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 40px; color: #1b2430; }
      h1 { font-size: 24px; } h2 { font-size: 18px; border-bottom: 1px solid #ddd; margin-top: 24px; padding-bottom: 4px; }
      table { border-collapse: collapse; width: 100%; margin: 8px 0 16px; font-size: 13px; }
      th, td { border: 1px solid #cfd6e0; padding: 5px 8px; text-align: left; }
      th { background: #eef1f5; }
      .muted { color: #667; }
    </style>
    """
    return f"<html><head>{css}</head><body>{report.content_html or '<p>Empty report</p>'}</body></html>"


@router.get("/{report_id}/pdf")
def download_pdf(db: DbSession, report_id: int, user: CurrentUser) -> Response:
    """Regenerate the PDF from stored report data (no secrets included)."""
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(404, detail="Report not found")
    creator = db.get(User, report.created_by_id) if report.created_by_id else user
    payload = report_generator.build_report_payload(
        db, creator, report.title, report.scope, report.summary, None
    )
    payload["report_number"] = report.report_number
    pdf_bytes = report_generator.render_pdf(payload)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{report.report_number}.pdf"'
        },
    )
