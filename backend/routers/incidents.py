"""
routers/incidents.py — Incident management endpoints (stub for Phase 2).

Endpoints implemented here:
  GET  /incidents        — list all incidents
  GET  /incidents/{id}   — get a single incident

Full CRUD + investigation trigger added in Phase 3/4.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List

from database import get_db
from models import Incident
from models.models import AuditLog, Approval, Action

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("/")
def list_incidents(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """Return a paginated list of incidents, newest first."""
    incidents = (
        db.query(Incident)
        .order_by(Incident.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [
        {
            "id": inc.id,
            "incident_id": inc.incident_id,
            "created_at": inc.created_at,
            "severity": inc.severity,
            "status": inc.status,
            "classification": inc.classification,
            "affected_asset": inc.affected_asset,
        }
        for inc in incidents
    ]


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """
    Return summary statistics for the dashboard.

    Counts incidents grouped by status and by severity.
    Also returns the number of actions currently pending approval.
    """
    # Total and per-status counts
    status_rows = (
        db.query(Incident.status, func.count(Incident.id).label("count"))
        .group_by(Incident.status)
        .all()
    )
    by_status = {row.status: row.count for row in status_rows}

    total = sum(by_status.values())

    # Per-severity counts
    sev_rows = (
        db.query(Incident.severity, func.count(Incident.id).label("count"))
        .group_by(Incident.severity)
        .all()
    )
    by_severity = {row.severity: row.count for row in sev_rows}

    # Pending approvals count (actions in approval queue not yet decided)
    pending_approvals = (
        db.query(func.count(Approval.id))
        .filter(Approval.decision == None)  # noqa: E711
        .scalar()
    ) or 0

    return {
        "total":            total,
        "open":             by_status.get("open", 0),
        "investigating":    by_status.get("investigating", 0),
        "pending_approval": by_status.get("pending_approval", 0),
        "resolved":         by_status.get("resolved", 0),
        "pending_approvals_count": pending_approvals,
        "by_severity":      by_severity,
        "by_status":        by_status,
    }


@router.get("/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    """Return a single incident by its string incident_id."""
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return {
        "id": inc.id,
        "incident_id": inc.incident_id,
        "created_at": inc.created_at,
        "severity": inc.severity,
        "status": inc.status,
        "classification": inc.classification,
        "confidence": inc.confidence,
        "affected_asset": inc.affected_asset,
        "raw_alert": inc.raw_alert,
        "ai_report": inc.ai_report,
    }


@router.get("/{incident_id}/audit")
def get_audit_trail(incident_id: str, db: Session = Depends(get_db)):
    """
    Return the full audit trail for an incident, ordered chronologically.

    Each entry includes:
    - **event_type**: e.g. incident.created, incident.investigated,
      safety.actions_processed, safety.action_executed, safety.approval_required,
      approval.approved, action.executed, remediation.complete
    - **actor**: system | ai_agent | analyst
    - **description**: human-readable description
    - **timestamp**: ISO-8601 UTC
    - **metadata**: structured data about the event
    """
    # Verify incident exists
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    entries = (
        db.query(AuditLog)
        .filter(AuditLog.incident_id == incident_id)
        .order_by(AuditLog.timestamp.asc())
        .all()
    )

    return [
        {
            "id":          entry.id,
            "event_type":  entry.event_type,
            "actor":       entry.actor,
            "description": entry.description,
            "timestamp":   entry.timestamp.isoformat() if entry.timestamp else None,
            "metadata":    entry.metadata_,
        }
        for entry in entries
    ]
