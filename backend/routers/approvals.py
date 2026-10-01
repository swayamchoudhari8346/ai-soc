"""
routers/approvals.py — Approval queue API endpoints.

GET  /approvals          — list all pending approvals (for the analyst dashboard)
GET  /approvals/{id}     — get a single approval with its associated action
POST /approvals/{id}/decide — analyst approves or rejects an action
"""

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from database import get_db
from models.models import Action, Approval, AuditLog

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/approvals",
    tags=["approvals"],
)


# ── Request / Response schemas ────────────────────────────────────────────────
class ApprovalDecision(BaseModel):
    """Request body for POST /approvals/{id}/decide."""
    decision: str          # "approved" | "rejected"
    approver: str          # analyst username or identifier
    reason:   str = ""     # optional explanation

    @field_validator("decision")
    @classmethod
    def decision_must_be_valid(cls, v: str) -> str:
        if v not in ("approved", "rejected"):
            raise ValueError("decision must be 'approved' or 'rejected'")
        return v


# ── Serialiser ────────────────────────────────────────────────────────────────
def _approval_to_dict(approval: Approval) -> dict[str, Any]:
    action = approval.action
    return {
        "id":          approval.id,
        "action_id":   approval.action_id,
        "decision":    approval.decision,
        "approver":    approval.approver,
        "reason":      approval.reason,
        "decided_at":  approval.decided_at.isoformat() if approval.decided_at else None,
        # Embedded action details for UI convenience
        "action": {
            "incident_id":     action.incident_id     if action else None,
            "action_type":     action.action_type      if action else None,
            "target":          action.target           if action else None,
            "risk_level":      action.risk_level       if action else None,
            "status":          action.status           if action else None,
            "policy_decision": action.policy_decision  if action else None,
            "policy_reason":   action.policy_reason    if action else None,
        } if action else None,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.get(
    "",
    summary="List all pending approvals",
    response_description="Approval queue — all actions awaiting analyst decision",
)
def list_approvals(
    status: str = "pending",
    db: Session = Depends(get_db),
) -> list[dict]:
    """
    Return approvals filtered by status.

    - `status=pending` (default) — actions waiting for a decision
    - `status=all`  — entire history
    - `status=approved` / `status=rejected` — decided items

    Each approval includes the embedded action details for display.
    """
    query = db.query(Approval).join(Action, Approval.action_id == Action.id)

    if status == "pending":
        query = query.filter(Approval.decision == None)  # noqa: E711
    elif status == "approved":
        query = query.filter(Approval.decision == "approved")
    elif status == "rejected":
        query = query.filter(Approval.decision == "rejected")
    # "all" → no filter

    approvals = query.order_by(Approval.id).all()
    return [_approval_to_dict(a) for a in approvals]


@router.get(
    "/{approval_id}",
    summary="Get a single approval",
)
def get_approval(
    approval_id: int,
    db: Session = Depends(get_db),
) -> dict:
    """Return a single approval by ID with its associated action."""
    approval = db.query(Approval).filter(Approval.id == approval_id).first()
    if approval is None:
        raise HTTPException(status_code=404, detail=f"Approval {approval_id} not found.")
    return _approval_to_dict(approval)


@router.post(
    "/{approval_id}/decide",
    summary="Approve or reject a queued action",
    response_description="Updated approval record",
)
def decide_approval(
    approval_id: int,
    body: ApprovalDecision,
    db: Session = Depends(get_db),
) -> dict:
    """
    Record an analyst's decision on a queued action.

    - **decision**: `"approved"` or `"rejected"`
    - **approver**: analyst username (e.g. `"analyst1"`)
    - **reason**: optional free-text explanation

    On approval → action status set to `"approved"` (execution happens in Phase 9).
    On rejection → action status set to `"rejected"`.

    **Errors:**
    - `404` — approval not found
    - `409` — already decided
    """
    approval = db.query(Approval).filter(Approval.id == approval_id).first()
    if approval is None:
        raise HTTPException(status_code=404, detail=f"Approval {approval_id} not found.")

    if approval.decision is not None:
        raise HTTPException(
            status_code=409,
            detail=f"Approval {approval_id} already decided: {approval.decision}",
        )

    # Record the decision
    approval.decision  = body.decision
    approval.approver  = body.approver
    approval.reason    = body.reason
    approval.decided_at = datetime.now(tz=timezone.utc)

    # Update the action status to match
    action = approval.action
    if action:
        action.status = body.decision   # "approved" or "rejected"

    # Audit log
    audit_entry = AuditLog(
        incident_id = action.incident_id if action else None,
        event_type  = f"approval.{body.decision}",
        actor       = body.approver,
        description = (
            f"Analyst '{body.approver}' {body.decision} action "
            f"'{action.action_type if action else '?'}' "
            f"on '{action.target if action else '?'}'. "
            f"Reason: {body.reason or 'none provided'}."
        ),
        metadata_   = {
            "approval_id":  approval_id,
            "action_id":    approval.action_id,
            "action_type":  action.action_type  if action else None,
            "target":       action.target        if action else None,
            "risk_level":   action.risk_level    if action else None,
            "decision":     body.decision,
            "approver":     body.approver,
        },
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(approval)

    logger.info(
        "Approval %d → %s by %s (action: %s on %s)",
        approval_id,
        body.decision,
        body.approver,
        action.action_type if action else "?",
        action.target if action else "?",
    )

    return _approval_to_dict(approval)
