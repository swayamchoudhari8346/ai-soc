"""
routers/actions.py — Actions API endpoints.

GET  /incidents/{incident_id}/actions         — list all actions for an incident
POST /incidents/{incident_id}/execute-actions — run pending actions through safety engine
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models.models import Action, Incident
from services.safety import process_actions, execute_approved_actions

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/incidents",
    tags=["actions"],
)


def _action_to_dict(action: Action) -> dict[str, Any]:
    """Serialise an Action ORM row to a plain dict."""
    return {
        "id":              action.id,
        "incident_id":     action.incident_id,
        "action_type":     action.action_type,
        "target":          action.target,
        "risk_level":      action.risk_level,
        "status":          action.status,
        "policy_decision": action.policy_decision,
        "policy_reason":   action.policy_reason,
        "created_at":      action.created_at.isoformat() if action.created_at else None,
    }


@router.get(
    "/{incident_id}/actions",
    summary="List all actions for an incident",
    response_description="List of proposed/evaluated actions with policy decisions",
)
def list_actions(
    incident_id: str,
    db: Session = Depends(get_db),
) -> list[dict]:
    """
    Return all Action rows associated with the given incident.

    Each action includes:
    - **action_type**: what the AI recommended (e.g. block_ip, disable_account)
    - **target**: the asset/account/IP the action targets
    - **risk_level**: L0–L7 integer
    - **status**: pending | blocked | approved | rejected | executed
    - **policy_decision**: allowed | require_approval | block
    - **policy_reason**: the human-readable policy rule that matched

    **Returns** empty list if the incident has no actions yet (not investigated).

    **Errors:**
    - `404` — incident not found
    """
    incident = (
        db.query(Incident)
        .filter(Incident.incident_id == incident_id)
        .first()
    )
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    actions = (
        db.query(Action)
        .filter(Action.incident_id == incident_id)
        .order_by(Action.created_at)
        .all()
    )

    return [_action_to_dict(a) for a in actions]


@router.post(
    "/{incident_id}/execute-actions",
    summary="Run pending actions through the safety engine",
    response_description="Per-action outcomes: auto_executed | queued_for_approval | blocked_by_safety | policy_blocked",
)
async def execute_actions(
    incident_id: str,
    db: Session = Depends(get_db),
) -> dict:
    """
    Pass all **pending** actions for this incident through the safety engine.

    Safety engine logic:
    - **L0–L4** + policy=allowed → auto-executed immediately (simulated in Phase 7, real in Phase 9)
    - **L5–L6** or policy=require_approval → queued in approvals table, analyst must decide
    - **L7** → hard-blocked regardless of policy
    - Already policy-blocked actions → skipped

    Call this endpoint after `POST /incidents/{id}/investigate` to process the
    recommended actions and populate the approval queue.

    **Errors:**
    - `404` — incident not found
    """
    incident = (
        db.query(Incident)
        .filter(Incident.incident_id == incident_id)
        .first()
    )
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    results = await process_actions(incident_id=incident_id, db=db)

    summary = {
        "auto_executed":       sum(1 for r in results if r["outcome"] == "auto_executed"),
        "queued_for_approval": sum(1 for r in results if r["outcome"] == "queued_for_approval"),
        "blocked_by_safety":   sum(1 for r in results if r["outcome"] == "blocked_by_safety"),
        "policy_blocked":      sum(1 for r in results if r["outcome"] == "policy_blocked"),
    }

    return {
        "incident_id": incident_id,
        "status":      "safety_processing_complete",
        "summary":     summary,
        "actions":     results,
    }


@router.post(
    "/{incident_id}/execute-approved",
    summary="Execute all analyst-approved actions for an incident",
    response_description="List of executed actions with outcomes",
)
async def execute_approved(
    incident_id: str,
    db: Session = Depends(get_db),
) -> dict:
    """
    Execute every Action row with `status='approved'` for this incident.

    Intended to be called after the analyst has approved one or more actions
    via `POST /approvals/{id}/decide`. Each approved action is simulated,
    status set to `'executed'`, and an AuditLog entry written.

    **Errors:**
    - `404` — incident not found
    """
    incident = (
        db.query(Incident)
        .filter(Incident.incident_id == incident_id)
        .first()
    )
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    results = await execute_approved_actions(incident_id=incident_id, db=db)

    return {
        "incident_id":    incident_id,
        "status":         "remediation_complete",
        "executed_count": len(results),
        "actions":        results,
    }
