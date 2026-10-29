"""
services/safety.py — Safety Engine (bounded autonomy layer).

Sits between the policy engine and actual execution. Takes the Action rows
that passed policy evaluation and decides:

  L0–L4  → auto-execute (safe, low-impact, reversible)
  L5–L6  → queue for human approval (create Approval record, status=pending)
  L7     → never execute autonomously (blocked at this layer even if policy allowed)

The safety engine is deliberately CONSERVATIVE. Its job is not to decide
WHETHER an action is appropriate (that's the policy engine's job) — it decides
HOW MUCH autonomy the system is allowed when executing.

Risk level table (from build guide):
  L0  notify_analyst          → automatic
  L1  (search_logs)           → automatic
  L2  (ioc_enrichment)        → automatic
  L3  (create/update records) → automatic
  L4  tag_ioc, collect_logs, block_ip → automatic
  L5  kill_process            → requires approval
  L6  isolate_host, disable_account, recover_system → requires approval
  L7  shutdown_server, delete_data → NEVER autonomous

Usage:
    from services.safety import process_actions

    results = await process_actions(incident_id, db)
    # Returns list of dicts describing what happened to each action.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from models.models import Action, Approval, AuditLog

logger = logging.getLogger(__name__)

# ── Risk level thresholds ─────────────────────────────────────────────────────
_AUTO_EXECUTE_MAX    = 4   # L0–L4 → automatic
_APPROVAL_REQUIRED_MIN = 5   # L5–L6 → queue for approval
_NEVER_AUTONOMOUS    = 7   # L7 → always blocked by safety engine


# ── Simulated execution handlers ─────────────────────────────────────────────
# Phase 9 will replace these with real implementations.
# For now they log the action and return a simulated result.

def _simulate_execute(action: Action) -> dict[str, Any]:
    """
    Simulate execution of a safe (L0–L4) action.
    Returns a result dict that gets stored in the audit log.
    """
    simulations: dict[str, str] = {
        "notify_analyst":  "Analyst notification sent via internal alert channel.",
        "collect_logs":    f"Log collection initiated on {action.target}. 847 log entries retrieved.",
        "tag_ioc":         f"IOC tag applied to {action.target} in threat intel database.",
        "block_ip":        f"IP {action.target} added to firewall block list (iptables DROP rule).",
        "search_logs":     f"Log search completed for {action.target}.",
    }
    result_msg = simulations.get(
        action.action_type,
        f"Action {action.action_type} executed on {action.target} (simulated).",
    )
    logger.info(
        "AUTO-EXECUTED L%d action: %s → %s → %s",
        action.risk_level,
        action.action_type,
        action.target,
        result_msg,
    )
    return {"executed": True, "result": result_msg, "simulated": True}


# ── Core function ─────────────────────────────────────────────────────────────
async def process_actions(
    incident_id: str,
    db: Session,
) -> list[dict[str, Any]]:
    """
    Process all pending Action rows for the given incident through the safety engine.

    For each action:
      - If blocked (policy_decision=block): skip — already handled by policy engine.
      - If risk_level == L7: double-block at safety layer, update status=blocked.
      - If risk_level L0–L4 AND policy_decision=allowed: auto-execute (simulated).
      - If risk_level L5–L6 OR policy_decision=require_approval: create Approval row.

    Args:
        incident_id: The incident_id to process actions for.
        db:          SQLAlchemy session.

    Returns:
        List of result dicts — one per action processed.
    """
    actions = (
        db.query(Action)
        .filter(
            Action.incident_id == incident_id,
            Action.status == "pending",          # only unprocessed actions
        )
        .all()
    )

    if not actions:
        logger.info("No pending actions for incident %s", incident_id)
        return []

    results = []

    for action in actions:
        result = _process_single_action(action, db)
        results.append(result)

    db.commit()

    # Write a summary audit log entry
    auto_count     = sum(1 for r in results if r["outcome"] == "auto_executed")
    queued_count   = sum(1 for r in results if r["outcome"] == "queued_for_approval")
    blocked_count  = sum(1 for r in results if r["outcome"] == "blocked_by_safety")

    audit_entry = AuditLog(
        incident_id = incident_id,
        event_type  = "safety.actions_processed",
        actor       = "system",
        description = (
            f"Safety engine processed {len(results)} actions for {incident_id}. "
            f"Auto-executed: {auto_count}. "
            f"Queued for approval: {queued_count}. "
            f"Blocked by safety: {blocked_count}."
        ),
        metadata_ = {
            "auto_executed":       auto_count,
            "queued_for_approval": queued_count,
            "blocked_by_safety":   blocked_count,
            "actions":             [
                {
                    "action_type": r["action_type"],
                    "risk_level":  r["risk_level"],
                    "outcome":     r["outcome"],
                }
                for r in results
            ],
        },
    )
    db.add(audit_entry)
    db.commit()

    logger.info(
        "Safety engine complete for %s: %d auto-executed, %d queued, %d blocked",
        incident_id, auto_count, queued_count, blocked_count,
    )
    return results


def _process_single_action(action: Action, db: Session) -> dict[str, Any]:
    """Process one Action row and return a result dict (does NOT commit)."""

    # ── Already policy-blocked — skip ─────────────────────────────────────────
    if action.policy_decision == "block":
        logger.debug(
            "Action %d (%s) already policy-blocked — skipping safety layer",
            action.id, action.action_type,
        )
        return {
            "action_id":   action.id,
            "action_type": action.action_type,
            "risk_level":  action.risk_level,
            "outcome":     "policy_blocked",
            "detail":      action.policy_reason,
        }

    # ── L7 — never autonomous, safety hard-stop ───────────────────────────────
    if action.risk_level >= _NEVER_AUTONOMOUS:
        action.status = "blocked"
        _write_action_audit(
            action, db,
            event_type  = "safety.action_blocked",
            description = (
                f"Safety engine blocked L{action.risk_level} action "
                f"'{action.action_type}' on '{action.target}'. "
                f"L7 actions are never autonomous."
            ),
        )
        logger.warning(
            "SAFETY BLOCK L%d action: %s on %s",
            action.risk_level, action.action_type, action.target,
        )
        return {
            "action_id":   action.id,
            "action_type": action.action_type,
            "risk_level":  action.risk_level,
            "outcome":     "blocked_by_safety",
            "detail":      f"L{action.risk_level} actions are never autonomous (safety engine hard stop).",
        }

    # ── L5–L6 OR require_approval — queue for human approval ─────────────────
    needs_approval = (
        action.risk_level >= _APPROVAL_REQUIRED_MIN
        or action.policy_decision == "require_approval"
    )

    if needs_approval:
        # Create an Approval row (decision=None until analyst acts)
        existing_approval = (
            db.query(Approval)
            .filter(Approval.action_id == action.id)
            .first()
        )
        if existing_approval is None:
            approval = Approval(
                action_id  = action.id,
                approver   = None,
                decision   = None,
                reason     = None,
                decided_at = None,
            )
            db.add(approval)

        action.status = "pending"   # stays pending until analyst approves/rejects
        _write_action_audit(
            action, db,
            event_type  = "safety.approval_required",
            description = (
                f"Action '{action.action_type}' on '{action.target}' "
                f"(L{action.risk_level}) queued for analyst approval. "
                f"Policy: {action.policy_decision}."
            ),
        )
        logger.info(
            "QUEUED FOR APPROVAL L%d action: %s on %s",
            action.risk_level, action.action_type, action.target,
        )
        return {
            "action_id":   action.id,
            "action_type": action.action_type,
            "risk_level":  action.risk_level,
            "outcome":     "queued_for_approval",
            "detail":      f"Approval required (L{action.risk_level}, policy={action.policy_decision}).",
        }

    # ── L0–L4, allowed — auto-execute (simulated) ─────────────────────────────
    # Defense in depth: never auto-execute when policy requires approval or
    # risk is above the auto-execute ceiling (should already be handled above).
    if (
        action.policy_decision == "require_approval"
        or (action.risk_level is not None and action.risk_level > _AUTO_EXECUTE_MAX)
    ):
        action.status = "pending"
        _write_action_audit(
            action, db,
            event_type  = "safety.approval_required",
            description = (
                f"Refused auto-execute for '{action.action_type}' on "
                f"'{action.target}' (L{action.risk_level}, "
                f"policy={action.policy_decision}); queued for approval."
            ),
        )
        existing_approval = (
            db.query(Approval)
            .filter(Approval.action_id == action.id)
            .first()
        )
        if existing_approval is None:
            db.add(Approval(
                action_id  = action.id,
                approver   = None,
                decision   = None,
                reason     = None,
                decided_at = None,
            ))
        return {
            "action_id":   action.id,
            "action_type": action.action_type,
            "risk_level":  action.risk_level,
            "outcome":     "queued_for_approval",
            "detail":      "Auto-execute refused; approval required.",
        }

    exec_result = _simulate_execute(action)
    action.status = "executed"

    _write_action_audit(
        action, db,
        event_type  = "safety.action_executed",
        description = (
            f"Auto-executed L{action.risk_level} action "
            f"'{action.action_type}' on '{action.target}' "
            f"(simulated). Result: {exec_result['result']}"
        ),
    )
    return {
        "action_id":   action.id,
        "action_type": action.action_type,
        "risk_level":  action.risk_level,
        "outcome":     "auto_executed",
        "detail":      exec_result["result"],
        "simulated":   True,
    }


def _write_action_audit(
    action: Action,
    db: Session,
    event_type: str,
    description: str,
) -> None:
    """Helper: write an AuditLog entry for a single action (does NOT commit)."""
    entry = AuditLog(
        incident_id = action.incident_id,
        event_type  = event_type,
        actor       = "system",
        description = description,
        metadata_   = {
            "action_id":       action.id,
            "action_type":     action.action_type,
            "target":          action.target,
            "risk_level":      action.risk_level,
            "policy_decision": action.policy_decision,
        },
    )
    db.add(entry)


# ── Phase 9: execute approved actions ────────────────────────────────────────

async def execute_approved_actions(
    incident_id: str,
    db: Session,
) -> list[dict[str, Any]]:
    """
    Execute all actions for the given incident that have status='approved'.

    Called after an analyst approves actions via POST /approvals/{id}/decide.
    Each approved action is simulated (same executor as auto-execute), status
    set to 'executed', and an AuditLog entry written.

    Args:
        incident_id: The incident_id to process.
        db:          SQLAlchemy session.

    Returns:
        List of result dicts — one per executed action.
    """
    approved_actions = (
        db.query(Action)
        .filter(
            Action.incident_id == incident_id,
            Action.status == "approved",
        )
        .all()
    )

    if not approved_actions:
        logger.info("No approved actions to execute for incident %s", incident_id)
        return []

    results = []

    for action in approved_actions:
        # Enforce policy + approval record before any (simulated) execution.
        if action.policy_decision == "block":
            action.status = "blocked"
            _write_action_audit(
                action, db,
                event_type  = "action.blocked",
                description = (
                    f"Refused execution of '{action.action_type}' on "
                    f"'{action.target}': policy decision is block."
                ),
            )
            results.append({
                "action_id":   action.id,
                "action_type": action.action_type,
                "target":      action.target,
                "risk_level":  action.risk_level,
                "outcome":     "refused_policy_block",
                "detail":      action.policy_reason or "Blocked by policy.",
            })
            continue

        approval = (
            db.query(Approval)
            .filter(
                Approval.action_id == action.id,
                Approval.decision == "approved",
            )
            .first()
        )
        if approval is None:
            logger.warning(
                "Action %d marked approved but has no approved Approval row — refusing",
                action.id,
            )
            _write_action_audit(
                action, db,
                event_type  = "action.execution_refused",
                description = (
                    f"Refused execution of '{action.action_type}' on "
                    f"'{action.target}': no matching approved Approval record."
                ),
            )
            results.append({
                "action_id":   action.id,
                "action_type": action.action_type,
                "target":      action.target,
                "risk_level":  action.risk_level,
                "outcome":     "refused_missing_approval",
                "detail":      "Action status=approved but no Approval(decision=approved) found.",
            })
            continue

        if action.risk_level is not None and action.risk_level >= _NEVER_AUTONOMOUS:
            action.status = "blocked"
            _write_action_audit(
                action, db,
                event_type  = "action.blocked",
                description = (
                    f"Refused execution of L{action.risk_level} action "
                    f"'{action.action_type}' — L7+ is never executable."
                ),
            )
            results.append({
                "action_id":   action.id,
                "action_type": action.action_type,
                "target":      action.target,
                "risk_level":  action.risk_level,
                "outcome":     "refused_l7",
                "detail":      "L7 actions are never executable.",
            })
            continue

        exec_result = _simulate_execute(action)
        action.status = "executed"

        _write_action_audit(
            action, db,
            event_type  = "action.executed",
            description = (
                f"Analyst-approved L{action.risk_level} action "
                f"'{action.action_type}' on '{action.target}' executed "
                f"(simulated). Result: {exec_result['result']}"
            ),
        )

        results.append({
            "action_id":   action.id,
            "action_type": action.action_type,
            "target":      action.target,
            "risk_level":  action.risk_level,
            "outcome":     "executed",
            "detail":      exec_result["result"],
            "simulated":   True,
        })

        logger.info(
            "EXECUTED approved L%d action: %s on %s (simulated)",
            action.risk_level, action.action_type, action.target,
        )

    db.commit()

    executed = [r for r in results if r["outcome"] == "executed"]
    refused  = [r for r in results if r["outcome"] != "executed"]

    # Summary audit entry — only claim execution for outcomes that actually ran
    audit_summary = AuditLog(
        incident_id = incident_id,
        event_type  = "remediation.complete" if executed else "remediation.refused",
        actor       = "system",
        description = (
            f"Controlled remediation for {incident_id}: "
            f"{len(executed)} executed (simulated), {len(refused)} refused."
        ),
        metadata_ = {
            "executed_count": len(executed),
            "refused_count":  len(refused),
            "actions": results,
        },
    )
    db.add(audit_summary)
    db.commit()

    logger.info(
        "Remediation for %s: %d executed, %d refused",
        incident_id, len(executed), len(refused),
    )
    return results
