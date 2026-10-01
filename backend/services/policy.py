"""
services/policy.py — Deterministic policy engine.

Evaluates AI-recommended actions against a fixed rule set BEFORE they are
executed or queued. This layer enforces organisational security policies that
cannot be overridden by the LLM regardless of its recommendation.

Design:
  - POLICIES is a plain Python list of rule dicts — no OPA, no external engine.
  - evaluate_action() is synchronous and has zero side effects.
  - Rules are checked in order; the FIRST matching rule wins.
  - If no rule matches, the action is ALLOWED with no policy attached.

Policy effects:
  - "allowed"          → action may proceed automatically
  - "require_approval" → action is queued; a human analyst must approve
  - "block"            → action is permanently rejected; will not execute

Usage:
    from services.policy import evaluate_action, derive_asset_criticality

    context = {
        "asset_criticality": "critical",
        "user_role":         "administrator",
        "forensic_complete": False,
    }
    result = evaluate_action("isolate_host", context)
    # → {"decision": "require_approval", "policy_id": "P001", "reason": "..."}
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ── Policy definitions ────────────────────────────────────────────────────────
# Each policy dict:
#   id          : unique identifier (for audit trail)
#   description : human-readable explanation
#   action      : exact action_type string to match (or "*" for any)
#   condition   : dict of context fields that must match for the rule to trigger
#                 empty dict {} means "match always regardless of context"
#   effect      : "require_approval" | "block" | "allowed"
#
# Matching logic for condition fields:
#   - If the condition key is present in context AND the values match → rule fires
#   - If the condition key is absent from context → the rule fires (conservative default)
#   - Special value True/False checked with equality

POLICIES: list[dict[str, Any]] = [
    {
        "id":          "P001",
        "description": "Isolating a critical asset requires human approval",
        "action":      "isolate_host",
        "condition":   {"asset_criticality": "critical"},
        "effect":      "require_approval",
    },
    {
        "id":          "P001b",
        "description": "Isolating any host requires human approval (default safe)",
        "action":      "isolate_host",
        "condition":   {},
        "effect":      "require_approval",
    },
    {
        "id":          "P002",
        "description": "Disabling an administrator account requires human approval",
        "action":      "disable_account",
        "condition":   {"user_role": "administrator"},
        "effect":      "require_approval",
    },
    {
        "id":          "P002b",
        "description": "Disabling any account requires human approval (default safe)",
        "action":      "disable_account",
        "condition":   {},
        "effect":      "require_approval",
    },
    {
        "id":          "P003",
        "description": "Server shutdown is never autonomous — always blocked",
        "action":      "shutdown_server",
        "condition":   {},
        "effect":      "block",
    },
    {
        "id":          "P004",
        "description": "Recovery cannot start before forensic collection is complete",
        "action":      "recover_system",
        "condition":   {"forensic_complete": False},
        "effect":      "block",
    },
    {
        "id":          "P005",
        "description": "Killing a process requires human approval",
        "action":      "kill_process",
        "condition":   {},
        "effect":      "require_approval",
    },
]

# ── Risk level table ──────────────────────────────────────────────────────────
# Maps action_type → default risk level (L0–L7).
# Phase 7 (Safety Engine) will use this; stored on the Action row now.
ACTION_RISK_LEVELS: dict[str, int] = {
    "notify_analyst":  0,
    "collect_logs":    4,
    "tag_ioc":         4,
    "block_ip":        4,
    "kill_process":    5,
    "isolate_host":    6,
    "disable_account": 6,
    "recover_system":  6,
    "shutdown_server": 7,
}

_DEFAULT_RISK_LEVEL = 3   # fallback for unknown action types


# ── Context derivation helpers ────────────────────────────────────────────────
def derive_asset_criticality(affected_asset: str) -> str:
    """
    Infer asset criticality from the asset name string.

    Convention:
      "critical" if name contains server, db, database, prod, critical, dc, dc01, dc02
      "medium"   otherwise
    """
    if not affected_asset:
        return "medium"

    name = affected_asset.lower()
    critical_keywords = ("server", "db", "database", "prod", "critical", "dc", "controller")
    if any(kw in name for kw in critical_keywords):
        return "critical"
    return "medium"


def derive_user_role(target: str) -> str:
    """
    Infer user role from the target account name.

    Convention:
      "administrator" if name matches common admin account patterns
      "user"          otherwise
    """
    if not target:
        return "user"

    name = target.lower()
    admin_names = ("admin", "root", "administrator", "superuser", "sysadmin", "sa", "wheel")
    if any(name == a or name.startswith(a) for a in admin_names):
        return "administrator"
    return "user"


# ── Core evaluation function ──────────────────────────────────────────────────
def evaluate_action(action_type: str, context: dict[str, Any]) -> dict[str, Any]:
    """
    Evaluate a proposed action against the POLICIES list.

    Args:
        action_type: The action string, e.g. "isolate_host", "disable_account".
        context:     Dict of situational facts used by policy conditions:
                       asset_criticality: "critical" | "high" | "medium" | "low"
                       user_role:         "administrator" | "user" | "service"
                       forensic_complete: True | False

    Returns:
        {
            "decision":   "allowed" | "require_approval" | "block",
            "policy_id":  str | None,   # None if no policy matched
            "reason":     str,
        }

    Evaluation order:
      1. Iterate POLICIES in order.
      2. Skip policies whose "action" doesn't match (exact string match).
      3. For matching policies, check the "condition" dict:
           - For each key in condition, check if context[key] == condition[key].
           - If context is missing the key → conservatively treat as matching.
      4. First matching policy wins → return its effect.
      5. If no policy matches → "allowed" with no policy ID.
    """
    for policy in POLICIES:
        # Step 1: action must match
        if policy["action"] != "*" and policy["action"] != action_type:
            continue

        # Step 2: check condition fields
        condition = policy.get("condition", {})
        condition_matches = True
        for cond_key, cond_value in condition.items():
            ctx_value = context.get(cond_key)
            if ctx_value is None:
                # Key absent from context — conservative: treat as matching
                # (when in doubt, apply the restriction)
                continue
            if ctx_value != cond_value:
                condition_matches = False
                break

        if not condition_matches:
            continue

        # Policy matched
        effect = policy["effect"]
        decision = "block" if effect == "block" else effect

        logger.info(
            "Policy %s matched for action=%s context=%s → %s",
            policy["id"], action_type, context, decision,
        )

        return {
            "decision":  decision,
            "policy_id": policy["id"],
            "reason":    policy["description"],
        }

    # No policy matched — allow by default
    logger.debug("No policy matched for action=%s → allowed", action_type)
    return {
        "decision":  "allowed",
        "policy_id": None,
        "reason":    "No applicable policy — action permitted.",
    }


def get_risk_level(action_type: str) -> int:
    """Return the default risk level (0–7) for the given action type."""
    return ACTION_RISK_LEVELS.get(action_type, _DEFAULT_RISK_LEVEL)
