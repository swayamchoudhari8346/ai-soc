"""
services/ingestion.py — Alert ingestion business logic.

Responsibilities:
  1. Map Wazuh rule level (1-15) to severity (LOW/MEDIUM/HIGH/CRITICAL)
  2. Generate a unique incident_id
  3. Persist the Incident row
  4. Write an AuditLog entry for incident.created
  5. Return the created Incident
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from models.models import Incident, AuditLog
from schemas.alert import AlertIngest


# ── Severity mapping ──────────────────────────────────────────────────────────
def map_severity(rule_level: int) -> str:
    """
    Map a Wazuh rule level (1-15) to a severity string.

    Wazuh levels:
      0        — Ignored / no threat
      1–3      — Informational
      4–7      — Low
      8–11     — Medium
      12–14    — High
      15       — Critical (max)
    """
    if rule_level <= 7:
        return "LOW"
    elif rule_level <= 11:
        return "MEDIUM"
    elif rule_level <= 14:
        return "HIGH"
    else:
        return "CRITICAL"


def _generate_incident_id() -> str:
    """Generate a unique, human-readable incident ID."""
    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d%H%M%S")
    short_uuid = uuid.uuid4().hex[:8].upper()
    return f"INC-{ts}-{short_uuid}"


# ── Main ingestion function ───────────────────────────────────────────────────
def ingest_alert(alert: AlertIngest, db: Session) -> Incident:
    """
    Ingest a Wazuh alert, create an incident and audit log entry.

    Args:
        alert: Validated alert payload.
        db:    SQLAlchemy session.

    Returns:
        The newly created Incident ORM object.
    """
    severity    = map_severity(alert.rule_level)
    incident_id = _generate_incident_id()
    event_time  = alert.timestamp or datetime.now(tz=timezone.utc)

    # Build the raw_alert JSONB payload — store everything for later analysis
    raw_alert_payload = {
        "rule_id":          alert.rule_id,
        "rule_description": alert.rule_description,
        "rule_level":       alert.rule_level,
        "agent_name":       alert.agent_name,
        "agent_id":         alert.agent_id,
        "timestamp":        event_time.isoformat(),
        "full_log":         alert.full_log,
        "data":             alert.data or {},
    }

    # ── Create the Incident row ───────────────────────────────────────────────
    incident = Incident(
        incident_id    = incident_id,
        severity       = severity,
        status         = "open",
        classification = f"Rule {alert.rule_id}: {alert.rule_description}",
        affected_asset = alert.agent_name,
        raw_alert      = raw_alert_payload,
        ai_report      = None,         # filled in Phase 4
    )
    db.add(incident)
    db.flush()   # get the auto-generated id without committing yet

    # ── Create AuditLog entry ─────────────────────────────────────────────────
    audit_entry = AuditLog(
        incident_id = incident_id,
        event_type  = "incident.created",
        actor       = "system",
        description = (
            f"Incident {incident_id} created from Wazuh rule {alert.rule_id} "
            f"({alert.rule_description}). Severity: {severity}. "
            f"Affected asset: {alert.agent_name}."
        ),
        metadata_   = {
            "rule_id":    alert.rule_id,
            "rule_level": alert.rule_level,
            "agent_id":   alert.agent_id,
            "source":     "wazuh",
        },
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(incident)

    return incident
