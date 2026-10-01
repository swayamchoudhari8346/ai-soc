"""
models.py — SQLAlchemy ORM models for the AI-SOC database.

Tables:
  - incidents    : security incidents detected by Wazuh
  - evidence     : log entries / artefacts linked to an incident
  - actions      : AI-proposed remediation actions
  - approvals    : analyst decisions on high-risk actions
  - audit_log    : immutable timeline of every event in the system
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Text,
    DateTime, ForeignKey, func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from database import Base


# ── Incidents ─────────────────────────────────────────────────────────────────
class Incident(Base):
    __tablename__ = "incidents"

    id              = Column(Integer, primary_key=True, index=True)
    incident_id     = Column(String(50), unique=True, nullable=False, index=True)
    created_at      = Column(DateTime, server_default=func.now(), nullable=False)
    severity        = Column(String(20))      # LOW | MEDIUM | HIGH | CRITICAL
    status          = Column(String(30))      # open | investigating | pending_approval | resolved
    classification  = Column(String(100))
    confidence      = Column(Float)
    affected_asset  = Column(String(100))
    raw_alert       = Column(JSONB)           # original Wazuh alert payload
    ai_report       = Column(JSONB)           # structured investigation report from LLM

    # relationships
    evidence        = relationship("Evidence", back_populates="incident", cascade="all, delete-orphan")
    actions         = relationship("Action",   back_populates="incident", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Incident {self.incident_id} severity={self.severity} status={self.status}>"


# ── Evidence ──────────────────────────────────────────────────────────────────
class Evidence(Base):
    __tablename__ = "evidence"

    id          = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(50), ForeignKey("incidents.incident_id"), nullable=False, index=True)
    source      = Column(String(50))          # wazuh | syslog | netflow | manual
    timestamp   = Column(DateTime)
    event_data  = Column(Text)                # raw log line or description
    relevance   = Column(String(20))          # high | medium | low

    # relationships
    incident    = relationship("Incident", back_populates="evidence")

    def __repr__(self):
        return f"<Evidence id={self.id} incident={self.incident_id} source={self.source}>"


# ── Actions ───────────────────────────────────────────────────────────────────
class Action(Base):
    __tablename__ = "actions"

    id              = Column(Integer, primary_key=True, index=True)
    incident_id     = Column(String(50), ForeignKey("incidents.incident_id"), nullable=False, index=True)
    action_type     = Column(String(100))     # isolate_host | disable_account | kill_process | etc.
    target          = Column(String(100))     # hostname, username, PID, etc.
    risk_level      = Column(Integer)         # 0–7 (L0 = automatic, L5+ = approval required, L7 = never)
    status          = Column(String(30))      # pending | approved | rejected | executed | blocked
    policy_decision = Column(String(20))      # allowed | blocked | require_approval
    policy_reason   = Column(Text)
    created_at      = Column(DateTime, server_default=func.now(), nullable=False)

    # relationships
    incident        = relationship("Incident", back_populates="actions")
    approval        = relationship("Approval", back_populates="action", uselist=False, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Action {self.action_type} target={self.target} risk=L{self.risk_level} status={self.status}>"


# ── Approvals ─────────────────────────────────────────────────────────────────
class Approval(Base):
    __tablename__ = "approvals"

    id          = Column(Integer, primary_key=True, index=True)
    action_id   = Column(Integer, ForeignKey("actions.id"), nullable=False, unique=True)
    approver    = Column(String(100))         # analyst username or "system"
    decision    = Column(String(20))          # approved | rejected
    reason      = Column(Text)
    decided_at  = Column(DateTime)

    # relationships
    action      = relationship("Action", back_populates="approval")

    def __repr__(self):
        return f"<Approval action={self.action_id} decision={self.decision} by={self.approver}>"


# ── Audit Log ─────────────────────────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_log"

    id          = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(50), index=True)   # not a FK — log survives incident deletion
    event_type  = Column(String(100), nullable=False)   # incident.created | action.blocked | approval.granted | etc.
    actor       = Column(String(100))          # system | analyst | ai_agent
    description = Column(Text)
    timestamp   = Column(DateTime, server_default=func.now(), nullable=False, index=True)
    metadata_   = Column("metadata", JSONB)    # arbitrary extra context

    def __repr__(self):
        return f"<AuditLog {self.event_type} incident={self.incident_id} actor={self.actor}>"
