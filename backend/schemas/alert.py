"""
schemas/alert.py — Pydantic models for alert ingestion.

AlertIngest mirrors the structure of a Wazuh alert JSON.
The backend accepts this shape on POST /alerts/ingest.

Wazuh alert reference fields:
  rule.id          — rule number (e.g. 5710 = SSH auth fail)
  rule.description — human-readable description
  rule.level       — severity 1-15
  agent.name       — hostname of the monitored agent
  agent.id         — agent ID string (e.g. "001")
  timestamp        — ISO 8601 string
  full_log         — raw syslog line
  data             — arbitrary key/value extra fields
"""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class AlertIngest(BaseModel):
    """Incoming alert payload — mirrors Wazuh alert format."""

    rule_id: str = Field(..., description="Wazuh rule ID, e.g. '5710'")
    rule_description: str = Field(..., description="Human-readable rule description")
    rule_level: int = Field(..., ge=1, le=15, description="Wazuh severity level 1-15")

    agent_name: str = Field(..., description="Hostname of the monitored agent")
    agent_id: str = Field(default="000", description="Wazuh agent ID")

    timestamp: Optional[datetime] = Field(
        default=None,
        description="Event timestamp (defaults to now if omitted)",
    )
    full_log: Optional[str] = Field(
        default=None,
        description="Raw syslog / log line that triggered the rule",
    )
    data: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Arbitrary extra fields from the Wazuh alert",
    )

    model_config = {"json_schema_extra": {
        "example": {
            "rule_id": "5710",
            "rule_description": "sshd: Attempt to login using a denied user",
            "rule_level": 10,
            "agent_name": "web-server-01",
            "agent_id": "001",
            "timestamp": "2026-09-18T07:00:00Z",
            "full_log": "Sep 18 07:00:00 web-server-01 sshd[1234]: Invalid user admin from 192.168.1.100",
            "data": {
                "srcip": "192.168.1.100",
                "srcuser": "admin",
                "protocol": "ssh",
            },
        }
    }}


class AlertIngestResponse(BaseModel):
    """Response returned after successfully ingesting an alert."""

    incident_id: str
    status: str
    severity: str
    affected_asset: str
    message: str = "Alert ingested and incident created"
