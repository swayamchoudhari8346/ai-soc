"""
routers/investigation.py — Investigation API endpoint.

POST /incidents/{incident_id}/investigate
  Triggers the AI investigation agent for a specific incident.
  Returns the structured investigation report (flat fields + metadata).
"""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from services.investigation import investigate_incident

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/incidents",
    tags=["investigation"],
)


@router.post(
    "/{incident_id}/investigate",
    summary="Run AI investigation on an incident",
    response_description="Structured AI investigation report",
)
async def trigger_investigation(
    incident_id: str,
    db: Session = Depends(get_db),
) -> dict:
    """
    Trigger an LLM-powered investigation for the given incident.

    - Loads the incident and its raw Wazuh alert from the database.
    - Calls the local Ollama model (llama3.1:8b) with a structured prompt.
    - Parses the response into a JSON report with classification, MITRE
      technique, severity, confidence, and recommended actions.
    - Saves the report to `incidents.ai_report` in PostgreSQL.
    - Writes an audit log entry for `incident.investigated`.

    **Returns** the investigation report fields at the top level (plus
    `incident_id` and `status`) so clients and e2e scripts can read
    `classification` / `mitre_technique` without unwrapping a nested object.

    **Errors:**
    - `404` — incident not found
    - `502` — LLM returned output that could not be parsed as a valid report
    - `503` — Ollama is unreachable or timed out
    """
    logger.info("Investigation requested for incident_id=%s", incident_id)
    report = await investigate_incident(incident_id=incident_id, db=db)
    return {
        **report,
        "incident_id": incident_id,
        "status": "investigation_complete",
    }
