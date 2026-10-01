"""
routers/alerts.py — Alert ingestion endpoint.

POST /alerts/ingest
  Accepts a Wazuh-format alert JSON.
  Creates an incident in the database.
  Returns the incident ID and severity.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import logging

from database import get_db
from schemas.alert import AlertIngest, AlertIngestResponse
from services.ingestion import ingest_alert

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.post(
    "/ingest",
    response_model=AlertIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a Wazuh alert and create an incident",
)
def ingest_alert_endpoint(
    alert: AlertIngest,
    db: Session = Depends(get_db),
):
    """
    Receive a Wazuh alert and store it as a security incident.

    - Maps rule level to severity (LOW / MEDIUM / HIGH / CRITICAL)
    - Generates a unique incident ID
    - Persists the incident in PostgreSQL
    - Writes an audit log entry
    """
    try:
        incident = ingest_alert(alert, db)
        logger.info(
            "Ingested alert rule=%s → incident=%s severity=%s asset=%s",
            alert.rule_id,
            incident.incident_id,
            incident.severity,
            incident.affected_asset,
        )
        return AlertIngestResponse(
            incident_id    = incident.incident_id,
            status         = incident.status,
            severity       = incident.severity,
            affected_asset = incident.affected_asset,
        )
    except Exception as exc:
        logger.exception("Failed to ingest alert: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest alert: {exc}",
        )
