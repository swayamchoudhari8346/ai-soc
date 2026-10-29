"""
routers/health.py — Health check endpoint.

GET /health  →  database + Ollama reachability (honest; never faked as ok).
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from database import get_db
from services.ollama_client import check_ollama_health

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """
    Returns system health.

    - database: SELECT 1 against PostgreSQL
    - ollama: live probe of the configured Ollama host
    """
    try:
        db.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {e}"

    ollama = await check_ollama_health()

    overall = "ok" if db_status == "ok" else "degraded"

    return {
        "status": overall,
        "database": db_status,
        "ollama": ollama,
    }
