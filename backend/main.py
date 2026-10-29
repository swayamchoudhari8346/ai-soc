"""
main.py — AI-SOC FastAPI application entry point.

Startup sequence:
  1. Connect to PostgreSQL
  2. Create all tables (idempotent — safe to run every restart)
  3. Register routers
"""

from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import engine, Base
# Import all models so SQLAlchemy registers them with Base before create_all
import models  # noqa: F401

from routers import health, incidents, alerts, investigation, actions, approvals
from services.rag import init_knowledge_base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create database tables on startup, then initialise the RAG knowledge base."""
    logger.info("Creating database tables if they do not exist...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables ready.")

    logger.info("Initialising RAG knowledge base...")
    await init_knowledge_base()
    logger.info("RAG knowledge base ready.")

    yield
    logger.info("Shutting down.")


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="AI-SOC Backend",
    description="AI-Augmented Security Operations Center — backend API",
    version="0.1.0",
    lifespan=lifespan,
)

# ── CORS (Vite dev server on :5173; optional static serve on :3000) ────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(health.router)
app.include_router(incidents.router)
app.include_router(alerts.router)
app.include_router(investigation.router)
app.include_router(actions.router)
app.include_router(approvals.router)


@app.get("/")
def root():
    return {"message": "AI-SOC backend is running", "docs": "/docs"}
