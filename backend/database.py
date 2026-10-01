"""
database.py — SQLAlchemy engine, session factory, and Base.

All models import Base from here.
All route handlers use get_db() as a dependency.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from dotenv import load_dotenv

load_dotenv()

# ── Build the connection URL from environment variables ──────────────────────
POSTGRES_USER = os.getenv("POSTGRES_USER", "aisoc")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "aisoc_dev_password")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "postgres")   # Docker service name
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB = os.getenv("POSTGRES_DB", "aisoc")

DATABASE_URL = (
    f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
    f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
)

# ── Engine ───────────────────────────────────────────────────────────────────
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,       # reconnect if connection dropped
    pool_size=5,
    max_overflow=10,
)

# ── Session factory ──────────────────────────────────────────────────────────
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ── Declarative base (shared by all models) ──────────────────────────────────
class Base(DeclarativeBase):
    pass


# ── FastAPI dependency ───────────────────────────────────────────────────────
def get_db():
    """Yield a database session, close it when the request is done."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
