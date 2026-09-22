"""pytest fixtures: create an isolated PostgreSQL test database per session.

Uses the same Postgres server as development but a dedicated `mlinziops_test`
database, created/dropped via the postgres superuser where possible.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("APP_ENV", "testing")

TEST_DB_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+psycopg://mlinziops:mlinziops@127.0.0.1:5432/mlinziops_test"
)

# Set config BEFORE importing app modules.
os.environ["DATABASE_URL"] = TEST_DB_URL

from app.config import settings  # noqa: E402
from app.database import Base  # noqa: E402
from app import models  # noqa: E402,F401


def _admin_engine():
    url = os.environ.get(
        "TEST_ADMIN_DATABASE_URL",
        "postgresql+psycopg://postgres:postgres@127.0.0.1:5432/postgres",
    )
    return create_engine(url, isolation_level="AUTOCOMMIT")


def _create_test_db() -> None:
    """Create the test role + database if they don't exist (idempotent)."""
    try:
        eng = _admin_engine()
        with eng.connect() as conn:
            conn.execute(
                text("DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='mlinziops') "
                     "THEN CREATE ROLE mlinziops LOGIN PASSWORD 'mlinziops'; END IF; END $$;")
            )
            existing = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname='mlinziops_test'")
            ).scalar()
            if not existing:
                conn.execute(text("CREATE DATABASE mlinziops_test OWNER mlinziops"))
    except Exception as exc:  # pragma: no cover - depends on server privileges
        import warnings

        warnings.warn(f"Could not auto-create test db (continuing): {exc}")


@pytest.fixture(scope="session")
def db_engine():
    _create_test_db()
    engine = create_engine(TEST_DB_URL)
    # Schema for tests comes from migrations via metadata? We use create_all in
    # tests only (the production migration path is Alembic, untouched here).
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture()
def db_session(db_engine):
    factory = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)
    session = factory()
    yield session
    session.rollback()
    session.close()


@pytest.fixture()
def clean_tables(db_session):
    """Truncate all tables between tests for isolation."""
    from sqlalchemy import text as _text

    yield db_session
    db_session.rollback()
    for table in reversed(Base.metadata.sorted_tables):
        db_session.execute(_text(f'TRUNCATE TABLE "{table.name}" RESTART IDENTITY CASCADE'))
    db_session.commit()
