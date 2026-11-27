"""Datenbank-Zugriff (PostgreSQL) für die Pipeline."""

from datetime import datetime

import psycopg
from psycopg.types.json import Jsonb

from pipeline.models import SecurityEvent
from pipeline.sources.base import Source

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    name        TEXT PRIMARY KEY,
    label       TEXT NOT NULL,
    description TEXT,
    homepage    TEXT
);

CREATE TABLE IF NOT EXISTS security_events (
    source      TEXT NOT NULL REFERENCES sources(name),
    external_id TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    severity    TEXT NOT NULL DEFAULT 'unknown',
    event_date  TIMESTAMPTZ NOT NULL,
    url         TEXT,
    data        JSONB NOT NULL DEFAULT '{}',
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (source, external_id)
);

CREATE INDEX IF NOT EXISTS security_events_date_idx
    ON security_events (event_date);

CREATE TABLE IF NOT EXISTS ingestion_runs (
    id          BIGSERIAL PRIMARY KEY,
    source      TEXT NOT NULL REFERENCES sources(name),
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    status      TEXT NOT NULL DEFAULT 'running',
    records     INTEGER NOT NULL DEFAULT 0,
    error       TEXT
);
"""


def connect(db_url: str) -> psycopg.Connection:
    return psycopg.connect(db_url)


def ensure_schema(conn: psycopg.Connection) -> None:
    conn.execute(SCHEMA)


def register_source(conn: psycopg.Connection, source: Source) -> None:
    conn.execute(
        """
        INSERT INTO sources (name, label, description, homepage)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (name) DO UPDATE SET
            label = EXCLUDED.label,
            description = EXCLUDED.description,
            homepage = EXCLUDED.homepage
        """,
        (source.name, source.label, source.description, source.homepage),
    )


def upsert_events(conn: psycopg.Connection, events: list[SecurityEvent]) -> int:
    if not events:
        return 0

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO security_events
                (source, external_id, title, description, severity,
                 event_date, url, data, fetched_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now())
            ON CONFLICT (source, external_id) DO UPDATE SET
                title = EXCLUDED.title,
                description = EXCLUDED.description,
                severity = EXCLUDED.severity,
                event_date = EXCLUDED.event_date,
                url = EXCLUDED.url,
                data = EXCLUDED.data,
                fetched_at = now()
            """,
            [
                (
                    e.source, e.external_id, e.title, e.description,
                    e.severity, e.event_date, e.url, Jsonb(e.data),
                )
                for e in events
            ],
        )

    return len(events)


def delete_events_before(conn: psycopg.Connection, cutoff: datetime) -> int:
    cur = conn.execute(
        "DELETE FROM security_events WHERE event_date < %s", (cutoff,)
    )
    conn.execute("DELETE FROM ingestion_runs WHERE started_at < %s", (cutoff,))
    return cur.rowcount


def last_successful_run(conn: psycopg.Connection, source: str) -> datetime | None:
    row = conn.execute(
        """
        SELECT max(started_at) FROM ingestion_runs
        WHERE source = %s AND status = 'success'
        """,
        (source,),
    ).fetchone()
    return row[0] if row else None


def start_run(conn: psycopg.Connection, source: str) -> int:
    row = conn.execute(
        "INSERT INTO ingestion_runs (source) VALUES (%s) RETURNING id",
        (source,),
    ).fetchone()
    return row[0]


def finish_run(
    conn: psycopg.Connection,
    run_id: int,
    status: str,
    records: int = 0,
    error: str | None = None,
) -> None:
    conn.execute(
        """
        UPDATE ingestion_runs
        SET finished_at = now(), status = %s, records = %s, error = %s
        WHERE id = %s
        """,
        (status, records, error, run_id),
    )
