"""API-Endpunkte für die von Airflow gesammelten Security-Feeds."""

import os
from contextlib import contextmanager

import psycopg
from fastapi import APIRouter, HTTPException, Query
from psycopg.rows import dict_row

router = APIRouter(prefix="/api/feeds", tags=["feeds"])

SEVERITIES = ("critical", "high", "medium", "low", "unknown")
NO_DATA_MESSAGE = (
    "Noch keine Daten vorhanden. Der Airflow-DAG 'security_feeds' "
    "ist noch nicht gelaufen."
)


@contextmanager
def database():
    url = os.getenv("SECURITY_HUB_DATABASE_URL")

    if not url:
        raise HTTPException(
            status_code=503,
            detail="Datenbank ist nicht konfiguriert (SECURITY_HUB_DATABASE_URL fehlt).",
        )

    try:
        conn = psycopg.connect(url, row_factory=dict_row, connect_timeout=5)
    except psycopg.OperationalError:
        raise HTTPException(
            status_code=503,
            detail="Datenbank ist gerade nicht erreichbar.",
        )

    with conn:
        yield conn


def serialize_event(row: dict) -> dict:
    return {
        "source": row["source"],
        "id": row["external_id"],
        "title": row["title"],
        "description": row["description"],
        "severity": row["severity"],
        "date": row["event_date"].isoformat(),
        "url": row["url"],
        "data": row["data"],
    }


def source_summary(conn, source: dict, days: int, latest_limit: int) -> dict:
    name = source["name"]

    totals = conn.execute(
        """
        SELECT count(*) AS total,
               sum((data->>'affected_accounts')::bigint) AS affected_accounts
        FROM security_events
        WHERE source = %s AND event_date >= now() - make_interval(days => %s::int)
        """,
        (name, days),
    ).fetchone()

    severity_rows = conn.execute(
        """
        SELECT severity, count(*) AS count
        FROM security_events
        WHERE source = %s AND event_date >= now() - make_interval(days => %s::int)
        GROUP BY severity
        """,
        (name, days),
    ).fetchall()
    by_severity = {severity: 0 for severity in SEVERITIES}
    by_severity.update({row["severity"]: row["count"] for row in severity_rows})

    # Jeder Tag erscheint, auch ohne Einträge (dann mit 0)
    daily = conn.execute(
        """
        SELECT day::date AS date, count(e.external_id) AS count
        FROM generate_series(
            (now() AT TIME ZONE 'UTC')::date - (%s::int - 1),
            (now() AT TIME ZONE 'UTC')::date,
            interval '1 day'
        ) AS day
        LEFT JOIN security_events e
            ON e.source = %s
           AND (e.event_date AT TIME ZONE 'UTC')::date = day::date
        GROUP BY day
        ORDER BY day
        """,
        (days, name),
    ).fetchall()

    latest = conn.execute(
        """
        SELECT * FROM security_events
        WHERE source = %s
        ORDER BY event_date DESC,
                 array_position(ARRAY['critical','high','medium','low','unknown'], severity)
        LIMIT %s
        """,
        (name, latest_limit),
    ).fetchall()

    last_run = conn.execute(
        """
        SELECT started_at, finished_at, status, records, error
        FROM ingestion_runs
        WHERE source = %s
        ORDER BY started_at DESC
        LIMIT 1
        """,
        (name,),
    ).fetchone()

    return {
        "name": name,
        "label": source["label"],
        "description": source["description"],
        "homepage": source["homepage"],
        "total": totals["total"],
        "affected_accounts": totals["affected_accounts"],
        "by_severity": by_severity,
        "daily": [
            {"date": row["date"].isoformat(), "count": row["count"]}
            for row in daily
        ],
        "latest": [serialize_event(row) for row in latest],
        "last_run": (
            {
                "started_at": last_run["started_at"].isoformat(),
                "finished_at": (
                    last_run["finished_at"].isoformat()
                    if last_run["finished_at"] else None
                ),
                "status": last_run["status"],
                "records": last_run["records"],
            }
            if last_run else None
        ),
    }


@router.get("/summary")
def feeds_summary(
    days: int = Query(default=30, ge=1, le=30),
    latest: int = Query(default=5, ge=0, le=50),
):
    with database() as conn:
        try:
            sources = conn.execute(
                "SELECT * FROM sources ORDER BY name"
            ).fetchall()
        except psycopg.errors.UndefinedTable:
            return {"days": days, "sources": [], "message": NO_DATA_MESSAGE}

        return {
            "days": days,
            "sources": [
                source_summary(conn, source, days, latest)
                for source in sources
            ],
        }


@router.get("/events")
def feeds_events(
    source: str | None = None,
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low|unknown)$"),
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    with database() as conn:
        try:
            rows = conn.execute(
                """
                SELECT * FROM security_events
                WHERE (%(source)s::text IS NULL OR source = %(source)s)
                  AND (%(severity)s::text IS NULL OR severity = %(severity)s)
                ORDER BY event_date DESC
                LIMIT %(limit)s OFFSET %(offset)s
                """,
                {"source": source, "severity": severity, "limit": limit, "offset": offset},
            ).fetchall()
        except psycopg.errors.UndefinedTable:
            return {"events": [], "message": NO_DATA_MESSAGE}

        return {"events": [serialize_event(row) for row in rows]}
