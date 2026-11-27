"""Steuert einen Abruf: Quelle abfragen, speichern, Lauf protokollieren.

Wird vom Airflow-DAG aufgerufen, funktioniert aber auch direkt:
    python -m pipeline.runner            (alle Quellen)
    python -m pipeline.runner nvd hibp   (nur bestimmte Quellen)
"""

import logging
import os
import sys
from datetime import datetime, timedelta, timezone

import httpx

from pipeline import db
from pipeline.sources import SOURCES

log = logging.getLogger(__name__)

DEFAULT_RETENTION_DAYS = 30
USER_AGENT = "security-hub-pipeline (DHBW student project)"


def http_client() -> httpx.Client:
    return httpx.Client(
        timeout=60,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    )


def fetch_window(
    retention_days: int,
    now: datetime,
    incremental: bool,
    last_success: datetime | None,
) -> datetime:
    """Ab welchem Zeitpunkt Daten abgerufen werden.

    Normal: die letzten `retention_days` Tage.
    Inkrementell: ab dem letzten erfolgreichen Lauf (1 Tag Puffer),
    aber nie weiter zurück als das Aufbewahrungsfenster.
    """
    since = now - timedelta(days=retention_days)

    if incremental and last_success is not None:
        since = max(since, last_success - timedelta(days=1))

    return since


def prepare_database(db_url: str) -> None:
    with db.connect(db_url) as conn:
        db.ensure_schema(conn)
        for source in SOURCES.values():
            db.register_source(conn, source)


def ingest_source(
    name: str,
    db_url: str,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> int:
    source = SOURCES[name]
    now = datetime.now(timezone.utc)

    with db.connect(db_url) as conn:
        db.register_source(conn, source)
        since = fetch_window(
            retention_days, now, source.incremental,
            db.last_successful_run(conn, name),
        )
        run_id = db.start_run(conn, name)
        conn.commit()

        log.info("%s: rufe Daten ab seit %s", name, since.isoformat())

        try:
            with http_client() as client:
                raw = source.fetch(client, since, now)

            events = source.parse(raw, since)
            count = db.upsert_events(conn, events)
            db.finish_run(conn, run_id, "success", count)
            conn.commit()

        except Exception as error:
            conn.rollback()
            db.finish_run(conn, run_id, "failed", 0, str(error)[:500])
            conn.commit()
            raise

    log.info("%s: %d Einträge gespeichert", name, count)
    return count


def cleanup_old_events(
    db_url: str,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    with db.connect(db_url) as conn:
        deleted = db.delete_events_before(conn, cutoff)

    log.info("%d Einträge älter als %d Tage gelöscht", deleted, retention_days)
    return deleted


def main(argv: list[str]) -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    db_url = os.environ["SECURITY_HUB_DATABASE_URL"]
    retention = int(os.getenv("SECURITY_HUB_RETENTION_DAYS", DEFAULT_RETENTION_DAYS))

    prepare_database(db_url)
    for name in argv or list(SOURCES):
        ingest_source(name, db_url, retention)
    cleanup_old_events(db_url, retention)


if __name__ == "__main__":
    main(sys.argv[1:])
