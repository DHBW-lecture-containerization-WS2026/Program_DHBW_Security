"""
### Security Feeds

Ruft täglich alle Quellen aus `pipeline.sources.SOURCES` ab, speichert sie in
PostgreSQL und löscht Einträge, die älter als das Aufbewahrungsfenster
(Standard: 30 Tage) sind.

Für jede Quelle entsteht automatisch ein eigener Task `ingest_<name>`.
Fällt eine Quelle aus, laufen die anderen trotzdem weiter.
"""

import os
from datetime import datetime, timedelta

try:  # Airflow 3
    from airflow.sdk import dag, task
except ImportError:  # Airflow 2
    from airflow.decorators import dag, task

from pipeline.runner import cleanup_old_events, ingest_source, prepare_database
from pipeline.sources import SOURCES

RETENTION_DAYS = int(os.getenv("SECURITY_HUB_RETENTION_DAYS", "30"))


def database_url() -> str:
    return os.environ["SECURITY_HUB_DATABASE_URL"]


@dag(
    dag_id="security_feeds",
    schedule="@daily",
    start_date=datetime(2026, 1, 1),
    catchup=False,
    max_active_runs=1,
    default_args={"retries": 2, "retry_delay": timedelta(minutes=5)},
    tags=["security-hub"],
    doc_md=__doc__,
)
def security_feeds():

    @task
    def prepare():
        prepare_database(database_url())

    @task
    def ingest(source_name: str) -> int:
        return ingest_source(source_name, database_url(), RETENTION_DAYS)

    # Läuft auch, wenn einzelne Quellen fehlgeschlagen sind
    @task(trigger_rule="all_done")
    def cleanup() -> int:
        return cleanup_old_events(database_url(), RETENTION_DAYS)

    prepared = prepare()
    cleaned = cleanup()

    for name in SOURCES:
        prepared >> ingest.override(task_id=f"ingest_{name}")(name) >> cleaned


security_feeds()
