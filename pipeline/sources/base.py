from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, ClassVar

import httpx

from pipeline.models import SecurityEvent


class Source(ABC):
    """Basisklasse für eine Datenquelle.

    Neue Quelle hinzufügen:
      1. Neue Datei in pipeline/sources/ mit einer Unterklasse anlegen
      2. In pipeline/sources/__init__.py in SOURCES eintragen
    DAG, Datenbank und Dashboard übernehmen die Quelle automatisch.
    """

    name: ClassVar[str]           # technischer Schlüssel, z. B. "hibp"
    label: ClassVar[str]          # Anzeigename im Dashboard
    description: ClassVar[str]    # ein Satz, was die Quelle liefert
    homepage: ClassVar[str]
    # True: nur neue Daten seit dem letzten erfolgreichen Lauf abrufen
    incremental: ClassVar[bool] = False

    @abstractmethod
    def fetch(self, client: httpx.Client, since: datetime, until: datetime) -> Any:
        """Rohdaten von der API holen (Netzwerkzugriff)."""

    @abstractmethod
    def parse(self, raw: Any, since: datetime) -> list[SecurityEvent]:
        """Rohdaten in SecurityEvents umwandeln (ohne Netzwerk, gut testbar)."""
