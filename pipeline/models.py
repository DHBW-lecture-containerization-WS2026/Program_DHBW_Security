from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Einheitliche Schweregrade für alle Quellen
SEVERITIES = ("critical", "high", "medium", "low", "unknown")


@dataclass(frozen=True)
class SecurityEvent:
    """Ein einzelner Eintrag aus einer Quelle (Datenleck, CVE, ...)."""

    source: str
    external_id: str
    title: str
    event_date: datetime
    severity: str = "unknown"
    description: str | None = None
    url: str | None = None
    # Quellenspezifische Zusatzfelder, landen als JSONB in der Datenbank
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"Unbekannter Schweregrad: {self.severity}")
        if self.event_date.tzinfo is None:
            raise ValueError("event_date braucht eine Zeitzone")
