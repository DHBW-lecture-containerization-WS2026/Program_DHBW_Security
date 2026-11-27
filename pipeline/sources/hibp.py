import html
import re
from datetime import datetime

import httpx

from pipeline.models import SecurityEvent
from pipeline.sources.base import Source

TAG_PATTERN = re.compile(r"<[^>]+>")


def strip_html(text: str | None) -> str | None:
    if not text:
        return None
    return html.unescape(TAG_PATTERN.sub("", text)).strip()


def severity_from_accounts(count: int) -> str:
    """Schweregrad anhand der Anzahl betroffener Konten."""
    if count >= 10_000_000:
        return "critical"
    if count >= 1_000_000:
        return "high"
    if count >= 100_000:
        return "medium"
    return "low"


class HibpBreaches(Source):
    name = "hibp"
    label = "Datenlecks"
    description = "Neu bekannt gewordene Datenlecks aus Have I Been Pwned."
    homepage = "https://haveibeenpwned.com/PwnedWebsites"

    url = "https://haveibeenpwned.com/api/v3/breaches"

    def fetch(self, client: httpx.Client, since: datetime, until: datetime):
        response = client.get(self.url)
        response.raise_for_status()
        return response.json()

    def parse(self, raw, since: datetime) -> list[SecurityEvent]:
        events = []

        for breach in raw:
            added = datetime.fromisoformat(
                breach["AddedDate"].replace("Z", "+00:00")
            )

            # Erfundene Lecks und reine Spam-Listen auslassen
            if added < since or breach.get("IsFabricated") or breach.get("IsSpamList"):
                continue

            accounts = int(breach.get("PwnCount") or 0)

            events.append(SecurityEvent(
                source=self.name,
                external_id=breach["Name"],
                title=breach.get("Title") or breach["Name"],
                event_date=added,
                severity=severity_from_accounts(accounts),
                description=strip_html(breach.get("Description")),
                url=f"{self.homepage}#{breach['Name']}",
                data={
                    "affected_accounts": accounts,
                    "domain": breach.get("Domain"),
                    "breach_date": breach.get("BreachDate"),
                    "data_classes": breach.get("DataClasses", []),
                    "is_verified": breach.get("IsVerified", False),
                },
            ))

        return events
