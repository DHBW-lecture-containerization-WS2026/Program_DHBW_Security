from datetime import datetime, timezone

import httpx

from pipeline.models import SecurityEvent
from pipeline.sources.base import Source


class CisaKev(Source):
    name = "cisa_kev"
    label = "Aktiv ausgenutzte Lücken"
    description = (
        "Sicherheitslücken, die laut US-Behörde CISA nachweislich "
        "angegriffen werden."
    )
    homepage = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

    url = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    def fetch(self, client: httpx.Client, since: datetime, until: datetime):
        response = client.get(self.url)
        response.raise_for_status()
        return response.json()

    def parse(self, raw, since: datetime) -> list[SecurityEvent]:
        events = []

        for vuln in raw.get("vulnerabilities", []):
            added = datetime.strptime(vuln["dateAdded"], "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )

            if added.date() < since.date():
                continue

            ransomware = vuln.get("knownRansomwareCampaignUse") == "Known"
            cve_id = vuln["cveID"]
            name = vuln.get("vulnerabilityName") or ""

            events.append(SecurityEvent(
                source=self.name,
                external_id=cve_id,
                title=f"{cve_id}: {name}" if name else cve_id,
                event_date=added,
                # Alle KEV-Einträge werden aktiv ausgenutzt, Ransomware ist am kritischsten
                severity="critical" if ransomware else "high",
                description=vuln.get("shortDescription"),
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                data={
                    "vendor": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                    "due_date": vuln.get("dueDate"),
                    "ransomware": ransomware,
                    "cwes": vuln.get("cwes", []),
                },
            ))

        return events
