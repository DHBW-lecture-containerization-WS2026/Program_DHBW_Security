import os
import time
from datetime import datetime, timezone

import httpx

from pipeline.models import SecurityEvent
from pipeline.sources.base import Source

# Reihenfolge = Priorität: neuere CVSS-Versionen zuerst
CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def extract_cvss(metrics: dict) -> tuple[float | None, str, str | None]:
    """Liefert (Score, Schweregrad, CVSS-Version) aus dem NVD-metrics-Objekt."""
    for key in CVSS_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue

        # Bevorzugt die Bewertung des NVD selbst ("Primary")
        entry = next(
            (item for item in entries if item.get("type") == "Primary"),
            entries[0],
        )
        cvss = entry.get("cvssData", {})
        severity = (cvss.get("baseSeverity") or entry.get("baseSeverity") or "").lower()

        if severity not in ("critical", "high", "medium", "low"):
            severity = "unknown"

        return cvss.get("baseScore"), severity, cvss.get("version")

    return None, "unknown", None


def parse_nvd_date(value: str) -> datetime:
    # NVD liefert Zeitstempel ohne Zeitzone, gemeint ist UTC
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)


class NvdCves(Source):
    name = "nvd"
    label = "Neue CVEs"
    description = (
        "Neu veröffentlichte Sicherheitslücken aus der "
        "NIST National Vulnerability Database."
    )
    homepage = "https://nvd.nist.gov/vuln/search"
    incremental = True

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    page_size = 2000

    def fetch(self, client: httpx.Client, since: datetime, until: datetime):
        api_key = os.getenv("NVD_API_KEY")
        headers = {"apiKey": api_key} if api_key else {}
        # Ohne Key erlaubt NVD nur 5 Anfragen pro 30 Sekunden
        pause = 0.7 if api_key else 6.5

        date_format = "%Y-%m-%dT%H:%M:%S.000Z"
        params = {
            "pubStartDate": since.astimezone(timezone.utc).strftime(date_format),
            "pubEndDate": until.astimezone(timezone.utc).strftime(date_format),
            "resultsPerPage": self.page_size,
            "startIndex": 0,
        }

        vulnerabilities = []

        while True:
            response = client.get(self.url, params=params, headers=headers)
            response.raise_for_status()
            page = response.json()

            vulnerabilities.extend(page.get("vulnerabilities", []))
            params["startIndex"] += page.get("resultsPerPage") or self.page_size

            if params["startIndex"] >= page.get("totalResults", 0):
                break

            time.sleep(pause)

        return {"vulnerabilities": vulnerabilities}

    def parse(self, raw, since: datetime) -> list[SecurityEvent]:
        events = []

        for item in raw.get("vulnerabilities", []):
            cve = item["cve"]

            # Zurückgezogene CVEs sind kein echtes Risiko
            if cve.get("vulnStatus") == "Rejected":
                continue

            published = parse_nvd_date(cve["published"])
            if published < since:
                continue

            score, severity, version = extract_cvss(cve.get("metrics", {}))
            description = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                None,
            )

            events.append(SecurityEvent(
                source=self.name,
                external_id=cve["id"],
                title=cve["id"],
                event_date=published,
                severity=severity,
                description=description,
                url=f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
                data={
                    "cvss_score": score,
                    "cvss_version": version,
                    "status": cve.get("vulnStatus"),
                },
            ))

        return events
