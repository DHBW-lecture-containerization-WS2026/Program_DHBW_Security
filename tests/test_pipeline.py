from datetime import datetime, timedelta, timezone

import pytest

from pipeline.models import SecurityEvent
from pipeline.runner import fetch_window
from pipeline.sources import SOURCES
from pipeline.sources.cisa_kev import CisaKev
from pipeline.sources.hibp import HibpBreaches, severity_from_accounts, strip_html
from pipeline.sources.nvd import NvdCves, extract_cvss

SINCE = datetime(2026, 11, 1, tzinfo=timezone.utc)


# ---------- Have I Been Pwned ----------

def hibp_breach(name, added, pwn_count=1000, **extra):
    return {
        "Name": name,
        "Title": name,
        "Domain": f"{name.lower()}.com",
        "BreachDate": "2026-10-01",
        "AddedDate": added,
        "PwnCount": pwn_count,
        "Description": "Leak bei <a href=\"https://x\">Firma</a> &amp; Co.",
        "DataClasses": ["Email addresses", "Passwords"],
        "IsVerified": True,
        **extra,
    }


def test_hibp_parse_filters_old_and_fabricated():
    raw = [
        hibp_breach("New", "2026-11-20T10:00:00Z", 2_000_000),
        hibp_breach("Old", "2026-10-01T10:00:00Z"),
        hibp_breach("Fake", "2026-11-21T10:00:00Z", IsFabricated=True),
        hibp_breach("Spam", "2026-11-21T10:00:00Z", IsSpamList=True),
    ]

    events = HibpBreaches().parse(raw, SINCE)

    assert [e.external_id for e in events] == ["New"]
    event = events[0]
    assert event.severity == "high"
    assert event.data["affected_accounts"] == 2_000_000
    assert event.description == "Leak bei Firma & Co."
    assert event.event_date.tzinfo is not None


@pytest.mark.parametrize("count, expected", [
    (50, "low"),
    (100_000, "medium"),
    (1_000_000, "high"),
    (25_000_000, "critical"),
])
def test_hibp_severity_from_accounts(count, expected):
    assert severity_from_accounts(count) == expected


def test_strip_html_handles_empty():
    assert strip_html(None) is None
    assert strip_html("<b>fett</b>") == "fett"


# ---------- CISA KEV ----------

def test_cisa_kev_parse():
    raw = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "Acme",
                "product": "Router",
                "vulnerabilityName": "Acme Router RCE",
                "dateAdded": "2026-11-25",
                "shortDescription": "Remote code execution.",
                "dueDate": "2026-12-16",
                "knownRansomwareCampaignUse": "Known",
            },
            {
                "cveID": "CVE-2026-0002",
                "vulnerabilityName": "Acme Old",
                "dateAdded": "2026-10-01",
                "knownRansomwareCampaignUse": "Unknown",
            },
        ]
    }

    events = CisaKev().parse(raw, SINCE)

    assert len(events) == 1
    assert events[0].title == "CVE-2026-0001: Acme Router RCE"
    assert events[0].severity == "critical"
    assert events[0].data["ransomware"] is True


# ---------- NVD ----------

def nvd_item(cve_id, published, metrics=None, status="Analyzed"):
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "vulnStatus": status,
            "descriptions": [
                {"lang": "es", "value": "Descripción"},
                {"lang": "en", "value": "Description"},
            ],
            "metrics": metrics or {},
        }
    }


def test_nvd_parse_skips_rejected_and_reads_cvss():
    metrics = {
        "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM", "version": "3.1"}},
            {"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "version": "3.1"}},
        ]
    }
    raw = {
        "vulnerabilities": [
            nvd_item("CVE-2026-1", "2026-11-20T08:00:00.000", metrics),
            nvd_item("CVE-2026-2", "2026-11-20T08:00:00.000", status="Rejected"),
            nvd_item("CVE-2026-3", "2026-11-21T08:00:00.000"),
        ]
    }

    events = NvdCves().parse(raw, SINCE)

    assert [e.external_id for e in events] == ["CVE-2026-1", "CVE-2026-3"]
    assert events[0].severity == "critical"
    assert events[0].data["cvss_score"] == 9.8
    assert events[0].description == "Description"
    assert events[1].severity == "unknown"


def test_extract_cvss_prefers_newest_version():
    metrics = {
        "cvssMetricV2": [{"baseSeverity": "LOW", "cvssData": {"baseScore": 2.0, "version": "2.0"}}],
        "cvssMetricV40": [{"cvssData": {"baseScore": 8.7, "baseSeverity": "HIGH", "version": "4.0"}}],
    }

    assert extract_cvss(metrics) == (8.7, "high", "4.0")
    assert extract_cvss({}) == (None, "unknown", None)


# ---------- Allgemein ----------

def test_all_sources_registered_with_metadata():
    assert len(SOURCES) >= 3
    for name, source in SOURCES.items():
        assert source.name == name
        assert source.label and source.description and source.homepage


def test_security_event_validates_input():
    with pytest.raises(ValueError):
        SecurityEvent("x", "1", "t", SINCE, severity="egal")
    with pytest.raises(ValueError):
        SecurityEvent("x", "1", "t", datetime(2026, 1, 1))


def test_fetch_window():
    now = datetime(2026, 11, 27, tzinfo=timezone.utc)

    # Erster Lauf: volle 30 Tage
    assert fetch_window(30, now, True, None) == now - timedelta(days=30)
    # Inkrementell: ab letztem Lauf minus 1 Tag Puffer
    assert fetch_window(30, now, True, now - timedelta(days=2)) == now - timedelta(days=3)
    # Nie weiter zurück als 30 Tage
    assert fetch_window(30, now, True, now - timedelta(days=90)) == now - timedelta(days=30)
    # Nicht inkrementell: immer 30 Tage
    assert fetch_window(30, now, False, now - timedelta(days=2)) == now - timedelta(days=30)
