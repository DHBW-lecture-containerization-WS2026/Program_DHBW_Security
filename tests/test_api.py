
import re

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)

GOOGLE_URL = (
    "https://safebrowsing.googleapis.com"
    "/v4/threatMatches:find?key=test-key"
)

# TEST 1: Läuft unser Backend?
def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


# TEST 2: Generiert das Backend ein Passwort?
def test_password_generator():
    response = client.post(
        "/api/generate/password",
        json={"length": 20}
    )

    assert response.status_code == 200

    password = response.json()["password"]

    assert len(password) == 20
    assert re.search(r"[a-z]", password)
    assert re.search(r"[A-Z]", password)
    assert re.search(r"[0-9]", password)
    assert re.search(r"[!@#$%&*?\-_]", password)


# TEST 3: Ungültige Passwortlängen ablehnen
@pytest.mark.parametrize("length", [8, 65])
def test_invalid_password_length(length):
    response = client.post(
        "/api/generate/password",
        json={"length": length}
    )

    assert response.status_code == 422


# TEST 4: URL ohne bekannte Bedrohung
def test_url_no_threat(monkeypatch, respx_mock):
    monkeypatch.setenv(
        "GOOGLE_SAFE_BROWSING_API_KEY",
        "test-key"
    )

    google_mock = respx_mock.post(GOOGLE_URL).mock(
        return_value=httpx.Response(
            200,
            json={}
        )
    )

    response = client.post(
        "/api/analyze/url",
        json={"url": "https://example.com"}
    )

    assert response.status_code == 200
    assert response.json()["status"] == "no_known_threat"
    assert google_mock.called


# TEST 5: Google meldet eine Bedrohung

def test_url_threat_detected(monkeypatch, respx_mock):
    monkeypatch.setenv(
        "GOOGLE_SAFE_BROWSING_API_KEY",
        "test-key"
    )

    respx_mock.post(GOOGLE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "matches": [
                    {
                        "threatType": "SOCIAL_ENGINEERING",
                        "platformType": "ANY_PLATFORM",
                        "threatEntryType": "URL",
                        "threat": {
                            "url": "https://example.com/"
                        }
                    }
                ]
            }
        )
    )

    response = client.post(
        "/api/analyze/url",
        json={"url": "https://example.com"}
    )

    assert response.status_code == 200
    assert response.json()["status"] == "threat_detected"
    assert len(response.json()["threats"]) > 0


# TEST 6: Google antwortet mit Fehler
def test_url_google_error(monkeypatch, respx_mock):
    monkeypatch.setenv(
        "GOOGLE_SAFE_BROWSING_API_KEY",
        "test-key"
    )

    respx_mock.post(GOOGLE_URL).mock(
        return_value=httpx.Response(
            403,
            json={"error": "Forbidden"}
        )
    )

    response = client.post(
        "/api/analyze/url",
        json={"url": "https://example.com"}
    )

    assert response.status_code == 502


# TEST 7: Ungültige URL ablehnen
def test_invalid_url():
    response = client.post(
        "/api/analyze/url",
        json={"url": "kein-gueltiger-link"}
    )

    assert response.status_code == 422


# TEST 8: Fehlender API-Key
def test_missing_api_key(monkeypatch):
    monkeypatch.delenv(
        "GOOGLE_SAFE_BROWSING_API_KEY",
        raising=False
    )

    response = client.post(
        "/api/analyze/url",
        json={"url": "https://example.com"}
    )

    assert response.status_code == 503



# TEST 9: E-Mail ohne Zustimmung
def test_email_without_consent():
    response = client.post(
        "/api/analyze/email",
        json={
            "email": "test@example.com",
            "consent": False
        }
    )

    assert response.status_code == 400


# TEST 10: Ungültige E-Mail-Adresse
def test_invalid_email():
    response = client.post(
        "/api/analyze/email",
        json={
            "email": "keine-email",
            "consent": True
        }
    )

    assert response.status_code == 422


# TEST 11: E-Mail ohne bekannten Leak
def test_email_no_breach(respx_mock):
    respx_mock.get(
        url__regex=r"https://api\.xposedornot\.com/v1/check-email/.*"
    ).mock(
        return_value=httpx.Response(404)
    )

    response = client.post(
        "/api/analyze/email",
        json={
            "email": "test@example.com",
            "consent": True
        }
    )

    assert response.status_code == 200
    assert response.json()["status"] == "no_known_breach"
    assert response.json()["count"] == 0


# TEST 12: E-Mail mit bekannten Leaks
def test_email_breach_detected(respx_mock):
    respx_mock.get(
        url__regex=r"https://api\.xposedornot\.com/v1/check-email/.*"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "breaches": [
                    ["ExampleBreach", "DemoLeak"]
                ]
            }
        )
    )

    response = client.post(
        "/api/analyze/email",
        json={
            "email": "test@example.com",
            "consent": True
        }
    )

    assert response.status_code == 200
    assert response.json()["status"] == "breach_detected"
    assert response.json()["count"] == 2
    assert "ExampleBreach" in response.json()["breaches"]






