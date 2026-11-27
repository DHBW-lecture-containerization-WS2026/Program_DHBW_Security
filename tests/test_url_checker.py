import httpx
import pytest

GOOGLE_URL = (
            "https://safebrowsing.googleapis.com"
            "/v4/threatMatches:find?key=test-key"
        )


# TEST: URL ohne bekannte Bedrohung
def test_url_no_threat(monkeypatch, respx_mock, client):
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


# TEST: Google meldet eine Bedrohung

def test_url_threat_detected(monkeypatch, respx_mock, client):
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


# TEST: Google antwortet mit Fehler
def test_url_google_error(monkeypatch, respx_mock, client):
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


# TEST: Ungültige URL ablehnen
def test_invalid_url(client):
    response = client.post(
        "/api/analyze/url",
        json={"url": "kein-gueltiger-link"}
    )

    assert response.status_code == 422


# TEST: Fehlender API-Key
def test_missing_api_key(monkeypatch, client):
    monkeypatch.delenv(
        "GOOGLE_SAFE_BROWSING_API_KEY",
        raising=False
    )

    response = client.post(
        "/api/analyze/url",
        json={"url": "https://example.com"}
    )

    assert response.status_code == 503



# TEST: Bedrohungstypen werden mit lesbarer Bezeichnung zurückgegeben
def test_url_threat_types_labeled(monkeypatch, respx_mock, client):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")

    match = {
        "threatType": "MALWARE",
        "platformType": "ANY_PLATFORM",
        "threatEntryType": "URL",
        "threat": {"url": "https://example.com/"}
    }
    respx_mock.post(GOOGLE_URL).mock(
        return_value=httpx.Response(200, json={"matches": [match, match]})
    )

    response = client.post(
        "/api/analyze/url",
        json={"url": "https://example.com"}
    )

    assert response.status_code == 200
    assert response.json()["threat_types"] == [
        {"type": "MALWARE", "label": "Schadsoftware (Malware)"}
    ]


# TEST: Lokale Warnhinweise für verdächtige URLs
@pytest.mark.parametrize("url, expected", [
    ("http://example.com", "http statt https"),
    ("https://192.168.0.1/login", "IP-Adresse"),
    ("https://xn--pypal-4ve.com", "Punycode"),
    ("https://user@example.com", "'@'"),
    ("https://example.com:8081", "Port"),
    ("https://bit.ly/abc", "URL-Kürzer"),
    ("https://a.b.c.d.example.com", "Subdomains"),
])
def test_url_local_warnings(monkeypatch, respx_mock, client, url, expected):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")
    respx_mock.post(GOOGLE_URL).mock(
        return_value=httpx.Response(200, json={})
    )

    response = client.post("/api/analyze/url", json={"url": url})

    assert response.status_code == 200
    warnings = response.json()["warnings"]
    assert any(expected in warning for warning in warnings)


# TEST: Normale https-URL erzeugt keine Warnhinweise
def test_url_no_warnings_for_clean_url(monkeypatch, respx_mock, client):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")
    respx_mock.post(GOOGLE_URL).mock(
        return_value=httpx.Response(200, json={})
    )

    response = client.post(
        "/api/analyze/url",
        json={"url": "https://www.example.com/page"}
    )

    assert response.json()["warnings"] == []
