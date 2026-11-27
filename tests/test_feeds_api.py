import psycopg


# TEST: Ohne Datenbank-Konfiguration kommt eine verständliche Fehlermeldung
def test_feeds_without_database_url(monkeypatch, client):
    monkeypatch.delenv("SECURITY_HUB_DATABASE_URL", raising=False)

    response = client.get("/api/feeds/summary")

    assert response.status_code == 503
    assert "SECURITY_HUB_DATABASE_URL" in response.json()["detail"]


# TEST: Datenbank nicht erreichbar
def test_feeds_database_unreachable(monkeypatch, client):
    monkeypatch.setenv("SECURITY_HUB_DATABASE_URL", "postgresql://x@localhost:1/x")

    def fail(*args, **kwargs):
        raise psycopg.OperationalError("connection refused")

    monkeypatch.setattr("backend.feeds.psycopg.connect", fail)

    response = client.get("/api/feeds/events")

    assert response.status_code == 503


# TEST: Ungültige Parameter werden abgelehnt
def test_feeds_invalid_parameters(client):
    assert client.get("/api/feeds/summary?days=90").status_code == 422
    assert client.get("/api/feeds/events?severity=egal").status_code == 422
