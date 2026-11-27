import httpx
import pytest

# TEST: E-Mail ohne Zustimmung
def test_email_without_consent(client):
    response = client.post(
        "/api/analyze/email",
        json={
            "email": "test@example.com",
            "consent": False
        }
    )

    assert response.status_code == 400


# TEST: Ungültige E-Mail-Adresse
def test_invalid_email(client):
    response = client.post(
        "/api/analyze/email",
        json={
            "email": "keine-email",
            "consent": True
        }
    )

    assert response.status_code == 422


# TEST: E-Mail ohne bekannten Leak
def test_email_no_breach(respx_mock, client):
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
def test_email_breach_detected(respx_mock, client):
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
