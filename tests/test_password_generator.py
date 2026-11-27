import re
import pytest

# TEST: Generiert das Backend ein Passwort?
def test_password_generator(client):
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


# TEST: Ungültige Passwortlängen ablehnen
@pytest.mark.parametrize("length", [8, 65])
def test_invalid_password_length(length, client):
    response = client.post(
        "/api/generate/password",
        json={"length": length}
    )

    assert response.status_code == 422
