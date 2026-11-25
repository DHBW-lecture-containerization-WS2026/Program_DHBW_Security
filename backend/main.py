
import os

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, HttpUrl
import secrets
import string
from pydantic import Field
from urllib.parse import quote
from pydantic import EmailStr

app = FastAPI(title="Security Hub")


# Datenmodell für die URL-Eingabe
class URLRequest(BaseModel):
    url: HttpUrl


# Startseite
@app.get("/")
def home():
    return {"message": "Security Hub is running!"}


# Prüfen, ob das Backend funktioniert
@app.get("/health")
def health():
    return {"status": "ok"}


# Unser erster Security-Checker

@app.post("/api/analyze/url")
async def analyze_url(request: URLRequest):
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="Google API-Key fehlt."
        )

    endpoint = (
        "https://safebrowsing.googleapis.com"
        "/v4/threatMatches:find"
    )

    payload = {
        "client": {
            "clientId": "securityhub",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": str(request.url)}
            ]
        }
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                endpoint,
                params={"key": api_key},
                json=payload
            )

            response.raise_for_status()
            data = response.json()

    except httpx.HTTPStatusError as error:
        raise HTTPException(
            status_code=502,
            detail=(
                "Google API antwortet mit HTTP "
                f"{error.response.status_code}"
            )
        )

    except (httpx.RequestError, ValueError):
        raise HTTPException(
            status_code=502,
            detail="Antwort der Google-API konnte nicht verarbeitet werden."
        )

    matches = data.get("matches", [])

    return {
        "url": str(request.url),
        "status": (
            "threat_detected"
            if matches
            else "no_known_threat"
        ),
        "threats": matches,
        "message": (
            "Bekannte Bedrohung gefunden."
            if matches
            else "Keine bekannte Bedrohung gefunden."
        )
    }


class PasswordGenerateRequest(BaseModel):
    length: int = Field(default=20, ge=12, le=64)


@app.post("/api/generate/password")
def generate_password(request: PasswordGenerateRequest):

    groups = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        "!@#$%&*?-_"
    ]

    alphabet = "".join(groups)

    characters = [
        secrets.choice(group)
        for group in groups
    ]

    for _ in range(request.length - len(characters)):
        characters.append(secrets.choice(alphabet))

    secrets.SystemRandom().shuffle(characters)

    return {
        "password": "".join(characters),
        "length": request.length
    }


# Frontend-Route
@app.get("/app", include_in_schema=False)
def frontend():
    return FileResponse("frontend/index.html")




class EmailRequest(BaseModel):
    email: EmailStr
    consent: bool = False


@app.post("/api/analyze/email")
async def analyze_email(request: EmailRequest):

    if not request.consent:
        raise HTTPException(
            status_code=400,
            detail="Zustimmung zur externen Prüfung erforderlich."
        )

    email = quote(str(request.email), safe="")

    api_url = (
        "https://api.xposedornot.com"
        f"/v1/check-email/{email}"
    )

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(api_url)

        # XposedOrNot: kein Eintrag gefunden
        if response.status_code == 404:
            return {
                "status": "no_known_breach",
                "count": 0,
                "breaches": []
            }

        if response.status_code == 429:
            raise HTTPException(
                status_code=429,
                detail="API-Limit erreicht. Bitte später erneut versuchen."
            )

        response.raise_for_status()
        data = response.json()

    except httpx.HTTPError:
        raise HTTPException(
            status_code=502,
            detail="E-Mail-Prüfung derzeit nicht verfügbar."
        )

    except ValueError:
        raise HTTPException(
            status_code=502,
            detail="Ungültige API-Antwort."
        )

    if data.get("Error") == "Not found":
        return {
            "status": "no_known_breach",
            "count": 0,
            "breaches": []
        }

    raw_breaches = data.get("breaches")

    if not isinstance(raw_breaches, list):
        raise HTTPException(
            status_code=502,
            detail="Unerwartetes API-Antwortformat."
        )

    # API liefert eine verschachtelte Liste
    breaches = [
        name
        for group in raw_breaches
        for name in (group if isinstance(group, list) else [group])
        if isinstance(name, str)
    ]

    return {
        "status": (
            "breach_detected"
            if breaches
            else "no_known_breach"
        ),
        "count": len(breaches),
        "breaches": breaches
    }
