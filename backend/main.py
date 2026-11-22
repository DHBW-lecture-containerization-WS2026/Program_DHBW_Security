
import os

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl

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
