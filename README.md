# Security Hub

Security Hub ist eine Webanwendung, mit der Benutzer verschiedene Sicherheitsprüfungen an einem zentralen Ort durchführen können.

## Features

- **Email Leak Checker:** Überprüft, ob eine E-Mail-Adresse in bekannten Datenlecks vorkommt.
- **Password Checker:** Prüft die Passwortstärke und ob ein Passwort in bekannten Leaks gefunden wurde.
- **Password Generator:** Generiert sichere, zufällige Passwörter.
- **URL Safety Checker:** Überprüft URLs auf bekannte Phishing- und Malware-Bedrohungen.
- **Lagebild:** Dashboard mit neuen Datenlecks und Sicherheitslücken der letzten 30 Tage, täglich per Airflow gesammelt.

## Verwendete APIs

- **XposedOrNot:** Überprüfung von E-Mail-Datenlecks
- **Have I Been Pwned:** Überprüfung kompromittierter Passwörter, Liste aller Datenlecks (Lagebild)
- **Google Safe Browsing:** Erkennung gefährlicher URLs
- **CISA KEV:** Aktiv ausgenutzte Sicherheitslücken (Lagebild)
- **NIST NVD:** Neu veröffentlichte CVEs (Lagebild)

## Architektur

```
                 täglich                      liest
Öffentliche APIs ───────► Airflow-DAG ──► PostgreSQL ◄──── FastAPI-Backend ◄──── Browser
(HIBP, CISA, NVD)        security_feeds   (30 Tage)        + Frontend
```

| Ordner | Inhalt |
|---|---|
| `backend/` | FastAPI-App (Checker + `/api/feeds/*` für das Lagebild) |
| `frontend/` | Weboberfläche (eine HTML-Datei) |
| `pipeline/` | ETL-Code: Quellen abrufen, normalisieren, speichern. Unabhängig von Airflow |
| `airflow/` | Dockerfile und DAG `security_feeds` |
| `db/init/` | SQL, das beim ersten Start der Datenbank läuft |
| `tests/` | pytest-Tests |

## Lokal starten

```bash
cp .env.example .env      # optional, z. B. für den Google-API-Key
docker compose up --build
```

- Web-App: http://localhost:8000/app
- Airflow: http://localhost:8080 (DAG `security_feeds` läuft beim Start einmal automatisch)

Der erste Abruf dauert ein paar Minuten, weil NVD ohne API-Key nur langsam abgefragt werden darf.

Tests ausführen:

```bash
pip install -r requirements.txt
python -m pytest tests/
```

## Neue Datenquelle hinzufügen

1. Datei in `pipeline/sources/` anlegen und eine Klasse von `Source` ableiten (`fetch` holt die Rohdaten, `parse` wandelt sie in `SecurityEvent`s um).
2. Klasse in `pipeline/sources/__init__.py` in `SOURCES` eintragen.
3. Test in `tests/test_pipeline.py` ergänzen.

Airflow-Task, Datenbank und Dashboard übernehmen die neue Quelle automatisch.

## Team-Mitglieder
- Michael Kurz
- Bartolmay Can
- Schayan Goudarzi
- Maksym Mykhailych
- Tim Bornemann

## Projektziel

Ziel ist die Entwicklung einer benutzerfreundlichen Plattform, die verschiedene Security-Tools kombiniert und das Sicherheitsbewusstsein der Benutzer verbessert.

Das Projekt entsteht im Rahmen einer Hochschulprojektarbeit zum Thema Containerization.

https://xposedornot.com/api_doc

https://haveibeenpwned.com/API/v3?utm_source=#PwnedPasswords

https://developers.google.com/safe-browsing
