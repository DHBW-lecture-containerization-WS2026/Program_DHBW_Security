-- Läuft nur beim allerersten Start (leeres Datenbank-Volume).
-- Airflow bekommt eine eigene Datenbank für seine Metadaten,
-- die Security-Daten liegen in POSTGRES_DB (securityhub).
CREATE DATABASE airflow;
