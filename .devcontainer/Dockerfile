FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm

# Das Basis-Image enthält eine Yarn-Paketquelle mit abgelaufenem GPG-Schlüssel.
# Dadurch scheitert "apt-get update" und damit die Installation der
# Devcontainer-Features. Yarn wird hier nicht gebraucht.
RUN rm -f /etc/apt/sources.list.d/yarn.list \
    && apt-get update \
    && rm -rf /var/lib/apt/lists/*
