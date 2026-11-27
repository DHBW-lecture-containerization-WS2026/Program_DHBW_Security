# Build-Kontext ist das Projekt-Root:
#   docker build -f airflow/Dockerfile -t security-hub-airflow .
ARG AIRFLOW_VERSION=3.1.3
ARG PYTHON_VERSION=3.12

FROM apache/airflow:${AIRFLOW_VERSION}-python${PYTHON_VERSION}

ARG AIRFLOW_VERSION

# Airflow-Version mitgeben, damit pip sie nicht versehentlich ändert
COPY airflow/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir "apache-airflow==${AIRFLOW_VERSION}" -r /tmp/requirements.txt

# Pipeline-Code und DAGs
COPY --chown=airflow:root pipeline/ /opt/airflow/pipeline/
COPY --chown=airflow:root airflow/dags/ /opt/airflow/dags/

ENV PYTHONPATH=/opt/airflow
