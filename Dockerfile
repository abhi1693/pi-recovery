FROM docker.io/library/python:3.15-alpine@sha256:ff4d3c9b1a48f646eedd93182aaea385c7a5452f4c8a8cd7cef686babacf4928

ARG APP_VERSION=0.0.1
ARG REVISION=unknown
LABEL org.opencontainers.image.title="Pi Recovery" \
      org.opencontainers.image.description="Guarded Alertmanager-driven PoE recovery" \
      org.opencontainers.image.source="https://github.com/abhi1693/pi-recovery" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY --chmod=0444 controller.py policy.py /app/
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["python3", "-u", "/app/controller.py"]
