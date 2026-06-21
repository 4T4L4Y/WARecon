# syntax=docker/dockerfile:1

FROM python:3.12-slim-bookworm

ARG TARGETARCH

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/data \
    REDIS_HOST=redis \
    REDIS_PORT=6379 \
    DJANGO_USE_WHITENOISE=true \
    DJANGO_ALLOWED_HOSTS=* \
    PATH="/usr/local/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libpcap0.8 \
    ca-certificates \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY docker/install-pd-tools.sh /tmp/install-pd-tools.sh
RUN chmod +x /tmp/install-pd-tools.sh \
    && /tmp/install-pd-tools.sh /usr/local/bin \
    && rm /tmp/install-pd-tools.sh
RUN nuclei -update-templates -silent || true

COPY . .

RUN chmod +x /app/docker/entrypoint.sh \
    && mkdir -p /data/outputs /data/staticfiles

VOLUME ["/data"]

EXPOSE 8000

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["gunicorn", "warecon.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "120"]
