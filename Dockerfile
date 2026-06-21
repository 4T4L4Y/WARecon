# syntax=docker/dockerfile:1

FROM golang:1.23-bookworm AS tools
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*
ENV CGO_ENABLED=1
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

FROM python:3.12-slim-bookworm

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
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --from=tools /go/bin/naabu /go/bin/subfinder /go/bin/dnsx /go/bin/httpx /go/bin/katana /go/bin/nuclei /usr/local/bin/
RUN nuclei -update-templates -silent || true

COPY . .

RUN chmod +x /app/docker/entrypoint.sh \
    && mkdir -p /data/outputs /data/staticfiles

VOLUME ["/data"]

EXPOSE 8000

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["gunicorn", "warecon.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "120"]
