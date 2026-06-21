import re

from django.core.exceptions import ValidationError

DOMAIN_PATTERN = re.compile(
    r"^(?:https?://)?(?:[^@/\n]+@)?(?:www\.)?"
    r"([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)$"
)
HOST_PATTERN = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)
PORTS_PATTERN = re.compile(r"^[\d,\-\s]*$")
STATUS_CODES_PATTERN = re.compile(r"^[\d,\s]*$")
TEMPLATE_IDS_PATTERN = re.compile(r"^[a-zA-Z0-9_\-,\s]*$")


def extract_domain(raw: str) -> str:
    raw = (raw or "").strip()
    match = DOMAIN_PATTERN.match(raw)
    if match:
        return match.group(1).lower()
    return raw.lower()


def validate_domain(raw: str) -> str:
    domain = extract_domain(raw)
    if not domain or not HOST_PATTERN.match(domain):
        raise ValidationError("Geçerli bir domain girin (ör. ornek.com).")
    return domain


def validate_ports(ports: str) -> str:
    ports = (ports or "").strip()
    if ports and not PORTS_PATTERN.match(ports):
        raise ValidationError("Port formatı geçersiz.")
    return ports.replace(" ", "")


def validate_status_codes(codes: str) -> str:
    codes = (codes or "").strip().replace(" ", "")
    if codes and not STATUS_CODES_PATTERN.match(codes):
        raise ValidationError("Durum kodu formatı geçersiz.")
    return codes


def validate_template_ids(templates: str) -> str:
    templates = (templates or "").strip()
    if templates and not TEMPLATE_IDS_PATTERN.match(templates):
        raise ValidationError("Şablon ID formatı geçersiz.")
    return templates
