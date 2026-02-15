from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlparse


def normalize_target_value(target_type: str, raw_value: str) -> str:
    kind = str(target_type).strip().lower()
    value = str(raw_value).strip()
    if not value:
        return ""

    if kind == "url":
        return _normalize_url_like(value)
    if kind == "domain":
        return _normalize_domain(value)
    if kind == "ip":
        return _normalize_ip(value)
    if kind in {"git", "repo", "repository"}:
        return _normalize_git_repo(value)

    # Conservative default: lowercase + trim only.
    return value.lower().strip("/")


def generate_target_id(target_type: str, normalized_value: str) -> str:
    stable = f"{str(target_type).strip().lower()}:{normalized_value}"
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


def build_target_identity(target_type: str, raw_value: str) -> dict[str, str]:
    normalized_value = normalize_target_value(target_type, raw_value)
    return {
        "type": str(target_type).strip().lower(),
        "raw": str(raw_value),
        "normalized": normalized_value,
        "target_id": generate_target_id(target_type, normalized_value),
    }


def _normalize_url_like(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = (parsed.hostname or "").lower()
    port = parsed.port

    if not host:
        return value.lower().strip("/")

    is_default_port = (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)
    host_port = host if (port is None or is_default_port) else f"{host}:{port}"
    path = (parsed.path or "").rstrip("/")
    return f"{host_port}{path}" if path else host_port


def _normalize_domain(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = parsed.hostname or value
    return host.lower().strip().rstrip(".")


def _normalize_ip(value: str) -> str:
    cleaned = value.strip()
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", cleaned):
        octets = cleaned.split(".")
        if len(octets) == 4:
            cleaned = ".".join(str(int(o)) for o in octets)
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return cleaned


def _normalize_git_repo(value: str) -> str:
    cleaned = value.strip()
    # Handle SCP-like git syntax: git@github.com:org/repo.git
    if "@" in cleaned and ":" in cleaned and "://" not in cleaned:
        prefix, rest = cleaned.split("@", 1)
        if prefix in {"git", "ssh"} and ":" in rest:
            host, path = rest.split(":", 1)
            return f"{host.lower()}/{path.removesuffix('.git').strip('/')}"

    parsed = urlparse(cleaned if "://" in cleaned else f"https://{cleaned}")
    host = (parsed.hostname or "").lower()
    path = (parsed.path or cleaned).strip("/")
    path = path.removesuffix(".git")
    if host and path and not path.startswith(host):
        return f"{host}/{path}"
    if host:
        return host
    return cleaned.removesuffix(".git").lower().strip("/")
