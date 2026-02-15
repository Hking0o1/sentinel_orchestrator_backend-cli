import json
from pathlib import Path
from typing import Any

import requests

from scanner.ai.exceptions import AIAttackPathError, AIInputValidationError


LEAK_KEYWORDS = {
    "api key",
    "secret",
    "token",
    "credential",
    "password",
    "private key",
    "exposed",
    "leak",
}

CRAWLER_SURFACES = {
    "/admin",
    "/internal",
    "/debug",
    "/.git",
    "/backup",
    "/swagger",
    "/graphql",
    "/api",
}

DEPENDENCY_KEYWORDS = {
    "vulnerable lib",
    "dependency",
    "package-lock",
    "pom.xml",
    "requirements.txt",
    "npm",
    "pip",
    "maven",
}


def generate_attack_path_analysis(
    *,
    findings_path: str,
    output_path: str,
    target_url: str | None,
    ollama_base_url: str,
    ollama_model: str,
    timeout_sec: int,
) -> str:
    try:
        findings = _read_findings(findings_path)
    except Exception as exc:
        raise AIInputValidationError(
            "Failed to parse findings for attack path analysis",
            details={"findings_path": findings_path},
        ) from exc

    context = _build_context(findings, target_url)
    ai_text: str | None = None

    try:
        ai_text = _query_ollama(
            context=context,
            base_url=ollama_base_url,
            model=ollama_model,
            timeout_sec=timeout_sec,
        )
    except AIAttackPathError:
        ai_text = None

    if not ai_text:
        ai_text = _fallback_analysis(context)

    out = Path(output_path)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(ai_text, encoding="utf-8")
    except Exception as exc:
        raise AIAttackPathError(
            "Failed to persist attack path analysis",
            retryable=False,
        ) from exc

    return str(out)


def build_fallback_attack_path_text(*, findings_path: str, target_url: str | None) -> str:
    findings = _read_findings(findings_path)
    context = _build_context(findings, target_url)
    return _fallback_analysis(context)


def _read_findings(path: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    p = Path(path)
    if not p.exists():
        return findings

    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    findings.append(item)
            except Exception:
                continue
    return findings


def _build_context(findings: list[dict[str, Any]], target_url: str | None) -> dict[str, Any]:
    high_sev = [f for f in findings if str(f.get("severity", "")).upper() in {"CRITICAL", "HIGH"}]
    medium_sev = [f for f in findings if str(f.get("severity", "")).upper() == "MEDIUM"]

    text_blob = " ".join(
        f"{f.get('title','')} {f.get('description','')} {f.get('tool_source','')} {f.get('tool','')} {f.get('endpoint_location',{})}"
        for f in findings[:200]
    ).lower()

    leak_signals = sorted(k for k in LEAK_KEYWORDS if k in text_blob)
    crawler_signals = sorted(s for s in CRAWLER_SURFACES if s in text_blob or (target_url and s in target_url.lower()))
    dependency_signals = sorted(k for k in DEPENDENCY_KEYWORDS if k in text_blob)
    cve_ids = sorted(
        {
            str(f.get("cve_id")).strip()
            for f in findings
            if f.get("cve_id")
        }
    )

    return {
        "target_url": target_url,
        "total_findings": len(findings),
        "high_severity_count": len(high_sev),
        "medium_severity_count": len(medium_sev),
        "leak_signals": leak_signals,
        "crawler_surface_signals": crawler_signals,
        "dependency_signals": dependency_signals,
        "cve_ids": cve_ids,
        "top_findings": [
            {
                "severity": f.get("severity"),
                "title": f.get("title"),
                "description": (f.get("description") or "")[:300],
            }
            for f in (high_sev[:12] if high_sev else findings[:12])
        ],
    }


def _query_ollama(*, context: dict[str, Any], base_url: str, model: str, timeout_sec: int) -> str | None:
    prompt = (
        "You are a senior penetration tester. Analyze the context and produce:\n"
        "1) AI-Crawler Leak Risk Score (0-10)\n"
        "2) 2-3 plausible step-by-step attack paths\n"
        "3) likely data leak vectors tied to crawler discovery\n"
        "4) concrete mitigations.\n\n"
        f"Context:\n{json.dumps(context, indent=2)}"
    )

    payload = {"model": model, "prompt": prompt, "stream": False}

    try:
        resp = requests.post(
            f"{base_url.rstrip('/')}/api/generate",
            json=payload,
            timeout=timeout_sec,
        )
        resp.raise_for_status()
        data = resp.json()
        text = (data.get("response") or "").strip()
        return text or None
    except requests.Timeout as exc:
        raise AIAttackPathError(
            "Attack path request to Ollama timed out",
            provider="ollama",
            retryable=True,
        ) from exc
    except requests.HTTPError as exc:
        raise AIAttackPathError(
            f"Attack path provider returned HTTP error: {exc}",
            provider="ollama",
            retryable=True,
        ) from exc
    except requests.RequestException as exc:
        raise AIAttackPathError(
            f"Attack path provider request failed: {exc}",
            provider="ollama",
            retryable=True,
        ) from exc
    except Exception as exc:
        raise AIAttackPathError(
            f"Unexpected attack path provider error: {exc}",
            provider="ollama",
            retryable=True,
        ) from exc


def _fallback_analysis(context: dict[str, Any]) -> str:
    score = min(
        10,
        max(
            1,
            len(context.get("leak_signals", []))
            + len(context.get("crawler_surface_signals", []))
            + len(context.get("dependency_signals", []))
            + context.get("high_severity_count", 0),
        ),
    )
    has_dependency_risk = bool(context.get("dependency_signals") or context.get("cve_ids"))

    if has_dependency_risk:
        path_block = (
            "Suggested Attack Path:\n"
            "1. Identify vulnerable dependency versions in lock/manifest files.\n"
            "2. Trigger known exploit primitive tied to the vulnerable package.\n"
            "3. Cause service disruption or controlled code path abuse.\n"
            "4. Chain with exposed endpoints/secrets if available for impact escalation.\n\n"
            "Mitigations:\n"
            "- Upgrade vulnerable libraries to patched versions.\n"
            "- Enforce dependency pinning and automated security updates.\n"
            "- Add SCA policy gates in CI/CD for HIGH/CRITICAL CVEs.\n"
            "- Validate untrusted input and add runtime protections/rate limits.\n"
        )
    else:
        path_block = (
            "Suggested Attack Path:\n"
            "1. Crawl discoverable endpoints and metadata exposures.\n"
            "2. Correlate leaked tokens/secrets with high-risk endpoints.\n"
            "3. Use leaked context to escalate access and exfiltrate sensitive data.\n\n"
            "Mitigations:\n"
            "- Restrict crawler-exposed sensitive routes and debug assets.\n"
            "- Rotate and vault secrets; block secrets in responses/logs.\n"
            "- Add robots, authz checks, WAF rules, and anomaly monitoring.\n"
        )

    return (
        "AI Attack Path Analysis (Fallback)\n\n"
        f"AI-Crawler Leak Risk Score: {score}/10\n"
        f"Target: {context.get('target_url')}\n"
        f"Total Findings: {context.get('total_findings')}\n"
        f"High/Critical Findings: {context.get('high_severity_count')}\n\n"
        f"Medium Findings: {context.get('medium_severity_count')}\n\n"
        f"Leak Signals: {', '.join(context.get('leak_signals') or ['none'])}\n"
        f"Crawler Surface Signals: {', '.join(context.get('crawler_surface_signals') or ['none'])}\n\n"
        f"Dependency Signals: {', '.join(context.get('dependency_signals') or ['none'])}\n"
        f"CVEs: {', '.join(context.get('cve_ids') or ['none'])}\n\n"
        f"{path_block}"
    )
