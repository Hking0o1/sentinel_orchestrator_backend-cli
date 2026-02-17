from __future__ import annotations

import asyncio


async def resolve_txt_records(domain: str, timeout_seconds: float = 2.0) -> list[str]:
    try:
        import dns.resolver
    except Exception:
        return []

    def _lookup() -> list[str]:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = max(0.5, min(timeout_seconds, 2.0))
        resolver.lifetime = max(0.5, min(timeout_seconds, 2.0))
        answers = resolver.resolve(domain, "TXT")
        records: list[str] = []
        for answer in answers:
            if hasattr(answer, "strings"):
                joined = "".join(
                    s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s)
                    for s in answer.strings
                )
                records.append(joined)
            else:
                records.append(answer.to_text().strip('"'))
        return records

    try:
        return await asyncio.to_thread(_lookup)
    except Exception:
        return []


async def verify_dns_txt_token(domain: str, expected_record_value: str, timeout_seconds: float = 2.0) -> bool:
    records = await resolve_txt_records(domain=domain, timeout_seconds=timeout_seconds)
    normalized = {r.strip().strip('"') for r in records}
    return expected_record_value in normalized
