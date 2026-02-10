import json
import logging
from pathlib import Path
from typing import Dict

from scanner.correlation.normalizers import Normalizer
from scanner.correlation.mapper import SourceMapper
from scanner.correlation.models import UnifiedFinding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------
# Public API (this is what DAG / Celery will call)
# ---------------------------------------------------------

def correlate_from_disk(
    *,
    input_paths: list[str],
    output_path: str,
) -> str:
    """
    Stateless, disk-first correlation function.

    - Deterministic
    - Retry-safe
    - No AI
    - No global state

    Args:
        input_paths: JSONL files from tool executions
        output_path: JSONL output for correlated findings

    Returns:
        Path to correlated findings file
    """

    normalized_input_paths = _normalize_paths(input_paths)
    correlated = _load_and_correlate(normalized_input_paths)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open("w", encoding="utf-8") as f:
        for finding in correlated.values():
            f.write(json.dumps(finding.model_dump(mode="json"), ensure_ascii=False))
            f.write("\n")

    return str(out)


# ---------------------------------------------------------
# Internal helpers (pure functions)
# ---------------------------------------------------------

def _load_and_correlate(input_paths: list[str]) -> Dict[str, UnifiedFinding]:
    findings: Dict[str, UnifiedFinding] = {}

    for path in input_paths:
        _consume_findings_file(path, findings)

    if not findings:
        return findings

    mapped = SourceMapper(list(findings.values())).correlate()
    return {f.id: f for f in mapped}


def _normalize_paths(raw_paths) -> list[str]:
    normalized: list[str] = []

    def _walk(value):
        if value is None:
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                _walk(item)
            return
        if isinstance(value, Path):
            normalized.append(str(value))
            return
        if isinstance(value, str):
            normalized.append(value)
            return

    _walk(raw_paths)
    return normalized


def _consume_findings_file(path: str, bucket: Dict[str, UnifiedFinding]) -> None:
    """Stream one JSONL file and normalize findings into a dedup bucket."""

    if not Path(path).exists():
        logger.warning("Correlation input file missing: %s", path)
        return

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            raw = json.loads(line)
            unified = Normalizer.normalize_finding(raw)

            # Deterministic dedup by fingerprint id.
            bucket.setdefault(unified.id, unified)
