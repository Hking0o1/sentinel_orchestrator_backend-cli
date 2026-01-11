# scanner/correlation/disk_correlator.py

import json
from pathlib import Path
from typing import Dict, Iterable

from scanner.correlation.normalizers import normalize_finding
from scanner.correlation.mapper import SourceMapper
from scanner.correlation.models import UnifiedFinding


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

    correlated: Dict[str, UnifiedFinding] = {}

    for path in input_paths:
        _consume_findings_file(path, correlated)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open("w", encoding="utf-8") as f:
        for finding in correlated.values():
            f.write(json.dumps(finding.to_dict(), ensure_ascii=False))
            f.write("\n")

    return str(out)


# ---------------------------------------------------------
# Internal helpers (pure functions)
# ---------------------------------------------------------

def _consume_findings_file(
    path: str,
    bucket: Dict[str, UnifiedFinding],
) -> None:
    """
    Stream findings from one JSONL file and merge into bucket.
    """

    mapper = SourceMapper()

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            raw = json.loads(line)

            normalized = normalize_finding(raw)
            unified = UnifiedFinding.from_normalized(normalized)

            mapper.map_source(unified)

            key = unified.fingerprint()

            if key not in bucket:
                bucket[key] = unified
            else:
                bucket[key].merge(unified)
