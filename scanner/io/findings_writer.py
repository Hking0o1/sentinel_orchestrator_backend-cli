import json
from typing import Iterable
from pathlib import Path

from scanner.types import Finding


def write_findings_jsonl(
    findings: Iterable[Finding],
    output_path: str,
) -> str:
    """
    Stream findings to disk as JSONL.

    - One finding per line
    - Constant memory usage
    - Safe for 100k+ findings
    """

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        for finding in findings:
            f.write(json.dumps(finding, ensure_ascii=False))
            f.write("\n")

    return str(path)
