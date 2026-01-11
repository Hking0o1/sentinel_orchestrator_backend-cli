import json
from typing import Iterator, List, Dict


def chunk_findings_jsonl(
    *,
    input_path: str,
    max_items: int,
) -> Iterator[List[Dict]]:
    """
    Stream and chunk findings from a JSONL file.

    Raises:
        ValueError if input is invalid.
    """

    if max_items <= 0:
        raise ValueError("max_items must be > 0")

    chunk: List[Dict] = []

    with open(input_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at line {line_no} in {input_path}"
                ) from exc

            if not isinstance(record, dict):
                raise ValueError(
                    f"Finding at line {line_no} is not an object"
                )

            chunk.append(record)

            if len(chunk) >= max_items:
                yield chunk
                chunk = []

    if chunk:
        yield chunk
