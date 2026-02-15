import json
from typing import Iterator, List, Dict

from scanner.ai.exceptions import AIInputValidationError


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
        raise AIInputValidationError(
            "max_items must be > 0",
            details={"max_items": max_items},
        )

    chunk: List[Dict] = []

    with open(input_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AIInputValidationError(
                    "Invalid JSON in findings JSONL",
                    details={"line_no": line_no, "input_path": input_path},
                ) from exc

            if not isinstance(record, dict):
                raise AIInputValidationError(
                    "Finding entry is not a JSON object",
                    details={"line_no": line_no, "input_path": input_path},
                )

            chunk.append(record)

            if len(chunk) >= max_items:
                yield chunk
                chunk = []

    if chunk:
        yield chunk
