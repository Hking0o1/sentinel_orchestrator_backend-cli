import json
from typing import Optional
from pathlib import Path

from scanner.reporting.exceptions import ReportIOError


def write_json_report(
    *,
    scan_id: str,
    findings_path: str,
    ai_summary_path: Optional[str],
    output_path: str,
) -> str:
    """
    Stream findings into a canonical JSON report.

    This function never loads all findings into memory.
    """

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    try:
        with out.open("w", encoding="utf-8") as f:
            f.write("{\n")
            f.write(f'  "scan_id": "{scan_id}",\n')
            f.write('  "findings": [\n')

            first = True
            with open(findings_path, "r", encoding="utf-8") as fin:
                for line in fin:
                    if not first:
                        f.write(",\n")
                    f.write("    " + line.strip())
                    first = False

            f.write("\n  ]")

            if ai_summary_path:
                f.write(",\n  \"ai_summary\": ")
                with open(ai_summary_path, "r", encoding="utf-8") as s:
                    summary_text = s.read()
                f.write(json.dumps(summary_text))

            f.write("\n}\n")

    except Exception as exc:
        raise ReportIOError(str(exc)) from exc

    return str(out)

