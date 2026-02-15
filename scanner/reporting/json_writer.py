import json
from typing import Optional
from pathlib import Path
from datetime import datetime, timezone

from scanner.reporting.exceptions import ReportFormatError, ReportIOError


def write_json_report(
    *,
    scan_id: str,
    findings_path: str,
    ai_summary_path: Optional[str],
    output_path: str,
    attack_path_path: Optional[str] = None,
) -> str:
    """
    Stream findings into a canonical JSON report.

    This function never loads all findings into memory.
    """

    try:
        findings_file = Path(findings_path)
        if not findings_file.exists():
            raise ReportIOError("Findings file not found", path=str(findings_file))

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        severity_counts: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        findings_count = 0

        with out.open("w", encoding="utf-8") as f:
            f.write("{\n")
            f.write(f'  "scan_id": "{scan_id}",\n')
            f.write(
                '  "generated_at_utc": '
                + json.dumps(datetime.now(timezone.utc).isoformat())
                + ",\n"
            )
            f.write('  "findings": [\n')

            first = True
            with open(findings_path, "r", encoding="utf-8") as fin:
                for line_no, line in enumerate(fin, start=1):
                    raw = line.strip()
                    if not raw:
                        continue
                    try:
                        finding = json.loads(raw)
                    except json.JSONDecodeError as exc:
                        raise ReportFormatError(
                            "Invalid JSON finding line",
                            path=findings_path,
                            line_no=line_no,
                        ) from exc
                    if not isinstance(finding, dict):
                        raise ReportFormatError(
                            "Finding entry must be a JSON object",
                            path=findings_path,
                            line_no=line_no,
                        )

                    if not first:
                        f.write(",\n")
                    f.write("    " + json.dumps(finding, ensure_ascii=False))
                    first = False

                    findings_count += 1
                    sev = str(finding.get("severity", "INFO")).upper()
                    if sev not in severity_counts:
                        sev = "INFO"
                    severity_counts[sev] += 1

            f.write("\n  ]")

            if ai_summary_path:
                if not Path(ai_summary_path).exists():
                    raise ReportIOError("AI summary file not found", path=ai_summary_path)
                f.write(",\n  \"ai_summary\": ")
                with open(ai_summary_path, "r", encoding="utf-8") as s:
                    summary_text = s.read()
                f.write(json.dumps(summary_text))

            if attack_path_path:
                if not Path(attack_path_path).exists():
                    raise ReportIOError("Attack path file not found", path=attack_path_path)
                f.write(",\n  \"attack_path_analysis\": ")
                with open(attack_path_path, "r", encoding="utf-8") as ap:
                    attack_text = ap.read()
                f.write(json.dumps(attack_text))

            f.write(",\n  \"summary\": {\n")
            f.write(f'    "total_findings": {findings_count},\n')
            f.write('    "severity_breakdown": ' + json.dumps(severity_counts))
            f.write("\n  }")
            f.write("\n}\n")

        return str(out)
    except (ReportIOError, ReportFormatError):
        raise
    except Exception as exc:
        raise ReportIOError(str(exc), path=output_path) from exc

