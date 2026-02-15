import json
from pathlib import Path
from typing import Optional

from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer

from scanner.reporting.exceptions import ReportFormatError, ReportIOError, ReportRenderError


def _sanitize_text_for_pdf(text: str) -> str:
    replacements = {
        "â€¢": "-",
        "â€“": "-",
        "â€”": "-",
        "â€œ": '"',
        "â€": '"',
        "â€˜": "'",
        "â€™": "'",
        "â€¦": "...",
    }
    clean = text
    for char, replacement in replacements.items():
        clean = clean.replace(char, replacement)
    return clean


def _escape_text(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _markdown_to_flowables(markdown_text: str, styles) -> list:
    flowables = []
    bullets: list[str] = []

    def flush_bullets() -> None:
        nonlocal bullets
        if not bullets:
            return
        flowables.append(
            ListFlowable(
                [
                    ListItem(Paragraph(_escape_text(_sanitize_text_for_pdf(item)), styles["SentinelBody"]))
                    for item in bullets
                ],
                start="bullet",
                leftIndent=16,
            )
        )
        flowables.append(Spacer(1, 4))
        bullets = []

    for raw_line in markdown_text.splitlines():
        line = _sanitize_text_for_pdf(raw_line.strip())
        if not line:
            flush_bullets()
            flowables.append(Spacer(1, 4))
            continue
        if line.startswith("```"):
            continue
        if line.startswith("- ") or line.startswith("* "):
            bullets.append(line[2:])
            continue
        if line.startswith("### "):
            flush_bullets()
            flowables.append(Paragraph(_escape_text(line[4:]), styles["SentinelH2"]))
            continue
        if line.startswith("## "):
            flush_bullets()
            flowables.append(Paragraph(_escape_text(line[3:]), styles["SentinelH2"]))
            continue
        if line.startswith("# "):
            flush_bullets()
            flowables.append(Paragraph(_escape_text(line[2:]), styles["SentinelH1"]))
            continue

        flush_bullets()
        flowables.append(Paragraph(_escape_text(line), styles["SentinelBody"]))

    flush_bullets()
    return flowables


def write_pdf_report(
    *,
    scan_id: str,
    findings_path: str,
    ai_summary_path: Optional[str],
    output_path: str,
    attack_path_path: Optional[str] = None,
    max_findings: int = 500,
) -> str:
    """
    Generate a human-readable PDF report.

    For very large scans, limits findings to keep PDF usable.
    """
    try:
        findings_file = Path(findings_path)
        if not findings_file.exists():
            raise ReportIOError("Findings file not found", path=str(findings_file))

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        styles = getSampleStyleSheet()
        styles.add(
            ParagraphStyle(
                name="SentinelH1",
                fontSize=16,
                leading=20,
                spaceAfter=10,
                spaceBefore=8,
                fontName="Helvetica-Bold",
            )
        )
        styles.add(
            ParagraphStyle(
                name="SentinelH2",
                fontSize=13,
                leading=16,
                spaceAfter=8,
                spaceBefore=6,
                fontName="Helvetica-Bold",
            )
        )
        styles.add(
            ParagraphStyle(
                name="SentinelBody",
                fontSize=10,
                leading=14,
                spaceAfter=4,
                alignment=TA_LEFT,
            )
        )

        doc = SimpleDocTemplate(
            str(out),
            pagesize=A4,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        flowables = [
            Paragraph(f"Sentinel Security Report - {scan_id}", styles["SentinelH1"]),
            Spacer(1, 6),
        ]

        if ai_summary_path:
            summary_file = Path(ai_summary_path)
            if not summary_file.exists():
                raise ReportIOError("AI summary file not found", path=str(summary_file))
            flowables.append(Paragraph("AI Summary", styles["SentinelH2"]))
            flowables.extend(_markdown_to_flowables(summary_file.read_text(encoding="utf-8"), styles))

        if attack_path_path:
            attack_file = Path(attack_path_path)
            if not attack_file.exists():
                raise ReportIOError("Attack path file not found", path=str(attack_file))
            flowables.append(Paragraph("Attack Path Analysis", styles["SentinelH2"]))
            flowables.extend(_markdown_to_flowables(attack_file.read_text(encoding="utf-8"), styles))

        flowables.append(Paragraph("Findings", styles["SentinelH2"]))

        finding_count = 0
        with findings_file.open("r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
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

                if finding_count >= max_findings:
                    flowables.append(Paragraph("... output truncated ...", styles["SentinelBody"]))
                    break

                severity = str(finding.get("severity", "INFO")).upper()
                title = str(finding.get("title", "Unnamed issue"))
                tool = str(finding.get("tool_source") or finding.get("tool") or "unknown")
                location = (
                    (finding.get("code_location") or {}).get("file_path")
                    or (finding.get("endpoint_location") or {}).get("url")
                    or "n/a"
                )
                desc = str(finding.get("description") or finding.get("details") or "").strip()
                snippet = _escape_text(_sanitize_text_for_pdf(desc[:400]))

                text = (
                    f"[{severity}] {_escape_text(title)}<br/>"
                    f"Tool: {_escape_text(tool)} | Location: {_escape_text(str(location))}<br/>"
                    f"{snippet if snippet else 'No details provided.'}"
                )
                flowables.append(Paragraph(text, styles["SentinelBody"]))
                finding_count += 1

        doc.build(flowables)
        return str(out)
    except (ReportIOError, ReportFormatError, ReportRenderError):
        raise
    except Exception as exc:
        raise ReportRenderError(str(exc), path=output_path) from exc
