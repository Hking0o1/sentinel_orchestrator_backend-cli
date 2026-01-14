from pathlib import Path
from typing import Optional

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from scanner.reporting.exceptions import ReportIOError


def write_pdf_report(
    *,
    scan_id: str,
    findings_path: str,
    ai_summary_path: Optional[str],
    output_path: str,
    max_findings: int = 500,
) -> str:
    """
    Generate a human-readable PDF report.

    For very large scans, limits findings to keep PDF usable.
    """

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    try:
        c = canvas.Canvas(str(out), pagesize=A4)
        width, height = A4
        y = height - 40

        def new_page():
            nonlocal y
            c.showPage()
            y = height - 40

        # Title
        c.setFont("Helvetica-Bold", 14)
        c.drawString(40, y, f"Sentinel Security Report — {scan_id}")
        y -= 30

        # AI summary (if exists)
        if ai_summary_path:
            c.setFont("Helvetica", 10)
            c.drawString(40, y, "AI Summary:")
            y -= 20

            with open(ai_summary_path, "r", encoding="utf-8") as f:
                for line in f:
                    if y < 40:
                        new_page()
                    c.drawString(40, y, line.strip())
                    y -= 14

            y -= 20

        # Findings (bounded)
        c.setFont("Helvetica", 9)
        c.drawString(40, y, "Findings:")
        y -= 20

        count = 0
        with open(findings_path, "r", encoding="utf-8") as f:
            for line in f:
                if count >= max_findings:
                    c.drawString(40, y, "... output truncated ...")
                    break

                if y < 40:
                    new_page()

                c.drawString(40, y, line.strip()[:120])
                y -= 12
                count += 1

        c.save()

    except Exception as exc:
        raise ReportIOError(str(exc)) from exc

    return str(out)
