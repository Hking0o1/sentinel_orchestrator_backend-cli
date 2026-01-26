import subprocess
import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional

from scanner.tools.registry import register_tool

logger = logging.getLogger(__name__)

# -----------------------------
# CONFIG
# -----------------------------
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
ZAP_TIMEOUT_SECONDS = 20 * 60  # 20 minutes hard stop

# -----------------------------
# TOOL RUNNER
# -----------------------------
def run_zap_scan(
    *,
    target_url: str,
    output_dir: str,
    auth_cookie: Optional[str] = None,
) -> Dict[str, Any]:
    """
    OWASP ZAP baseline scan via Docker.

    Guarantees:
    - Hard timeout
    - Deterministic exit
    - Artifact persistence
    - Scheduler-safe execution
    """

    if not target_url:
        raise RuntimeError("run_zap_scan requires target_url")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    abs_output_dir = str(output_path.resolve())

    logger.info("Starting ZAP scan | target=%s | output=%s", target_url, abs_output_dir)

    cmd = [
        "docker", "run", "--rm",
        "--user", "0",
        "-v", f"{abs_output_dir}:/zap/wrk/:rw",
        ZAP_IMAGE,
        "zap-baseline.py",
        "-t", target_url,
        "-r", "zap_report.html",
        "-J", "zap_report.json",
    ]

    if auth_cookie:
        logger.info("ZAP running in authenticated mode")
        replacer = (
            "-config replacer.full_list(0).description=auth "
            "-config replacer.full_list(0).enabled=true "
            "-config replacer.full_list(0).matchtype=REQ_HEADER "
            "-config replacer.full_list(0).matchstr=Cookie "
            "-config replacer.full_list(0).regex=false "
            f"-config replacer.full_list(0).replacement={auth_cookie}"
        )
        cmd.extend(["-z", replacer])

    logger.info("Running ZAP command: %s", " ".join(cmd))

    start = time.time()

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            stdout, stderr = proc.communicate(timeout=ZAP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            logger.warning("ZAP exceeded timeout, terminating container")
            proc.kill()
            stdout, stderr = proc.communicate()

        duration = int(time.time() - start)

        logger.info("ZAP finished | exit_code=%s | duration=%ss", proc.returncode, duration)

        # Persist logs
        (output_path / "zap_stdout.log").write_text(stdout or "", encoding="utf-8")
        (output_path / "zap_stderr.log").write_text(stderr or "", encoding="utf-8")

        report_json = output_path / "zap_report.json"
        report_html = output_path / "zap_report.html"

        findings_count = 0
        if report_json.exists():
            try:
                import json
                findings = json.loads(report_json.read_text(encoding="utf-8"))
                findings_count = len(findings)
            except Exception:
                logger.warning("Failed to parse zap_report.json")

        return {
            "findings": findings_count,
            "raw_report": ("DAST_ZAP", str(report_json) if report_json.exists() else None),
        }
    except Exception as exc:
        logger.exception("ZAP execution failed")
        raise RuntimeError(f"ZAP scan failed: {exc}") from exc


# -----------------------------
# REGISTRATION
# -----------------------------
register_tool("DAST_ZAP", run_zap_scan)
