import os
import json
from collections import deque
from typing import Dict, Any
from .utils import (
    run_subprocess, is_tool_installed, normalize_severity, 
    ensure_dir, get_logger, SCAN_EXCLUDE_DIRS
)
from config.settings import settings # Import settings to get API Key
from scanner.tools.registry import register_tool

log = get_logger("scanner.tools.sca")
REQUIRES_EXTERNAL_DEPENDENCIES = True

def _tail_text_file(path: str, max_lines: int = 40) -> str:
    """
    Read the last N lines from a text file safely.
    Uses replacement for undecodable bytes to avoid crashing diagnostics.
    """
    if not os.path.exists(path):
        return ""

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            last = deque(f, maxlen=max_lines)
        return "".join(last).strip()
    except Exception as exc:
        return f"<failed to read log tail: {exc}>"


def run_sca_scan(src_path: str, output_dir: str) -> Dict[str, Any]:
    """
    Runs OWASP Dependency-Check.
    """
    log.info(f"Starting Dependency-Check scan on: {src_path}")

    if not src_path or not os.path.isdir(src_path):
        return {
            "findings": [],
            "raw_report": ("SCA_DependencyCheck", "Skipped: invalid source path."),
        }
    
    if not is_tool_installed("dependency-check"):
        log.error("Tool 'dependency-check' not found in PATH")
        return {"findings": [], "raw_report": ("SCA_DependencyCheck", "Tool missing")}

    ensure_dir(output_dir)
    # This is the separate log file for the tool itself
    tool_log_file = os.path.join(output_dir, "dependency-check-update.log")
    json_report = os.path.join(output_dir, "dependency-check-report.json")
    
    cmd = [
        "dependency-check", "--scan", src_path,
        "--format", "JSON", "--out", output_dir,
        "--log", tool_log_file
    ]

    if settings.NVD_API_KEY:
        cmd.extend(["--nvdApiKey", settings.NVD_API_KEY])
    
    for exclude in SCAN_EXCLUDE_DIRS:
        cmd.extend(["--exclude", f"**/{exclude}/**"])

    # Run the subprocess
    success, output = run_subprocess(cmd, timeout=1800)
    
    # --- Error visibility (stable + bounded) ---
    if not success:
        log.error("Dependency-Check failed for path: %s", src_path)

        tail = _tail_text_file(tool_log_file, max_lines=40)
        if tail:
            log.error(
                "Dependency-Check log tail (%s):\n%s",
                tool_log_file,
                tail,
            )
        else:
            truncated = (output or "")[-1500:]
            if truncated:
                log.error("Dependency-Check subprocess output (tail):\n%s", truncated)
            else:
                log.error(
                    "Dependency-Check failed but produced no log/output. "
                    "Check tool installation and NVD connectivity."
                )

    findings = []
    if os.path.exists(json_report):
        try:
            with open(json_report, 'r') as f:
                report = json.load(f)
            
            vuln_count = 0
            for dep in report.get('dependencies', []):
                for vuln in dep.get('vulnerabilities', []):
                    vuln_count += 1
                    findings.append({
                        "tool": "SCA (Dependency-Check)",
                        "severity": normalize_severity(vuln.get('severity')),
                        "title": f"Vulnerable Lib: {dep.get('fileName')}",
                        "description": vuln.get('description'),
                        "details": f"CVE: {vuln.get('name')}",
                        "file_path": dep.get('filePath'),
                        "cve_id": vuln.get('name'),
                        "cwe_id": vuln.get('cwe')
                    })
            log.info(f"Analysis complete. Found {vuln_count} vulnerabilities.")
            
        except Exception as e:
            log.error(f"Failed to parse report: {e}")

    return {"findings": findings, "raw_report": ("SCA_DependencyCheck", output)}

register_tool("SCA", run_sca_scan)
