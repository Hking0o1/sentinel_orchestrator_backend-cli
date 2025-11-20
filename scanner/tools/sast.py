import os
import json
from typing import Dict, Any
from .utils import (
    run_subprocess, is_tool_installed, normalize_severity, 
    ensure_dir, get_logger, SCAN_EXCLUDE_DIRS, SHORT_CMD_TIMEOUT
)

log = get_logger("scanner.sast")

def _create_ignore_file(output_dir: str):
    ignore_path = os.path.join(output_dir, ".semgrepignore")
    try:
        with open(ignore_path, "w") as f:
            for directory in SCAN_EXCLUDE_DIRS:
                f.write(f"{directory}/\n")
    except Exception as e:
        log.warning(f"Could not write ignore file: {e}")
    return ignore_path

def run_sast_scan(src_path: str, output_dir: str) -> Dict[str, Any]:
    log.info(f"Starting Semgrep scan on: {src_path}")
    
    if not is_tool_installed("semgrep"):
        log.error("Tool 'semgrep' not found")
        return {"findings": [], "raw_report": ("SAST_Semgrep", "Tool missing")}

    ensure_dir(output_dir)
    json_report = os.path.join(output_dir, "semgrep_report.json")
    ignore_file = _create_ignore_file(output_dir)
    
    cmd = [
        "semgrep", "scan", "--config", "auto",
        "--json", "--output", json_report,
        "--ignore-file", ignore_file,
        "--verbose", src_path
    ]
    
    success, output = run_subprocess(cmd, timeout=SHORT_CMD_TIMEOUT)
    
    findings = []
    if os.path.exists(json_report) and os.path.getsize(json_report) > 20:
        try:
            with open(json_report, 'r') as f:
                data = json.load(f)
            
            for res in data.get('results', []):
                extra = res.get('extra', {})
                findings.append({
                    "tool": "SAST (Semgrep)",
                    "severity": normalize_severity(extra.get('severity')),
                    "title": f"Code Flaw: {res.get('check_id')}",
                    "description": extra.get('message'),
                    "remediation": extra.get('metadata', {}).get('fix'),
                    "file_path": res.get('path'),
                    "line_start": res.get('start', {}).get('line'),
                    "code_snippet": extra.get('lines')
                })
            log.info(f"Analysis complete. Found {len(findings)} issues.")
            
        except Exception as e:
            log.error(f"Failed to parse report: {e}")

    return {"findings": findings, "raw_report": ("SAST_Semgrep", output)}