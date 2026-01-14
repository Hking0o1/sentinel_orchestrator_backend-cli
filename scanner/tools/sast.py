import os
import json
from typing import Dict, Any, List
from .utils import (
    run_subprocess, 
    is_tool_installed, 
    normalize_severity, 
    ensure_dir, 
    get_logger,
    SCAN_EXCLUDE_DIRS,
    DEFAULT_CMD_TIMEOUT  
)

from scanner.tools.registry import register_tool
REQUIRES_EXTERNAL_DEPENDENCIES = True

COST_METADATA = {
    "tier": "MEDIUM",
    "units": 3,
}

log = get_logger("scanner.tools.sast")

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
    """
    Runs Semgrep (installed via pipx) to find security flaws.
    """
    log.info(f"Starting Semgrep scan on: {src_path}")
    
    # Determine semgrep executable path
    semgrep_exec = "semgrep"
    if not is_tool_installed("semgrep"):
        # Fallback for Docker/Codespaces pipx locations
        common_paths = [
            "/root/.local/bin/semgrep",
            "/home/vscode/.local/bin/semgrep", 
            "/home/ubuntu/.local/bin/semgrep"
        ]
        found_path = None
        for p in common_paths:
            if os.path.exists(p):
                found_path = p
                break
        
        if found_path:
            semgrep_exec = found_path
        else:
            log.error("Tool 'semgrep' not found. Ensure it is installed via pipx.")
            return {
                "findings": [], 
                "raw_report": ("SAST_Semgrep", "Semgrep missing")
            }

    ensure_dir(output_dir)
    json_report_path = os.path.join(output_dir, "semgrep_report.json")
    log_file = os.path.join(output_dir, "semgrep-scan.log")
    
    # Generate ignore file
    ignore_file = _create_ignore_file(output_dir)
    
    # Build Command
    cmd = [
        semgrep_exec, "scan",
        "--config", "auto",
        "--json",
        "--output", json_report_path,
        "--verbose",
        "--no-git-ignore", 
        src_path
    ]

    log.info(f"Scan running (Timeout: {DEFAULT_CMD_TIMEOUT}s). Logs: {log_file}")
    
    # --- FIX: Use DEFAULT_CMD_TIMEOUT (20 mins) instead of SHORT_CMD_TIMEOUT ---
    success, output = run_subprocess(cmd, timeout=DEFAULT_CMD_TIMEOUT)
    # ---------------------------------------------------------------------------
    
    # Save raw logs
    try:
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(output)
    except Exception as e:
        log.warning(f"Failed to write log file: {e}")
        
    findings = []
    
    if os.path.exists(json_report_path) and os.path.getsize(json_report_path) > 20:
        try:
            with open(json_report_path, 'r') as f:
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


register_tool("SAST", run_sast_scan)
