import os
import json
from typing import Dict, Any, List
from .utils import (
    run_subprocess, 
    is_tool_installed, 
    normalize_severity, 
    ensure_dir, 
    get_logger, # <-- Added import
    SCAN_EXCLUDE_DIRS,
    SHORT_CMD_TIMEOUT
)

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
    Runs Semgrep via Docker to find security flaws in the source code.
    """
    log.info(f"Starting Semgrep scan on: {src_path}")
    
    # We check for 'docker' instead of 'semgrep' now
    if not is_tool_installed("docker"):
        log.error("Tool 'docker' not found. Semgrep requires Docker.")
        return {
            "findings": [], 
            "raw_report": ("SAST_Semgrep", "Docker missing")
        }

    ensure_dir(output_dir)
    json_report_path = os.path.join(output_dir, "semgrep_report.json")
    log_file = os.path.join(output_dir, "semgrep-scan.log")
    
    # Generate ignore file (we'll mount this too)
    ignore_file = _create_ignore_file(output_dir)
    
    # Get absolute paths for mounting
    abs_src = os.path.abspath(src_path)
    abs_out_dir = os.path.abspath(output_dir)
    abs_ignore = os.path.abspath(ignore_file)

    # Build Docker command
    # We mount the source code to /src
    # We mount the output directory to /out
    # We mount the ignore file to /out/.semgrepignore
    cmd = [
        "docker", "run", "--rm",
        "--user", "0", # Run as root to avoid permission issues
        "-v", f"{abs_src}:/src:ro",
        "-v", f"{abs_out_dir}:/out:rw",
        "semgrep/semgrep", # Official image
        "semgrep", "scan",
        "--config", "auto",
        "--json",
        "--output", "/out/semgrep_report.json",
        "--exclude", ".git",
        "--exclude", "node_modules",
        "--verbose"
    ]
    
    # Add other excludes manually since .semgrepignore mount can be tricky
    for exclude in SCAN_EXCLUDE_DIRS:
         cmd.extend(["--exclude", exclude])

    log.info(f"Scan running. Logs: {log_file}")
    
    success, output = run_subprocess(cmd, timeout=SHORT_CMD_TIMEOUT)
    
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