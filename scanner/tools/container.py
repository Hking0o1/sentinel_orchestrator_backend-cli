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
from scanner.tools.registry import register_tool

# --- Setup Logger ---
log = get_logger("scanner.tools.container")

def run_container_scan(src_path: str, output_dir: str) -> Dict[str, Any]:
    """
    Runs Trivy to find misconfigurations (IaC) and hardcoded secrets.
    """
    log.info(f"Starting Trivy scan on: {src_path}")
    
    if not is_tool_installed("trivy"):
        log.error("Tool 'trivy' not found in PATH.")
        return {
            "findings": [], 
            "raw_report": ("CONTAINER_Trivy", "Tool 'trivy' not found in PATH.")
        }

    ensure_dir(output_dir)
    output_file = os.path.join(output_dir, "trivy_report.json")
    log_file = os.path.join(output_dir, "trivy-scan.log")
    
    # Build command
    cmd = [
        "trivy", "fs",
        "--scanners", "secret,misconfig",
        "--format", "json",
        "--output", output_file,
        "--debug"
    ]
    
    # Add exclusions
    for exclude in SCAN_EXCLUDE_DIRS:
        cmd.extend(["--skip-dirs", f"{src_path}/{exclude}"])
        cmd.extend(["--skip-dirs", f"**/{exclude}"])

    cmd.append(src_path)
    
    log.info(f"Scan running. Logs: {log_file}")
    
    # Run subprocess (logs command debug info internally)
    success, output = run_subprocess(cmd, timeout=SHORT_CMD_TIMEOUT)
    
    # Save raw logs for debugging
    try:
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(output)
    except Exception as e:
        log.warning(f"Failed to write log file: {e}")
    
    findings = []
    
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
                
            results = data.get('Results', [])
            for result in results:
                target_file = result.get('Target')
                
                # Process Misconfigurations
                for misconf in result.get('Misconfigurations', []):
                    findings.append({
                        "tool": "CONTAINER (Trivy)",
                        "severity": normalize_severity(misconf.get('Severity')),
                        "title": f"Misconfiguration: {misconf.get('Title')}",
                        "description": misconf.get('Description'),
                        "details": f"ID: {misconf.get('ID')}\nMessage: {misconf.get('Message')}",
                        "remediation": misconf.get('Resolution'),
                        "file_path": target_file,
                        "line_start": misconf.get('IacMetadata', {}).get('StartLine'),
                        "line_end": misconf.get('IacMetadata', {}).get('EndLine')
                    })

                # Process Secrets
                for secret in result.get('Secrets', []):
                    findings.append({
                        "tool": "CONTAINER (Trivy)",
                        "severity": normalize_severity(secret.get('Severity')),
                        "title": f"Secret Found: {secret.get('Title')}",
                        "description": f"Category: {secret.get('Category')}",
                        "details": f"Match: {secret.get('Match')}",
                        "remediation": "Revoke this secret immediately and rotate credentials.",
                        "file_path": target_file,
                        "line_start": secret.get('StartLine'),
                        "line_end": secret.get('EndLine')
                    })

            log.info(f"Trivy scan complete. Findings: {len(findings)}")

        except json.JSONDecodeError:
             log.error("Failed to parse Trivy JSON report.")
             
    return {
        "findings": findings,
        "raw_report": ("CONTAINER_Trivy", output)
    }

register_tool("CONTAINER", run_container_scan)