import os
import json
from typing import Dict, Any
from .utils import (
    run_subprocess, 
    is_tool_installed, 
    ensure_dir, 
    get_logger,
    SCAN_EXCLUDE_DIRS,
    SHORT_CMD_TIMEOUT
)
from scanner.tools.registry import register_tool


log = get_logger("scanner.tools.iac")

def run_iac_scan(src_path: str, output_dir: str) -> Dict[str, Any]:
    """
    Runs Checkov to find security flaws in Infrastructure-as-Code.
    """
    log.info(f"Starting Checkov scan on: {src_path}")
    
    if not is_tool_installed("checkov"):
        log.error("Tool 'checkov' not found in PATH.")
        return {
            "findings": [], 
            "raw_report": ("IAC_Checkov", "Tool 'checkov' not found in PATH.")
        }

    ensure_dir(output_dir)
    json_report_path = os.path.join(output_dir, "checkov_report.json")
    
    # Build command
    # Put flags BEFORE the directory argument to avoid parsing issues
    cmd = [
        "checkov",
        "-o", "json",
        "--soft-fail",
        "--quiet",
        "--compact",
        "-d", src_path
    ]

    for exclude in SCAN_EXCLUDE_DIRS:
        cmd.extend(["--skip-path", exclude])


    # Run the scan
    success, output = run_subprocess(cmd, timeout=SHORT_CMD_TIMEOUT)
    
    # Save the output manually for debugging
    try:
        with open(json_report_path, "w") as f:
            f.write(output)
    except Exception as e:
        log.warning(f"Failed to write Checkov output file: {e}")

    findings = []
    
    # Robust JSON parsing
    # Checkov might output multiple JSON objects or prepends text. We try to find the JSON start.
    if output:
        try:
            # Try cleaning the output if it contains non-json prefix
            json_start = output.find('[')
            dict_start = output.find('{')
            
            # Determine which starts first (list of results or single result)
            start_idx = -1
            if json_start != -1 and dict_start != -1:
                start_idx = min(json_start, dict_start)
            elif json_start != -1:
                start_idx = json_start
            elif dict_start != -1:
                start_idx = dict_start
                
            if start_idx != -1:
                clean_output = output[start_idx:]
                data = json.loads(clean_output)
                
                # Normalize to a list
                if isinstance(data, dict):
                    reports = [data]
                else:
                    reports = data
                    
                for report in reports:
                    # Checkov structure: results -> failed_checks
                    results = report.get('results', {})
                    failed_checks = results.get('failed_checks', [])
                    
                    for check in failed_checks:
                        findings.append({
                            "tool": "IAC (Checkov)",
                            "severity": "MEDIUM", # Default for IaC
                            "title": f"IaC: {check.get('check_name')}",
                            "description": check.get('check_id'),
                            "details": f"Resource: {check.get('resource')}",
                            "remediation": check.get('guideline'),
                            "file_path": check.get('file_path'),
                            "line_start": check.get('file_line_range', [0, 0])[0],
                            "line_end": check.get('file_line_range', [0, 0])[1],
                            "resource_id": check.get('resource')
                        })
                
                log.info(f"Checkov scan complete. Findings: {len(findings)}")
            else:
                log.warning("Could not find JSON start in Checkov output.")

        except json.JSONDecodeError:
             log.error("Failed to parse Checkov JSON report.")
             
    return {
        "findings": findings,
        "raw_report": ("IAC_Checkov", output)
    }
    
register_tool("IAC", run_iac_scan)