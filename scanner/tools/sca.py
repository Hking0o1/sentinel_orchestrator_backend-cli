import os
import json
from typing import Dict, Any
from .utils import (
    run_subprocess, is_tool_installed, normalize_severity, 
    ensure_dir, get_logger, SCAN_EXCLUDE_DIRS
)
from config.settings import settings # Import settings to get API Key
from scanner.tools.registry import register_tool

log = get_logger("scanner.tools.sca")
REQUIRES_EXTERNAL_DEPENDENCIES = True

def run_sca_scan(src_path: str, output_dir: str) -> Dict[str, Any]:
    """
    Runs OWASP Dependency-Check.
    """
    log.info(f"Starting Dependency-Check scan on: {src_path}")
    
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
    
    # --- FIX: Error Visibility ---
    if not success:
        log.error("Dependency-Check FAILED.")
        # Read the last 20 lines of the log file and print them to the console
        if os.path.exists(tool_log_file):
            try:
                with open(tool_log_file, 'r') as f:
                    lines = f.readlines()
                    last_lines = "".join(lines[-20:])
                    log.error(f"--- TAIL OF DEPENDENCY-CHECK LOG ---\n{last_lines}\n------------------------------------")
            except Exception as e:
                log.error(f"Could not read log file: {e}")
        else:
            log.error(f"No log file found at {tool_log_file}")
            # Print stdout/stderr captured by subprocess as backup
            log.error(f"Subprocess Output:\n{output[-1000:]}") # Last 1000 chars

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