import os
from typing import Dict, Any, Optional
from .utils import (
    run_subprocess, is_tool_installed, normalize_severity, 
    ensure_dir, get_logger, SHORT_CMD_TIMEOUT
)

log = get_logger("scanner.dast.nikto")

def run_nikto_scan(target_url: Optional[str], output_dir: str) -> Dict[str, Any]:
    log.info(f"Starting Nikto scan on: {target_url}")

    if not target_url:
        return {"findings": [], "raw_report": ("DAST_Nikto", "Skipped")}

    if not is_tool_installed("nikto"):
        log.error("Nikto tool not found")
        return {"findings": [], "raw_report": ("DAST_Nikto", "Tool missing")}

    ensure_dir(output_dir)
    output_file = os.path.join(output_dir, "nikto_report.txt")
    
    cmd = [
        "nikto", "-h", target_url, 
        "-o", output_file, "-Format", "txt",
        "-Tuning", "x", "3", "5" # Exclude DoS and noisy checks
    ]
    
    if target_url.startswith("https"):
        cmd.append("-ssl")

    success, output = run_subprocess(cmd, timeout=SHORT_CMD_TIMEOUT)
    
    findings = []
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            for line in f:
                if line.startswith("+ ") and "No web server found" not in line:
                    # Basic parsing logic
                    sev = "INFO"
                    lower = line.lower()
                    if "vulnerable" in lower or "xss" in lower or "sql" in lower:
                        sev = "HIGH"
                    elif "outdated" in lower:
                        sev = "MEDIUM"
                        
                    findings.append({
                        "tool": "DAST (Nikto)",
                        "severity": normalize_severity(sev),
                        "title": "Server Config Issue",
                        "description": line[2:].strip(),
                        "url": target_url
                    })
    
    log.info(f"Analysis complete. Found {len(findings)} items.")
    return {"findings": findings, "raw_report": ("DAST_Nikto", output)}