import os
import json
from typing import Dict, Any, Optional
from .utils import (
    run_subprocess, is_tool_installed, normalize_severity, 
    ensure_dir, get_logger, DEFAULT_CMD_TIMEOUT
)
from scanner.tools.registry import register_tool

log = get_logger("scanner.dast.zap")

def run_zap_scan(target_url: Optional[str], output_dir: str, auth_cookie: Optional[str] = None) -> Dict[str, Any]:
    log.info(f"Starting ZAP scan on: {target_url}")

    if not target_url:
        return {"findings": [], "raw_report": ("DAST_ZAP", "Skipped: No URL")}

    ensure_dir(output_dir)
    abs_output_dir = os.path.abspath(output_dir)
    
    cmd = [
        "docker", "run", "--rm", "--user", "0",
        "-v", f"{abs_output_dir}:/zap/wrk/:rw",
        "ghcr.io/zaproxy/zaproxy:stable",
        "zap-baseline.py",
        "-t", target_url,
        "-r", "zap_report.html",
        "-J", "zap_report.json"
    ]

    if auth_cookie:
        log.info("Running in AUTHENTICATED mode")
        # Inject auth cookie via ZAP replacer
        replacer = f"-config replacer.full_list(0).description=auth -config replacer.full_list(0).enabled=true -config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=Cookie -config replacer.full_list(0).regex=false -config replacer.full_list(0).replacement={auth_cookie}"
        cmd.extend(["-z", replacer])
    
    success, output = run_subprocess(cmd, timeout=DEFAULT_CMD_TIMEOUT)

    findings = []
    json_report = os.path.join(output_dir, "zap_report.json")

    if os.path.exists(json_report):
        try:
            with open(json_report, 'r') as f:
                data = json.load(f)
            
            for s in data.get('site', []):
                for alert in s.get('alerts', []):
                    risk = alert.get('riskcode', '0')
                    sev = "INFO"
                    if risk == '3': sev = "HIGH"
                    elif risk == '2': sev = "MEDIUM"
                    elif risk == '1': sev = "LOW"

                    findings.append({
                        "tool": "DAST (ZAP)",
                        "severity": normalize_severity(sev),
                        "title": alert.get('name'),
                        "description": alert.get('desc'),
                        "remediation": alert.get('solution'),
                        "url": alert.get('instances', [{}])[0].get('uri')
                    })
            log.info(f"Analysis complete. Found {len(findings)} alerts.")
            
        except Exception as e:
            log.error(f"Failed to parse report: {e}")

    return {"findings": findings, "raw_report": ("DAST_ZAP", output)}

register_tool("DAST_ZAP", run_zap_scan)