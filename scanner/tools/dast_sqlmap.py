import os
from typing import Dict, Any, Optional
from .utils import (
    run_subprocess,
    is_tool_installed,
    normalize_severity,
    ensure_dir,
    get_logger,
    SHORT_CMD_TIMEOUT
)

log = get_logger("scanner.dast.sqlmap")

def run_sqlmap_scan(target_url: Optional[str], output_dir: str, timeout: int = SHORT_CMD_TIMEOUT) -> Dict[str, Any]:
    """
    Runs SQLMap to detect SQL Injection vulnerabilities.
    """
    log.info(f"Starting SQLMap scan on: {target_url}")

    if not target_url:
        return {"findings": [], "raw_report": ("DAST_SQLMap", "Skipped: No target URL.")}

    if not is_tool_installed("sqlmap"):
        log.error("SQLMap tool not found")
        return {"findings": [], "raw_report": ("DAST_SQLMap", "Tool missing")}

    ensure_dir(output_dir)
    
    # --- FIX: Smart Command Construction ---
    # We no longer skip if '?' is missing. Instead, we adapt the command.
    cmd = [
        "sqlmap", 
        "-u", target_url, 
        "--batch",            # Never ask for user input
        "--random-agent",     # Use a random User-Agent to bypass basic filters
        "--level=1",          # Level 1 is safe/fast
        "--risk=1",           # Risk 1 avoids dangerous payloads
    ]

    # If there are no parameters in the URL, enable crawling
    if '?' not in target_url:
        log.info("No parameters detected in URL. Enabling SQLMap crawler (depth=2).")
        cmd.append("--crawl=2")
    else:
        log.info("Parameters detected. Scanning specific URL.")

    # Run the scan
    # We execute from output_dir to try and capture SQLMap's generated files
    success, output = run_subprocess(cmd, cwd=output_dir, timeout=timeout)
    
    findings = []
    
    # SQLMap doesn't output easy JSON, so we grep the output for known success strings
    output_lower = output.lower()
    
    if "is vulnerable" in output_lower or "seems to be injectable" in output_lower:
        log.warning("CRITICAL: SQL Injection found!")
        
        # Try to extract the parameter name from logs
        param_name = "Unknown"
        if "parameter '" in output:
            try:
                param_name = output.split("parameter '")[1].split("'")[0]
            except IndexError:
                pass

        findings.append({
            "tool": "DAST (SQLMap)",
            "severity": "CRITICAL",
            "title": f"SQL Injection (Param: {param_name})",
            "description": "SQLMap confirmed that a parameter is vulnerable to SQL Injection.",
            "details": f"The parameter '{param_name}' appears to be injectable.",
            "remediation": "Use parameterized queries (prepared statements) for all database access.",
            "url": target_url,
            "parameter": param_name
        })
    else:
        log.info("SQLMap finished. No vulnerabilities found.")
    
    return {
        "findings": findings,
        "raw_report": ("DAST_SQLMap", output)
    }