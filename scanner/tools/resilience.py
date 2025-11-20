import requests
import urllib3
from typing import Dict, Any, Optional
from .utils import normalize_severity, get_logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = get_logger("scanner.resilience")

def run_resilience_check(target_url: Optional[str]) -> Dict[str, Any]:
    log.info(f"Checking resilience for: {target_url}")
    
    if not target_url:
        return {"findings": [], "raw_report": ("Resilience_Check", "Skipped")}
        
    findings = []
    headers = {'User-Agent': 'ProjectSentinel/1.0'}
    
    # 1. CDN Check
    try:
        r = requests.head(target_url, headers=headers, timeout=10, verify=False)
        headers_str = str(r.headers).lower()
        
        detected = next((cdn for cdn in ['cloudflare', 'cloudfront', 'akamai', 'fastly'] if cdn in headers_str), None)
        
        if detected:
            findings.append({
                "tool": "Resilience Check", "severity": "INFO",
                "title": "CDN Detected", "description": f"Protected by {detected.capitalize()}"
            })
        else:
            findings.append({
                "tool": "Resilience Check", "severity": "MEDIUM",
                "title": "No CDN Detected", "description": "Origin server may be exposed."
            })
            
    except Exception as e:
        log.error(f"CDN check failed: {e}")

    # 2. Rate Limit Check
    try:
        rate_limited = False
        with requests.Session() as s:
            for _ in range(15):
                if s.get(target_url, headers=headers, timeout=2, verify=False).status_code == 429:
                    rate_limited = True
                    break
        
        if rate_limited:
            findings.append({
                "tool": "Resilience Check", "severity": "INFO",
                "title": "Rate Limiting Active", "description": "Server blocks rapid requests."
            })
        else:
            findings.append({
                "tool": "Resilience Check", "severity": "LOW",
                "title": "No Rate Limiting", "description": "Server allowed rapid request burst."
            })
            
    except Exception:
        pass

    return {"findings": findings, "raw_report": ("Resilience_Check", "Complete")}