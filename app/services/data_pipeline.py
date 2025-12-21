import json
import re
import os
import logging
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, field_validator

# REBRANDING: Updated logger to Sentrion
logger = logging.getLogger("sentrion.data_pipeline")

class VulnerabilityRecord(BaseModel):
    tool_name: str
    rule_id: Optional[str] = None
    cwe: Optional[str] = None
    test_case_id: Optional[str] = None
    expected_vulnerable: str = "UNKNOWN"
    detected: bool = True
    vulnerability_type: str
    severity: str
    description: str
    target_code: Optional[str] = None
    cvss_score: float

    @field_validator('severity')
    def check_severity(cls, v):
        valid_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO']
        if v.upper() not in valid_levels:
            return 'INFO'
        return v.upper()

    @field_validator('cvss_score')
    def check_score(cls, v):
        return max(0.0, min(10.0, float(v)))

class DataSanitizer:
    def __init__(self, output_file="scan_results/dataset_v1.jsonl"):
        try:
            directory = os.path.dirname(output_file)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create dataset directory: {e}")
        self.output_file = output_file

    def clean_text(self, text: str) -> str:
        if not text:
            return "N/A"
        # Remove newlines and excess whitespace for clean JSONL
        return re.sub(r'\s+', ' ', str(text)).strip()

    def _estimate_score(self, severity: str) -> float:
        mapping = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0}
        return mapping.get(severity.upper(), 0.0)

    def _extract_rule_id(self, finding: Dict[str, Any]) -> str:
        if finding.get("cve_id"):
            return finding.get("cve_id")
        
        text_blob = (str(finding.get("title", "")) + " " + str(finding.get("description", ""))).upper()
        
        # Checkov ID Pattern (CKV_AWS_123)
        ckv_match = re.search(r'(CKV[2]?_[A-Z]+_\d+)', text_blob)
        if ckv_match:
            return ckv_match.group(1)
            
        # CVE Pattern
        cve_match = re.search(r'(CVE-\d{4}-\d{4,})', text_blob)
        if cve_match:
            return cve_match.group(1)
            
        # Fallback to title if it looks like a rule ID (no spaces, e.g., "bandit.B101")
        title = str(finding.get("title", ""))
        if "." in title and " " not in title:
            return title
            
        return "UNKNOWN_RULE"

    def _extract_test_case_id(self, finding: Dict[str, Any]) -> Optional[str]:
        """
        FIX: Extract Test Case ID from the nested code_location file path.
        Crucial for OWASP Benchmark grading.
        """
        path = ""
        # 1. Try Code Location (SAST/IAC tools usually put it here)
        if finding.get("code_location"):
            path = finding["code_location"].get("file_path", "")
        # 2. Try Endpoint Location (DAST tools)
        elif finding.get("endpoint_location"):
            path = finding["endpoint_location"].get("url", "")

        # Pattern: OWASP Benchmark (BenchmarkTest00001)
        match = re.search(r'(BenchmarkTest\d+)', str(path), re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def _extract_cwe(self, finding: Dict[str, Any]) -> Optional[str]:
        # 1. Direct field (populated by our Normalizer)
        if finding.get("cwe_id"):
            val = finding.get("cwe_id")
            if isinstance(val, list) and len(val) > 0:
                return str(val[0])
            if val and str(val).lower() != "none":
                return str(val)

        # 2. FIX: Parse from text if missing (Regex fallback)
        text_blob = (str(finding.get("title", "")) + " " + str(finding.get("description", ""))).upper()
        match = re.search(r'(CWE-\d+)', text_blob)
        if match:
            return match.group(1)
        return None

    def process_and_save(self, findings: List[Dict[str, Any]]):
        if not findings:
            return

        success_count = 0
        try:
            with open(self.output_file, 'a', encoding='utf-8') as f:
                for raw_entry in findings:
                    try:
                        severity = raw_entry.get("severity", "INFO")
                        
                        code_snippet = None
                        if raw_entry.get("code_location"):
                            code_snippet = raw_entry["code_location"].get("snippet")

                        cleaned_data = {
                            "tool_name": raw_entry.get("tool_source") or raw_entry.get("tool") or "Sentrion",
                            "rule_id": self._extract_rule_id(raw_entry),
                            "cwe": self._extract_cwe(raw_entry),
                            "test_case_id": self._extract_test_case_id(raw_entry),
                            "expected_vulnerable": "UNKNOWN", # To be filled by benchmark grader
                            "detected": True,
                            "vulnerability_type": self.clean_text(raw_entry.get("title", "")),
                            "severity": severity,
                            "description": self.clean_text(raw_entry.get("description") or raw_entry.get("details", "")),
                            "target_code": self.clean_text(code_snippet) if code_snippet else None,
                            "cvss_score": self._estimate_score(severity)
                        }

                        record = VulnerabilityRecord(**cleaned_data)
                        f.write(json.dumps(record.model_dump()) + "\n")
                        success_count += 1
                    except Exception:
                        continue
            
            if success_count > 0:
                logger.info(f"Data Pipeline: Saved {success_count} records.")
                
        except Exception as e:
            logger.error(f"Data Pipeline Failure: {e}")