import json
import re
import os
import logging
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, field_validator, ValidationError

# Setup logger for this service
logger = logging.getLogger("sentinel.data_pipeline")

class VulnerabilityRecord(BaseModel):
    """
    Enhanced schema for AI training and Benchmark testing.
    """
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
        if not text: return "N/A"
        return re.sub(r'\s+', ' ', str(text)).strip()

    def _estimate_score(self, severity: str) -> float:
        mapping = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0}
        return mapping.get(severity.upper(), 0.0)

    def _extract_rule_id(self, finding: Dict[str, Any]) -> str:
        # 1. Check explicit ID fields first
        if finding.get("cve_id"): return finding.get("cve_id")
        
        # 2. Check title/description for common patterns
        text_blob = (str(finding.get("title", "")) + " " + str(finding.get("description", ""))).upper()
        
        ckv_match = re.search(r'(CKV[2]?_[A-Z]+_\d+)', text_blob)
        if ckv_match: return ckv_match.group(1)
            
        cve_match = re.search(r'(CVE-\d{4}-\d{4,})', text_blob)
        if cve_match: return cve_match.group(1)
            
        if "." in str(finding.get("title", "")) and " " not in str(finding.get("title", "")):
             return finding.get("title")

        return "UNKNOWN_RULE"

    def _extract_test_case_id(self, finding: Dict[str, Any]) -> Optional[str]:
        """
        Extracts the Test Case ID from the file path.
        Standard for OWASP Benchmark (e.g., BenchmarkTest00001).
        """
        # Look in file_path or location
        path = finding.get("file_path") or finding.get("location") or ""
        
        # Pattern 1: OWASP Benchmark (BenchmarkTest02345)
        match = re.search(r'(BenchmarkTest\d+)', str(path), re.IGNORECASE)
        if match:
            return match.group(1)
            
        # Pattern 2: Generic Test files (Test1, test_01)
        match = re.search(r'(Test\d+|test_\d+)', str(path), re.IGNORECASE)
        if match:
            return match.group(1)
            
        return None

    def _extract_cwe(self, finding: Dict[str, Any]) -> Optional[str]:
        """
        Extracts CWE ID from various fields.
        """
        # 1. Direct field
        if finding.get("cwe_id"):
            val = finding.get("cwe_id")
            # Handle list or string
            if isinstance(val, list) and len(val) > 0: return str(val[0])
            return str(val)

        # 2. Parse from title/description
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
                        
                        # Extract snippet
                        code_snippet = None
                        if "code_location" in raw_entry and raw_entry["code_location"]:
                            loc = raw_entry["code_location"]
                            if isinstance(loc, dict):
                                code_snippet = loc.get("snippet")
                            elif hasattr(loc, 'snippet'):
                                code_snippet = loc.snippet
                        
                        # Extract Metadata
                        rule_id = self._extract_rule_id(raw_entry)
                        test_case_id = self._extract_test_case_id(raw_entry)
                        cwe_id = self._extract_cwe(raw_entry)
                        
                        cleaned_data = {
                            "tool_name": raw_entry.get("tool_source") or raw_entry.get("tool") or "Sentinel",
                            "rule_id": rule_id,
                            "cwe": cwe_id,
                            "test_case_id": test_case_id,
                            "expected_vulnerable": "UNKNOWN",
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
                        
                    except ValidationError as ve:
                        logger.warning(f"Skipping invalid record: {ve}")
                        continue
                    except Exception as e:
                        logger.error(f"Error processing single finding: {e}")
                        continue
                        
            if success_count > 0:
                logger.info(f"Data Pipeline: Saved {success_count} records to {self.output_file}")
                
        except Exception as e:
            logger.error(f"Data Pipeline Critical Failure: {e}")

data_sanitizer = DataSanitizer()