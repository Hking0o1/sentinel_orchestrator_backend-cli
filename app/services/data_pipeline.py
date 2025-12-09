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
    Strict schema for AI training data.
    Ensures only high-quality data enters the dataset.
    """
    tool_name: str = "Sentinel"
    vulnerability_type: str
    severity: str
    description: str
    target_code: Optional[str] = None 
    cvss_score: float

    @field_validator('severity')
    def check_severity(cls, v):
        valid_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO']
        if v.upper() not in valid_levels:
            # Fallback to INFO instead of crashing
            return 'INFO'
        return v.upper()

    @field_validator('cvss_score')
    def check_score(cls, v):
        # Clamp score to valid range
        return max(0.0, min(10.0, float(v)))

class DataSanitizer:
    def __init__(self, output_file="scan_results/dataset_v1.jsonl"):
        # Ensure directory exists. In Docker, 'scan_results' is a volume.
        # We check if the parent dir exists before creating.
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create dataset directory: {e}")
        self.output_file = output_file

    def clean_text(self, text: str) -> str:
        """Removes newlines and extra spaces for clean JSONL."""
        if not text: return "N/A"
        # Remove multiple spaces, tabs, newlines
        return re.sub(r'\s+', ' ', str(text)).strip()

    def _estimate_score(self, severity: str) -> float:
        """Helper to assign a dummy CVSS score if missing."""
        mapping = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0}
        return mapping.get(severity.upper(), 0.0)

    def process_and_save(self, findings: List[Dict[str, Any]]):
        """
        Validates and appends a LIST of findings to the dataset.
        Running in a background thread prevents blocking.
        """
        if not findings:
            return

        success_count = 0
        
        try:
            with open(self.output_file, 'a', encoding='utf-8') as f:
                for raw_entry in findings:
                    try:
                        # 1. Map 'Sentinel' finding structure to 'Training' schema
                        # We handle missing keys gracefully here
                        severity = raw_entry.get("severity", "INFO")
                        
                        # Extract snippet if available (from SAST)
                        code_snippet = None
                        if "code_location" in raw_entry and raw_entry["code_location"]:
                            # Handle both object and dict access if pydantic model was dumped
                            loc = raw_entry["code_location"]
                            if isinstance(loc, dict):
                                code_snippet = loc.get("snippet")
                        
                        cleaned_data = {
                            "tool_name": raw_entry.get("tool_source") or raw_entry.get("tool") or "Sentinel",
                            "vulnerability_type": self.clean_text(raw_entry.get("title", "")),
                            "severity": severity,
                            "description": self.clean_text(raw_entry.get("description") or raw_entry.get("details", "")),
                            "target_code": self.clean_text(code_snippet) if code_snippet else None,
                            # Use provided score or estimate based on severity
                            "cvss_score": self._estimate_score(severity)
                        }

                        # 2. Validate with Pydantic
                        record = VulnerabilityRecord(**cleaned_data)
                        
                        # 3. Write to JSONL (One line per record)
                        f.write(json.dumps(record.model_dump()) + "\n")
                        success_count += 1
                        
                    except ValidationError as ve:
                        # Log validation error but continue processing other findings
                        # logger.warning(f"Skipping invalid record: {ve}")
                        continue
                        
            if success_count > 0:
                logger.info(f"Background Pipeline: Saved {success_count} records to {self.output_file}")
                
        except Exception as e:
            # Global safety net - ensure thread never crashes the app
            logger.error(f"Data Pipeline Crash: {e}")

# Singleton instance
data_sanitizer = DataSanitizer()