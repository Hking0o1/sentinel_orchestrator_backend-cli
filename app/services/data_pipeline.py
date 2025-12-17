import json
import re
import os
import logging
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, field_validator, ValidationError

# Setup logger for this service
logger = logging.getLogger("sentinel.data_pipeline")

class VulnerabilityRecord(BaseModel):
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
            return 'INFO'
        return v.upper()

    @field_validator('cvss_score')
    def check_score(cls, v):
        return max(0.0, min(10.0, float(v)))

class DataSanitizer:
    def __init__(self, output_file="scan_results/dataset_v1.jsonl"):
        # Ensure the directory exists. In Docker, this should be a volume.
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

    def process_and_save(self, findings: List[Dict[str, Any]]):
        """
        Validates and appends a LIST of findings to the dataset.
        """
        if not findings:
            logger.warning("Data Pipeline: No findings to save.")
            return

        success_count = 0
        
        try:
            # Use 'a' (append) mode to never overwrite previous data
            with open(self.output_file, 'a', encoding='utf-8') as f:
                for raw_entry in findings:
                    try:
                        severity = raw_entry.get("severity", "INFO")
                        
                        code_snippet = None
                        # Robustly handle code_location, whether it's a dict or object
                        if "code_location" in raw_entry and raw_entry["code_location"]:
                            loc = raw_entry["code_location"]
                            if isinstance(loc, dict):
                                code_snippet = loc.get("snippet")
                            elif hasattr(loc, 'snippet'):
                                code_snippet = loc.snippet
                        
                        cleaned_data = {
                            "tool_name": raw_entry.get("tool_source") or raw_entry.get("tool") or "Sentinel",
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
                logger.info(f"Data Pipeline: Successfully saved {success_count} records to {self.output_file}")
            else:
                logger.warning("Data Pipeline: No valid records were saved.")
                
        except Exception as e:
            logger.error(f"Data Pipeline Critical Failure: {e}")

data_sanitizer = DataSanitizer()