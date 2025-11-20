from typing import Dict, Any, Optional
from .models import UnifiedFinding, Severity, ToolType, CodeLocation, EndpointLocation

def _norm_sev(sev: Optional[str]) -> Severity:
    """Normalizes severity strings."""
    if not sev:
        return Severity.INFO
    s = sev.upper()
    if "CRIT" in s: return Severity.CRITICAL
    if "HIGH" in s: return Severity.HIGH
    if "MED" in s: return Severity.MEDIUM
    if "LOW" in s: return Severity.LOW
    return Severity.INFO

class Normalizer:
    """
    Factory class to convert PRE-PARSED findings (from scanner/tools/*.py)
    into strict UnifiedFinding Pydantic objects for the Correlation Engine.
    """

    @staticmethod
    def from_standard_finding(finding_dict: Dict[str, Any]) -> UnifiedFinding:
        """
        Converts a standard dictionary finding from our orchestrator into a UnifiedFinding object.
        """
        
        # 1. Determine Tool Type based on the tool name string
        tool_name = finding_dict.get("tool", "Unknown").upper()
        t_type = ToolType.SAST # Default
        
        if "TRIVY" in tool_name or "CONTAINER" in tool_name:
            if "SECRET" in finding_dict.get("title", "").upper():
                t_type = ToolType.SECRET
            elif "MISCONFIG" in finding_dict.get("title", "").upper():
                t_type = ToolType.IAC
            else:
                t_type = ToolType.CONTAINER
        elif "CHECKOV" in tool_name or "IAC" in tool_name:
            t_type = ToolType.IAC
        elif "ZAP" in tool_name or "NIKTO" in tool_name or "SQLMAP" in tool_name or "DAST" in tool_name:
            t_type = ToolType.DAST
        elif "DEPENDENCY" in tool_name or "SCA" in tool_name:
            t_type = ToolType.SCA

        # 2. Build Code Location (if applicable)
        code_loc = None
        if finding_dict.get("file_path"):
            # Ensure lines are integers
            start = finding_dict.get("line_start")
            end = finding_dict.get("line_end")
            try:
                start = int(start) if start else 0
                end = int(end) if end else 0
            except (ValueError, TypeError):
                start = 0
                end = 0
                
            code_loc = CodeLocation(
                file_path=finding_dict["file_path"],
                line_start=start,
                line_end=end,
                snippet=finding_dict.get("code_snippet")
            )

        # 3. Build Endpoint Location (if applicable)
        end_loc = None
        if finding_dict.get("url") and "http" in finding_dict["url"]:
            end_loc = EndpointLocation(
                url=finding_dict["url"],
                method=finding_dict.get("method", "GET"),
                parameter=finding_dict.get("param")
            )

        # 4. Construct UnifiedFinding
        unified = UnifiedFinding(
            id="", # Will be set by fingerprint()
            title=finding_dict.get("title", "Unknown Issue"),
            description=finding_dict.get("description") or finding_dict.get("details", "No description"),
            severity=_norm_sev(finding_dict.get("severity")),
            tool_source=finding_dict.get("tool", "Unknown Tool"),
            tool_type=t_type,
            code_location=code_loc,
            endpoint_location=end_loc,
            cwe_id=finding_dict.get("cwe_id"),
            cve_id=finding_dict.get("cve_id"),
            remediation_steps=finding_dict.get("remediation"),
            raw_data=finding_dict # Store the original dict for reference
        )
        
        # Generate deterministic ID
        unified.id = unified.fingerprint()
        
        return unified