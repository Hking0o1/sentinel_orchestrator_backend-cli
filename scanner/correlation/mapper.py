from typing import List, Dict, Optional
from .models import UnifiedFinding, ToolType

class SourceMapper:
    """
    Correlates SAST (Code) locations with DAST (Endpoint) locations.
    """
    
    def __init__(self, findings: List[UnifiedFinding]):
        self.findings = findings
        # Filter findings by type for comparison
        self.sast_findings = [f for f in findings if f.tool_type in [ToolType.SAST, ToolType.SECRET]]
        self.dast_findings = [f for f in findings if f.tool_type == ToolType.DAST]

    def correlate(self) -> List[UnifiedFinding]:
        """
        Iterates through findings and creates links between related items.
        Updates the findings in-place and returns the full list.
        """
        # Only run if we have both types of findings
        if not self.sast_findings or not self.dast_findings:
            return self.findings

        for dast_f in self.dast_findings:
            # Skip if DAST finding has no URL context
            if not dast_f.endpoint_location or not dast_f.endpoint_location.url:
                continue
                
            url_path = dast_f.endpoint_location.url
            
            for sast_f in self.sast_findings:
                # Skip if SAST finding has no file context
                if not sast_f.code_location or not sast_f.code_location.file_path:
                    continue
                    
                file_path = sast_f.code_location.file_path
                
                # Calculate match score
                score = self._calculate_match_score(url_path, file_path, dast_f.title, sast_f.title)

                # Threshold for linking (e.g., 50%)
                if score >= 50:
                    self._link_findings(dast_f, sast_f, score)
                    
        return self.findings

    def _calculate_match_score(self, url: str, file_path: str, dast_title: str, sast_title: str) -> int:
        """
        Heuristic scoring for correlation.
        Returns an integer score (0-100).
        """
        score = 0
        
        # --- 1. Path Matching (Highest Weight) ---
        # Try to match URL segments to filenames
        # e.g., URL: /api/users/login -> File: src/api/users/login_controller.ts
        
        try:
            # Normalize URL: remove query params, protocol
            clean_url = url.split('?')[0].split('#')[0]
            if "://" in clean_url:
                clean_url = clean_url.split("://")[1]
            
            # Split into segments
            url_segments = [s.lower() for s in clean_url.split('/') if len(s) > 2]
            file_lower = file_path.lower()

            matches = 0
            for segment in url_segments:
                if segment in file_lower:
                    matches += 1
            
            # Scoring: 25 points per matching segment, capped at 75
            if matches > 0:
                score += min(matches * 25, 75)

        except Exception:
            # Safely ignore parsing errors
            pass
        
        # --- 2. Vulnerability Type Matching ---
        # Do both tools describe the same kind of bug?
        dast_title_lower = (dast_title or "").lower()
        sast_title_lower = (sast_title or "").lower()
        
        keywords = ["sql", "xss", "injection", "auth", "jwt", "deserialization", "config", "csrf"]
        
        for keyword in keywords:
            if keyword in dast_title_lower and keyword in sast_title_lower:
                score += 30 # Bonus for matching vulnerability type
                break
        
        return min(score, 100) # Cap at 100

    def _link_findings(self, f1: UnifiedFinding, f2: UnifiedFinding, score: int):
        """Bi-directionally links two findings."""
        
        # Link f1 -> f2
        if f2.id not in f1.related_findings:
            f1.related_findings.append(f2.id)
            f1.is_confirmed_by_other_tool = True
            f1.correlation_score = max(f1.correlation_score, score)
            
        # Link f2 -> f1
        if f1.id not in f2.related_findings:
            f2.related_findings.append(f1.id)
            f2.is_confirmed_by_other_tool = True
            f2.correlation_score = max(f2.correlation_score, score)