from typing import List, Dict, Any
from .models import UnifiedFinding
from .normalizers import Normalizer
from .mapper import SourceMapper
from .enricher import LLMEnricher

class CorrelationEngine:
    def __init__(self):
        self.findings: List[UnifiedFinding] = []

    def ingest_standard_findings(self, findings_list: List[Dict[str, Any]]):
        """
        Ingests a list of pre-parsed findings (dictionaries) from the orchestrator
        and converts them into UnifiedFinding objects.
        """
        print(f"[Correlation] Ingesting {len(findings_list)} findings...")
        for f_dict in findings_list:
            try:
                # Use the 'standard' normalizer since our tools already cleaned the data
                unified_f = Normalizer.from_standard_finding(f_dict)
                self.findings.append(unified_f)
            except Exception as e:
                print(f"[Correlation] Error ingesting finding: {e}")

    def deduplicate(self):
        """
        Removes duplicate findings based on fingerprint.
        """
        unique = {}
        for f in self.findings:
            fp = f.fingerprint()
            if fp not in unique:
                unique[fp] = f
            else:
                # Merge tags if needed
                unique[fp].tags.update(f.tags)
        
        # Calculate reduction stats
        before = len(self.findings)
        after = len(unique)
        if before > after:
            print(f"[Correlation] Deduplication: Reduced {before} findings to {after}.")
        
        self.findings = list(unique.values())

    def run(self) -> List[UnifiedFinding]:
        """
        Main execution pipeline:
        1. Deduplicate
        2. Map Source <-> Endpoint (SAST + DAST correlation)
        3. AI Enrichment (Explain connections)
        """
        # 1. Deduplicate raw inputs
        self.deduplicate()
        
        # 2. Run the Source Mapper (Heuristic Linking)
        mapper = SourceMapper(self.findings)
        self.findings = mapper.correlate()
        
        # 3. Run AI Enrichment on Correlated items
        # (Only runs if LLM is available)
        enricher = LLMEnricher()
        self.findings = enricher.enrich_correlated_findings(self.findings)
        
        return self.findings