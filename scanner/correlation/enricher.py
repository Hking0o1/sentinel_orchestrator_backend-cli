import os
import json
from typing import List
from .models import UnifiedFinding
from config.settings import settings

# Import LangChain/Ollama conditionally
try:
    from langchain_ollama import ChatOllama
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import StrOutputParser
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

class LLMEnricher:
    """
    Uses AI (Local Ollama or Cloud Gemini) to enrich findings with
    explanations, fix suggestions, and attack path context.
    """
    
    def __init__(self):
        self.llm = None
        if LANGCHAIN_AVAILABLE:
            # Default to local Ollama for speed/cost
            # Use 'host.docker.internal' to reach host from container
            self.llm = ChatOllama(
                base_url="http://host.docker.internal:11434",
                model="gemma:2b" 
            )

    def enrich_correlated_findings(self, findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
        """
        Iterates through findings that are 'confirmed by other tool'
        and asks the AI to explain the correlation.
        """
        if not self.llm:
            print("[Enricher] LLM not available, skipping enrichment.")
            return findings

        # Filter for high-value, correlated findings
        correlated = [f for f in findings if f.is_confirmed_by_other_tool and not f.ai_explanation]
        
        print(f"[Enricher] Enriching {len(correlated)} correlated findings with AI...")

        for finding in correlated:
            # Find the related finding object
            related_id = finding.related_findings[0] if finding.related_findings else None
            related_finding = next((f for f in findings if f.id == related_id), None)
            
            if not related_finding:
                continue
                
            # Construct prompt context
            context = f"""
            Finding A ({finding.tool_type}): {finding.title}
            Description: {finding.description}
            Location: {finding.code_location or finding.endpoint_location}
            
            Finding B ({related_finding.tool_type}): {related_finding.title}
            Description: {related_finding.description}
            Location: {related_finding.code_location or related_finding.endpoint_location}
            """
            
            prompt = ChatPromptTemplate.from_messages([
                ("system", "You are a senior security engineer. I have found two potentially related security issues. One from Static Analysis (Code) and one from Dynamic Analysis (Runtime)."),
                ("human", f"Analyze this correlation:\n{context}\n\nExplain 1) How these two might represent the same vulnerability, and 2) A specific code fix.")
            ])
            
            try:
                chain = prompt | self.llm | StrOutputParser()
                explanation = chain.invoke({})
                
                # Update the finding with the AI's wisdom
                finding.ai_explanation = explanation
                # We can also update the related finding
                related_finding.ai_explanation = "See related finding for analysis."
                
            except Exception as e:
                print(f"[Enricher] AI enrichment failed for {finding.id}: {e}")
                
        return findings