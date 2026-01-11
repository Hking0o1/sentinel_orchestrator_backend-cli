from typing import List, Dict
from scanner.ai.provider import AIProvider
from scanner.ai.exceptions import AISummarizationError


def summarize_chunk(
    *,
    provider: AIProvider,
    findings: List[Dict],
) -> str:
    """
    Summarize one chunk of findings via an AI provider.
    """
    try:
        return provider.summarize(findings)
    except AISummarizationError:
        raise
