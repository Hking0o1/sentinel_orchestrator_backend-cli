from typing import List, Dict
import time

from scanner.ai.exceptions import (
    AITokenLimitError,
    AITimeoutError,
    AIProviderError,
    AIInputValidationError,
)


class AIProvider:
    """
    Abstract LLM provider interface.
    """

    def summarize(self, findings: List[Dict]) -> str:
        raise NotImplementedError


class GeminiProvider(AIProvider):
    """
    Concrete Gemini implementation.
    """

    def __init__(self, client, timeout_sec: int = 30):
        self.client = client
        self.timeout_sec = timeout_sec

    def summarize(self, findings: List[Dict]) -> str:
        if not findings:
            raise AIInputValidationError("Empty findings chunk")

        prompt = self._build_prompt(findings)

        try:
            start = time.time()
            response = self.client.generate(
                prompt=prompt,
                timeout=self.timeout_sec,
            )

            if time.time() - start > self.timeout_sec:
                raise AITimeoutError("Gemini request timed out")

            if response.token_usage_exceeded:
                raise AITokenLimitError("Gemini token limit exceeded")

            return response.text

        except AITokenLimitError:
            raise
        except AITimeoutError:
            raise
        except Exception as exc:
            raise AIProviderError(str(exc)) from exc

    def _build_prompt(self, findings: List[Dict]) -> str:
        lines = []
        for f in findings:
            title = f.get("title", "Unnamed issue")
            severity = f.get("severity", "UNKNOWN")
            lines.append(f"- [{severity}] {title}")

        return (
            "Summarize the following security findings concisely "
            "for an engineering report:\n\n"
            + "\n".join(lines)
        )
