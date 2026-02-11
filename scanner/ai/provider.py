from typing import List, Dict, Any
import time
import requests
try:
    import google.generativeai as genai
except Exception:  # pragma: no cover - optional dependency
    genai = None

from config.settings import settings

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

    def __init__(self, model_name: str = "gemini-2.5-flash", timeout_sec: int = 30):
        self.model_name = model_name
        self.timeout_sec = timeout_sec
        if genai is None:
            raise AIProviderError(
                "google-generativeai is not installed; install it to use Gemini provider"
            )
        if not settings.GEMINI_API_KEY:
            raise AIProviderError("GEMINI_API_KEY is not configured")
        genai.configure(api_key=settings.GEMINI_API_KEY)
        self.client = genai.GenerativeModel(self.model_name)

    def summarize(self, findings: List[Dict]) -> str:
        if not findings:
            raise AIInputValidationError("Empty findings chunk")

        prompt = self._build_prompt(findings)

        try:
            start = time.time()
            response = self.client.generate_content(prompt)

            if time.time() - start > self.timeout_sec:
                raise AITimeoutError("Gemini request timed out")

            text = getattr(response, "text", None)
            if not text:
                raise AIProviderError("Gemini returned empty response")
            return text

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
            desc = (f.get("description") or "").strip()
            remediation = (f.get("remediation") or "").strip()
            location = (f.get("location") or "").strip()
            lines.append(
                f"- [{severity}] {title} | location={location or 'n/a'} | "
                f"desc={desc[:180]} | remediation_hint={remediation[:120]}"
            )

        return (
            "You are a principal application security engineer.\n"
            "Write a HUMAN-READABLE Markdown report for developers and product owners.\n"
            "Do NOT output JSON.\n"
            "Keep language simple and practical.\n"
            "Required sections:\n"
            "1) Executive Summary (plain language)\n"
            "2) Top Risks (bullet list with severity and impact)\n"
            "3) Recommended Fixes (numbered, concrete steps)\n"
            "4) Quick Wins This Sprint (3-5 items)\n"
            "5) Verification Steps (how to confirm fixes)\n\n"
            "Findings:\n"
            + "\n".join(lines)
        )


class OllamaProvider(AIProvider):
    """
    Ollama-backed local LLM provider.
    """

    def __init__(
        self,
        base_url: str = "http://host.docker.internal:11434",
        model: str = "gemma:2b",
        timeout_sec: int = 60,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_sec = timeout_sec

    def summarize(self, findings: List[Dict]) -> str:
        if not findings:
            raise AIInputValidationError("Empty findings chunk")

        prompt = self._build_prompt(findings)
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }

        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout_sec,
            )
            resp.raise_for_status()
            data = resp.json()
            text = data.get("response", "").strip()
            if not text:
                raise AIProviderError("Ollama returned empty response")
            return text
        except requests.Timeout as exc:
            raise AITimeoutError("Ollama request timed out") from exc
        except requests.HTTPError as exc:
            raise AIProviderError(f"Ollama HTTP error: {exc}") from exc
        except Exception as exc:
            raise AIProviderError(str(exc)) from exc

    def _build_prompt(self, findings: List[Dict]) -> str:
        lines = []
        for f in findings:
            title = f.get("title", "Unnamed issue")
            severity = f.get("severity", "UNKNOWN")
            desc = (f.get("description") or f.get("details") or "").strip()
            remediation = (f.get("remediation") or "").strip()
            location = (f.get("location") or "").strip()
            if desc:
                lines.append(
                    f"- [{severity}] {title} | location={location or 'n/a'} | "
                    f"desc={desc[:180]} | remediation_hint={remediation[:120]}"
                )
            else:
                lines.append(f"- [{severity}] {title} | location={location or 'n/a'}")

        return (
            "You are a senior application security engineer.\n"
            "Write a HUMAN-READABLE Markdown report.\n"
            "Do NOT output JSON.\n"
            "Use clear, non-jargon language where possible.\n"
            "Required sections:\n"
            "## Executive Summary\n"
            "## Top Risks\n"
            "## Recommended Remediations (step-by-step)\n"
            "## Quick Wins (this sprint)\n"
            "## Verification Checklist\n\n"
            "Findings:\n"
            + "\n".join(lines)
        )


def build_provider(provider_config: Dict[str, Any] | None = None) -> AIProvider:
    cfg = provider_config or {}
    provider_name = str(cfg.get("provider", settings.AI_PROVIDER)).lower()

    if provider_name == "gemini":
        return GeminiProvider(
            model_name=str(cfg.get("model", "gemini-2.5-flash")),
            timeout_sec=int(cfg.get("timeout_sec", settings.AI_TIMEOUT_SEC)),
        )

    return OllamaProvider(
        base_url=str(cfg.get("base_url", settings.OLLAMA_BASE_URL)),
        model=str(cfg.get("model", settings.OLLAMA_MODEL)),
        timeout_sec=int(cfg.get("timeout_sec", settings.AI_TIMEOUT_SEC)),
    )
