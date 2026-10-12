"""Google Gemini Flash AI reasoning provider."""
import time
from typing import Any, Dict, List, Optional

from bharydangerous.ai.base import BaseAIProvider, AIProviderResponse
from bharydangerous.ai.consent import extract_and_verify_cited_finding_ids
from bharydangerous.ai.prompt_templates import (
    SYSTEM_INSTRUCTION,
    build_finding_explanation_prompt,
    build_investigation_summary_prompt,
    build_next_steps_prompt,
)
from bharydangerous.ai.redactor import redact_sensitive_data
from bharydangerous.core.config import get_gemini_api_key, get_gemini_model
from bharydangerous.core.exceptions import AIProviderError
from bharydangerous.core.models import FindingRecord, TimelineEventRecord

class GeminiProvider(BaseAIProvider):
    """Forensic AI provider using the Google Gemini Developer API SDK."""

    def __init__(self, api_key: Optional[str] = None, model_name: Optional[str] = None):
        self.api_key = api_key or get_gemini_api_key()
        self.model_name = model_name or get_gemini_model()
        self._client = None

        if not self.api_key:
            raise AIProviderError(
                "Gemini API key not found. Set GEMINI_API_KEY environment variable or run 'bdinvestigator config set-api-key <KEY>'."
            )

        try:
            from google import genai
            self._client = genai.Client(api_key=self.api_key)
        except ImportError:
            raise AIProviderError(
                "The 'google-genai' SDK is not installed. Run 'pip install google-genai' to enable Gemini reasoning."
            )
        except Exception as exc:
            raise AIProviderError(f"Failed to initialize Gemini Client: {redact_sensitive_data(str(exc))}")

    def explain_finding(self, finding: FindingRecord, context_events: List[TimelineEventRecord]) -> AIProviderResponse:
        prompt = build_finding_explanation_prompt(finding, context_events)
        response_text = self._generate_with_retry(prompt)
        cited_ids = extract_and_verify_cited_finding_ids(response_text, {finding.finding_id})
        return AIProviderResponse(text=response_text, model_name=self.model_name, cited_finding_ids=cited_ids)

    def summarize_investigation(
        self, case_name: str, findings: List[FindingRecord], timeline_events: List[TimelineEventRecord]
    ) -> AIProviderResponse:
        prompt = build_investigation_summary_prompt(case_name, findings, timeline_events)
        response_text = self._generate_with_retry(prompt)
        valid_ids = {f.finding_id for f in findings}
        cited_ids = extract_and_verify_cited_finding_ids(response_text, valid_ids)
        return AIProviderResponse(text=response_text, model_name=self.model_name, cited_finding_ids=cited_ids)

    def suggest_next_steps(self, findings: List[FindingRecord]) -> AIProviderResponse:
        prompt = build_next_steps_prompt(findings)
        response_text = self._generate_with_retry(prompt)
        valid_ids = {f.finding_id for f in findings}
        cited_ids = extract_and_verify_cited_finding_ids(response_text, valid_ids)
        return AIProviderResponse(text=response_text, model_name=self.model_name, cited_finding_ids=cited_ids)

    def _generate_with_retry(self, user_prompt: str, max_retries: int = 3) -> str:
        """Call Gemini API with system instructions, timeouts, and bounded backoff."""
        from google.genai import types

        config = types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            temperature=0.2,  # Low temperature for deterministic forensic reasoning
            max_output_tokens=4096,
        )

        last_error = None
        for attempt in range(max_retries):
            try:
                response = self._client.models.generate_content(
                    model=self.model_name,
                    contents=user_prompt,
                    config=config,
                )
                if response and response.text:
                    return response.text
                return "AI provider returned empty response."
            except Exception as exc:
                last_error = exc
                err_str = str(exc).lower()
                # Check for rate limit or transient error
                if "429" in err_str or "quota" in err_str or "resource_exhausted" in err_str:
                    time.sleep(2 ** attempt + 1)
                    continue
                elif "timeout" in err_str or "503" in err_str or "unavailable" in err_str:
                    time.sleep(2 ** attempt + 1)
                    continue
                else:
                    raise AIProviderError(f"Gemini API generation error: {redact_sensitive_data(str(exc))}")

        raise AIProviderError(f"Gemini API request failed after {max_retries} attempts: {redact_sensitive_data(str(last_error))}")
