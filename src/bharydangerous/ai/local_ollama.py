"""Local OpenAI-compatible AI adapter (e.g., Ollama, vLLM, LM Studio)."""
import json
from typing import List, Optional
import urllib.request
import urllib.error

from bharydangerous.ai.base import BaseAIProvider, AIProviderResponse
from bharydangerous.ai.consent import extract_and_verify_cited_finding_ids
from bharydangerous.ai.prompt_templates import (
    SYSTEM_INSTRUCTION,
    build_finding_explanation_prompt,
    build_investigation_summary_prompt,
    build_next_steps_prompt,
)
from bharydangerous.core.config import get_local_ai_url
from bharydangerous.core.exceptions import AIProviderError
from bharydangerous.core.models import FindingRecord, TimelineEventRecord

class LocalOllamaProvider(BaseAIProvider):
    """Provider for air-gapped, on-prem local models via OpenAI-compatible endpoints."""

    def __init__(self, endpoint_url: Optional[str] = None, model_name: str = "llama3:latest"):
        self.endpoint_url = (endpoint_url or get_local_ai_url()).rstrip("/") + "/chat/completions"
        self.model_name = model_name

    def explain_finding(self, finding: FindingRecord, context_events: List[TimelineEventRecord]) -> AIProviderResponse:
        prompt = build_finding_explanation_prompt(finding, context_events)
        response_text = self._chat_completion(prompt)
        cited_ids = extract_and_verify_cited_finding_ids(response_text, {finding.finding_id})
        return AIProviderResponse(text=response_text, model_name=self.model_name, cited_finding_ids=cited_ids)

    def summarize_investigation(
        self, case_name: str, findings: List[FindingRecord], timeline_events: List[TimelineEventRecord]
    ) -> AIProviderResponse:
        prompt = build_investigation_summary_prompt(case_name, findings, timeline_events)
        response_text = self._chat_completion(prompt)
        valid_ids = {f.finding_id for f in findings}
        cited_ids = extract_and_verify_cited_finding_ids(response_text, valid_ids)
        return AIProviderResponse(text=response_text, model_name=self.model_name, cited_finding_ids=cited_ids)

    def suggest_next_steps(self, findings: List[FindingRecord]) -> AIProviderResponse:
        prompt = build_next_steps_prompt(findings)
        response_text = self._chat_completion(prompt)
        valid_ids = {f.finding_id for f in findings}
        cited_ids = extract_and_verify_cited_finding_ids(response_text, valid_ids)
        return AIProviderResponse(text=response_text, model_name=self.model_name, cited_finding_ids=cited_ids)

    def _chat_completion(self, user_prompt: str) -> str:
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": SYSTEM_INSTRUCTION},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                return res_data["choices"][0]["message"]["content"]
        except urllib.error.URLError as exc:
            raise AIProviderError(f"Failed to communicate with local AI endpoint ({self.endpoint_url}): {exc}")
        except Exception as exc:
            raise AIProviderError(f"Local AI parsing error: {exc}")
