"""Secret and PII redactor to prevent data leakage in AI prompts."""
import re

PATTERNS = [
    # Google API Key
    (re.compile(r"AIza[0-9A-Za-z\-_]{20,}"), "[REDACTED_GOOGLE_API_KEY]"),
    # GitHub Token
    (re.compile(r"gh[pousr]_[0-9A-Za-z]{36,255}"), "[REDACTED_GITHUB_TOKEN]"),
    # AWS Access Key
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    # Generic Private Key
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    # Password parameters
    (re.compile(r'(?i)\b(password|passwd|pwd|secret)\b\s*[:=]\s*["\']?([^"\'\s&]+)["\']?'), r"\1=[REDACTED_PASSWORD]"),
    # Basic Auth Base64
    (re.compile(r"(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]+"), "Authorization: Basic [REDACTED_CREDENTIAL]"),
    # Credit Card
    (re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"), "[REDACTED_CREDIT_CARD]"),
]

def redact_sensitive_data(text: str) -> str:
    """Sanitize sensitive secrets, keys, and tokens from text before egress."""
    redacted = text
    for pattern, replacement in PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted
