
from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any

from pydantic import BaseModel

DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:latest")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")

logger = logging.getLogger(__name__)


class OllamaAuditConfig(BaseModel):
    model: str = DEFAULT_MODEL
    url: str = OLLAMA_URL
    timeout: int = 180
    temperature: float = 0.1
    max_findings: int = 25
    max_prompt_chars: int = 28000
    snippet_radius: int = 1200


class OllamaAuditResult(BaseModel):
    summary: str | None
    status: str
    error: str | None = None


class OllamaAuditClient:
    def __init__(self, config: OllamaAuditConfig | None = None) -> None:
        self.config = config or OllamaAuditConfig()

    def summarize(self, source: str, heuristic_report: dict[str, Any], model: str | None = None) -> str | None:
        return self.summarize_result(source, heuristic_report, model).summary

    def summarize_result(self, source: str, heuristic_report: dict[str, Any], model: str | None = None) -> OllamaAuditResult:
        prompt = self.build_prompt(source, heuristic_report)

        payload = {
            "model": model or self.config.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": self.config.temperature},
        }

        request = urllib.request.Request(
            self.config.url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"content-type": "application/json"},
            method="POST",
        )

        started = time.monotonic()

        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))

            logger.info(
                "ollama completed in %.2fs response_chars=%s",
                time.monotonic() - started,
                len(data.get("response", "")),
            )

            summary = data.get("response", "").strip() or None
            if not summary:
                return OllamaAuditResult(summary=None, status="empty")
            return OllamaAuditResult(summary=summary, status="done")

        except Exception as exc:
            logger.warning("ollama request failed: %s", exc)
            return OllamaAuditResult(summary=None, status="error", error=str(exc))

    def build_prompt(self, source: str, heuristic_report: dict[str, Any]) -> str:
        findings = heuristic_report.get("findings", [])[: self.config.max_findings]
        snippets = self.extract_relevant_code(source, findings)

        prompt = f"""
You are a senior Solidity security auditor.

Goals:
1. Confirm real vulnerabilities.
2. Separate public exploits from owner-only risks.
3. Detect rug-pull and honeypot indicators.
4. Identify false positives.
5. Recommend manual review.

Return sections:
- Verdict
- Externally exploitable issues
- Owner / privileged risks
- Honeypot signals
- False positives
- Manual review

Findings:
{json.dumps(findings, ensure_ascii=False, indent=2)}

Relevant code:
```solidity
{snippets}
```
"""
        return prompt[: self.config.max_prompt_chars]

    def extract_relevant_code(self, source: str, findings: list[dict[str, Any]]) -> str:
        patterns = [
            r"tx\.origin",
            r"delegatecall",
            r"selfdestruct",
            r"function\s+_transfer",
            r"function\s+transferFrom",
            r"function\s+balanceOf",
            r"function\s+manualSwap",
            r"function\s+removeStuckBalance",
            r"function\s+changeTaxes",
            r"function\s+enableTrading",
            r"\.call\s*\{[^}]*value",
            r"\.transfer\s*\(",
            r"\.send\s*\(",
        ]

        chunks: list[str] = []

        for pattern in patterns:
            for match in re.finditer(pattern, source, re.IGNORECASE):
                start = max(0, match.start() - self.config.snippet_radius)
                end = min(len(source), match.end() + self.config.snippet_radius)
                chunks.append(source[start:end])

        if not chunks:
            return source[:8000]

        return self.dedupe(chunks)

    def dedupe(self, chunks: list[str]) -> str:
        seen: set[str] = set()
        result: list[str] = []

        for chunk in chunks:
            key = re.sub(r"\s+", " ", chunk[:500])
            if key in seen:
                continue
            seen.add(key)
            result.append(chunk)

        return "\n\n".join(result)


def summarize_with_ollama(
    source: str,
    heuristic_report: dict[str, Any],
    model: str | None = None,
) -> str | None:
    return OllamaAuditClient().summarize(
        source,
        heuristic_report,
        model=model,
    )


def summarize_with_ollama_result(
    source: str,
    heuristic_report: dict[str, Any],
    model: str | None = None,
) -> OllamaAuditResult:
    return OllamaAuditClient().summarize_result(
        source,
        heuristic_report,
        model=model,
    )
