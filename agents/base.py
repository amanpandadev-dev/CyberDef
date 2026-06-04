"""
Base Agent

Abstract base class and Ollama client for AI agents.
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar
from uuid import UUID

# pyrefly: ignore [missing-import]
import httpx
from pydantic import BaseModel, ValidationError

from core.config import get_settings
from core.exceptions import AgentError
from core.logging import get_logger

logger = get_logger(__name__)

# Type variable for agent output types
T = TypeVar("T", bound=BaseModel)


class OllamaClient:
    """
    Client for Ollama API communication.

    Handles all LLM inference requests locally via Ollama.
    """

    def __init__(
        self,
        host: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
    ):
        settings = get_settings()
        self.host = host or settings.ollama_host
        self.model = model or settings.ollama_model
        self.timeout = timeout or settings.ollama_timeout
        self.temperature = settings.ollama_temperature
        self.num_ctx = settings.ollama_num_ctx
        self.num_predict = settings.ollama_num_predict

        self._client = httpx.AsyncClient(timeout=self.timeout)

    async def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float | None = None,
    ) -> str:
        """
        Generate a response from Ollama.

        Args:
            prompt: User prompt
            system_prompt: System prompt for role/context
            temperature: Temperature override (must be <= 0.2)

        Returns:
            Generated response text
        """
        temp = temperature if temperature is not None else self.temperature

        # Enforce low temperature for determinism
        if temp > 0.2:
            logger.warning(f"Temperature clamped to 0.2 for determinism | requested={temp}")
            temp = 0.2

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": temp,
                "num_ctx": self.num_ctx,
                "num_predict": self.num_predict,
            },
        }

        if system_prompt:
            payload["system"] = system_prompt

        settings = get_settings()
        last_error: httpx.HTTPError | None = None
        for attempt in range(1, settings.agent_max_retries + 1):
            try:
                response = await self._client.post(
                    f"{self.host}/api/generate",
                    json=payload,
                )
                response.raise_for_status()

                result = response.json()
                return result.get("response", "")

            except httpx.HTTPError as e:
                last_error = e
                logger.warning(
                    f"Ollama API attempt failed | attempt={attempt}, "
                    f"max_attempts={settings.agent_max_retries}, error={e}"
                )

        logger.error(f"Ollama API error | error={last_error}")
        raise AgentError(
            f"Ollama API error: {str(last_error)}",
            details={"host": self.host, "model": self.model},
        )

    async def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float | None = None,
    ) -> str:
        """
        Chat-style interaction with Ollama.

        Args:
            messages: List of message dicts with 'role' and 'content'
            temperature: Temperature override

        Returns:
            Assistant response text
        """
        temp = temperature if temperature is not None else self.temperature

        if temp > 0.2:
            temp = 0.2

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temp,
                "num_ctx": self.num_ctx,
                "num_predict": self.num_predict,
            },
        }

        try:
            response = await self._client.post(
                f"{self.host}/api/chat",
                json=payload,
            )
            response.raise_for_status()

            result = response.json()
            return result.get("message", {}).get("content", "")

        except httpx.HTTPError as e:
            logger.error(f"Ollama chat error | error={e}")
            raise AgentError(f"Ollama chat error: {str(e)}")

    async def health_check(self) -> bool:
        """Check if Ollama is available."""
        try:
            response = await self._client.get(f"{self.host}/api/tags")
            return response.status_code == 200
        except Exception:
            return False

    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()


class BaseAgent(ABC, Generic[T]):
    """
    Abstract base class for AI agents.

    Each agent:
    - Receives structured behavioral summaries (never raw data)
    - Returns strict JSON with confidence scores
    - Uses low temperature for determinism
    """

    name: str = "base"
    description: str = "Base agent"

    # System prompt used for all agents
    BASE_SYSTEM_PROMPT = """You are a cybersecurity intelligence agent.

CRITICAL RULES:
1. Input is structured behavioral summaries only - NOT raw logs
2. Do NOT analyze raw logs or invent data
3. Do NOT hallucinate or make up facts
4. Return ONLY valid JSON - no markdown, no explanation
5. Always include confidence scores (0.0 to 1.0)
6. Be conservative - low confidence is acceptable
7. Your analysis must be based ONLY on the provided data

You will receive a JSON object describing observed network behavior.
Analyze it and respond with the specified JSON format."""

    # Agent-specific system prompt addition
    agent_system_prompt: str = ""

    # Output schema class
    output_schema: type[T]

    def __init__(self, client: OllamaClient | None = None):
        self.client = client or OllamaClient()
        self.invocations = 0
        self.errors = 0

    @abstractmethod
    def build_prompt(self, summary: dict[str, Any]) -> str:
        """
        Build the user prompt for this agent.

        Args:
            summary: ChunkSummary as dictionary

        Returns:
            Formatted prompt string
        """
        pass

    @abstractmethod
    def get_output_schema_description(self) -> str:
        """
        Get the expected output JSON schema description.

        Returns:
            Description of expected output format
        """
        pass

    async def analyze(
        self,
        summary: dict[str, Any],
        chunk_id: UUID,
    ) -> T:
        """
        Analyze a behavioral summary.

        Args:
            summary: ChunkSummary as dictionary
            chunk_id: ID of the source chunk

        Returns:
            Typed agent output
        """
        start_time = time.time()
        self.invocations += 1

        # Build prompts
        schema_desc = self.get_output_schema_description()
        system_prompt = f"{self.BASE_SYSTEM_PROMPT}\n\n{self.agent_system_prompt}\n\nEXPECTED JSON SCHEMA:\n{schema_desc}"
        user_prompt = self.build_prompt(summary)

        logger.debug(f"Agent invocation | agent={self.name}, chunk_id={chunk_id}")
        logger.info(f"--- [AGENT: {self.name}] SYSTEM PROMPT ---\n{system_prompt}\n-----------------------------------------")
        logger.info(f"--- [AGENT: {self.name}] USER PROMPT ---\n{user_prompt}\n---------------------------------------")

        try:
            # Call Ollama
            response = await self.client.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
            )
            
            logger.info(f"--- [AGENT: {self.name}] RAW LLM RESPONSE ---\n{response}\n--------------------------------------------")

            # Parse JSON response
            parsed = self._parse_json_response(response)

            # Add metadata
            parsed["chunk_id"] = str(chunk_id)
            parsed["agent_name"] = self.name
            parsed["model_used"] = self.client.model
            parsed["temperature"] = self.client.temperature
            parsed["processing_time_ms"] = int((time.time() - start_time) * 1000)

            # Validate against schema
            result = self.output_schema.model_validate(parsed)

            logger.info(f"Agent analysis complete | agent={self.name}, chunk_id={chunk_id}, confidence={parsed.get('confidence', 0)}, time_ms={parsed['processing_time_ms']}")

            return result

        except ValidationError as e:
            self.errors += 1
            logger.error(f"Agent output validation failed | agent={self.name}, error={e}")
            raise AgentError(
                f"Output validation failed: {str(e)}",
                agent_name=self.name,
                chunk_id=str(chunk_id),
            )
        except Exception as e:
            self.errors += 1
            logger.error(f"Agent analysis failed | agent={self.name}, error={e}")
            raise AgentError(
                f"Analysis failed: {str(e)}",
                agent_name=self.name,
                chunk_id=str(chunk_id),
            )

    def _parse_json_response(self, response: str) -> dict[str, Any]:
        """
        Parse JSON from agent response with robust fallback handling.

        Handles common LLM output quirks:
        - Markdown code fences (```json ... ```)
        - Preamble/postamble text around the JSON object
        - Nested braces (correct brace-depth scanning)
        - Trailing commas before } or ]
        - Bare null / true / false tokens outside strings
        - Truncated responses
        """
        import re

        text = response.strip()

        # ── 1. Strip markdown code fences ────────────────────────────────────
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if fence_match:
            text = fence_match.group(1).strip()

        # ── 2. First attempt: parse the cleaned text directly ─────────────────
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # ── 3. Find the outermost JSON object using brace-depth scanning ──────
        #    This correctly handles nested objects/arrays.
        extracted: str | None = None
        brace_start = text.find("{")
        if brace_start >= 0:
            depth = 0
            in_string = False
            escape_next = False
            for i, ch in enumerate(text[brace_start:], start=brace_start):
                if escape_next:
                    escape_next = False
                    continue
                if ch == "\\" and in_string:
                    escape_next = True
                    continue
                if ch == '"':
                    in_string = not in_string
                    continue
                if in_string:
                    continue
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        extracted = text[brace_start : i + 1]
                        break

        if extracted:
            try:
                return json.loads(extracted)
            except json.JSONDecodeError:
                pass

            # ── 4. Auto-fix common LLM formatting errors and retry ────────────
            fixed = extracted
            # Remove trailing commas before } or ]
            fixed = re.sub(r",\s*([}\]])", r"\1", fixed)
            # Replace bare None / True / False (Python-style) with JSON equivalents
            fixed = re.sub(r"\bNone\b", "null", fixed)
            fixed = re.sub(r"\bTrue\b", "true", fixed)
            fixed = re.sub(r"\bFalse\b", "false", fixed)
            try:
                return json.loads(fixed)
            except json.JSONDecodeError:
                pass

        # ── 5. Give up — log the raw response to aid debugging ────────────────
        preview = (text[:600] + "…") if len(text) > 600 else text
        logger.error(
            f"JSON parse failed after all fallbacks | agent={self.name} | "
            f"raw_response_preview={preview!r}"
        )
        raise AgentError(
            "Failed to parse JSON from agent response",
            agent_name=self.name,
            raw_output=text[:600],
        )

    def get_stats(self) -> dict[str, Any]:
        """Get agent statistics."""
        return {
            "agent": self.name,
            "invocations": self.invocations,
            "errors": self.errors,
            "success_rate": (
                (self.invocations - self.errors) / self.invocations
                if self.invocations > 0 else 0
            ),
        }
