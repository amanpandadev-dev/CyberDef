"""
Base Agent

Abstract base class and Ollama client for AI agents.
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from typing import Any, TypeVar, Generic
from uuid import UUID

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
            "options": {
                "temperature": temp,
                "num_predict": 2048,
            },
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        try:
            response = await self._client.post(
                f"{self.host}/api/generate",
                json=payload,
            )
            response.raise_for_status()
            
            result = response.json()
            return result.get("response", "")
            
        except httpx.HTTPError as e:
            logger.error(f"Ollama API error | error={e}")
            raise AgentError(
                f"Ollama API error: {str(e)}",
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
        system_prompt = f"{self.BASE_SYSTEM_PROMPT}\n\n{self.agent_system_prompt}"
        user_prompt = self.build_prompt(summary)
        
        logger.debug(f"Agent invocation | agent={self.name}, chunk_id={chunk_id}")
        
        try:
            # Call Ollama
            response = await self.client.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
            )
            
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
        """Parse JSON from agent response."""
        # Clean up response
        text = response.strip()
        
        # Try to extract JSON from markdown code blocks
        if "```json" in text:
            start = text.find("```json") + 7
            end = text.find("```", start)
            if end > start:
                text = text[start:end].strip()
        elif "```" in text:
            start = text.find("```") + 3
            end = text.find("```", start)
            if end > start:
                text = text[start:end].strip()
        
        # Try to parse as JSON
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON object in text
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass
        
        raise AgentError(
            "Failed to parse JSON from agent response",
            agent_name=self.name,
            raw_output=text[:500],
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
