"""
services/ollama_client.py — Async wrapper around the Ollama REST API.

The Ollama server runs on the HOST machine (not in Docker) and is reachable
from inside the backend container via http://host.docker.internal:11434.

Usage:
    from services.ollama_client import call_ollama

    response_text = await call_ollama(
        messages=[
            {"role": "system", "content": "You are a security analyst."},
            {"role": "user",   "content": "Investigate this incident: ..."},
        ],
        model="llama3.1:8b",
    )
"""

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Ollama is on the host; host.docker.internal resolves from inside Docker.
# On Linux, host.docker.internal may not be set automatically — we also
# fall back to the host gateway IP 172.17.0.1 which is the default Docker
# bridge gateway, or allow override via OLLAMA_HOST env var.
import os

_OLLAMA_BASE = os.environ.get("OLLAMA_HOST", "http://host.docker.internal:11434")
_DEFAULT_MODEL = "llama3.1:8b"
_REQUEST_TIMEOUT = 120.0   # seconds — LLM inference can be slow


async def call_ollama(
    messages: list[dict],
    model: str = _DEFAULT_MODEL,
    temperature: float = 0.1,
) -> str:
    """
    Send a chat request to Ollama and return the assistant's response text.

    Args:
        messages:    List of {"role": "system"|"user"|"assistant", "content": str}.
        model:       Ollama model name (default: llama3.1:8b).
        temperature: Sampling temperature — low (0.1) for deterministic analysis.

    Returns:
        The assistant message content as a plain string.

    Raises:
        RuntimeError: If Ollama is unreachable or returns an error.
    """
    url = f"{_OLLAMA_BASE}/api/chat"
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": 1024,   # cap tokens to avoid runaway responses
        },
    }

    logger.info("Calling Ollama model=%s url=%s", model, url)

    try:
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
    except httpx.ConnectError as exc:
        raise RuntimeError(
            f"Cannot reach Ollama at {_OLLAMA_BASE}. "
            "Is Ollama running on the host? Run: ollama serve"
        ) from exc
    except httpx.TimeoutException as exc:
        raise RuntimeError(
            f"Ollama request timed out after {_REQUEST_TIMEOUT}s. "
            "The model may be loading — try again in a moment."
        ) from exc
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(
            f"Ollama returned HTTP {exc.response.status_code}: {exc.response.text}"
        ) from exc

    data = response.json()

    # Ollama /api/chat response shape:
    # {"model": "...", "message": {"role": "assistant", "content": "..."}, ...}
    try:
        content = data["message"]["content"]
    except (KeyError, TypeError) as exc:
        raise RuntimeError(
            f"Unexpected Ollama response shape: {data}"
        ) from exc

    logger.info(
        "Ollama responded: model=%s tokens_eval=%s",
        model,
        data.get("eval_count", "?"),
    )

    return content


async def check_ollama_health() -> dict:
    """
    Quick health check — returns model list or an error dict.
    Useful for the /health endpoint to report Ollama status.
    """
    url = f"{_OLLAMA_BASE}/api/tags"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            models = [m["name"] for m in data.get("models", [])]
            return {"status": "ok", "models": models}
    except Exception as exc:  # noqa: BLE001
        return {"status": "unreachable", "error": str(exc)}
