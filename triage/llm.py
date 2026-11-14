"""Free-tier LLM client: Groq first, OpenRouter as fallback. OpenAI-compatible chat API.

Rate-limit handling: honours Retry-After on HTTP 429, exponential backoff with jitter on
429/5xx/timeouts, then falls through to the next provider. A small client-side limiter keeps
us under the free-tier requests-per-minute. Never raises to the caller: returns None when
every provider fails, and the app falls back to the deterministic answer.
"""
from __future__ import annotations

import os
import random
import threading
import time
from dataclasses import dataclass

import requests


@dataclass
class Provider:
    name: str
    url: str
    key_env: str
    model: str

    @property
    def key(self) -> str:
        return os.getenv(self.key_env, "").strip()


def providers() -> list[Provider]:
    ps = [
        Provider("groq", "https://api.groq.com/openai/v1/chat/completions", "GROQ_API_KEY",
                 os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")),
        Provider("openrouter", "https://openrouter.ai/api/v1/chat/completions", "OPENROUTER_API_KEY",
                 os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-20b:free")),
    ]
    return [p for p in ps if p.key]


class _Limiter:
    def __init__(self, per_min: int) -> None:
        self.gap = 60.0 / max(per_min, 1)
        self.next = 0.0
        self.lock = threading.Lock()

    def wait(self) -> None:
        with self.lock:
            now = time.monotonic()
            delay = max(0.0, self.next - now)
            self.next = max(now, self.next) + self.gap
        if delay:
            time.sleep(delay)


_LIMIT = _Limiter(int(os.getenv("LLM_RPM", "25")))
last_error = ""


def chat(messages: list[dict], max_tokens: int = 900, temperature: float = 0.0, retries: int = 3) -> tuple[str, str] | None:
    """Returns (text, 'provider/model') or None."""
    global last_error
    for p in providers():
        for attempt in range(retries):
            _LIMIT.wait()
            try:
                r = requests.post(p.url, timeout=45, headers={"Authorization": f"Bearer {p.key}", "Content-Type": "application/json"},
                                  json={"model": p.model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens})
            except requests.RequestException as e:
                last_error = f"{p.name}: {type(e).__name__}"
                time.sleep(min(8, 2 ** attempt) + random.random())
                continue
            if r.status_code == 200:
                try:
                    text = r.json()["choices"][0]["message"]["content"] or ""
                except (ValueError, KeyError, IndexError):
                    last_error = f"{p.name}: malformed response"
                    break
                if text.strip():
                    return text.strip(), f"{p.name}/{p.model}"
                last_error = f"{p.name}: empty response"
                break
            last_error = f"{p.name}: HTTP {r.status_code} {r.text[:160]}"
            if r.status_code == 429 or r.status_code >= 500:
                ra = r.headers.get("retry-after")
                try:
                    wait = float(ra) if ra else 2 ** attempt
                except ValueError:
                    wait = 2 ** attempt
                if wait > 20:                 # a long ban: try the next provider instead
                    break
                time.sleep(wait + random.random())
                continue
            break                             # 4xx other than 429: config problem, next provider
    return None


def available() -> bool:
    return bool(providers())
