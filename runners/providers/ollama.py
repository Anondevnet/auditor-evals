"""Ollama provider (local, $0). Loopback only — no paid API."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from .base import Completion, Provider, ProviderError, estimate_cost


class OllamaProvider(Provider):
    name = "ollama"

    def complete(
        self,
        prompt: str,
        *,
        model: str,
        price_key: str,
        spend_so_far: float,
        cap: float,
        max_output_tokens: int,
        system=None,
        timeout: float | None = 180.0,
    ) -> Completion:
        # Local inference is $0, but still honour a cap of 0 as a dry-run lock.
        price = self.price_row(price_key)
        estimated = estimate_cost(max(1, len(prompt) // 4), max_output_tokens, price)
        self.assert_can_spend(spend_so_far, cap, estimated)

        endpoint = (self.defaults.get("endpoint") or "http://127.0.0.1:11434")
        host = urlparse(endpoint).hostname or ""
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ProviderError(
                f"ollama endpoint host {host!r} is not loopback; refusing to send prompts"
            )

        url = endpoint.rstrip("/") + "/api/chat"
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": float(self.defaults.get("temperature") or 0.0),
                "num_predict": int(max_output_tokens),
            },
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:400]
            raise ProviderError(f"ollama HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise ProviderError(f"ollama unreachable at {endpoint}: {exc.reason}") from exc
        latency = time.monotonic() - t0

        text = ""
        if isinstance(body, dict):
            msg = body.get("message") or {}
            if isinstance(msg, dict):
                text = str(msg.get("content") or "")
            if not text:
                text = str(body.get("response") or "")
        in_tok = int((body or {}).get("prompt_eval_count") or 0)
        out_tok = int((body or {}).get("eval_count") or 0)
        return Completion(
            text=text,
            input_tokens=in_tok,
            output_tokens=out_tok,
            cost_usd=0.0,
            latency_s=latency,
            model=model,
            raw={"endpoint": endpoint},
        )
