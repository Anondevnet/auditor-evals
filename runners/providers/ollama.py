"""Ollama provider stub (local, $0). Loopback only — no paid API."""

from __future__ import annotations

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
    ) -> Completion:
        # Cost is always 0, but still honour a cap of 0 as a dry-run lock.
        price = self.price_row(price_key)
        estimated = estimate_cost(max(1, len(prompt) // 4), max_output_tokens, price)
        self.assert_can_spend(spend_so_far, cap, estimated)

        endpoint = (self.defaults.get("endpoint") or "http://127.0.0.1:11434")
        # system entry may also carry endpoint
        host = urlparse(endpoint).hostname or ""
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ProviderError(
                f"ollama endpoint host {host!r} is not loopback; refusing to send prompts"
            )
        raise ProviderError(
            "Ollama provider is stubbed in this workstream. To run the local Qwen "
            "eval on Solana's Mac: install/start Ollama, pull the exact tag from "
            "config/models.yaml (record `ollama list`), confirm the daemon is on "
            "127.0.0.1:11434, then `make run MODEL=qwen-local`."
        )
