"""Anthropic provider stub. Same safety gates as the OpenAI stub."""

from __future__ import annotations

from .base import Completion, Provider, ProviderError, env_key, estimate_cost


class AnthropicProvider(Provider):
    name = "anthropic"

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
        price = self.price_row(price_key)
        multiplier = float(self.prices.get("claude_token_multiplier") or 1.0)
        est_in = max(1, len(prompt) // 4 + (len(system or "") // 4))
        estimated = estimate_cost(est_in, max_output_tokens, price, multiplier=multiplier)
        self.assert_can_spend(spend_so_far, cap, estimated)

        key_env = self.defaults.get("anthropic_key_env") or "ANTHROPIC_API_KEY"
        if not env_key(key_env):
            raise ProviderError(f"anthropic: ${key_env} is not set; refusing to call a paid API")
        if not self.paid_allowed():
            raise ProviderError(
                "anthropic: paid calls are disabled (set AUDITOR_EVALS_ALLOW_PAID=1 to enable). "
                "This workstream does not call paid APIs."
            )
        raise ProviderError(
            "anthropic: live HTTP client is not implemented in this stub; no request was sent"
        )
