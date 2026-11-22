"""OpenAI-compatible provider stub. Never hardcodes keys; never calls out
unless AUDITOR_EVALS_ALLOW_PAID is set AND a key is in the environment AND
the spend cap can cover the next request.
"""

from __future__ import annotations

from .base import Completion, Provider, ProviderError, env_key, estimate_cost


class OpenAIProvider(Provider):
    name = "openai"

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
        # Conservative pre-call estimate: char/4 input + configured max output.
        est_in = max(1, len(prompt) // 4 + (len(system or "") // 4))
        estimated = estimate_cost(est_in, max_output_tokens, price)
        self.assert_can_spend(spend_so_far, cap, estimated)

        key_env = self.defaults.get("openai_key_env") or "OPENAI_API_KEY"
        if not env_key(key_env):
            raise ProviderError(f"openai: ${key_env} is not set; refusing to call a paid API")
        if not self.paid_allowed():
            raise ProviderError(
                "openai: paid calls are disabled (set AUDITOR_EVALS_ALLOW_PAID=1 to enable). "
                "This workstream does not call paid APIs."
            )
        # Even when allowed, this stub does not perform the HTTP call — a
        # later workstream will implement batch mode. Abort rather than spend.
        raise ProviderError(
            "openai: live HTTP client is not implemented in this stub; no request was sent"
        )
