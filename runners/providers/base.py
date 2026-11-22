"""Provider interface and spend-cap helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional


class ProviderError(RuntimeError):
    pass


class SpendCapExceeded(ProviderError):
    pass


@dataclass
class Completion:
    text: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    latency_s: float
    model: str
    raw: dict = field(default_factory=dict)


def env_key(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    val = os.environ.get(name, "").strip()
    return val or None


def estimate_cost(input_tokens: int, output_tokens: int, price: dict, *, multiplier: float = 1.0) -> float:
    inp = float(price.get("input_per_million") or 0.0)
    out = float(price.get("output_per_million") or 0.0)
    it = input_tokens * multiplier
    ot = output_tokens * multiplier
    return (it / 1_000_000.0) * inp + (ot / 1_000_000.0) * out


class Provider:
    name = "base"

    def __init__(self, config: dict, prices: dict):
        self.config = config
        self.prices = prices
        self.defaults = (config.get("defaults") or {}) if "defaults" in config else config

    def price_row(self, price_key: str) -> dict:
        models = (self.prices.get("models") or self.prices)
        if price_key not in models:
            raise ProviderError(f"no price row for {price_key!r}")
        return models[price_key]

    def remaining(self, spend_so_far: float, cap: float) -> float:
        return cap - spend_so_far

    def assert_can_spend(self, spend_so_far: float, cap: float, estimated: float) -> None:
        """Abort *before* a call if this request would exceed the cap."""
        if estimated < 0:
            estimated = 0.0
        if spend_so_far + estimated > cap + 1e-12:
            raise SpendCapExceeded(
                f"{self.name}: spend cap ${cap:.4f} would be exceeded "
                f"(spent ${spend_so_far:.4f} + estimate ${estimated:.4f})"
            )

    def paid_allowed(self) -> bool:
        flag = self.defaults.get("allow_paid_env") or "AUDITOR_EVALS_ALLOW_PAID"
        return os.environ.get(flag, "").strip() in {"1", "true", "TRUE", "yes"}

    def complete(
        self,
        prompt: str,
        *,
        model: str,
        price_key: str,
        spend_so_far: float,
        cap: float,
        max_output_tokens: int,
        system: Optional[str] = None,
    ) -> Completion:
        raise NotImplementedError
