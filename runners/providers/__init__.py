"""LLM provider stubs.

Paid providers never make an HTTP call unless AUDITOR_EVALS_ALLOW_PAID is set,
a key is present in the environment, and the remaining spend cap can cover the
estimated cost of the next request. There are no hardcoded keys.
"""

from .base import Provider, ProviderError, SpendCapExceeded, Completion
from .ollama import OllamaProvider
from .openai import OpenAIProvider
from .anthropic import AnthropicProvider

__all__ = [
    "Provider", "ProviderError", "SpendCapExceeded", "Completion",
    "OllamaProvider", "OpenAIProvider", "AnthropicProvider", "get_provider",
]


def get_provider(name: str, config: dict, prices: dict) -> "Provider":
    name = name.lower()
    if name == "ollama":
        return OllamaProvider(config, prices)
    if name == "openai":
        return OpenAIProvider(config, prices)
    if name == "anthropic":
        return AnthropicProvider(config, prices)
    raise ProviderError(f"unknown provider {name!r}")
