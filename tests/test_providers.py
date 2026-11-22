from runners.providers.anthropic import AnthropicProvider
from runners.providers.base import SpendCapExceeded, estimate_cost
from runners.providers.ollama import OllamaProvider
from runners.providers.openai import OpenAIProvider

PRICES = {
    "claude_token_multiplier": 1.3,
    "models": {
        "gpt-6.1-sol": {"input_per_million": 2.0, "output_per_million": 10.0},
        "claude-haiku-5.5": {"input_per_million": 0.10, "output_per_million": 0.50},
        "qwen-local": {"input_per_million": 0.0, "output_per_million": 0.0},
    },
}
CFG = {"defaults": {
    "allow_paid_env": "AUDITOR_EVALS_ALLOW_PAID",
    "openai_key_env": "OPENAI_API_KEY",
    "anthropic_key_env": "ANTHROPIC_API_KEY",
    "endpoint": "http://127.0.0.1:11434",
}}


def test_spend_cap_aborts_before_call(monkeypatch):
    monkeypatch.delenv("AUDITOR_EVALS_ALLOW_PAID", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")
    p = OpenAIProvider(CFG, PRICES)
    with __import__("pytest").raises(SpendCapExceeded):
        p.complete("hello world " * 100, model="gpt-6.1-sol", price_key="gpt-6.1-sol",
                   spend_so_far=14.99, cap=15.0, max_output_tokens=1500)


def test_openai_refuses_without_key_and_without_allow(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("AUDITOR_EVALS_ALLOW_PAID", raising=False)
    p = OpenAIProvider(CFG, PRICES)
    with __import__("pytest").raises(Exception, match="OPENAI_API_KEY"):
        p.complete("hi", model="gpt-6.1-sol", price_key="gpt-6.1-sol",
                   spend_so_far=0, cap=15, max_output_tokens=10)


def test_openai_refuses_paid_flag(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")
    monkeypatch.delenv("AUDITOR_EVALS_ALLOW_PAID", raising=False)
    p = OpenAIProvider(CFG, PRICES)
    with __import__("pytest").raises(Exception, match="paid calls are disabled"):
        p.complete("hi", model="gpt-6.1-sol", price_key="gpt-6.1-sol",
                   spend_so_far=0, cap=15, max_output_tokens=10)


def test_anthropic_refuses_similarly(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-real")
    monkeypatch.delenv("AUDITOR_EVALS_ALLOW_PAID", raising=False)
    p = AnthropicProvider(CFG, PRICES)
    with __import__("pytest").raises(Exception, match="paid calls are disabled"):
        p.complete("hi", model="claude-haiku-5.5", price_key="claude-haiku-5.5",
                   spend_so_far=0, cap=15, max_output_tokens=10)


def test_ollama_refuses_non_loopback_and_is_stubbed():
    p = OllamaProvider({"defaults": {**CFG["defaults"], "endpoint": "https://example.com"}}, PRICES)
    with __import__("pytest").raises(Exception, match="not loopback"):
        p.complete("hi", model="qwen", price_key="qwen-local",
                   spend_so_far=0, cap=15, max_output_tokens=10)
    p = OllamaProvider(CFG, PRICES)
    with __import__("pytest").raises(Exception, match="stubbed"):
        p.complete("hi", model="qwen", price_key="qwen-local",
                   spend_so_far=0, cap=15, max_output_tokens=10)


def test_estimate_cost():
    assert estimate_cost(1_000_000, 0, PRICES["models"]["gpt-6.1-sol"]) == 2.0
