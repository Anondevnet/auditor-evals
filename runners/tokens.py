"""Local tokenizer estimates. No API calls."""

from __future__ import annotations

from typing import Optional

_ENC = None
_ENC_NAME = None


def get_encoder():
    global _ENC, _ENC_NAME
    if _ENC is not None:
        return _ENC, _ENC_NAME
    try:
        import tiktoken
        for name in ("o200k_base", "cl100k_base"):
            try:
                _ENC = tiktoken.get_encoding(name)
                _ENC_NAME = name
                return _ENC, _ENC_NAME
            except Exception:
                continue
    except ImportError:
        pass
    _ENC = None
    _ENC_NAME = "char4"
    return None, _ENC_NAME


def count_tokens(text: str) -> int:
    enc, name = get_encoder()
    if enc is None:
        return max(1, (len(text) + 3) // 4)
    return len(enc.encode(text))


def encoding_name() -> str:
    get_encoder()
    return _ENC_NAME or "char4"
