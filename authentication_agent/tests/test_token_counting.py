"""Local tokenizer construction and conservative fallback require no network/model."""

from tokenizers.pre_tokenizers import ByteLevel
from authentication_agent.llm import token_counting as T


def metadata():
    return {"tokenizer.ggml.model":"gpt2","tokenizer.ggml.pre":"qwen2",
        "tokenizer.ggml.tokens":sorted(ByteLevel.alphabet())+["ab"],"tokenizer.ggml.merges":["a b"]}


def test_installed_bpe_vocab_and_merges_are_used_without_any_hub_access():
    tokenizer=T.from_metadata(metadata())
    assert len(tokenizer.encode("abc",add_special_tokens=False).ids)==2
    assert len(tokenizer.encode("123",add_special_tokens=False).ids)==3


def test_unknown_or_malformed_tokenizer_metadata_is_not_used():
    assert T.from_metadata({}) is None
    m=metadata();m["tokenizer.ggml.merges"]=["invalid merge references"]
    assert T.from_metadata(m) is None


def test_fallback_remains_a_utf8_upper_bound_with_template_reserve(monkeypatch):
    monkeypatch.setattr(T,"installed_tokenizer",lambda *a:None)
    messages=[{"role":"user","content":"中文 🙂"}]
    assert T.input_upper_bound(messages,"http://127.0.0.1:1","missing")==len("中文 🙂".encode())+256
