"""Count installed Qwen BPE tokens using local Ollama metadata, never a hub download.

The qwen2 pre-tokenization pattern is the one in llama.cpp's llama-vocab.cpp.
https://github.com/ggml-org/llama.cpp/blob/master/src/llama-vocab.cpp
Unsupported or unavailable tokenizer metadata falls back to the UTF-8 bound.
"""

from functools import lru_cache
import httpx

QWEN2_PATTERN = r"(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+"


def from_metadata(info):
    if not isinstance(info,dict):
        return None
    if info.get("tokenizer.ggml.model") != "gpt2" or info.get("tokenizer.ggml.pre") != "qwen2":
        return None
    from tokenizers import Tokenizer,Regex,models,pre_tokenizers
    tokens,merges=info.get("tokenizer.ggml.tokens"),info.get("tokenizer.ggml.merges")
    if (not isinstance(tokens,list) or not isinstance(merges,list) or len(tokens)<256
            or len(tokens)>300000 or len(merges)>300000
            or any(not isinstance(t,str) for t in tokens+merges)):
        return None
    vocab={token:i for i,token in enumerate(tokens)}
    if len(vocab)!=len(tokens):
        return None
    try:
        tokenizer=Tokenizer(models.BPE(vocab, [tuple(merge.split(" ",1)) for merge in merges]))
        tokenizer.pre_tokenizer=pre_tokenizers.Sequence([
            pre_tokenizers.Split(Regex(QWEN2_PATTERN),behavior="isolated"),
            pre_tokenizers.ByteLevel(add_prefix_space=False,use_regex=False)])
    except Exception:  # Native tokenizer bindings can raise a generic Exception.
        return None
    return tokenizer


@lru_cache(maxsize=4)
def installed_tokenizer(endpoint,model):
    try:
        with httpx.Client(timeout=10,trust_env=False,follow_redirects=False) as client:
            response=client.post(endpoint+"/api/show",json={"model":model,"verbose":True})
            response.raise_for_status()
            envelope=response.json()
            return from_metadata(envelope.get("model_info",{})) if isinstance(envelope,dict) else None
    except (ImportError,ValueError,KeyError,TypeError,httpx.HTTPError):
        return None


def input_upper_bound(messages,endpoint,model):
    tokenizer=installed_tokenizer(endpoint,model)
    if tokenizer is None:
        return sum(len(m["content"].encode()) for m in messages)+256
    # Encode fields independently: no merges across message boundaries. Template
    # delimiters, role tokens and the generation prefix have a separate reserve.
    return sum(len(tokenizer.encode(m["content"],add_special_tokens=False).ids) for m in messages)+256
