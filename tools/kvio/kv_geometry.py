# SPDX-License-Identifier: Apache-2.0
"""KV-cache byte geometry for real model configs.

Python port of the size math in ``examples/kv_cache_calculator`` (the web
calculator's ``kv_cache_calculator.html``), sharing its ``modelconfig.json``.
Given a model config and a token count it returns the KV-cache byte size,
handling the four families the calculator supports:

  * default (MHA / GQA): ``2 * layers * tokens * kv_heads * head_size`` where
    ``head_size = hidden_size / num_attention_heads``;
  * GQA with an explicit ``head_dim`` (Qwen3, GLM-4.x, Hunyuan dense):
    ``2 * layers * tokens * kv_heads * head_dim``;
  * DeepSeek MLA (V3/V3.1/V3.2, R1): a single latent, no factor of two, no
    kv-head axis -- ``layers * tokens * (kv_lora_rank + qk_rope_head_dim)``;
  * Hunyuan-Large CLA: ``2 * (layers / cla_share_factor) * tokens * kv_heads *
    head_size`` (every ``cla_share_factor`` layers share one KV cache).

This is the geometry the IO workload generator uses to size fake KV blocks from
real model dimensions -- see ``run_kv_offload_io.py``.
"""
from __future__ import annotations

DTYPE_BYTES = {
    "float32": 4,
    "float16": 2,
    "bfloat16": 2,
    "int8": 1,
    # storage codecs sometimes offload V at 1 byte; accept the common spellings
    "fp8": 1,
    "float8": 1,
}


def model_family(model_name: str) -> str:
    """Classify a model name into a KV-geometry family (mirrors the calculator)."""
    m = model_name
    ml = model_name.lower()
    if m.startswith("deepseek-ai/DeepSeek-V3") or m == "deepseek-ai/DeepSeek-R1":
        return "mla"
    if ml == "tencent/hunyuan-large":
        return "cla"
    if (
        "qwen/qwen3-" in ml
        or m.startswith("zai-org/GLM-4.")
        or (ml.startswith("tencent/hunyuan-") and ml != "tencent/hunyuan-large")
    ):
        return "gqa_head_dim"
    return "default"


def resolve_family(model_name: str, config: dict) -> str:
    """Family used for the byte math.

    The calculator's name rules come first, so every shipped catalog model keeps
    its exact classification. For an arbitrary model whose name matches no known
    pattern (the HF-config fallback path) fall back to config signals: an MLA
    latent (``kv_lora_rank`` + ``qk_rope_head_dim``), Hunyuan CLA sharing
    (``cla_share_factor``), or an explicit ``head_dim`` that differs from
    ``hidden_size / num_attention_heads`` (Qwen3/GLM-style GQA).
    """
    fam = model_family(model_name)
    if fam != "default":
        return fam
    if config.get("kv_lora_rank") and config.get("qk_rope_head_dim"):
        return "mla"
    if config.get("cla_share_factor"):
        return "cla"
    head_dim = config.get("head_dim")
    if head_dim:
        try:
            implied = int(config["hidden_size"]) / int(config["num_attention_heads"])
            if int(head_dim) != int(implied):
                return "gqa_head_dim"
        except (KeyError, TypeError, ZeroDivisionError):
            return "gqa_head_dim"
    return "default"


def load_hf_config(model_name: str) -> dict:
    """Fetch a model's config from Hugging Face (config JSON only -- no weights,
    no GPU) and normalize it to the fields the geometry needs.

    This is what lets the generator size *any* HF model, not just the calculator
    catalog. Raises a clean error if ``transformers`` is missing or the config
    lacks the core attention dimensions.
    """
    try:
        from transformers import AutoConfig
    except ImportError as e:  # pragma: no cover - depends on env
        raise SystemExit(
            "transformers is required to fetch configs for models outside the "
            "calculator catalog. `pip install transformers`, or add the model to "
            "modelconfig.json.") from e
    raw = AutoConfig.from_pretrained(model_name, trust_remote_code=True).to_dict()
    # multimodal configs nest the text tower under text_config
    if raw.get("num_hidden_layers") is None and isinstance(raw.get("text_config"), dict):
        raw = {**raw, **raw["text_config"]}
    n_heads = raw.get("num_attention_heads")
    config = {
        "num_hidden_layers": raw.get("num_hidden_layers"),
        "hidden_size": raw.get("hidden_size"),
        "num_attention_heads": n_heads,
        # MHA models omit num_key_value_heads; it then equals num_attention_heads
        "num_key_value_heads": raw.get("num_key_value_heads", n_heads),
    }
    for k in ("head_dim", "kv_lora_rank", "qk_rope_head_dim", "cla_share_factor"):
        if raw.get(k) is not None:
            config[k] = raw[k]
    missing = [k for k in ("num_hidden_layers", "hidden_size", "num_attention_heads")
               if config.get(k) is None]
    if missing:
        raise SystemExit(
            f"HF config for {model_name!r} is missing {missing}; add the model to "
            "modelconfig.json with the calculator's fields instead.")
    return config


def kv_cache_bytes(model_name: str, config: dict, tokens: int, dtype: str):
    """Return ``(total_bytes, detail)`` for ``tokens`` tokens of KV cache.

    ``detail`` carries the family and the resolved dimensions so callers can
    print/record exactly how the size was derived (same fields the calculator
    shows).  Byte count is integer; head_size/effective_layers are exact for
    the shipped configs (integer divisions) but rounded defensively.
    """
    if dtype not in DTYPE_BYTES:
        raise ValueError(f"unknown dtype {dtype!r}; know {sorted(DTYPE_BYTES)}")
    dbytes = DTYPE_BYTES[dtype]
    fam = resolve_family(model_name, config)
    nl = int(config["num_hidden_layers"])
    detail = {"family": fam, "dtype": dtype, "dtype_bytes": dbytes,
              "tokens": tokens, "num_hidden_layers": nl}

    if fam == "mla":
        kv_lora_rank = int(config["kv_lora_rank"])
        qk_rope_head_dim = int(config["qk_rope_head_dim"])
        elements = nl * tokens * (kv_lora_rank + qk_rope_head_dim)
        detail.update(kv_lora_rank=kv_lora_rank, qk_rope_head_dim=qk_rope_head_dim)
    elif fam == "cla":
        cla = int(config["cla_share_factor"])
        eff = nl / cla
        head_size = config["hidden_size"] / config["num_attention_heads"]
        kv_heads = int(config["num_key_value_heads"])
        elements = 2 * eff * tokens * kv_heads * head_size
        detail.update(cla_share_factor=cla, effective_layers=eff,
                      num_key_value_heads=kv_heads, head_size=head_size)
    elif fam == "gqa_head_dim":
        head_dim = int(config["head_dim"])
        kv_heads = int(config["num_key_value_heads"])
        elements = 2 * nl * tokens * kv_heads * head_dim
        detail.update(num_key_value_heads=kv_heads, head_dim=head_dim)
    else:  # default MHA / GQA
        head_size = config["hidden_size"] / config["num_attention_heads"]
        kv_heads = int(config["num_key_value_heads"])
        elements = 2 * nl * tokens * kv_heads * head_size
        detail.update(hidden_size=config["hidden_size"],
                      num_attention_heads=config["num_attention_heads"],
                      num_key_value_heads=kv_heads, head_size=head_size)

    total_bytes = int(round(elements * dbytes))
    detail["total_elements"] = int(round(elements))
    detail["total_bytes"] = total_bytes
    return total_bytes, detail


def shard_kv_bytes(total_bytes: int, detail: dict, tp: int):
    """Per-rank KV bytes and per-chunk object count under tensor parallelism.

    vLLM runs one KV-cache worker per TP rank; each stores only its shard, so a
    single logical chunk becomes ``tp`` offloaded objects (same chunk hash,
    distinct ``kv_rank``).  How the bytes divide depends on the family:

      * default / gqa_head_dim / cla -- sharded along the KV-head axis:
          - ``kv_heads % tp == 0``: each rank holds ``kv_heads/tp`` heads ->
            per-rank = ``total/tp``  (the validated case: Llama-3.1-70B has
            8 kv-heads, tp=4 -> 2/rank -> 80 MiB chunk -> 20 MiB per rank).
          - ``kv_heads < tp`` (head replication): vLLM replicates KV heads so
            every rank holds >=1; each rank stores one head -> per-rank =
            ``total/kv_heads`` and total device footprint inflates ``x tp/kv_heads``.
      * mla (DeepSeek V3/R1) -- the latent KV has no kv-head axis and vLLM
        replicates it on every rank: per-rank = ``total`` (footprint x tp).

    Returns ``(per_rank_bytes, objects_per_chunk, note)``.  ``objects_per_chunk``
    is ``tp`` for tp>1 (one object per rank) and 1 for tp<=1.
    """
    if tp <= 1:
        return total_bytes, 1, "tp=1 (no sharding)"
    fam = detail.get("family")
    if fam == "mla":
        return total_bytes, tp, "MLA latent replicated on every rank (footprint x%d)" % tp
    kv_heads = int(detail.get("num_key_value_heads") or 0)
    if kv_heads <= 0:
        raise ValueError(f"cannot shard family {fam!r} under tp={tp}: no kv-head count")
    if kv_heads >= tp:
        if kv_heads % tp != 0:
            raise ValueError(
                f"num_kv_heads={kv_heads} not divisible by tp={tp} "
                "(vLLM requires an even KV-head split)")
        return total_bytes // tp, tp, f"{kv_heads // tp} of {kv_heads} kv-heads per rank"
    # kv_heads < tp: vLLM replicates KV heads, one head per rank
    return (total_bytes // kv_heads, tp,
            f"kv-head replication: {kv_heads} heads over {tp} ranks, "
            f"footprint x{tp / kv_heads:.2f}")


if __name__ == "__main__":
    # Self-test against known calculator outputs (float16).
    llama8b = {"hidden_size": 4096, "num_attention_heads": 32,
               "num_hidden_layers": 32, "num_key_value_heads": 8}
    b, _ = kv_cache_bytes("meta-llama/Llama-3.1-8B-Instruct", llama8b, 4096, "float16")
    assert b == 536870912, b  # 0.5 GiB
    qwen3 = {"hidden_size": 5120, "num_attention_heads": 64, "num_hidden_layers": 64,
             "num_key_value_heads": 8, "head_dim": 128}
    b2, d2 = kv_cache_bytes("Qwen/Qwen3-32B", qwen3, 4096, "float16")
    assert d2["family"] == "gqa_head_dim" and b2 == 1073741824, (d2, b2)  # 1.0 GiB
    hl = {"hidden_size": 6400, "num_attention_heads": 80, "num_hidden_layers": 64,
          "num_key_value_heads": 8, "cla_share_factor": 2}
    b3, d3 = kv_cache_bytes("tencent/Hunyuan-Large", hl, 4096, "float16")
    assert d3["family"] == "cla" and d3["effective_layers"] == 32, d3
    print("kv_geometry self-test OK:",
          f"Llama-3.1-8B@4096={b/1024**3:.3f}GiB, Qwen3-32B@4096={b2/1024**3:.3f}GiB")
