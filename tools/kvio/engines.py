#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Engine registry, capability preflight and the fidelity manifest.

An engine is a real component kvio drives (LMCache's raw_block core, a
mounted file system through the POSIX API, an S3 SDK) with the storage
providers it supports.  The registry says which typed calls each engine
realizes; :func:`preflight` refuses a workload whose required calls the
chosen engine cannot make, before anything is mutated, and never lets an
unsupported call turn into a skipped operation counted as done.

The fidelity manifest is what a run must carry to be believed: the
capture boundary and evidence labels of the workload, the engine's
name, revision and the modules actually loaded (not the label the
adapter was given), the provider and resolved configuration, the timing
mode, the content profile, and the digests that bind them.  A missing
dimension is recorded as missing.
"""
from __future__ import annotations

import importlib
import json
import os
import platform
import sys
from dataclasses import dataclass, field

import workload3


@dataclass
class EngineSpec:
    name: str
    family: str
    capabilities: frozenset
    providers: tuple
    make: object                      # callable(config: dict) -> backend
    revision: object = None           # callable() -> str
    notes: tuple = ()


REGISTRY: dict = {}


def register(spec: EngineSpec):
    REGISTRY[spec.name] = spec
    return spec


class PreflightError(RuntimeError):
    pass


def preflight(workload, engine_name, provider=None):
    """The engine must realize every call the workload needs; say which it cannot."""
    spec = REGISTRY.get(engine_name)
    if spec is None:
        raise PreflightError(f"unknown engine {engine_name!r}; known: {sorted(REGISTRY)}")
    if provider is not None and provider not in spec.providers:
        raise PreflightError(f"engine {engine_name!r} has no provider {provider!r}; has {spec.providers}")
    needed = workload3.required_capabilities(workload)
    missing = [c for c in needed if c not in spec.capabilities]
    families = {c.split(".")[0] for c in needed}
    if families - {spec.family}:
        raise PreflightError(f"engine {engine_name!r} serves family {spec.family!r}; workload needs {sorted(families)}")
    if missing:
        raise PreflightError(f"engine {engine_name!r} cannot realize {missing}")
    return spec


def _loaded(modname):
    m = sys.modules.get(modname)
    if m is None:
        try:
            m = importlib.import_module(modname)
        except Exception:
            return None
    return getattr(m, "__file__", None)


def fidelity_manifest(workload, spec, provider, config, *, timing_profile, content_profile,
                      backend=None, sidecar_bytes=None, extra=None):
    prov = workload["provenance"]
    man = {
        "schema": "kvio.fidelity-manifest.v1",
        "workload": {"schema": workload["schema"], "sha256": workload3.workload_sha256(workload),
                     "bundle_sha256": workload3.bundle_sha256(workload, sidecar_bytes)
                     if (sidecar_bytes is not None or prov["timing_model"] != "captured") else None,
                     "capture_level": prov["capture_level"], "mapping_method": prov["mapping_method"],
                     "completeness": prov["completeness"], "timing_model": prov["timing_model"],
                     "release_provenance": prov["release_provenance"],
                     "required_capabilities": workload3.required_capabilities(workload),
                     "source_engine": workload["engine"]},
        "engine": {"name": spec.name, "family": spec.family, "provider": provider,
                   "revision": spec.revision() if callable(spec.revision) else spec.revision,
                   "config": dict(config or {}),
                   "loaded": {m: _loaded(m) for m in getattr(backend, "provenance_modules", ())},
                   "overrides": {k: v for k, v in os.environ.items() if k.startswith("KVIO_")}},
        "replay": {"timing_profile": timing_profile, "content_profile": content_profile,
                   "host": {"python": sys.version.split()[0], "platform": platform.platform()}},
        "missing": [],
    }
    if backend is not None and hasattr(backend, "describe"):
        man["engine"]["target"] = backend.describe()
    for m, path in man["engine"]["loaded"].items():
        if path is None:
            man["missing"].append(f"module {m} not importable")
    if prov["timing_model"] == "absent" and timing_profile == "offered":
        man["missing"].append("offered-load profile requested without recorded release times")
    if extra:
        man.update(extra)
    return man


def doctor():
    """One line per registered engine: what it needs and whether it is here."""
    lines = []
    for name, spec in sorted(REGISTRY.items()):
        status = "ok"
        try:
            probe = spec.make({"probe": True})
            if hasattr(probe, "doctor"):
                status = probe.doctor()
        except Exception as error:
            status = f"unavailable: {type(error).__name__}: {error}"
        lines.append(f"  {name:<20} family={spec.family:<7} providers={','.join(spec.providers):<24} {status}")
    return "\n".join(lines)


def register_builtin():
    import intent_exec
    register(EngineSpec(
        name="fake", family="object",
        capabilities=frozenset({"object.store", "object.load", "object.release", "object.exists"}),
        providers=("memory",), make=lambda cfg: intent_exec.FakeBackend(), revision="in-tree"))
    register(EngineSpec(
        name="lmcache-raw_block", family="object",
        capabilities=frozenset({"object.store", "object.load", "object.release", "object.exists"}),
        providers=("posix", "io_uring", "uring_cmd"),
        make=lambda cfg: intent_exec.raw_block_from_config(cfg),
        revision=intent_exec.vendored_lmcache_revision,
        notes=("the vendored core decides slots, headers, padding and commands",)))
    try:
        import posix_fs
        register(EngineSpec(
            name="posix-direct", family="posix",
            capabilities=frozenset(f"posix.{c}" for c in workload3.CALLS["posix"]),
            providers=("mount",), make=lambda cfg: posix_fs.PosixBackend(cfg.get("root")) if not cfg.get("probe") else posix_fs.PosixBackend.probe(),
            revision="in-tree", notes=("a real directory under a generated root; the kernel and the mount decide everything below",)))
        register(EngineSpec(
            name="fake-fs", family="posix",
            capabilities=frozenset(f"posix.{c}" for c in workload3.CALLS["posix"]),
            providers=("memory",), make=lambda cfg: posix_fs.FakeFS(), revision="in-tree"))
    except ImportError:
        pass
    try:
        import s3_client
        register(EngineSpec(
            name="s3-sdk", family="s3",
            capabilities=frozenset(f"s3.{c}" for c in workload3.CALLS["s3"]),
            providers=("endpoint",), make=lambda cfg: s3_client.S3Backend.probe() if cfg.get("probe") else s3_client.S3Backend(cfg),
            revision=s3_client.sdk_revision, notes=("a pinned SDK against a configured endpoint; the SDK's transfer helper is not used",)))
        register(EngineSpec(
            name="fake-s3", family="s3",
            capabilities=frozenset(f"s3.{c}" for c in workload3.CALLS["s3"]),
            providers=("memory",), make=lambda cfg: s3_client.FakeS3(), revision="in-tree"))
    except ImportError:
        pass


register_builtin()


if __name__ == "__main__":
    print("kvio engines:")
    print(doctor())
