#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Record a serving LMCache's raw_block object operations without editing it.

The capture adapter in ``lmcache_adapter.py`` wraps a core the caller
constructed.  A serving vLLM constructs its cores inside LMCache's storage
plugin, in the worker process, where no caller of ours exists.  This hook
reaches that construction from the outside: when ``KVIO_CAPTURE_DIR`` is
set, it wraps ``RawBlockCore.__init__`` so that every core the plugin
builds records its object operations to
``$KVIO_CAPTURE_DIR/<host>-<pid>-<n>.jsonl`` through the same recorder and
the same per-item outcome rules as the adapter, with the initial live set
snapshotted right after construction.  The engine's own code is untouched;
the recorder is bounded and asynchronous; payloads never pass through it.

Install it with ``PYTHONPATH=<tools/kvio/hook>:<tools/kvio>`` so the
``sitecustomize`` next to this file runs in every Python of the serving
stack, including the workers vLLM spawns, which inherit the environment.
"""
from __future__ import annotations

import atexit
import os
import socket
import sys

_installed = False
_recorders = []


def install(capture_dir):
    global _installed
    if _installed:
        return
    _installed = True
    try:
        from lmcache.v1.storage_backend.raw_block import core as core_mod
    except Exception as error:  # LMCache absent in this interpreter: nothing to record
        sys.stderr.write(f"[kvio-capture] no raw_block core here: {error}\n")
        return
    import capture_events
    import lmcache_adapter

    RawBlockCore = core_mod.RawBlockCore
    orig_init = RawBlockCore.__init__
    orig = {n: getattr(RawBlockCore, n) for n in ("put_many", "load_many_into", "delete_many")}
    os.makedirs(capture_dir, exist_ok=True)

    def _init(self, *args, **kwargs):
        orig_init(self, *args, **kwargs)
        n = len(_recorders)
        path = os.path.join(capture_dir, f"{socket.gethostname()}-{os.getpid()}-{n}.jsonl")
        rec = lmcache_adapter.open_recorder(path, core=self, engine_revision=os.environ.get("KVIO_LMCACHE_REVISION"))
        rec.engine["process"] = {"pid": os.getpid(), "argv0": sys.argv[0] if sys.argv else None}
        wrapper = lmcache_adapter.RecordingRawBlockCore(self, rec, stream=f"{socket.gethostname()}-{os.getpid()}-core{n}")
        # The wrapper records around the *original* methods; the core's own
        # public methods now route through it.
        wrapper._core = _Delegate(self, orig)
        self._kvio_wrapper = wrapper
        _recorders.append(rec)
        _wrappers.append(wrapper)
        try:
            wrapper.record_initial_state()
        except Exception as error:
            rec.marker("initial_state_failed", error=repr(error))
        wrapper.write_key_mapping()
        _every = wrapper._begin

        def _begin_and_map(**fields):
            op = _every(**fields)
            wrapper.write_key_mapping()
            return op
        wrapper._begin = _begin_and_map
        sys.stderr.write(f"[kvio-capture] recording core {n} of pid {os.getpid()} to {path}\n")

    def _put_many(self, *a, **k):
        w = getattr(self, "_kvio_wrapper", None)
        return w.put_many(*a, **k) if w else orig["put_many"](self, *a, **k)

    def _load_many_into(self, *a, **k):
        w = getattr(self, "_kvio_wrapper", None)
        return w.load_many_into(*a, **k) if w else orig["load_many_into"](self, *a, **k)

    def _delete_many(self, *a, **k):
        w = getattr(self, "_kvio_wrapper", None)
        return w.delete_many(*a, **k) if w else orig["delete_many"](self, *a, **k)

    RawBlockCore.__init__ = _init
    RawBlockCore.put_many = _put_many
    RawBlockCore.load_many_into = _load_many_into
    RawBlockCore.delete_many = _delete_many
    atexit.register(_close_all)


class _Delegate:
    """The core as the wrapper sees it: original methods, everything else forwarded."""

    def __init__(self, core, orig):
        self._c = core
        self._orig = orig

    def put_many(self, *a, **k):
        return self._orig["put_many"](self._c, *a, **k)

    def load_many_into(self, *a, **k):
        return self._orig["load_many_into"](self._c, *a, **k)

    def delete_many(self, *a, **k):
        return self._orig["delete_many"](self._c, *a, **k)

    def __getattr__(self, name):
        return getattr(self._c, name)


_wrappers = []


def _close_all():
    for w in _wrappers:
        try:
            w.write_key_mapping()
        except Exception:
            pass
    for rec in _recorders:
        try:
            h = rec.close()
            sys.stderr.write(f"[kvio-capture] closed {rec.path}: {h}\n")
        except Exception:
            pass


if os.environ.get("KVIO_CAPTURE_DIR"):
    install(os.environ["KVIO_CAPTURE_DIR"])
