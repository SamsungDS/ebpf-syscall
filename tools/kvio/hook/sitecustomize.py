# SPDX-License-Identifier: Apache-2.0
"""Runs in every Python that has this directory on PYTHONPATH.  Does nothing
unless KVIO_CAPTURE_DIR is set; then arms the LMCache raw_block capture hook
lazily, the first time LMCache's core module is imported, so an interpreter
that never touches LMCache pays nothing."""
import os
import sys

if os.environ.get("KVIO_CAPTURE_DIR"):
    import importlib.abc
    import importlib.util

    class _ArmOnImport(importlib.abc.MetaPathFinder):
        target = "lmcache.v1.storage_backend.raw_block.core"

        def find_spec(self, name, path, target=None):
            if name != self.target:
                return None
            sys.meta_path.remove(self)
            spec = importlib.util.find_spec(name)
            if spec is None:
                return None
            loader = spec.loader

            class _Loader(importlib.abc.Loader):
                def create_module(self, s):
                    return loader.create_module(s)

                def exec_module(self, module):
                    loader.exec_module(module)
                    import lmcache_capture_hook
                    lmcache_capture_hook.install(os.environ["KVIO_CAPTURE_DIR"])

            spec.loader = _Loader()
            return spec

    sys.meta_path.insert(0, _ArmOnImport())
