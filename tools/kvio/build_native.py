#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build LMCache's lmcache_native C++ extension from the vendored sources.

The engine path hard-requires it: lmcache/__init__ resolves device_ops through
the platform layer, whose compute backend imports lmcache.lmcache_native (a
torch CppExtension). This mirrors upstream's build spec exactly
(setup_extensions/common_cpp.py: the six .cpp files, csrc include dirs,
-O3 -std=c++17, torch.utils.cpp_extension) and drops the resulting .so INSIDE
the vendored package as lmcache/lmcache_native.so so `import
lmcache.lmcache_native` resolves. Build with the same python you will run kvio
with -- the extension links that interpreter's torch.

Run via `make kvio`; needs torch (CPU wheel fine) + a C++ toolchain.
"""
import glob
import os
import shutil
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
VENDOR = os.path.join(HERE, "vendor", "lmcache")
CSRC = os.path.join(VENDOR, "csrc", "lmcache_native")
OUT = os.path.join(HERE, "build", "native")
DEST = os.path.join(VENDOR, "lmcache", "lmcache_native.so")

SOURCES = ["bitmap.cpp", "fold.cpp", "periodic_event_notifier.cpp",
           "pybind.cpp", "ttl_lock.cpp", "utils.cpp"]


def main():
    if not os.path.isdir(CSRC):
        sys.exit("vendored csrc/lmcache_native missing -- run sync-lmcache.sh")
    try:
        from torch.utils import cpp_extension
    except ImportError:
        sys.exit("torch is required to build lmcache_native (CPU wheel is "
                 "fine): pip install torch")
    os.makedirs(OUT, exist_ok=True)
    cpp_extension.load(
        name="lmcache_native",
        sources=[os.path.join(CSRC, s) for s in SOURCES],
        extra_include_paths=[CSRC, os.path.join(VENDOR, "csrc")],
        extra_cflags=["-O3", "-std=c++17"],
        build_directory=OUT,
        is_python_module=False,   # compile + link only; we place the .so ourselves
        verbose=True,
    )
    built = os.path.join(OUT, "lmcache_native.so")
    if not os.path.isfile(built):
        cands = glob.glob(os.path.join(OUT, "lmcache_native*.so"))
        if not cands:
            sys.exit("build produced no lmcache_native*.so in " + OUT)
        built = cands[0]
    shutil.copy2(built, DEST)
    print(f"lmcache_native built -> {DEST}")


if __name__ == "__main__":
    main()
