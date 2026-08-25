#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# sync-lmcache.sh -- vendor the LMCache surface the kvio tool needs, so kvio
# builds and runs from this tree alone (no LMCache install).
#
# kvio's engine-driving commands (workload/sweep/replay/...) instantiate
# LMCache's RawBlockCore -- the real raw_block engine, whose data path is the
# Rust crate rust/raw_block (a pyo3 extension module `make kvio` builds into
# tools/kvio/build/). Rather than fork LMCache (~150 commits/month), this
# script vendors exactly the modules that execute when kvio imports the engine:
#
#   1. a STATIC runtime-import closure walked from the pinned ref itself
#      (module/class/try scope; function bodies and TYPE_CHECKING excluded),
#      so upstream refactors change the vendored set instead of breaking it;
#   2. an EMPIRICAL refinement loop -- import the seeds in a subprocess and
#      add any missing lmcache module it reports -- which catches imports
#      static analysis cannot see (e.g. a module calling its own function at
#      init time, whose body imports); it stops at the first non-lmcache
#      missing dep (say, torch on a box without it), where `kvio doctor` on a
#      deps-complete machine takes over as the final gate.
#
# DELIBERATE: ancestor package __init__.py files are stubbed empty unless
# something imports them by name. Upstream's storage_backend/__init__.py
# imports the entire backend zoo (transformers, zmq, ...), which kvio does not
# use; stubbing keeps the vendor at ~3 dozen files instead of 141. If raw_block
# ever depends on a package init's side effects, the empirical probe or
# `kvio doctor` fails loudly and a human revisits this choice.
#
# The script also fails loudly when a public symbol kvio calls disappears
# upstream -- an API break, the one sync event that truly needs a human. It
# never builds anything; the Rust build is `make kvio` (run on a real box).
#
#   LMCACHE=~/devel/lmcache REF=upstream/dev ./sync-lmcache.sh
#
# Run it every now and then; monthly matches the measured churn of these paths
# (~2-5 upstream commits/month each; see README.md).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
LMCACHE=${LMCACHE:-$HOME/devel/lmcache}
REF=${REF:-upstream/dev}
VENDOR="$HERE/vendor/lmcache"

[ -e "$LMCACHE/.git" ] || { echo "no LMCache git tree at $LMCACHE" >&2; exit 1; }

LMCACHE="$LMCACHE" REF="$REF" VENDOR="$VENDOR" python3 - <<'PY'
import ast, io, os, re, shutil, subprocess, sys, tarfile

LMCACHE = os.environ["LMCACHE"]; REF = os.environ["REF"]; VENDOR = os.environ["VENDOR"]

def git(*args, binary=False):
    r = subprocess.run(["git", "-C", LMCACHE, *args],
                       capture_output=True, text=not binary)
    return r.stdout if r.returncode == 0 else None

def show(path):
    return git("show", f"{REF}:{path}")

# The modules kvio imports (see tools/kvio/*.py and examples/lmcache/kvio_*.py).
SEEDS = [
    "lmcache/v1/storage_backend/raw_block/__init__.py",
    "lmcache/v1/storage_backend/raw_block/core.py",
    "lmcache/v1/storage_backend/raw_block/key_codec.py",
    "lmcache/v1/distributed/api.py",
    "lmcache/v1/memory_management.py",
]
SEED_MODULES = ("lmcache.v1.storage_backend.raw_block, "
                "lmcache.v1.distributed.api, lmcache.v1.memory_management")
RUST = "rust/raw_block"
NATIVE = "csrc/lmcache_native"   # torch CppExtension the platform layer needs
# headers under csrc/ that lmcache_native's sources include via the csrc dir
NATIVE_HDRS = ["csrc/engine_kv_format.h", "csrc/kv_transfer_plan_types.h",
               "csrc/kv_transfer_types.h"]
# stdlib-only test helper the sweep/replay/proof tools load by path
TEST_UTILS = "tests/v1/storage_backend/raw_block_test_utils.py"
# Apache-2.0 section 4: redistributions carry the license text itself
LICENSE = "LICENSE"

# Subtrees vendored WHOLESALE: the platform layer picks its per-device module
# (cpu/cuda/rocm/...) via importlib inside a function at detect time, which no
# import walk -- static or probe-on-one-box -- can enumerate. 43 small files,
# stdlib-only besides the tolerated numba/torch compute backends.
WHOLESALE = ["lmcache/v1/platform", "lmcache/v1/kv_codec"]

# Public symbols kvio calls; their disappearance upstream is an API break.
API = {
    "lmcache/v1/storage_backend/raw_block/core.py":
        ["class RawBlockCore", "class RawBlockCoreConfig", "class RawBlockPutManyResult"],
    "lmcache/v1/storage_backend/raw_block/key_codec.py":
        ["def encode_object_key", "def slot_identity_from_encoded_key"],
    "lmcache/v1/distributed/api.py": ["class ObjectKey"],
    "lmcache/v1/memory_management.py": ["class MemoryObj", "class MemoryFormat"],
}

def mod_to_path(mod):
    p = mod.replace(".", "/")
    for cand in (p + ".py", p + "/__init__.py"):
        if show(cand) is not None:
            return cand
    return None

def import_nodes(src, include_try=True, pkg=None):
    """Imports that execute at module-import time: module body, class bodies,
    if/with/for/while/try (and match where the grammar has it) -- never
    function bodies. Relative imports are resolved against ``pkg`` (the dotted
    package of the file being scanned)."""
    mods = set()
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        print(f"WARNING: could not parse a closure file ({e}); its imports "
              "are invisible to the walk", file=sys.stderr)
        return mods

    def add_from(node):
        if node.level == 0:
            if node.module:
                mods.add(node.module)
            return
        if pkg is None:
            return
        parts = pkg.split(".")
        base = parts[: len(parts) - (node.level - 1)]
        if node.module:
            base = base + [node.module]
        if base:
            mods.add(".".join(base))

    def walk(body):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(node, ast.Import):
                mods.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                add_from(node)
            elif isinstance(node, ast.If):
                if "TYPE_CHECKING" in ast.dump(node.test):
                    walk(node.orelse)
                else:
                    walk(node.body); walk(node.orelse)
            elif isinstance(node, ast.Try):
                if include_try:
                    walk(node.body); walk(node.orelse); walk(node.finalbody)
                    for h in node.handlers:
                        walk(h.body)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                walk(node.body)
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                walk(node.body); walk(node.orelse)
            elif isinstance(node, ast.ClassDef):
                walk(node.body)
            elif hasattr(ast, "Match") and isinstance(node, ast.Match):
                for case in node.cases:
                    walk(case.body)
    walk(tree.body)
    return mods


def pkg_of(path):
    """Dotted package of a file path: lmcache/a/b.py -> lmcache.a;
    lmcache/a/__init__.py -> lmcache.a."""
    d = path[:-len("/__init__.py")] if path.endswith("/__init__.py") \
        else os.path.dirname(path)
    return d.replace("/", ".") if d else None

def static_closure(seed_paths):
    seen, queue = set(), list(seed_paths)
    while queue:
        path = queue.pop()
        if path in seen:
            continue
        seen.add(path)
        src = show(path)
        if src is None:
            print(f"ERROR: closure file missing upstream: {path}", file=sys.stderr)
            sys.exit(1)
        for mod in import_nodes(src, pkg=pkg_of(path)):
            if mod.split(".")[0] != "lmcache":
                continue
            mp = mod_to_path(mod)
            if mp and mp not in seen:
                queue.append(mp)
    return seen

def extract(closure):
    if os.path.isdir(VENDOR):
        shutil.rmtree(VENDOR)
    os.makedirs(VENDOR)
    blob = git("archive", REF, *sorted(closure), RUST, NATIVE, *NATIVE_HDRS,
               TEST_UTILS, LICENSE, binary=True)
    if blob is None:
        print("ERROR: git archive failed (bad ref or path set)", file=sys.stderr)
        sys.exit(1)
    tarfile.open(fileobj=io.BytesIO(blob)).extractall(VENDOR)
    # empty __init__.py stubs for ancestor packages not vendored by name
    # (see the DELIBERATE note in the header)
    for path in closure:
        d = os.path.dirname(path)
        while d.startswith("lmcache"):
            init = os.path.join(VENDOR, d, "__init__.py")
            if not os.path.exists(init):
                open(init, "w").close()
            d = os.path.dirname(d)

# ---- static closure (+ wholesale subtrees), then empirical refinement ----
closure = static_closure(SEEDS)
for tree in WHOLESALE:
    files = (git("ls-tree", "-r", "--name-only", REF, tree) or "").split()
    closure |= static_closure([f for f in files if f.endswith(".py")])
empirical = []
for _ in range(25):
    extract(closure)
    # -P drops sys.path[0] (the cwd/'' entry) so a stray lmcache package in
    # the invoking directory cannot shadow the vendored tree and green-light a
    # broken closure; cwd is pinned to VENDOR's parent for the same reason on
    # pythons without -P.
    r = subprocess.run(
        [sys.executable, "-P", "-c", f"import {SEED_MODULES}"],
        env={**os.environ, "PYTHONPATH": VENDOR},
        cwd=os.path.dirname(VENDOR), capture_output=True, text=True)
    if r.returncode == 0:
        probe = "imports cleanly on this machine"
        break
    # Only the FINAL raised exception counts: LMCache logs tolerated
    # missing-module WARNINGs to stderr, which must not be mistaken for gaps.
    tail = [l for l in r.stderr.strip().splitlines() if "Error" in l]
    last = tail[-1] if tail else ""
    m = re.match(r".*No module named '(lmcache(?:\.[\w.]+)?)'", last)
    if m and m.group(1) in ("lmcache.lmcache_native",):
        # the torch C++ extension -- built into the vendor by `make kvio`,
        # which necessarily runs after this sync. Expected pre-build stop.
        probe = ("stops at lmcache.lmcache_native (built later by `make kvio`); "
                 "`kvio doctor` verifies after the build")
        break
    if not m:
        missing = re.search(r"No module named '([\w.]*)'", last)
        if missing:
            probe = (f"stops at non-lmcache dep '{missing.group(1)}' on this "
                     "machine (fine -- `kvio doctor` verifies on a "
                     "deps-complete box)")
            break
        # Any other lmcache-internal failure (cannot import name X, a
        # SyntaxError in a vendored file, a signal-killed probe) is a
        # positively detected broken vendor -- fail loudly, never exit 0.
        print("ERROR: import probe failed with a non-missing-module error:",
              file=sys.stderr)
        print("  " + (last or (r.stderr.strip().splitlines() or ["?"])[-1]),
              file=sys.stderr)
        sys.exit(2)
    mod = m.group(1)
    mp = mod_to_path(mod)
    if mp is None:
        print(f"ERROR: probe needs '{mod}' but upstream has no such module", file=sys.stderr)
        sys.exit(1)
    empirical.append(mp)
    closure |= static_closure([mp])
else:
    print("ERROR: empirical refinement did not converge in 25 rounds", file=sys.stderr)
    sys.exit(1)
closure = sorted(closure)

# the probe imports the vendored tree, which litters __pycache__ -- purge it
for root, dirs, _files in os.walk(VENDOR):
    for d in list(dirs):
        if d == "__pycache__":
            shutil.rmtree(os.path.join(root, d))
            dirs.remove(d)

# ---- API-break check ----
breaks = []
for path, symbols in API.items():
    src = show(path) or ""
    for sym in symbols:
        if not re.search(rf"^{re.escape(sym)}\b", src, re.M):
            breaks.append(f"{path}: `{sym}` no longer found")

# ---- third-party deps: required (unconditional) vs optional (try-guarded) ----
req, opt = set(), set()
for path in closure:
    text = show(path) or ""
    hard = {m.split(".")[0]
            for m in import_nodes(text, include_try=False, pkg=pkg_of(path))}
    every = {m.split(".")[0]
             for m in import_nodes(text, include_try=True, pkg=pkg_of(path))}
    req |= hard
    opt |= every - hard
std = set(sys.stdlib_module_names) | {"lmcache", "__future__"}
required = sorted(d for d in req if d not in std)
optional = sorted(d for d in opt - req if d not in std)

commit = git("rev-parse", REF).strip()
short = git("rev-parse", "--short", REF).strip()
date = git("log", "-1", "--format=%cs", REF).strip()

with open(os.path.join(VENDOR, "PROVENANCE.md"), "w") as f:
    f.write("# vendored LMCache surface -- regenerate with sync-lmcache.sh, never hand-edit\n\n")
    f.write(f"- synced_commit: {commit}\n- synced_ref: {REF} ({short}, {date})\n")
    f.write("- upstream: https://github.com/LMCache/LMCache (Apache-2.0; text vendored "
            "as LICENSE alongside this file)\n\n")
    f.write("## what is vendored\n\n")
    f.write(f"- `{RUST}/` -- the Rust raw_block engine (pyo3); `make kvio` builds it. "
            f"Last upstream change: {git('log','-1','--format=%h %cs %s',REF,'--',RUST).strip()}\n")
    f.write(f"- `{NATIVE}/` -- the lmcache_native torch CppExtension (device_ops "
            "backend needs it); `make kvio` builds it via build_native.py. "
            f"Last upstream change: {git('log','-1','--format=%h %cs %s',REF,'--',NATIVE).strip()}\n")
    f.write(f"- {len(closure)} Python files -- the runtime import closure of the modules kvio\n"
            "  uses (static walk + empirical import-probe refinement; the on-disk tree\n"
            "  additionally holds empty ancestor-package __init__ stubs and the\n"
            "  stdlib-only tests/.../raw_block_test_utils.py the tools load):\n")
    for p in closure:
        tag = "  (added by the import probe)" if p in empirical else ""
        f.write(f"  - `{p}`{tag}\n")
    f.write(f"\n- import probe on this sync: {probe}\n")
    f.write("\n## third-party Python deps (module-level, unconditional)\n\n")
    f.write("```\n" + "\n".join(required) + "\n```\n")
    f.write("(GPU-free is not torch-free: these modules import torch at module "
            "level; the CPU wheel suffices.)\n")
    if optional:
        f.write("\nOptional (imported inside try/except; absence tolerated):\n")
        f.write("```\n" + "\n".join(optional) + "\n```\n")
    f.write("\n## API check\n\n")
    if breaks:
        f.write("⚠ **UPSTREAM API BREAK -- fix kvio before using this vendor:**\n")
        for b in breaks:
            f.write(f"- {b}\n")
    else:
        f.write("All public symbols kvio calls are present upstream at this ref.\n")

print(f"vendored {REF} ({short}, {date}) -> {VENDOR}")
print(f"  {len(closure)} python files (+{len(empirical)} via import probe) + {RUST}/")
print(f"  import probe: {probe}")
print(f"  required deps: {', '.join(required)}")
if optional:
    print(f"  optional deps (try-guarded): {', '.join(optional)}")
if breaks:
    print("⚠ UPSTREAM API BREAK:", *breaks, sep="\n  ")
    sys.exit(2)
print("ok: kvio's API surface intact upstream")
PY
