# kvio minimal offline package

The `install-kvio-offline` target installs one deliberately small subset of
kvio for an environment where production traces must stay local. It contains
no LMCache source, PyTorch module, model configuration, model data, tokenizer,
download client, or engine-driving command.

## Installed functions

- `kvio record` invokes the local `nvme_tp_monitor` binary. Its setup and
  completion hooks are below syscall/io_uring batching and cover the selected
  Linux NVMe namespace, not PCIe traffic or userspace-owned controller paths.
- `kvio iolog` converts a strict capture-v1 stream to a confidential fio
  replay bundle.
- `kvio fio-certify` invokes the independent Rust translation verifier.
- `kvio compare` compares an original and re-recorded device stream.
- `kvio release-example`, `release-build`, and `release-verify` operate on the
  bounded results-only candidate.
- `kvio doctor` checks only this package's local files and the fio executable.

The package does not authorize release. The capture and fio replay bundle
retain exact request metadata and must remain confidential. A successful
results-candidate verification still reports `export_allowed: false`.

## Source and licenses

All installed source is from the same ebpf-syscall checkout used to run the
install target. The repository `LICENSE` and kvio `NOTICE` are installed beside
this file. The Python tools and `kvio-ir` crate carry Apache-2.0 identifiers.
The tracer includes the Linux BPF program's required GPL license declaration.

The Rust verifier is built with `tools/kvio/rust/kvio-ir/Cargo.lock`.
`make kvio-offline` passes Cargo's `--offline` option, so a missing cached crate
fails the build instead of contacting a registry. Record the repository
revision, compiler versions, build environment, and hashes of the installed
files in the organization's own software inventory. This target does not claim
bit-for-bit reproducible builds or supply a vulnerability scanner.

## Runtime boundary

The Python commands use only the Python standard library. `kvio-ir` is a local
binary. Capture requires Linux BPF support and the tracer's normal libbpf,
libelf, zlib, and kernel prerequisites. Actual replay requires a separately
installed fio executable and an explicitly approved disposable target.

Installation and the installed commands do not fetch dependencies or contact a
network service. Build dependencies must already be present. Test the final
package with network access denied under the organization's own host or
container policy; the project test also runs every non-destructive installed
workflow with Python socket construction blocked.
