# vendored LMCache surface -- regenerate with sync-lmcache.sh, never hand-edit

- synced_commit: 23cca67908e17b193eb8fab08ba1beb0115881cd
- synced_ref: upstream/dev (23cca67908e1, 2026-08-25)
- upstream: https://github.com/LMCache/LMCache (Apache-2.0; text vendored as LICENSE alongside this file)

## what is vendored

- `rust/raw_block/` -- the Rust raw_block engine (pyo3); `make kvio` builds it. Last upstream change: a976ce09dd98 2026-08-11 [Fix][RawBlock] Bounce unaligned buffers in io_uring uring_cmd read paths (#3891)
- `csrc/lmcache_native/` -- the lmcache_native torch CppExtension (device_ops backend needs it); `make kvio` builds it via build_native.py. Last upstream change: ab09ffeb72d8 2026-08-19 Move common transfer descriptors into lmcache_native (#4515)
- 116 Python files -- the runtime import closure of the modules kvio
  uses (static walk + empirical import-probe refinement; the on-disk tree
  additionally holds empty ancestor-package __init__ stubs and the
  stdlib-only tests/.../raw_block_test_utils.py the tools load):
  - `lmcache/__init__.py`
  - `lmcache/connections.py`
  - `lmcache/integration/vllm/utils.py`
  - `lmcache/logging.py`
  - `lmcache/observability.py`
  - `lmcache/usage_telemetry/__init__.py`
  - `lmcache/usage_telemetry/context.py`
  - `lmcache/usage_telemetry/continuous.py`
  - `lmcache/usage_telemetry/env_probe.py`
  - `lmcache/usage_telemetry/guard.py`
  - `lmcache/usage_telemetry/identity.py`
  - `lmcache/usage_telemetry/messages.py`
  - `lmcache/usage_telemetry/mp.py`
  - `lmcache/usage_telemetry/transport.py`
  - `lmcache/utils.py`
  - `lmcache/v1/compute/attention/metadata.py`
  - `lmcache/v1/compute/blend/blender.py`
  - `lmcache/v1/compute/blend/metadata.py`
  - `lmcache/v1/compute/blend/utils.py`
  - `lmcache/v1/compute/models/utils.py`
  - `lmcache/v1/config.py`
  - `lmcache/v1/config_base.py`
  - `lmcache/v1/distributed/api.py`
  - `lmcache/v1/distributed/config.py`
  - `lmcache/v1/distributed/l2_adapters/config.py`
  - `lmcache/v1/distributed/serde/__init__.py`
  - `lmcache/v1/distributed/serde/aesgcm.py`
  - `lmcache/v1/distributed/serde/async_processor.py`
  - `lmcache/v1/distributed/serde/base.py`
  - `lmcache/v1/distributed/serde/factory.py`
  - `lmcache/v1/distributed/serde/fp8.py`
  - `lmcache/v1/distributed/serde/key_provider.py`
  - `lmcache/v1/distributed/serde/multi.py`
  - `lmcache/v1/distributed/serde/turboquant/__init__.py`
  - `lmcache/v1/distributed/serde/turboquant/turboquant.py`
  - `lmcache/v1/distributed/serde/utils.py`
  - `lmcache/v1/exceptions/__init__.py`
  - `lmcache/v1/gpu_connector/__init__.py`
  - `lmcache/v1/gpu_connector/gds_context.py`
  - `lmcache/v1/gpu_connector/gpu_connectors.py`
  - `lmcache/v1/gpu_connector/kv_format/__init__.py`
  - `lmcache/v1/gpu_connector/kv_format/contiguity.py`
  - `lmcache/v1/gpu_connector/kv_format/detection.py`
  - `lmcache/v1/gpu_connector/kv_format/detectors/__init__.py`
  - `lmcache/v1/gpu_connector/kv_format/detectors/base.py`
  - `lmcache/v1/gpu_connector/kv_format/detectors/registry.py`
  - `lmcache/v1/gpu_connector/kv_format/specs/__init__.py`
  - `lmcache/v1/gpu_connector/kv_format/specs/base.py`
  - `lmcache/v1/gpu_connector/kv_format/specs/registry.py`
  - `lmcache/v1/gpu_connector/kv_format/types.py`
  - `lmcache/v1/gpu_connector/mock_gpu_connector.py`
  - `lmcache/v1/gpu_connector/utils.py`
  - `lmcache/v1/kv_codec/__init__.py`
  - `lmcache/v1/kv_codec/asym_k16_v8.py`
  - `lmcache/v1/kv_codec/encoded_kv.py`
  - `lmcache/v1/kv_codec/errors.py`
  - `lmcache/v1/kv_layer_groups.py`
  - `lmcache/v1/memory_allocators/gpu_memory_allocator.py`
  - `lmcache/v1/memory_allocators/paged_tensor_memory_allocator.py`
  - `lmcache/v1/memory_allocators/tensor_memory_allocator.py`
  - `lmcache/v1/memory_management.py`
  - `lmcache/v1/metadata.py`
  - `lmcache/v1/multiprocess/custom_types.py`
  - `lmcache/v1/multiprocess/group_view.py`
  - `lmcache/v1/multiprocess/posix_shm.py`
  - `lmcache/v1/periodic_thread.py`
  - `lmcache/v1/pin_monitor.py`
  - `lmcache/v1/platform/__init__.py`
  - `lmcache/v1/platform/_device_detect.py`
  - `lmcache/v1/platform/base/__init__.py`
  - `lmcache/v1/platform/base/cache_context.py`
  - `lmcache/v1/platform/base/device_ops.py`
  - `lmcache/v1/platform/base/device_spec.py`
  - `lmcache/v1/platform/base/event_ipc.py`
  - `lmcache/v1/platform/base/ipc_wrapper.py`
  - `lmcache/v1/platform/base/pin_memory.py`
  - `lmcache/v1/platform/cache_context.py`
  - `lmcache/v1/platform/cpu/__init__.py`
  - `lmcache/v1/platform/cpu/cache_context.py`
  - `lmcache/v1/platform/cpu/device_ops.py`
  - `lmcache/v1/platform/cpu/shm.py`
  - `lmcache/v1/platform/cpu/stub_cpu_device.py`
  - `lmcache/v1/platform/cuda/__init__.py`
  - `lmcache/v1/platform/cuda/cache_context.py`
  - `lmcache/v1/platform/cuda/device_ops.py`
  - `lmcache/v1/platform/cuda/ipc_wrapper.py`
  - `lmcache/v1/platform/cuda/pin_memory.py`
  - `lmcache/v1/platform/cuda/timeline_semaphore_event_ipc.py`
  - `lmcache/v1/platform/cuda/utils.py`
  - `lmcache/v1/platform/event_notifier.py`
  - `lmcache/v1/platform/hpu/__init__.py`
  - `lmcache/v1/platform/hpu/device_ops.py`
  - `lmcache/v1/platform/kv_wrap.py`
  - `lmcache/v1/platform/musa/__init__.py`
  - `lmcache/v1/platform/musa/cache_context.py`
  - `lmcache/v1/platform/musa/device_ops.py`
  - `lmcache/v1/platform/musa/event_ipc.py`
  - `lmcache/v1/platform/musa/ipc_wrapper.py`
  - `lmcache/v1/platform/musa/native_kv_transfer.py`
  - `lmcache/v1/platform/musa/pin_memory.py`
  - `lmcache/v1/platform/musa/tensor_from_ptr.py`
  - `lmcache/v1/platform/ops_types.py`
  - `lmcache/v1/platform/rbln/__init__.py`
  - `lmcache/v1/platform/rbln/device_ops.py`
  - `lmcache/v1/platform/rbln/kv_layout.py`
  - `lmcache/v1/platform/rbln/kv_ops.py`
  - `lmcache/v1/platform/rocm/__init__.py`
  - `lmcache/v1/platform/torch_ops.py`
  - `lmcache/v1/platform/xpu/__init__.py`
  - `lmcache/v1/platform/xpu/device_ops.py`
  - `lmcache/v1/storage_backend/raw_block/__init__.py`
  - `lmcache/v1/storage_backend/raw_block/core.py`
  - `lmcache/v1/storage_backend/raw_block/key_codec.py`
  - `lmcache/v1/system_detection.py`
  - `lmcache/v1/utils/__init__.py`  (added by the import probe)
  - `lmcache/v1/utils/subclass_discovery.py`  (added by the import probe)

- import probe on this sync: stops at non-lmcache dep 'torch' on this machine (fine -- `kvio doctor` verifies on a deps-complete box)

## third-party Python deps (module-level, unconditional)

```
aiohttp
cachetools
cpuinfo
cryptography
msgspec
numba
numpy
prometheus_client
psutil
requests
sortedcontainers
torch
yaml
```
(GPU-free is not torch-free: these modules import torch at module level; the CPU wheel suffices.)

Optional (imported inside try/except; absence tolerated):
```
nvtx
```

## API check

All public symbols kvio calls are present upstream at this ref.
