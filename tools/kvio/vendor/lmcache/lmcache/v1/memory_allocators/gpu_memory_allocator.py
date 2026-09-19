# SPDX-License-Identifier: Apache-2.0

# Standard
from contextlib import nullcontext
from typing import List, Optional, Union
import threading

# Third Party
import torch

# First Party
from lmcache import torch_dev, torch_device_type
from lmcache.logging import init_logger
from lmcache.utils import _lmcache_nvtx_annotate
from lmcache.v1 import memory_management
from lmcache.v1.memory_allocators.paged_tensor_memory_allocator import (
    PagedTensorMemoryAllocator,
)
from lmcache.v1.memory_allocators.tensor_memory_allocator import TensorMemoryAllocator
from lmcache.v1.memory_management import (
    MemoryAllocatorInterface,
    MemoryFormat,
    MemoryObj,
)


logger = init_logger(__name__)


class GPUMemoryAllocator(MemoryAllocatorInterface):
    """Allocates memory in the pre-allocated GPU memory."""

    def __init__(
        self,
        size: int,
        device=torch_device_type,
        align_bytes: Optional[int] = None,
        use_paging: bool = False,
        **kwargs,
    ) -> None:
        """
        :param int size: The size of the GPU memory in bytes.
        :param Optional[int] align_bytes: The byte alignment for allocations.
        """
        if not torch_dev.is_available():
            device = "cpu"

        # The buffer starts and ends on a host page boundary so it can be
        # exported as a dma-buf (the driver refuses a range that is not page
        # aligned).  Over-allocate by one page and slice to the first page
        # boundary; the extra page is the cost of the guarantee.
        page = 4096
        aligned_size = (size + page - 1) // page * page
        self._backing = torch.empty(
            aligned_size + page, dtype=torch.uint8, device=device
        )
        start = (-self._backing.data_ptr()) % page
        self.tensor = self._backing[start : start + aligned_size]

        self.allocator: MemoryAllocatorInterface
        if use_paging:
            assert "shapes" in kwargs, (
                "shapes must be specified for paged memory allocator"
            )
            assert "dtypes" in kwargs, (
                "dtypes must be specified for paged memory allocator"
            )
            assert "fmt" in kwargs, "fmt must be specified for paged memory allocator"
            self.allocator = PagedTensorMemoryAllocator(
                tensor=self.tensor,
                shapes=kwargs["shapes"],
                dtypes=kwargs["dtypes"],
                fmt=kwargs["fmt"],
            )
        else:
            kwargs = {}
            if align_bytes is not None:
                kwargs["align_bytes"] = align_bytes
            self.allocator = TensorMemoryAllocator(self.tensor, **kwargs)

        self.device_mem_lock = threading.Lock() if not use_paging else nullcontext()
        # dma-buf regions of the GPU buffer, exported on first request; they let
        # a raw_block backend register the paged buffers with its NVMe device so
        # loads and stores DMA straight to device memory.
        self._dmabuf_regions: Optional[list[tuple[int, int, int]]] = None

    @_lmcache_nvtx_annotate
    def allocate(
        self,
        shapes: Union[torch.Size, list[torch.Size]],
        dtypes: Union[torch.dtype, list[torch.dtype]],
        fmt: MemoryFormat = MemoryFormat.KV_2LTD,
        allocator_type: Optional[str] = None,
    ) -> Optional[MemoryObj]:
        """Allocate one GPU-backed memory object.

        Args:
            shapes: Logical tensor shape or shapes to allocate.
            dtypes: Logical tensor dtype or dtypes to allocate.
            fmt: Memory format stored in the returned metadata.
            allocator_type: Optional allocator type string.

        Returns:
            A memory object, or ``None`` if the inner allocator is full.
        """
        with self.device_mem_lock:
            return self.allocator.allocate(shapes, dtypes, fmt, str(self))

    @_lmcache_nvtx_annotate
    def batched_allocate(
        self,
        shapes: Union[torch.Size, list[torch.Size]],
        dtypes: Union[torch.dtype, list[torch.dtype]],
        batch_size: int,
        fmt: MemoryFormat = MemoryFormat.KV_2LTD,
        allocator_type: Optional[str] = None,
    ) -> Optional[List[MemoryObj]]:
        """Allocate multiple GPU-backed memory objects.

        Args:
            shapes: Logical tensor shape or shapes for each allocation.
            dtypes: Logical tensor dtype or dtypes for each allocation.
            batch_size: Number of memory objects to allocate.
            fmt: Memory format stored in each returned object's metadata.
            allocator_type: Optional allocator type string.

        Returns:
            Memory objects, or ``None`` if the inner allocator is full.
        """
        with self.device_mem_lock:
            return self.allocator.batched_allocate(
                shapes, dtypes, batch_size, fmt, str(self)
            )

    def free(self, memory_obj: MemoryObj, allocator_type: Optional[str] = None) -> None:
        """Free one GPU-backed memory object.

        Args:
            memory_obj: Memory object to release.
            allocator_type: Optional allocator type string.
        """
        with self.device_mem_lock:
            self.allocator.free(memory_obj)

    def batched_free(
        self,
        memory_objs: List[MemoryObj],
        allocator_type: Optional[str] = None,
        update_stats: bool = True,
    ) -> None:
        """Free multiple GPU-backed memory objects.

        Args:
            memory_objs: Memory objects to release.
            allocator_type: Optional allocator type string.
            update_stats: Whether to update allocator statistics.
        """
        with self.device_mem_lock:
            self.allocator.batched_free(memory_objs)

    def memcheck(self) -> bool:
        """Return whether allocator state is consistent."""
        with self.device_mem_lock:
            return self.allocator.memcheck()

    def __str__(self) -> str:
        return "GPUMemoryAllocator"

    def get_paged_buffers(self) -> Optional[tuple[torch.Tensor, ...]]:
        """Paged buffers for fixed-buffer registration, when paged."""
        if isinstance(self.allocator, PagedTensorMemoryAllocator):
            return self.allocator.get_paged_buffers()
        return None

    def get_paged_dmabuf_regions(self) -> Optional[list[tuple[int, int]]]:
        """
        For each paged buffer, the (dma-buf fd, mapped base) of the dma-buf
        chunk of the GPU buffer that contains it, exporting the buffer on
        first use.  None when not paged or when the device cannot export.
        """
        buffers = self.get_paged_buffers()
        if not buffers:
            return None
        if self._dmabuf_regions is None:
            try:
                self._dmabuf_regions = memory_management.export_device_dmabufs(
                    self.tensor
                )
            except Exception as exc:
                logger.warning(
                    "GPUMemoryAllocator: dma-buf export unavailable (%s); "
                    "device-direct I/O disabled",
                    exc,
                )
                self._dmabuf_regions = []
        if not self._dmabuf_regions:
            return None
        regions = [
            memory_management.get_dmabuf_region(buf.data_ptr()) for buf in buffers
        ]
        if any(r is None for r in regions):
            return None
        return regions  # type: ignore[return-value]
