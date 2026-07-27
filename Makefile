CC = gcc
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Use system libbpf if available (libbpf-dev >= 1.0), else fall back to
# building from source in ./libbpf/
LIBBPF_SYSTEM := $(shell pkg-config --exists libbpf 2>/dev/null && echo yes || echo no)

ifeq ($(LIBBPF_SYSTEM),yes)
  INCLUDES  = $(shell pkg-config --cflags libbpf) -I.
  LIBS_DIR  =
  LIBS      = $(shell pkg-config --libs libbpf) -lelf -lz
  BPFTOOL   = $(shell command -v bpftool || command -v /usr/sbin/bpftool)
else
  LIBBPF_DIR     = ./libbpf
  LIBBPF_HDR_DIR = $(LIBBPF_DIR)/install_headers/usr/include
  INCLUDES       = -I$(LIBBPF_HDR_DIR) -I$(LIBBPF_DIR)/src -I.
  LIBS_DIR       = -L$(LIBBPF_DIR)/src
  LIBS           = -lbpf -lelf -lz
  BPFTOOL        = $(shell command -v bpftool || command -v /usr/sbin/bpftool)
endif

# Compiler flags
CFLAGS     = -g -O2 -Wall -Wextra
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CLANG      = clang

# Targets
TARGET  = syscall_monitor
BPF_OBJ = syscall_monitor.bpf.o
SKEL    = syscall_monitor.skel.h

MMAP_TARGET  = mmap_readamp
MMAP_BPF_OBJ = mmap_readamp.bpf.o
MMAP_SKEL    = mmap_readamp.skel.h

IOU_TARGET  = iouring_monitor
IOU_BPF_OBJ = iouring_monitor.bpf.o
IOU_SKEL    = iouring_monitor.skel.h

NVME_TARGET  = nvme_uring_cmd_monitor
NVME_BPF_OBJ = nvme_uring_cmd_monitor.bpf.o
NVME_SKEL    = nvme_uring_cmd_monitor.skel.h

.PHONY: all clean setup

all: setup $(TARGET) $(MMAP_TARGET) $(IOU_TARGET) $(NVME_TARGET) $(NVMETP_TARGET)

setup:
ifeq ($(LIBBPF_SYSTEM),yes)
	@echo "Using system libbpf ($(shell pkg-config --modversion libbpf))"
else
	@echo "Setting up libbpf from source..."
	@if [ ! -d "$(LIBBPF_DIR)" ]; then \
		git clone --depth 1 https://github.com/libbpf/libbpf.git $(LIBBPF_DIR); \
	fi
	@$(MAKE) -C $(LIBBPF_DIR)/src
	@if [ ! -f "$(LIBBPF_HDR_DIR)/bpf/bpf_helpers.h" ]; then \
		echo "Installing libbpf headers into $(LIBBPF_HDR_DIR)..."; \
		$(MAKE) -C $(LIBBPF_DIR)/src install_headers DESTDIR=../install_headers prefix=/usr; \
	fi
endif

$(BPF_OBJ): syscall_monitor.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c syscall_monitor.bpf.c -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(TARGET): syscall_monitor.c $(SKEL)
	$(CC) $(CFLAGS) $(INCLUDES) syscall_monitor.c $(LIBS_DIR) $(LIBS) -o $@

$(MMAP_BPF_OBJ): mmap_readamp.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c mmap_readamp.bpf.c -o $@

$(MMAP_SKEL): $(MMAP_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(MMAP_TARGET): mmap_readamp.c $(MMAP_SKEL)
	$(CC) $(CFLAGS) $(INCLUDES) mmap_readamp.c $(LIBS_DIR) $(LIBS) -o $@

$(IOU_BPF_OBJ): iouring_monitor.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c iouring_monitor.bpf.c -o $@

$(IOU_SKEL): $(IOU_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(IOU_TARGET): iouring_monitor.c $(IOU_SKEL)
	$(CC) $(CFLAGS) $(INCLUDES) iouring_monitor.c $(LIBS_DIR) $(LIBS) -o $@

$(NVME_BPF_OBJ): nvme_uring_cmd_monitor.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c nvme_uring_cmd_monitor.bpf.c -o $@

$(NVME_SKEL): $(NVME_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(NVME_TARGET): nvme_uring_cmd_monitor.c $(NVME_SKEL)
	$(CC) $(CFLAGS) $(INCLUDES) nvme_uring_cmd_monitor.c $(LIBS_DIR) $(LIBS) -o $@

NVMETP_TARGET  = nvme_tp_monitor
NVMETP_BPF_OBJ = nvme_tp_monitor.bpf.o
NVMETP_SKEL    = nvme_tp_monitor.skel.h

$(NVMETP_BPF_OBJ): nvme_tp_monitor.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c nvme_tp_monitor.bpf.c -o $@

$(NVMETP_SKEL): $(NVMETP_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(NVMETP_TARGET): nvme_tp_monitor.c $(NVMETP_SKEL)
	$(CC) $(CFLAGS) $(INCLUDES) nvme_tp_monitor.c $(LIBS_DIR) $(LIBS) -o $@

# NVMe passthrough workload generator (firing test for the monitor's
# completion probe on hosts with no LMCache stack). Needs liburing-dev;
# not part of 'all' so the monitors build without it.
nvme_uring_cmd_smoke: nvme_uring_cmd_smoke.c
	$(CC) $(CFLAGS) nvme_uring_cmd_smoke.c -luring -o $@

vmlinux.h:
	@echo "Generating vmlinux.h from running kernel..."
	@if [ -n "$(BPFTOOL)" ] && [ -x "$(BPFTOOL)" ]; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	else \
		echo "ERROR: bpftool not found (tried BPFTOOL=$(BPFTOOL))"; \
		exit 1; \
	fi

install-deps:
	@echo "Installing dependencies..."
	@if command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get update; \
		sudo apt-get install -y clang llvm libelf-dev libz-dev linux-tools-common linux-tools-generic build-essential git; \
	elif command -v yum >/dev/null 2>&1; then \
		sudo yum install -y clang llvm elfutils-libelf-devel zlib-devel bpftool kernel-devel git make; \
	elif command -v dnf >/dev/null 2>&1; then \
		sudo dnf install -y clang llvm elfutils-libelf-devel zlib-devel bpftool kernel-devel git make; \
	else \
		echo "Please install dependencies manually:"; \
		echo "- clang, llvm"; \
		echo "- libelf-dev, zlib-dev"; \
		echo "- linux-tools (for bpftool)"; \
		echo "- kernel headers"; \
	fi

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(SKEL) vmlinux.h
	rm -f $(MMAP_TARGET) $(MMAP_BPF_OBJ) $(MMAP_SKEL)
	rm -f $(IOU_TARGET) $(IOU_BPF_OBJ) $(IOU_SKEL)
	rm -f $(NVME_TARGET) $(NVME_BPF_OBJ) $(NVME_SKEL)
	rm -f $(NVMETP_TARGET) $(NVMETP_BPF_OBJ) $(NVMETP_SKEL) nvme_uring_cmd_smoke
	rm -rf $(LIBBPF_DIR)

help:
	@echo "Available targets:"
	@echo "  all          - Build the complete project"
	@echo "  install-deps - Install system dependencies"
	@echo "  setup        - Setup libbpf and check tools"
	@echo "  clean        - Clean build artifacts"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make install-deps  # First time setup"
	@echo "  make all          # Build the project"
	@echo "  sudo ./syscall_monitor  # Run the program"
