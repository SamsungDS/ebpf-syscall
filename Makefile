CC = gcc
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Directories
LIBBPF_DIR = ./libbpf
INCLUDES = -I$(LIBBPF_DIR)/src -I.
LIBS_DIR = -L$(LIBBPF_DIR)/src
LIBS = -lbpf -lelf -lz

# Compiler flags
CFLAGS = -g -O2 -Wall -Wextra
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

# Tools
CLANG = clang
BPFTOOL = bpftool

# Targets
TARGET = syscall_monitor
BPF_OBJ = syscall_monitor.bpf.o
SKEL = syscall_monitor.skel.h

.PHONY: all clean setup

all: setup $(TARGET)

setup:
	@echo "Setting up libbpf..."
	@if [ ! -d "$(LIBBPF_DIR)" ]; then \
		git clone --depth 1 https://github.com/libbpf/libbpf.git $(LIBBPF_DIR); \
	fi
	@$(MAKE) -C $(LIBBPF_DIR)/src
	@echo "Checking for bpftool..."
	@if ! command -v bpftool >/dev/null 2>&1; then \
		echo "Installing bpftool..."; \
		sudo apt-get update && sudo apt-get install -y linux-tools-common linux-tools-generic || \
		sudo yum install -y bpftool || \
		echo "Please install bpftool manually"; \
	fi

$(BPF_OBJ): syscall_monitor.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c syscall_monitor.bpf.c -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(TARGET): syscall_monitor.c $(SKEL)
	$(CC) $(CFLAGS) $(INCLUDES) syscall_monitor.c $(LIBS_DIR) $(LIBS) -o $@

vmlinux.h:
	@echo "Generating vmlinux.h..."
	@if command -v bpftool >/dev/null 2>&1; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	else \
		echo "bpftool not found, downloading vmlinux.h..."; \
		curl -s https://raw.githubusercontent.com/libbpf/libbpf-bootstrap/master/vmlinux/vmlinux.h -o vmlinux.h; \
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
