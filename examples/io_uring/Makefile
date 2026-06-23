# Phase 1 controlled io_uring example. Needs liburing-dev.
# Kept self-contained so it does not perturb the top-level ebpf-syscall build.
CC      ?= gcc
CFLAGS  ?= -g -O2 -Wall -Wextra
LIBURING_CFLAGS := $(shell pkg-config --cflags liburing 2>/dev/null)
LIBURING_LIBS   := $(shell pkg-config --libs liburing 2>/dev/null || echo -luring)

TARGET = io_uring_demo

.PHONY: all clean check-liburing
all: check-liburing $(TARGET)

check-liburing:
	@pkg-config --exists liburing 2>/dev/null && \
	  echo "liburing $(shell pkg-config --modversion liburing)" || \
	  { echo "WARNING: liburing not found via pkg-config; trying -luring"; }

$(TARGET): io_uring_demo.c
	$(CC) $(CFLAGS) $(LIBURING_CFLAGS) $< $(LIBURING_LIBS) -o $@

clean:
	rm -f $(TARGET) /tmp/io_uring_demo.dat
