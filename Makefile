CLANG ?= clang
CFLAGS := -g -O2 -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERNEL_HEADERS := /usr/src/linux-headers-$(shell uname -r)
BPF_CFLAGS := -target bpf \
              -D__TARGET_ARCH_$(ARCH) \
              -I/usr/include/$(shell uname -m)-linux-gnu \
              -I$(KERNEL_HEADERS)
BPFTOOL ?= bpftool

# First generate vmlinux.h from the running kernel
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Make sign-ebpf.o depend on vmlinux.h
sign-ebpf.o: sign-ebpf.c vmlinux.h
	$(CLANG) $(CFLAGS) $(BPF_CFLAGS) -c $< -o $@

bpf-loader: bpf-loader.c
	$(CC) $(CFLAGS) $< -o $@ -lbpf

.PHONY: clean
clean:
	rm -f sign-ebpf.o bpf-loader vmlinux.h

all: sign-ebpf.o bpf-loader
