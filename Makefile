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

minimal-sign.bpf.o: minimal-sign.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) $(BPF_CFLAGS) -c $< -o $@

bpf-loader: bpf-loader.c
	$(CC) $(CFLAGS) $< -o $@ -lbpf

program-loader: program-loader.c
	$(CC) -Wall -o $@ $< -lz -lcrypto -lbpf

# OpenSSL key generation settings
KEY_DIR := keys
PRIVATE_KEY := $(KEY_DIR)/private.key
CERT := $(KEY_DIR)/cert.pem

# Generate OpenSSL keys for signing
.PHONY: keys
keys:
	@mkdir -p $(KEY_DIR)
	@openssl req -x509 -newkey rsa:4096 -keyout $(PRIVATE_KEY) -out $(CERT) -days 365 -nodes -subj "/CN=Test"
	@echo "Generated keys in $(KEY_DIR) directory"
	@echo "WARNING: Keep $(PRIVATE_KEY) private and secure!"

.PHONY: clean
clean:
	rm -f sign-ebpf.o bpf-loader program-loader vmlinux.h minimal-sign.bpf.o
	rm -rf $(KEY_DIR)

all: sign-ebpf.o bpf-loader program-loader minimal-sign.bpf.o

.PHONY: clean all
