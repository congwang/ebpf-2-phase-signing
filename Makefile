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

add_key: add_key.c
	$(CC) $(CFLAGS) -o $@ $< -lkeyutils

# OpenSSL key generation settings
KEY_DIR := keys
PRIVATE_KEY := $(KEY_DIR)/private.key
CERT := $(KEY_DIR)/cert.pem
CERT_DER := $(KEY_DIR)/cert.der

# Generate OpenSSL keys for signing
.PHONY: keys
keys:
	@mkdir -p $(KEY_DIR)
	@openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out $(PRIVATE_KEY)
	@openssl req -new -x509 -config bpf_cert.conf -key $(PRIVATE_KEY) -out $(CERT) -days 365
	@openssl x509 -in $(CERT) -outform DER -out $(CERT_DER)
	@echo "Generated keys in $(KEY_DIR) directory"
	@echo "WARNING: Keep $(PRIVATE_KEY) private and secure!"

.PHONY: clean
clean:
	rm -f sign-ebpf.o bpf-loader program-loader vmlinux.h minimal-sign.bpf.o
	rm -rf $(KEY_DIR)

all: bpf-loader program-loader add_key sign-ebpf.o minimal-sign.bpf.o

.PHONY: clean all
