# eBPF Two-Phase Signing System

This project implements a two-phase signing system for eBPF programs using PKCS#7 signatures. The system provides enhanced security by requiring two separate signatures: an original signature for the program itself, and a 2nd signature that covers both the program and its original signature.

> **⚠️ WARNING ⚠️**  
> **This only provides a proof of concept and is NOT suitable for production use!**

## Overview

### Components

1. **sign-ebpf.c**: The core eBPF LSM (Linux Security Module) program that verifies eBPF program signatures during loading
2. **bpf-loader.c**: The loader for sign-ebpf.o eBPF program
3. **program-loader.c**: User-space program that loads and signs eBPF programs
4. **minimal.bpf.c**: A minimal sample eBPF program for testing

### Technical Implementation

#### Buffer Management

The system uses several key buffers with strict size limits:
- `MAX_DATA_SIZE`: 1MB (1024 * 1024 bytes) for program instructions
- `MAX_SIG_SIZE`: 4KB (4096 bytes) for signatures

Key data structures:
```c
struct original_data {
    __u8 data[MAX_DATA_SIZE];    // Original program data
    __u32 data_len;              // Length of program data
    __u8 sig[MAX_SIG_SIZE];      // Original signature
    __u32 sig_len;               // Length of original signature
};

struct modified_sig {
    __u8 sig[MAX_SIG_SIZE];      // Modified signature
    __u32 sig_len;               // Length of modified signature
};

### How It Works
1. **1st Signature Generation**:
   - The original program instructions stored in the eBPF program are signed using PKCS#7

2. **2nd Signature Generation**:
   - Combines modified program instructions (e.g. by libbpf) and original signature
   - Sign the combined data using PKCS#7

3. **Verification Process**:
   - Uses BPF LSM hooks to intercept eBPF program loading
   - Verifies the 1st signature against original eBPF program data
   - Verifies the 2nd signature against combined data
   - Only if both verifications pass will the program be loaded

## Prerequisites

- Linux kernel 5.15 or later with eBPF and LSM support
- libbpf development files
- OpenSSL development files
- clang and llvm for BPF compilation

Install dependencies on Ubuntu/Debian:
```bash
sudo apt-get install libbpf-dev libssl-dev clang llvm
```

## Building

1. Clone the repository:
```bash
git clone https://github.com/congwang/ebpf-2-phase-signing.git
cd ebpf-2-phase-signing
```

2. Build the project:
```bash
make all
```

This will generate:
- `sign-ebpf.o`: The compiled eBPF LSM program
- `bpf-loader`: The helper program for loading `sign-ebpf.o` eBPF programs
- `program-loader`: The user-space loader program
- `minimal.bpf.o`: The minimal sample eBPF program for testing
- `add_key`: A helper program for adding keys to the keyring

## Usage

### 1. Generate Keys and Certificates

First, generate a key pair and self-signed certificate for signing:

```bash
make keys
```

### 2. Add Keys to the Keyring

Add the private key and certificate to the system keyrings:
```bash
sudo ./add_key keys/cert.der
```

### 3. Load the Signing Verification Program

Load the eBPF LSM program that performs signature verification:

```bash
sudo ./bpf-loader sign-ebpf.o
```

### 4. Sign and Load an eBPF Program

Use the program loader to sign and load your eBPF program:

```bash
# Sign and load the minimal program for testing
sudo ./program-loader minimal.bpf.o keys/private.key keys/cert.pem minimal_prog
```

### 5. Verify Operation

Check the kernel logs to see the verification results:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Security Considerations

1. **Key Management**:
   - Keep private keys secure and separate from production systems
   - Use proper certificate management practices
   - Consider using a hardware security module (HSM) for key storage

### Verification Process Details

The verification happens in multiple steps:

1. **Program Loading Interception**:
   - LSM hook intercepts BPF program loading
   - Checks for required signatures

2. **Original Signature Verification**:
   ```c
   ret = bpf_verify_pkcs7_signature(&orig_data_ptr, &orig_sig_ptr, trusted_keyring);
   if (ret) {
       // Original signature verification failed
       goto out;
   }
   ```

3. **Combined Data Verification**:
   ```c
   ret = bpf_verify_pkcs7_signature(&combined_data_ptr, &sig_ptr, trusted_keyring);
   if (ret) {
       // Modified signature verification failed
       goto out;
   }
   ```

4. **Buffer Validation**:
   - All memory operations use `bpf_dynptr` for safety
   - Strict bounds checking on all buffers
   - Size limitations enforced by verifier

## Debugging

Enable verbose output for detailed verification information:
```bash
sudo ./program-loader -v minimal.bpf.o keys/private.key keys/cert.pem minimal_prog
```

The system provides detailed error reporting through BPF prints:
- Copy failures
- Buffer size violations
- Signature verification failures

View these messages using:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Common Issues and Debugging

1. **Signature Size Issues**:
   - Ensure signatures don't exceed `MAX_SIG_SIZE` (4KB)
   - Check OpenSSL configuration for signature size

2. **Buffer Space Errors**:
   - Monitor total size of program + signature
   - Check debug output for size violations

3. **Keyring Access**:
   - Verify correct keyring permissions
   - Check keyring serial numbers in debug output

4. **Verification Failures**:
   - Enable verbose logging with `-v` flag
   - Check certificate validity and trust chain
   - Verify signature format and encoding

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the GPL License - see the LICENSE file for details.
