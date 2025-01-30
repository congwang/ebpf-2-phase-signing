# eBPF Two-Phase Signing System

This project implements a two-phase signing system for eBPF programs using PKCS#7 signatures. The system provides enhanced security by requiring two separate signatures: a 1st signature for the original program itself, and a 2nd signature that covers both the modified program and its original signature.

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
```

## Background and Design

### The Challenge with eBPF Program Signing

Traditional code signing approaches don't work well with eBPF programs due to their unique loading process. Here's why:

1. **Post-Compilation Modifications**:
   - When you compile an eBPF program, the resulting binary isn't in its final form
   - The libbpf library must modify this binary before it can run in the kernel
   - These modifications include:
     - Patching relocations
     - Updating map file descriptors
     - Other runtime adjustments

2. **Traditional Signing Problem**:
   - If you simply signed the original binary
   - The signature would become invalid after libbpf's necessary modifications
   - This makes traditional single-signature approaches ineffective

### Two-Phase Signing Solution

This project introduces a two-phase signing approach that mirrors the eBPF program preparation and loading process:

#### Phase 1: Baseline Signature
- Generated when the eBPF program is initially compiled
- Signs the original, unmodified program
- Serves as proof that the original program came from a trusted source
- Similar to getting a document notarized before filling in the blanks

#### Phase 2: Modified Program Signature
- Takes place after libbpf has made its necessary modifications
- Creates a signature covering:
  - The modified program
  - The original signature from Phase 1
- Establishes a chain of trust
- Proves modifications were authorized and applied to legitimate code

### Verification Process

When loading an eBPF program, the kernel performs verification in sequence:

1. **Original Program Verification**:
   - Verifies the original program against its baseline signature
   - Establishes that we started with trusted code

2. **Modified Program Verification**:
   - Verifies the secondary signature
   - Confirms that modifications were authorized
   - Ensures no unauthorized tampering occurred

### Benefits of This Approach

1. **Practical Security**:
   - Maintains security while accommodating necessary program modifications
   - Similar to legal documents with initial notarization and subsequent verification

2. **Strong Auditability**:
   - If verification fails, you can pinpoint the exact stage of failure
   - Helps distinguish between:
     - Compromised original program
     - Unauthorized post-compilation modifications

3. **Chain of Trust**:
   - Each phase builds upon the previous one
   - Creates a verifiable link between original and modified code
   - Prevents signature stripping attacks

## How It Works

The implementation follows the two-phase signing process:

1. **1st Signature Generation**:
   - The original eBPF program binary is signed using PKCS#7
   - This happens before any libbpf modifications
   - Establishes the program's original trusted state

2. **2nd Signature Generation**:
   - After libbpf processes the program (relocations, map FDs, etc.)
   - The modified program and original signature are combined
   - This combined data is signed with PKCS#7
   - Proves the modifications were authorized

3. **Runtime Verification**:
   - Uses BPF LSM hooks to intercept eBPF program loading
   - First the kernel verifies the original signature against the unmodified program data
   - Then the kernel verifies the second signature against the combined data
   - Program loading proceeds only if both verifications succeed
   - Failures provide detailed diagnostics about which phase failed

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
- `bpf-loader`: The helper program for loading the `sign-ebpf.o` eBPF program
- `program-loader`: The user-space loader program for signing and loading eBPF programs
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

You should see the verification result from the output of the program loader.
If any failure, check the kernel logs to see the verification results:

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
