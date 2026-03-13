# Keyvault FreeBSD Kernel Module - Implementation Plan

## Overview

A FreeBSD kernel module providing secure key storage and cryptographic operations.
Keys are generated and stored exclusively in kernel space, never exposed to userland.

## Architecture

```
Userspace                    Kernel
─────────────────────────────────────────────────────
Process A ─┐
           ├─► /dev/keyvault ─► kv_softc (device)
Process B ─┘                         │
     │                               ▼
     │                         kv_file (per-open context)
     │                            │  + capability flags
   fd passing                     │
   via SCM_RIGHTS                 ▼
     │                       kv_key objects (refcounted)
     ▼                            │
  Restricted                      ▼
  capabilities              OpenCrypto Framework
                                  │
                                  ▼
                           crypto drivers (AES-NI, etc.)
```

## Current Status

### Phase 1: Core Infrastructure - COMPLETE ✓

| Component | Status | Notes |
|-----------|--------|-------|
| Module skeleton | ✓ | `keyvault.c` - device registration, ioctl dispatch |
| Key management | ✓ | `keyvault_key.c` - lifecycle, reference counting |
| Crypto operations | ✓ | `keyvault_crypto.c` - AES-GCM, AES-CBC, HMAC, SHA |
| Public header | ✓ | `keyvault.h` - ioctl interface |
| Internal header | ✓ | `keyvault_internal.h` - kernel structures |
| DTrace probes | ✓ | Key lifecycle and crypto operation tracing |
| Capability system | ✓ | `KV_IOC_RESTRICT`, `KV_IOC_GETCAPS` |
| FD passing | ✓ | Works with capability restrictions |
| Unit tests | ✓ | 9/9 tests passing |
| Integration tests | ✓ | FD passing server/client (7/7 tests) |
| Deploy script | ✓ | `deploy.sh` for remote VM deployment |

### Implemented Algorithms

| Algorithm | Constant | Status |
|-----------|----------|--------|
| AES-128-GCM | `KV_ALG_AES128_GCM` | ✓ Implemented |
| AES-256-GCM | `KV_ALG_AES256_GCM` | ✓ Implemented |
| AES-128-CBC | `KV_ALG_AES128_CBC` | ✓ Implemented |
| AES-256-CBC | `KV_ALG_AES256_CBC` | ✓ Implemented |
| HMAC-SHA256 | `KV_ALG_HMAC_SHA256` | ✓ Implemented |
| HMAC-SHA512 | `KV_ALG_HMAC_SHA512` | ✓ Implemented |
| SHA-256 | `KV_ALG_SHA256` | ✓ Implemented |
| SHA-512 | `KV_ALG_SHA512` | ✓ Implemented |

### Implemented ioctls

| ioctl | Purpose | Status |
|-------|---------|--------|
| `KV_IOC_GENKEY` | Generate key, return key_id | ✓ |
| `KV_IOC_DESTROY` | Destroy key by key_id | ✓ |
| `KV_IOC_GETINFO` | Get key metadata | ✓ |
| `KV_IOC_LIST` | List key_ids in context | ✓ |
| `KV_IOC_REVOKE` | Mark key as revoked | ✓ |
| `KV_IOC_RESTRICT` | Restrict fd capabilities | ✓ |
| `KV_IOC_GETCAPS` | Get current capabilities | ✓ |
| `KV_IOC_ENCRYPT` | AES-CBC encryption | ✓ |
| `KV_IOC_DECRYPT` | AES-CBC decryption | ✓ |
| `KV_IOC_AEAD_ENCRYPT` | AES-GCM encryption | ✓ |
| `KV_IOC_AEAD_DECRYPT` | AES-GCM decryption | ✓ |
| `KV_IOC_MAC` | HMAC generation | ✓ |
| `KV_IOC_HASH` | SHA hash computation | ✓ |
| `KV_IOC_SIGN` | Digital signature | Stub (Phase 2) |
| `KV_IOC_VERIFY` | Signature verification | Stub (Phase 2) |

---

## Phase 2: Asymmetric Cryptography - PLANNED

FreeBSD kernel includes libsodium with Ed25519 support. No external dependencies needed.

### Available Kernel APIs

```c
#include <crypto/curve25519.h>          // X25519 key exchange
#include <sodium/crypto_sign_ed25519.h> // Ed25519 signatures (via crypto.ko)
```

### Planned Algorithms

| Algorithm | Constant | Kernel Support | Priority |
|-----------|----------|----------------|----------|
| Ed25519 | `KV_ALG_ED25519` | ✓ libsodium in crypto.ko | High |
| X25519 | `KV_ALG_X25519` | ✓ curve25519.h | Medium |
| ECDSA P-256 | `KV_ALG_ECDSA_P256` | ✗ Not in kernel | Skip |
| RSA | `KV_ALG_RSA*` | ✗ Not in kernel | Skip |

### Phase 2 Tasks

- [ ] Add Ed25519 key generation (`crypto_sign_ed25519_seed_keypair`)
- [ ] Implement `KV_IOC_SIGN` for Ed25519 (`crypto_sign_ed25519_detached`)
- [ ] Implement `KV_IOC_VERIFY` for Ed25519 (`crypto_sign_ed25519_verify_detached`)
- [ ] Add `KV_IOC_GET_PUBKEY` to export Ed25519 public key (safe - not secret)
- [ ] Update tests for Ed25519 signing/verification
- [ ] Optional: X25519 key exchange for DH

### Ed25519 Key Structure

```c
// Ed25519 key sizes (from libsodium)
#define crypto_sign_ed25519_SEEDBYTES      32  // Secret seed
#define crypto_sign_ed25519_PUBLICKEYBYTES 32  // Public key
#define crypto_sign_ed25519_SECRETKEYBYTES 64  // seed + public key
#define crypto_sign_ed25519_BYTES          64  // Signature size
```

---

## Phase 3: Advanced Features - FUTURE

### 3.1 ChaCha20-Poly1305 Support
Already available in OpenCrypto (`CRYPTO_CHACHA20_POLY1305`).

- [ ] Add `KV_ALG_CHACHA20_POLY1305`
- [ ] Implement AEAD operations using ChaCha20-Poly1305

### 3.2 Key Derivation Functions
Can be built from existing HMAC primitives.

- [ ] HKDF (HMAC-based Key Derivation Function)
- [ ] `KV_IOC_DERIVE` ioctl

### 3.3 Async Operations (Optional)
For high-throughput use cases.

- [ ] kevent-based completion notification
- [ ] Non-blocking ioctl mode

### 3.4 Capsicum Integration
For sandboxed applications.

- [ ] Capability mode compatibility
- [ ] cap_rights integration

---

## File Layout

```
keyvault/
├── PLAN.md                 # This file
├── README.md               # User documentation
├── Makefile                # Kernel module makefile
├── deploy.sh               # VM deployment script
├── keyvault.h              # Public header (ioctl definitions)
├── keyvault_internal.h     # Private kernel structures
├── keyvault.c              # Module init, device, ioctl dispatch
├── keyvault_key.c          # Key management, capabilities
├── keyvault_crypto.c       # Crypto operations
└── tests/
    ├── Makefile            # Test build
    ├── kv_test.c           # Main test suite
    ├── kv_fdpass_server.c  # FD passing demo server
    └── kv_fdpass_client.c  # FD passing demo client
```

## Build & Test

```sh
# Build module
make

# Load module
sudo kldload ./keyvault.ko

# Run tests
sudo make test

# Or deploy to VM
./deploy.sh <vm-ip>
ssh root@<vm-ip>
cd /root/keyvault
./run_tests.sh
```

## DTrace Probes

```sh
# Key lifecycle
dtrace -n 'keyvault:::key-create { printf("key=%d alg=%d", arg0, arg1); }'
dtrace -n 'keyvault:::key-destroy { printf("key=%d", arg0); }'
dtrace -n 'keyvault:::key-revoke { printf("key=%d", arg0); }'

# Crypto operations
dtrace -n 'keyvault:::aead-encrypt { printf("key=%d len=%d err=%d", arg0, arg1, arg2); }'
dtrace -n 'keyvault:::aead-decrypt { printf("key=%d len=%d err=%d", arg0, arg1, arg2); }'

# Errors
dtrace -n 'keyvault:::cap-denied { printf("cap=%x have=%x", arg0, arg1); }'
```

## Security Notes

1. **Key isolation**: Keys in kernel memory, never exposed to userspace
2. **Secure destruction**: `explicit_bzero()` before `free()`
3. **Capability restriction**: FD receivers can only use permitted operations
4. **No key export**: Only key_id returned, never key material
5. **Revocation**: Revoked keys return EACCES for new operations
6. **Expiration**: Expired keys return ESTALE
