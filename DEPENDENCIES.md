# Keyvault Dependencies

## Runtime Dependencies

### crypto.ko (Required)

The `keyvault.ko` module depends on `crypto.ko` for:

1. **OpenCrypto Framework** - Used for symmetric encryption (AES-GCM, AES-CBC), MAC (HMAC-SHA256, HMAC-SHA512), and hashing (SHA-256, SHA-512)

2. **Ed25519 Primitives** - The Ed25519 digital signature implementation uses low-level primitives from libsodium's `ed25519_ref10.c` which is compiled into `crypto.ko`:
   - `ge25519_scalarmult_base()` - Base point multiplication for key generation
   - `ge25519_p3_tobytes()` - Point to bytes conversion
   - `ge25519_frombytes_negate_vartime()` - Bytes to point conversion
   - `ge25519_double_scalarmult_vartime()` - Signature verification
   - `sc25519_reduce()` - Scalar reduction mod L
   - `sc25519_muladd()` - Scalar multiply-add
   - `ge25519_has_small_order()` - Key validation
   - `sc25519_is_canonical()` - Signature validation

### Loading Dependencies

Before loading `keyvault.ko`, ensure `crypto.ko` is loaded:

```sh
# Check if crypto.ko is loaded
kldstat | grep crypto

# Load crypto.ko if needed
kldload crypto

# Then load keyvault.ko
kldload ./keyvault.ko
```

The module declares its dependency via:
```c
MODULE_DEPEND(keyvault, crypto, 1, 1, 1);
```

This means `kldload keyvault` will automatically load `crypto` if available.

## Build Dependencies

### FreeBSD Source Tree

The module requires access to FreeBSD kernel source headers:

- `/usr/src/sys/` - Kernel headers
- `/usr/src/sys/crypto/sha2/sha512.h` - SHA-512 for Ed25519 signatures
- `/usr/src/sys/opencrypto/cryptodev.h` - OpenCrypto framework

### Compiler

- Clang (FreeBSD default) or GCC
- Standard FreeBSD kernel module build infrastructure (`bsd.kmod.mk`)

## Algorithm Support Matrix

| Algorithm      | Backend            | Module       |
|---------------|-------------------|--------------|
| AES-128-GCM   | OpenCrypto        | crypto.ko    |
| AES-256-GCM   | OpenCrypto        | crypto.ko    |
| AES-128-CBC   | OpenCrypto        | crypto.ko    |
| AES-256-CBC   | OpenCrypto        | crypto.ko    |
| HMAC-SHA256   | OpenCrypto        | crypto.ko    |
| HMAC-SHA512   | OpenCrypto        | crypto.ko    |
| SHA-256       | OpenCrypto        | crypto.ko    |
| SHA-512       | OpenCrypto        | crypto.ko    |
| Ed25519       | ed25519_ref10 + SHA-512 | crypto.ko |

## Notes

- The Ed25519 implementation is self-contained within keyvault.ko for the sign/verify logic, but relies on crypto.ko for the mathematical primitives
- All cryptographic operations use kernel-approved random number generation via `arc4random_buf()`
- Key material never leaves kernel space; only public keys can be exported for Ed25519
