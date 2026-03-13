# Keyvault Implementation TODO

## Current Focus: Phase 3

See Future section below for upcoming features.

---

## Completed: Phase 2 - Ed25519 Signing

### Implementation (DONE)

- [x] Created Ed25519 implementation using crypto.ko primitives
  - `keyvault_ed25519.c` - sign/verify/keypair functions
  - `keyvault_ed25519.h` - public interface
  - `crypto_compat.h` - SHA-512 compatibility layer

- [x] Updated keyvault.h (Public Header)
  - [x] `KV_ALG_ED25519` constant (value: 30)
  - [x] `KV_IOC_GET_PUBKEY` ioctl definition
  - [x] `struct kv_getpubkey_req` structure

- [x] Updated keyvault_internal.h
  - [x] Extended `struct kv_key` with `kk_pubkey`, `kk_publen`, `kk_type`
  - [x] Added `KV_KEY_TYPE_SYMMETRIC` and `KV_KEY_TYPE_ASYMMETRIC`

- [x] Updated keyvault_key.c
  - [x] Ed25519 entry in algorithm table
  - [x] `kv_key_alloc_ed25519()` for keypair generation
  - [x] Updated `kv_key_free_material()` to free public key

- [x] Updated keyvault_crypto.c
  - [x] `kv_crypto_sign()` - Ed25519 detached signatures
  - [x] `kv_crypto_verify()` - signature verification
  - [x] `kv_crypto_get_pubkey()` - export public key

- [x] Updated keyvault.c
  - [x] `KV_IOC_GET_PUBKEY` handler

- [x] Updated Makefile
  - [x] Added keyvault_ed25519.c to SRCS
  - [x] Added SHA-512 include path

- [x] Tests (5 new tests)
  - [x] Ed25519 key generation test
  - [x] Sign/verify round-trip test
  - [x] Public key export test
  - [x] Tampered message verification failure
  - [x] Wrong key verification failure

- [x] Documentation
  - [x] DEPENDENCIES.md - runtime and build dependencies

### Technical Notes

```c
// Key sizes
#define KV_ED25519_SEED_SIZE      32  // Random seed
#define KV_ED25519_PUBLIC_SIZE    32  // Public key
#define KV_ED25519_SECRET_SIZE    64  // seed || public_key
#define KV_ED25519_SIGNATURE_SIZE 64  // Signature

// API
int kv_ed25519_keypair(pk, sk);           // Generate keypair
int kv_ed25519_sign_detached(sig, m, mlen, sk);
int kv_ed25519_verify_detached(sig, m, mlen, pk);
```

### Security Notes
- Secret key (64 bytes) NEVER leaves kernel
- Public key CAN be exported via `KV_IOC_GET_PUBKEY`
- Uses `explicit_bzero()` on secret key during destruction
- Validates key type before signing (must be Ed25519)

---

## Completed: Phase 1

- [x] Module skeleton (`keyvault.c`)
- [x] Key management (`keyvault_key.c`)
- [x] Crypto operations (`keyvault_crypto.c`)
- [x] Public header (`keyvault.h`)
- [x] Internal header (`keyvault_internal.h`)
- [x] DTrace probes
- [x] Capability system (`KV_IOC_RESTRICT`, `KV_IOC_GETCAPS`)
- [x] FD passing with capability restrictions
- [x] Unit tests (9/9 passing)
- [x] Integration tests - FD passing (7/7 passing)
- [x] Deploy script (`deploy.sh`)
- [x] AES-128-GCM, AES-256-GCM
- [x] AES-128-CBC, AES-256-CBC
- [x] HMAC-SHA256, HMAC-SHA512
- [x] SHA-256, SHA-512

---

## Future: Phase 3

- [ ] ChaCha20-Poly1305 AEAD
- [ ] X25519 key exchange
- [ ] HKDF key derivation
- [ ] Async operations (kevent)
- [ ] Capsicum integration
