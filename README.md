# Keyvault

FreeBSD kernel module for secure key storage and cryptographic operations.

Keys are generated and stored exclusively in kernel space - they never leave the kernel.
Userspace receives only opaque key identifiers and performs crypto operations via ioctl.

## Features

- **Kernel-resident keys**: Key material never exposed to userspace
- **Capability-based access**: Restrict operations when passing fd to other processes
- **FD passing**: Share keys between processes via Unix socket (SCM_RIGHTS)
- **Reference counting**: Safe concurrent access to keys
- **Key lifecycle**: Generation, revocation, expiration, destruction
- **DTrace probes**: Full observability of key and crypto operations

## Supported Algorithms

| Type | Algorithms |
|------|------------|
| AEAD | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 |
| Cipher | AES-128-CBC, AES-256-CBC |
| Signatures | Ed25519 |
| Key Exchange | X25519 |
| Key Derivation | HKDF-SHA256, HKDF-SHA512 |
| MAC | HMAC-SHA256, HMAC-SHA512 |
| Hash | SHA-256, SHA-512 |

## Quick Start

```sh
# Build
make

# Load module (as root)
kldload ./keyvault.ko

# Verify device created
ls -la /dev/keyvault

# Run tests
make test
```

## Usage Example

```c
#include <sys/ioctl.h>
#include <fcntl.h>
#include "keyvault.h"

int fd = open("/dev/keyvault", O_RDWR);

// Generate a key
struct kv_genkey_req gen = {
    .algorithm = KV_ALG_AES256_GCM,
    .key_bits = 256
};
ioctl(fd, KV_IOC_GENKEY, &gen);
uint64_t key_id = gen.key_id;

// Encrypt data
const char *data = "Hello, World!";
size_t data_len = strlen(data);

// Buffers: ciphertext is same size as plaintext for GCM
uint8_t ciphertext[128];          // Must be >= data_len
uint8_t nonce[KV_AEAD_NONCE_SIZE]; // 12 bytes, filled by kernel
uint8_t tag[KV_AEAD_TAG_SIZE];     // 16 bytes, auth tag output

struct kv_aead_encrypt_req enc = {
    .key_id = key_id,
    .plaintext = data,
    .plaintext_len = data_len,
    .ciphertext = ciphertext,
    .ciphertext_len = sizeof(ciphertext),
    .nonce = NULL,                 // NULL = kernel generates random nonce
    .nonce_out = nonce,            // Kernel writes nonce here (12 bytes)
    .tag = tag                     // Kernel writes tag here (16 bytes)
};
ioctl(fd, KV_IOC_AEAD_ENCRYPT, &enc);
// enc.ciphertext_len now contains actual ciphertext length (== data_len)
// nonce[] and tag[] are filled by kernel - save these for decryption!
```

## FD Passing with Capability Restriction

```c
// Process A: Create key and restrict capabilities
int fd = open("/dev/keyvault", O_RDWR);
ioctl(fd, KV_IOC_GENKEY, &gen);

// Remove dangerous capabilities before passing fd
struct kv_restrict_req restrict = {
    .caps = KV_CAP_READONLY  // Only encrypt/decrypt/hash/mac
};
ioctl(fd, KV_IOC_RESTRICT, &restrict);

// Pass fd to Process B via Unix socket (SCM_RIGHTS)
sendmsg(sock, &msg, 0);

// Process B receives fd and can:
// - Encrypt/decrypt with existing keys
// - Compute MACs and hashes
// Process B CANNOT:
// - Generate new keys
// - Destroy or revoke keys
```

## Capability Flags

| Flag | Description |
|------|-------------|
| `KV_CAP_GENKEY` | Generate new keys |
| `KV_CAP_DESTROY` | Destroy keys |
| `KV_CAP_REVOKE` | Revoke keys |
| `KV_CAP_ENCRYPT` | Encrypt data |
| `KV_CAP_DECRYPT` | Decrypt data |
| `KV_CAP_SIGN` | Sign data (Ed25519) |
| `KV_CAP_VERIFY` | Verify signatures |
| `KV_CAP_MAC` | Compute MACs |
| `KV_CAP_HASH` | Compute hashes |
| `KV_CAP_GETINFO` | Query key info |
| `KV_CAP_LIST` | List keys |
| `KV_CAP_RESTRICT` | Further restrict capabilities |
| `KV_CAP_DERIVE` | Derive keys (HKDF) |
| `KV_CAP_EXCHANGE` | Perform key exchange (X25519) |
| `KV_CAP_IMPORT` | Import keys |
| `KV_CAP_ALL` | All capabilities (default) |
| `KV_CAP_READONLY` | Encrypt/decrypt/sign/verify/mac/hash/info/list |

## Deployment

```sh
# Deploy to remote VM
./deploy.sh 192.168.1.100

# On the VM
cd /root/keyvault
./run_tests.sh
```

## DTrace

```sh
# Watch key creation
dtrace -n 'keyvault:::key-create { printf("key=%d alg=%d", arg0, arg1); }'

# Watch crypto operations
dtrace -n 'keyvault:::aead-encrypt { printf("key=%d len=%d", arg0, arg1); }'

# Watch capability denials
dtrace -n 'keyvault:::cap-denied { printf("wanted=%x have=%x", arg0, arg1); }'
```

## Requirements

- FreeBSD 14.0+ or 15.0+
- Kernel source tree at `/usr/src/sys`

## License

BSD-2-Clause
