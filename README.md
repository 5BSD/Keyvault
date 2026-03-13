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
| AEAD | AES-128-GCM, AES-256-GCM |
| Cipher | AES-128-CBC, AES-256-CBC |
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
struct kv_aead_encrypt_req enc = {
    .key_id = key_id,
    .plaintext = data,
    .plaintext_len = data_len,
    .ciphertext = output,
    .ciphertext_len = sizeof(output),
    .nonce_out = nonce,
    .tag = tag,
    .tag_len = 16
};
ioctl(fd, KV_IOC_AEAD_ENCRYPT, &enc);
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
| `KV_CAP_SIGN` | Sign data (Phase 2) |
| `KV_CAP_VERIFY` | Verify signatures |
| `KV_CAP_MAC` | Compute MACs |
| `KV_CAP_HASH` | Compute hashes |
| `KV_CAP_GETINFO` | Query key info |
| `KV_CAP_LIST` | List keys |
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

## See Also

- [PLAN.md](PLAN.md) - Detailed implementation plan and roadmap
