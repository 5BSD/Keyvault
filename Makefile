# Keyvault - FreeBSD Kernel Module
# Secure kernel-space key storage and cryptographic operations
#
# Build:    make
# Install:  make load (as root, uses bsd.kmod.mk target)
# Unload:   make unload (as root, uses bsd.kmod.mk target)
# Test:     make test (as root)
# Clean:    make clean
#
# Dependencies:
#   - crypto.ko must be loaded (provides Ed25519 primitives)

KMOD=	keyvault
SRCS=	keyvault.c keyvault_key.c keyvault_crypto.c keyvault_ed25519.c \
	keyvault_x25519.c keyvault_hkdf.c

# Include path for SHA-512 header
CFLAGS+=	-I/usr/src/sys/crypto/sha2

# Enable DTrace SDT probes
CFLAGS+=	-DKDTRACE_HOOKS

# Debug build (uncomment for development)
#CFLAGS+=	-g -O0 -DDEBUG
#DEBUG_FLAGS=	-g

.include <bsd.kmod.mk>

# Additional targets for convenience
.PHONY: test clean-test reload

reload:
	-kldunload ${KMOD}
	kldload ./${KMOD}.ko

test:
	@echo "Building module..."
	@${MAKE} all
	@echo "Loading module..."
	@kldload ./${KMOD}.ko || true
	@echo "Building test program..."
	@(cd tests && ${MAKE})
	@echo "Running tests..."
	@tests/kv_test
	@echo "Unloading module..."
	@-kldunload ${KMOD}

clean-test:
	@(cd tests && ${MAKE} clean)
