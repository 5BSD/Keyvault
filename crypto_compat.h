/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Keyvault Authors
 *
 * Compatibility layer for libsodium Ed25519 in FreeBSD kernel
 *
 * Maps libsodium crypto_hash_sha512_* API to FreeBSD kernel SHA512_* API
 */

#ifndef _KEYVAULT_CRYPTO_COMPAT_H_
#define _KEYVAULT_CRYPTO_COMPAT_H_

#ifdef _KERNEL

#include <sys/types.h>
#include <sys/systm.h>		/* explicit_bzero */
#include <crypto/sha2/sha512.h>

/*
 * Map libsodium SHA-512 types to FreeBSD kernel types
 */
typedef SHA512_CTX crypto_hash_sha512_state;

#define crypto_hash_sha512_BYTES SHA512_DIGEST_LENGTH

/*
 * Map libsodium SHA-512 functions to FreeBSD kernel functions
 */
static inline int
crypto_hash_sha512_init(crypto_hash_sha512_state *state)
{
	SHA512_Init(state);
	return 0;
}

static inline int
crypto_hash_sha512_update(crypto_hash_sha512_state *state,
    const unsigned char *in, unsigned long long inlen)
{
	SHA512_Update(state, in, (size_t)inlen);
	return 0;
}

static inline int
crypto_hash_sha512_final(crypto_hash_sha512_state *state,
    unsigned char *out)
{
	SHA512_Final(out, state);

	/* Zero intermediate hash state to prevent information leakage */
	explicit_bzero(state, sizeof(*state));
	return 0;
}

static inline int
crypto_hash_sha512(unsigned char *out, const unsigned char *in,
    unsigned long long inlen)
{
	SHA512_CTX ctx;

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, in, (size_t)inlen);
	SHA512_Final(out, &ctx);

	/* Zero intermediate hash state to prevent information leakage */
	explicit_bzero(&ctx, sizeof(ctx));
	return 0;
}

/*
 * Constant-time memory comparison (from libsodium)
 */
static inline int
sodium_memcmp(const void *b1_, const void *b2_, size_t len)
{
	const volatile unsigned char *b1 =
	    (const volatile unsigned char *)b1_;
	const volatile unsigned char *b2 =
	    (const volatile unsigned char *)b2_;
	size_t i;
	volatile unsigned char d = 0U;

	for (i = 0U; i < len; i++) {
		d |= b1[i] ^ b2[i];
	}
	return (1 & ((d - 1) >> 8)) - 1;
}

/*
 * Constant-time 32-byte comparison
 */
static inline int
crypto_verify_32(const unsigned char *x, const unsigned char *y)
{
	return sodium_memcmp(x, y, 32);
}

#endif /* _KERNEL */

#endif /* _KEYVAULT_CRYPTO_COMPAT_H_ */
