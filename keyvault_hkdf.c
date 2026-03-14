/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024-2025 Keyvault Authors
 *
 * HKDF (HMAC-based Key Derivation Function) implementation
 * RFC 5869
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

#include <crypto/sha2/sha256.h>
#include <crypto/sha2/sha512.h>

#include "keyvault_hkdf.h"

MALLOC_DECLARE(M_KEYVAULT);

/*
 * Hash parameters
 */
#define SHA256_BLOCK_SIZE	64
#define SHA256_DIGEST_SIZE	32
#define SHA512_BLOCK_SIZE	128
#define SHA512_DIGEST_SIZE	64

/*
 * Get hash parameters
 */
static int
hkdf_hash_params(int hash_alg, size_t *hash_len, size_t *block_len)
{
	switch (hash_alg) {
	case KV_HKDF_HASH_SHA256:
		*hash_len = SHA256_DIGEST_SIZE;
		*block_len = SHA256_BLOCK_SIZE;
		return (0);
	case KV_HKDF_HASH_SHA512:
		*hash_len = SHA512_DIGEST_SIZE;
		*block_len = SHA512_BLOCK_SIZE;
		return (0);
	default:
		return (EINVAL);
	}
}

/*
 * HMAC-SHA256
 */
static void
hmac_sha256(unsigned char *out,
    const unsigned char *key, size_t key_len,
    const unsigned char *data, size_t data_len)
{
	SHA256_CTX ctx;
	unsigned char k_ipad[SHA256_BLOCK_SIZE];
	unsigned char k_opad[SHA256_BLOCK_SIZE];
	unsigned char tk[SHA256_DIGEST_SIZE];
	size_t i;

	/* If key is longer than block size, hash it first */
	if (key_len > SHA256_BLOCK_SIZE) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, key, key_len);
		SHA256_Final(tk, &ctx);
		key = tk;
		key_len = SHA256_DIGEST_SIZE;
	}

	/* XOR key with ipad and opad */
	memset(k_ipad, 0x36, SHA256_BLOCK_SIZE);
	memset(k_opad, 0x5c, SHA256_BLOCK_SIZE);
	for (i = 0; i < key_len; i++) {
		k_ipad[i] ^= key[i];
		k_opad[i] ^= key[i];
	}

	/* Inner hash: H(K XOR ipad || data) */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, k_ipad, SHA256_BLOCK_SIZE);
	SHA256_Update(&ctx, data, data_len);
	SHA256_Final(out, &ctx);

	/* Outer hash: H(K XOR opad || inner) */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, k_opad, SHA256_BLOCK_SIZE);
	SHA256_Update(&ctx, out, SHA256_DIGEST_SIZE);
	SHA256_Final(out, &ctx);

	explicit_bzero(&ctx, sizeof(ctx));
	explicit_bzero(k_ipad, sizeof(k_ipad));
	explicit_bzero(k_opad, sizeof(k_opad));
	explicit_bzero(tk, sizeof(tk));
}

/*
 * HMAC-SHA512
 */
static void
hmac_sha512(unsigned char *out,
    const unsigned char *key, size_t key_len,
    const unsigned char *data, size_t data_len)
{
	SHA512_CTX ctx;
	unsigned char k_ipad[SHA512_BLOCK_SIZE];
	unsigned char k_opad[SHA512_BLOCK_SIZE];
	unsigned char tk[SHA512_DIGEST_SIZE];
	size_t i;

	/* If key is longer than block size, hash it first */
	if (key_len > SHA512_BLOCK_SIZE) {
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, key, key_len);
		SHA512_Final(tk, &ctx);
		key = tk;
		key_len = SHA512_DIGEST_SIZE;
	}

	/* XOR key with ipad and opad */
	memset(k_ipad, 0x36, SHA512_BLOCK_SIZE);
	memset(k_opad, 0x5c, SHA512_BLOCK_SIZE);
	for (i = 0; i < key_len; i++) {
		k_ipad[i] ^= key[i];
		k_opad[i] ^= key[i];
	}

	/* Inner hash: H(K XOR ipad || data) */
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, k_ipad, SHA512_BLOCK_SIZE);
	SHA512_Update(&ctx, data, data_len);
	SHA512_Final(out, &ctx);

	/* Outer hash: H(K XOR opad || inner) */
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, k_opad, SHA512_BLOCK_SIZE);
	SHA512_Update(&ctx, out, SHA512_DIGEST_SIZE);
	SHA512_Final(out, &ctx);

	explicit_bzero(&ctx, sizeof(ctx));
	explicit_bzero(k_ipad, sizeof(k_ipad));
	explicit_bzero(k_opad, sizeof(k_opad));
	explicit_bzero(tk, sizeof(tk));
}

/*
 * HMAC wrapper
 *
 * Caller must ensure hash_alg is valid (validated by hkdf_hash_params).
 */
static void
hmac(unsigned char *out, int hash_alg,
    const unsigned char *key, size_t key_len,
    const unsigned char *data, size_t data_len)
{
	switch (hash_alg) {
	case KV_HKDF_HASH_SHA256:
		hmac_sha256(out, key, key_len, data, data_len);
		break;
	case KV_HKDF_HASH_SHA512:
		hmac_sha512(out, key, key_len, data, data_len);
		break;
	default:
		/*
		 * Should never happen - callers validate via hkdf_hash_params.
		 * Zero output to avoid undefined behavior.
		 */
		memset(out, 0, 64);  /* Max hash size */
		break;
	}
}

/*
 * HKDF-Extract
 *
 * PRK = HMAC-Hash(salt, IKM)
 */
int
kv_hkdf_extract(unsigned char *prk, size_t *prk_len,
    int hash_alg,
    const unsigned char *salt, size_t salt_len,
    const unsigned char *ikm, size_t ikm_len)
{
	size_t hash_len, block_len;
	unsigned char zero_salt[SHA512_DIGEST_SIZE];
	int error;

	error = hkdf_hash_params(hash_alg, &hash_len, &block_len);
	if (error != 0)
		return (error);

	/* If salt is NULL, use zeros */
	if (salt == NULL || salt_len == 0) {
		memset(zero_salt, 0, hash_len);
		salt = zero_salt;
		salt_len = hash_len;
	}

	hmac(prk, hash_alg, salt, salt_len, ikm, ikm_len);
	*prk_len = hash_len;

	explicit_bzero(zero_salt, sizeof(zero_salt));
	return (0);
}

/*
 * HKDF-Expand
 *
 * OKM = T(1) || T(2) || ... || T(N)
 * T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
 */
int
kv_hkdf_expand(unsigned char *okm, size_t okm_len,
    int hash_alg,
    const unsigned char *prk, size_t prk_len,
    const unsigned char *info, size_t info_len)
{
	size_t hash_len, block_len;
	unsigned char t[SHA512_DIGEST_SIZE];
	unsigned char *data;
	size_t data_len, done, todo;
	unsigned char counter;
	int error;

	error = hkdf_hash_params(hash_alg, &hash_len, &block_len);
	if (error != 0)
		return (error);

	/* Check output length limit: L <= 255 * HashLen */
	if (okm_len > 255 * hash_len)
		return (EINVAL);

	if (okm_len == 0)
		return (0);

	/* Allocate buffer for T(i-1) || info || counter */
	data = malloc(hash_len + info_len + 1, M_KEYVAULT, M_WAITOK);

	done = 0;
	counter = 1;

	while (done < okm_len) {
		/* Build input: T(i-1) || info || counter */
		if (counter == 1) {
			/* First iteration: no T(0) */
			if (info_len > 0)
				memcpy(data, info, info_len);
			data[info_len] = counter;
			data_len = info_len + 1;
		} else {
			/* Subsequent: T(i-1) || info || counter */
			memcpy(data, t, hash_len);
			if (info_len > 0)
				memcpy(data + hash_len, info, info_len);
			data[hash_len + info_len] = counter;
			data_len = hash_len + info_len + 1;
		}

		/* T(i) = HMAC-Hash(PRK, data) */
		hmac(t, hash_alg, prk, prk_len, data, data_len);

		/* Copy to output */
		todo = okm_len - done;
		if (todo > hash_len)
			todo = hash_len;
		memcpy(okm + done, t, todo);

		done += todo;
		counter++;
	}

	explicit_bzero(t, sizeof(t));
	explicit_bzero(data, hash_len + info_len + 1);
	free(data, M_KEYVAULT);

	return (0);
}

/*
 * HKDF: Combined Extract-and-Expand
 */
int
kv_hkdf(unsigned char *okm, size_t okm_len,
    int hash_alg,
    const unsigned char *salt, size_t salt_len,
    const unsigned char *ikm, size_t ikm_len,
    const unsigned char *info, size_t info_len)
{
	unsigned char prk[SHA512_DIGEST_SIZE];
	size_t prk_len;
	int error;

	/* Extract */
	error = kv_hkdf_extract(prk, &prk_len, hash_alg,
	    salt, salt_len, ikm, ikm_len);
	if (error != 0)
		return (error);

	/* Expand */
	error = kv_hkdf_expand(okm, okm_len, hash_alg,
	    prk, prk_len, info, info_len);

	explicit_bzero(prk, sizeof(prk));
	return (error);
}
