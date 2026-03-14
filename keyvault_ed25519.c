/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024-2025 Keyvault Authors
 *
 * Ed25519 digital signature implementation for keyvault
 *
 * Uses primitives from FreeBSD's crypto.ko (libsodium ed25519_ref10)
 *
 * Note: Empty messages (mlen == 0) are valid for Ed25519 signing/verification.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/libkern.h>

#include "keyvault_ed25519.h"
#include "crypto_compat.h"
#include "ge25519.h"

/*
 * Clamp a secret key scalar
 */
static inline void
ed25519_clamp(unsigned char k[32])
{
	k[0] &= 248;
	k[31] &= 127;
	k[31] |= 64;
}

/*
 * Generate an Ed25519 keypair from a 32-byte seed
 */
int
kv_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
    const unsigned char *seed)
{
	ge25519_p3 A;
	unsigned char az[64];

	/* Hash the seed to get the scalar */
	crypto_hash_sha512(az, seed, 32);

	/* Clamp the scalar */
	ed25519_clamp(az);

	/* Compute public key: A = a * B (base point multiplication) */
	ge25519_scalarmult_base(&A, az);
	ge25519_p3_tobytes(pk, &A);

	/* Secret key format: seed || public_key */
	memcpy(sk, seed, 32);
	memcpy(sk + 32, pk, 32);

	/* Clear sensitive data */
	explicit_bzero(az, sizeof(az));

	return 0;
}

/*
 * Generate an Ed25519 keypair with random seed
 */
int
kv_ed25519_keypair(unsigned char *pk, unsigned char *sk)
{
	unsigned char seed[32];
	int ret;

	arc4random_buf(seed, sizeof(seed));
	ret = kv_ed25519_seed_keypair(pk, sk, seed);
	explicit_bzero(seed, sizeof(seed));

	return ret;
}

/*
 * Sign a message (detached signature)
 *
 * sig: output 64-byte signature
 * m: message to sign
 * mlen: message length
 * sk: 64-byte secret key
 */
int
kv_ed25519_sign_detached(unsigned char *sig, const unsigned char *m,
    unsigned long long mlen, const unsigned char *sk)
{
	crypto_hash_sha512_state hs;
	unsigned char az[64];
	unsigned char nonce[64];
	unsigned char hram[64];
	ge25519_p3 R;

	/* Hash secret key to get scalar and prefix */
	crypto_hash_sha512(az, sk, 32);

	/* Compute nonce: H(prefix || message) */
	crypto_hash_sha512_init(&hs);
	crypto_hash_sha512_update(&hs, az + 32, 32);
	crypto_hash_sha512_update(&hs, m, mlen);
	crypto_hash_sha512_final(&hs, nonce);

	/* Copy public key to signature[32..63] */
	memcpy(sig + 32, sk + 32, 32);

	/* Reduce nonce mod L */
	sc25519_reduce(nonce);

	/* R = nonce * B */
	ge25519_scalarmult_base(&R, nonce);
	ge25519_p3_tobytes(sig, &R);

	/* Compute challenge: H(R || pk || message) */
	crypto_hash_sha512_init(&hs);
	crypto_hash_sha512_update(&hs, sig, 64);
	crypto_hash_sha512_update(&hs, m, mlen);
	crypto_hash_sha512_final(&hs, hram);

	/* Reduce challenge mod L */
	sc25519_reduce(hram);

	/* Clamp secret scalar */
	ed25519_clamp(az);

	/* s = nonce + challenge * secret (mod L) */
	sc25519_muladd(sig + 32, hram, az, nonce);

	/* Clear sensitive data */
	explicit_bzero(az, sizeof(az));
	explicit_bzero(nonce, sizeof(nonce));

	return 0;
}

/*
 * Verify a detached signature
 *
 * sig: 64-byte signature
 * m: message
 * mlen: message length
 * pk: 32-byte public key
 *
 * Returns 0 on success (valid signature), -1 on failure
 */
int
kv_ed25519_verify_detached(const unsigned char *sig, const unsigned char *m,
    unsigned long long mlen, const unsigned char *pk)
{
	crypto_hash_sha512_state hs;
	unsigned char h[64];
	unsigned char rcheck[32];
	ge25519_p3 A;
	ge25519_p2 R;

	/* Validate signature and public key */
	if (sc25519_is_canonical(sig + 32) == 0 ||
	    ge25519_has_small_order(sig) != 0) {
		return -1;
	}
	if (ge25519_is_canonical(pk) == 0 ||
	    ge25519_has_small_order(pk) != 0) {
		return -1;
	}

	/* Decode public key */
	if (ge25519_frombytes_negate_vartime(&A, pk) != 0) {
		return -1;
	}

	/* Compute challenge: H(R || pk || message) */
	crypto_hash_sha512_init(&hs);
	crypto_hash_sha512_update(&hs, sig, 32);
	crypto_hash_sha512_update(&hs, pk, 32);
	crypto_hash_sha512_update(&hs, m, mlen);
	crypto_hash_sha512_final(&hs, h);

	/* Reduce challenge mod L */
	sc25519_reduce(h);

	/* R' = s * B - h * A */
	ge25519_double_scalarmult_vartime(&R, h, &A, sig + 32);
	ge25519_tobytes(rcheck, &R);

	/* Compare R' with R from signature */
	if (crypto_verify_32(rcheck, sig) != 0) {
		return -1;
	}

	return 0;
}
