/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024-2025 Keyvault Authors
 *
 * X25519 key exchange implementation for FreeBSD kernel
 *
 * This is a thin wrapper around FreeBSD's built-in curve25519
 * implementation in sys/crypto/curve25519.h
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <crypto/curve25519.h>

#include "keyvault_x25519.h"

/*
 * Generate X25519 keypair
 */
int
kv_x25519_keypair(unsigned char *pk, unsigned char *sk)
{
	/* Generate random secret key (clamped) */
	curve25519_generate_secret(sk);

	/* Compute public key = sk * basepoint */
	if (!curve25519_generate_public(pk, sk))
		return (-1);

	return (0);
}

/*
 * X25519 scalar multiplication (key exchange)
 */
int
kv_x25519_scalarmult(unsigned char *shared, const unsigned char *sk,
    const unsigned char *pk)
{
	/*
	 * curve25519() returns false if the result is all zeros
	 * (low-order point attack), which we treat as an error.
	 */
	if (!curve25519(shared, sk, pk))
		return (-1);

	return (0);
}

/*
 * Compute X25519 public key from secret key
 */
int
kv_x25519_scalarmult_base(unsigned char *pk, const unsigned char *sk)
{
	if (!curve25519_generate_public(pk, sk))
		return (-1);

	return (0);
}
