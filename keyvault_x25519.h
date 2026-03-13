/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Keyvault Authors
 *
 * X25519 key exchange interface for FreeBSD kernel
 */

#ifndef _KEYVAULT_X25519_H_
#define _KEYVAULT_X25519_H_

#ifdef _KERNEL

#include <sys/types.h>

/*
 * X25519 key sizes (all in bytes)
 */
#define KV_X25519_SCALAR_SIZE   32  /* Private key / scalar */
#define KV_X25519_POINT_SIZE    32  /* Public key / point */
#define KV_X25519_SHARED_SIZE   32  /* Shared secret */

/*
 * Generate an X25519 keypair
 *
 * @param pk  Output: 32-byte public key
 * @param sk  Output: 32-byte secret key (clamped scalar)
 * @return 0 on success, non-zero on failure
 */
int kv_x25519_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Perform X25519 scalar multiplication (key exchange)
 *
 * Computes: shared = scalar * point
 *
 * @param shared  Output: 32-byte shared secret
 * @param sk      Input: our 32-byte secret key
 * @param pk      Input: peer's 32-byte public key
 * @return 0 on success, -1 if result is all zeros (low-order point)
 */
int kv_x25519_scalarmult(unsigned char *shared,
    const unsigned char *sk, const unsigned char *pk);

/*
 * Compute X25519 public key from secret key
 *
 * Computes: pk = sk * basepoint
 *
 * @param pk  Output: 32-byte public key
 * @param sk  Input: 32-byte secret key
 * @return 0 on success
 */
int kv_x25519_scalarmult_base(unsigned char *pk, const unsigned char *sk);

#endif /* _KERNEL */

#endif /* _KEYVAULT_X25519_H_ */
