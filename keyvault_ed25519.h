/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Keyvault Authors
 *
 * Ed25519 digital signature interface for keyvault
 */

#ifndef _KEYVAULT_ED25519_H_
#define _KEYVAULT_ED25519_H_

#ifdef _KERNEL

/*
 * Ed25519 key and signature sizes
 */
#define KV_ED25519_SEED_SIZE      32  /* Random seed */
#define KV_ED25519_PUBLIC_SIZE    32  /* Public key */
#define KV_ED25519_SECRET_SIZE    64  /* Secret key (seed || public) */
#define KV_ED25519_SIGNATURE_SIZE 64  /* Signature */

/*
 * Generate an Ed25519 keypair with random seed
 *
 * pk: output 32-byte public key
 * sk: output 64-byte secret key
 *
 * Returns 0 on success
 */
int kv_ed25519_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Generate an Ed25519 keypair from a specific seed
 *
 * pk: output 32-byte public key
 * sk: output 64-byte secret key
 * seed: input 32-byte seed
 *
 * Returns 0 on success
 */
int kv_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
    const unsigned char *seed);

/*
 * Sign a message (detached signature)
 *
 * sig: output 64-byte signature
 * m: message to sign
 * mlen: message length
 * sk: 64-byte secret key
 *
 * Returns 0 on success
 */
int kv_ed25519_sign_detached(unsigned char *sig, const unsigned char *m,
    unsigned long long mlen, const unsigned char *sk);

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
int kv_ed25519_verify_detached(const unsigned char *sig, const unsigned char *m,
    unsigned long long mlen, const unsigned char *pk);

#endif /* _KERNEL */

#endif /* _KEYVAULT_ED25519_H_ */
