/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Keyvault Authors
 *
 * HKDF (HMAC-based Key Derivation Function) interface for FreeBSD kernel
 * RFC 5869
 */

#ifndef _KEYVAULT_HKDF_H_
#define _KEYVAULT_HKDF_H_

#ifdef _KERNEL

#include <sys/types.h>

/*
 * HKDF hash algorithm selection
 */
#define KV_HKDF_HASH_SHA256	0
#define KV_HKDF_HASH_SHA512	1

/*
 * HKDF-Extract: Extract a pseudorandom key from input key material
 *
 * PRK = HMAC-Hash(salt, IKM)
 *
 * @param prk       Output: pseudorandom key (hash_len bytes)
 * @param prk_len   Output: length of PRK
 * @param hash_alg  Hash algorithm (KV_HKDF_HASH_*)
 * @param salt      Optional salt (NULL = zeros)
 * @param salt_len  Salt length
 * @param ikm       Input key material
 * @param ikm_len   IKM length
 * @return 0 on success
 */
int kv_hkdf_extract(unsigned char *prk, size_t *prk_len,
    int hash_alg,
    const unsigned char *salt, size_t salt_len,
    const unsigned char *ikm, size_t ikm_len);

/*
 * HKDF-Expand: Expand a pseudorandom key to desired length
 *
 * OKM = T(1) || T(2) || ... || T(N)
 * T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
 *
 * @param okm       Output: derived key material
 * @param okm_len   Desired output length
 * @param hash_alg  Hash algorithm (KV_HKDF_HASH_*)
 * @param prk       Pseudorandom key from Extract
 * @param prk_len   PRK length
 * @param info      Optional context/application-specific info
 * @param info_len  Info length
 * @return 0 on success, EINVAL if okm_len too large
 */
int kv_hkdf_expand(unsigned char *okm, size_t okm_len,
    int hash_alg,
    const unsigned char *prk, size_t prk_len,
    const unsigned char *info, size_t info_len);

/*
 * HKDF: Combined Extract-and-Expand
 *
 * @param okm       Output: derived key material
 * @param okm_len   Desired output length
 * @param hash_alg  Hash algorithm (KV_HKDF_HASH_*)
 * @param salt      Optional salt (NULL = zeros)
 * @param salt_len  Salt length
 * @param ikm       Input key material
 * @param ikm_len   IKM length
 * @param info      Optional context/application-specific info
 * @param info_len  Info length
 * @return 0 on success
 */
int kv_hkdf(unsigned char *okm, size_t okm_len,
    int hash_alg,
    const unsigned char *salt, size_t salt_len,
    const unsigned char *ikm, size_t ikm_len,
    const unsigned char *info, size_t info_len);

#endif /* _KERNEL */

#endif /* _KEYVAULT_HKDF_H_ */
