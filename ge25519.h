/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024-2025 Keyvault Authors
 *
 * Ed25519 group element primitives from FreeBSD crypto.ko
 *
 * These functions are provided by libsodium's ed25519_ref10.c
 * compiled into the crypto.ko kernel module.
 */

#ifndef _KEYVAULT_GE25519_H_
#define _KEYVAULT_GE25519_H_

#ifdef _KERNEL

/*
 * Field element type - depends on HAVE_TI_MODE
 *
 * HAVE_TI_MODE is defined when the compiler supports 128-bit integers
 * (__int128), which allows for a more efficient 5-limb representation.
 * Otherwise, a 10-limb representation using 32-bit integers is used.
 */
#ifdef HAVE_TI_MODE
typedef uint64_t fe25519[5];
#else
typedef int32_t fe25519[10];
#endif

/*
 * Group element in projective coordinates (X:Y:Z)
 * Represents the point (X/Z, Y/Z)
 */
typedef struct {
	fe25519 X;
	fe25519 Y;
	fe25519 Z;
} ge25519_p2;

/*
 * Group element in extended coordinates (X:Y:Z:T)
 * Represents the point (X/Z, Y/Z) with T = X*Y/Z
 */
typedef struct {
	fe25519 X;
	fe25519 Y;
	fe25519 Z;
	fe25519 T;
} ge25519_p3;

/*
 * Scalar multiplication by the base point
 * h = a * B where B is the Ed25519 base point
 */
extern void ge25519_scalarmult_base(ge25519_p3 *h, const unsigned char *a);

/*
 * Convert extended coordinates to bytes (compressed point)
 */
extern void ge25519_p3_tobytes(unsigned char *s, const ge25519_p3 *h);

/*
 * Convert projective coordinates to bytes (compressed point)
 */
extern void ge25519_tobytes(unsigned char *s, const ge25519_p2 *h);

/*
 * Decode bytes to extended coordinates with negation
 * Returns 0 on success, -1 if the point is not on the curve
 */
extern int ge25519_frombytes_negate_vartime(ge25519_p3 *h,
    const unsigned char *s);

/*
 * Double scalar multiplication (variable time)
 * r = a*A + b*B where B is the base point
 */
extern void ge25519_double_scalarmult_vartime(ge25519_p2 *r,
    const unsigned char *a, const ge25519_p3 *A, const unsigned char *b);

/*
 * Check if a point has small order (unsafe for use)
 * Returns non-zero if the point has small order
 */
extern int ge25519_has_small_order(const unsigned char s[32]);

/*
 * Check if a point encoding is canonical
 * Returns non-zero if canonical
 */
extern int ge25519_is_canonical(const unsigned char *s);

/*
 * Scalar operations modulo L (the group order)
 */

/* Reduce a 64-byte scalar modulo L */
extern void sc25519_reduce(unsigned char *s);

/* s = a*b + c (mod L) */
extern void sc25519_muladd(unsigned char *s, const unsigned char *a,
    const unsigned char *b, const unsigned char *c);

/* Check if a scalar is in canonical form (< L) */
extern int sc25519_is_canonical(const unsigned char *s);

#endif /* _KERNEL */

#endif /* _KEYVAULT_GE25519_H_ */
