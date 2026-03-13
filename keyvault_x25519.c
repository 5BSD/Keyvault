/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Keyvault Authors
 *
 * X25519 key exchange implementation for FreeBSD kernel
 *
 * Based on the Curve25519 Montgomery ladder implementation.
 * This is a constant-time implementation suitable for cryptographic use.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/random.h>

#include "keyvault_x25519.h"

/*
 * Field element operations for X25519
 * Using 5 limbs of 51 bits for efficient implementation
 */
typedef uint64_t fe51[5];

static inline uint64_t
load_3(const unsigned char *in)
{
	return ((uint64_t)in[0]) |
	       (((uint64_t)in[1]) << 8) |
	       (((uint64_t)in[2]) << 16);
}

static inline uint64_t
load_4(const unsigned char *in)
{
	return ((uint64_t)in[0]) |
	       (((uint64_t)in[1]) << 8) |
	       (((uint64_t)in[2]) << 16) |
	       (((uint64_t)in[3]) << 24);
}

static void
fe51_frombytes(fe51 h, const unsigned char *s)
{
	uint64_t h0 = load_4(s);
	uint64_t h1 = load_3(s + 4) << 6;
	uint64_t h2 = load_3(s + 7) << 5;
	uint64_t h3 = load_3(s + 10) << 3;
	uint64_t h4 = load_3(s + 13) << 2;
	uint64_t h5 = load_4(s + 16);
	uint64_t h6 = load_3(s + 20) << 7;
	uint64_t h7 = load_3(s + 23) << 5;
	uint64_t h8 = load_3(s + 26) << 4;
	uint64_t h9 = (load_3(s + 29) & 0x7fffff) << 2;

	h[0] = h0 | (h1 << 26);
	h[0] &= 0x7ffffffffffffULL;
	h[1] = (h1 >> 25) | (h2 << 1) | (h3 << 27);
	h[1] &= 0x7ffffffffffffULL;
	h[2] = (h3 >> 24) | (h4 << 2) | (h5 << 28);
	h[2] &= 0x7ffffffffffffULL;
	h[3] = (h5 >> 23) | (h6 << 3) | (h7 << 29);
	h[3] &= 0x7ffffffffffffULL;
	h[4] = (h7 >> 22) | (h8 << 4) | (h9 << 30);
	h[4] &= 0x7ffffffffffffULL;
}

static void
fe51_tobytes(unsigned char *s, const fe51 h)
{
	uint64_t t[5];
	uint64_t c;

	t[0] = h[0];
	t[1] = h[1];
	t[2] = h[2];
	t[3] = h[3];
	t[4] = h[4];

	/* Reduce to canonical form */
	c = t[0] >> 51; t[0] &= 0x7ffffffffffffULL; t[1] += c;
	c = t[1] >> 51; t[1] &= 0x7ffffffffffffULL; t[2] += c;
	c = t[2] >> 51; t[2] &= 0x7ffffffffffffULL; t[3] += c;
	c = t[3] >> 51; t[3] &= 0x7ffffffffffffULL; t[4] += c;
	c = t[4] >> 51; t[4] &= 0x7ffffffffffffULL; t[0] += c * 19;
	c = t[0] >> 51; t[0] &= 0x7ffffffffffffULL; t[1] += c;
	c = t[1] >> 51; t[1] &= 0x7ffffffffffffULL; t[2] += c;
	c = t[2] >> 51; t[2] &= 0x7ffffffffffffULL; t[3] += c;
	c = t[3] >> 51; t[3] &= 0x7ffffffffffffULL; t[4] += c;
	c = t[4] >> 51; t[4] &= 0x7ffffffffffffULL; t[0] += c * 19;

	s[0] = (unsigned char)(t[0]);
	s[1] = (unsigned char)(t[0] >> 8);
	s[2] = (unsigned char)(t[0] >> 16);
	s[3] = (unsigned char)(t[0] >> 24);
	s[4] = (unsigned char)(t[0] >> 32);
	s[5] = (unsigned char)(t[0] >> 40);
	s[6] = (unsigned char)((t[0] >> 48) | (t[1] << 3));
	s[7] = (unsigned char)(t[1] >> 5);
	s[8] = (unsigned char)(t[1] >> 13);
	s[9] = (unsigned char)(t[1] >> 21);
	s[10] = (unsigned char)(t[1] >> 29);
	s[11] = (unsigned char)(t[1] >> 37);
	s[12] = (unsigned char)((t[1] >> 45) | (t[2] << 6));
	s[13] = (unsigned char)(t[2] >> 2);
	s[14] = (unsigned char)(t[2] >> 10);
	s[15] = (unsigned char)(t[2] >> 18);
	s[16] = (unsigned char)(t[2] >> 26);
	s[17] = (unsigned char)(t[2] >> 34);
	s[18] = (unsigned char)(t[2] >> 42);
	s[19] = (unsigned char)((t[2] >> 50) | (t[3] << 1));
	s[20] = (unsigned char)(t[3] >> 7);
	s[21] = (unsigned char)(t[3] >> 15);
	s[22] = (unsigned char)(t[3] >> 23);
	s[23] = (unsigned char)(t[3] >> 31);
	s[24] = (unsigned char)(t[3] >> 39);
	s[25] = (unsigned char)((t[3] >> 47) | (t[4] << 4));
	s[26] = (unsigned char)(t[4] >> 4);
	s[27] = (unsigned char)(t[4] >> 12);
	s[28] = (unsigned char)(t[4] >> 20);
	s[29] = (unsigned char)(t[4] >> 28);
	s[30] = (unsigned char)(t[4] >> 36);
	s[31] = (unsigned char)(t[4] >> 44);
}

static void
fe51_0(fe51 h)
{
	h[0] = h[1] = h[2] = h[3] = h[4] = 0;
}

static void
fe51_1(fe51 h)
{
	h[0] = 1;
	h[1] = h[2] = h[3] = h[4] = 0;
}

static void
fe51_copy(fe51 f, const fe51 g)
{
	f[0] = g[0];
	f[1] = g[1];
	f[2] = g[2];
	f[3] = g[3];
	f[4] = g[4];
}

static void
fe51_add(fe51 h, const fe51 f, const fe51 g)
{
	h[0] = f[0] + g[0];
	h[1] = f[1] + g[1];
	h[2] = f[2] + g[2];
	h[3] = f[3] + g[3];
	h[4] = f[4] + g[4];
}

static void
fe51_sub(fe51 h, const fe51 f, const fe51 g)
{
	/* Add 2p to avoid underflow */
	h[0] = f[0] + 0xfffffffffffda - g[0];
	h[1] = f[1] + 0xffffffffffffe - g[1];
	h[2] = f[2] + 0xffffffffffffe - g[2];
	h[3] = f[3] + 0xffffffffffffe - g[3];
	h[4] = f[4] + 0xffffffffffffe - g[4];
}

static void
fe51_mul(fe51 h, const fe51 f, const fe51 g)
{
	__uint128_t t0, t1, t2, t3, t4;
	uint64_t g1_19, g2_19, g3_19, g4_19;

	g1_19 = g[1] * 19;
	g2_19 = g[2] * 19;
	g3_19 = g[3] * 19;
	g4_19 = g[4] * 19;

	t0 = (__uint128_t)f[0] * g[0] +
	     (__uint128_t)f[1] * g4_19 +
	     (__uint128_t)f[2] * g3_19 +
	     (__uint128_t)f[3] * g2_19 +
	     (__uint128_t)f[4] * g1_19;

	t1 = (__uint128_t)f[0] * g[1] +
	     (__uint128_t)f[1] * g[0] +
	     (__uint128_t)f[2] * g4_19 +
	     (__uint128_t)f[3] * g3_19 +
	     (__uint128_t)f[4] * g2_19;

	t2 = (__uint128_t)f[0] * g[2] +
	     (__uint128_t)f[1] * g[1] +
	     (__uint128_t)f[2] * g[0] +
	     (__uint128_t)f[3] * g4_19 +
	     (__uint128_t)f[4] * g3_19;

	t3 = (__uint128_t)f[0] * g[3] +
	     (__uint128_t)f[1] * g[2] +
	     (__uint128_t)f[2] * g[1] +
	     (__uint128_t)f[3] * g[0] +
	     (__uint128_t)f[4] * g4_19;

	t4 = (__uint128_t)f[0] * g[4] +
	     (__uint128_t)f[1] * g[3] +
	     (__uint128_t)f[2] * g[2] +
	     (__uint128_t)f[3] * g[1] +
	     (__uint128_t)f[4] * g[0];

	/* Carry propagation */
	t1 += t0 >> 51; h[0] = (uint64_t)t0 & 0x7ffffffffffffULL;
	t2 += t1 >> 51; h[1] = (uint64_t)t1 & 0x7ffffffffffffULL;
	t3 += t2 >> 51; h[2] = (uint64_t)t2 & 0x7ffffffffffffULL;
	t4 += t3 >> 51; h[3] = (uint64_t)t3 & 0x7ffffffffffffULL;
	h[0] += ((uint64_t)t4 >> 51) * 19; h[4] = (uint64_t)t4 & 0x7ffffffffffffULL;
	h[1] += h[0] >> 51; h[0] &= 0x7ffffffffffffULL;
}

static void
fe51_sq(fe51 h, const fe51 f)
{
	fe51_mul(h, f, f);
}

/*
 * Constant-time conditional swap
 */
static void
fe51_cswap(fe51 f, fe51 g, unsigned int b)
{
	uint64_t mask = -(uint64_t)b;
	uint64_t t;
	int i;

	for (i = 0; i < 5; i++) {
		t = mask & (f[i] ^ g[i]);
		f[i] ^= t;
		g[i] ^= t;
	}
}

/*
 * Compute f^(2^252 - 3) for inversion
 */
static void
fe51_invert(fe51 out, const fe51 z)
{
	fe51 t0, t1, t2, t3;
	int i;

	/* z^2 */
	fe51_sq(t0, z);
	/* z^4 */
	fe51_sq(t1, t0);
	/* z^8 */
	fe51_sq(t1, t1);
	/* z^9 */
	fe51_mul(t1, z, t1);
	/* z^11 */
	fe51_mul(t0, t0, t1);
	/* z^22 */
	fe51_sq(t2, t0);
	/* z^31 */
	fe51_mul(t1, t1, t2);
	/* z^2^5 */
	fe51_sq(t2, t1);
	for (i = 1; i < 5; i++) fe51_sq(t2, t2);
	/* z^2^5 * z^31 = z^(2^10 - 1) */
	fe51_mul(t1, t2, t1);
	/* z^(2^20 - 1) */
	fe51_sq(t2, t1);
	for (i = 1; i < 10; i++) fe51_sq(t2, t2);
	fe51_mul(t2, t2, t1);
	/* z^(2^40 - 1) */
	fe51_sq(t3, t2);
	for (i = 1; i < 20; i++) fe51_sq(t3, t3);
	fe51_mul(t2, t3, t2);
	/* z^(2^50 - 1) */
	for (i = 0; i < 10; i++) fe51_sq(t2, t2);
	fe51_mul(t1, t2, t1);
	/* z^(2^100 - 1) */
	fe51_sq(t2, t1);
	for (i = 1; i < 50; i++) fe51_sq(t2, t2);
	fe51_mul(t2, t2, t1);
	/* z^(2^200 - 1) */
	fe51_sq(t3, t2);
	for (i = 1; i < 100; i++) fe51_sq(t3, t3);
	fe51_mul(t2, t3, t2);
	/* z^(2^250 - 1) */
	for (i = 0; i < 50; i++) fe51_sq(t2, t2);
	fe51_mul(t1, t2, t1);
	/* z^(2^252 - 3) */
	fe51_sq(t1, t1);
	fe51_sq(t1, t1);
	fe51_mul(out, t1, z);
}

/*
 * X25519 basepoint (u = 9)
 */
static const unsigned char basepoint[32] = { 9 };

/*
 * Clamp a 32-byte secret key per RFC 7748
 */
static void
x25519_clamp(unsigned char *k)
{
	k[0] &= 248;
	k[31] &= 127;
	k[31] |= 64;
}

/*
 * Montgomery ladder for X25519
 */
static void
x25519_ladder(unsigned char *out, const unsigned char *scalar,
    const unsigned char *point)
{
	fe51 x1, x2, z2, x3, z3, tmp0, tmp1;
	unsigned char e[32];
	unsigned int swap;
	int pos;

	/* Copy and clamp scalar */
	memcpy(e, scalar, 32);
	x25519_clamp(e);

	/* Initialize */
	fe51_frombytes(x1, point);
	fe51_1(x2);
	fe51_0(z2);
	fe51_copy(x3, x1);
	fe51_1(z3);

	swap = 0;

	/* Montgomery ladder - 255 iterations (constant time) */
	for (pos = 254; pos >= 0; pos--) {
		unsigned int b = (e[pos / 8] >> (pos & 7)) & 1;
		swap ^= b;
		fe51_cswap(x2, x3, swap);
		fe51_cswap(z2, z3, swap);
		swap = b;

		/* Montgomery step */
		fe51_sub(tmp0, x3, z3);
		fe51_sub(tmp1, x2, z2);
		fe51_add(x2, x2, z2);
		fe51_add(z2, x3, z3);
		fe51_mul(z3, tmp0, x2);
		fe51_mul(z2, z2, tmp1);
		fe51_sq(tmp0, tmp1);
		fe51_sq(tmp1, x2);
		fe51_add(x3, z3, z2);
		fe51_sub(z2, z3, z2);
		fe51_mul(x2, tmp1, tmp0);
		fe51_sub(tmp1, tmp1, tmp0);
		fe51_sq(z2, z2);
		fe51_mul(z3, tmp1, (fe51){121666, 0, 0, 0, 0});
		fe51_sq(x3, x3);
		fe51_add(tmp0, tmp0, z3);
		fe51_mul(z3, x1, z2);
		fe51_mul(z2, tmp1, tmp0);
	}

	fe51_cswap(x2, x3, swap);
	fe51_cswap(z2, z3, swap);

	/* Compute x2 * z2^(p-2) = x2 / z2 */
	fe51_invert(z2, z2);
	fe51_mul(x2, x2, z2);
	fe51_tobytes(out, x2);

	/* Clear sensitive data */
	explicit_bzero(e, sizeof(e));
	explicit_bzero(x1, sizeof(x1));
	explicit_bzero(x2, sizeof(x2));
	explicit_bzero(z2, sizeof(z2));
	explicit_bzero(x3, sizeof(x3));
	explicit_bzero(z3, sizeof(z3));
	explicit_bzero(tmp0, sizeof(tmp0));
	explicit_bzero(tmp1, sizeof(tmp1));
}

/*
 * Generate X25519 keypair
 */
int
kv_x25519_keypair(unsigned char *pk, unsigned char *sk)
{
	/* Generate random secret key */
	arc4random_buf(sk, 32);

	/* Compute public key = sk * basepoint */
	x25519_ladder(pk, sk, basepoint);

	return (0);
}

/*
 * X25519 scalar multiplication
 */
int
kv_x25519_scalarmult(unsigned char *shared, const unsigned char *sk,
    const unsigned char *pk)
{
	int i;
	unsigned char zero_check;

	x25519_ladder(shared, sk, pk);

	/* Check for all-zero output (low-order point attack) */
	zero_check = 0;
	for (i = 0; i < 32; i++)
		zero_check |= shared[i];

	if (zero_check == 0) {
		explicit_bzero(shared, 32);
		return (-1);
	}

	return (0);
}

/*
 * X25519 scalar multiplication with basepoint
 */
int
kv_x25519_scalarmult_base(unsigned char *pk, const unsigned char *sk)
{
	x25519_ladder(pk, sk, basepoint);
	return (0);
}
