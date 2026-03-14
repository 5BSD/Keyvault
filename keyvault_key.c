/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Keyvault Authors
 *
 * Keyvault - Key lifecycle management
 *
 * Handles key creation, destruction, reference counting, and lookup.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/refcount.h>
#include <sys/random.h>
#include <sys/time.h>
#include <sys/sdt.h>
#include <sys/event.h>

#include "keyvault_internal.h"
#include "keyvault_ed25519.h"
#include "keyvault_x25519.h"

/*
 * Algorithm metadata
 */
struct kv_alg_info {
	uint32_t    ai_alg;         /* KV_ALG_* */
	uint32_t    ai_default_bits;/* default key size in bits */
	uint32_t    ai_min_bits;    /* minimum key size */
	uint32_t    ai_max_bits;    /* maximum key size */
	int         ai_crypto_alg;  /* OpenCrypto algorithm ID */
	const char *ai_name;        /* human readable name */
};

static const struct kv_alg_info kv_algorithms[] = {
	/* Hash algorithms (no key material) */
	{ KV_ALG_SHA256,      0,    0,    0,    CRYPTO_SHA2_256, "SHA-256" },
	{ KV_ALG_SHA512,      0,    0,    0,    CRYPTO_SHA2_512, "SHA-512" },

	/* Symmetric encryption */
	{ KV_ALG_AES128_GCM,  128,  128,  128,  CRYPTO_AES_NIST_GCM_16, "AES-128-GCM" },
	{ KV_ALG_AES256_GCM,  256,  256,  256,  CRYPTO_AES_NIST_GCM_16, "AES-256-GCM" },
	{ KV_ALG_AES128_CBC,  128,  128,  128,  CRYPTO_AES_CBC,  "AES-128-CBC" },
	{ KV_ALG_AES256_CBC,  256,  256,  256,  CRYPTO_AES_CBC,  "AES-256-CBC" },
	{ KV_ALG_CHACHA20_POLY1305, 256, 256, 256, CRYPTO_CHACHA20_POLY1305, "ChaCha20-Poly1305" },

	/* MAC algorithms */
	{ KV_ALG_HMAC_SHA256, 256,  128,  512,  CRYPTO_SHA2_256_HMAC, "HMAC-SHA256" },
	{ KV_ALG_HMAC_SHA512, 512,  256,  1024, CRYPTO_SHA2_512_HMAC, "HMAC-SHA512" },

	/* Asymmetric algorithms (no OpenCrypto session) */
	{ KV_ALG_ED25519,     256,  256,  256,  0, "Ed25519" },
	{ KV_ALG_X25519,      256,  256,  256,  0, "X25519" },

	/* Key derivation (uses HMAC internally, not OpenCrypto session) */
	{ KV_ALG_HKDF_SHA256, 256,  128,  8160, 0, "HKDF-SHA256" },
	{ KV_ALG_HKDF_SHA512, 512,  128,  16320, 0, "HKDF-SHA512" },

	/* Terminator */
	{ KV_ALG_NONE, 0, 0, 0, 0, NULL }
};

/*
 * Find algorithm info by algorithm ID
 */
static const struct kv_alg_info *
kv_alg_lookup(uint32_t algorithm)
{
	const struct kv_alg_info *ai;

	for (ai = kv_algorithms; ai->ai_name != NULL; ai++) {
		if (ai->ai_alg == algorithm)
			return (ai);
	}
	return (NULL);
}

/*
 * Allocate a new file context
 */
struct kv_file *
kv_file_alloc(struct kv_softc *sc)
{
	struct kv_file *kf;

	kf = malloc(sizeof(*kf), M_KEYVAULT, M_WAITOK | M_ZERO);

	mtx_init(&kf->kf_mtx, "kv_file", NULL, MTX_DEF);
	LIST_INIT(&kf->kf_keys);
	kf->kf_sc = sc;
	kf->kf_nkeys = 0;
	kf->kf_keybytes = 0;
	kf->kf_caps = KV_CAP_ALL;
	kf->kf_pending_ops = 0;
	kf->kf_completed_ops = 0;
	knlist_init_mtx(&kf->kf_sel.si_note, &kf->kf_mtx);

	return (kf);
}

/*
 * Free a file context and all its keys
 *
 * Keys are collected to a local list while holding the file lock,
 * then released after dropping the lock. This avoids sleeping in
 * crypto_freesession() while holding kf_mtx.
 */
void
kv_file_free(struct kv_file *kf)
{
	struct kv_key *kk, *kk_next;
	LIST_HEAD(, kv_key) keys_to_free;

	if (kf == NULL)
		return;

	LIST_INIT(&keys_to_free);

	/* Collect keys while holding the file lock */
	KV_FILE_LOCK(kf);
	LIST_FOREACH_SAFE(kk, &kf->kf_keys, kk_link, kk_next) {
		LIST_REMOVE(kk, kk_link);
		kf->kf_nkeys--;
		kf->kf_keybytes -= kk->kk_matlen;

		/* Mark as destroying to prevent new references */
		KV_KEY_LOCK(kk);
		kk->kk_state = KV_KEY_STATE_DESTROYING;
		KV_KEY_UNLOCK(kk);

		SDT_PROBE1(keyvault, key, lifecycle, destroy, kk->kk_id);

		/* Add to local list for deferred release */
		LIST_INSERT_HEAD(&keys_to_free, kk, kk_link);
	}
	KV_FILE_UNLOCK(kf);

	/*
	 * Release keys without holding the file lock.
	 * kv_key_release() may call crypto_freesession() which can sleep.
	 */
	LIST_FOREACH_SAFE(kk, &keys_to_free, kk_link, kk_next) {
		kv_key_release(kk);
	}

	/* Destroy kqueue notification list */
	knlist_destroy(&kf->kf_sel.si_note);
	seldrain(&kf->kf_sel);

	mtx_destroy(&kf->kf_mtx);
	free(kf, M_KEYVAULT);
}

/*
 * Check if file context has a capability
 */
int
kv_file_check_cap(struct kv_file *kf, uint32_t cap)
{
	uint32_t caps;

	KV_FILE_LOCK(kf);
	caps = kf->kf_caps;
	KV_FILE_UNLOCK(kf);

	if ((caps & cap) == 0)
		return (EPERM);
	return (0);
}

/*
 * Restrict capabilities (can only remove, never add)
 */
int
kv_file_restrict(struct kv_file *kf, uint32_t newcaps)
{
	/*
	 * New capabilities must be a subset of current capabilities.
	 * This is enforced by AND-ing with current caps.
	 */
	KV_FILE_LOCK(kf);
	kf->kf_caps &= newcaps;
	KV_FILE_UNLOCK(kf);

	return (0);
}

/*
 * Allocate and generate Ed25519 keypair
 */
static int
kv_key_alloc_ed25519(struct kv_key *kk)
{
	unsigned char pk[KV_ED25519_PUBLIC_SIZE];
	unsigned char sk[KV_ED25519_SECRET_SIZE];

	/* Generate keypair */
	if (kv_ed25519_keypair(pk, sk) != 0)
		return (EIO);

	/* Allocate and copy secret key */
	kk->kk_material = malloc(KV_ED25519_SECRET_SIZE, M_KEYVAULT,
	    M_WAITOK | M_ZERO);
	memcpy(kk->kk_material, sk, KV_ED25519_SECRET_SIZE);
	kk->kk_matlen = KV_ED25519_SECRET_SIZE;
	kk->kk_keybits = 256;

	/* Allocate and copy public key */
	kk->kk_pubkey = malloc(KV_ED25519_PUBLIC_SIZE, M_KEYVAULT,
	    M_WAITOK | M_ZERO);
	memcpy(kk->kk_pubkey, pk, KV_ED25519_PUBLIC_SIZE);
	kk->kk_publen = KV_ED25519_PUBLIC_SIZE;

	/* Mark as asymmetric key */
	kk->kk_type = KV_KEY_TYPE_ASYMMETRIC;

	/* Clear stack copies */
	explicit_bzero(pk, sizeof(pk));
	explicit_bzero(sk, sizeof(sk));

	return (0);
}

/*
 * Allocate and generate X25519 keypair
 */
static int
kv_key_alloc_x25519(struct kv_key *kk)
{
	unsigned char pk[KV_X25519_POINT_SIZE];
	unsigned char sk[KV_X25519_SCALAR_SIZE];

	/* Generate keypair */
	if (kv_x25519_keypair(pk, sk) != 0)
		return (EIO);

	/* Allocate and copy secret key */
	kk->kk_material = malloc(KV_X25519_SCALAR_SIZE, M_KEYVAULT,
	    M_WAITOK | M_ZERO);
	memcpy(kk->kk_material, sk, KV_X25519_SCALAR_SIZE);
	kk->kk_matlen = KV_X25519_SCALAR_SIZE;
	kk->kk_keybits = 256;

	/* Allocate and copy public key */
	kk->kk_pubkey = malloc(KV_X25519_POINT_SIZE, M_KEYVAULT,
	    M_WAITOK | M_ZERO);
	memcpy(kk->kk_pubkey, pk, KV_X25519_POINT_SIZE);
	kk->kk_publen = KV_X25519_POINT_SIZE;

	/* Mark as asymmetric key */
	kk->kk_type = KV_KEY_TYPE_ASYMMETRIC;

	/* Clear stack copies */
	explicit_bzero(pk, sizeof(pk));
	explicit_bzero(sk, sizeof(sk));

	return (0);
}

/*
 * Allocate key material and generate random key
 */
static int
kv_key_alloc_material(struct kv_key *kk, uint32_t keybits)
{
	size_t keylen;

	/* Handle Ed25519 specially */
	if (kk->kk_algorithm == KV_ALG_ED25519)
		return (kv_key_alloc_ed25519(kk));

	/* Handle X25519 specially */
	if (kk->kk_algorithm == KV_ALG_X25519)
		return (kv_key_alloc_x25519(kk));

	/* Check for overflow: keybits + 7 must not overflow uint32_t */
	if (keybits > UINT32_MAX - 7)
		return (EINVAL);

	keylen = (keybits + 7) / 8;
	if (keylen == 0 || keylen > KV_MAX_KEY_SIZE)
		return (EINVAL);

	kk->kk_material = malloc(keylen, M_KEYVAULT, M_WAITOK | M_ZERO);
	kk->kk_matlen = keylen;
	kk->kk_keybits = keybits;
	kk->kk_type = KV_KEY_TYPE_SYMMETRIC;
	kk->kk_pubkey = NULL;
	kk->kk_publen = 0;

	/* Generate random key material */
	arc4random_buf(kk->kk_material, keylen);

	return (0);
}

/*
 * Securely wipe and free key material
 */
static void
kv_key_free_material(struct kv_key *kk)
{
	if (kk->kk_material != NULL) {
		explicit_bzero(kk->kk_material, kk->kk_matlen);
		free(kk->kk_material, M_KEYVAULT);
		kk->kk_material = NULL;
		kk->kk_matlen = 0;
	}

	/* Free public key for asymmetric keys */
	if (kk->kk_pubkey != NULL) {
		explicit_bzero(kk->kk_pubkey, kk->kk_publen);
		free(kk->kk_pubkey, M_KEYVAULT);
		kk->kk_pubkey = NULL;
		kk->kk_publen = 0;
	}
}

/*
 * Free a key object
 *
 * Called when reference count reaches zero.
 */
static void
kv_key_free(struct kv_key *kk)
{
	/* Free OpenCrypto session */
	if (kk->kk_have_session) {
		crypto_freesession(kk->kk_session);
		kk->kk_have_session = 0;
	}

	/* Securely wipe and free key material */
	kv_key_free_material(kk);

	/* Destroy mutex */
	mtx_destroy(&kk->kk_mtx);

	/* Free the key structure */
	free(kk, M_KEYVAULT);
}

/*
 * Generate a new key
 */
int
kv_key_generate(struct kv_file *kf, uint32_t algorithm, uint32_t keybits,
                uint32_t ttl, uint64_t *key_id_out)
{
	const struct kv_alg_info *ai;
	struct kv_key *kk;
	struct timeval tv;
	size_t matlen;
	int error;

	/* Look up algorithm */
	ai = kv_alg_lookup(algorithm);
	if (ai == NULL)
		return (EINVAL);

	/* Use default key size if not specified */
	if (keybits == 0)
		keybits = ai->ai_default_bits;

	/* Hash algorithms don't need keys */
	if (ai->ai_default_bits == 0)
		return (EINVAL);

	/* Validate key size */
	if (keybits < ai->ai_min_bits || keybits > ai->ai_max_bits)
		return (EINVAL);

	/* Calculate actual material length */
	matlen = (keybits + 7) / 8;

	/* Allocate key structure before taking lock (may sleep) */
	kk = malloc(sizeof(*kk), M_KEYVAULT, M_WAITOK | M_ZERO);

	mtx_init(&kk->kk_mtx, "kv_key", NULL, MTX_DEF);
	refcount_init(&kk->kk_refcnt, 1);  /* One ref for the file context */
	kk->kk_algorithm = algorithm;
	kk->kk_state = KV_KEY_STATE_ACTIVE;
	kk->kk_file = kf;

	/* Generate key material (may sleep) */
	error = kv_key_alloc_material(kk, keybits);
	if (error != 0) {
		mtx_destroy(&kk->kk_mtx);
		free(kk, M_KEYVAULT);
		return (error);
	}

	/* Set timestamps */
	getmicrotime(&tv);
	kk->kk_created = tv.tv_sec;
	if (ttl > 0) {
		/*
		 * Check for overflow when adding TTL.
		 * time_t is int64_t on FreeBSD; we use INT64_MAX as ceiling.
		 */
		if (tv.tv_sec > 0 && ttl > (uint32_t)(INT64_MAX - tv.tv_sec))
			kk->kk_expires = INT64_MAX;
		else
			kk->kk_expires = tv.tv_sec + ttl;
	} else
		kk->kk_expires = 0;

	/*
	 * Atomically check resource limits and insert.
	 * This fixes the TOCTOU race in the original code.
	 */
	KV_FILE_LOCK(kf);
	if (kf->kf_nkeys >= kv_max_keys_per_file) {
		KV_FILE_UNLOCK(kf);
		kv_key_free_material(kk);
		mtx_destroy(&kk->kk_mtx);
		free(kk, M_KEYVAULT);
		return (EMFILE);
	}
	if (kf->kf_keybytes + matlen > kv_max_key_bytes) {
		KV_FILE_UNLOCK(kf);
		kv_key_free_material(kk);
		mtx_destroy(&kk->kk_mtx);
		free(kk, M_KEYVAULT);
		return (ENOSPC);
	}

	/*
	 * Generate random key ID to prevent predictability.
	 * With 64-bit random IDs, collision probability is negligible.
	 */
	do {
		kk->kk_id = ((uint64_t)arc4random() << 32) | arc4random();
	} while (kk->kk_id == 0);  /* Ensure non-zero ID */

	/* Insert into key list */
	LIST_INSERT_HEAD(&kf->kf_keys, kk, kk_link);
	kf->kf_nkeys++;
	kf->kf_keybytes += kk->kk_matlen;
	KV_FILE_UNLOCK(kf);

	SDT_PROBE3(keyvault, key, lifecycle, create,
	    kk->kk_id, algorithm, keybits);

	*key_id_out = kk->kk_id;
	return (0);
}

/*
 * Import a key from raw material
 *
 * For Ed25519: key_material is a 32-byte seed
 * For symmetric keys: key_material is the raw key bytes
 */
int
kv_key_import(struct kv_file *kf, struct kv_import_req *req)
{
	const struct kv_alg_info *ai;
	struct kv_key *kk;
	struct timeval tv;
	uint8_t *keybuf = NULL;
	size_t keylen;
	int error;

	/* Validate algorithm */
	ai = kv_alg_lookup(req->algorithm);
	if (ai == NULL)
		return (EINVAL);

	/* Validate key material length */
	if (req->key_material == NULL || req->key_len == 0)
		return (EINVAL);

	/* Copy key material from userspace */
	keylen = req->key_len;
	if (keylen > KV_MAX_KEY_SIZE)
		return (EINVAL);

	keybuf = malloc(keylen, M_KEYVAULT, M_WAITOK);
	error = copyin(req->key_material, keybuf, keylen);
	if (error != 0) {
		explicit_bzero(keybuf, keylen);
		free(keybuf, M_KEYVAULT);
		return (error);
	}

	/* Allocate key structure */
	kk = malloc(sizeof(*kk), M_KEYVAULT, M_WAITOK | M_ZERO);
	mtx_init(&kk->kk_mtx, "kv_key", NULL, MTX_DEF);
	refcount_init(&kk->kk_refcnt, 1);
	kk->kk_algorithm = req->algorithm;
	kk->kk_state = KV_KEY_STATE_ACTIVE;
	kk->kk_file = kf;

	/* Handle Ed25519: import from seed */
	if (req->algorithm == KV_ALG_ED25519) {
		unsigned char pk[KV_ED25519_PUBLIC_SIZE];
		unsigned char sk[KV_ED25519_SECRET_SIZE];

		if (keylen != KV_ED25519_SEED_SIZE) {
			explicit_bzero(keybuf, keylen);
			free(keybuf, M_KEYVAULT);
			mtx_destroy(&kk->kk_mtx);
			free(kk, M_KEYVAULT);
			return (EINVAL);
		}

		/* Generate keypair from seed */
		if (kv_ed25519_seed_keypair(pk, sk, keybuf) != 0) {
			explicit_bzero(keybuf, keylen);
			free(keybuf, M_KEYVAULT);
			mtx_destroy(&kk->kk_mtx);
			free(kk, M_KEYVAULT);
			return (EIO);
		}

		/* Allocate and copy secret key */
		kk->kk_material = malloc(KV_ED25519_SECRET_SIZE, M_KEYVAULT,
		    M_WAITOK | M_ZERO);
		memcpy(kk->kk_material, sk, KV_ED25519_SECRET_SIZE);
		kk->kk_matlen = KV_ED25519_SECRET_SIZE;
		kk->kk_keybits = 256;

		/* Allocate and copy public key */
		kk->kk_pubkey = malloc(KV_ED25519_PUBLIC_SIZE, M_KEYVAULT,
		    M_WAITOK | M_ZERO);
		memcpy(kk->kk_pubkey, pk, KV_ED25519_PUBLIC_SIZE);
		kk->kk_publen = KV_ED25519_PUBLIC_SIZE;

		kk->kk_type = KV_KEY_TYPE_ASYMMETRIC;

		explicit_bzero(pk, sizeof(pk));
		explicit_bzero(sk, sizeof(sk));
	} else {
		/* Symmetric key: use raw material directly */
		kk->kk_material = malloc(keylen, M_KEYVAULT, M_WAITOK);
		memcpy(kk->kk_material, keybuf, keylen);
		kk->kk_matlen = keylen;
		kk->kk_keybits = keylen * 8;
		kk->kk_type = KV_KEY_TYPE_SYMMETRIC;
		kk->kk_pubkey = NULL;
		kk->kk_publen = 0;
	}

	/* Clear temporary buffer */
	explicit_bzero(keybuf, keylen);
	free(keybuf, M_KEYVAULT);

	/* Set timestamps */
	getmicrotime(&tv);
	kk->kk_created = tv.tv_sec;
	kk->kk_expires = 0;

	/* Check limits and insert */
	KV_FILE_LOCK(kf);
	if (kf->kf_nkeys >= kv_max_keys_per_file) {
		KV_FILE_UNLOCK(kf);
		kv_key_free_material(kk);
		mtx_destroy(&kk->kk_mtx);
		free(kk, M_KEYVAULT);
		return (EMFILE);
	}
	if (kf->kf_keybytes + kk->kk_matlen > kv_max_key_bytes) {
		KV_FILE_UNLOCK(kf);
		kv_key_free_material(kk);
		mtx_destroy(&kk->kk_mtx);
		free(kk, M_KEYVAULT);
		return (ENOSPC);
	}

	/* Generate random key ID */
	do {
		kk->kk_id = ((uint64_t)arc4random() << 32) | arc4random();
	} while (kk->kk_id == 0);

	/* Insert into key list */
	LIST_INSERT_HEAD(&kf->kf_keys, kk, kk_link);
	kf->kf_nkeys++;
	kf->kf_keybytes += kk->kk_matlen;
	KV_FILE_UNLOCK(kf);

	SDT_PROBE3(keyvault, key, lifecycle, create,
	    kk->kk_id, req->algorithm, kk->kk_keybits);

	req->key_id = kk->kk_id;
	return (0);
}

/*
 * Destroy a key
 */
int
kv_key_destroy(struct kv_file *kf, uint64_t key_id)
{
	struct kv_key *kk;

	KV_FILE_LOCK(kf);

	/* Find the key */
	LIST_FOREACH(kk, &kf->kf_keys, kk_link) {
		if (kk->kk_id == key_id)
			break;
	}

	if (kk == NULL) {
		KV_FILE_UNLOCK(kf);
		SDT_PROBE1(keyvault, error, key, notfound, key_id);
		return (ENOENT);
	}

	/* Remove from file's key list */
	LIST_REMOVE(kk, kk_link);
	kf->kf_nkeys--;
	kf->kf_keybytes -= kk->kk_matlen;

	KV_FILE_UNLOCK(kf);

	/* Mark as destroying */
	KV_KEY_LOCK(kk);
	kk->kk_state = KV_KEY_STATE_DESTROYING;
	KV_KEY_UNLOCK(kk);

	SDT_PROBE1(keyvault, key, lifecycle, destroy, key_id);

	/* Release the file context's reference */
	kv_key_release(kk);

	return (0);
}

/*
 * Revoke a key
 *
 * Revoked keys cannot start new operations but in-flight operations
 * are allowed to complete.
 */
int
kv_key_revoke(struct kv_file *kf, uint64_t key_id)
{
	struct kv_key *kk;
	int error = 0;

	KV_FILE_LOCK(kf);

	/* Find the key */
	LIST_FOREACH(kk, &kf->kf_keys, kk_link) {
		if (kk->kk_id == key_id)
			break;
	}

	if (kk == NULL) {
		KV_FILE_UNLOCK(kf);
		SDT_PROBE1(keyvault, error, key, notfound, key_id);
		return (ENOENT);
	}

	KV_KEY_LOCK(kk);
	if (kk->kk_state == KV_KEY_STATE_DESTROYING) {
		error = ENOENT;
	} else if (kk->kk_state != KV_KEY_STATE_REVOKED) {
		kk->kk_state = KV_KEY_STATE_REVOKED;
		SDT_PROBE1(keyvault, key, lifecycle, revoke, key_id);
	}
	KV_KEY_UNLOCK(kk);

	KV_FILE_UNLOCK(kf);

	return (error);
}

/*
 * Look up a key by ID (no reference taken)
 *
 * Caller must hold kf_mtx.
 */
struct kv_key *
kv_key_lookup(struct kv_file *kf, uint64_t key_id)
{
	struct kv_key *kk;

	KV_FILE_LOCK_ASSERT(kf);

	LIST_FOREACH(kk, &kf->kf_keys, kk_link) {
		if (kk->kk_id == key_id)
			return (kk);
	}

	return (NULL);
}

/*
 * Acquire a reference to a key for a crypto operation
 *
 * Returns NULL if the key doesn't exist, is revoked, or is expired.
 */
struct kv_key *
kv_key_acquire(struct kv_file *kf, uint64_t key_id)
{
	struct kv_key *kk;
	struct timeval tv;
	int error = 0;

	KV_FILE_LOCK(kf);

	/* Find the key */
	kk = kv_key_lookup(kf, key_id);
	if (kk == NULL) {
		KV_FILE_UNLOCK(kf);
		SDT_PROBE1(keyvault, error, key, notfound, key_id);
		return (NULL);
	}

	KV_KEY_LOCK(kk);

	/* Check key state */
	switch (kk->kk_state) {
	case KV_KEY_STATE_ACTIVE:
		/* Check expiration */
		if (kk->kk_expires != 0) {
			getmicrotime(&tv);
			if (tv.tv_sec >= kk->kk_expires) {
				kk->kk_state = KV_KEY_STATE_EXPIRED;
				SDT_PROBE1(keyvault, key, lifecycle, expire,
				    key_id);
				error = ESTALE;  /* Key has expired */
			}
		}
		break;

	case KV_KEY_STATE_REVOKED:
		error = EACCES;  /* Key has been revoked */
		break;

	case KV_KEY_STATE_EXPIRED:
		error = ESTALE;  /* Key has expired */
		break;

	case KV_KEY_STATE_DESTROYING:
		error = ENOENT;
		break;

	default:
		error = EINVAL;
		break;
	}

	if (error != 0) {
		KV_KEY_UNLOCK(kk);
		KV_FILE_UNLOCK(kf);
		return (NULL);
	}

	/* Take a reference */
	refcount_acquire(&kk->kk_refcnt);

	KV_KEY_UNLOCK(kk);
	KV_FILE_UNLOCK(kf);

	return (kk);
}

/*
 * Release a key reference
 *
 * If this was the last reference, the key is freed.
 */
void
kv_key_release(struct kv_key *kk)
{
	if (kk == NULL)
		return;

	if (refcount_release(&kk->kk_refcnt))
		kv_key_free(kk);
}

/*
 * Get key information
 */
int
kv_key_getinfo(struct kv_file *kf, uint64_t key_id, struct kv_keyinfo_req *info)
{
	struct kv_key *kk;

	KV_FILE_LOCK(kf);

	kk = kv_key_lookup(kf, key_id);
	if (kk == NULL) {
		KV_FILE_UNLOCK(kf);
		SDT_PROBE1(keyvault, error, key, notfound, key_id);
		return (ENOENT);
	}

	KV_KEY_LOCK(kk);

	info->algorithm = kk->kk_algorithm;
	info->key_bits = kk->kk_keybits;
	info->flags = 0;

	if (kk->kk_state == KV_KEY_STATE_REVOKED)
		info->flags |= KV_KEY_FLAG_REVOKED;
	if (kk->kk_state == KV_KEY_STATE_EXPIRED)
		info->flags |= KV_KEY_FLAG_EXPIRED;

	info->created = kk->kk_created;
	info->expires = kk->kk_expires;

	KV_KEY_UNLOCK(kk);
	KV_FILE_UNLOCK(kf);

	return (0);
}

/*
 * List all key IDs in a file context
 */
int
kv_key_list(struct kv_file *kf, uint64_t *ids, uint32_t max_keys,
            uint32_t *num_keys)
{
	struct kv_key *kk;
	uint64_t *id_buf;
	uint32_t count, alloc_keys;
	int error = 0;

	/* Validate and cap max_keys to prevent DoS */
	if (max_keys == 0) {
		*num_keys = 0;
		return (0);
	}
	if (max_keys > KV_MAX_LIST_KEYS)
		alloc_keys = KV_MAX_LIST_KEYS;
	else
		alloc_keys = max_keys;

	/* Allocate temporary buffer for key IDs */
	id_buf = malloc(alloc_keys * sizeof(uint64_t), M_KEYVAULT,
	    M_WAITOK | M_ZERO);

	KV_FILE_LOCK(kf);

	count = 0;
	LIST_FOREACH(kk, &kf->kf_keys, kk_link) {
		if (count >= alloc_keys)
			break;

		/* Skip keys being destroyed */
		KV_KEY_LOCK(kk);
		if (kk->kk_state != KV_KEY_STATE_DESTROYING) {
			id_buf[count++] = kk->kk_id;
		}
		KV_KEY_UNLOCK(kk);
	}

	*num_keys = count;

	KV_FILE_UNLOCK(kf);

	/* Copy to userspace */
	if (count > 0 && ids != NULL) {
		error = copyout(id_buf, ids, count * sizeof(uint64_t));
	}

	free(id_buf, M_KEYVAULT);

	return (error);
}
