/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Keyvault Authors
 *
 * Keyvault - Internal kernel structures
 *
 * This header is NOT for userspace consumption.
 */

#ifndef _KEYVAULT_INTERNAL_H_
#define _KEYVAULT_INTERNAL_H_

#ifdef _KERNEL

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/conf.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <sys/refcount.h>
#include <sys/time.h>
#include <sys/sdt.h>
#include <sys/selinfo.h>
#include <sys/poll.h>

#include <opencrypto/cryptodev.h>

#include "keyvault.h"

/*
 * DTrace SDT probes
 *
 * Usage:
 *   dtrace -n 'keyvault:::key-create { printf("key %d alg %d", arg0, arg1); }'
 */
SDT_PROVIDER_DECLARE(keyvault);

/* Key lifecycle probes */
SDT_PROBE_DECLARE(keyvault, key, lifecycle, create);
SDT_PROBE_DECLARE(keyvault, key, lifecycle, destroy);
SDT_PROBE_DECLARE(keyvault, key, lifecycle, revoke);
SDT_PROBE_DECLARE(keyvault, key, lifecycle, expire);

/* Crypto operation probes */
SDT_PROBE_DECLARE(keyvault, crypto, op, encrypt);
SDT_PROBE_DECLARE(keyvault, crypto, op, decrypt);
SDT_PROBE_DECLARE(keyvault, crypto, op, aead_encrypt);
SDT_PROBE_DECLARE(keyvault, crypto, op, aead_decrypt);
SDT_PROBE_DECLARE(keyvault, crypto, op, mac);
SDT_PROBE_DECLARE(keyvault, crypto, op, hash);
SDT_PROBE_DECLARE(keyvault, crypto, op, sign);
SDT_PROBE_DECLARE(keyvault, crypto, op, verify);
SDT_PROBE_DECLARE(keyvault, crypto, op, get_pubkey);
SDT_PROBE_DECLARE(keyvault, crypto, op, keyexchange);
SDT_PROBE_DECLARE(keyvault, crypto, op, derive);

/* Error probes */
SDT_PROBE_DECLARE(keyvault, error, cap, denied);
SDT_PROBE_DECLARE(keyvault, error, key, notfound);

/*
 * Resource limits (defaults, tunable via sysctl)
 */
#define KV_DEFAULT_MAX_KEYS_PER_FILE    256
#define KV_DEFAULT_MAX_KEY_BYTES        (1024 * 1024)   /* 1MB total key material */
#define KV_DEFAULT_MAX_FILES            1024
#define KV_DEFAULT_MAX_DATA_SIZE        (1024 * 1024)   /* 1MB max encrypt/decrypt */

/*
 * Sysctl tunable variables (defined in keyvault.c)
 */
extern unsigned int kv_max_keys_per_file;
extern unsigned int kv_max_key_bytes;
extern unsigned int kv_max_files;
extern unsigned int kv_max_data_size;

/*
 * Memory allocation type
 */
MALLOC_DECLARE(M_KEYVAULT);

/*
 * Forward declarations
 */
struct kv_softc;
struct kv_file;
struct kv_key;

/*
 * Per-device state (singleton)
 *
 * There is one kv_softc for the entire /dev/keyvault device.
 * It tracks all open file contexts.
 */
struct kv_softc {
	struct cdev             *sc_cdev;       /* character device */
	struct mtx               sc_mtx;        /* protects sc_files, sc_nfiles, sc_draining */
	LIST_HEAD(, kv_file)     sc_files;      /* list of open contexts */
	uint32_t                 sc_nfiles;     /* number of open contexts */
	int                      sc_draining;   /* set during module unload */
};

/*
 * Per-open context
 *
 * Created on open(), destroyed on final close().
 * Multiple processes can share this via fd passing (SCM_RIGHTS).
 * Lifetime managed by devfs cdevpriv mechanism.
 */
struct kv_file {
	struct mtx               kf_mtx;        /* protects kf_keys, kf_nkeys, kf_caps */
	LIST_HEAD(, kv_key)      kf_keys;       /* keys owned by this context */
	LIST_ENTRY(kv_file)      kf_link;       /* link in sc_files */
	struct kv_softc         *kf_sc;         /* back pointer to device */
	uint32_t                 kf_nkeys;      /* number of keys */
	size_t                   kf_keybytes;   /* total key material bytes */
	uint32_t                 kf_caps;       /* capability flags (protected by kf_mtx) */
	struct selinfo           kf_sel;        /* for select/poll/kevent */
	uint32_t                 kf_pending_ops; /* pending async operations */
	uint32_t                 kf_completed_ops; /* completed async operations */
};

/*
 * Key state
 */
#define KV_KEY_STATE_ACTIVE     0   /* Key is usable */
#define KV_KEY_STATE_REVOKED    1   /* Key is revoked */
#define KV_KEY_STATE_EXPIRED    2   /* Key has expired */
#define KV_KEY_STATE_DESTROYING 3   /* Key is being destroyed */

/*
 * Key type (symmetric vs asymmetric)
 */
#define KV_KEY_TYPE_SYMMETRIC   0   /* Symmetric key (AES, HMAC) */
#define KV_KEY_TYPE_ASYMMETRIC  1   /* Asymmetric key (Ed25519) */

/*
 * Key object
 *
 * Contains the actual key material, never exposed to userspace.
 * Reference counted to handle concurrent crypto operations.
 *
 * For symmetric keys:
 *   kk_material = key bytes
 *   kk_pubkey = NULL
 *
 * For asymmetric keys (Ed25519):
 *   kk_material = 64-byte secret key
 *   kk_pubkey = 32-byte public key (CAN be exported)
 */
struct kv_key {
	uint64_t                 kk_id;         /* unique key identifier */
	struct mtx               kk_mtx;        /* protects key state */
	volatile u_int           kk_refcnt;     /* reference count */
	uint32_t                 kk_algorithm;  /* KV_ALG_* */
	uint32_t                 kk_keybits;    /* key size in bits */
	int                      kk_state;      /* KV_KEY_STATE_* */
	int                      kk_type;       /* KV_KEY_TYPE_* */

	/* Key material - NEVER leaves kernel (secret key for asymmetric) */
	uint8_t                 *kk_material;   /* key data */
	size_t                   kk_matlen;     /* material length in bytes */

	/* Public key - CAN be exported (asymmetric keys only) */
	uint8_t                 *kk_pubkey;     /* public key (NULL for symmetric) */
	size_t                   kk_publen;     /* public key length */

	/* OpenCrypto session */
	crypto_session_t         kk_session;    /* crypto session handle */
	int                      kk_have_session; /* session is valid */

	/* Lifecycle timestamps */
	time_t                   kk_created;    /* creation time */
	time_t                   kk_expires;    /* expiry time (0 = never) */

	/* Linkage */
	LIST_ENTRY(kv_key)       kk_link;       /* link in kf_keys */
	struct kv_file          *kk_file;       /* owning file context */
};

/*
 * Global device pointer (singleton)
 */
extern struct kv_softc *kv_softc;

/*
 * Function prototypes - keyvault.c
 */
int  kv_open(struct cdev *dev, int oflags, int devtype, struct thread *td);
int  kv_close(struct cdev *dev, int fflag, int devtype, struct thread *td);
int  kv_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
              struct thread *td);
int  kv_poll(struct cdev *dev, int events, struct thread *td);
int  kv_kqfilter(struct cdev *dev, struct knote *kn);
void kv_file_dtor(void *data);

/*
 * Function prototypes - keyvault_key.c
 */

/* File context management */
struct kv_file *kv_file_alloc(struct kv_softc *sc);
void            kv_file_free(struct kv_file *kf);

/* Capability checking */
int             kv_file_check_cap(struct kv_file *kf, uint32_t cap);
int             kv_file_restrict(struct kv_file *kf, uint32_t newcaps);

/* Key lifecycle */
int             kv_key_generate(struct kv_file *kf, uint32_t algorithm,
                                uint32_t keybits, uint32_t ttl,
                                uint64_t *key_id_out);
int             kv_key_import(struct kv_file *kf, struct kv_import_req *req);
int             kv_key_destroy(struct kv_file *kf, uint64_t key_id);
int             kv_key_revoke(struct kv_file *kf, uint64_t key_id);

/* Key lookup and reference */
struct kv_key  *kv_key_lookup(struct kv_file *kf, uint64_t key_id);
struct kv_key  *kv_key_acquire(struct kv_file *kf, uint64_t key_id);
void            kv_key_release(struct kv_key *kk);

/* Key information */
int             kv_key_getinfo(struct kv_file *kf, uint64_t key_id,
                               struct kv_keyinfo_req *info);
int             kv_key_list(struct kv_file *kf, uint64_t *ids,
                            uint32_t max_keys, uint32_t *num_keys);

/*
 * Function prototypes - keyvault_crypto.c
 */
int             kv_crypto_encrypt(struct kv_file *kf, struct kv_encrypt_req *req);
int             kv_crypto_decrypt(struct kv_file *kf, struct kv_decrypt_req *req);
int             kv_crypto_aead_encrypt(struct kv_file *kf,
                                       struct kv_aead_encrypt_req *req);
int             kv_crypto_aead_decrypt(struct kv_file *kf,
                                       struct kv_aead_decrypt_req *req);
int             kv_crypto_sign(struct kv_file *kf, struct kv_sign_req *req);
int             kv_crypto_verify(struct kv_file *kf, struct kv_verify_req *req);
int             kv_crypto_mac(struct kv_file *kf, struct kv_mac_req *req);
int             kv_crypto_hash(struct kv_hash_req *req);
int             kv_crypto_get_pubkey(struct kv_file *kf,
                                     struct kv_getpubkey_req *req);
int             kv_crypto_keyexchange(struct kv_file *kf,
                                      struct kv_keyexchange_req *req);
int             kv_crypto_derive(struct kv_file *kf,
                                 struct kv_derive_req *req);

/*
 * Utility macros
 */
#define KV_LOCK(sc)             mtx_lock(&(sc)->sc_mtx)
#define KV_UNLOCK(sc)           mtx_unlock(&(sc)->sc_mtx)
#define KV_LOCK_ASSERT(sc)      mtx_assert(&(sc)->sc_mtx, MA_OWNED)

#define KV_FILE_LOCK(kf)        mtx_lock(&(kf)->kf_mtx)
#define KV_FILE_UNLOCK(kf)      mtx_unlock(&(kf)->kf_mtx)
#define KV_FILE_LOCK_ASSERT(kf) mtx_assert(&(kf)->kf_mtx, MA_OWNED)

#define KV_KEY_LOCK(kk)         mtx_lock(&(kk)->kk_mtx)
#define KV_KEY_UNLOCK(kk)       mtx_unlock(&(kk)->kk_mtx)
#define KV_KEY_LOCK_ASSERT(kk)  mtx_assert(&(kk)->kk_mtx, MA_OWNED)

#endif /* _KERNEL */

#endif /* _KEYVAULT_INTERNAL_H_ */
