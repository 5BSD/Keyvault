/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024-2025 Keyvault Authors
 *
 * Keyvault - Secure kernel-space key storage and cryptographic operations
 *
 * Public ioctl interface - shared between kernel and userspace
 */

#ifndef _KEYVAULT_H_
#define _KEYVAULT_H_

#include <sys/types.h>
#include <sys/ioccom.h>

/*
 * Algorithm identifiers
 */
#define KV_ALG_NONE             0

/* Hash algorithms */
#define KV_ALG_SHA256           1
#define KV_ALG_SHA512           2

/* Symmetric encryption */
#define KV_ALG_AES128_GCM       10
#define KV_ALG_AES256_GCM       11
#define KV_ALG_AES128_CBC       12
#define KV_ALG_AES256_CBC       13

/* MAC algorithms */
#define KV_ALG_HMAC_SHA256      20
#define KV_ALG_HMAC_SHA512      21

/* Asymmetric algorithms */
#define KV_ALG_ED25519          30	/* Ed25519 digital signatures */
#define KV_ALG_X25519           41	/* X25519 key exchange */

/* Additional AEAD */
#define KV_ALG_CHACHA20_POLY1305 40	/* ChaCha20-Poly1305 AEAD */

/* Key derivation */
#define KV_ALG_HKDF_SHA256      50	/* HKDF with SHA-256 */
#define KV_ALG_HKDF_SHA512      51	/* HKDF with SHA-512 */

/*
 * Key flags
 */
#define KV_KEY_FLAG_NONE        0x00000000
#define KV_KEY_FLAG_REVOKED     0x00000001  /* Key has been revoked */
#define KV_KEY_FLAG_EXPIRED     0x00000002  /* Key has expired */

/*
 * Capability flags for ioctl restrictions
 *
 * When a file descriptor is passed to another process, the sender can
 * restrict which operations the receiver may perform using KV_IOC_RESTRICT.
 * Capabilities can only be removed, never added.
 */
#define KV_CAP_GENKEY           0x00000001  /* Can generate new keys */
#define KV_CAP_DESTROY          0x00000002  /* Can destroy keys */
#define KV_CAP_REVOKE           0x00000004  /* Can revoke keys */
#define KV_CAP_ENCRYPT          0x00000008  /* Can perform encryption */
#define KV_CAP_DECRYPT          0x00000010  /* Can perform decryption */
#define KV_CAP_SIGN             0x00000020  /* Can sign data */
#define KV_CAP_VERIFY           0x00000040  /* Can verify signatures */
#define KV_CAP_MAC              0x00000080  /* Can compute MACs */
#define KV_CAP_HASH             0x00000100  /* Can compute hashes */
#define KV_CAP_GETINFO          0x00000200  /* Can query key info */
#define KV_CAP_LIST             0x00000400  /* Can list keys */
#define KV_CAP_RESTRICT         0x00000800  /* Can further restrict caps */
#define KV_CAP_DERIVE           0x00001000  /* Can derive keys (HKDF) */
#define KV_CAP_EXCHANGE         0x00002000  /* Can perform key exchange */
#define KV_CAP_IMPORT           0x00004000  /* Can import keys */

/* All capabilities (default for new opens) */
#define KV_CAP_ALL              0x00007FFF

/* Read-only operations */
#define KV_CAP_READONLY         (KV_CAP_ENCRYPT | KV_CAP_DECRYPT | \
                                 KV_CAP_SIGN | KV_CAP_VERIFY | \
                                 KV_CAP_MAC | KV_CAP_HASH | \
                                 KV_CAP_GETINFO | KV_CAP_LIST)

/*
 * Maximum sizes
 */
#define KV_MAX_KEY_SIZE         8192    /* Max key material in bytes */
#define KV_MAX_IV_SIZE          32      /* Max IV/nonce size */
#define KV_MAX_TAG_SIZE         32      /* Max auth tag size */
#define KV_MAX_AAD_SIZE         65536   /* Max additional auth data */
#define KV_MAX_DATA_SIZE        (1024 * 1024)  /* Max encrypt/decrypt size */
#define KV_MAX_LIST_KEYS        1024    /* Max keys in list request */

/*
 * ioctl structures
 */

/* Key generation request */
struct kv_genkey_req {
	uint32_t        algorithm;      /* in: KV_ALG_* */
	uint32_t        key_bits;       /* in: key size in bits (0 = default) */
	uint32_t        flags;          /* in: KV_KEY_FLAG_* */
	uint32_t        ttl_seconds;    /* in: time-to-live (0 = no expiry) */
	uint64_t        key_id;         /* out: assigned key identifier */
};

/* Key destruction request */
struct kv_destroy_req {
	uint64_t        key_id;         /* in: key to destroy */
};

/* Key info request */
struct kv_keyinfo_req {
	uint64_t        key_id;         /* in: key to query */
	uint32_t        algorithm;      /* out: KV_ALG_* */
	uint32_t        key_bits;       /* out: key size in bits */
	uint32_t        flags;          /* out: KV_KEY_FLAG_* */
	uint32_t        _pad;
	int64_t         created;        /* out: creation time (unix timestamp) */
	int64_t         expires;        /* out: expiry time (0 = never) */
};

/* List keys request */
struct kv_list_req {
	uint64_t       *key_ids;        /* out: array of key IDs (userspace ptr) */
	uint32_t        max_keys;       /* in: size of key_ids array */
	uint32_t        num_keys;       /* out: actual number of keys */
};

/* Symmetric encryption request */
struct kv_encrypt_req {
	uint64_t        key_id;         /* in: key to use */
	const void     *plaintext;      /* in: data to encrypt */
	size_t          plaintext_len;  /* in: plaintext length */
	void           *ciphertext;     /* out: encrypted data */
	size_t          ciphertext_len; /* in/out: buffer size / actual size */
	const void     *iv;             /* in: IV (NULL for random) */
	size_t          iv_len;         /* in: IV length */
	void           *iv_out;         /* out: IV used (if input IV was NULL) */
};

/* Symmetric decryption request */
struct kv_decrypt_req {
	uint64_t        key_id;         /* in: key to use */
	const void     *ciphertext;     /* in: data to decrypt */
	size_t          ciphertext_len; /* in: ciphertext length */
	void           *plaintext;      /* out: decrypted data */
	size_t          plaintext_len;  /* in/out: buffer size / actual size */
	const void     *iv;             /* in: IV used for encryption */
	size_t          iv_len;         /* in: IV length */
};

/* AEAD encryption request (AES-GCM) */
struct kv_aead_encrypt_req {
	uint64_t        key_id;         /* in: key to use */
	const void     *plaintext;      /* in: data to encrypt */
	size_t          plaintext_len;  /* in: plaintext length */
	const void     *aad;            /* in: additional authenticated data */
	size_t          aad_len;        /* in: AAD length */
	void           *ciphertext;     /* out: encrypted data */
	size_t          ciphertext_len; /* in/out: buffer size / actual size */
	const void     *nonce;          /* in: nonce (NULL for random) */
	size_t          nonce_len;      /* in: nonce length */
	void           *nonce_out;      /* out: nonce used (if input was NULL) */
	void           *tag;            /* out: authentication tag */
	size_t          tag_len;        /* in/out: tag buffer size / actual */
};

/* AEAD decryption request */
struct kv_aead_decrypt_req {
	uint64_t        key_id;         /* in: key to use */
	const void     *ciphertext;     /* in: data to decrypt */
	size_t          ciphertext_len; /* in: ciphertext length */
	const void     *aad;            /* in: additional authenticated data */
	size_t          aad_len;        /* in: AAD length */
	const void     *nonce;          /* in: nonce used for encryption */
	size_t          nonce_len;      /* in: nonce length */
	const void     *tag;            /* in: authentication tag */
	size_t          tag_len;        /* in: tag length */
	void           *plaintext;      /* out: decrypted data */
	size_t          plaintext_len;  /* in/out: buffer size / actual size */
};

/* Digital signature request */
struct kv_sign_req {
	uint64_t        key_id;         /* in: signing key */
	const void     *data;           /* in: data to sign */
	size_t          data_len;       /* in: data length */
	void           *signature;      /* out: signature */
	size_t          signature_len;  /* in/out: buffer size / actual size */
};

/* Signature verification request */
struct kv_verify_req {
	uint64_t        key_id;         /* in: verification key */
	const void     *data;           /* in: signed data */
	size_t          data_len;       /* in: data length */
	const void     *signature;      /* in: signature to verify */
	size_t          signature_len;  /* in: signature length */
	int             valid;          /* out: 1 if valid, 0 if invalid */
};

/* MAC generation request */
struct kv_mac_req {
	uint64_t        key_id;         /* in: MAC key */
	const void     *data;           /* in: data to MAC */
	size_t          data_len;       /* in: data length */
	void           *mac;            /* out: MAC value */
	size_t          mac_len;        /* in/out: buffer size / actual size */
};

/* Hash computation request (no key needed) */
struct kv_hash_req {
	uint32_t        algorithm;      /* in: KV_ALG_SHA256/SHA512 */
	uint32_t        _pad;
	const void     *data;           /* in: data to hash */
	size_t          data_len;       /* in: data length */
	void           *digest;         /* out: hash digest */
	size_t          digest_len;     /* in/out: buffer size / actual size */
};

/* Key revocation request */
struct kv_revoke_req {
	uint64_t        key_id;         /* in: key to revoke */
};

/* Capability restriction request */
struct kv_restrict_req {
	uint32_t        caps;           /* in: new capabilities (can only remove) */
	uint32_t        _pad;
};

/* Get current capabilities */
struct kv_getcaps_req {
	uint32_t        caps;           /* out: current capabilities */
	uint32_t        _pad;
};

/* Get public key (for asymmetric keys like Ed25519, X25519) */
struct kv_getpubkey_req {
	uint64_t        key_id;         /* in: asymmetric key */
	void           *pubkey;         /* out: public key buffer */
	size_t          pubkey_len;     /* in/out: buffer size / actual size */
};

/* X25519 key exchange request */
struct kv_keyexchange_req {
	uint64_t        key_id;         /* in: our X25519 private key */
	const void     *peer_pubkey;    /* in: peer's public key */
	size_t          peer_pubkey_len; /* in: peer public key length (must be 32) */
	void           *shared_secret;  /* out: derived shared secret */
	size_t          shared_secret_len; /* in/out: buffer size / actual (32) */
};

/* HKDF key derivation request */
struct kv_derive_req {
	uint64_t        key_id;         /* in: input key material (IKM) */
	uint32_t        algorithm;      /* in: KV_ALG_HKDF_SHA256/512 */
	uint32_t        output_bits;    /* in: output key size in bits */
	uint32_t        output_algorithm; /* in: algorithm for derived key (0=HMAC-SHA256) */
	uint32_t        _pad;
	const void     *salt;           /* in: optional salt (NULL for zeros) */
	size_t          salt_len;       /* in: salt length */
	const void     *info;           /* in: optional context info */
	size_t          info_len;       /* in: info length */
	uint64_t        derived_key_id; /* out: new derived key ID */
};

/* Key import request (for testing/backup restore) */
struct kv_import_req {
	uint32_t        algorithm;      /* in: KV_ALG_* */
	uint32_t        flags;          /* in: KV_KEY_FLAG_* */
	const void     *key_material;   /* in: raw key/seed bytes */
	size_t          key_len;        /* in: key material length */
	uint64_t        key_id;         /* out: assigned key identifier */
};

/*
 * ioctl commands
 *
 * Naming: KV_IOC_<operation>
 * Group: 'K' for Keyvault
 */
#define KV_IOC_GENKEY       _IOWR('K', 1, struct kv_genkey_req)
#define KV_IOC_DESTROY      _IOW('K', 2, struct kv_destroy_req)
#define KV_IOC_GETINFO      _IOWR('K', 3, struct kv_keyinfo_req)
#define KV_IOC_LIST         _IOWR('K', 4, struct kv_list_req)
#define KV_IOC_REVOKE       _IOW('K', 5, struct kv_revoke_req)
#define KV_IOC_RESTRICT     _IOW('K', 6, struct kv_restrict_req)
#define KV_IOC_GETCAPS      _IOR('K', 7, struct kv_getcaps_req)

#define KV_IOC_ENCRYPT      _IOWR('K', 10, struct kv_encrypt_req)
#define KV_IOC_DECRYPT      _IOWR('K', 11, struct kv_decrypt_req)
#define KV_IOC_AEAD_ENCRYPT _IOWR('K', 12, struct kv_aead_encrypt_req)
#define KV_IOC_AEAD_DECRYPT _IOWR('K', 13, struct kv_aead_decrypt_req)

#define KV_IOC_SIGN         _IOWR('K', 20, struct kv_sign_req)
#define KV_IOC_VERIFY       _IOWR('K', 21, struct kv_verify_req)
#define KV_IOC_MAC          _IOWR('K', 22, struct kv_mac_req)
#define KV_IOC_HASH         _IOWR('K', 23, struct kv_hash_req)
#define KV_IOC_GET_PUBKEY   _IOWR('K', 24, struct kv_getpubkey_req)

/* Key exchange and derivation */
#define KV_IOC_KEYEXCHANGE  _IOWR('K', 30, struct kv_keyexchange_req)
#define KV_IOC_DERIVE       _IOWR('K', 31, struct kv_derive_req)

/* Key import (for testing/backup restore) */
#define KV_IOC_IMPORT       _IOWR('K', 40, struct kv_import_req)

/*
 * X25519 / Curve25519 constants
 */
#define KV_X25519_PUBLIC_SIZE   32
#define KV_X25519_SECRET_SIZE   32
#define KV_X25519_SHARED_SIZE   32

/*
 * HKDF constants
 */
#define KV_HKDF_MAX_INFO_SIZE   1024
#define KV_HKDF_MAX_OUTPUT_SIZE 8160  /* 255 * 32 for SHA-256 */

/*
 * AEAD constants (AES-GCM, ChaCha20-Poly1305)
 */
#define KV_AEAD_NONCE_SIZE      12    /* 96-bit nonce for GCM/ChaCha20 */
#define KV_AEAD_TAG_SIZE        16    /* 128-bit authentication tag */

/*
 * AES-CBC constants
 */
#define KV_AES_BLOCK_SIZE       16    /* AES block size */
#define KV_AES_IV_SIZE          16    /* IV size for CBC mode */

/*
 * Ed25519 constants (also defined in keyvault_ed25519.h for kernel)
 */
#define KV_ED25519_SEED_SIZE      32
#define KV_ED25519_PUBLIC_SIZE    32
#define KV_ED25519_SECRET_SIZE    64
#define KV_ED25519_SIGNATURE_SIZE 64

#endif /* _KEYVAULT_H_ */
