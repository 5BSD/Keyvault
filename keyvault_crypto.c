/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024-2025 Keyvault Authors
 *
 * Keyvault - Cryptographic operations
 *
 * Implements encryption, decryption, signing, MAC, and hashing
 * using the FreeBSD OpenCrypto framework.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/uio.h>
#include <sys/random.h>
#include <sys/sdt.h>
#include <sys/proc.h>

#include <opencrypto/cryptodev.h>

#include "keyvault_internal.h"
#include "keyvault_ed25519.h"
#include "keyvault_x25519.h"
#include "keyvault_hkdf.h"

/*
 * Synchronous crypto completion context
 *
 * Used for blocking crypto operations when the driver doesn't
 * support synchronous completion.
 *
 * Heap-allocated to handle timeout race conditions safely.
 * If the caller times out, the callback is responsible for
 * freeing this structure.
 */
struct kv_crypto_wait {
	struct mtx	mtx;
	int		done;
	int		error;
	int		timedout;	/* Caller gave up waiting */
};

/*
 * Crypto callback for synchronous operations
 *
 * If the caller has timed out (cw->timedout set), we are responsible
 * for cleaning up the wait structure since the caller has abandoned it.
 */
static int
kv_crypto_callback(struct cryptop *crp)
{
	struct kv_crypto_wait *cw;
	int timedout;

	cw = crp->crp_opaque;
	mtx_lock(&cw->mtx);
	timedout = cw->timedout;
	if (!timedout) {
		cw->done = 1;
		cw->error = crp->crp_etype;
		wakeup(cw);
	}
	mtx_unlock(&cw->mtx);

	/*
	 * If the caller timed out and abandoned the request, we must
	 * clean up the wait structure. The caller has already returned.
	 */
	if (timedout) {
		mtx_destroy(&cw->mtx);
		free(cw, M_KEYVAULT);
	}

	return (0);
}

/*
 * Crypto operation timeout in seconds.
 * If a crypto operation takes longer than this, it's considered failed.
 */
#define KV_CRYPTO_TIMEOUT_SECS	30

/*
 * Dispatch a crypto request and wait for completion
 *
 * This handles both synchronous and asynchronous crypto drivers.
 * Includes a timeout to prevent indefinite hangs if the crypto
 * driver misbehaves.
 *
 * The wait structure is heap-allocated to safely handle timeout races.
 * If we timeout, we mark the structure as abandoned and let the callback
 * free it. Otherwise, we free it ourselves after completion.
 */
static int
kv_crypto_dispatch_sync(struct cryptop *crp)
{
	struct kv_crypto_wait *cw;
	int error, slperror;

	cw = malloc(sizeof(*cw), M_KEYVAULT, M_WAITOK | M_ZERO);
	mtx_init(&cw->mtx, "kvcrypto", NULL, MTX_DEF);
	cw->done = 0;
	cw->error = 0;
	cw->timedout = 0;

	crp->crp_opaque = cw;
	crp->crp_callback = kv_crypto_callback;

	error = crypto_dispatch(crp);

	/*
	 * If crypto_dispatch returns 0 and the callback hasn't been
	 * called yet, we need to wait for it.
	 */
	if (error == 0 || error == EINPROGRESS) {
		mtx_lock(&cw->mtx);
		while (!cw->done) {
			slperror = msleep(cw, &cw->mtx, PWAIT, "kvcrypt",
			    hz * KV_CRYPTO_TIMEOUT_SECS);
			if (slperror == EWOULDBLOCK) {
				/*
				 * Timeout expired. Mark as timed out so
				 * the callback knows to free the structure.
				 * The callback will still fire eventually.
				 */
				cw->timedout = 1;
				mtx_unlock(&cw->mtx);
				return (ETIMEDOUT);
			}
		}
		error = cw->error;
		mtx_unlock(&cw->mtx);
	}

	mtx_destroy(&cw->mtx);
	free(cw, M_KEYVAULT);
	return (error);
}

/*
 * Initialize a crypto session for a key
 *
 * Called lazily on first use of the key.
 */
static int
kv_crypto_init_session(struct kv_key *kk)
{
	struct crypto_session_params csp;
	int error;

	KV_KEY_LOCK_ASSERT(kk);

	if (kk->kk_have_session)
		return (0);

	memset(&csp, 0, sizeof(csp));

	switch (kk->kk_algorithm) {
	case KV_ALG_AES128_GCM:
	case KV_ALG_AES256_GCM:
		csp.csp_mode = CSP_MODE_AEAD;
		csp.csp_cipher_alg = CRYPTO_AES_NIST_GCM_16;
		csp.csp_cipher_key = kk->kk_material;
		csp.csp_cipher_klen = kk->kk_matlen;
		csp.csp_ivlen = 12;
		csp.csp_auth_mlen = 16;
		break;

	case KV_ALG_AES128_CBC:
	case KV_ALG_AES256_CBC:
		csp.csp_mode = CSP_MODE_CIPHER;
		csp.csp_cipher_alg = CRYPTO_AES_CBC;
		csp.csp_cipher_key = kk->kk_material;
		csp.csp_cipher_klen = kk->kk_matlen;
		csp.csp_ivlen = 16;
		break;

	case KV_ALG_HMAC_SHA256:
		csp.csp_mode = CSP_MODE_DIGEST;
		csp.csp_auth_alg = CRYPTO_SHA2_256_HMAC;
		csp.csp_auth_key = kk->kk_material;
		csp.csp_auth_klen = kk->kk_matlen;
		break;

	case KV_ALG_HMAC_SHA512:
		csp.csp_mode = CSP_MODE_DIGEST;
		csp.csp_auth_alg = CRYPTO_SHA2_512_HMAC;
		csp.csp_auth_key = kk->kk_material;
		csp.csp_auth_klen = kk->kk_matlen;
		break;

	case KV_ALG_CHACHA20_POLY1305:
		csp.csp_mode = CSP_MODE_AEAD;
		csp.csp_cipher_alg = CRYPTO_CHACHA20_POLY1305;
		csp.csp_cipher_key = kk->kk_material;
		csp.csp_cipher_klen = kk->kk_matlen;
		csp.csp_ivlen = 12;  /* 96-bit nonce */
		csp.csp_auth_mlen = 16;  /* 128-bit tag */
		break;

	default:
		return (EOPNOTSUPP);
	}

	/* Try hardware first, fall back to software */
	error = crypto_newsession(&kk->kk_session, &csp,
	    CRYPTOCAP_F_HARDWARE | CRYPTOCAP_F_SOFTWARE);
	if (error == 0)
		kk->kk_have_session = 1;

	return (error);
}

/*
 * Symmetric encryption (AES-CBC)
 */
int
kv_crypto_encrypt(struct kv_file *kf, struct kv_encrypt_req *req)
{
	struct kv_key *kk;
	struct cryptop *crp;
	uint8_t *inbuf, *outbuf, *iv;
	size_t ivlen;
	int error;

	/* Validate pointers and input sizes */
	if (req->plaintext == NULL || req->ciphertext == NULL)
		return (EINVAL);
	if (req->plaintext_len == 0 || req->plaintext_len > kv_get_max_data_size())
		return (EINVAL);

	/* Acquire key */
	kk = kv_key_acquire(kf, req->key_id);
	if (kk == NULL)
		return (ENOENT);

	/* Only CBC supported for this operation */
	if (kk->kk_algorithm != KV_ALG_AES128_CBC &&
	    kk->kk_algorithm != KV_ALG_AES256_CBC) {
		kv_key_release(kk);
		return (EOPNOTSUPP);
	}

	/* AES-CBC requires block-aligned input (no padding in kernel) */
	if (req->plaintext_len % KV_AES_BLOCK_SIZE != 0) {
		kv_key_release(kk);
		return (EINVAL);
	}

	/* Initialize session if needed */
	KV_KEY_LOCK(kk);
	error = kv_crypto_init_session(kk);
	KV_KEY_UNLOCK(kk);
	if (error != 0) {
		kv_key_release(kk);
		return (error);
	}

	/* Allocate buffers */
	ivlen = KV_AES_IV_SIZE;
	inbuf = malloc(req->plaintext_len, M_KEYVAULT, M_WAITOK);
	outbuf = malloc(req->plaintext_len, M_KEYVAULT, M_WAITOK);
	iv = malloc(ivlen, M_KEYVAULT, M_WAITOK);

	/* Copy plaintext from userspace */
	error = copyin(req->plaintext, inbuf, req->plaintext_len);
	if (error != 0)
		goto out;

	/* Handle IV */
	if (req->iv != NULL && req->iv_len > 0) {
		if (req->iv_len != ivlen) {
			error = EINVAL;
			goto out;
		}
		error = copyin(req->iv, iv, ivlen);
		if (error != 0)
			goto out;
	} else {
		/* Generate random IV */
		arc4random_buf(iv, ivlen);
	}

	/* Set up crypto request */
	crp = crypto_getreq(kk->kk_session, M_WAITOK);

	crypto_use_buf(crp, inbuf, req->plaintext_len);
	crypto_use_output_buf(crp, outbuf, req->plaintext_len);
	crp->crp_op = CRYPTO_OP_ENCRYPT;
	crp->crp_flags = CRYPTO_F_CBIFSYNC | CRYPTO_F_IV_SEPARATE;
	crp->crp_payload_start = 0;
	crp->crp_payload_length = req->plaintext_len;

	memcpy(crp->crp_iv, iv, ivlen);

	/* Dispatch and wait for completion */
	error = kv_crypto_dispatch_sync(crp);

	crypto_freereq(crp);

	if (error != 0)
		goto out;

	/* Copy ciphertext to userspace */
	if (req->ciphertext_len < req->plaintext_len) {
		error = ENOSPC;
		goto out;
	}
	error = copyout(outbuf, req->ciphertext, req->plaintext_len);
	if (error != 0)
		goto out;

	req->ciphertext_len = req->plaintext_len;

	/* Copy IV out if requested */
	if (req->iv_out != NULL) {
		error = copyout(iv, req->iv_out, ivlen);
	}

out:
	SDT_PROBE3(keyvault, crypto, op, encrypt,
	    req->key_id, req->plaintext_len, error);

	explicit_bzero(inbuf, req->plaintext_len);
	explicit_bzero(outbuf, req->plaintext_len);
	explicit_bzero(iv, ivlen);
	free(inbuf, M_KEYVAULT);
	free(outbuf, M_KEYVAULT);
	free(iv, M_KEYVAULT);
	kv_key_release(kk);
	return (error);
}

/*
 * Symmetric decryption (AES-CBC)
 */
int
kv_crypto_decrypt(struct kv_file *kf, struct kv_decrypt_req *req)
{
	struct kv_key *kk;
	struct cryptop *crp;
	uint8_t *inbuf, *outbuf, *iv;
	size_t ivlen;
	int error;

	/* Validate pointers and input sizes */
	if (req->ciphertext == NULL || req->plaintext == NULL)
		return (EINVAL);
	if (req->ciphertext_len == 0 || req->ciphertext_len > kv_get_max_data_size())
		return (EINVAL);
	if (req->iv == NULL || req->iv_len == 0)
		return (EINVAL);

	/* Acquire key */
	kk = kv_key_acquire(kf, req->key_id);
	if (kk == NULL)
		return (ENOENT);

	/* Only CBC supported for this operation */
	if (kk->kk_algorithm != KV_ALG_AES128_CBC &&
	    kk->kk_algorithm != KV_ALG_AES256_CBC) {
		kv_key_release(kk);
		return (EOPNOTSUPP);
	}

	/* AES-CBC requires block-aligned input (no padding in kernel) */
	if (req->ciphertext_len % KV_AES_BLOCK_SIZE != 0) {
		kv_key_release(kk);
		return (EINVAL);
	}

	/* Initialize session if needed */
	KV_KEY_LOCK(kk);
	error = kv_crypto_init_session(kk);
	KV_KEY_UNLOCK(kk);
	if (error != 0) {
		kv_key_release(kk);
		return (error);
	}

	/* Allocate buffers */
	ivlen = KV_AES_IV_SIZE;
	inbuf = malloc(req->ciphertext_len, M_KEYVAULT, M_WAITOK);
	outbuf = malloc(req->ciphertext_len, M_KEYVAULT, M_WAITOK);
	iv = malloc(ivlen, M_KEYVAULT, M_WAITOK);

	/* Copy ciphertext and IV from userspace */
	error = copyin(req->ciphertext, inbuf, req->ciphertext_len);
	if (error != 0)
		goto out;

	if (req->iv_len != ivlen) {
		error = EINVAL;
		goto out;
	}
	error = copyin(req->iv, iv, ivlen);
	if (error != 0)
		goto out;

	/* Set up crypto request */
	crp = crypto_getreq(kk->kk_session, M_WAITOK);

	crypto_use_buf(crp, inbuf, req->ciphertext_len);
	crypto_use_output_buf(crp, outbuf, req->ciphertext_len);
	crp->crp_op = CRYPTO_OP_DECRYPT;
	crp->crp_flags = CRYPTO_F_CBIFSYNC | CRYPTO_F_IV_SEPARATE;
	crp->crp_payload_start = 0;
	crp->crp_payload_length = req->ciphertext_len;

	memcpy(crp->crp_iv, iv, ivlen);

	/* Dispatch and wait for completion */
	error = kv_crypto_dispatch_sync(crp);

	crypto_freereq(crp);

	if (error != 0)
		goto out;

	/* Copy plaintext to userspace */
	if (req->plaintext_len < req->ciphertext_len) {
		error = ENOSPC;
		goto out;
	}
	error = copyout(outbuf, req->plaintext, req->ciphertext_len);
	if (error != 0)
		goto out;

	req->plaintext_len = req->ciphertext_len;

out:
	SDT_PROBE3(keyvault, crypto, op, decrypt,
	    req->key_id, req->ciphertext_len, error);

	explicit_bzero(inbuf, req->ciphertext_len);
	explicit_bzero(outbuf, req->ciphertext_len);
	explicit_bzero(iv, ivlen);
	free(inbuf, M_KEYVAULT);
	free(outbuf, M_KEYVAULT);
	free(iv, M_KEYVAULT);
	kv_key_release(kk);
	return (error);
}

/*
 * AEAD encryption (AES-GCM, ChaCha20-Poly1305)
 */
int
kv_crypto_aead_encrypt(struct kv_file *kf, struct kv_aead_encrypt_req *req)
{
	struct kv_key *kk;
	struct cryptop *crp;
	uint8_t *plainbuf, *outbuf, *aadbuf, *nonce, *tag;
	size_t nonce_len, tag_len, total_len;
	int error;

	/* Validate pointers */
	if (req->ciphertext == NULL || req->tag == NULL)
		return (EINVAL);
	if (req->plaintext_len > 0 && req->plaintext == NULL)
		return (EINVAL);
	if (req->aad_len > 0 && req->aad == NULL)
		return (EINVAL);

	/* Validate input sizes */
	if (req->plaintext_len > kv_get_max_data_size())
		return (EINVAL);
	if (req->aad_len > KV_MAX_AAD_SIZE)
		return (EINVAL);

	/* Check for integer overflow in total_len calculation */
	if (req->aad_len > SIZE_MAX - req->plaintext_len)
		return (EOVERFLOW);
	if (req->aad_len + req->plaintext_len > SIZE_MAX - 16) /* tag_len */
		return (EOVERFLOW);

	/* Acquire key */
	kk = kv_key_acquire(kf, req->key_id);
	if (kk == NULL)
		return (ENOENT);

	/* Only AEAD algorithms supported */
	if (kk->kk_algorithm != KV_ALG_AES128_GCM &&
	    kk->kk_algorithm != KV_ALG_AES256_GCM &&
	    kk->kk_algorithm != KV_ALG_CHACHA20_POLY1305) {
		kv_key_release(kk);
		return (EOPNOTSUPP);
	}

	/* Initialize session if needed */
	KV_KEY_LOCK(kk);
	error = kv_crypto_init_session(kk);
	KV_KEY_UNLOCK(kk);
	if (error != 0) {
		kv_key_release(kk);
		return (error);
	}

	/* AEAD parameters (same for AES-GCM and ChaCha20-Poly1305) */
	nonce_len = KV_AEAD_NONCE_SIZE;
	tag_len = KV_AEAD_TAG_SIZE;

	/* Allocate buffers */
	total_len = req->aad_len + req->plaintext_len + tag_len;
	plainbuf = req->plaintext_len > 0 ?
	    malloc(req->plaintext_len, M_KEYVAULT, M_WAITOK) : NULL;
	outbuf = malloc(total_len, M_KEYVAULT, M_WAITOK | M_ZERO);
	aadbuf = req->aad_len > 0 ?
	    malloc(req->aad_len, M_KEYVAULT, M_WAITOK) : NULL;
	nonce = malloc(nonce_len, M_KEYVAULT, M_WAITOK);
	tag = malloc(tag_len, M_KEYVAULT, M_WAITOK);

	/* Copy plaintext from userspace */
	if (req->plaintext_len > 0) {
		error = copyin(req->plaintext, plainbuf, req->plaintext_len);
		if (error != 0)
			goto out;
	}

	/* Copy AAD from userspace */
	if (req->aad_len > 0) {
		error = copyin(req->aad, aadbuf, req->aad_len);
		if (error != 0)
			goto out;
	}

	/* Handle nonce */
	if (req->nonce != NULL && req->nonce_len > 0) {
		if (req->nonce_len != nonce_len) {
			error = EINVAL;
			goto out;
		}
		error = copyin(req->nonce, nonce, nonce_len);
		if (error != 0)
			goto out;
	} else {
		arc4random_buf(nonce, nonce_len);
	}

	/* Set up crypto request */
	crp = crypto_getreq(kk->kk_session, M_WAITOK);

	/* For GCM, AAD comes first, then payload */
	if (aadbuf != NULL)
		memcpy(outbuf, aadbuf, req->aad_len);
	if (plainbuf != NULL)
		memcpy(outbuf + req->aad_len, plainbuf, req->plaintext_len);

	crypto_use_buf(crp, outbuf, total_len);
	crp->crp_op = CRYPTO_OP_ENCRYPT | CRYPTO_OP_COMPUTE_DIGEST;
	crp->crp_flags = CRYPTO_F_CBIFSYNC | CRYPTO_F_IV_SEPARATE;
	crp->crp_aad_start = 0;
	crp->crp_aad_length = req->aad_len;
	crp->crp_payload_start = req->aad_len;
	crp->crp_payload_length = req->plaintext_len;
	crp->crp_digest_start = req->aad_len + req->plaintext_len;

	memcpy(crp->crp_iv, nonce, nonce_len);

	/* Dispatch and wait for completion */
	error = kv_crypto_dispatch_sync(crp);

	crypto_freereq(crp);

	if (error != 0)
		goto out;

	/* Copy ciphertext to userspace */
	if (req->ciphertext_len < req->plaintext_len) {
		error = ENOSPC;
		goto out;
	}
	error = copyout(outbuf + req->aad_len, req->ciphertext,
	    req->plaintext_len);
	if (error != 0)
		goto out;
	req->ciphertext_len = req->plaintext_len;

	/* Copy tag to userspace */
	if (req->tag_len < tag_len) {
		error = ENOSPC;
		goto out;
	}
	memcpy(tag, outbuf + req->aad_len + req->plaintext_len, tag_len);
	error = copyout(tag, req->tag, tag_len);
	if (error != 0)
		goto out;
	req->tag_len = tag_len;

	/* Copy nonce out if requested */
	if (req->nonce_out != NULL) {
		error = copyout(nonce, req->nonce_out, nonce_len);
	}

out:
	SDT_PROBE3(keyvault, crypto, op, aead_encrypt,
	    req->key_id, req->plaintext_len, error);

	if (plainbuf != NULL) {
		explicit_bzero(plainbuf, req->plaintext_len);
		free(plainbuf, M_KEYVAULT);
	}
	explicit_bzero(outbuf, total_len);
	if (aadbuf != NULL) {
		explicit_bzero(aadbuf, req->aad_len);
		free(aadbuf, M_KEYVAULT);
	}
	explicit_bzero(nonce, nonce_len);
	explicit_bzero(tag, tag_len);
	free(outbuf, M_KEYVAULT);
	free(nonce, M_KEYVAULT);
	free(tag, M_KEYVAULT);
	kv_key_release(kk);
	return (error);
}

/*
 * AEAD decryption (AES-GCM, ChaCha20-Poly1305)
 */
int
kv_crypto_aead_decrypt(struct kv_file *kf, struct kv_aead_decrypt_req *req)
{
	struct kv_key *kk;
	struct cryptop *crp;
	uint8_t *cipherbuf, *aadbuf, *nonce, *tag;
	size_t nonce_len, tag_len, total_len;
	int error;

	/* Validate pointers */
	if (req->plaintext == NULL || req->nonce == NULL || req->tag == NULL)
		return (EINVAL);
	if (req->ciphertext_len > 0 && req->ciphertext == NULL)
		return (EINVAL);
	if (req->aad_len > 0 && req->aad == NULL)
		return (EINVAL);

	/* Validate input sizes */
	if (req->ciphertext_len > kv_get_max_data_size())
		return (EINVAL);
	if (req->aad_len > KV_MAX_AAD_SIZE)
		return (EINVAL);

	/* Check for integer overflow in total_len calculation */
	if (req->aad_len > SIZE_MAX - req->ciphertext_len)
		return (EOVERFLOW);
	if (req->aad_len + req->ciphertext_len > SIZE_MAX - 16) /* tag_len */
		return (EOVERFLOW);

	/* Acquire key */
	kk = kv_key_acquire(kf, req->key_id);
	if (kk == NULL)
		return (ENOENT);

	/* Only AEAD algorithms supported */
	if (kk->kk_algorithm != KV_ALG_AES128_GCM &&
	    kk->kk_algorithm != KV_ALG_AES256_GCM &&
	    kk->kk_algorithm != KV_ALG_CHACHA20_POLY1305) {
		kv_key_release(kk);
		return (EOPNOTSUPP);
	}

	/* Initialize session if needed */
	KV_KEY_LOCK(kk);
	error = kv_crypto_init_session(kk);
	KV_KEY_UNLOCK(kk);
	if (error != 0) {
		kv_key_release(kk);
		return (error);
	}

	/* AEAD parameters (same for AES-GCM and ChaCha20-Poly1305) */
	nonce_len = KV_AEAD_NONCE_SIZE;
	tag_len = KV_AEAD_TAG_SIZE;

	if (req->nonce_len != nonce_len || req->tag_len != tag_len) {
		kv_key_release(kk);
		return (EINVAL);
	}

	/* Allocate buffers */
	total_len = req->aad_len + req->ciphertext_len + tag_len;
	cipherbuf = malloc(total_len, M_KEYVAULT, M_WAITOK | M_ZERO);
	aadbuf = req->aad_len > 0 ?
	    malloc(req->aad_len, M_KEYVAULT, M_WAITOK) : NULL;
	nonce = malloc(nonce_len, M_KEYVAULT, M_WAITOK);
	tag = malloc(tag_len, M_KEYVAULT, M_WAITOK);

	/* Copy ciphertext from userspace */
	if (req->ciphertext_len > 0) {
		error = copyin(req->ciphertext, cipherbuf + req->aad_len,
		    req->ciphertext_len);
		if (error != 0)
			goto out;
	}

	/* Copy AAD from userspace */
	if (req->aad_len > 0) {
		error = copyin(req->aad, aadbuf, req->aad_len);
		if (error != 0)
			goto out;
		memcpy(cipherbuf, aadbuf, req->aad_len);
	}

	/* Copy nonce and tag from userspace */
	error = copyin(req->nonce, nonce, nonce_len);
	if (error != 0)
		goto out;
	error = copyin(req->tag, tag, tag_len);
	if (error != 0)
		goto out;

	/* Append tag to buffer */
	memcpy(cipherbuf + req->aad_len + req->ciphertext_len, tag, tag_len);

	/* Set up crypto request */
	crp = crypto_getreq(kk->kk_session, M_WAITOK);

	crypto_use_buf(crp, cipherbuf, total_len);
	crp->crp_op = CRYPTO_OP_DECRYPT | CRYPTO_OP_VERIFY_DIGEST;
	crp->crp_flags = CRYPTO_F_CBIFSYNC | CRYPTO_F_IV_SEPARATE;
	crp->crp_aad_start = 0;
	crp->crp_aad_length = req->aad_len;
	crp->crp_payload_start = req->aad_len;
	crp->crp_payload_length = req->ciphertext_len;
	crp->crp_digest_start = req->aad_len + req->ciphertext_len;

	memcpy(crp->crp_iv, nonce, nonce_len);

	/* Dispatch and wait for completion */
	error = kv_crypto_dispatch_sync(crp);

	crypto_freereq(crp);

	if (error != 0)
		goto out;

	/* Copy plaintext to userspace */
	if (req->plaintext_len < req->ciphertext_len) {
		error = ENOSPC;
		goto out;
	}
	error = copyout(cipherbuf + req->aad_len, req->plaintext,
	    req->ciphertext_len);
	if (error != 0)
		goto out;
	req->plaintext_len = req->ciphertext_len;

out:
	SDT_PROBE3(keyvault, crypto, op, aead_decrypt,
	    req->key_id, req->ciphertext_len, error);

	explicit_bzero(cipherbuf, total_len);
	if (aadbuf != NULL) {
		explicit_bzero(aadbuf, req->aad_len);
		free(aadbuf, M_KEYVAULT);
	}
	explicit_bzero(nonce, nonce_len);
	explicit_bzero(tag, tag_len);
	free(cipherbuf, M_KEYVAULT);
	free(nonce, M_KEYVAULT);
	free(tag, M_KEYVAULT);
	kv_key_release(kk);
	return (error);
}

/*
 * Digital signature (Ed25519)
 */
int
kv_crypto_sign(struct kv_file *kf, struct kv_sign_req *req)
{
	struct kv_key *kk;
	unsigned char *data = NULL;
	unsigned char sig[KV_ED25519_SIGNATURE_SIZE];
	int error;

	/* Validate parameters - empty messages (data_len == 0) are allowed */
	if ((req->data_len > 0 && req->data == NULL) ||
	    req->signature == NULL || req->signature_len < KV_ED25519_SIGNATURE_SIZE)
		return (EINVAL);

	if (req->data_len > kv_get_max_data_size())
		return (EFBIG);

	/* Acquire key */
	kk = kv_key_acquire(kf, req->key_id);
	if (kk == NULL) {
		SDT_PROBE1(keyvault, error, key, notfound, req->key_id);
		return (ENOENT);
	}

	/* Must be an Ed25519 key */
	if (kk->kk_algorithm != KV_ALG_ED25519) {
		kv_key_release(kk);
		return (EINVAL);
	}

	/* Check key state */
	KV_KEY_LOCK(kk);
	if (kk->kk_state != KV_KEY_STATE_ACTIVE) {
		KV_KEY_UNLOCK(kk);
		kv_key_release(kk);
		return (EACCES);  /* Key revoked or expired */
	}
	KV_KEY_UNLOCK(kk);

	/* Allocate and copy data from userspace (skip for empty messages) */
	if (req->data_len > 0) {
		data = malloc(req->data_len, M_KEYVAULT, M_WAITOK);
		error = copyin(req->data, data, req->data_len);
		if (error != 0) {
			explicit_bzero(data, req->data_len);
			free(data, M_KEYVAULT);
			kv_key_release(kk);
			return (error);
		}
	}

	/* Sign the data (empty message is valid for Ed25519) */
	error = kv_ed25519_sign_detached(sig, data, req->data_len,
	    kk->kk_material);
	if (error != 0) {
		if (data != NULL) {
			explicit_bzero(data, req->data_len);
			free(data, M_KEYVAULT);
		}
		kv_key_release(kk);
		return (EIO);
	}

	/* Copy signature to userspace */
	error = copyout(sig, req->signature, KV_ED25519_SIGNATURE_SIZE);
	if (error == 0)
		req->signature_len = KV_ED25519_SIGNATURE_SIZE;

	SDT_PROBE3(keyvault, crypto, op, sign,
	    req->key_id, req->data_len, error);

	/* Cleanup - zero sensitive data before freeing */
	explicit_bzero(sig, sizeof(sig));
	if (data != NULL) {
		explicit_bzero(data, req->data_len);
		free(data, M_KEYVAULT);
	}
	kv_key_release(kk);

	return (error);
}

/*
 * Signature verification (Ed25519)
 */
int
kv_crypto_verify(struct kv_file *kf, struct kv_verify_req *req)
{
	struct kv_key *kk;
	unsigned char *data = NULL;
	unsigned char sig[KV_ED25519_SIGNATURE_SIZE];
	int error;

	/* Validate parameters - empty messages (data_len == 0) are allowed */
	if ((req->data_len > 0 && req->data == NULL) ||
	    req->signature == NULL || req->signature_len != KV_ED25519_SIGNATURE_SIZE)
		return (EINVAL);

	if (req->data_len > kv_get_max_data_size())
		return (EFBIG);

	/* Acquire key */
	kk = kv_key_acquire(kf, req->key_id);
	if (kk == NULL) {
		SDT_PROBE1(keyvault, error, key, notfound, req->key_id);
		return (ENOENT);
	}

	/* Must be an Ed25519 key with valid public key */
	if (kk->kk_algorithm != KV_ALG_ED25519) {
		kv_key_release(kk);
		return (EINVAL);
	}
	if (kk->kk_pubkey == NULL || kk->kk_publen != KV_ED25519_PUBLIC_SIZE) {
		kv_key_release(kk);
		return (EINVAL);
	}

	/* Check key state */
	KV_KEY_LOCK(kk);
	if (kk->kk_state != KV_KEY_STATE_ACTIVE) {
		KV_KEY_UNLOCK(kk);
		kv_key_release(kk);
		return (EACCES);
	}
	KV_KEY_UNLOCK(kk);

	/* Allocate and copy data from userspace (skip for empty messages) */
	if (req->data_len > 0) {
		data = malloc(req->data_len, M_KEYVAULT, M_WAITOK);
		error = copyin(req->data, data, req->data_len);
		if (error != 0) {
			explicit_bzero(data, req->data_len);
			free(data, M_KEYVAULT);
			kv_key_release(kk);
			return (error);
		}
	}

	/* Copy signature from userspace */
	error = copyin(req->signature, sig, KV_ED25519_SIGNATURE_SIZE);
	if (error != 0) {
		explicit_bzero(sig, sizeof(sig));
		if (data != NULL) {
			explicit_bzero(data, req->data_len);
			free(data, M_KEYVAULT);
		}
		kv_key_release(kk);
		return (error);
	}

	/* Verify the signature using public key (empty message is valid) */
	error = kv_ed25519_verify_detached(sig, data, req->data_len,
	    kk->kk_pubkey);
	req->valid = (error == 0) ? 1 : 0;

	SDT_PROBE4(keyvault, crypto, op, verify,
	    req->key_id, req->data_len, 0, req->valid);

	/* Cleanup - zero sensitive data before freeing */
	explicit_bzero(sig, sizeof(sig));
	if (data != NULL) {
		explicit_bzero(data, req->data_len);
		free(data, M_KEYVAULT);
	}
	kv_key_release(kk);

	/* Verification failure is not an error, just sets valid=0 */
	return (0);
}

/*
 * MAC generation (HMAC)
 */
int
kv_crypto_mac(struct kv_file *kf, struct kv_mac_req *req)
{
	struct kv_key *kk;
	struct cryptop *crp;
	uint8_t *databuf, *macbuf;
	size_t mac_len;
	int error;

	/* Validate pointers and input sizes */
	if (req->data == NULL || req->mac == NULL)
		return (EINVAL);
	if (req->data_len == 0 || req->data_len > kv_get_max_data_size())
		return (EINVAL);

	/* Acquire key */
	kk = kv_key_acquire(kf, req->key_id);
	if (kk == NULL)
		return (ENOENT);

	/* Determine MAC length based on algorithm */
	switch (kk->kk_algorithm) {
	case KV_ALG_HMAC_SHA256:
		mac_len = 32;
		break;
	case KV_ALG_HMAC_SHA512:
		mac_len = 64;
		break;
	default:
		kv_key_release(kk);
		return (EOPNOTSUPP);
	}

	/* Check for integer overflow */
	if (req->data_len > SIZE_MAX - mac_len) {
		kv_key_release(kk);
		return (EOVERFLOW);
	}

	/* Initialize session if needed */
	KV_KEY_LOCK(kk);
	error = kv_crypto_init_session(kk);
	KV_KEY_UNLOCK(kk);
	if (error != 0) {
		kv_key_release(kk);
		return (error);
	}

	/* Allocate buffers */
	databuf = malloc(req->data_len + mac_len, M_KEYVAULT, M_WAITOK);
	macbuf = malloc(mac_len, M_KEYVAULT, M_WAITOK);

	/* Copy data from userspace */
	error = copyin(req->data, databuf, req->data_len);
	if (error != 0)
		goto out;

	/* Set up crypto request */
	crp = crypto_getreq(kk->kk_session, M_WAITOK);

	crypto_use_buf(crp, databuf, req->data_len + mac_len);
	crp->crp_op = CRYPTO_OP_COMPUTE_DIGEST;
	crp->crp_flags = CRYPTO_F_CBIFSYNC;
	crp->crp_payload_start = 0;
	crp->crp_payload_length = req->data_len;
	crp->crp_digest_start = req->data_len;

	/* Dispatch and wait for completion */
	error = kv_crypto_dispatch_sync(crp);

	crypto_freereq(crp);

	if (error != 0)
		goto out;

	/* Copy MAC to userspace */
	if (req->mac_len < mac_len) {
		error = ENOSPC;
		goto out;
	}
	memcpy(macbuf, databuf + req->data_len, mac_len);
	error = copyout(macbuf, req->mac, mac_len);
	if (error != 0)
		goto out;
	req->mac_len = mac_len;

out:
	SDT_PROBE3(keyvault, crypto, op, mac,
	    req->key_id, req->data_len, error);

	explicit_bzero(databuf, req->data_len + mac_len);
	explicit_bzero(macbuf, mac_len);
	free(databuf, M_KEYVAULT);
	free(macbuf, M_KEYVAULT);
	kv_key_release(kk);
	return (error);
}

/*
 * Hash computation (no key required)
 */
int
kv_crypto_hash(struct kv_hash_req *req)
{
	struct crypto_session_params csp;
	crypto_session_t session;
	struct cryptop *crp;
	uint8_t *databuf, *hashbuf;
	size_t hash_len;
	int error;

	/* Validate pointers and input sizes */
	if (req->data == NULL || req->digest == NULL)
		return (EINVAL);
	if (req->data_len == 0 || req->data_len > kv_get_max_data_size())
		return (EINVAL);

	/* Determine hash length and algorithm */
	memset(&csp, 0, sizeof(csp));
	csp.csp_mode = CSP_MODE_DIGEST;

	switch (req->algorithm) {
	case KV_ALG_SHA256:
		csp.csp_auth_alg = CRYPTO_SHA2_256;
		hash_len = 32;
		break;
	case KV_ALG_SHA512:
		csp.csp_auth_alg = CRYPTO_SHA2_512;
		hash_len = 64;
		break;
	default:
		return (EINVAL);
	}

	/* Check for integer overflow */
	if (req->data_len > SIZE_MAX - hash_len)
		return (EOVERFLOW);

	/* Create session */
	error = crypto_newsession(&session, &csp,
	    CRYPTOCAP_F_HARDWARE | CRYPTOCAP_F_SOFTWARE);
	if (error != 0)
		return (error);

	/* Allocate buffers */
	databuf = malloc(req->data_len + hash_len, M_KEYVAULT, M_WAITOK);
	hashbuf = malloc(hash_len, M_KEYVAULT, M_WAITOK);

	/* Copy data from userspace */
	error = copyin(req->data, databuf, req->data_len);
	if (error != 0)
		goto out;

	/* Set up crypto request */
	crp = crypto_getreq(session, M_WAITOK);

	crypto_use_buf(crp, databuf, req->data_len + hash_len);
	crp->crp_op = CRYPTO_OP_COMPUTE_DIGEST;
	crp->crp_flags = CRYPTO_F_CBIFSYNC;
	crp->crp_payload_start = 0;
	crp->crp_payload_length = req->data_len;
	crp->crp_digest_start = req->data_len;

	/* Dispatch and wait for completion */
	error = kv_crypto_dispatch_sync(crp);

	crypto_freereq(crp);

	if (error != 0)
		goto out;

	/* Copy hash to userspace */
	if (req->digest_len < hash_len) {
		error = ENOSPC;
		goto out;
	}
	memcpy(hashbuf, databuf + req->data_len, hash_len);
	error = copyout(hashbuf, req->digest, hash_len);
	if (error != 0)
		goto out;
	req->digest_len = hash_len;

out:
	SDT_PROBE2(keyvault, crypto, op, hash, req->data_len, error);

	explicit_bzero(databuf, req->data_len + hash_len);
	explicit_bzero(hashbuf, hash_len);
	free(databuf, M_KEYVAULT);
	free(hashbuf, M_KEYVAULT);
	crypto_freesession(session);
	return (error);
}

/*
 * Get public key from asymmetric key (Ed25519, X25519)
 */
int
kv_crypto_get_pubkey(struct kv_file *kf, struct kv_getpubkey_req *req)
{
	struct kv_key *kk;
	int error;

	/* Basic parameter validation */
	if (req->pubkey == NULL)
		return (EINVAL);

	/* Acquire key */
	kk = kv_key_acquire(kf, req->key_id);
	if (kk == NULL) {
		SDT_PROBE1(keyvault, error, key, notfound, req->key_id);
		return (ENOENT);
	}

	/*
	 * Must be an asymmetric key (Ed25519 or X25519).
	 * Note: kk_type, kk_algorithm, kk_pubkey, and kk_publen are all
	 * immutable after key creation, so no locking is needed here.
	 */
	if (kk->kk_type != KV_KEY_TYPE_ASYMMETRIC || kk->kk_pubkey == NULL) {
		kv_key_release(kk);
		return (EINVAL);
	}

	/* Verify algorithm is Ed25519 or X25519 (immutable field) */
	if (kk->kk_algorithm != KV_ALG_ED25519 &&
	    kk->kk_algorithm != KV_ALG_X25519) {
		kv_key_release(kk);
		return (EINVAL);
	}

	/* Check buffer size against actual public key length (immutable) */
	if (req->pubkey_len < kk->kk_publen) {
		kv_key_release(kk);
		return (ENOSPC);
	}

	/* Check key state */
	KV_KEY_LOCK(kk);
	if (kk->kk_state != KV_KEY_STATE_ACTIVE) {
		KV_KEY_UNLOCK(kk);
		kv_key_release(kk);
		return (EACCES);
	}
	KV_KEY_UNLOCK(kk);

	/* Copy public key to userspace */
	error = copyout(kk->kk_pubkey, req->pubkey, kk->kk_publen);
	if (error == 0)
		req->pubkey_len = kk->kk_publen;

	SDT_PROBE2(keyvault, crypto, op, get_pubkey, req->key_id, error);

	kv_key_release(kk);
	return (error);
}

/*
 * X25519 key exchange
 *
 * Computes a shared secret from our private key and peer's public key.
 *
 * SECURITY NOTE: The raw X25519 shared secret returned by this function
 * should NOT be used directly as a symmetric key. Applications should
 * process the shared secret through a KDF (such as HKDF via KV_IOC_DERIVE)
 * before using it for encryption. The raw output has non-uniform
 * distribution and should be considered input key material, not a key.
 */
int
kv_crypto_keyexchange(struct kv_file *kf, struct kv_keyexchange_req *req)
{
	struct kv_key *kk;
	unsigned char *peer_pk = NULL;
	unsigned char shared[KV_X25519_SHARED_SIZE];
	int error;

	/* Validate parameters */
	if (req->peer_pubkey == NULL ||
	    req->peer_pubkey_len != KV_X25519_POINT_SIZE)
		return (EINVAL);
	if (req->shared_secret == NULL ||
	    req->shared_secret_len < KV_X25519_SHARED_SIZE)
		return (EINVAL);

	/* Acquire key */
	kk = kv_key_acquire(kf, req->key_id);
	if (kk == NULL) {
		SDT_PROBE1(keyvault, error, key, notfound, req->key_id);
		return (ENOENT);
	}

	/* Must be an X25519 key */
	if (kk->kk_algorithm != KV_ALG_X25519) {
		kv_key_release(kk);
		return (EINVAL);
	}

	/* Check key state */
	KV_KEY_LOCK(kk);
	if (kk->kk_state != KV_KEY_STATE_ACTIVE) {
		KV_KEY_UNLOCK(kk);
		kv_key_release(kk);
		return (EACCES);
	}
	KV_KEY_UNLOCK(kk);

	/* Allocate buffer for peer's public key */
	peer_pk = malloc(KV_X25519_POINT_SIZE, M_KEYVAULT, M_WAITOK);

	/* Copy peer's public key from userspace */
	error = copyin(req->peer_pubkey, peer_pk, KV_X25519_POINT_SIZE);
	if (error != 0)
		goto out;

	/* Perform key exchange */
	error = kv_x25519_scalarmult(shared, kk->kk_material, peer_pk);
	if (error != 0) {
		/* Low-order point detected - potential attack */
		error = EINVAL;
		goto out;
	}

	/* Copy shared secret to userspace */
	error = copyout(shared, req->shared_secret, KV_X25519_SHARED_SIZE);
	if (error == 0)
		req->shared_secret_len = KV_X25519_SHARED_SIZE;

out:
	SDT_PROBE3(keyvault, crypto, op, keyexchange,
	    req->key_id, KV_X25519_SHARED_SIZE, error);

	/* Cleanup */
	explicit_bzero(shared, sizeof(shared));
	if (peer_pk != NULL) {
		explicit_bzero(peer_pk, KV_X25519_POINT_SIZE);
		free(peer_pk, M_KEYVAULT);
	}
	kv_key_release(kk);

	return (error);
}

/*
 * HKDF key derivation
 *
 * Derives a new key from an existing key using HKDF.
 * The derived key is stored in the keyvault and its ID is returned.
 */
int
kv_crypto_derive(struct kv_file *kf, struct kv_derive_req *req)
{
	struct kv_key *kk;
	unsigned char *salt = NULL;
	unsigned char *info = NULL;
	unsigned char *okm = NULL;
	size_t okm_len;
	uint32_t output_alg;
	int hash_alg;
	int error;

	/* Validate HKDF algorithm */
	switch (req->algorithm) {
	case KV_ALG_HKDF_SHA256:
		hash_alg = KV_HKDF_HASH_SHA256;
		break;
	case KV_ALG_HKDF_SHA512:
		hash_alg = KV_HKDF_HASH_SHA512;
		break;
	default:
		return (EINVAL);
	}

	/*
	 * Validate output algorithm.
	 * Only symmetric algorithms are allowed for derived keys.
	 * Default to HMAC-SHA256 if not specified (0).
	 */
	output_alg = req->output_algorithm;
	if (output_alg == 0)
		output_alg = KV_ALG_HMAC_SHA256;

	switch (output_alg) {
	case KV_ALG_AES128_GCM:
	case KV_ALG_AES256_GCM:
	case KV_ALG_AES128_CBC:
	case KV_ALG_AES256_CBC:
	case KV_ALG_CHACHA20_POLY1305:
	case KV_ALG_HMAC_SHA256:
	case KV_ALG_HMAC_SHA512:
		break;
	default:
		return (EINVAL);
	}

	/* Validate output size */
	if (req->output_bits == 0 || req->output_bits > 8160 * 8)
		return (EINVAL);
	if (req->output_bits % 8 != 0)
		return (EINVAL);
	okm_len = req->output_bits / 8;

	/* Validate info length */
	if (req->info_len > KV_HKDF_MAX_INFO_SIZE)
		return (EINVAL);

	/* Acquire source key (IKM) */
	kk = kv_key_acquire(kf, req->key_id);
	if (kk == NULL) {
		SDT_PROBE1(keyvault, error, key, notfound, req->key_id);
		return (ENOENT);
	}

	/* Check key state */
	KV_KEY_LOCK(kk);
	if (kk->kk_state != KV_KEY_STATE_ACTIVE) {
		KV_KEY_UNLOCK(kk);
		kv_key_release(kk);
		return (EACCES);
	}
	KV_KEY_UNLOCK(kk);

	/* Allocate buffers */
	okm = malloc(okm_len, M_KEYVAULT, M_WAITOK | M_ZERO);

	if (req->salt != NULL && req->salt_len > 0) {
		salt = malloc(req->salt_len, M_KEYVAULT, M_WAITOK);
		error = copyin(req->salt, salt, req->salt_len);
		if (error != 0)
			goto out;
	}

	if (req->info != NULL && req->info_len > 0) {
		info = malloc(req->info_len, M_KEYVAULT, M_WAITOK);
		error = copyin(req->info, info, req->info_len);
		if (error != 0)
			goto out;
	}

	/* Perform HKDF */
	error = kv_hkdf(okm, okm_len, hash_alg,
	    salt, req->salt_len,
	    kk->kk_material, kk->kk_matlen,
	    info, req->info_len);
	if (error != 0)
		goto out;

	/*
	 * Create a new symmetric key directly from the derived material.
	 * This avoids the race condition of generate-then-overwrite.
	 * Use the caller-specified algorithm, or HMAC-SHA256 if not specified.
	 */
	error = kv_key_create_from_material(kf, output_alg,
	    okm, okm_len, &req->derived_key_id);

out:
	SDT_PROBE3(keyvault, crypto, op, derive,
	    req->key_id, okm_len, error);

	/* Cleanup */
	if (okm != NULL) {
		explicit_bzero(okm, okm_len);
		free(okm, M_KEYVAULT);
	}
	if (salt != NULL) {
		explicit_bzero(salt, req->salt_len);
		free(salt, M_KEYVAULT);
	}
	if (info != NULL) {
		explicit_bzero(info, req->info_len);
		free(info, M_KEYVAULT);
	}
	kv_key_release(kk);

	return (error);
}
