/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024-2025 Keyvault Authors
 *
 * Keyvault - FreeBSD kernel module for secure key storage
 *
 * Main module: initialization, device registration, ioctl dispatch
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sdt.h>
#include <sys/sysctl.h>
#include <sys/event.h>
#include <sys/selinfo.h>
#include <sys/poll.h>

#include "keyvault_internal.h"

/*
 * Memory allocation type for keyvault
 */
MALLOC_DEFINE(M_KEYVAULT, "keyvault", "Keyvault key storage");

/*
 * Sysctl tunables
 *
 * These can be adjusted at runtime via:
 *   sysctl security.keyvault.max_keys_per_file=512
 *
 * All tunables have bounds checking to prevent denial of service.
 */
SYSCTL_NODE(_security, OID_AUTO, keyvault, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Keyvault kernel module");

/*
 * Sysctl bounds
 */
#define KV_SYSCTL_MIN_KEYS_PER_FILE	1
#define KV_SYSCTL_MAX_KEYS_PER_FILE	65536

#define KV_SYSCTL_MIN_KEY_BYTES		1024		/* 1KB minimum */
#define KV_SYSCTL_MAX_KEY_BYTES		(16 * 1024 * 1024)  /* 16MB max */

#define KV_SYSCTL_MIN_FILES		1
#define KV_SYSCTL_MAX_FILES		65536

#define KV_SYSCTL_MIN_DATA_SIZE		64		/* 64 bytes minimum */
#define KV_SYSCTL_MAX_DATA_SIZE		(16 * 1024 * 1024)  /* 16MB max */

unsigned int kv_max_keys_per_file = KV_DEFAULT_MAX_KEYS_PER_FILE;
unsigned int kv_max_key_bytes = KV_DEFAULT_MAX_KEY_BYTES;
unsigned int kv_max_files = KV_DEFAULT_MAX_FILES;
unsigned int kv_max_data_size = KV_DEFAULT_MAX_DATA_SIZE;

/*
 * Sysctl handler with bounds checking
 */
static int
kv_sysctl_uint_bounded(SYSCTL_HANDLER_ARGS)
{
	unsigned int val, min_val, max_val;
	int error;

	/* arg1 is the variable, arg2 encodes min (low 16 bits) and max (high 16 bits) index */
	val = *(unsigned int *)arg1;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	/* Decode bounds from arg2 */
	switch (arg2) {
	case 0:  /* max_keys_per_file */
		min_val = KV_SYSCTL_MIN_KEYS_PER_FILE;
		max_val = KV_SYSCTL_MAX_KEYS_PER_FILE;
		break;
	case 1:  /* max_key_bytes */
		min_val = KV_SYSCTL_MIN_KEY_BYTES;
		max_val = KV_SYSCTL_MAX_KEY_BYTES;
		break;
	case 2:  /* max_files */
		min_val = KV_SYSCTL_MIN_FILES;
		max_val = KV_SYSCTL_MAX_FILES;
		break;
	case 3:  /* max_data_size */
		min_val = KV_SYSCTL_MIN_DATA_SIZE;
		max_val = KV_SYSCTL_MAX_DATA_SIZE;
		break;
	default:
		return (EINVAL);
	}

	if (val < min_val || val > max_val)
		return (EINVAL);

	*(unsigned int *)arg1 = val;
	return (0);
}

SYSCTL_PROC(_security_keyvault, OID_AUTO, max_keys_per_file,
    CTLTYPE_UINT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE,
    &kv_max_keys_per_file, 0, kv_sysctl_uint_bounded, "IU",
    "Maximum keys per file descriptor (1-65536)");

SYSCTL_PROC(_security_keyvault, OID_AUTO, max_key_bytes,
    CTLTYPE_UINT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE,
    &kv_max_key_bytes, 1, kv_sysctl_uint_bounded, "IU",
    "Maximum total key material bytes per file descriptor (1KB-16MB)");

SYSCTL_PROC(_security_keyvault, OID_AUTO, max_files,
    CTLTYPE_UINT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE,
    &kv_max_files, 2, kv_sysctl_uint_bounded, "IU",
    "Maximum concurrent open file descriptors (1-65536)");

SYSCTL_PROC(_security_keyvault, OID_AUTO, max_data_size,
    CTLTYPE_UINT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE,
    &kv_max_data_size, 3, kv_sysctl_uint_bounded, "IU",
    "Maximum data size for encrypt/decrypt operations (64B-16MB)");

/*
 * DTrace SDT provider and probe definitions
 */
SDT_PROVIDER_DEFINE(keyvault);

/* Key lifecycle probes: (key_id, algorithm, keybits) */
SDT_PROBE_DEFINE3(keyvault, key, lifecycle, create,
    "uint64_t", "uint32_t", "uint32_t");
SDT_PROBE_DEFINE1(keyvault, key, lifecycle, destroy,
    "uint64_t");
SDT_PROBE_DEFINE1(keyvault, key, lifecycle, revoke,
    "uint64_t");
SDT_PROBE_DEFINE1(keyvault, key, lifecycle, expire,
    "uint64_t");

/* Crypto operation probes: (key_id, data_len, error) */
SDT_PROBE_DEFINE3(keyvault, crypto, op, encrypt,
    "uint64_t", "size_t", "int");
SDT_PROBE_DEFINE3(keyvault, crypto, op, decrypt,
    "uint64_t", "size_t", "int");
SDT_PROBE_DEFINE3(keyvault, crypto, op, aead_encrypt,
    "uint64_t", "size_t", "int");
SDT_PROBE_DEFINE3(keyvault, crypto, op, aead_decrypt,
    "uint64_t", "size_t", "int");
SDT_PROBE_DEFINE3(keyvault, crypto, op, mac,
    "uint64_t", "size_t", "int");
SDT_PROBE_DEFINE2(keyvault, crypto, op, hash,
    "size_t", "int");
SDT_PROBE_DEFINE3(keyvault, crypto, op, sign,
    "uint64_t", "size_t", "int");
SDT_PROBE_DEFINE4(keyvault, crypto, op, verify,
    "uint64_t", "size_t", "int", "int");  /* key_id, data_len, error, valid */
SDT_PROBE_DEFINE2(keyvault, crypto, op, get_pubkey,
    "uint64_t", "int");  /* key_id, error */
SDT_PROBE_DEFINE3(keyvault, crypto, op, keyexchange,
    "uint64_t", "size_t", "int");  /* key_id, shared_len, error */
SDT_PROBE_DEFINE3(keyvault, crypto, op, derive,
    "uint64_t", "size_t", "int");  /* key_id, output_len, error */

/* Error probes: (required_cap, current_caps) */
SDT_PROBE_DEFINE2(keyvault, error, cap, denied,
    "uint32_t", "uint32_t");
SDT_PROBE_DEFINE1(keyvault, error, key, notfound,
    "uint64_t");

/*
 * Global device state
 */
struct kv_softc *kv_softc = NULL;

/*
 * Character device switch table
 */
static struct cdevsw kv_cdevsw = {
	.d_version  = D_VERSION,
	.d_flags    = D_TRACKCLOSE,
	.d_open     = kv_open,
	.d_close    = kv_close,
	.d_ioctl    = kv_ioctl,
	.d_poll     = kv_poll,
	.d_kqfilter = kv_kqfilter,
	.d_name     = "keyvault",
};

/*
 * Device open
 *
 * Creates a new file context for this open instance.
 */
int
kv_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct kv_softc *sc;
	struct kv_file *kf;
	int error;

	sc = dev->si_drv1;
	if (sc == NULL)
		return (ENXIO);

	/* Allocate new file context */
	kf = kv_file_alloc(sc);
	if (kf == NULL)
		return (ENOMEM);

	/*
	 * Atomically check file limit and insert.
	 * This fixes the TOCTOU race in the original code.
	 * Also check if module is being unloaded.
	 */
	KV_LOCK(sc);
	if (sc->sc_draining) {
		KV_UNLOCK(sc);
		kv_file_free(kf);
		return (ENXIO);
	}
	if (sc->sc_nfiles >= kv_max_files) {
		KV_UNLOCK(sc);
		kv_file_free(kf);
		return (EMFILE);
	}
	LIST_INSERT_HEAD(&sc->sc_files, kf, kf_link);
	sc->sc_nfiles++;
	KV_UNLOCK(sc);

	/* Store file context in devfs */
	error = devfs_set_cdevpriv(kf, kv_file_dtor);
	if (error != 0) {
		KV_LOCK(sc);
		LIST_REMOVE(kf, kf_link);
		sc->sc_nfiles--;
		KV_UNLOCK(sc);
		kv_file_free(kf);
		return (error);
	}

	return (0);
}

/*
 * Device close
 *
 * The actual cleanup happens in kv_file_dtor when the last reference
 * to the cdevpriv is released.
 */
int
kv_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	/* Cleanup handled by devfs_clear_cdevpriv -> kv_file_dtor */
	return (0);
}

/*
 * File context destructor (called by devfs)
 *
 * This is called when the last reference to the file descriptor is released.
 */
void
kv_file_dtor(void *data)
{
	struct kv_file *kf = data;
	struct kv_softc *sc;

	if (kf == NULL)
		return;

	sc = kf->kf_sc;

	/* Remove from device's file list */
	KV_LOCK(sc);
	LIST_REMOVE(kf, kf_link);
	sc->sc_nfiles--;
	KV_UNLOCK(sc);

	/* Free the file context (destroys all keys) */
	kv_file_free(kf);
}

/*
 * Poll for events (select/poll)
 *
 * Returns readable when completed async operations are available.
 */
int
kv_poll(struct cdev *dev, int events, struct thread *td)
{
	struct kv_file *kf;
	int revents = 0;
	int error;

	error = devfs_get_cdevpriv((void **)&kf);
	if (error != 0)
		return (0);

	KV_FILE_LOCK(kf);

	/*
	 * POLLIN/POLLRDNORM: readable when completed operations available
	 * For now, always readable since we use synchronous ops
	 */
	if (events & (POLLIN | POLLRDNORM)) {
		if (kf->kf_completed_ops > 0)
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(td, &kf->kf_sel);
	}

	/* Device is always writable (can submit operations) */
	if (events & (POLLOUT | POLLWRNORM))
		revents |= events & (POLLOUT | POLLWRNORM);

	KV_FILE_UNLOCK(kf);

	return (revents);
}

/*
 * Kqueue filter operations
 */
static int kv_kqfilter_read(struct knote *kn, long hint);
static void kv_kqfilter_detach(struct knote *kn);

static struct filterops kv_read_filterops = {
	.f_isfd = 1,
	.f_detach = kv_kqfilter_detach,
	.f_event = kv_kqfilter_read,
};

static void
kv_kqfilter_detach(struct knote *kn)
{
	struct kv_file *kf = kn->kn_hook;

	KV_FILE_LOCK(kf);
	knlist_remove(&kf->kf_sel.si_note, kn, 1);
	KV_FILE_UNLOCK(kf);
}

static int
kv_kqfilter_read(struct knote *kn, long hint)
{
	struct kv_file *kf = kn->kn_hook;
	int ready;

	KV_FILE_LOCK(kf);
	kn->kn_data = kf->kf_completed_ops;
	ready = (kf->kf_completed_ops > 0);
	KV_FILE_UNLOCK(kf);

	return (ready);
}

/*
 * Kqueue filter attachment
 */
int
kv_kqfilter(struct cdev *dev, struct knote *kn)
{
	struct kv_file *kf;
	int error;

	error = devfs_get_cdevpriv((void **)&kf);
	if (error != 0)
		return (error);

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &kv_read_filterops;
		kn->kn_hook = kf;
		KV_FILE_LOCK(kf);
		knlist_add(&kf->kf_sel.si_note, kn, 1);
		KV_FILE_UNLOCK(kf);
		return (0);

	default:
		return (EINVAL);
	}
}

/*
 * Check capability and return error if denied
 */
static int
kv_check_cap(struct kv_file *kf, uint32_t cap)
{
	int error;

	error = kv_file_check_cap(kf, cap);
	if (error != 0) {
		SDT_PROBE2(keyvault, error, cap, denied, cap, kf->kf_caps);
	}
	return (error);
}

/*
 * Device ioctl handler
 *
 * Dispatch to appropriate handler based on command.
 */
int
kv_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
         struct thread *td)
{
	struct kv_file *kf;
	int error;

	/* Get the file context for this open instance */
	error = devfs_get_cdevpriv((void **)&kf);
	if (error != 0)
		return (error);

	switch (cmd) {
	/*
	 * Capability management
	 */
	case KV_IOC_GETCAPS:
		{
			struct kv_getcaps_req *req = (struct kv_getcaps_req *)data;
			KV_FILE_LOCK(kf);
			req->caps = kf->kf_caps;
			KV_FILE_UNLOCK(kf);
			error = 0;
		}
		break;

	case KV_IOC_RESTRICT:
		{
			struct kv_restrict_req *req = (struct kv_restrict_req *)data;
			error = kv_check_cap(kf, KV_CAP_RESTRICT);
			if (error == 0)
				error = kv_file_restrict(kf, req->caps);
		}
		break;

	/*
	 * Key management
	 */
	case KV_IOC_GENKEY:
		{
			struct kv_genkey_req *req = (struct kv_genkey_req *)data;
			error = kv_check_cap(kf, KV_CAP_GENKEY);
			if (error == 0)
				error = kv_key_generate(kf, req->algorithm,
				    req->key_bits, req->ttl_seconds, &req->key_id);
		}
		break;

	case KV_IOC_DESTROY:
		{
			struct kv_destroy_req *req = (struct kv_destroy_req *)data;
			error = kv_check_cap(kf, KV_CAP_DESTROY);
			if (error == 0)
				error = kv_key_destroy(kf, req->key_id);
		}
		break;

	case KV_IOC_GETINFO:
		{
			struct kv_keyinfo_req *req = (struct kv_keyinfo_req *)data;
			error = kv_check_cap(kf, KV_CAP_GETINFO);
			if (error == 0)
				error = kv_key_getinfo(kf, req->key_id, req);
		}
		break;

	case KV_IOC_LIST:
		{
			struct kv_list_req *req = (struct kv_list_req *)data;
			error = kv_check_cap(kf, KV_CAP_LIST);
			if (error == 0)
				error = kv_key_list(kf, req->key_ids, req->max_keys,
				    &req->num_keys);
		}
		break;

	case KV_IOC_REVOKE:
		{
			struct kv_revoke_req *req = (struct kv_revoke_req *)data;
			error = kv_check_cap(kf, KV_CAP_REVOKE);
			if (error == 0)
				error = kv_key_revoke(kf, req->key_id);
		}
		break;

	/*
	 * Crypto operations
	 */
	case KV_IOC_ENCRYPT:
		{
			struct kv_encrypt_req *req = (struct kv_encrypt_req *)data;
			error = kv_check_cap(kf, KV_CAP_ENCRYPT);
			if (error == 0)
				error = kv_crypto_encrypt(kf, req);
		}
		break;

	case KV_IOC_DECRYPT:
		{
			struct kv_decrypt_req *req = (struct kv_decrypt_req *)data;
			error = kv_check_cap(kf, KV_CAP_DECRYPT);
			if (error == 0)
				error = kv_crypto_decrypt(kf, req);
		}
		break;

	case KV_IOC_AEAD_ENCRYPT:
		{
			struct kv_aead_encrypt_req *req =
			    (struct kv_aead_encrypt_req *)data;
			error = kv_check_cap(kf, KV_CAP_ENCRYPT);
			if (error == 0)
				error = kv_crypto_aead_encrypt(kf, req);
		}
		break;

	case KV_IOC_AEAD_DECRYPT:
		{
			struct kv_aead_decrypt_req *req =
			    (struct kv_aead_decrypt_req *)data;
			error = kv_check_cap(kf, KV_CAP_DECRYPT);
			if (error == 0)
				error = kv_crypto_aead_decrypt(kf, req);
		}
		break;

	case KV_IOC_SIGN:
		{
			struct kv_sign_req *req = (struct kv_sign_req *)data;
			error = kv_check_cap(kf, KV_CAP_SIGN);
			if (error == 0)
				error = kv_crypto_sign(kf, req);
		}
		break;

	case KV_IOC_VERIFY:
		{
			struct kv_verify_req *req = (struct kv_verify_req *)data;
			error = kv_check_cap(kf, KV_CAP_VERIFY);
			if (error == 0)
				error = kv_crypto_verify(kf, req);
		}
		break;

	case KV_IOC_MAC:
		{
			struct kv_mac_req *req = (struct kv_mac_req *)data;
			error = kv_check_cap(kf, KV_CAP_MAC);
			if (error == 0)
				error = kv_crypto_mac(kf, req);
		}
		break;

	case KV_IOC_HASH:
		{
			struct kv_hash_req *req = (struct kv_hash_req *)data;
			error = kv_check_cap(kf, KV_CAP_HASH);
			if (error == 0)
				error = kv_crypto_hash(req);
		}
		break;

	case KV_IOC_GET_PUBKEY:
		{
			struct kv_getpubkey_req *req =
			    (struct kv_getpubkey_req *)data;
			error = kv_check_cap(kf, KV_CAP_GETINFO);
			if (error == 0)
				error = kv_crypto_get_pubkey(kf, req);
		}
		break;

	/*
	 * Key exchange and derivation
	 */
	case KV_IOC_KEYEXCHANGE:
		{
			struct kv_keyexchange_req *req =
			    (struct kv_keyexchange_req *)data;
			error = kv_check_cap(kf, KV_CAP_EXCHANGE);
			if (error == 0)
				error = kv_crypto_keyexchange(kf, req);
		}
		break;

	case KV_IOC_DERIVE:
		{
			struct kv_derive_req *req =
			    (struct kv_derive_req *)data;
			error = kv_check_cap(kf, KV_CAP_DERIVE);
			if (error == 0)
				error = kv_crypto_derive(kf, req);
		}
		break;

	case KV_IOC_IMPORT:
		{
			struct kv_import_req *req =
			    (struct kv_import_req *)data;
			error = kv_check_cap(kf, KV_CAP_IMPORT);
			if (error == 0)
				error = kv_key_import(kf, req);
		}
		break;

	default:
		error = ENOTTY;
		break;
	}

	return (error);
}

/*
 * Module load handler
 */
static int
kv_modevent(module_t mod, int type, void *arg)
{
	struct kv_softc *sc;
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		/* Allocate device state */
		sc = malloc(sizeof(*sc), M_KEYVAULT, M_WAITOK | M_ZERO);

		/* Initialize mutex */
		mtx_init(&sc->sc_mtx, "keyvault", NULL, MTX_DEF);

		/* Initialize file list */
		LIST_INIT(&sc->sc_files);
		sc->sc_nfiles = 0;
		sc->sc_draining = 0;

		/* Create character device */
		sc->sc_cdev = make_dev(&kv_cdevsw, 0, UID_ROOT, GID_WHEEL,
		    0600, "keyvault");
		if (sc->sc_cdev == NULL) {
			mtx_destroy(&sc->sc_mtx);
			free(sc, M_KEYVAULT);
			return (ENXIO);
		}
		sc->sc_cdev->si_drv1 = sc;

		/* Store global reference */
		kv_softc = sc;

		printf("keyvault: loaded\n");
		break;

	case MOD_UNLOAD:
		sc = kv_softc;
		if (sc == NULL)
			return (0);

		/*
		 * Set draining flag and check for open files atomically.
		 * This prevents new opens from racing with unload.
		 */
		KV_LOCK(sc);
		sc->sc_draining = 1;
		if (sc->sc_nfiles > 0) {
			sc->sc_draining = 0;  /* Reset on failure */
			KV_UNLOCK(sc);
			printf("keyvault: cannot unload, %u files open\n",
			    sc->sc_nfiles);
			return (EBUSY);
		}
		KV_UNLOCK(sc);

		/* Destroy character device */
		if (sc->sc_cdev != NULL)
			destroy_dev(sc->sc_cdev);

		/* Cleanup */
		mtx_destroy(&sc->sc_mtx);
		free(sc, M_KEYVAULT);
		kv_softc = NULL;

		printf("keyvault: unloaded\n");
		break;

	case MOD_SHUTDOWN:
		/* Nothing special needed */
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

/*
 * Module declaration
 */
static moduledata_t kv_mod = {
	"keyvault",
	kv_modevent,
	NULL
};

DECLARE_MODULE(keyvault, kv_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(keyvault, 1);
MODULE_DEPEND(keyvault, crypto, 1, 1, 1);
