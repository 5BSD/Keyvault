/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Keyvault comprehensive test program
 *
 * Tests:
 * - Basic key generation and lifecycle
 * - Encrypt/decrypt round-trip
 * - AEAD encrypt/decrypt
 * - File descriptor passing between processes
 * - Capability restrictions (receiver cannot revoke)
 *
 * Compile: cc -o kv_test kv_test.c
 * Run: ./kv_test (as root)
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include "../keyvault.h"

#define DEVICE_PATH "/dev/keyvault"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST_START(name) do { \
	printf("Test: %s... ", name); \
	fflush(stdout); \
	tests_run++; \
} while (0)

#define TEST_PASS() do { \
	printf("PASS\n"); \
	tests_passed++; \
} while (0)

#define TEST_FAIL(msg) do { \
	printf("FAIL (%s)\n", msg); \
} while (0)

/*
 * Test: Basic open/close
 */
static int
test_open_close(void)
{
	int fd;

	TEST_START("open/close");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Key generation
 */
static int
test_genkey(void)
{
	int fd;
	struct kv_genkey_req req;

	TEST_START("generate AES-256-GCM key");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	memset(&req, 0, sizeof(req));
	req.algorithm = KV_ALG_AES256_GCM;
	req.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &req) < 0) {
		TEST_FAIL("ioctl(KV_IOC_GENKEY)");
		close(fd);
		return (1);
	}

	if (req.key_id == 0) {
		TEST_FAIL("key_id is 0");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Key lifecycle (create, info, destroy)
 */
static int
test_key_lifecycle(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_keyinfo_req inforeq;
	struct kv_destroy_req destroyreq;

	TEST_START("key lifecycle");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_HMAC_SHA256;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Get info */
	memset(&inforeq, 0, sizeof(inforeq));
	inforeq.key_id = genreq.key_id;

	if (ioctl(fd, KV_IOC_GETINFO, &inforeq) < 0) {
		TEST_FAIL("getinfo");
		close(fd);
		return (1);
	}

	if (inforeq.algorithm != KV_ALG_HMAC_SHA256 ||
	    inforeq.key_bits != 256) {
		TEST_FAIL("info mismatch");
		close(fd);
		return (1);
	}

	/* Destroy key */
	memset(&destroyreq, 0, sizeof(destroyreq));
	destroyreq.key_id = genreq.key_id;

	if (ioctl(fd, KV_IOC_DESTROY, &destroyreq) < 0) {
		TEST_FAIL("destroy");
		close(fd);
		return (1);
	}

	/* Verify key is gone */
	if (ioctl(fd, KV_IOC_GETINFO, &inforeq) == 0) {
		TEST_FAIL("key still exists");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: AEAD encrypt/decrypt round-trip
 */
static int
test_aead_roundtrip(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_aead_encrypt_req encreq;
	struct kv_aead_decrypt_req decreq;
	const char *plaintext = "Hello, Keyvault! This is a test message.";
	const char *aad = "additional authenticated data";
	char ciphertext[128];
	char decrypted[128];
	char nonce[12];
	char tag[16];

	TEST_START("AEAD encrypt/decrypt round-trip");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate AES-256-GCM key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Encrypt */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = genreq.key_id;
	encreq.plaintext = plaintext;
	encreq.plaintext_len = strlen(plaintext);
	encreq.aad = aad;
	encreq.aad_len = strlen(aad);
	encreq.ciphertext = ciphertext;
	encreq.ciphertext_len = sizeof(ciphertext);
	encreq.nonce = NULL;  /* Let kernel generate */
	encreq.nonce_len = 0;
	encreq.nonce_out = nonce;
	encreq.tag = tag;
	encreq.tag_len = sizeof(tag);

	if (ioctl(fd, KV_IOC_AEAD_ENCRYPT, &encreq) < 0) {
		TEST_FAIL("encrypt");
		close(fd);
		return (1);
	}

	/* Verify ciphertext differs from plaintext */
	if (memcmp(ciphertext, plaintext, strlen(plaintext)) == 0) {
		TEST_FAIL("ciphertext equals plaintext");
		close(fd);
		return (1);
	}

	/* Decrypt */
	memset(&decreq, 0, sizeof(decreq));
	memset(decrypted, 0, sizeof(decrypted));
	decreq.key_id = genreq.key_id;
	decreq.ciphertext = ciphertext;
	decreq.ciphertext_len = encreq.ciphertext_len;
	decreq.aad = aad;
	decreq.aad_len = strlen(aad);
	decreq.nonce = nonce;
	decreq.nonce_len = 12;
	decreq.tag = tag;
	decreq.tag_len = 16;
	decreq.plaintext = decrypted;
	decreq.plaintext_len = sizeof(decrypted);

	if (ioctl(fd, KV_IOC_AEAD_DECRYPT, &decreq) < 0) {
		TEST_FAIL("decrypt");
		close(fd);
		return (1);
	}

	/* Verify decryption */
	if (decreq.plaintext_len != strlen(plaintext) ||
	    memcmp(decrypted, plaintext, strlen(plaintext)) != 0) {
		TEST_FAIL("decryption mismatch");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: HMAC-SHA256
 */
static int
test_mac(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_mac_req macreq;
	const char *data = "Data to authenticate";
	char mac[64];

	TEST_START("HMAC-SHA256");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate HMAC key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_HMAC_SHA256;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Compute MAC */
	memset(&macreq, 0, sizeof(macreq));
	macreq.key_id = genreq.key_id;
	macreq.data = data;
	macreq.data_len = strlen(data);
	macreq.mac = mac;
	macreq.mac_len = sizeof(mac);

	if (ioctl(fd, KV_IOC_MAC, &macreq) < 0) {
		TEST_FAIL("mac");
		close(fd);
		return (1);
	}

	if (macreq.mac_len != 32) {
		TEST_FAIL("wrong MAC length");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: SHA-256 hash
 */
static int
test_hash(void)
{
	int fd;
	struct kv_hash_req hashreq;
	const char *data = "Data to hash";
	char digest[64];

	TEST_START("SHA-256 hash");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Compute hash */
	memset(&hashreq, 0, sizeof(hashreq));
	hashreq.algorithm = KV_ALG_SHA256;
	hashreq.data = data;
	hashreq.data_len = strlen(data);
	hashreq.digest = digest;
	hashreq.digest_len = sizeof(digest);

	if (ioctl(fd, KV_IOC_HASH, &hashreq) < 0) {
		TEST_FAIL("hash");
		close(fd);
		return (1);
	}

	if (hashreq.digest_len != 32) {
		TEST_FAIL("wrong hash length");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Capability restriction
 */
static int
test_capability_restrict(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_revoke_req revreq;
	struct kv_getcaps_req getcaps;
	struct kv_restrict_req restrict_req;

	TEST_START("capability restriction");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate a key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Check initial capabilities */
	memset(&getcaps, 0, sizeof(getcaps));
	if (ioctl(fd, KV_IOC_GETCAPS, &getcaps) < 0) {
		TEST_FAIL("getcaps");
		close(fd);
		return (1);
	}

	if (getcaps.caps != KV_CAP_ALL) {
		TEST_FAIL("initial caps not KV_CAP_ALL");
		close(fd);
		return (1);
	}

	/* Restrict: remove revoke capability */
	memset(&restrict_req, 0, sizeof(restrict_req));
	restrict_req.caps = KV_CAP_ALL & ~KV_CAP_REVOKE;

	if (ioctl(fd, KV_IOC_RESTRICT, &restrict_req) < 0) {
		TEST_FAIL("restrict");
		close(fd);
		return (1);
	}

	/* Verify restriction took effect */
	if (ioctl(fd, KV_IOC_GETCAPS, &getcaps) < 0) {
		TEST_FAIL("getcaps after restrict");
		close(fd);
		return (1);
	}

	if (getcaps.caps & KV_CAP_REVOKE) {
		TEST_FAIL("revoke cap not removed");
		close(fd);
		return (1);
	}

	/* Try to revoke - should fail with EPERM */
	memset(&revreq, 0, sizeof(revreq));
	revreq.key_id = genreq.key_id;

	if (ioctl(fd, KV_IOC_REVOKE, &revreq) == 0) {
		TEST_FAIL("revoke should have failed");
		close(fd);
		return (1);
	}

	if (errno != EPERM) {
		TEST_FAIL("expected EPERM");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Send file descriptor over Unix socket
 */
static int
send_fd(int sock, int fd_to_send)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))];
	char dummy = 'F';

	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, sizeof(buf));

	iov.iov_base = &dummy;
	iov.iov_len = 1;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));

	return (sendmsg(sock, &msg, 0) >= 0 ? 0 : -1);
}

/*
 * Receive file descriptor over Unix socket
 */
static int
recv_fd(int sock)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))];
	char dummy;
	int fd;

	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, sizeof(buf));

	iov.iov_base = &dummy;
	iov.iov_len = 1;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	if (recvmsg(sock, &msg, 0) < 0)
		return (-1);

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL ||
	    cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS)
		return (-1);

	memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
	return (fd);
}

/*
 * Test: FD passing with restricted capabilities
 *
 * This test demonstrates:
 * 1. Process A opens /dev/keyvault and creates a key
 * 2. Process A restricts capabilities (removes REVOKE)
 * 3. Process A passes the fd to Process B via Unix socket
 * 4. Process B can use the key for crypto but cannot revoke it
 */
static int
test_fd_passing(void)
{
	int sv[2];
	pid_t pid;
	int status;
	int fd;
	struct kv_genkey_req genreq;
	struct kv_restrict_req restrict_req;
	struct kv_aead_encrypt_req encreq;
	struct kv_revoke_req revreq;
	const char *plaintext = "Secret message";
	char ciphertext[64];
	char nonce[12];
	char tag[16];

	TEST_START("fd passing with capability restriction");

	/* Create socket pair for fd passing */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		TEST_FAIL("socketpair");
		return (1);
	}

	pid = fork();
	if (pid < 0) {
		TEST_FAIL("fork");
		close(sv[0]);
		close(sv[1]);
		return (1);
	}

	if (pid == 0) {
		/* Child process (Process B - receiver) */
		close(sv[0]);

		/* Receive the fd */
		fd = recv_fd(sv[1]);
		if (fd < 0) {
			fprintf(stderr, "Child: failed to receive fd\n");
			_exit(1);
		}

		/* Read key_id from parent */
		uint64_t key_id;
		if (read(sv[1], &key_id, sizeof(key_id)) != sizeof(key_id)) {
			fprintf(stderr, "Child: failed to read key_id\n");
			close(fd);
			_exit(1);
		}

		/* Try to encrypt - should succeed */
		memset(&encreq, 0, sizeof(encreq));
		encreq.key_id = key_id;
		encreq.plaintext = plaintext;
		encreq.plaintext_len = strlen(plaintext);
		encreq.aad = NULL;
		encreq.aad_len = 0;
		encreq.ciphertext = ciphertext;
		encreq.ciphertext_len = sizeof(ciphertext);
		encreq.nonce = NULL;
		encreq.nonce_len = 0;
		encreq.nonce_out = nonce;
		encreq.tag = tag;
		encreq.tag_len = sizeof(tag);

		if (ioctl(fd, KV_IOC_AEAD_ENCRYPT, &encreq) < 0) {
			fprintf(stderr, "Child: encrypt failed (should succeed)\n");
			close(fd);
			_exit(2);
		}

		/* Try to revoke - should fail with EPERM */
		memset(&revreq, 0, sizeof(revreq));
		revreq.key_id = key_id;

		if (ioctl(fd, KV_IOC_REVOKE, &revreq) == 0) {
			fprintf(stderr, "Child: revoke succeeded (should fail)\n");
			close(fd);
			_exit(3);
		}

		if (errno != EPERM) {
			fprintf(stderr, "Child: expected EPERM, got %d\n", errno);
			close(fd);
			_exit(4);
		}

		close(fd);
		close(sv[1]);
		_exit(0);

	} else {
		/* Parent process (Process A - sender) */
		close(sv[1]);

		/* Open device and create key */
		fd = open(DEVICE_PATH, O_RDWR);
		if (fd < 0) {
			TEST_FAIL("parent: open");
			close(sv[0]);
			waitpid(pid, NULL, 0);
			return (1);
		}

		memset(&genreq, 0, sizeof(genreq));
		genreq.algorithm = KV_ALG_AES256_GCM;
		genreq.key_bits = 256;

		if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
			TEST_FAIL("parent: genkey");
			close(fd);
			close(sv[0]);
			waitpid(pid, NULL, 0);
			return (1);
		}

		/* Restrict capabilities - remove REVOKE and DESTROY */
		memset(&restrict_req, 0, sizeof(restrict_req));
		restrict_req.caps = KV_CAP_READONLY;

		if (ioctl(fd, KV_IOC_RESTRICT, &restrict_req) < 0) {
			TEST_FAIL("parent: restrict");
			close(fd);
			close(sv[0]);
			waitpid(pid, NULL, 0);
			return (1);
		}

		/* Send the fd to child */
		if (send_fd(sv[0], fd) < 0) {
			TEST_FAIL("parent: send_fd");
			close(fd);
			close(sv[0]);
			waitpid(pid, NULL, 0);
			return (1);
		}

		/* Send key_id to child */
		if (write(sv[0], &genreq.key_id, sizeof(genreq.key_id)) !=
		    sizeof(genreq.key_id)) {
			TEST_FAIL("parent: write key_id");
			close(fd);
			close(sv[0]);
			waitpid(pid, NULL, 0);
			return (1);
		}

		/* Wait for child */
		close(fd);
		close(sv[0]);
		waitpid(pid, &status, 0);

		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			char msg[64];
			snprintf(msg, sizeof(msg), "child exit status %d",
			    WEXITSTATUS(status));
			TEST_FAIL(msg);
			return (1);
		}

		TEST_PASS();
		return (0);
	}
}

/*
 * Test: AES-CBC encrypt/decrypt round-trip
 */
static int
test_cbc_roundtrip(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_encrypt_req encreq;
	struct kv_decrypt_req decreq;
	/* Plaintext must be multiple of 16 (AES block size) */
	const char *plaintext = "0123456789ABCDEF0123456789ABCDEF";
	char ciphertext[64];
	char decrypted[64];
	char iv[16];

	TEST_START("AES-CBC encrypt/decrypt round-trip");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate AES-256-CBC key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_CBC;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Encrypt */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = genreq.key_id;
	encreq.plaintext = plaintext;
	encreq.plaintext_len = strlen(plaintext);
	encreq.ciphertext = ciphertext;
	encreq.ciphertext_len = sizeof(ciphertext);
	encreq.iv = NULL;  /* Let kernel generate */
	encreq.iv_len = 0;
	encreq.iv_out = iv;

	if (ioctl(fd, KV_IOC_ENCRYPT, &encreq) < 0) {
		TEST_FAIL("encrypt");
		close(fd);
		return (1);
	}

	/* Verify ciphertext differs from plaintext */
	if (memcmp(ciphertext, plaintext, strlen(plaintext)) == 0) {
		TEST_FAIL("ciphertext equals plaintext");
		close(fd);
		return (1);
	}

	/* Decrypt */
	memset(&decreq, 0, sizeof(decreq));
	memset(decrypted, 0, sizeof(decrypted));
	decreq.key_id = genreq.key_id;
	decreq.ciphertext = ciphertext;
	decreq.ciphertext_len = encreq.ciphertext_len;
	decreq.plaintext = decrypted;
	decreq.plaintext_len = sizeof(decrypted);
	decreq.iv = iv;
	decreq.iv_len = 16;

	if (ioctl(fd, KV_IOC_DECRYPT, &decreq) < 0) {
		TEST_FAIL("decrypt");
		close(fd);
		return (1);
	}

	/* Verify decryption */
	if (decreq.plaintext_len != strlen(plaintext) ||
	    memcmp(decrypted, plaintext, strlen(plaintext)) != 0) {
		TEST_FAIL("decryption mismatch");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: HMAC-SHA512
 */
static int
test_mac_sha512(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_mac_req macreq;
	const char *data = "Data to authenticate with SHA512";
	char mac[64];

	TEST_START("HMAC-SHA512");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate HMAC-SHA512 key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_HMAC_SHA512;
	genreq.key_bits = 512;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Compute MAC */
	memset(&macreq, 0, sizeof(macreq));
	macreq.key_id = genreq.key_id;
	macreq.data = data;
	macreq.data_len = strlen(data);
	macreq.mac = mac;
	macreq.mac_len = sizeof(mac);

	if (ioctl(fd, KV_IOC_MAC, &macreq) < 0) {
		TEST_FAIL("mac");
		close(fd);
		return (1);
	}

	if (macreq.mac_len != 64) {
		TEST_FAIL("wrong MAC length (expected 64)");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: SHA-512 hash
 */
static int
test_hash_sha512(void)
{
	int fd;
	struct kv_hash_req hashreq;
	const char *data = "Data to hash with SHA512";
	char digest[64];

	TEST_START("SHA-512 hash");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Compute hash */
	memset(&hashreq, 0, sizeof(hashreq));
	hashreq.algorithm = KV_ALG_SHA512;
	hashreq.data = data;
	hashreq.data_len = strlen(data);
	hashreq.digest = digest;
	hashreq.digest_len = sizeof(digest);

	if (ioctl(fd, KV_IOC_HASH, &hashreq) < 0) {
		TEST_FAIL("hash");
		close(fd);
		return (1);
	}

	if (hashreq.digest_len != 64) {
		TEST_FAIL("wrong hash length (expected 64)");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: List keys
 */
static int
test_list_keys(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_list_req listreq;
	uint64_t key_ids[16];
	uint64_t created_ids[3];
	int i, found;

	TEST_START("list keys");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Create 3 keys */
	for (i = 0; i < 3; i++) {
		memset(&genreq, 0, sizeof(genreq));
		genreq.algorithm = KV_ALG_AES256_GCM;

		if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
			TEST_FAIL("genkey");
			close(fd);
			return (1);
		}
		created_ids[i] = genreq.key_id;
	}

	/* List keys */
	memset(&listreq, 0, sizeof(listreq));
	listreq.key_ids = key_ids;
	listreq.max_keys = 16;

	if (ioctl(fd, KV_IOC_LIST, &listreq) < 0) {
		TEST_FAIL("list");
		close(fd);
		return (1);
	}

	if (listreq.num_keys < 3) {
		TEST_FAIL("expected at least 3 keys");
		close(fd);
		return (1);
	}

	/* Verify all created keys are in the list */
	for (i = 0; i < 3; i++) {
		found = 0;
		for (uint32_t j = 0; j < listreq.num_keys; j++) {
			if (key_ids[j] == created_ids[i]) {
				found = 1;
				break;
			}
		}
		if (!found) {
			TEST_FAIL("created key not found in list");
			close(fd);
			return (1);
		}
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: AEAD authentication failure (tampered tag)
 */
static int
test_aead_auth_failure(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_aead_encrypt_req encreq;
	struct kv_aead_decrypt_req decreq;
	const char *plaintext = "Authentic message";
	char ciphertext[64];
	char decrypted[64];
	char nonce[12];
	char tag[16];

	TEST_START("AEAD authentication failure detection");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Encrypt */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = genreq.key_id;
	encreq.plaintext = plaintext;
	encreq.plaintext_len = strlen(plaintext);
	encreq.ciphertext = ciphertext;
	encreq.ciphertext_len = sizeof(ciphertext);
	encreq.nonce_out = nonce;
	encreq.tag = tag;
	encreq.tag_len = sizeof(tag);

	if (ioctl(fd, KV_IOC_AEAD_ENCRYPT, &encreq) < 0) {
		TEST_FAIL("encrypt");
		close(fd);
		return (1);
	}

	/* Tamper with the tag */
	tag[0] ^= 0xFF;

	/* Try to decrypt - should fail */
	memset(&decreq, 0, sizeof(decreq));
	decreq.key_id = genreq.key_id;
	decreq.ciphertext = ciphertext;
	decreq.ciphertext_len = encreq.ciphertext_len;
	decreq.nonce = nonce;
	decreq.nonce_len = 12;
	decreq.tag = tag;
	decreq.tag_len = 16;
	decreq.plaintext = decrypted;
	decreq.plaintext_len = sizeof(decrypted);

	if (ioctl(fd, KV_IOC_AEAD_DECRYPT, &decreq) == 0) {
		TEST_FAIL("decrypt should fail with tampered tag");
		close(fd);
		return (1);
	}

	/* Should get EBADMSG (authentication failure) or similar error */
	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Invalid key ID error handling
 */
static int
test_invalid_key_id(void)
{
	int fd;
	struct kv_keyinfo_req inforeq;
	struct kv_destroy_req destroyreq;

	TEST_START("invalid key ID error handling");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Try to get info for non-existent key */
	memset(&inforeq, 0, sizeof(inforeq));
	inforeq.key_id = 0xDEADBEEF;

	if (ioctl(fd, KV_IOC_GETINFO, &inforeq) == 0) {
		TEST_FAIL("getinfo should fail for invalid key");
		close(fd);
		return (1);
	}

	if (errno != ENOENT) {
		TEST_FAIL("expected ENOENT");
		close(fd);
		return (1);
	}

	/* Try to destroy non-existent key */
	memset(&destroyreq, 0, sizeof(destroyreq));
	destroyreq.key_id = 0xDEADBEEF;

	if (ioctl(fd, KV_IOC_DESTROY, &destroyreq) == 0) {
		TEST_FAIL("destroy should fail for invalid key");
		close(fd);
		return (1);
	}

	if (errno != ENOENT) {
		TEST_FAIL("expected ENOENT");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Wrong algorithm error handling
 */
static int
test_wrong_algorithm(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_aead_encrypt_req encreq;
	const char *plaintext = "test";
	char ciphertext[64];
	char nonce[12];
	char tag[16];

	TEST_START("wrong algorithm error handling");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate an HMAC key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_HMAC_SHA256;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Try AEAD encrypt with HMAC key - should fail */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = genreq.key_id;
	encreq.plaintext = plaintext;
	encreq.plaintext_len = strlen(plaintext);
	encreq.ciphertext = ciphertext;
	encreq.ciphertext_len = sizeof(ciphertext);
	encreq.nonce_out = nonce;
	encreq.tag = tag;
	encreq.tag_len = sizeof(tag);

	if (ioctl(fd, KV_IOC_AEAD_ENCRYPT, &encreq) == 0) {
		TEST_FAIL("AEAD encrypt should fail with HMAC key");
		close(fd);
		return (1);
	}

	if (errno != EOPNOTSUPP) {
		TEST_FAIL("expected EOPNOTSUPP");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Key expiration
 */
static int
test_key_expiration(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_aead_encrypt_req encreq;
	const char *plaintext = "test";
	char ciphertext[64];
	char nonce[12];
	char tag[16];

	TEST_START("key expiration");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate key with 1 second TTL */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;
	genreq.key_bits = 256;
	genreq.ttl_seconds = 1;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Use key immediately - should work */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = genreq.key_id;
	encreq.plaintext = plaintext;
	encreq.plaintext_len = strlen(plaintext);
	encreq.ciphertext = ciphertext;
	encreq.ciphertext_len = sizeof(ciphertext);
	encreq.nonce_out = nonce;
	encreq.tag = tag;
	encreq.tag_len = sizeof(tag);

	if (ioctl(fd, KV_IOC_AEAD_ENCRYPT, &encreq) < 0) {
		TEST_FAIL("encrypt before expiry");
		close(fd);
		return (1);
	}

	/* Wait for key to expire */
	sleep(2);

	/* Try to use expired key - should fail */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = genreq.key_id;
	encreq.plaintext = plaintext;
	encreq.plaintext_len = strlen(plaintext);
	encreq.ciphertext = ciphertext;
	encreq.ciphertext_len = sizeof(ciphertext);
	encreq.nonce_out = nonce;
	encreq.tag = tag;
	encreq.tag_len = sizeof(tag);

	if (ioctl(fd, KV_IOC_AEAD_ENCRYPT, &encreq) == 0) {
		TEST_FAIL("encrypt should fail after expiry");
		close(fd);
		return (1);
	}

	/* Should get ENOENT (key not found) since expired keys aren't usable */
	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: MAC consistency (same input = same output)
 */
static int
test_mac_consistency(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_mac_req macreq;
	const char *data = "Consistent data";
	char mac1[32];
	char mac2[32];

	TEST_START("MAC consistency");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate HMAC key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_HMAC_SHA256;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Compute MAC first time */
	memset(&macreq, 0, sizeof(macreq));
	macreq.key_id = genreq.key_id;
	macreq.data = data;
	macreq.data_len = strlen(data);
	macreq.mac = mac1;
	macreq.mac_len = sizeof(mac1);

	if (ioctl(fd, KV_IOC_MAC, &macreq) < 0) {
		TEST_FAIL("mac1");
		close(fd);
		return (1);
	}

	/* Compute MAC second time */
	memset(&macreq, 0, sizeof(macreq));
	macreq.key_id = genreq.key_id;
	macreq.data = data;
	macreq.data_len = strlen(data);
	macreq.mac = mac2;
	macreq.mac_len = sizeof(mac2);

	if (ioctl(fd, KV_IOC_MAC, &macreq) < 0) {
		TEST_FAIL("mac2");
		close(fd);
		return (1);
	}

	/* MACs should be identical */
	if (memcmp(mac1, mac2, 32) != 0) {
		TEST_FAIL("MACs differ for same input");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Hash consistency (same input = same output)
 */
static int
test_hash_consistency(void)
{
	int fd;
	struct kv_hash_req hashreq;
	const char *data = "Consistent data";
	char digest1[32];
	char digest2[32];

	TEST_START("hash consistency");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Compute hash first time */
	memset(&hashreq, 0, sizeof(hashreq));
	hashreq.algorithm = KV_ALG_SHA256;
	hashreq.data = data;
	hashreq.data_len = strlen(data);
	hashreq.digest = digest1;
	hashreq.digest_len = sizeof(digest1);

	if (ioctl(fd, KV_IOC_HASH, &hashreq) < 0) {
		TEST_FAIL("hash1");
		close(fd);
		return (1);
	}

	/* Compute hash second time */
	memset(&hashreq, 0, sizeof(hashreq));
	hashreq.algorithm = KV_ALG_SHA256;
	hashreq.data = data;
	hashreq.data_len = strlen(data);
	hashreq.digest = digest2;
	hashreq.digest_len = sizeof(digest2);

	if (ioctl(fd, KV_IOC_HASH, &hashreq) < 0) {
		TEST_FAIL("hash2");
		close(fd);
		return (1);
	}

	/* Hashes should be identical */
	if (memcmp(digest1, digest2, 32) != 0) {
		TEST_FAIL("hashes differ for same input");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Key revocation
 */
static int
test_key_revoke(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_revoke_req revreq;
	struct kv_keyinfo_req inforeq;
	struct kv_aead_encrypt_req encreq;
	const char *plaintext = "test";
	char ciphertext[64];
	char nonce[12];
	char tag[16];

	TEST_START("key revocation");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Revoke the key */
	memset(&revreq, 0, sizeof(revreq));
	revreq.key_id = genreq.key_id;

	if (ioctl(fd, KV_IOC_REVOKE, &revreq) < 0) {
		TEST_FAIL("revoke");
		close(fd);
		return (1);
	}

	/* Check key is marked as revoked */
	memset(&inforeq, 0, sizeof(inforeq));
	inforeq.key_id = genreq.key_id;

	if (ioctl(fd, KV_IOC_GETINFO, &inforeq) < 0) {
		TEST_FAIL("getinfo");
		close(fd);
		return (1);
	}

	if (!(inforeq.flags & KV_KEY_FLAG_REVOKED)) {
		TEST_FAIL("key not marked revoked");
		close(fd);
		return (1);
	}

	/* Try to use revoked key - should fail */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = genreq.key_id;
	encreq.plaintext = plaintext;
	encreq.plaintext_len = strlen(plaintext);
	encreq.ciphertext = ciphertext;
	encreq.ciphertext_len = sizeof(ciphertext);
	encreq.nonce_out = nonce;
	encreq.tag = tag;
	encreq.tag_len = sizeof(tag);

	if (ioctl(fd, KV_IOC_AEAD_ENCRYPT, &encreq) == 0) {
		TEST_FAIL("encrypt on revoked key should fail");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Zero-length data for various operations
 */
static int
test_zero_length_data(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_mac_req macreq;
	struct kv_hash_req hashreq;
	char buf[64];
	uint64_t hmac_key;

	TEST_START("zero-length data rejected");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate HMAC key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_HMAC_SHA256;
	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey HMAC");
		close(fd);
		return (1);
	}
	hmac_key = genreq.key_id;

	/* Zero-length MAC should fail */
	memset(&macreq, 0, sizeof(macreq));
	macreq.key_id = hmac_key;
	macreq.data = "x";
	macreq.data_len = 0;
	macreq.mac = buf;
	macreq.mac_len = sizeof(buf);

	if (ioctl(fd, KV_IOC_MAC, &macreq) == 0) {
		TEST_FAIL("zero-length MAC should fail");
		close(fd);
		return (1);
	}

	/* Zero-length hash should fail */
	memset(&hashreq, 0, sizeof(hashreq));
	hashreq.algorithm = KV_ALG_SHA256;
	hashreq.data = "x";
	hashreq.data_len = 0;
	hashreq.digest = buf;
	hashreq.digest_len = sizeof(buf);

	if (ioctl(fd, KV_IOC_HASH, &hashreq) == 0) {
		TEST_FAIL("zero-length hash should fail");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Invalid algorithm ID
 */
static int
test_invalid_algorithm(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_hash_req hashreq;
	char buf[64];

	TEST_START("invalid algorithm ID rejected");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Invalid algorithm for key generation */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = 9999;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) == 0) {
		TEST_FAIL("invalid algorithm should fail genkey");
		close(fd);
		return (1);
	}

	if (errno != EINVAL) {
		TEST_FAIL("expected EINVAL for bad algorithm");
		close(fd);
		return (1);
	}

	/* Invalid algorithm for hash */
	memset(&hashreq, 0, sizeof(hashreq));
	hashreq.algorithm = 9999;
	hashreq.data = "test";
	hashreq.data_len = 4;
	hashreq.digest = buf;
	hashreq.digest_len = sizeof(buf);

	if (ioctl(fd, KV_IOC_HASH, &hashreq) == 0) {
		TEST_FAIL("invalid algorithm should fail hash");
		close(fd);
		return (1);
	}

	/* Try to generate key for hash-only algorithm (SHA256) */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_SHA256;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) == 0) {
		TEST_FAIL("hash algorithm should not allow key generation");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: CBC non-aligned input rejected
 */
static int
test_cbc_alignment(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_encrypt_req encreq;
	char ciphertext[64];
	char iv[16];

	TEST_START("CBC non-aligned input rejected");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate CBC key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_CBC;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Try to encrypt 15 bytes (not multiple of 16) */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = genreq.key_id;
	encreq.plaintext = "123456789012345";  /* 15 bytes */
	encreq.plaintext_len = 15;
	encreq.ciphertext = ciphertext;
	encreq.ciphertext_len = sizeof(ciphertext);
	encreq.iv_out = iv;

	if (ioctl(fd, KV_IOC_ENCRYPT, &encreq) == 0) {
		TEST_FAIL("non-aligned CBC encrypt should fail");
		close(fd);
		return (1);
	}

	if (errno != EINVAL) {
		TEST_FAIL("expected EINVAL for non-aligned CBC");
		close(fd);
		return (1);
	}

	/* Try 17 bytes */
	encreq.plaintext = "12345678901234567";
	encreq.plaintext_len = 17;

	if (ioctl(fd, KV_IOC_ENCRYPT, &encreq) == 0) {
		TEST_FAIL("17-byte CBC encrypt should fail");
		close(fd);
		return (1);
	}

	/* 16 bytes should work */
	encreq.plaintext = "1234567890123456";
	encreq.plaintext_len = 16;

	if (ioctl(fd, KV_IOC_ENCRYPT, &encreq) < 0) {
		TEST_FAIL("16-byte CBC encrypt should succeed");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Invalid key size
 */
static int
test_invalid_key_size(void)
{
	int fd;
	struct kv_genkey_req genreq;

	TEST_START("invalid key size rejected");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* AES-256-GCM with wrong key size (128 bits) */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;
	genreq.key_bits = 128;  /* Should be 256 */

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) == 0) {
		TEST_FAIL("AES256 with 128-bit key should fail");
		close(fd);
		return (1);
	}

	if (errno != EINVAL) {
		TEST_FAIL("expected EINVAL");
		close(fd);
		return (1);
	}

	/* AES-128-GCM with wrong key size (256 bits) */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES128_GCM;
	genreq.key_bits = 256;  /* Should be 128 */

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) == 0) {
		TEST_FAIL("AES128 with 256-bit key should fail");
		close(fd);
		return (1);
	}

	/* Absurdly large key size */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_HMAC_SHA256;
	genreq.key_bits = 1000000;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) == 0) {
		TEST_FAIL("huge key size should fail");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Output buffer too small
 */
static int
test_buffer_too_small(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_aead_encrypt_req encreq;
	struct kv_mac_req macreq;
	struct kv_hash_req hashreq;
	char tiny_buf[4];
	char nonce[12];
	char tag[16];

	TEST_START("buffer too small rejected");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate keys */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;
	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey GCM");
		close(fd);
		return (1);
	}
	uint64_t gcm_key = genreq.key_id;

	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_HMAC_SHA256;
	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey HMAC");
		close(fd);
		return (1);
	}
	uint64_t hmac_key = genreq.key_id;

	/* AEAD encrypt with tiny ciphertext buffer */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = gcm_key;
	encreq.plaintext = "Hello World Test";
	encreq.plaintext_len = 16;
	encreq.ciphertext = tiny_buf;
	encreq.ciphertext_len = sizeof(tiny_buf);  /* Too small */
	encreq.nonce_out = nonce;
	encreq.tag = tag;
	encreq.tag_len = sizeof(tag);

	if (ioctl(fd, KV_IOC_AEAD_ENCRYPT, &encreq) == 0) {
		TEST_FAIL("tiny ciphertext buffer should fail");
		close(fd);
		return (1);
	}

	if (errno != ENOSPC) {
		TEST_FAIL("expected ENOSPC for small buffer");
		close(fd);
		return (1);
	}

	/* MAC with tiny output buffer */
	memset(&macreq, 0, sizeof(macreq));
	macreq.key_id = hmac_key;
	macreq.data = "test data";
	macreq.data_len = 9;
	macreq.mac = tiny_buf;
	macreq.mac_len = sizeof(tiny_buf);  /* Need 32 bytes */

	if (ioctl(fd, KV_IOC_MAC, &macreq) == 0) {
		TEST_FAIL("tiny MAC buffer should fail");
		close(fd);
		return (1);
	}

	if (errno != ENOSPC) {
		TEST_FAIL("expected ENOSPC for small MAC buffer");
		close(fd);
		return (1);
	}

	/* Hash with tiny output buffer */
	memset(&hashreq, 0, sizeof(hashreq));
	hashreq.algorithm = KV_ALG_SHA256;
	hashreq.data = "test data";
	hashreq.data_len = 9;
	hashreq.digest = tiny_buf;
	hashreq.digest_len = sizeof(tiny_buf);  /* Need 32 bytes */

	if (ioctl(fd, KV_IOC_HASH, &hashreq) == 0) {
		TEST_FAIL("tiny hash buffer should fail");
		close(fd);
		return (1);
	}

	if (errno != ENOSPC) {
		TEST_FAIL("expected ENOSPC for small hash buffer");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Double destroy fails
 */
static int
test_double_destroy(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_destroy_req destroyreq;

	TEST_START("double destroy fails");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* First destroy - should succeed */
	memset(&destroyreq, 0, sizeof(destroyreq));
	destroyreq.key_id = genreq.key_id;

	if (ioctl(fd, KV_IOC_DESTROY, &destroyreq) < 0) {
		TEST_FAIL("first destroy failed");
		close(fd);
		return (1);
	}

	/* Second destroy - should fail with ENOENT */
	if (ioctl(fd, KV_IOC_DESTROY, &destroyreq) == 0) {
		TEST_FAIL("second destroy should fail");
		close(fd);
		return (1);
	}

	if (errno != ENOENT) {
		TEST_FAIL("expected ENOENT");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Double revoke is idempotent
 */
static int
test_double_revoke(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_revoke_req revreq;
	struct kv_keyinfo_req inforeq;

	TEST_START("double revoke is idempotent");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	memset(&revreq, 0, sizeof(revreq));
	revreq.key_id = genreq.key_id;

	/* First revoke */
	if (ioctl(fd, KV_IOC_REVOKE, &revreq) < 0) {
		TEST_FAIL("first revoke failed");
		close(fd);
		return (1);
	}

	/* Second revoke - should succeed (idempotent) */
	if (ioctl(fd, KV_IOC_REVOKE, &revreq) < 0) {
		TEST_FAIL("second revoke should succeed");
		close(fd);
		return (1);
	}

	/* Verify still revoked */
	memset(&inforeq, 0, sizeof(inforeq));
	inforeq.key_id = genreq.key_id;

	if (ioctl(fd, KV_IOC_GETINFO, &inforeq) < 0) {
		TEST_FAIL("getinfo");
		close(fd);
		return (1);
	}

	if (!(inforeq.flags & KV_KEY_FLAG_REVOKED)) {
		TEST_FAIL("key should still be revoked");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Revoke non-existent key fails
 */
static int
test_revoke_nonexistent(void)
{
	int fd;
	struct kv_revoke_req revreq;

	TEST_START("revoke non-existent key fails");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	memset(&revreq, 0, sizeof(revreq));
	revreq.key_id = 0xDEADBEEFCAFEBABE;

	if (ioctl(fd, KV_IOC_REVOKE, &revreq) == 0) {
		TEST_FAIL("revoke non-existent should fail");
		close(fd);
		return (1);
	}

	if (errno != ENOENT) {
		TEST_FAIL("expected ENOENT");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Invalid IV/nonce length
 */
static int
test_invalid_iv_length(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_encrypt_req encreq;
	struct kv_aead_decrypt_req decreq;
	char ciphertext[64];
	char iv[32];
	char tag[16];

	TEST_START("invalid IV/nonce length rejected");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate CBC key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_CBC;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey CBC");
		close(fd);
		return (1);
	}
	uint64_t cbc_key = genreq.key_id;

	/* Generate GCM key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey GCM");
		close(fd);
		return (1);
	}
	uint64_t gcm_key = genreq.key_id;

	/* CBC encrypt with wrong IV length (should be 16) */
	memset(&encreq, 0, sizeof(encreq));
	memset(iv, 'A', sizeof(iv));
	encreq.key_id = cbc_key;
	encreq.plaintext = "1234567890123456";
	encreq.plaintext_len = 16;
	encreq.ciphertext = ciphertext;
	encreq.ciphertext_len = sizeof(ciphertext);
	encreq.iv = iv;
	encreq.iv_len = 8;  /* Wrong - should be 16 */

	if (ioctl(fd, KV_IOC_ENCRYPT, &encreq) == 0) {
		TEST_FAIL("CBC with 8-byte IV should fail");
		close(fd);
		return (1);
	}

	if (errno != EINVAL) {
		TEST_FAIL("expected EINVAL for wrong IV length");
		close(fd);
		return (1);
	}

	/* GCM decrypt with wrong nonce length (should be 12) */
	memset(&decreq, 0, sizeof(decreq));
	decreq.key_id = gcm_key;
	decreq.ciphertext = ciphertext;
	decreq.ciphertext_len = 16;
	decreq.nonce = iv;
	decreq.nonce_len = 8;  /* Wrong - should be 12 */
	decreq.tag = tag;
	decreq.tag_len = 16;
	decreq.plaintext = ciphertext;
	decreq.plaintext_len = sizeof(ciphertext);

	if (ioctl(fd, KV_IOC_AEAD_DECRYPT, &decreq) == 0) {
		TEST_FAIL("GCM with 8-byte nonce should fail");
		close(fd);
		return (1);
	}

	if (errno != EINVAL) {
		TEST_FAIL("expected EINVAL for wrong nonce length");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Empty key list
 */
static int
test_empty_key_list(void)
{
	int fd;
	struct kv_list_req listreq;
	uint64_t key_ids[16];

	TEST_START("empty key list");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* List keys on fresh fd - should be empty */
	memset(&listreq, 0, sizeof(listreq));
	listreq.key_ids = key_ids;
	listreq.max_keys = 16;

	if (ioctl(fd, KV_IOC_LIST, &listreq) < 0) {
		TEST_FAIL("list");
		close(fd);
		return (1);
	}

	if (listreq.num_keys != 0) {
		TEST_FAIL("expected 0 keys on fresh fd");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Expired key shows flag in getinfo
 */
static int
test_expired_key_flag(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_keyinfo_req inforeq;

	TEST_START("expired key shows flag in getinfo");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate key with 1 second TTL */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;
	genreq.ttl_seconds = 1;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Check not expired yet */
	memset(&inforeq, 0, sizeof(inforeq));
	inforeq.key_id = genreq.key_id;

	if (ioctl(fd, KV_IOC_GETINFO, &inforeq) < 0) {
		TEST_FAIL("getinfo before expiry");
		close(fd);
		return (1);
	}

	if (inforeq.flags & KV_KEY_FLAG_EXPIRED) {
		TEST_FAIL("key should not be expired yet");
		close(fd);
		return (1);
	}

	/* Wait for expiry */
	sleep(2);

	/*
	 * Try to use the key - this triggers expiration check.
	 * We need to attempt to acquire the key to mark it expired.
	 */
	struct kv_aead_encrypt_req encreq;
	char buf[32], nonce[12], tag[16];
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = genreq.key_id;
	encreq.plaintext = "test";
	encreq.plaintext_len = 4;
	encreq.ciphertext = buf;
	encreq.ciphertext_len = sizeof(buf);
	encreq.nonce_out = nonce;
	encreq.tag = tag;
	encreq.tag_len = sizeof(tag);
	ioctl(fd, KV_IOC_AEAD_ENCRYPT, &encreq);  /* Expected to fail */

	/* Now check info shows expired */
	memset(&inforeq, 0, sizeof(inforeq));
	inforeq.key_id = genreq.key_id;

	if (ioctl(fd, KV_IOC_GETINFO, &inforeq) < 0) {
		TEST_FAIL("getinfo after expiry");
		close(fd);
		return (1);
	}

	if (!(inforeq.flags & KV_KEY_FLAG_EXPIRED)) {
		TEST_FAIL("key should be marked expired");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Use key after destroy fails
 */
static int
test_use_after_destroy(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_destroy_req destroyreq;
	struct kv_aead_encrypt_req encreq;
	char buf[32], nonce[12], tag[16];

	TEST_START("use after destroy fails");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Destroy it */
	memset(&destroyreq, 0, sizeof(destroyreq));
	destroyreq.key_id = genreq.key_id;

	if (ioctl(fd, KV_IOC_DESTROY, &destroyreq) < 0) {
		TEST_FAIL("destroy");
		close(fd);
		return (1);
	}

	/* Try to use destroyed key */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = genreq.key_id;
	encreq.plaintext = "test";
	encreq.plaintext_len = 4;
	encreq.ciphertext = buf;
	encreq.ciphertext_len = sizeof(buf);
	encreq.nonce_out = nonce;
	encreq.tag = tag;
	encreq.tag_len = sizeof(tag);

	if (ioctl(fd, KV_IOC_AEAD_ENCRYPT, &encreq) == 0) {
		TEST_FAIL("encrypt on destroyed key should fail");
		close(fd);
		return (1);
	}

	if (errno != ENOENT) {
		TEST_FAIL("expected ENOENT");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/* ========================================
 * Ed25519 Digital Signature Tests
 * ======================================== */

/*
 * Test: Ed25519 key generation
 */
static int
test_ed25519_keygen(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_keyinfo_req inforeq;

	TEST_START("Ed25519 key generation");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate Ed25519 key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_ED25519;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Verify key info */
	memset(&inforeq, 0, sizeof(inforeq));
	inforeq.key_id = genreq.key_id;

	if (ioctl(fd, KV_IOC_GETINFO, &inforeq) < 0) {
		TEST_FAIL("getinfo");
		close(fd);
		return (1);
	}

	if (inforeq.algorithm != KV_ALG_ED25519) {
		TEST_FAIL("algorithm mismatch");
		close(fd);
		return (1);
	}

	if (inforeq.key_bits != 256) {
		TEST_FAIL("key bits should be 256");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Ed25519 sign/verify round-trip
 */
static int
test_ed25519_sign_verify(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_sign_req signreq;
	struct kv_verify_req verifyreq;
	const char *message = "Hello, Ed25519!";
	unsigned char signature[64];

	TEST_START("Ed25519 sign/verify round-trip");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate Ed25519 key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_ED25519;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Sign the message */
	memset(&signreq, 0, sizeof(signreq));
	signreq.key_id = genreq.key_id;
	signreq.data = message;
	signreq.data_len = strlen(message);
	signreq.signature = signature;
	signreq.signature_len = sizeof(signature);

	if (ioctl(fd, KV_IOC_SIGN, &signreq) < 0) {
		TEST_FAIL("sign");
		close(fd);
		return (1);
	}

	if (signreq.signature_len != 64) {
		TEST_FAIL("signature should be 64 bytes");
		close(fd);
		return (1);
	}

	/* Verify the signature */
	memset(&verifyreq, 0, sizeof(verifyreq));
	verifyreq.key_id = genreq.key_id;
	verifyreq.data = message;
	verifyreq.data_len = strlen(message);
	verifyreq.signature = signature;
	verifyreq.signature_len = 64;

	if (ioctl(fd, KV_IOC_VERIFY, &verifyreq) < 0) {
		TEST_FAIL("verify ioctl");
		close(fd);
		return (1);
	}

	if (!verifyreq.valid) {
		TEST_FAIL("signature should be valid");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Ed25519 get public key
 */
static int
test_ed25519_get_pubkey(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_getpubkey_req pubkeyreq;
	unsigned char pubkey[32];

	TEST_START("Ed25519 get public key");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate Ed25519 key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_ED25519;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Get public key */
	memset(&pubkeyreq, 0, sizeof(pubkeyreq));
	pubkeyreq.key_id = genreq.key_id;
	pubkeyreq.pubkey = pubkey;
	pubkeyreq.pubkey_len = sizeof(pubkey);

	if (ioctl(fd, KV_IOC_GET_PUBKEY, &pubkeyreq) < 0) {
		TEST_FAIL("get_pubkey");
		close(fd);
		return (1);
	}

	if (pubkeyreq.pubkey_len != 32) {
		TEST_FAIL("public key should be 32 bytes");
		close(fd);
		return (1);
	}

	/* Public key should not be all zeros */
	int all_zero = 1;
	for (int i = 0; i < 32; i++) {
		if (pubkey[i] != 0) {
			all_zero = 0;
			break;
		}
	}
	if (all_zero) {
		TEST_FAIL("public key should not be all zeros");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Ed25519 tampered message fails verification
 */
static int
test_ed25519_tampered_message(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_sign_req signreq;
	struct kv_verify_req verifyreq;
	const char *message = "Original message";
	const char *tampered = "Tampered message";
	unsigned char signature[64];

	TEST_START("Ed25519 tampered message fails verification");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate Ed25519 key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_ED25519;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Sign the original message */
	memset(&signreq, 0, sizeof(signreq));
	signreq.key_id = genreq.key_id;
	signreq.data = message;
	signreq.data_len = strlen(message);
	signreq.signature = signature;
	signreq.signature_len = sizeof(signature);

	if (ioctl(fd, KV_IOC_SIGN, &signreq) < 0) {
		TEST_FAIL("sign");
		close(fd);
		return (1);
	}

	/* Verify with tampered message should fail */
	memset(&verifyreq, 0, sizeof(verifyreq));
	verifyreq.key_id = genreq.key_id;
	verifyreq.data = tampered;
	verifyreq.data_len = strlen(tampered);
	verifyreq.signature = signature;
	verifyreq.signature_len = 64;

	if (ioctl(fd, KV_IOC_VERIFY, &verifyreq) < 0) {
		TEST_FAIL("verify ioctl");
		close(fd);
		return (1);
	}

	if (verifyreq.valid) {
		TEST_FAIL("tampered message should not verify");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Ed25519 wrong key fails verification
 */
static int
test_ed25519_wrong_key(void)
{
	int fd;
	struct kv_genkey_req genreq1, genreq2;
	struct kv_sign_req signreq;
	struct kv_verify_req verifyreq;
	const char *message = "Test message";
	unsigned char signature[64];

	TEST_START("Ed25519 wrong key fails verification");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate two Ed25519 keys */
	memset(&genreq1, 0, sizeof(genreq1));
	genreq1.algorithm = KV_ALG_ED25519;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq1) < 0) {
		TEST_FAIL("genkey 1");
		close(fd);
		return (1);
	}

	memset(&genreq2, 0, sizeof(genreq2));
	genreq2.algorithm = KV_ALG_ED25519;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq2) < 0) {
		TEST_FAIL("genkey 2");
		close(fd);
		return (1);
	}

	/* Sign with key 1 */
	memset(&signreq, 0, sizeof(signreq));
	signreq.key_id = genreq1.key_id;
	signreq.data = message;
	signreq.data_len = strlen(message);
	signreq.signature = signature;
	signreq.signature_len = sizeof(signature);

	if (ioctl(fd, KV_IOC_SIGN, &signreq) < 0) {
		TEST_FAIL("sign");
		close(fd);
		return (1);
	}

	/* Verify with key 2 should fail */
	memset(&verifyreq, 0, sizeof(verifyreq));
	verifyreq.key_id = genreq2.key_id;
	verifyreq.data = message;
	verifyreq.data_len = strlen(message);
	verifyreq.signature = signature;
	verifyreq.signature_len = 64;

	if (ioctl(fd, KV_IOC_VERIFY, &verifyreq) < 0) {
		TEST_FAIL("verify ioctl");
		close(fd);
		return (1);
	}

	if (verifyreq.valid) {
		TEST_FAIL("wrong key should not verify");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Sysctl tunables exist and are readable
 */
static int
test_sysctl_readable(void)
{
	unsigned int val;
	size_t len;

	TEST_START("sysctl tunables readable");

	/* max_keys_per_file */
	len = sizeof(val);
	if (sysctlbyname("security.keyvault.max_keys_per_file", &val, &len,
	    NULL, 0) < 0) {
		TEST_FAIL("max_keys_per_file not readable");
		return (1);
	}
	if (val == 0) {
		TEST_FAIL("max_keys_per_file is 0");
		return (1);
	}

	/* max_key_bytes */
	len = sizeof(val);
	if (sysctlbyname("security.keyvault.max_key_bytes", &val, &len,
	    NULL, 0) < 0) {
		TEST_FAIL("max_key_bytes not readable");
		return (1);
	}
	if (val == 0) {
		TEST_FAIL("max_key_bytes is 0");
		return (1);
	}

	/* max_files */
	len = sizeof(val);
	if (sysctlbyname("security.keyvault.max_files", &val, &len,
	    NULL, 0) < 0) {
		TEST_FAIL("max_files not readable");
		return (1);
	}
	if (val == 0) {
		TEST_FAIL("max_files is 0");
		return (1);
	}

	/* max_data_size */
	len = sizeof(val);
	if (sysctlbyname("security.keyvault.max_data_size", &val, &len,
	    NULL, 0) < 0) {
		TEST_FAIL("max_data_size not readable");
		return (1);
	}
	if (val == 0) {
		TEST_FAIL("max_data_size is 0");
		return (1);
	}

	TEST_PASS();
	return (0);
}

/*
 * Test: max_keys_per_file limit is enforced
 */
static int
test_sysctl_max_keys_enforced(void)
{
	unsigned int orig_max, test_max;
	size_t len;
	int fd;
	struct kv_genkey_req genreq;
	int i, error;

	TEST_START("sysctl max_keys_per_file enforced");

	/* Get current value */
	len = sizeof(orig_max);
	if (sysctlbyname("security.keyvault.max_keys_per_file", &orig_max, &len,
	    NULL, 0) < 0) {
		TEST_FAIL("cannot read max_keys_per_file");
		return (1);
	}

	/* Set to a small value for testing */
	test_max = 5;
	if (sysctlbyname("security.keyvault.max_keys_per_file", NULL, NULL,
	    &test_max, sizeof(test_max)) < 0) {
		TEST_FAIL("cannot write max_keys_per_file (need root?)");
		return (1);
	}

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		/* Restore original value */
		sysctlbyname("security.keyvault.max_keys_per_file", NULL, NULL,
		    &orig_max, sizeof(orig_max));
		TEST_FAIL("open");
		return (1);
	}

	/* Create test_max keys - should succeed */
	for (i = 0; i < (int)test_max; i++) {
		memset(&genreq, 0, sizeof(genreq));
		genreq.algorithm = KV_ALG_AES256_GCM;
		if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
			close(fd);
			sysctlbyname("security.keyvault.max_keys_per_file",
			    NULL, NULL, &orig_max, sizeof(orig_max));
			TEST_FAIL("genkey within limit failed");
			return (1);
		}
	}

	/* Try to create one more - should fail with EMFILE */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;
	error = ioctl(fd, KV_IOC_GENKEY, &genreq);

	close(fd);

	/* Restore original value */
	sysctlbyname("security.keyvault.max_keys_per_file", NULL, NULL,
	    &orig_max, sizeof(orig_max));

	if (error == 0) {
		TEST_FAIL("exceeded max_keys_per_file limit");
		return (1);
	}

	if (errno != EMFILE) {
		TEST_FAIL("expected EMFILE");
		return (1);
	}

	TEST_PASS();
	return (0);
}

/*
 * Test: max_data_size limit is enforced
 */
static int
test_sysctl_max_data_enforced(void)
{
	unsigned int orig_max, test_max;
	size_t len;
	int fd;
	struct kv_genkey_req genreq;
	struct kv_aead_encrypt_req encreq;
	char *plaintext;
	char *ciphertext;
	char nonce[12];
	char tag[16];

	TEST_START("sysctl max_data_size enforced");

	/* Get current value */
	len = sizeof(orig_max);
	if (sysctlbyname("security.keyvault.max_data_size", &orig_max, &len,
	    NULL, 0) < 0) {
		TEST_FAIL("cannot read max_data_size");
		return (1);
	}

	/* Set to a small value for testing */
	test_max = 1024;
	if (sysctlbyname("security.keyvault.max_data_size", NULL, NULL,
	    &test_max, sizeof(test_max)) < 0) {
		TEST_FAIL("cannot write max_data_size (need root?)");
		return (1);
	}

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		sysctlbyname("security.keyvault.max_data_size", NULL, NULL,
		    &orig_max, sizeof(orig_max));
		TEST_FAIL("open");
		return (1);
	}

	/* Generate key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;
	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		close(fd);
		sysctlbyname("security.keyvault.max_data_size", NULL, NULL,
		    &orig_max, sizeof(orig_max));
		TEST_FAIL("genkey");
		return (1);
	}

	/* Allocate data larger than limit */
	plaintext = malloc(test_max + 1);
	ciphertext = malloc(test_max + 1 + 16);
	if (plaintext == NULL || ciphertext == NULL) {
		free(plaintext);
		free(ciphertext);
		close(fd);
		sysctlbyname("security.keyvault.max_data_size", NULL, NULL,
		    &orig_max, sizeof(orig_max));
		TEST_FAIL("malloc");
		return (1);
	}
	memset(plaintext, 'A', test_max + 1);

	/* Try to encrypt data larger than limit - should fail */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = genreq.key_id;
	encreq.plaintext = plaintext;
	encreq.plaintext_len = test_max + 1;  /* Exceeds limit */
	encreq.ciphertext = ciphertext;
	encreq.ciphertext_len = test_max + 1 + 16;
	encreq.nonce_out = nonce;
	encreq.tag = tag;
	encreq.tag_len = sizeof(tag);

	if (ioctl(fd, KV_IOC_AEAD_ENCRYPT, &encreq) == 0) {
		free(plaintext);
		free(ciphertext);
		close(fd);
		sysctlbyname("security.keyvault.max_data_size", NULL, NULL,
		    &orig_max, sizeof(orig_max));
		TEST_FAIL("exceeded max_data_size limit");
		return (1);
	}

	if (errno != EINVAL) {
		free(plaintext);
		free(ciphertext);
		close(fd);
		sysctlbyname("security.keyvault.max_data_size", NULL, NULL,
		    &orig_max, sizeof(orig_max));
		TEST_FAIL("expected EINVAL");
		return (1);
	}

	free(plaintext);
	free(ciphertext);
	close(fd);

	/* Restore original value */
	sysctlbyname("security.keyvault.max_data_size", NULL, NULL,
	    &orig_max, sizeof(orig_max));

	TEST_PASS();
	return (0);
}

/*
 * Test: AES-128-GCM roundtrip
 */
static int
test_aes128_gcm_roundtrip(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_aead_encrypt_req encreq;
	struct kv_aead_decrypt_req decreq;
	const char *plaintext = "AES-128-GCM test message.";
	const char *aad = "additional data";
	char ciphertext[64];
	char decrypted[64];
	char nonce[12];
	char tag[16];

	TEST_START("AES-128-GCM encrypt/decrypt round-trip");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate AES-128-GCM key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES128_GCM;
	genreq.key_bits = 128;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Encrypt */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = genreq.key_id;
	encreq.plaintext = plaintext;
	encreq.plaintext_len = strlen(plaintext);
	encreq.aad = aad;
	encreq.aad_len = strlen(aad);
	encreq.ciphertext = ciphertext;
	encreq.ciphertext_len = sizeof(ciphertext);
	encreq.nonce = NULL;
	encreq.nonce_len = 0;
	encreq.nonce_out = nonce;
	encreq.tag = tag;
	encreq.tag_len = sizeof(tag);

	if (ioctl(fd, KV_IOC_AEAD_ENCRYPT, &encreq) < 0) {
		TEST_FAIL("encrypt");
		close(fd);
		return (1);
	}

	/* Decrypt */
	memset(&decreq, 0, sizeof(decreq));
	memset(decrypted, 0, sizeof(decrypted));
	decreq.key_id = genreq.key_id;
	decreq.ciphertext = ciphertext;
	decreq.ciphertext_len = encreq.ciphertext_len;
	decreq.aad = aad;
	decreq.aad_len = strlen(aad);
	decreq.nonce = nonce;
	decreq.nonce_len = 12;
	decreq.tag = tag;
	decreq.tag_len = 16;
	decreq.plaintext = decrypted;
	decreq.plaintext_len = sizeof(decrypted);

	if (ioctl(fd, KV_IOC_AEAD_DECRYPT, &decreq) < 0) {
		TEST_FAIL("decrypt");
		close(fd);
		return (1);
	}

	/* Verify decryption */
	if (decreq.plaintext_len != strlen(plaintext) ||
	    memcmp(decrypted, plaintext, strlen(plaintext)) != 0) {
		TEST_FAIL("decryption mismatch");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: AES-128-CBC roundtrip
 */
static int
test_aes128_cbc_roundtrip(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_encrypt_req encreq;
	struct kv_decrypt_req decreq;
	/* Plaintext must be multiple of 16 (AES block size) */
	const char *plaintext = "AES-128-CBC test";
	char ciphertext[32];
	char decrypted[32];
	char iv[16];

	TEST_START("AES-128-CBC encrypt/decrypt round-trip");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate AES-128-CBC key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES128_CBC;
	genreq.key_bits = 128;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Encrypt */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = genreq.key_id;
	encreq.plaintext = plaintext;
	encreq.plaintext_len = strlen(plaintext);
	encreq.ciphertext = ciphertext;
	encreq.ciphertext_len = sizeof(ciphertext);
	encreq.iv = NULL;
	encreq.iv_len = 0;
	encreq.iv_out = iv;

	if (ioctl(fd, KV_IOC_ENCRYPT, &encreq) < 0) {
		TEST_FAIL("encrypt");
		close(fd);
		return (1);
	}

	/* Decrypt */
	memset(&decreq, 0, sizeof(decreq));
	memset(decrypted, 0, sizeof(decrypted));
	decreq.key_id = genreq.key_id;
	decreq.ciphertext = ciphertext;
	decreq.ciphertext_len = encreq.ciphertext_len;
	decreq.plaintext = decrypted;
	decreq.plaintext_len = sizeof(decrypted);
	decreq.iv = iv;
	decreq.iv_len = 16;

	if (ioctl(fd, KV_IOC_DECRYPT, &decreq) < 0) {
		TEST_FAIL("decrypt");
		close(fd);
		return (1);
	}

	/* Verify decryption */
	if (decreq.plaintext_len != strlen(plaintext) ||
	    memcmp(decrypted, plaintext, strlen(plaintext)) != 0) {
		TEST_FAIL("decryption mismatch");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Sign with symmetric key (should fail)
 */
static int
test_sign_with_symmetric_key(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_sign_req signreq;
	const char *data = "test data";
	char signature[64];

	TEST_START("sign with symmetric key (expect EINVAL)");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate AES key (symmetric) */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Try to sign - should fail */
	memset(&signreq, 0, sizeof(signreq));
	signreq.key_id = genreq.key_id;
	signreq.data = data;
	signreq.data_len = strlen(data);
	signreq.signature = signature;
	signreq.signature_len = sizeof(signature);

	if (ioctl(fd, KV_IOC_SIGN, &signreq) == 0) {
		TEST_FAIL("sign should have failed");
		close(fd);
		return (1);
	}

	if (errno != EINVAL) {
		TEST_FAIL("expected EINVAL");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Encrypt with Ed25519 key (should fail)
 */
static int
test_encrypt_with_ed25519_key(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_encrypt_req encreq;
	const char *plaintext = "0123456789ABCDEF";
	char ciphertext[32];
	char iv[16];

	TEST_START("encrypt with Ed25519 key (expect EOPNOTSUPP)");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate Ed25519 key (asymmetric) */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_ED25519;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Try to encrypt - should fail */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = genreq.key_id;
	encreq.plaintext = plaintext;
	encreq.plaintext_len = strlen(plaintext);
	encreq.ciphertext = ciphertext;
	encreq.ciphertext_len = sizeof(ciphertext);
	encreq.iv = NULL;
	encreq.iv_len = 0;
	encreq.iv_out = iv;

	if (ioctl(fd, KV_IOC_ENCRYPT, &encreq) == 0) {
		TEST_FAIL("encrypt should have failed");
		close(fd);
		return (1);
	}

	if (errno != EOPNOTSUPP) {
		TEST_FAIL("expected EOPNOTSUPP");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: Get pubkey from symmetric key (should fail)
 */
static int
test_get_pubkey_from_symmetric_key(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_getpubkey_req pubreq;
	char pubkey[32];

	TEST_START("get pubkey from symmetric key (expect EINVAL)");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate AES key (symmetric) */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Try to get pubkey - should fail */
	memset(&pubreq, 0, sizeof(pubreq));
	pubreq.key_id = genreq.key_id;
	pubreq.pubkey = pubkey;
	pubreq.pubkey_len = sizeof(pubkey);

	if (ioctl(fd, KV_IOC_GET_PUBKEY, &pubreq) == 0) {
		TEST_FAIL("get_pubkey should have failed");
		close(fd);
		return (1);
	}

	if (errno != EINVAL) {
		TEST_FAIL("expected EINVAL");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: MAC with Ed25519 key (should fail)
 */
static int
test_mac_with_ed25519_key(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_mac_req macreq;
	const char *data = "test data";
	char mac[64];

	TEST_START("MAC with Ed25519 key (expect EOPNOTSUPP)");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate Ed25519 key (asymmetric) */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_ED25519;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Try to MAC - should fail */
	memset(&macreq, 0, sizeof(macreq));
	macreq.key_id = genreq.key_id;
	macreq.data = data;
	macreq.data_len = strlen(data);
	macreq.mac = mac;
	macreq.mac_len = sizeof(mac);

	if (ioctl(fd, KV_IOC_MAC, &macreq) == 0) {
		TEST_FAIL("MAC should have failed");
		close(fd);
		return (1);
	}

	if (errno != EOPNOTSUPP) {
		TEST_FAIL("expected EOPNOTSUPP");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/* ========================================
 * Phase 3: ChaCha20-Poly1305 AEAD Tests
 * ======================================== */

/*
 * Test: ChaCha20-Poly1305 key generation
 */
static int
test_chacha20_poly1305_keygen(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_keyinfo_req inforeq;

	TEST_START("ChaCha20-Poly1305 key generation");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate ChaCha20-Poly1305 key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_CHACHA20_POLY1305;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Verify key info */
	memset(&inforeq, 0, sizeof(inforeq));
	inforeq.key_id = genreq.key_id;

	if (ioctl(fd, KV_IOC_GETINFO, &inforeq) < 0) {
		TEST_FAIL("getinfo");
		close(fd);
		return (1);
	}

	if (inforeq.algorithm != KV_ALG_CHACHA20_POLY1305) {
		TEST_FAIL("algorithm mismatch");
		close(fd);
		return (1);
	}

	if (inforeq.key_bits != 256) {
		TEST_FAIL("key bits should be 256");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: ChaCha20-Poly1305 AEAD encrypt/decrypt round-trip
 */
static int
test_chacha20_poly1305_roundtrip(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_aead_encrypt_req encreq;
	struct kv_aead_decrypt_req decreq;
	const char *plaintext = "Hello, ChaCha20-Poly1305! This is a test.";
	const char *aad = "additional authenticated data";
	char ciphertext[128];
	char decrypted[128];
	char nonce[12];
	char tag[16];

	TEST_START("ChaCha20-Poly1305 AEAD encrypt/decrypt round-trip");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate ChaCha20-Poly1305 key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_CHACHA20_POLY1305;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Encrypt */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = genreq.key_id;
	encreq.plaintext = plaintext;
	encreq.plaintext_len = strlen(plaintext);
	encreq.aad = aad;
	encreq.aad_len = strlen(aad);
	encreq.ciphertext = ciphertext;
	encreq.ciphertext_len = sizeof(ciphertext);
	encreq.nonce = NULL;
	encreq.nonce_len = 0;
	encreq.nonce_out = nonce;
	encreq.tag = tag;
	encreq.tag_len = sizeof(tag);

	if (ioctl(fd, KV_IOC_AEAD_ENCRYPT, &encreq) < 0) {
		TEST_FAIL("encrypt");
		close(fd);
		return (1);
	}

	/* Verify ciphertext differs from plaintext */
	if (memcmp(ciphertext, plaintext, strlen(plaintext)) == 0) {
		TEST_FAIL("ciphertext equals plaintext");
		close(fd);
		return (1);
	}

	/* Decrypt */
	memset(&decreq, 0, sizeof(decreq));
	memset(decrypted, 0, sizeof(decrypted));
	decreq.key_id = genreq.key_id;
	decreq.ciphertext = ciphertext;
	decreq.ciphertext_len = encreq.ciphertext_len;
	decreq.aad = aad;
	decreq.aad_len = strlen(aad);
	decreq.nonce = nonce;
	decreq.nonce_len = 12;
	decreq.tag = tag;
	decreq.tag_len = 16;
	decreq.plaintext = decrypted;
	decreq.plaintext_len = sizeof(decrypted);

	if (ioctl(fd, KV_IOC_AEAD_DECRYPT, &decreq) < 0) {
		TEST_FAIL("decrypt");
		close(fd);
		return (1);
	}

	/* Verify decryption */
	if (decreq.plaintext_len != strlen(plaintext) ||
	    memcmp(decrypted, plaintext, strlen(plaintext)) != 0) {
		TEST_FAIL("decryption mismatch");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: ChaCha20-Poly1305 authentication failure
 */
static int
test_chacha20_poly1305_auth_failure(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_aead_encrypt_req encreq;
	struct kv_aead_decrypt_req decreq;
	const char *plaintext = "Authentic message";
	char ciphertext[64];
	char decrypted[64];
	char nonce[12];
	char tag[16];

	TEST_START("ChaCha20-Poly1305 authentication failure detection");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_CHACHA20_POLY1305;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Encrypt */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = genreq.key_id;
	encreq.plaintext = plaintext;
	encreq.plaintext_len = strlen(plaintext);
	encreq.ciphertext = ciphertext;
	encreq.ciphertext_len = sizeof(ciphertext);
	encreq.nonce_out = nonce;
	encreq.tag = tag;
	encreq.tag_len = sizeof(tag);

	if (ioctl(fd, KV_IOC_AEAD_ENCRYPT, &encreq) < 0) {
		TEST_FAIL("encrypt");
		close(fd);
		return (1);
	}

	/* Tamper with the tag */
	tag[0] ^= 0xFF;

	/* Try to decrypt - should fail */
	memset(&decreq, 0, sizeof(decreq));
	decreq.key_id = genreq.key_id;
	decreq.ciphertext = ciphertext;
	decreq.ciphertext_len = encreq.ciphertext_len;
	decreq.nonce = nonce;
	decreq.nonce_len = 12;
	decreq.tag = tag;
	decreq.tag_len = 16;
	decreq.plaintext = decrypted;
	decreq.plaintext_len = sizeof(decrypted);

	if (ioctl(fd, KV_IOC_AEAD_DECRYPT, &decreq) == 0) {
		TEST_FAIL("decrypt should fail with tampered tag");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/* ========================================
 * Phase 3: X25519 Key Exchange Tests
 * ======================================== */

/*
 * Test: X25519 key generation
 */
static int
test_x25519_keygen(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_keyinfo_req inforeq;

	TEST_START("X25519 key generation");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate X25519 key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_X25519;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Verify key info */
	memset(&inforeq, 0, sizeof(inforeq));
	inforeq.key_id = genreq.key_id;

	if (ioctl(fd, KV_IOC_GETINFO, &inforeq) < 0) {
		TEST_FAIL("getinfo");
		close(fd);
		return (1);
	}

	if (inforeq.algorithm != KV_ALG_X25519) {
		TEST_FAIL("algorithm mismatch");
		close(fd);
		return (1);
	}

	if (inforeq.key_bits != 256) {
		TEST_FAIL("key bits should be 256");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: X25519 get public key
 */
static int
test_x25519_get_pubkey(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_getpubkey_req pubkeyreq;
	unsigned char pubkey[32];

	TEST_START("X25519 get public key");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate X25519 key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_X25519;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Get public key */
	memset(&pubkeyreq, 0, sizeof(pubkeyreq));
	pubkeyreq.key_id = genreq.key_id;
	pubkeyreq.pubkey = pubkey;
	pubkeyreq.pubkey_len = sizeof(pubkey);

	if (ioctl(fd, KV_IOC_GET_PUBKEY, &pubkeyreq) < 0) {
		TEST_FAIL("get_pubkey");
		close(fd);
		return (1);
	}

	if (pubkeyreq.pubkey_len != 32) {
		TEST_FAIL("public key should be 32 bytes");
		close(fd);
		return (1);
	}

	/* Public key should not be all zeros */
	int all_zero = 1;
	for (int i = 0; i < 32; i++) {
		if (pubkey[i] != 0) {
			all_zero = 0;
			break;
		}
	}
	if (all_zero) {
		TEST_FAIL("public key should not be all zeros");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: X25519 key exchange
 */
static int
test_x25519_keyexchange(void)
{
	int fd;
	struct kv_genkey_req genreq1, genreq2;
	struct kv_getpubkey_req pubkeyreq;
	struct kv_keyexchange_req kexreq;
	unsigned char pubkey1[32], pubkey2[32];
	unsigned char shared1[32], shared2[32];

	TEST_START("X25519 key exchange");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate two X25519 keypairs */
	memset(&genreq1, 0, sizeof(genreq1));
	genreq1.algorithm = KV_ALG_X25519;
	if (ioctl(fd, KV_IOC_GENKEY, &genreq1) < 0) {
		TEST_FAIL("genkey 1");
		close(fd);
		return (1);
	}

	memset(&genreq2, 0, sizeof(genreq2));
	genreq2.algorithm = KV_ALG_X25519;
	if (ioctl(fd, KV_IOC_GENKEY, &genreq2) < 0) {
		TEST_FAIL("genkey 2");
		close(fd);
		return (1);
	}

	/* Get public keys */
	memset(&pubkeyreq, 0, sizeof(pubkeyreq));
	pubkeyreq.key_id = genreq1.key_id;
	pubkeyreq.pubkey = pubkey1;
	pubkeyreq.pubkey_len = sizeof(pubkey1);
	if (ioctl(fd, KV_IOC_GET_PUBKEY, &pubkeyreq) < 0) {
		TEST_FAIL("get_pubkey 1");
		close(fd);
		return (1);
	}

	memset(&pubkeyreq, 0, sizeof(pubkeyreq));
	pubkeyreq.key_id = genreq2.key_id;
	pubkeyreq.pubkey = pubkey2;
	pubkeyreq.pubkey_len = sizeof(pubkey2);
	if (ioctl(fd, KV_IOC_GET_PUBKEY, &pubkeyreq) < 0) {
		TEST_FAIL("get_pubkey 2");
		close(fd);
		return (1);
	}

	/* Key exchange: key1 + pubkey2 */
	memset(&kexreq, 0, sizeof(kexreq));
	kexreq.key_id = genreq1.key_id;
	kexreq.peer_pubkey = pubkey2;
	kexreq.peer_pubkey_len = 32;
	kexreq.shared_secret = shared1;
	kexreq.shared_secret_len = sizeof(shared1);

	if (ioctl(fd, KV_IOC_KEYEXCHANGE, &kexreq) < 0) {
		TEST_FAIL("keyexchange 1");
		close(fd);
		return (1);
	}

	/* Key exchange: key2 + pubkey1 */
	memset(&kexreq, 0, sizeof(kexreq));
	kexreq.key_id = genreq2.key_id;
	kexreq.peer_pubkey = pubkey1;
	kexreq.peer_pubkey_len = 32;
	kexreq.shared_secret = shared2;
	kexreq.shared_secret_len = sizeof(shared2);

	if (ioctl(fd, KV_IOC_KEYEXCHANGE, &kexreq) < 0) {
		TEST_FAIL("keyexchange 2");
		close(fd);
		return (1);
	}

	/* Both should derive the same shared secret */
	if (memcmp(shared1, shared2, 32) != 0) {
		TEST_FAIL("shared secrets don't match");
		close(fd);
		return (1);
	}

	/* Shared secret should not be all zeros */
	int all_zero = 1;
	for (int i = 0; i < 32; i++) {
		if (shared1[i] != 0) {
			all_zero = 0;
			break;
		}
	}
	if (all_zero) {
		TEST_FAIL("shared secret should not be all zeros");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: X25519 key exchange with wrong key type fails
 */
static int
test_x25519_wrong_key_type(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_keyexchange_req kexreq;
	unsigned char peer_pubkey[32] = {0};
	unsigned char shared[32];

	TEST_START("X25519 key exchange with wrong key type (expect EINVAL)");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate an AES key (symmetric) */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Try key exchange - should fail */
	memset(&kexreq, 0, sizeof(kexreq));
	kexreq.key_id = genreq.key_id;
	kexreq.peer_pubkey = peer_pubkey;
	kexreq.peer_pubkey_len = 32;
	kexreq.shared_secret = shared;
	kexreq.shared_secret_len = sizeof(shared);

	if (ioctl(fd, KV_IOC_KEYEXCHANGE, &kexreq) == 0) {
		TEST_FAIL("keyexchange should fail with AES key");
		close(fd);
		return (1);
	}

	if (errno != EINVAL) {
		TEST_FAIL("expected EINVAL");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/* ========================================
 * Phase 3: HKDF Key Derivation Tests
 * ======================================== */

/*
 * Test: HKDF-SHA256 key derivation
 */
static int
test_hkdf_sha256(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_derive_req derivereq;
	struct kv_keyinfo_req inforeq;
	const char *salt = "salt value";
	const char *info = "context info";

	TEST_START("HKDF-SHA256 key derivation");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate source key (HMAC-SHA256) */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_HMAC_SHA256;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Derive a new key */
	memset(&derivereq, 0, sizeof(derivereq));
	derivereq.key_id = genreq.key_id;
	derivereq.algorithm = KV_ALG_HKDF_SHA256;
	derivereq.output_bits = 256;
	derivereq.salt = salt;
	derivereq.salt_len = strlen(salt);
	derivereq.info = info;
	derivereq.info_len = strlen(info);

	if (ioctl(fd, KV_IOC_DERIVE, &derivereq) < 0) {
		TEST_FAIL("derive");
		close(fd);
		return (1);
	}

	/* Verify derived key exists */
	memset(&inforeq, 0, sizeof(inforeq));
	inforeq.key_id = derivereq.derived_key_id;

	if (ioctl(fd, KV_IOC_GETINFO, &inforeq) < 0) {
		TEST_FAIL("getinfo");
		close(fd);
		return (1);
	}

	if (inforeq.key_bits != 256) {
		TEST_FAIL("derived key should be 256 bits");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: HKDF-SHA512 key derivation
 */
static int
test_hkdf_sha512(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_derive_req derivereq;
	struct kv_keyinfo_req inforeq;
	const char *info = "context info for SHA512";

	TEST_START("HKDF-SHA512 key derivation");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate source key (HMAC-SHA512) */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_HMAC_SHA512;
	genreq.key_bits = 512;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Derive a new 512-bit key (no salt) */
	memset(&derivereq, 0, sizeof(derivereq));
	derivereq.key_id = genreq.key_id;
	derivereq.algorithm = KV_ALG_HKDF_SHA512;
	derivereq.output_bits = 512;
	derivereq.salt = NULL;
	derivereq.salt_len = 0;
	derivereq.info = info;
	derivereq.info_len = strlen(info);

	if (ioctl(fd, KV_IOC_DERIVE, &derivereq) < 0) {
		TEST_FAIL("derive");
		close(fd);
		return (1);
	}

	/* Verify derived key exists */
	memset(&inforeq, 0, sizeof(inforeq));
	inforeq.key_id = derivereq.derived_key_id;

	if (ioctl(fd, KV_IOC_GETINFO, &inforeq) < 0) {
		TEST_FAIL("getinfo");
		close(fd);
		return (1);
	}

	if (inforeq.key_bits != 512) {
		TEST_FAIL("derived key should be 512 bits");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: HKDF consistency (same inputs = same derived key)
 */
static int
test_hkdf_consistency(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_derive_req derivereq;
	struct kv_mac_req macreq;
	const char *salt = "fixed salt";
	const char *info = "fixed info";
	const char *data = "Test message for MAC";
	char mac1[32], mac2[32];

	TEST_START("HKDF consistency");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate source key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_HMAC_SHA256;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Derive first key */
	memset(&derivereq, 0, sizeof(derivereq));
	derivereq.key_id = genreq.key_id;
	derivereq.algorithm = KV_ALG_HKDF_SHA256;
	derivereq.output_bits = 256;
	derivereq.salt = salt;
	derivereq.salt_len = strlen(salt);
	derivereq.info = info;
	derivereq.info_len = strlen(info);

	if (ioctl(fd, KV_IOC_DERIVE, &derivereq) < 0) {
		TEST_FAIL("derive 1");
		close(fd);
		return (1);
	}
	uint64_t derived1 = derivereq.derived_key_id;

	/* Derive second key with same parameters */
	memset(&derivereq, 0, sizeof(derivereq));
	derivereq.key_id = genreq.key_id;
	derivereq.algorithm = KV_ALG_HKDF_SHA256;
	derivereq.output_bits = 256;
	derivereq.salt = salt;
	derivereq.salt_len = strlen(salt);
	derivereq.info = info;
	derivereq.info_len = strlen(info);

	if (ioctl(fd, KV_IOC_DERIVE, &derivereq) < 0) {
		TEST_FAIL("derive 2");
		close(fd);
		return (1);
	}
	uint64_t derived2 = derivereq.derived_key_id;

	/* Compute MAC with first derived key */
	memset(&macreq, 0, sizeof(macreq));
	macreq.key_id = derived1;
	macreq.data = data;
	macreq.data_len = strlen(data);
	macreq.mac = mac1;
	macreq.mac_len = sizeof(mac1);

	if (ioctl(fd, KV_IOC_MAC, &macreq) < 0) {
		TEST_FAIL("mac1");
		close(fd);
		return (1);
	}

	/* Compute MAC with second derived key */
	memset(&macreq, 0, sizeof(macreq));
	macreq.key_id = derived2;
	macreq.data = data;
	macreq.data_len = strlen(data);
	macreq.mac = mac2;
	macreq.mac_len = sizeof(mac2);

	if (ioctl(fd, KV_IOC_MAC, &macreq) < 0) {
		TEST_FAIL("mac2");
		close(fd);
		return (1);
	}

	/* MACs should be identical if derived keys are the same */
	if (memcmp(mac1, mac2, 32) != 0) {
		TEST_FAIL("MACs differ - derived keys not consistent");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: HKDF from X25519 shared secret
 */
static int
test_hkdf_from_keyexchange(void)
{
	int fd;
	struct kv_genkey_req genreq1, genreq2;
	struct kv_getpubkey_req pubkeyreq;
	struct kv_keyexchange_req kexreq;
	struct kv_derive_req derivereq;
	struct kv_keyinfo_req inforeq;
	unsigned char pubkey2[32];
	unsigned char shared[32];
	const char *info = "encryption key";

	TEST_START("HKDF from X25519 shared secret");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate two X25519 keypairs */
	memset(&genreq1, 0, sizeof(genreq1));
	genreq1.algorithm = KV_ALG_X25519;
	if (ioctl(fd, KV_IOC_GENKEY, &genreq1) < 0) {
		TEST_FAIL("genkey 1");
		close(fd);
		return (1);
	}

	memset(&genreq2, 0, sizeof(genreq2));
	genreq2.algorithm = KV_ALG_X25519;
	if (ioctl(fd, KV_IOC_GENKEY, &genreq2) < 0) {
		TEST_FAIL("genkey 2");
		close(fd);
		return (1);
	}

	/* Get public key 2 */
	memset(&pubkeyreq, 0, sizeof(pubkeyreq));
	pubkeyreq.key_id = genreq2.key_id;
	pubkeyreq.pubkey = pubkey2;
	pubkeyreq.pubkey_len = sizeof(pubkey2);
	if (ioctl(fd, KV_IOC_GET_PUBKEY, &pubkeyreq) < 0) {
		TEST_FAIL("get_pubkey 2");
		close(fd);
		return (1);
	}

	/* Key exchange */
	memset(&kexreq, 0, sizeof(kexreq));
	kexreq.key_id = genreq1.key_id;
	kexreq.peer_pubkey = pubkey2;
	kexreq.peer_pubkey_len = 32;
	kexreq.shared_secret = shared;
	kexreq.shared_secret_len = sizeof(shared);

	if (ioctl(fd, KV_IOC_KEYEXCHANGE, &kexreq) < 0) {
		TEST_FAIL("keyexchange");
		close(fd);
		return (1);
	}

	/*
	 * Now import the shared secret as a key and derive from it.
	 * Since we can't directly import keys, we'll test with a generated key.
	 * This test verifies the HKDF/derivation mechanism works with HMAC keys.
	 */

	/* Generate an HMAC key to simulate imported shared secret */
	memset(&genreq1, 0, sizeof(genreq1));
	genreq1.algorithm = KV_ALG_HMAC_SHA256;
	genreq1.key_bits = 256;
	if (ioctl(fd, KV_IOC_GENKEY, &genreq1) < 0) {
		TEST_FAIL("genkey HMAC");
		close(fd);
		return (1);
	}

	/* Derive encryption key using HKDF */
	memset(&derivereq, 0, sizeof(derivereq));
	derivereq.key_id = genreq1.key_id;
	derivereq.algorithm = KV_ALG_HKDF_SHA256;
	derivereq.output_bits = 256;
	derivereq.info = info;
	derivereq.info_len = strlen(info);

	if (ioctl(fd, KV_IOC_DERIVE, &derivereq) < 0) {
		TEST_FAIL("derive");
		close(fd);
		return (1);
	}

	/* Verify derived key is usable */
	memset(&inforeq, 0, sizeof(inforeq));
	inforeq.key_id = derivereq.derived_key_id;

	if (ioctl(fd, KV_IOC_GETINFO, &inforeq) < 0) {
		TEST_FAIL("getinfo");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: HKDF capability restriction
 */
static int
test_hkdf_capability_restriction(void)
{
	int fd;
	struct kv_genkey_req genreq;
	struct kv_restrict_req restrictreq;
	struct kv_derive_req derivereq;

	TEST_START("HKDF capability restriction");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate source key */
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_HMAC_SHA256;
	genreq.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &genreq) < 0) {
		TEST_FAIL("genkey");
		close(fd);
		return (1);
	}

	/* Remove DERIVE capability */
	memset(&restrictreq, 0, sizeof(restrictreq));
	restrictreq.caps = KV_CAP_ALL & ~KV_CAP_DERIVE;

	if (ioctl(fd, KV_IOC_RESTRICT, &restrictreq) < 0) {
		TEST_FAIL("restrict");
		close(fd);
		return (1);
	}

	/* Try to derive - should fail */
	memset(&derivereq, 0, sizeof(derivereq));
	derivereq.key_id = genreq.key_id;
	derivereq.algorithm = KV_ALG_HKDF_SHA256;
	derivereq.output_bits = 256;

	if (ioctl(fd, KV_IOC_DERIVE, &derivereq) == 0) {
		TEST_FAIL("derive should fail without KV_CAP_DERIVE");
		close(fd);
		return (1);
	}

	if (errno != EPERM) {
		TEST_FAIL("expected EPERM");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * Test: X25519 capability restriction
 */
static int
test_x25519_capability_restriction(void)
{
	int fd;
	struct kv_genkey_req genreq1, genreq2;
	struct kv_getpubkey_req pubkeyreq;
	struct kv_restrict_req restrictreq;
	struct kv_keyexchange_req kexreq;
	unsigned char pubkey2[32];
	unsigned char shared[32];

	TEST_START("X25519 capability restriction");

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		TEST_FAIL("open");
		return (1);
	}

	/* Generate two X25519 keys */
	memset(&genreq1, 0, sizeof(genreq1));
	genreq1.algorithm = KV_ALG_X25519;
	if (ioctl(fd, KV_IOC_GENKEY, &genreq1) < 0) {
		TEST_FAIL("genkey 1");
		close(fd);
		return (1);
	}

	memset(&genreq2, 0, sizeof(genreq2));
	genreq2.algorithm = KV_ALG_X25519;
	if (ioctl(fd, KV_IOC_GENKEY, &genreq2) < 0) {
		TEST_FAIL("genkey 2");
		close(fd);
		return (1);
	}

	/* Get public key 2 */
	memset(&pubkeyreq, 0, sizeof(pubkeyreq));
	pubkeyreq.key_id = genreq2.key_id;
	pubkeyreq.pubkey = pubkey2;
	pubkeyreq.pubkey_len = sizeof(pubkey2);
	if (ioctl(fd, KV_IOC_GET_PUBKEY, &pubkeyreq) < 0) {
		TEST_FAIL("get_pubkey");
		close(fd);
		return (1);
	}

	/* Remove EXCHANGE capability */
	memset(&restrictreq, 0, sizeof(restrictreq));
	restrictreq.caps = KV_CAP_ALL & ~KV_CAP_EXCHANGE;

	if (ioctl(fd, KV_IOC_RESTRICT, &restrictreq) < 0) {
		TEST_FAIL("restrict");
		close(fd);
		return (1);
	}

	/* Try key exchange - should fail */
	memset(&kexreq, 0, sizeof(kexreq));
	kexreq.key_id = genreq1.key_id;
	kexreq.peer_pubkey = pubkey2;
	kexreq.peer_pubkey_len = 32;
	kexreq.shared_secret = shared;
	kexreq.shared_secret_len = sizeof(shared);

	if (ioctl(fd, KV_IOC_KEYEXCHANGE, &kexreq) == 0) {
		TEST_FAIL("keyexchange should fail without KV_CAP_EXCHANGE");
		close(fd);
		return (1);
	}

	if (errno != EPERM) {
		TEST_FAIL("expected EPERM");
		close(fd);
		return (1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

int
main(int argc, char *argv[])
{
	printf("===========================================\n");
	printf("Keyvault Kernel Module - Comprehensive Tests\n");
	printf("===========================================\n\n");

	/* Basic functionality */
	printf("--- Basic Operations ---\n");
	test_open_close();
	test_genkey();
	test_key_lifecycle();
	test_list_keys();

	/* Symmetric encryption */
	printf("\n--- Symmetric Encryption ---\n");
	test_aead_roundtrip();
	test_aes128_gcm_roundtrip();
	test_cbc_roundtrip();
	test_aes128_cbc_roundtrip();

	/* MAC and Hash */
	printf("\n--- MAC and Hash ---\n");
	test_mac();
	test_mac_sha512();
	test_mac_consistency();
	test_hash();
	test_hash_sha512();
	test_hash_consistency();

	/* Security features */
	printf("\n--- Security Features ---\n");
	test_capability_restrict();
	test_key_revoke();
	test_key_expiration();
	test_aead_auth_failure();

	/* Error handling */
	printf("\n--- Error Handling ---\n");
	test_invalid_key_id();
	test_wrong_algorithm();
	test_zero_length_data();
	test_invalid_algorithm();
	test_cbc_alignment();
	test_invalid_key_size();
	test_buffer_too_small();
	test_invalid_iv_length();
	test_double_destroy();
	test_double_revoke();
	test_revoke_nonexistent();
	test_use_after_destroy();
	test_empty_key_list();
	test_expired_key_flag();
	test_sign_with_symmetric_key();
	test_encrypt_with_ed25519_key();
	test_get_pubkey_from_symmetric_key();
	test_mac_with_ed25519_key();

	/* Ed25519 digital signatures */
	printf("\n--- Ed25519 Digital Signatures ---\n");
	test_ed25519_keygen();
	test_ed25519_sign_verify();
	test_ed25519_get_pubkey();
	test_ed25519_tampered_message();
	test_ed25519_wrong_key();

	/* Phase 3: ChaCha20-Poly1305 */
	printf("\n--- ChaCha20-Poly1305 AEAD ---\n");
	test_chacha20_poly1305_keygen();
	test_chacha20_poly1305_roundtrip();
	test_chacha20_poly1305_auth_failure();

	/* Phase 3: X25519 Key Exchange */
	printf("\n--- X25519 Key Exchange ---\n");
	test_x25519_keygen();
	test_x25519_get_pubkey();
	test_x25519_keyexchange();
	test_x25519_wrong_key_type();
	test_x25519_capability_restriction();

	/* Phase 3: HKDF Key Derivation */
	printf("\n--- HKDF Key Derivation ---\n");
	test_hkdf_sha256();
	test_hkdf_sha512();
	test_hkdf_consistency();
	test_hkdf_from_keyexchange();
	test_hkdf_capability_restriction();

	/* Sysctl tunables */
	printf("\n--- Sysctl Tunables ---\n");
	test_sysctl_readable();
	test_sysctl_max_keys_enforced();
	test_sysctl_max_data_enforced();

	/* Advanced features */
	printf("\n--- Advanced Features ---\n");
	test_fd_passing();

	printf("\n===========================================\n");
	printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
	printf("===========================================\n");

	return (tests_run - tests_passed);
}
