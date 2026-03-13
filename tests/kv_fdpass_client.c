/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Keyvault FD Passing Test - Client
 *
 * This program receives a restricted keyvault fd from the server and:
 * 1. Verifies it CAN encrypt data
 * 2. Verifies it CAN decrypt data
 * 3. Verifies it CANNOT revoke the key (EPERM)
 * 4. Verifies it CANNOT destroy the key (EPERM)
 * 5. Verifies it CANNOT generate new keys (EPERM)
 *
 * Usage: ./kv_fdpass_client [socket_path]
 *        Default socket: /tmp/keyvault.sock
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include "../keyvault.h"

#define DEFAULT_SOCKET "/tmp/keyvault.sock"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST_START(name) do { \
	printf("  Test: %-40s ", name); \
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
 * Receive file descriptor and key_id from server
 */
static int
recv_fd_and_keyid(int sock, int *fd_out, uint64_t *key_id_out)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))];
	uint64_t key_id;
	int fd;

	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, sizeof(buf));

	iov.iov_base = &key_id;
	iov.iov_len = sizeof(key_id);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	if (recvmsg(sock, &msg, 0) < 0) {
		warn("recvmsg");
		return (-1);
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL ||
	    cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS) {
		warnx("no fd in message");
		return (-1);
	}

	memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
	*fd_out = fd;
	*key_id_out = key_id;

	return (0);
}

/*
 * Test: Verify we can encrypt data
 */
static int
test_encrypt(int fd, uint64_t key_id)
{
	struct kv_aead_encrypt_req req;
	const char *plaintext = "Secret message from client!";
	char ciphertext[128];
	char nonce[12];
	char tag[16];

	TEST_START("encrypt with restricted fd");

	memset(&req, 0, sizeof(req));
	req.key_id = key_id;
	req.plaintext = plaintext;
	req.plaintext_len = strlen(plaintext);
	req.aad = NULL;
	req.aad_len = 0;
	req.ciphertext = ciphertext;
	req.ciphertext_len = sizeof(ciphertext);
	req.nonce = NULL;
	req.nonce_len = 0;
	req.nonce_out = nonce;
	req.tag = tag;
	req.tag_len = sizeof(tag);

	if (ioctl(fd, KV_IOC_AEAD_ENCRYPT, &req) < 0) {
		TEST_FAIL(strerror(errno));
		return (-1);
	}

	TEST_PASS();
	return (0);
}

/*
 * Test: Verify we can decrypt data
 */
static int
test_encrypt_decrypt_roundtrip(int fd, uint64_t key_id)
{
	struct kv_aead_encrypt_req encreq;
	struct kv_aead_decrypt_req decreq;
	const char *plaintext = "Round-trip test message 12345!";
	char ciphertext[128];
	char decrypted[128];
	char nonce[12];
	char tag[16];

	TEST_START("encrypt/decrypt round-trip");

	/* Encrypt */
	memset(&encreq, 0, sizeof(encreq));
	encreq.key_id = key_id;
	encreq.plaintext = plaintext;
	encreq.plaintext_len = strlen(plaintext);
	encreq.ciphertext = ciphertext;
	encreq.ciphertext_len = sizeof(ciphertext);
	encreq.nonce_out = nonce;
	encreq.tag = tag;
	encreq.tag_len = sizeof(tag);

	if (ioctl(fd, KV_IOC_AEAD_ENCRYPT, &encreq) < 0) {
		TEST_FAIL("encrypt failed");
		return (-1);
	}

	/* Decrypt */
	memset(&decreq, 0, sizeof(decreq));
	memset(decrypted, 0, sizeof(decrypted));
	decreq.key_id = key_id;
	decreq.ciphertext = ciphertext;
	decreq.ciphertext_len = encreq.ciphertext_len;
	decreq.nonce = nonce;
	decreq.nonce_len = 12;
	decreq.tag = tag;
	decreq.tag_len = 16;
	decreq.plaintext = decrypted;
	decreq.plaintext_len = sizeof(decrypted);

	if (ioctl(fd, KV_IOC_AEAD_DECRYPT, &decreq) < 0) {
		TEST_FAIL("decrypt failed");
		return (-1);
	}

	/* Verify */
	if (decreq.plaintext_len != strlen(plaintext) ||
	    memcmp(decrypted, plaintext, strlen(plaintext)) != 0) {
		TEST_FAIL("decrypted data mismatch");
		return (-1);
	}

	TEST_PASS();
	return (0);
}

/*
 * Test: Verify we CANNOT revoke the key
 */
static int
test_cannot_revoke(int fd, uint64_t key_id)
{
	struct kv_revoke_req req;

	TEST_START("revoke blocked (EPERM expected)");

	memset(&req, 0, sizeof(req));
	req.key_id = key_id;

	if (ioctl(fd, KV_IOC_REVOKE, &req) == 0) {
		TEST_FAIL("revoke succeeded (should have failed)");
		return (-1);
	}

	if (errno != EPERM) {
		char msg[64];
		snprintf(msg, sizeof(msg), "got %s, expected EPERM", strerror(errno));
		TEST_FAIL(msg);
		return (-1);
	}

	TEST_PASS();
	return (0);
}

/*
 * Test: Verify we CANNOT destroy the key
 */
static int
test_cannot_destroy(int fd, uint64_t key_id)
{
	struct kv_destroy_req req;

	TEST_START("destroy blocked (EPERM expected)");

	memset(&req, 0, sizeof(req));
	req.key_id = key_id;

	if (ioctl(fd, KV_IOC_DESTROY, &req) == 0) {
		TEST_FAIL("destroy succeeded (should have failed)");
		return (-1);
	}

	if (errno != EPERM) {
		char msg[64];
		snprintf(msg, sizeof(msg), "got %s, expected EPERM", strerror(errno));
		TEST_FAIL(msg);
		return (-1);
	}

	TEST_PASS();
	return (0);
}

/*
 * Test: Verify we CANNOT generate new keys
 */
static int
test_cannot_genkey(int fd)
{
	struct kv_genkey_req req;

	TEST_START("genkey blocked (EPERM expected)");

	memset(&req, 0, sizeof(req));
	req.algorithm = KV_ALG_AES256_GCM;
	req.key_bits = 256;

	if (ioctl(fd, KV_IOC_GENKEY, &req) == 0) {
		TEST_FAIL("genkey succeeded (should have failed)");
		return (-1);
	}

	if (errno != EPERM) {
		char msg[64];
		snprintf(msg, sizeof(msg), "got %s, expected EPERM", strerror(errno));
		TEST_FAIL(msg);
		return (-1);
	}

	TEST_PASS();
	return (0);
}

/*
 * Test: Verify we CAN query key info (read-only operation)
 */
static int
test_can_getinfo(int fd, uint64_t key_id)
{
	struct kv_keyinfo_req req;

	TEST_START("getinfo allowed");

	memset(&req, 0, sizeof(req));
	req.key_id = key_id;

	if (ioctl(fd, KV_IOC_GETINFO, &req) < 0) {
		TEST_FAIL(strerror(errno));
		return (-1);
	}

	if (req.algorithm != KV_ALG_AES256_GCM) {
		TEST_FAIL("wrong algorithm");
		return (-1);
	}

	TEST_PASS();
	return (0);
}

/*
 * Test: Verify we CAN list keys (read-only operation)
 */
static int
test_can_list(int fd)
{
	struct kv_list_req req;
	uint64_t key_ids[16];

	TEST_START("list keys allowed");

	memset(&req, 0, sizeof(req));
	req.key_ids = key_ids;
	req.max_keys = 16;

	if (ioctl(fd, KV_IOC_LIST, &req) < 0) {
		TEST_FAIL(strerror(errno));
		return (-1);
	}

	if (req.num_keys < 1) {
		TEST_FAIL("expected at least 1 key");
		return (-1);
	}

	TEST_PASS();
	return (0);
}

int
main(int argc, char *argv[])
{
	const char *socket_path = DEFAULT_SOCKET;
	struct sockaddr_un addr;
	int sock_fd, kv_fd;
	uint64_t key_id;
	char result;
	int failed = 0;

	if (argc > 1)
		socket_path = argv[1];

	printf("=== Keyvault FD Passing Client ===\n\n");

	/* Connect to server */
	printf("[1] Connecting to server at %s...\n", socket_path);
	sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock_fd < 0)
		err(1, "socket");

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, socket_path, sizeof(addr.sun_path));

	if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		err(1, "connect");
	printf("    Connected\n");

	/* Receive fd and key_id */
	printf("[2] Receiving fd and key_id from server...\n");
	if (recv_fd_and_keyid(sock_fd, &kv_fd, &key_id) < 0)
		err(1, "recv_fd_and_keyid");
	printf("    Received fd=%d, key_id=%lu\n", kv_fd, (unsigned long)key_id);

	/* Run tests */
	printf("\n[3] Running capability restriction tests...\n\n");

	/* Tests that should SUCCEED */
	if (test_encrypt(kv_fd, key_id) < 0)
		failed++;
	if (test_encrypt_decrypt_roundtrip(kv_fd, key_id) < 0)
		failed++;
	if (test_can_getinfo(kv_fd, key_id) < 0)
		failed++;
	if (test_can_list(kv_fd) < 0)
		failed++;

	/* Tests that should FAIL with EPERM */
	if (test_cannot_revoke(kv_fd, key_id) < 0)
		failed++;
	if (test_cannot_destroy(kv_fd, key_id) < 0)
		failed++;
	if (test_cannot_genkey(kv_fd) < 0)
		failed++;

	/* Report results to server */
	result = (failed == 0) ? 'P' : 'F';
	write(sock_fd, &result, 1);

	close(kv_fd);
	close(sock_fd);

	printf("\n===========================================\n");
	printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
	printf("===========================================\n");

	if (failed > 0) {
		printf("\nFD PASSING TEST FAILED\n");
		printf("The restricted fd did not behave as expected.\n");
		return (1);
	}

	printf("\nFD PASSING TEST PASSED\n");
	printf("The capability restriction system works correctly:\n");
	printf("  - Receiver CAN use the key for crypto operations\n");
	printf("  - Receiver CANNOT revoke, destroy, or create keys\n");

	return (0);
}
