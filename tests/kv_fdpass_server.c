/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Keyvault FD Passing Test - Server
 *
 * This program demonstrates the keyvault fd passing use case:
 * 1. Server opens /dev/keyvault and creates a key
 * 2. Server restricts capabilities (removes REVOKE, DESTROY, GENKEY)
 * 3. Server passes the fd to a client via Unix socket
 * 4. Client can use the key for encrypt/decrypt but cannot manage it
 *
 * Usage: ./kv_fdpass_server [socket_path]
 *        Default socket: /tmp/keyvault.sock
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <signal.h>

#include "../keyvault.h"

#define DEVICE_PATH "/dev/keyvault"
#define DEFAULT_SOCKET "/tmp/keyvault.sock"

static const char *socket_path = DEFAULT_SOCKET;
static int listen_fd = -1;

static void
cleanup(void)
{
	if (listen_fd >= 0)
		close(listen_fd);
	unlink(socket_path);
}

static void
sighandler(int sig)
{
	(void)sig;
	cleanup();
	_exit(0);
}

/*
 * Send file descriptor and key info over Unix socket
 */
static int
send_fd_and_keyid(int sock, int fd, uint64_t key_id)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))];

	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, sizeof(buf));

	/* Send key_id as the message data */
	iov.iov_base = &key_id;
	iov.iov_len = sizeof(key_id);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

	if (sendmsg(sock, &msg, 0) < 0) {
		warn("sendmsg");
		return (-1);
	}

	return (0);
}

int
main(int argc, char *argv[])
{
	struct sockaddr_un addr;
	int kv_fd, client_fd;
	struct kv_genkey_req genreq;
	struct kv_restrict_req restrict_req;
	struct kv_getcaps_req getcaps;

	if (argc > 1)
		socket_path = argv[1];

	/* Setup cleanup handlers */
	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);
	atexit(cleanup);

	printf("=== Keyvault FD Passing Server ===\n\n");

	/* Open keyvault device */
	printf("[1] Opening /dev/keyvault...\n");
	kv_fd = open(DEVICE_PATH, O_RDWR);
	if (kv_fd < 0)
		err(1, "open(%s)", DEVICE_PATH);
	printf("    Opened fd=%d\n", kv_fd);

	/* Generate a key */
	printf("[2] Generating AES-256-GCM key...\n");
	memset(&genreq, 0, sizeof(genreq));
	genreq.algorithm = KV_ALG_AES256_GCM;
	genreq.key_bits = 256;

	if (ioctl(kv_fd, KV_IOC_GENKEY, &genreq) < 0)
		err(1, "ioctl(KV_IOC_GENKEY)");
	printf("    Generated key_id=%lu\n", (unsigned long)genreq.key_id);

	/* Show current capabilities */
	memset(&getcaps, 0, sizeof(getcaps));
	if (ioctl(kv_fd, KV_IOC_GETCAPS, &getcaps) < 0)
		err(1, "ioctl(KV_IOC_GETCAPS)");
	printf("    Current capabilities: 0x%08x (KV_CAP_ALL)\n", getcaps.caps);

	/* Restrict capabilities - client can only encrypt/decrypt */
	printf("[3] Restricting capabilities to read-only...\n");
	memset(&restrict_req, 0, sizeof(restrict_req));
	restrict_req.caps = KV_CAP_READONLY;

	if (ioctl(kv_fd, KV_IOC_RESTRICT, &restrict_req) < 0)
		err(1, "ioctl(KV_IOC_RESTRICT)");

	/* Verify restriction */
	if (ioctl(kv_fd, KV_IOC_GETCAPS, &getcaps) < 0)
		err(1, "ioctl(KV_IOC_GETCAPS)");
	printf("    New capabilities: 0x%08x\n", getcaps.caps);
	printf("    Can ENCRYPT: %s\n", (getcaps.caps & KV_CAP_ENCRYPT) ? "yes" : "no");
	printf("    Can DECRYPT: %s\n", (getcaps.caps & KV_CAP_DECRYPT) ? "yes" : "no");
	printf("    Can REVOKE:  %s\n", (getcaps.caps & KV_CAP_REVOKE) ? "yes" : "no");
	printf("    Can DESTROY: %s\n", (getcaps.caps & KV_CAP_DESTROY) ? "yes" : "no");
	printf("    Can GENKEY:  %s\n", (getcaps.caps & KV_CAP_GENKEY) ? "yes" : "no");

	/* Create Unix socket */
	printf("[4] Creating Unix socket at %s...\n", socket_path);
	unlink(socket_path);

	listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_fd < 0)
		err(1, "socket");

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, socket_path, sizeof(addr.sun_path));

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		err(1, "bind");

	if (listen(listen_fd, 1) < 0)
		err(1, "listen");

	printf("    Listening for client connection...\n");

	/* Accept client connection */
	client_fd = accept(listen_fd, NULL, NULL);
	if (client_fd < 0)
		err(1, "accept");
	printf("    Client connected\n");

	/* Send the fd and key_id to client */
	printf("[5] Sending fd and key_id to client...\n");
	if (send_fd_and_keyid(client_fd, kv_fd, genreq.key_id) < 0)
		err(1, "send_fd_and_keyid");
	printf("    Sent fd=%d, key_id=%lu\n", kv_fd, (unsigned long)genreq.key_id);

	/* Wait for client to finish */
	printf("[6] Waiting for client to complete tests...\n");
	char result;
	if (read(client_fd, &result, 1) > 0) {
		printf("    Client result: %s\n", result == 'P' ? "PASS" : "FAIL");
	}

	close(client_fd);
	close(kv_fd);

	printf("\n=== Server done ===\n");
	return (result == 'P' ? 0 : 1);
}
