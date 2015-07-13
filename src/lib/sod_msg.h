/*-
 * Copyright (c) 2015 Henning Matyschok
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materiasc provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * version=0.1 
 */

#include <sys/uio.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>

#define SOD_WORK_DIR 	"/"
#define SOD_PID_FILE 	"/var/run/sod.pid"
#define SOD_SOCK_FILE 	"/var/run/sod.sock"

typedef long sod_tid_t;

/*
 * sh_cookie = $( date -u '+%s' )
 */

struct sod_header {
	u_long 	sh_cookie;
	uint32_t 	sh_flags;
	sigset_t 	sh_mask;
	sod_tid_t 	sh_tid;
};

#define SOD_NMAX 	512
#define SOD_QLEN 	10

#define SOD_SYSLOG 	0x00000010

/*
 * Message primitive (MPI) encapsulates message token.
 */
 
struct sod_buf {
	struct sod_header 	sb_h; 
	uint32_t 	sb_code; 	/* encodes request or response */
	char 	sb_tok[SOD_NMAX + 1];
};
#define SOD_BUF_LEN 	(sizeof(struct sod_buf))

/*
 * Service Primitives (SPI).
 */

#define SOD_AUTH_REQ 	0x00000001
#define SOD_TERM_REQ 	0x00000002

#define SOD_ACK 	0x00000010
#define SOD_NAK 	0x00000020
#define SOD_REJ 	0x00000030

#define SOD_AUTH_ACK 	(SOD_AUTH_REQ|SOD_ACK)
#define SOD_AUTH_NAK 	(SOD_AUTH_REQ|SOD_NAK)
#define SOD_AUTH_REJ 	(SOD_AUTH_REQ|SOD_REJ)
#define	SOD_TERM_ACK 	(SOD_TERM_REQ|SOD_ACK)
#define SOD_TERM_REJ 	(SOD_TERM_REQ|SOD_REJ)

typedef ssize_t 	(*sod_msg_t)(int, struct msghdr *, int);

typedef struct sod_buf * 	(*sod_alloc_msg_t)(size_t);
typedef void 	(*sod_prepare_msg_t)(char *, uint32_t, void *, 
	struct sod_buf *);
typedef ssize_t 	(*sod_send_msg_t)(int, struct msghdr *, int);
typedef ssize_t 	(*sod_recv_msg_t)(int, struct msghdr *, int);
typedef int 	(*sod_handle_msg_t)(sod_msg_t, int, struct sod_buf *);
typedef void 	(*sod_free_msg_t)(struct sod_buf *);

#define LIB_SOD_ALLOC_MSG 	"sod_alloc_msg"
#define LIB_SOD_PREPARE_MSG 	"sod_prepare_msg"
#define LIB_SOD_SEND_MSG 	"sod_send_msg"
#define LIB_SOD_RECV_MSG 	"sod_recv_msg"
#define LIB_SOD_HANDLE_MSG 	"sod_handle_msg"
#define LIB_SOD_FREE_MSG 	"sod_free_msg"

extern struct sod_buf * 	sod_alloc_msg(size_t);
extern void 	sod_prepare_msg(const char *, uint32_t, void *, 
	struct sod_buf *);
extern ssize_t 	sod_send_msg(int, struct msghdr *, int);
extern ssize_t 	sod_recv_msg(int, struct msghdr *, int);
extern int 	sod_handle_msg(sod_msg_t, int, struct sod_buf *);
extern void 	sod_free_msg(struct sod_buf *);
