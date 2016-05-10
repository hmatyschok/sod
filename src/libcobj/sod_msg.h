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





/*
 * Message primitive (MPI) encapsulates message token.
 */
 
struct tobj_mbuf {
	struct tobj_descr 	sb_h; 
	uint32_t 	sb_code; 	/* encodes request or response */
	char 	sb_tok[SOD_NMAX + 1];
};
#define SOD_MBUF_LEN 	(sizeof(struct tobj_mbuf))

/*
 * Service Primitives (SPI).
 */

#define TOBJ_MSG_ACK 	0x00000010
#define TOBJ_MSG_NAK 	0x00000020
#define TOBJ_MSG_REJ 	0x00000030

typedef ssize_t 	(*tobj_msg_t)(int, struct msghdr *, int);

typedef struct tobj_mbuf * 	(*tobj_msg_alloc_t)(size_t);
typedef void 	(*tobj_msg_prepare_t)(char *, uint32_t, void *, 
	struct tobj_mbuf *);
typedef ssize_t 	(*tobj_msg_send_t)(int, struct msghdr *, int);
typedef ssize_t 	(*tobj_msg_recv_t)(int, struct msghdr *, int);
typedef int 	(*tobj_msg_handle_t)(tobj_msg_t, int, struct tobj_mbuf *);
typedef void 	(*tobj_msg_free_t)(struct tobj_mbuf *);

_BEGIN_DECLS
extern struct tobj_mbuf * 	tobj_msg_alloc(size_t);
extern void 	tobj_msg_prepare(const char *, uint32_t, void *, 
	struct tobj_mbuf *);
extern ssize_t 	tobj_msg_send(int, struct msghdr *, int);
extern ssize_t 	tobj_msg_recv(int, struct msghdr *, int);
extern int 	tobj_msg_handle(tobj_msg_t, int, struct tobj_mbuf *);
extern void 	tobj_msg_free(struct tobj_mbuf *);
__END_DECLS
