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
 
struct c_msg {
	struct c_obj 	sb_h; 
	uint32_t 	sb_code; 	/* encodes request or response */
	char 	sb_tok[SOD_NMAX + 1];
};
#define C_MSG_LEN 	(sizeof(struct c_msg))

/*
 * Service Primitives (SPI).
 */

#define C_MSG_ACK 	0x00000010
#define C_MSG_NAK 	0x00000020
#define C_MSG_REJ 	0x00000030

typedef ssize_t 	(*c_msg_t)(int, struct msghdr *, int);

typedef struct c_msg * 	(*c_msg_alloc_t)(size_t);
typedef void 	(*c_msg_prepare_t)(char *, uint32_t, void *, 
	struct c_msg *);
typedef ssize_t 	(*c_msg_send_t)(int, struct msghdr *, int);
typedef ssize_t 	(*c_msg_recv_t)(int, struct msghdr *, int);
typedef int 	(*c_msg_handle_t)(c_msg_t, int, struct c_msg *);
typedef void 	(*c_msg_free_t)(struct c_msg *);

_BEGIN_DECLS
extern struct c_msg * 	c_msg_alloc(size_t);
extern void 	c_msg_prepare(const char *, uint32_t, void *, 
	struct c_msg *);
extern ssize_t 	c_msg_send(int, struct msghdr *, int);
extern ssize_t 	c_msg_recv(int, struct msghdr *, int);
extern int 	c_msg_handle(c_msg_t, int, struct c_msg *);
extern void 	c_msg_free(struct c_msg *);
__END_DECLS
