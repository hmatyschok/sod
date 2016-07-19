/*-
 * Copyright (c) 2016 Henning Matyschok
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
 * version=0.3
 */

#ifndef _SOD_H_
#define    _SOD_H_

#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX    _POSIX_PATH_MAX
#endif /* PATH_MAX */

#define SOD_WORK_DIR     "/"
#define SOD_PID_FILE     "/var/run/sod.pid"
#define SOD_SOCK_FILE     "/var/run/sod.sock"

#define SOD_NMAX     127

struct sod_msg {
    int     sm_code;     /* encodes request or response */
    char     sm_tok[SOD_NMAX + 1];
};
#define SOD_MSG_LEN     (sizeof(struct sod_msg))
#define SOD_MSG_QLEN     13

#define SOD_MSG_ACK     0x00000010
#define SOD_MSG_NAK     0x00000020
#define SOD_MSG_REJ     0x00000030

typedef ssize_t     (*sod_msg_fn_t)(int, struct sod_msg *, int);

#define SOD_AUTH_REQ    0x00000001
#define SOD_PASSWD_REQ  0x00000002
#define SOD_TERM_REQ     0x00000003

#define SOD_AUTH_ACK     (SOD_AUTH_REQ|SOD_MSG_ACK)
#define SOD_AUTH_NAK     (SOD_AUTH_REQ|SOD_MSG_NAK)
#define SOD_AUTH_REJ     (SOD_AUTH_REQ|SOD_MSG_REJ)

#define SOD_PASSWD_ACK     (SOD_PASSWD_REQ|SOD_MSG_ACK)
#define SOD_PASSWD_NAK     (SOD_PASSWD_REQ|SOD_MSG_NAK)
#define SOD_PASSWD_REJ     (SOD_PASSWD_REQ|SOD_MSG_REJ)

#define SOD_TERM_ACK     (SOD_TERM_REQ|SOD_MSG_ACK)
#define SOD_TERM_REJ     (SOD_TERM_REQ|SOD_MSG_REJ)

__BEGIN_DECLS
struct sod_msg *     sod_msg_alloc(void);
void     sod_msg_prepare(const char *, int, struct sod_msg *);
ssize_t     sod_msg_send(int, struct sod_msg *, int);
ssize_t     sod_msg_recv(int, struct sod_msg *, int);
ssize_t     sod_msg_fn(sod_msg_fn_t, int, struct sod_msg *);
void     sod_msg_free(struct sod_msg *);
__END_DECLS

#endif /* _SOD_H_ */
