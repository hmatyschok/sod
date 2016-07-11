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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SOD_WORK_DIR     "/"
#define SOD_PID_FILE     "/var/run/sod.pid"
#define SOD_SOCK_FILE     "/var/run/sod.sock"

#define SOD_NMAX     127

struct sod_msg {
    ssize_t     sm_len;
#define msg_id     msg_obj.co_id
#define msg_len     msg_obj.co_len
    int     sm_code;     /* encodes request or response */
    char     sm_tok[SOD_NMAX + 1];
};
#define SOD_MSG_LEN     (sizeof(struct sod_msg))
#define SOD_MSG_QLEN     13

#define SOD_MSG_ACK     0x00000010
#define SOD_MSG_NAK     0x00000020
#define SOD_MSG_REJ     0x00000030

typedef ssize_t     (*sod_msg_fn_t)(int, struct msghdr *, int);

#define SOD_AUTH_REQ     0x00000001
#define SOD_TERM_REQ     0x00000002

#define SOD_AUTH_ACK     (SOD_AUTH_REQ|SOD_MSG_ACK)
#define SOD_AUTH_NAK     (SOD_AUTH_REQ|SOD_MSG_NAK)
#define SOD_AUTH_REJ     (SOD_AUTH_REQ|SOD_MSG_REJ)
#define    SOD_TERM_ACK     (SOD_TERM_REQ|SOD_MSG_ACK)
#define SOD_TERM_REJ     (SOD_TERM_REQ|SOD_MSG_REJ)

static __inline struct sod_msg *     sod_msg_alloc(void);
static __inline void     sod_msg_prepare(const char *, uint32_t, 
    struct sod_msg *);
static __inline ssize_t     sod_msg_send(int, struct msghdr *, int);
static __inline ssize_t     sod_msg_recv(int, struct msghdr *, int);
static __inline int     sod_msg_fn(sod_msg_fn_t, int, struct sod_msg *);
static __inline void     sod_msg_free(struct sod_msg *);

/*
 * Allocate message primitive.
 */ 
static __inline struct sod_msg * 
sod_msg_alloc(void)
{
    struct sod_msg *sm;
    
    if ((sm = calloc(1, SOD_MSG_LEN)) != NULL) 
        sm->sm_len = SOD_MSG_LEN;
           
    return (sm);
}

/*
 * Fills message buffer with attributes, if any.
 */
static __inline void 
sod_msg_prepare(const char *s, uint32_t code, struct sod_msg *sm)
{
    if (sm != NULL) {
        (void)memset(sm, 0, sizeof(*sm));
    
        sm->sm_code = code;
    
        if (s != NULL) 
            (void)strncpy(sm->sm_tok, s, SOD_NMAX);
    }
}

/*
 * Wrapper for sendmsg(2).
 */
static __inline ssize_t 
sod_msg_send(int s, struct msghdr *msg, int flags)
{
    return (sendmsg(s, msg, flags));
}

/*
 * Wrapper for recvmsg(2).
 */
static __inline ssize_t 
sod_msg_recv(int s, struct msghdr *msg, int flags)
{
    return (recvmsg(s, msg, flags));
}

/* 
 * Performs MPI exchange via callback.  
 */
static __inline int
sod_msg_fn(sod_msg_fn_t fn, int s, struct sod_msg *sm)
{
    struct iovec vec;
    struct msghdr msg;
    int eval = -1;

    if (sm == NULL)
        goto out;

    if (fn == NULL)
        goto out;

    if (sm->sm_len != SOD_MSG_LEN)
        goto out;

    if (fn == sod_msg_recv || fn == sod_msg_send) {
        vec.iov_base = sm;
        vec.iov_len = sm->sm_len;
    
        (void)memset(&sm, 0, sizeof(msg));
    
        msg.msg_iov = &vec;
        msg.msg_iovlen = 1;            
        
        if ((*fn)(s, &msg, 0) == sm->sm_len)
            eval = 0;    
    }
out:
    return (eval);
}

/*
 * Fills buffer with zeroes and 
 * releases bound ressources.
 */
static __inline void 
sod_msg_free(struct sod_msg *sm)
{
    if (sm != NULL) {
        (void)memset(sm, 0, sizeof(*sm));
        free(sm);
    }
}

#endif /* _SOD_H_ */
