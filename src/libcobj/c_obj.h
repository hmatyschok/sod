/*-
 * Copyright (c) 2015, 2016 Henning Matyschok
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
 * version=0.2 
 */

#ifndef _C_OBJ_H_
#define    _C_OBJ_H_

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <db.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>

#ifdef C_OBJ_DEBUG
#include <syslog.h>
#endif /* C_OBJ_DEBUG */

#define C_NMAX     127

#define C_MSG_ACK     0x00000010
#define C_MSG_NAK     0x00000020
#define C_MSG_REJ     0x00000030

typedef ssize_t     (*c_msg_fn_t)(int, struct msghdr *, int);

typedef void *   (*c_obj_get_t)(void *, void *);

typedef void *     (*c_init_t)(void *);
typedef int     (*c_fini_t)(void *);

typedef void *    (*c_create_t)(void *);
typedef void *    (*c_start_t)(void *);

typedef int     (*c_lock_t)(void *);
typedef int     (*c_unlock_t)(void *);

typedef int     (*c_sleep_t)(void *, void *);
typedef int     (*c_wakeup_t)(void *, void *);
typedef int     (*c_wait_t)(void *, u_int, void *);

typedef int     (*c_stop_t)(void *);
typedef int     (*c_destroy_t)(void *, void *);
 
/*
 * Implements interface control information for an 
 * object still implements classes, by pthread(3) 
 * covered runtime instances, interfaces or message 
 * primitves.
 *
 *  co_id := $( date -u '+%s' )
 */
struct c_obj {
    long     co_id;     /* identifier */
    ssize_t     co_len;
    int         co_flags;
#define C_INIT  0x00000001    
#define C_LOCKED    0x00000002
#define C_THREAD    0x00000004    
    TAILQ_ENTRY(c_obj) co_next;
};
TAILQ_HEAD(c_cache, c_obj);

/*
 * Implements generic interface. 
 */
struct c_methods {
    struct c_obj         cm_co;
#define cm_id       cm_co.co_id
#define cm_len      cm_co.co_len
#define cm_flags    cm_co.co_flags
    c_init_t         cm_init;
    c_fini_t         cm_fini;
/*
 * Methods implemets life-cycle of an instance.  
 */    
    c_create_t         cm_create;
    c_start_t         cm_start;
    c_lock_t        cm_lock;
    c_unlock_t        cm_unlock;
    c_sleep_t        cm_sleep;    
    c_wakeup_t        cm_wakeup;    
    c_wait_t        cm_wait;
    c_stop_t         cm_stop;
    c_destroy_t         cm_destroy;
    
    c_obj_get_t    cm_get;
};
#define C_BASE_METHODS     1463676933
#define C_NOP_METHODS     1463677298
#define C_METHODS_LEN     (sizeof(struct c_methods))

/*
 * Implements class.
 */
struct c_class {
    struct c_obj         c_co;
#define c_id        c_co.co_id
#define c_len       c_co.co_len
#define c_flags     c_co.co_flags
    struct c_cache         c_children;
    struct c_cache         c_instances;
/*
 * From parent inherited interface.
 */
    struct c_methods         c_base;
/*
 * Public interface.
 */
    void     *c_public;
};
#define C_BASE_CLASS     1463676824
#define C_BASE_LEN     (sizeof(struct c_class))

/*
 * By pthread(3) covered instance.
 */
struct c_thr {
    struct c_obj     ct_co;
#define ct_id       ct_co.co_id
#define ct_len      ct_co.co_len
#define ct_flags    ct_co.co_flags

/*
 * Attributes, pthread(3).
 */    
    pthread_cond_t     ct_cv;
    pthread_mutex_t     ct_mtx;
    pthread_t     ct_tid;
};

/*
 * MPI encapsulates message token.
 */
 
struct c_msg {
    struct c_obj     msg_obj;    
#define msg_id     msg_obj.co_id
#define msg_len     msg_obj.co_len
    int     msg_code;     /* encodes request or response */
    char     msg_tok[C_NMAX + 1];
};
#define C_MSG     1463677004
#define C_MSG_LEN     (sizeof(struct c_msg))
#define C_MSG_QLEN     13

__BEGIN_DECLS
struct c_msg *     c_msg_alloc(void);
void     c_msg_prepare(const char *, uint32_t, long, struct c_msg *);
ssize_t     c_msg_send(int, struct msghdr *, int);
ssize_t     c_msg_recv(int, struct msghdr *, int);
int     c_msg_fn(c_msg_fn_t, int, struct c_msg *);
void     c_msg_free(struct c_msg *);

void *     c_base_class_init(void);
int     c_base_class_fini(void);
__END_DECLS

#endif /* _C_OBJ_H_ */
