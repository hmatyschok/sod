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
#include <unistd.h>

#include <db.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <semaphore.h>

#ifdef C_OBJ_DEBUG
#include <syslog.h>
#endif /* C_OBJ_DEBUG */

#define C_NMAX     127

#define C_MSG_ACK     0x00000010
#define C_MSG_NAK     0x00000020
#define C_MSG_REJ     0x00000030

/*
 * Accessor methods for objects.
 */ 
typedef void *  (*c_obj_fn_t)(DB *db, DBT *key, void *arg);
typedef ssize_t     (*c_msg_fn_t)(int, struct msghdr *, int);
typedef void *   (*c_class_fn_t)(void *, void *);

/*
 * Methods implements life-cycle of an instance.  
 */ 
typedef void *    (*c_create_t)(void *);
typedef void *    (*c_start_t)(void *);

typedef int     (*c_lock_t)(void *);
typedef int     (*c_unlock_t)(void *);

typedef int     (*c_sleep_t)(void *, void *);
typedef int     (*c_wakeup_t)(void *, void *);
typedef int     (*c_wait_t)(time_t, void *, void *);

typedef void     (*c_stop_t)(void *);
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
#define C_BASE    0x00000010
#define C_THR    0x00000020
    LIST_ENTRY(c_obj) co_next;
};
LIST_HEAD(c_cache, c_obj);

/*
 * Implements generic interface. 
 */
 
struct c_class {
    struct c_obj         c_co;
#define c_id        c_co.co_id
#define c_len       c_co.co_len
#define c_flags     c_co.co_flags
/*
 * Cache.
 */    
    struct c_cache  c_children;
    struct c_cache  c_instances;
/*
 * Accessor methods for children
 */ 
    c_class_fn_t    c_class_add;
    c_class_fn_t    c_class_del; 
/*
 * Accessor methods for instances
 */    
    c_class_fn_t    c_obj_add;
    c_class_fn_t    c_obj_del;
    c_class_fn_t    c_obj_get;  
/*
 * Methods implements life-cycle of an instance.  
 */    
    c_create_t         c_create;
    c_start_t         c_start;
    c_lock_t        c_lock;
    c_unlock_t        c_unlock;
    c_sleep_t        c_sleep;    
    c_wakeup_t        c_wakeup;    
    c_wait_t        c_wait;
    c_stop_t         c_stop;
    c_destroy_t         c_destroy;
};
#define C_NOP_CLASS     1464994078

/*
 * Generic instance.
 */
struct c_base {
    struct c_obj     ct_co;
#define cb_id       cb_co.co_id
#define cb_len      cb_co.co_len
#define cb_flags    cb_co.co_flags

/*
 * Unnamed semaphore.
 */    
    sem_t       cb_sem;
    pid_t       cb_pid;
};
#define C_BASE_CLASS     1463676824
#define C_BASE_LEN     (sizeof(struct c_base))

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
#define C_THR_CLASS     1464519469
#define C_THR_LEN     (sizeof(struct c_thr))

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

void *   c_obj_add(DB *, DBT *, void *);
void *     c_obj_get(DB *, DBT *, void *);
void *     c_obj_del(DB *, DBT *, void *);
void *   c_obj_fn(c_obj_fn_t, DB *, void *);

struct c_msg *     c_msg_alloc(void);
void     c_msg_prepare(const char *, uint32_t, long, struct c_msg *);
ssize_t     c_msg_send(int, struct msghdr *, int);
ssize_t     c_msg_recv(int, struct msghdr *, int);
int     c_msg_fn(c_msg_fn_t, int, struct c_msg *);
void     c_msg_free(struct c_msg *);

int     c_base_class_init(void *);
int     c_base_class_fini(void *);

int     c_thr_class_init(void *);
int     c_thr_class_fini(void *);
__END_DECLS

#endif /* _C_OBJ_H_ */
