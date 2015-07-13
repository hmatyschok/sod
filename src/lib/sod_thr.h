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

#include <pthread.h>

#define SOD_THR_COOKIE 	0
#define SOD_THR_TYPE 	"sod_thr"

/*
 * Implements binding of components with pthread(3) instances.
 */

typedef void 	(*sta_init_t)(void);

struct sod_thr_attr {
	struct sod_header 	sta_h;
	pthread_once_t 	sta_once;
	pthread_key_t 	sta_key;
	uint32_t 	sta_eval;
	sta_init_t 	sta_init;
};
#define SOD_BIND_ERR 	0x00000001

typedef void 	(*st_lock_t)(void *);
typedef void 	(*st_unlock_t)(void *);
typedef void *	(*st_start_t)(void *);
typedef int 	(*st_bind_t)(void *, void *, void *);
typedef int 	(*st_wait_t)(u_int, void *);
typedef void 	(*st_excp_t)(int, const char *, void *);
typedef void 	(*st_stop_t)(void *);

#define SOD_INIT 	0x00000001 	/* component, accessible */
#define SOD_RUN 	0x00000002 	/* component, pthread(3) */
#define SOD_SYNC 	0x00000004 	/* pthread(3), locked, life-cycle */
#define SOD_LOCKED 	0x00000008 	/* instance, holds lock */

struct sod_thr {
	u_long 	st_cookie; 	/* class-identifier */
	uint32_t 	st_flags; 	/* run-time properties */
	sigset_t 	st_mask; 	/* pthread(3) signal-mask */
	pthread_t 	st_tid;  	/* pthread(3)-identifier, long */
	const char 	*st_type;		/* id string */
	size_t 	st_size; 	/* by instance used ressources */
	size_t 	st_ref; 	/* cardinality or index */
/* 
 * Methods defining pthread(3) life-cycle.
 */
	st_start_t 	st_start;
/*
 * Locking primitves for pthread(3) synchronization.
 */
	st_lock_t 	st_lock; 	
	st_unlock_t 	st_unlock;
/*
 * Generic Service Primitves (SPI).
 */
	st_bind_t 	st_bind;
	st_wait_t 	st_wait;
/*
 * Exception handler set.
 */
	st_excp_t	st_log;
	st_excp_t 	st_exit;
	st_excp_t 	st_errx;
	st_stop_t 	st_stop;
};
#define SOD_THR_SIZE 	(sizeof(struct sod_thr))

/*
 * Public SPI.
 */

typedef int 	(*libsod_thr_include_t)(struct sod_thr *, void *, void *);
typedef void 	(*libsod_thr_exclude_t)(struct sod_thr *, void *);

typedef int 	(*sod_promote_thr_t)(void *, void *);
typedef struct sod_thr *	(*sod_create_thr_t)(struct sod_thr *, 
	sod_promote_thr_t, void *);
typedef void 	(*sod_delete_thr_t)(struct sod_thr *, void *); 
 
#define LIB_SOD 	"libsod.so"

extern int 	libsod_thr_include(struct sod_thr *, void *, void *);
extern void 	libsod_thr_exclude(struct sod_thr *, void *);

#define LIB_SOD_THR_INIT 	"libsod_thr_include"
#define LIB_SOD_THR_FINI 	"libsod_thr_exclude"

extern struct sod_thr * 	sod_create_thr(struct sod_thr *, 
	sod_promote_thr_t, void *);
extern void 	sod_delete_thr(struct sod_thr *, void *);

#define LIB_SOD_CREATE_THR 	"sod_create_thr"
#define LIB_SOD_DESTROY_THR 	"sod_destroy_thr"
