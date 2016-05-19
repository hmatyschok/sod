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
 * version=0.1 
 */

#include <sys/types.h>

#include <pthread.h>
#include <unistd.h>

#define C_NMAX 	127

struct c_obj;

typedef void * 	(*c_init_t)(void *);
typedef int 	(*c_fini_t)(void *);

typedef void *	(*c_create_t)(void *);
typedef void *	(*c_start_t)(void *);
typedef void 	(*c_stop_t)(void *);
typedef int 	(*c_destroy_t)(void *, void *);

/*
 * Implements generic interface. 
 */
struct c_methods {
	c_init_t 		cm_init;
	c_fini_t 		cm_free;
/*
 * Methods implemets life-cycle of an instance.  
 */	
	c_create_t 		cm_create;
	c_start_t 		cm_start;
	c_stop_t 		cm_stop;
	c_destroy_t 		cm_destroy;
};

/*
 * Implements generic object.
 *
 * c_id = $( date -u '+%s' )
 */
struct c_obj {
	long 	co_id; 	/* identifier */
	size_t 	co_size;
	
	TAILQ_NEXT(c_obj) co_next;
};
TAILQ_HEAD(c_obj_hd, c_obj);

/*
 * Implements generic cache. 
 */
struct c_cache {
	struct c_obj_hd 	ch_hd;
	DB 	*ch_db;
};

/*
 * By pthread(3) covered instance.
 */
struct c_thr {
	struct c_obj 	ct_co;
#define ct_id 	ct_co.co_id
#define ct_size 	ct_co.co_size
/*
 * Attcibutes, pthread(3).
 */	
	pthread_cond_t 	ct_cv;
	pthread_mutex_t 	ct_mtx;
	pthread_t 	ct_tid;
};


/*
 * Implements class.
 */
struct c_class {
	struct c_obj 		c_co;
#define c_id 	c_co.co_id
#define c_size 	c_co.co_size
	struct c_cache 		c_children;
	struct c_cache 		c_instances;
/*
 * From parent inherited interface.
 */
	struct c_methods 		c_base;
/*
 * Public interface.
 */
	void 	*c_methods;
};

__BEGIN_DECLS
void * 	c_base_class_init(void);
int 	c_base_class_fini(void);
__END_DECLS

