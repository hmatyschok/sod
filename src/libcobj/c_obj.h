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


typedef void * 	(*c_class_init_t)(void *);
typedef int 	(*c_class_free_t)(void *);
typedef int 	(*c_class_add_t)(void *);
typedef int 	(*c_class_del_t)(void *);


typedef void *	(*c_obj_create_t)(void *);
typedef void *	(*c_obj_start_t)(void *);
typedef int 	(*c_obj_stop_t)(void *);
typedef int 	(*c_obj_destroy_t)(void *, void *);

struct c_methods {
	c_class_init_t 		cm_class_init;
	c_class_add_t 		cm_class_add;
	c_class_del_t 		cm_class_del;
	c_class_free_t 		cm_class_free;
	
	c_obj_create_t 		cm_obj_create;
	c_obj_start_t 		cm_obj_start;
	c_obj_stop_t 		cm_obj_stop;
	c_obj_free_t 		cm_obj_free;
};

/*
 * c_cookie = $( date -u '+%s' )
 */
struct c_obj {
	long 	c_cookie; 	/* identifier */
	size_t 	c_size;
	
	TAILQ_NEXT(c_obj) c_next;
};
TAILQ_HEAD(c_obj_hd, c_obj);

struct c_cache {
	struct c_obj_hd 	ch_hd;
	DB 	*ch_db;
};

/*
 * By pthread(3) covered instance.
 */
struct c_thr {
	struct c_obj 	c_obj;
	
	pthread_cond_t 	c_cv;
	pthread_mutex_t 	c_mtx;
	pthread_t 	c_tid;
};

__BEGIN_DECLS
void * 	c_base_class_init(void);
int 	c_base_class_free(void);
__END_DECLS

