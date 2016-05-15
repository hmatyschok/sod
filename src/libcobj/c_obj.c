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

#include <sys/time.h>
#include <sys/types.h>

#include <db.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>

#include <c_obj.h>

/*
 * Set contains abstract components.
 */

typedef int  	(*c_cache_fn_t)(struct c_cache *, DBT *, DBT *);

static int 	c_cache_init(struct c_cache *);
static int 	c_cache_add(struct c_cache *, DBT *, DBT *);
static int 	c_cache_get(struct c_cache *, DBT *, DBT *);
static int 	c_cache_del(struct c_cache *, DBT *, DBT *);
static int 	c_cache_free(struct c_cache *);

static int 	c_class_cache_opt(c_cache_fn_t, struct c_cache *, 
	struct c_class *);

static void *	c_class_init(void *);
static int 	c_class_free(void *);
static void * 	c_thr_create(void *);
static void * 	c_thr_destroy(void *);

static void * 	c_nop_init(void *);
static int 	c_nop_free(void *);
static void * 	c_nop_create(void *);
static void * 	c_nop_start(void *);
static int 	c_nop_stop(void *);
static int 	c_nop_destroy(void *);

/******************************************************************************
 * Generic class-attributes.
 ******************************************************************************/

/*
 * Interface implements null-operations.
 */ 
static struct c_methods c_nop = {
	.cm_class_init 		= c_nop_init,
	.cm_class_free 		= c_nop_free,
	.cm_obj_create 		= c_nop_create,
	.cm_obj_start 		= c_nop_start,
	.cm_obj_stop 		= c_nop_stop,
	.cm_obj_free 		= c_nop_destroy,
}; 

/*
 * A component set C is free generated by the inclusion 
 * mapping i of any x element in C into set A containing 
 * abstract components a, where C subset A.
 * 
 * Any mapping f between C and B (containing components) 
 * can be unequely extended to a morphism h between A 
 * and B of Sigma-algebras, where f < h.  
 */
static struct c_class c_base_class = {
	.c_obj = {
		.c_cookie 		= C_BASE_CLASS,
		.c_size 		= C_BASE_CLASS_SIZE,
	},
	.c_base = {
		.cm_class_init 		= c_class_init,
		.cm_class_free 		= c_class_free,
		.cm_obj_create 		= c_thr_create,
		.cm_obj_start 		= c_nop_start,
		.cm_obj_stop 		= c_nop_stop,
		.cm_obj_free 		= c_thr_destroy,
	},
	.c_methods 		= &c_nop,
};


void * 
c_base_class_init(void)
{
	return (c_class_init(&c_base_class));	
}

int 
c_base_class_free(void)
{

	return (c_class_free(&c_base_class));	
}

/*
 * An abstract component acts as factory for generating a component
 * x in C, due to given morphism h: A -> B of Sigma-algebras, where A 
 * denotes set of abstract components and B subset of A and C. 
 * 
 * This implies, that following preconditions must hold 
 * for successfull component instantiation:
 *  
 *  o B subset C and C subset A
 *  o i: C -> A, dom(i) subset A
 *  o f: C -> B, either dom(f) subset B or dom(f) equals B
 *  o h: A -> B, where B subset dom(h) 
 */

static void *
c_thr_create(void *arg)
{
	struct c_thr *thr = NULL;
	struct c_class *cls;
	
	DBT key;
	DBT data;	
/*
 * Apply various condition tests.
 */	
	if ((cls = arg) == NULL)
		goto out;
/*
 * An abstract component cannot instantiate itself.
 */
	if (cls->c_obj.c_cookie == c_base_class.c_obj.c_cookie)
		goto out;
/*
 * Allocate.
 */
	if ((thr = calloc(1, cls->c_obj.c_size)) == NULL)
		goto out;
/*
 * On success, initialize generic properties.
 */	
	if (pthread_cond_init(&thr->c_cv, NULL))
		goto bad;
	
	if (pthread_mutex_init(&thr->c_mtx, NULL))
		goto bad1;
/*
 * If successfull, then create running pthread(3) instance.
 */	
	if (pthread_create(&thr->c_tid, NULL, cls->c_base->c_start, thr) != 0) 
		goto bad2;

	bcopy(thr->c_tid, &thr->c_obj.c_cookie, sizeof(thr->c_obj.c_cookie));
	
	key.data = &thr->c_obj.c_cookie;
	key.size = sizeof(thr->c_obj.c_cookie);
	
	thr->c_obj.c_size = cls->c_obj.c_size;
	data.size = thr->c_obj.c_size;
	data.data = thr;
	
	if (c_cache_add(&cls->c_instances, &key, &data))
		goto bad3;
out:		
	return (thr);
bad3:
	pthread_cancel(&thr->c_tid);
bad2:	
	pthread_mtx_destroy(&thr->c_cv);
bad1:
	pthread_cond_destroy(&thr->c_cv;
bad:
	free(thr);
	thr = NULL;
	goto out;
}

/*
 * Release lock, if any and release 
 * by pthread(3) private data bound 
 * ressources.
 */
static int
c_thr_destroy(void *arg0, void *arg1)
{
	int rv = -1;
	
	struct c_class *cls;
	struct c_thr *thr;
	
	DBT key;
	DBT data;

	if ((thr = arg1) == NULL)	
		goto out;
/*
 * Apply various condition tests.
 */	
	if ((cls = arg0) == NULL)
		goto out;
/*
 * An abstract component cannot be destroyed.
 */
	if (cls->c_obj.c_cookie == c_base_class.c_obj.c_cookie)
		goto out;
/*
 * Release pthread(3). This operation can't fail because
 * returned ESRCH means that there was no pthread(3). 
 */	
	(void)pthread_cancel(thr->c_tid);
	(void)pthread_cond_destroy(&thr->c_cv);
	(void)pthread_mutex_destroy(&thr->c_mtx);
/*
 * Release object from database.
 */	
	key.data = &thr->c_obj.c_cookie;
	key.size = sizeof(thr->c_obj.c_cookie);
	
	(void)memset(&data, 0, sizeof(data));
	
	rv = c_cache_del(&cls->c_instances, &key, &data);
	
	if (rv == 0) 
		free(data.data);
out:		
	return (rv);
}

/*
 * Generic class-methods.
 */

static void *
c_class_init(void *arg)
{
	struct c_class *cls;
	
	if ((cls = arg) == NULL) 
		return (NULL);
		
	if (c_cache_init(cls->c_children))
		return (NULL);

	if (c_cache_init(cls->c_instances)) {
		c_cache_free(cls->c_children);
		return (NULL);
	}
	
	if (cls != &c_base_class) {
		if (c_cache_op(&c_base_class.c_children, c_cache_add, cls))
			return (NULL);
		
		cls->c_base = c_base_class.c_base;
	}
	return (&cls->c_base);	
}

static int 
c_class_free(void *arg)
{
	struct c_class *cls;
	
	if ((cls = arg) == NULL) 
		return (-1);
	
	if (c_cache_free(cls->c_children))
		return (-1);
		
	if (c_cache_free(cls->c_instances))
		return (-1);

	if (cls != &c_base_class) {
		if (c_cache_op(&c_base_class.c_children, c_cache_del, cls))
			return (-1);
		
		cls->c_base = c_nop;
	}
	return (0);	
}

/*
 * Non-operations, class scope.
 */

static void *
c_nop_init(void *arg)
{

	return (NULL);	
}

static int 
c_nop_free(void *arg)
{

	return (0);	
}

/*
 * Null-operations, object scope.
 */

static void *
c_nop_create(void *arg)
{

	return (NULL);
}

static void * 	
c_nop_start(void *arg)
{

	return (arg);
}

static void 	
c_nop_stop(void *arg)
{

}

static int 	
c_nop_destroy(void *arg0, void *arg1)
{

	return (0);
}

/******************************************************************************
 * Subr.
 ******************************************************************************/

/*
 * Create in-memory hash table based on db(3) 
 * and initialize corrosponding tail queue.
 */

static int
c_cache_init(struct c_cache *ch)
{
	if (ch == NULL)
		return (-1)	

	if (ch->ch_db == NULL) {
		ch->ch_db = dbopen(NULL, O_RDWR, 0, DB_HASH, NULL);
		
		if (ch->ch_db == NULL)
			return (-1);
			
		TAILQ_INIT(&ch->ch_hd);
	}
	return (0);
}


/*
 * Insert item.
 */
static int 	
c_cache_add(struct c_cache *ch, DBT *key, DBT *data)
{	
	if ((*ch->ch_db->put)(ch->ch_db, key, data, 0))
		return (-1);
	
	TAILQ_INSERT_TAIL(&ch->ch_hd, data.data, c_next);
	
	return (0);
}

/*
 * Find requested item.
 */
static int 	
c_cache_get(struct c_cache *ch, DBT *key, DBT *data)
{	

	return ((*ch->ch_db->get)(ch->ch_db, key, data, 0));
}

/*
 * Fetch requested item.
 */
static int 	
c_cache_del(struct c_cache *ch, DBT *key, DBT *data)
{
	if ((*ch->ch_db->get)(ch->ch_db, key, data, 0))
		return (-1);
	
	if ((*ch->ch_db->del)(ch->ch_db, key, 0))
		return (-1);
		
	TAILQ_REMOVE(&ch->ch_hd, data.data, c_next);
		
	return (0);
}

/*
 * Release by hash table bound ressources,
 * if and only if all by table stored items
 * were released previously.
 */
static int
c_cache_free(struct c_cache *ch)
{
	if (ch == NULL)
		return (-1);

	if (ch->ch_db == NULL) 
		return (-1);
		
	if (!TAILQ_EMPTY(&ch->ch_hd))
		return (-1);
		
	if ((*ch->ch_db->close)(ch->ch_db))
		return (-1);
		
	ch->ch_db = NULL;
		
	return (0);
}

static int
c_class_cache_opt(c_cache_fn_t fn, struct c_cache *ch, struct c_class *cls)
{
	DBT key;
	DBT data;
	
	key.data = &cls->c_cookie;
	key.size = sizeof(cls->c_cookie);
	
	data.data = cls;
	data.size = sizeof(*cls);
	
	return ((*fn)(ch, &key, &data));
}
