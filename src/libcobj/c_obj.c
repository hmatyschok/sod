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

#include <sys/time.h>

#include <stdlib.h>
#include <string.h>

#include "c_obj.h"

/*
 * Implements abstract class.
 */

static void *	c_class_init(void *);
static int 	c_class_fini(void *);
static void * 	c_thr_create(void *);
static int  c_thr_lock(void *);
static int  c_thr_unlock(void *);
static int  c_thr_wakeup(struct c_methods *, void *);
static int  c_thr_sleep(struct c_methods *, void *);
static int  c_thr_wait(struct c_methods *, u_int, void *);
static int 	c_thr_destroy(void *, void *);

static void * 	c_nop_init(void *);
static int 	c_nop_fini(void *);
static void * 	c_nop_create(void *);
static void * 	c_nop_start(void *);

static int  c_nop_lock(void *);
static int  c_nop_unlock(void *);

static int  c_nop_sleep(struct c_methods *, void *);
static int  c_nop_wakeup(struct c_methods *, void *);
static int  c_nop_wait(struct c_methods *, u_int, void *);

static int 	c_nop_stop(void *);
static int 	c_nop_destroy(void *, void *);

/******************************************************************************
 * Generic class-attributes.
 ******************************************************************************/

/*
 * Interface implements null-operations.
 */ 
static struct c_methods c_nop = {
	.cm_co = {
		.co_id 		= C_NOP_METHODS,
		.co_len 		= C_METHODS_LEN,
	},
	.cm_init 		= c_nop_init,
	.cm_fini 		= c_nop_fini,
	.cm_create 		= c_nop_create,
	.cm_start 		= c_nop_start,
	.cm_lock 		= c_nop_lock,	
	.cm_unlock 		= c_nop_unlock,
	.cm_wakeup       = c_nop_wakeup,
	.cm_sleep       = c_nop_sleep,
	.cm_wait        = c_nop_wait,
	.cm_stop 		= c_nop_stop,
	.cm_destroy 		= c_nop_destroy,
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
	.c_co = {
		.co_id 		= C_BASE_CLASS,
		.co_len 		= C_BASE_LEN,
	},
	.c_base = {
		.cm_co = {
			.co_id 		= C_BASE_METHODS,
			.co_len 		= C_METHODS_LEN,
		},
		.cm_init 		= c_class_init,
		.cm_fini 		= c_class_fini,
		.cm_create 		= c_thr_create,
		.cm_start 		= c_nop_start,
		.cm_lock       = c_thr_lock,
		.cm_unlock       = c_thr_unlock,
		.cm_sleep       = c_thr_sleep,
		.cm_wakeup      = c_thr_wakeup,
		.cm_wait        = c_thr_wait,
		.cm_stop 		= c_nop_stop,
		.cm_destroy 		= c_thr_destroy,
	},
	.c_public 		= &c_nop,
};

/******************************************************************************
 * Protected Class-methods.
 ******************************************************************************/

/*
 * Generic class-methods.
 */

static void *
c_class_init(void *arg)
{
	struct c_class *cls;
	
	if ((cls = arg) == NULL) 
		return (NULL);
		
	if (c_cache_init(&cls->c_children))
		return (NULL);

	if (c_cache_init(&cls->c_instances)) {
		c_cache_free(&cls->c_children);
		return (NULL);
	}
	
	if (cls != &c_base_class) {
		if (c_cache_fn(c_cache_add, 
		    &c_base_class.c_children, cls) == NULL) {
			return (NULL);
		}
		cls->c_base = c_base_class.c_base;
	}
	return (&cls->c_base);	
}

static int 
c_class_fini(void *arg)
{
	struct c_class *cls;
	
	if ((cls = arg) == NULL) 
		return (-1);
	
	if (c_cache_free(&cls->c_children))
		return (-1);
		
	if (c_cache_free(&cls->c_instances))
		return (-1);

	if (cls != &c_base_class) {
		if (c_cache_fn(c_cache_del, 
		    &c_base_class.c_children, cls) == NULL) {
			return (-1);
		}
		cls->c_base = c_nop;
	}
	return (0);	
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
/*
 * Apply various condition tests.
 */	
	if ((cls = arg) == NULL)
		goto out;
/*
 * An abstract component cannot instantiate itself.
 */
	if (cls->c_id == c_base_class.c_id)
		goto out;
/*
 * Allocate.
 */
	if ((thr = calloc(1, cls->c_len)) == NULL)
		goto out;
/*
 * On success, initialize generic properties.
 */	
	if (pthread_cond_init(&thr->ct_cv, NULL))
		goto bad;
	
	if (pthread_mutex_init(&thr->ct_mtx, NULL))
		goto bad1;
/*
 * If successfull, then create running pthread(3) instance.
 */	
	if (pthread_create(&thr->ct_tid, NULL, cls->c_base.cm_start, thr) != 0) 
		goto bad2;

	(void)memcpy(&thr->ct_id, thr->ct_tid, sizeof(thr->ct_id));
	
	thr->ct_len = cls->c_len;
	
	if (c_cache_fn(c_cache_add, &cls->c_instances, thr) == NULL) {
	    (void)pthread_cancel(thr->ct_tid);
		goto bad2;
	}
out:		
	return (thr);
bad2:	
	(void)pthread_mutex_destroy(&thr->ct_mtx);
bad1:
	(void)pthread_cond_destroy(&thr->ct_cv);
bad:
	free(thr);
	thr = NULL;
	goto out;
}

/*
 * Lock instance.
 */
static int 
c_thr_lock(void *arg)
{
	struct c_thr *thr;
	
	if ((thr = arg) == NULL) 
		return (-1);
	
    if ((thr->ct_flags & C_LOCKED) ^ C_LOCKED) {
        if (pthread_mutex_lock(&thr->ct_mtx))
            return (-1);	
	
	    thr->ct_flags |= C_LOCKED;
	}
	return (0);
}

/*
 * Unlock instance.
 */
static int 
c_thr_unlock(void *arg)
{
	struct c_thr *thr;
	
	if ((thr = arg) == NULL) 
		return (-1);
	
    if (thr->ct_flags & C_LOCKED) {
        if (pthread_mutex_unlock(&thr->ct_mtx))
            return (-1);	
	
	    thr->ct_flags &= ~C_LOCKED;
	}
	return (0);
}

/*
 * Fell asleep.
 */
static int 
c_thr_sleep(struct c_methods *cm0, void *arg)
{
	struct c_thr *thr;
	struct c_methods *cm;
	
	if ((thr = arg) == NULL) 
		return (-1);
	
    cm = (cm0) ? cm0 : &c_base_class.c_base;
    
    (void)(*cm->cm_lock)(arg);
	(void)pthread_cond_wait(&thr->ct_cv, &thr->ct_mtx);

	return (0);
}

/*
 * Continue stalled pthread(3) execution.
 */ 
static int 
c_thr_wakeup(struct c_methods *cm0, void *arg)
{
	struct c_thr *thr;
	struct c_methods *cm;
	
	if ((thr = arg) == NULL) 
		return (-1);
	
    cm = (cm0) ? cm0 : &c_base_class.c_base;
    
	(void)pthread_cond_signal(&thr->ct_cv);
    (void)(*cm->cm_unlock)(arg);

	return (0);
}

/*
 * Fell asleep for ts seconds.
 */
static int 
c_thr_wait(struct c_methods *cm0, u_int ts, void *arg)
{
	struct c_thr *thr;
	struct c_methods *cm;
	
	u_int uts;	
	
	struct timespec ttw;
	struct timeval x;
	int eval = -1;
	
	if ((thr = arg) == NULL) 
		goto out;
	
	if ((uts = (ts * 1000)) == 0)
		goto out;
	
	cm = (cm0) ? cm0 : &c_base_class.c_base;
	
	if ((eval = gettimeofday(&x, NULL)) == 0) {
	    (void)(*cm->cm_lock)(arg);
	
	    ttw.tv_sec = x.tv_sec + ts;
	    ttw.tv_nsec = (x.tv_usec + uts) * 1000UL;
	
	    eval = pthread_cond_timedwait(&thr->ct_cv, &thr->ct_mtx, &ttw);

        (void)(*cm->cm_unlock)(arg);
    }
out:	
	return (eval);
}

/*
 * Release lock, if any and release 
 * by pthread(3) private data bound 
 * ressources.
 */
static int
c_thr_destroy(void *arg0, void *arg1)
{
	int eval = -1;
	
	struct c_class *cls;
	struct c_thr *thr;

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
	if (cls->c_id == c_base_class.c_id)
		goto out;
/*
 * Release pthread(3). This operation can't fail because
 * returned ESRCH means that there was no pthread(3). 
 */	
	(void)pthread_cancel(thr->ct_tid);
	(void)pthread_cond_destroy(&thr->ct_cv);
	(void)pthread_mutex_destroy(&thr->ct_mtx);
/*
 * Release object from database.
 */	
	thr = c_cache_fn(c_cache_del, &cls->c_instances, thr);
	if (thr) {
		eval = (*cls->c_base.cm_stop)(thr);
		free(thr);    
	}
out:		
	return (eval);
}

/******************************************************************************
 * Public Class-methods.
 ******************************************************************************/

void * 
c_base_class_init(void)
{
	return (c_class_init(&c_base_class));	
}

/*
 * Create in-memory db(3) based on hash table 
 * and initialize corrosponding tail queue.
 */

int
c_cache_init(struct c_cache *ch)
{
	if (ch == NULL)
		return (-1);	

	if (ch->ch_db == NULL) {
		ch->ch_db = dbopen(NULL, O_RDWR, 0, DB_HASH, NULL);
		
		if (ch->ch_db == NULL)
			return (-1);
			
		TAILQ_INIT(&ch->ch_hd);
	}
	return (0);
}


/*
 * Insert object.
 */
void *
c_cache_add(struct c_cache *ch, DBT *key, void *arg)
{	
	DBT data;
    struct c_obj *co;
    
	if ((co = arg) == NULL)
	    return (NULL);

	data.data = co;
	data.size = co->co_len;
	
	if ((*ch->ch_db->put)(ch->ch_db, key, &data, 0))
		return (NULL);
	
	co = data.data;
	
	TAILQ_INSERT_TAIL(&ch->ch_hd, co, co_next);
	
	return (co);
}

/*
 * Find requested object.
 */
void * 	
c_cache_get(struct c_cache *ch, DBT *key, void *arg __unused)
{	
	DBT data;

    (void)memset(&data, 0, sizeof(data));

    if ((*ch->ch_db->get)(ch->ch_db, key, &data, 0))
        return (NULL);
	
	return (data.data);
}

/*
 * Fetch requested object.
 */
void * 	
c_cache_del(struct c_cache *ch, DBT *key, void *arg __unused)
{
	DBT data;
    struct c_obj *co;
    	
	(void)memset(&data, 0, sizeof(data));
	
	if ((*ch->ch_db->get)(ch->ch_db, key, &data, 0))
		return (NULL);
	
	if ((*ch->ch_db->del)(ch->ch_db, key, 0))
		return (NULL);
		
	co = data.data;
		
	TAILQ_REMOVE(&ch->ch_hd, co, co_next);
		
	return (co);
}

void *
c_cache_fn(c_cache_fn_t fn, struct c_cache *ch, void *arg)
{
	struct c_obj *co;	
	DBT key;

	if ((co = arg) == NULL)
	    return (NULL);
	
	key.data = &co->co_id;
	key.size = sizeof(co->co_id);
	
	return ((*fn)(ch, &key, arg));
}

/*
 * Release by in-memory db(3) bound ressources,
 * if all objects were released previously.
 */
int
c_cache_free(struct c_cache *ch)
{
	if (ch == NULL)
		return (-1);

	if (ch->ch_db) { 
        if (!TAILQ_EMPTY(&ch->ch_hd))
		    return (-1);
		
	    if ((*ch->ch_db->close)(ch->ch_db))
		    return (-1);
		
	    ch->ch_db = NULL;
	}	
	return (0);
}

int 
c_base_class_fini(void)
{

	return (c_class_fini(&c_base_class));	
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
c_nop_fini(void *arg)
{

	return (-1);	
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

	return (NULL);
}

static int 	
c_nop_lock(void *arg)
{

    return (-1);
}

static int 	
c_nop_unlock(void *arg)
{

    return (-1);
}

static int 	
c_nop_sleep(struct c_methods *cm, void *arg)
{

    return (-1);
}

static int 	
c_nop_wakeup(struct c_methods *cm, void *arg)
{

    return (-1);
}


static int  
c_nop_wait(struct c_methods *cm, u_int ts, void *arg)
{

    return (-1);
}

static int 	
c_nop_stop(void *arg)
{

    return (-1);
}

static int 	
c_nop_destroy(void *arg0, void *arg1)
{

	return (-1);
}


