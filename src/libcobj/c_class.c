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
 * Implements set of abstract classes.
 */
 
/* 
 * XXX: I've planned to divide the System into partitons:
 * XXX:
 * XXX:  #1 Base classes, set contains non-threaded instances.
 * XXX:
 * XXX:  #2 Threaded Classes, set contains by pthread(3) 
 * XXX:     covered instances.
 */

static int  c_children_free(struct c_class *);
static int  c_instances_free(struct c_class *);

static void *   c_cache_add(void *, void *);
static void *   c_cache_get(void *, void *);
static void *   c_cache_del(void *, void *);

static int    c_class_init(void *, void *);
static int     c_class_fini(void *, void *);

static int  c_base_lock(void *);
static int  c_base_unlock(void *);

static void *     c_thr_create(void *);
static int  c_thr_lock(void *);
static int  c_thr_unlock(void *);
static int  c_thr_wakeup(void *, void *);
static int  c_thr_sleep(void *, void *);
static int  c_thr_wait(void *, u_int, void *);
static int     c_thr_destroy(void *, void *);

static void *     c_nop_create(void *);
static void *     c_nop_start(void *);

static int  c_nop_lock(void *);
static int  c_nop_unlock(void *);

static int  c_nop_sleep(void *, void *);
static int  c_nop_wakeup(void *, void *);
static int  c_nop_wait(void *, u_int, void *);

static void     c_nop_stop(void *);
static int     c_nop_destroy(void *, void *);

static void *   c_nop_add(void *, void *);
static void *   c_nop_del(void *, void *);
static void *   c_nop_get(void *, void *);

/******************************************************************************
 * Generic class-attributes.
 ******************************************************************************/

/*
 * Interface implements null-operations.
 */ 
static struct c_methods c_nop = {
    .cm_co = {
        .co_id         = C_NOP_METHODS,
        .co_len         = C_METHODS_LEN,
    },
    .cm_create         = c_nop_create,
    .cm_start         = c_nop_start,
    .cm_lock         = c_nop_lock,    
    .cm_unlock         = c_nop_unlock,
    .cm_wakeup       = c_nop_wakeup,
    .cm_sleep       = c_nop_sleep,
    .cm_wait        = c_nop_wait,
    .cm_stop         = c_nop_stop,
    .cm_destroy         = c_nop_destroy,
    .cm_add         = c_cache_add,
    .cm_del         = c_cache_del,
    .cm_get         = c_cache_get,        
}; 

/*
 * Interface implements base methods for class 
 * denotes set contains non-threaded instances.  
 */
static struct c_methods c_base = {
    .cm_co = {
        .co_id         = C_BASE_METHODS,
        .co_len         = C_METHODS_LEN,
    },
    .cm_create         = c_nop_create,
    .cm_start         = c_nop_start,
    .cm_lock         = c_base_lock,    
    .cm_unlock         = c_base_unlock,
    .cm_wakeup       = c_nop_wakeup,
    .cm_sleep       = c_nop_sleep,
    .cm_wait        = c_nop_wait,
    .cm_stop         = c_nop_stop,
    .cm_destroy         = c_nop_destroy,
    .cm_add         = c_cache_add,
    .cm_del         = c_cache_del,
    .cm_get         = c_cache_get,
}; 

/*
 * Interface implements base methods for class 
 * denotes set contains by pthread(3) covered
 * instances.  
 */
static struct c_methods c_thr = {
    .cm_co = {
        .co_id         = C_THR_METHODS,
        .co_len         = C_THR_LEN,
    },
    .cm_create         = c_thr_create,
    .cm_start         = c_nop_start,
    .cm_lock       = c_thr_lock,
    .cm_unlock       = c_thr_unlock,
    .cm_sleep       = c_thr_sleep,
    .cm_wakeup      = c_thr_wakeup,
    .cm_wait        = c_thr_wait,
    .cm_stop         = c_nop_stop,
    .cm_destroy         = c_thr_destroy,
    .cm_add         = c_cache_add,
    .cm_del         = c_cache_del,
    .cm_get         = c_cache_get,
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
        .co_id         = C_BASE_CLASS,
        .co_len         = C_BASE_LEN,
    },
};

static struct c_class c_thr_class = {
    .c_co = {
        .co_id         = C_THR_CLASS,
        .co_len         = C_THR_LEN,
    },
};

int 
c_base_class_init(void *arg)
{
    struct c_class *cls0;
    
    cls0 = &c_base_class;
    
    if ((cls0->c_flags & C_INIT) ^ C_INIT) 
        cls0->c_base = c_base;
    
    return (c_class_init(cls0, arg));    
}

int 
c_base_class_fini(void *arg)
{
    struct c_class *cls0;
    
    cls0 = &c_base_class;

    return (c_class_fini(cls0, arg));    
}

int 
c_thr_class_init(void *arg)
{
    struct c_class *cls0;
    
    cls0 = &c_thr_class;
    
    if ((cls0->c_flags & C_INIT) ^ C_INIT) 
        cls0->c_base = c_thr;
    
    return (c_class_init(cls0, arg));    
}

int 
c_thr_class_fini(void *arg)
{
    struct c_class *cls0;
    
    cls0 = &c_thr_class;
    
    return (c_class_fini(cls0, arg));    
}

/******************************************************************************
 * Private class-methods.
 ******************************************************************************/

/*
 * Insert object.
 */
static void *
c_cache_add(void *arg0, void *arg1)
{    
    struct c_obj *co;
    struct c_cache *ch;
    
    if ((co = arg1) == NULL)
        return (NULL); 
     
    if ((ch = arg0) == NULL)
        return (NULL);
     
    TAILQ_INSERT_TAIL(ch, co, co_next);    
    
    return (co);
}

/*
 * Find requested object.
 */
static void *     
c_cache_get(void *arg0, void *arg1)
{    
    struct c_obj *co, *co_tmp, *key;
    struct c_cache *ch;
    
    if ((key = arg1) == NULL) 
        return (NULL);
 
    if ((ch = arg0) == NULL)
        return (NULL);   
 
    TAILQ_FOREACH_SAFE(co, ch, co_next, co_tmp) {
        if (co->co_id == key->co_id) 
            break;
    } 
    return (co);
}

/*
 * Fetch requested object.
 */
static void *     
c_cache_del(void *arg0, void *arg1)
{    
    struct c_obj *co;
    struct c_cache *ch;
    
    if ((co = arg1) == NULL)
        return (NULL); 
     
    if ((ch = arg0) == NULL)
        return (NULL);
    
    if ((co = c_cache_get(ch, co)) != NULL)
        TAILQ_REMOVE(ch, co, co_next);
    
    return (co);
}

/*
 * Finalize children. This routine is called 
 * during runtime of c_class_fini.
 */
static int 
c_children_free(struct c_class *cls)
{
    struct c_obj *co;

    if (cls == NULL)
        return (-1);

    while (!TAILQ_EMPTY(&cls->c_children)) {
        co = TAILQ_FIRST(&cls->c_children);
        
        if (c_class_fini(cls, co))
            return (-1);
    }
    return (0);
}

/*
 * Finalize instances maps to focussed class.
 */
static int 
c_instances_free(struct c_class *cls)
{
    struct c_obj *co;

    if (cls == NULL)
        return (-1);

    while (!TAILQ_EMPTY(&cls->c_instances)) {
        co = TAILQ_FIRST(&cls->c_instances);
        
        if ((*cls->c_base.cm_destroy)(cls, co))
            return (-1);
    }
    return (0);
}

/*
 * Initialize class.
 */

static int
c_class_init(void *arg0, void *arg1)
{
    struct c_class *cls0;   /* base class */
    struct c_class *cls;    /* child */   
    
    if ((cls = arg1) == NULL) 
        cls = arg0;
     
    if (cls == NULL)
        return (-1);
    
    if ((cls0 = arg0) == NULL)
        return (-1);
    
    if ((cls->c_flags & C_INIT) ^ C_INIT) {
/*
 * XXX: This might be refactored as generic implementation.
 */
        TAILQ_INIT(&cls->c_children);
        TAILQ_INIT(&cls->c_instances);
       
        if (cls != cls0) { 
/*
 * Register child by its parent.
 */
            if (c_cache_add(&cls0->c_children, cls) == NULL) 
                return (-1);
            
            cls->c_base = cls0->c_base;
        }
        cls->c_flags |= C_INIT;
    }
    
#ifdef C_OBJ_DEBUG        
syslog(LOG_DEBUG, "%s: %ld\n", __func__, cls->c_id);
#endif /* C_OBJ_DEBUG */

    return (0);
}

/*
 * Finalize class, if any instance was 
 * released then focussed class might
 * be unregistered by its parent.
 */
static int 
c_class_fini(void *arg0, void *arg1)
{
    struct c_class *cls0;
    struct c_class *cls;
    
    if ((cls = arg1) == NULL) 
        cls = arg0;
     
    if (cls == NULL)
        return (-1);
    
    if ((cls0 = arg0) == NULL)
        return (-1);
    
    if (cls->c_flags & C_INIT) {
/*
 * Releases enqueued items.
 */     
        if (c_children_free(cls))
            return (-1);

        if (c_instances_free(cls)) 
            return (-1);

        if (cls != cls0) { 
/*
 * Unregister cls by its parent cls0.
 */            
            if (c_cache_del(&cls0->c_children, cls) == NULL) 
                return (-1);
            
            cls->c_base = c_nop;
        }
        cls->c_flags &= ~C_INIT;    
    }
        
#ifdef C_OBJ_DEBUG        
syslog(LOG_DEBUG, "%s: %ld\n", __func__, cls->c_id);
#endif /* C_OBJ_DEBUG */

    return (0);    
}

/******************************************************************************
 * Protected methods, c_thread_class
 ******************************************************************************/

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
    struct c_thr *thr;
    struct c_class *cls;
/*
 * Apply various condition tests.
 */    
    if ((cls = arg) == NULL)
        return (NULL);  
/*
 * An abstract component cannot instantiate itself.
 */
    if (cls->c_len < c_thr_class.c_len)
        return (NULL);
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
 * On success, create running pthread(3) instance.
 */    
    if (pthread_create(&thr->ct_tid, NULL, cls->c_base.cm_start, thr)) 
        goto bad2;

    (void)memcpy(&thr->ct_id, thr->ct_tid, sizeof(thr->ct_id));
    
    thr->ct_len = cls->c_len;
    
    if (c_cache_add(&cls->c_instances, thr) == NULL) 
        goto bad3;

#ifdef C_OBJ_DEBUG        
syslog(LOG_DEBUG, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */    
    
out:        
    return (thr);
bad3:    
    (void)pthread_cancel(thr->ct_tid);
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
c_thr_sleep(void *cm0, void *arg)
{
    struct c_thr *thr;
    struct c_methods *cm;
    
    if ((thr = arg) == NULL) 
        return (-1);
    
    cm = (cm0 == NULL) ? &c_thr_class.c_base : cm0;
 
#ifdef C_OBJ_DEBUG        
syslog(LOG_DEBUG, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */ 
    
    (void)(*cm->cm_lock)(arg);
    (void)pthread_cond_wait(&thr->ct_cv, &thr->ct_mtx);

    return (0);
}

/*
 * Continue stalled pthread(3) execution.
 */ 
static int 
c_thr_wakeup(void *cm0, void *arg)
{
    struct c_thr *thr;
    struct c_methods *cm;
    
    if ((thr = arg) == NULL) 
        return (-1);
    
    cm = (cm0 == NULL) ? &c_thr_class.c_base : cm0;
    
    (void)pthread_cond_signal(&thr->ct_cv);
    (void)(*cm->cm_unlock)(arg);

#ifdef C_OBJ_DEBUG        
syslog(LOG_DEBUG, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */ 

    return (0);
}

/*
 * Fell asleep for ts seconds.
 */
static int 
c_thr_wait(void *cm0, u_int ts, void *arg)
{
    struct c_thr *thr;
    struct c_methods *cm;
    
    u_int uts;    
    
    struct timespec ttw;
    struct timeval x;
    int eval = -1;
    
    if ((thr = arg) == NULL) 
        goto out;
    
    cm = (cm0 == NULL) ? &c_thr_class.c_base : cm0;
    
    if ((uts = (ts * 1000)) == 0)
        goto out;
    
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
    struct c_class *cls;
    struct c_thr *thr;

    if ((thr = arg1) == NULL)    
        return (-1);
 
    if ((cls = arg0) == NULL)
        return (-1);
/*
 * Finalize properties at focussed instance.
 */
    (*cls->c_base.cm_stop)(thr);
/*
 * Release pthread(3). This operation can't fail because
 * returned ESRCH means that there was no pthread(3). 
 */    
    (void)pthread_cancel(thr->ct_tid);
    (void)pthread_cond_destroy(&thr->ct_cv);
    (void)pthread_mutex_destroy(&thr->ct_mtx);
/*
 * Release object from database, if any.
 */    
    if ((thr = c_cache_del(&cls->c_instances, thr)) != NULL)
        free(thr);

#ifdef C_OBJ_DEBUG        
syslog(LOG_DEBUG, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */    

    return (0);
}

/******************************************************************************
 * Protected methods, c_base_class
 ******************************************************************************/

/*
 * XXX: incomplete...
 */

/*
 * Lock instance.
 */
static int 
c_base_lock(void *arg)
{
    struct c_base *base;
    
    if ((base = arg) == NULL) 
        return (-1);
    
    if ((base->ct_flags & C_LOCKED) ^ C_LOCKED) {
        if (sem_wait(base->cb_sem))
            return (-1);    
    
        base->ct_flags |= C_LOCKED;
    }
    return (0);
}

/*
 * Unlock instance.
 */
static int 
c_base_unlock(void *arg)
{
    struct c_base *base;
    
    if ((base = arg) == NULL) 
        return (-1);
    
    if (base->ct_flags & C_LOCKED) {
        if (sem_post(base->cb_sem))
            return (-1);    
    
        base->ct_flags &= ~C_LOCKED;
    }
    return (0);
}


/******************************************************************************
 * Protected methods, null-operations
 ******************************************************************************/

static void *
c_nop_create(void *arg __unused)
{

    return (NULL);
}

static void *     
c_nop_start(void *arg __unused)
{

    return (NULL);
}

static int     
c_nop_lock(void *arg __unused)
{

    return (-1);
}

static int     
c_nop_unlock(void *arg __unused)
{

    return (-1);
}

static int     
c_nop_sleep(void *cm0 __unused, void *arg __unused)
{

    return (-1);
}

static int     
c_nop_wakeup(void *cm0 __unused, void *arg __unused)
{

    return (-1);
}


static int  
c_nop_wait(void *cm0 __unused, u_int ts __unused , void *arg __unused)
{

    return (-1);
}

static void     
c_nop_stop(void *arg __unused)
{

}

static int     
c_nop_destroy(void *arg0 __unused, void *arg1 __unused)
{

    return (-1);
}


static void * 
c_nop_add(void *arg0 __unused, void *arg1 __unused)
{
 
    return (NULL);
}

static void * 
c_nop_del(void *arg0 __unused, void *arg1 __unused)
{
 
    return (NULL);
}

static void * 
c_nop_get(void *arg0 __unused, void *arg1 __unused)
{
 
    return (NULL);
}



