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

static int  c_base_wakeup(void *, void *);
static int  c_base_sleep(void *, void *);

static void *     c_thr_create(void *);
static int  c_thr_lock(void *);
static int  c_thr_unlock(void *);
static int  c_thr_wakeup(void *, void *);
static int  c_thr_sleep(void *, void *);
static int  c_thr_wait(time_t, void *, void *);
static int     c_thr_destroy(void *, void *);

static void *     c_nop_create(void *);
static void *     c_nop_start(void *);

static int  c_nop_lock(void *);
static int  c_nop_unlock(void *);

static int  c_nop_sleep(void *, void *);
static int  c_nop_wakeup(void *, void *);
static int  c_nop_wait(time_t, void *, void *);

static void     c_nop_stop(void *);
static int     c_nop_destroy(void *, void *);

static void *   c_nop_add(void *, void *);
static void *   c_nop_del(void *, void *);
static void *   c_nop_get(void *, void *);

/******************************************************************************
 * Generic class-attributes.
 ******************************************************************************/

static struct c_class c_nop_class = {
    .c_co = {
        .co_id         = C_NOP_CLASS,
    },
/*
 * Accessor methods for children.
 */ 
    .c_class_add    = c_nop_add,
    .c_class_del    = c_nop_del,
/*
 * Accessor methods for instances.
 */    
    .c_obj_add  = c_nop_add,
    .c_obj_del  = c_nop_del,
    .c_obj_get  = c_nop_get,
/*
 * Interface implements null-operations.
 */   
    .c_create         = c_nop_create,
    .c_start         = c_nop_start,
    .c_lock         = c_nop_lock,    
    .c_unlock         = c_nop_unlock,
    .c_wakeup       = c_nop_wakeup,
    .c_sleep       = c_nop_sleep,
    .c_wait        = c_nop_wait,
    .c_stop         = c_nop_stop,
    .c_destroy         = c_nop_destroy,
};

static struct c_class c_base_class = {
    .c_co = {
        .co_id         = C_BASE_CLASS,
        .co_len         = C_BASE_LEN,
    },
/*
 * Accessor methods for children.
 */ 
    .c_class_add    = c_cache_add,
    .c_class_del    = c_cache_del,
/*
 * Accessor methods for instances.
 */    
    .c_obj_add  = c_cache_add,
    .c_obj_del  = c_cache_del,
    .c_obj_get  = c_cache_get,
/*
 * Interface implements base methods for class 
 * denotes set contains non-threaded instances.  
 */  
    .c_create         = c_nop_create,
    .c_start         = c_nop_start,
    .c_lock         = c_nop_lock,    
    .c_unlock         = c_nop_unlock,
    .c_wakeup       = c_base_wakeup,
    .c_sleep       = c_base_sleep,
    .c_wait        = c_nop_wait,
    .c_stop         = c_nop_stop,
    .c_destroy         = c_nop_destroy,
};

static struct c_class c_thr_class = {
    .c_co = {
        .co_id         = C_THR_CLASS,
        .co_len         = C_THR_LEN,
    },
/*
 * Accessor methods for children.
 */ 
    .c_class_add    = c_cache_add,
    .c_class_del    = c_cache_del,
/*
 * Accessor methods for instances.
 */    
    .c_obj_add  = c_cache_add,
    .c_obj_del  = c_cache_del,
    .c_obj_get  = c_cache_get,
/*
 * Interface implements base methods for class 
 * denotes set contains by pthread(3) covered
 * instances.  
 */  
    .c_create         = c_thr_create,
    .c_start         = c_nop_start,
    .c_lock       = c_thr_lock,
    .c_unlock       = c_thr_unlock,
    .c_sleep       = c_thr_sleep,
    .c_wakeup      = c_thr_wakeup,
    .c_wait        = c_thr_wait,
    .c_stop         = c_nop_stop,
    .c_destroy         = c_thr_destroy,
};

int 
c_base_class_init(void *arg)
{
    struct c_class *cls0;
    
    cls0 = &c_base_class;
    
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
     
    LIST_INSERT_HEAD(ch, co, co_next);    
    
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
 
    LIST_FOREACH_SAFE(co, ch, co_next, co_tmp) {    
        
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
        LIST_REMOVE(co, co_next);
    
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

    while (!LIST_EMPTY(&cls->c_children)) {
        co = LIST_FIRST(&cls->c_children);
        
        if (c_class_fini(cls, co))
            return (-1);
    }
    LIST_INIT(&cls->c_children);
    
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

    while (!LIST_EMPTY(&cls->c_instances)) {
        co = LIST_FIRST(&cls->c_instances);
        
        if ((*cls->c_destroy)(cls, co))
            return (-1);
    }
    LIST_INIT(&cls->c_instances);
    
    return (0);
}

/*
 * A component set C is free generated by the inclusion 
 * mapping i of any x element in C into set A containing 
 * abstract components a, where C subset A.
 * 
 * Any mapping f between C and B (containing components) 
 * can be unequely extended to a morphism h between A 
 * and B of Sigma-algebras, where f < h.  
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
        LIST_INIT(&cls->c_children);
        LIST_INIT(&cls->c_instances);
       
        if (cls != cls0) { 
/*
 * Register child by its parent.
 */
            if ((*cls0->c_class_add)(&cls0->c_children, cls) == NULL) 
                return (-1);
/*
 * Accessor methods for children.
 */ 
            cls->c_class_add    = cls0->c_class_add;
            cls->c_class_del    = cls0->c_class_del; 
/*
 * Accessor methods for instances.
 */    
            cls->c_obj_add  = cls0->c_obj_add;
            cls->c_obj_del  = cls0->c_obj_del;
            cls->c_obj_get  = cls0->c_obj_get;
/*
 * Methods implements life-cycle of an instance.  
 */
            cls->c_create   = cls0->c_create;
            cls->c_start    = cls0->c_start;
            cls->c_lock     = cls0->c_lock;
            cls->c_unlock   = cls0->c_unlock;
            cls->c_sleep    = cls0->c_sleep;    
            cls->c_wakeup   = cls0->c_wakeup;    
            cls->c_wait     = cls0->c_wait;
            cls->c_stop     = cls0->c_stop;
            cls->c_destroy  = cls0->c_destroy;
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
    struct c_class *nop;
    
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
            if ((*cls0->c_class_del)(&cls0->c_children, cls) == NULL) 
                return (-1);
            
            nop = &c_nop_class;
/*
 * Accessor methods for children.
 */ 
            cls->c_class_add    = nop->c_class_add;
            cls->c_class_del    = nop->c_class_del; 
/*
 * Accessor methods for instances.
 */    
            cls->c_obj_add  = nop->c_obj_add;
            cls->c_obj_del  = nop->c_obj_del;
            cls->c_obj_get  = nop->c_obj_get;
/*
 * Map null-operations.
 */            
            cls->c_create   = nop->c_create;
            cls->c_start    = nop->c_start;
            cls->c_lock     = nop->c_lock;
            cls->c_unlock   = nop->c_unlock;
            cls->c_sleep    = nop->c_sleep;    
            cls->c_wakeup   = nop->c_wakeup;    
            cls->c_wait     = nop->c_wait;
            cls->c_stop     = nop->c_stop;
            cls->c_destroy  = nop->c_destroy;
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

static void *
c_thr_create(void *arg)
{
    struct c_class *cls0;
    struct c_class *cls;
    struct c_thr *thr;
    
    cls0 = &c_thr_class;
/*
 * Apply various condition tests.
 */    
    if ((cls = arg) == NULL)
        return (NULL);  
/*
 * An abstract component cannot instantiate itself.
 */
    if (cls->c_len < cls0->c_len)
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
    if (pthread_create(&thr->ct_tid, NULL, cls->c_start, thr)) 
        goto bad2;

    (void)memcpy(&thr->ct_id, thr->ct_tid, sizeof(thr->ct_id));
    
    thr->ct_len = cls->c_len;
    
    if ((*cls->c_obj_add)(&cls->c_instances, thr) == NULL) 
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
/*
 * Calling pthread(3) blocks, until mutual exclusion is available. 
 */
    return (pthread_mutex_lock(&thr->ct_mtx));
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
        
    return (pthread_mutex_unlock(&thr->ct_mtx));
}

/*
 * Fell asleep.
 */
static int 
c_thr_sleep(void *cls0, void *arg)
{
    struct c_thr *thr;
    struct c_class *cls;
    
    if ((thr = arg) == NULL) 
        return (-1);
    
    cls = (cls0 == NULL) ? &c_thr_class : cls0;

    if ((*cls->c_lock)(thr))
        return (-1);

    return (pthread_cond_wait(&thr->ct_cv, &thr->ct_mtx));
}

/*
 * Continue stalled pthread(3) execution.
 */ 
static int 
c_thr_wakeup(void *cls0, void *arg)
{
    struct c_thr *thr;
    struct c_class *cls;
    
    if ((thr = arg) == NULL) 
        return (-1);
    
    cls = (cls0 == NULL) ? &c_thr_class : cls0;
    
    if (pthread_cond_signal(&thr->ct_cv))
        return (-1); 

    return ((*cls->c_unlock)(thr));
}

/*
 * Fell asleep for ts seconds.
 */
static int 
c_thr_wait(time_t ts, void *cls0, void *arg)
{
    struct c_thr *thr;
    struct c_class *cls;
    
    time_t uts;    
    
    struct timeval tv;
    struct timespec abstime;
    
    if ((thr = arg) == NULL) 
        return (-1);
    
    cls = (cls0 == NULL) ? &c_thr_class : cls0;
    
    if ((uts = (ts * 1000)) == 0)
        return (-1);
    
    if (gettimeofday(&tv, NULL))
        return (-1);
 
    if ((*cls->c_lock)(thr))
        return (-1);
    
    abstime.tv_sec = tv.tv_sec + ts;
    abstime.tv_nsec = (tv.tv_usec + uts) * 1000UL;
    
    if (pthread_cond_timedwait(&thr->ct_cv, &thr->ct_mtx, &abstime))
        return (-1);

    return ((*cls->c_unlock)(thr));
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
    (*cls->c_stop)(thr);
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
    if ((thr = (*cls->c_obj_del)(&cls->c_instances, thr)) != NULL)
        free(thr);

    return (0);
}

/******************************************************************************
 * Protected methods, c_base_class
 ******************************************************************************/

/*
 * XXX: incomplete...
 */
 
/*
 * Fell asleep.
 */
static int 
c_base_sleep(void *cls0 __unused, void *arg)
{
    struct c_base *base;
    
    if ((base = arg) == NULL) 
        return (-1);

    return (sem_wait(&base->cb_sem));
}

/*
 * Continue stalled pthread(3) execution.
 */ 
static int 
c_base_wakeup(void *cls0 __unused, void *arg)
{
    struct c_base *base;
    
    if ((base = arg) == NULL) 
        return (-1);
/*
 * XXX: This is wrong, because sem_post(3) 
 * XXX: might be called during runtime of  
 * XXX: signal handler on signal(3).
 */    
    return (sem_post(&base->cb_sem));
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
c_nop_sleep(void *cls0 __unused, void *arg __unused)
{

    return (-1);
}

static int     
c_nop_wakeup(void *cls0 __unused, void *arg __unused)
{

    return (-1);
}

static int  
c_nop_wait(time_t ts __unused, void *cls0 __unused, void *arg __unused)
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



