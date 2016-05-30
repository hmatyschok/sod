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
 * version=0.2
 */

#include <string.h>
#include <stdlib.h>

#include "c_obj.h"
#include "c_obj_db.h"

/*
 * In-memory db(3) implements hash table holds non-threaded objects.
 */

struct c_obj_db_softc {
    struct c_thr     sc_thr;     /* binding, pthread(3) */
#define sc_id     sc_thr.ct_co.co_id
#define sc_len     sc_thr.ct_co.co_len    
    DB  *sc_db;
};
#define C_OBJ_DB_CLASS     1464425467
#define C_OBJ_DB_LEN (sizeof(struct c_obj_db_softc))

static void *     c_obj_db_start(void *); 
static int     c_obj_db_stop(void *);

static void *     c_obj_db_create(void);
static void *     c_obj_db_add(void *, void *);
static void *     c_obj_db_get(void *, void *);
static void *     c_obj_db_del(void *, void *);
static int     c_obj_db_destroy(void *); 

/******************************************************************************
 * Class-attributes.
 ******************************************************************************/
 
static struct c_obj_db c_obj_db_methods = {
    .c_obj_db_create         = c_obj_db_create,
    .c_obj_db_add        = c_obj_db_add,
    .c_obj_db_get        = c_obj_db_get,
    .c_obj_db_del        = c_obj_db_del,
    .c_obj_db_destroy     = c_obj_db_destroy,
};

static struct c_class c_obj_db_class = {
    .c_co = {
        .co_id         = C_OBJ_DB_CLASS,
        .co_len         = C_OBJ_DB_LEN,
    },
};

/******************************************************************************
 * Class-methods.
 ******************************************************************************/

/*
 * Initialize class properties and return public interface.
 */
 
struct c_obj_db * 
c_obj_db_class_init(void)
{
    struct c_class *this;
    
    if (c_thr_class_init(NULL))
        return (NULL);
    
    this = &c_obj_db_class;
    
    if (c_thr_class_init(this))
        return (NULL);

    this->c_base.cm_start = c_obj_db_start;
    this->c_base.cm_stop = c_obj_db_stop;
    
    return (&c_obj_db_methods);    
}

/*
 * Unregisters class at parent class, if there are no running instances. 
 */

int  
c_obj_db_class_fini(void)
{
    struct c_class *this;

    this = &c_obj_db_class;

    return (c_thr_class_fini(this));     
}

/******************************************************************************
 * Private methods.
 ******************************************************************************/

/*
 * By pthread_create(3) called start_routine.
 */
static void *
c_obj_db_start(void *arg)
{
    struct c_obj_db_softc *sc;
    struct c_class *this;
    
    if ((sc = arg) == NULL)
        goto out;
    
    sc->sc_db = dbopen(NULL, O_RDWR, 0, DB_HASH, NULL);

    if (sc->sc_db == NULL)
        goto out;
    
    this = &c_obj_db_class;
/*
 * On success, enter infinite loop and fell asleep.
 */    
    for (;;) {
        if ((*this->c_base.cm_sleep)(&this->c_base, sc))
            (void)(*this->c_base.cm_destroy)(this, sc);
    }    
out:    
    return (NULL);
}

/*
 * Implecitely called cleanup handler.
 */
static int  
c_obj_db_stop(void *arg)
{
    struct c_obj_db_softc *sc = NULL;

    if ((sc = arg) == NULL) 
        return (-1);

    if (sc->sc_db)
        (void)(*sc->sc_db->close)(sc->sc_db);

    return (0);
}

/******************************************************************************
 * Public methods.
 ******************************************************************************/

/*
 * Ctor.
 */
static void *
c_obj_db_create(void) 
{
    struct c_class *this;
    struct c_obj_db_softc *sc;

    this = &c_obj_db_class;
    sc = (*this->c_base.cm_create)(this);
    
    if (sc == NULL) {
        (void)(*this->c_base.cm_destroy)(this, sc);
         return (NULL);
    }
    return (&sc->sc_thr);
}

/*
 * Create instance by template.
 */
static void *
c_obj_db_add(void *arg0, void *arg1) 
{ 
    struct c_class *this;
    struct c_obj_db_softc *sc;

    this = &c_obj_db_class;
    sc = (*this->c_base.cm_get)(&this->c_instances, arg1);
    
    if (sc == NULL)
        return (NULL);
/*
 * Release stalled execution.
 */ 
    (void)(*this->c_base.cm_wakeup)(&this->c_base, sc);
 
    return (c_obj_fn(c_obj_add, sc->sc_db, arg0));
}

/*
 * Get instance.
 */
static void *
c_obj_db_get(void *arg0, void *arg1) 
{ 
    struct c_class *this;
    struct c_obj_db_softc *sc;

    this = &c_obj_db_class;
    sc = (*this->c_base.cm_get)(&this->c_instances, arg1);
    
    if (sc == NULL)
        return (NULL);
/*
 * Release stalled execution.
 */ 
    (void)(*this->c_base.cm_wakeup)(&this->c_base, sc);
 
    return (c_obj_fn(c_obj_get, sc->sc_db, arg0));
}

/*
 * Delete instance.
 */
static void *
c_obj_db_del(void *arg0, void *arg1) 
{
    struct c_class *this;
    struct c_obj_db_softc *sc;

    this = &c_obj_db_class;
    sc = (*this->c_base.cm_get)(&this->c_instances, arg1);
    
    if (sc == NULL)
        return (NULL);
/*
 * Release stalled execution.
 */ 
    (void)(*this->c_base.cm_wakeup)(&this->c_base, sc);
 
    return (c_obj_fn(c_obj_del, sc->sc_db, arg0));
}

/*
 * Dtor.
 */
static int 
c_obj_db_destroy(void *arg) 
{
    struct c_thr *thr;
    struct c_class *this;

    if ((thr = arg) == NULL)
        return (-1);
    
    this = &c_obj_db_class;
    
    return ((*this->c_base.cm_destroy)(this, thr));
}

