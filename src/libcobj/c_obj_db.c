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

#include "c_obj.h"
#include "c_obj_db.h"

typedef void * 	(*c_obj_fn_t)(DB *, DBT *, void *);

/*
 * In-memory db(3) implements hash table holds non-threaded objects.
 */

struct c_obj_db_softc {
    struct c_thr     sc_thr;     /* binding, pthread(3) */
#define sc_id     sc_thr.ct_co.co_id
#define sc_len     sc_thr.ct_co.co_len    
    c_obj_fn_t      sc_fn;
    void        *sc_co0;
    void        *sc_co1;
    DB  *sc_db;
};
#define C_OBJ_DB_CLASS     1464425467
#define C_OBJ_DB_LEN (sizeof(struct c_obj_db_softc))

static void *     c_obj_db_start(void *); 
static int     c_obj_db_stop(void *);

static void *   c_obj_add(DB *, DBT *, void *);
static void * 	c_obj_get(DB *, DBT *, void *);
static void * 	c_obj_del(DB *, DBT *, void *);
static void *   c_obj_fn(c_obj_fn_t, DB *, void *);

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
    .c_obj_db_destroy     = c_obj_db_destroy,
};

static struct c_class c_obj_db_class = {
    .c_co = {
        .co_id         = C_OBJ_DB_CLASS,
        .co_len         = C_OBJ_DB_LEN,
    },
    .c_public         = &c_obj_db_methods,
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
    struct c_methods *cm;

    this = &c_obj_db_class;

    if ((cm = c_base_class_init()) == NULL)
        return (NULL);
    
    if ((cm = (*cm->cm_init)(this)) == NULL)
        return (NULL);

    cm->cm_start = c_obj_db_start;
    cm->cm_stop = c_obj_db_stop;
    
    return (this->c_public);    
}

/*
 * Unregisters class at parent class, if there are no running instances. 
 */

int  
c_obj_db_class_fini(void)
{
    struct c_class *this;
    struct c_methods *cm;

    this = &c_obj_db_class;
    cm = &this->c_base;
    
    return ((*cm->cm_fini)(this));    
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
    struct c_class *this;
    struct c_methods *cm;
    struct c_obj_db_softc *sc;
    
    this = &c_obj_db_class;
    cm = &this->c_base;
    
    if ((sc = arg) == NULL)
        goto out;
    
    for (;;) {
        if ((*cm->cm_sleep)(cm, sc))
            (void)(*cm->cm_destroy)(this, sc);

        sc->sc_co1 = c_obj_fn(sc->sc_fn, sc->sc_db, sc->sc_co0); 
    }
out:    
    return (NULL);
}

/*
 * Insert object.
 */
static void *
c_obj_add(DB *db, DBT *key, void *arg)
{	
    struct c_obj *co;
    DBT data;
    
	if ((co = arg) == NULL)
	    return (NULL);

	data.data = co;
	data.size = co->co_len;
	
	if ((*db->put)(db, key, &data, 0))
		return (NULL);
	
	return (data.data);
}

/*
 * Find requested object.
 */
static void * 	
c_obj_get(DB *db, DBT *key, void *arg __unused)
{	
	DBT data;

    (void)memset(&data, 0, sizeof(data));

    if ((*db->get)(db, key, &data, 0))
        return (NULL);
	
	return (data.data);
}

/*
 * Fetch requested object.
 */
static void * 	
c_obj_del(DB *db, DBT *key, void *arg __unused)
{
	DBT data;
    	
	(void)memset(&data, 0, sizeof(data));
	
	if ((*db->get)(db, key, &data, 0))
		return (NULL);
	
	if ((*db->del)(db, key, 0))
		return (NULL);	

	return (data.data);
}

static void *
c_obj_fn(c_obj_fn_t fn, DB *db, void *arg)
{
	struct c_obj *co;	
	DBT key;

	if ((co = arg) == NULL)
	    return (NULL);
	
	key.data = &co->co_id;
	key.size = sizeof(co->co_id);
	
	return ((*fn)(db, &key, arg));
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
    struct c_methods *cm;
    struct c_obj_db_softc *sc;

    this = &c_obj_db_class;
    cm = &this->c_base;
    
    if ((sc = (*cm->cm_create)(this)) == NULL)
        goto bad;
    
    sc->sc_db = dbopen(NULL, O_RDWR, 0, DB_HASH, NULL);
		
    if (sc->sc_db == NULL)
	    goto bad1;
    
    return (&sc->sc_thr);
bad1:    
    (void)(*cm->cm_destroy)(this, sc);
bad:
    return (NULL);
}

/*
 * Create instance by template.
 */
static void *
c_obj_db_add(void *arg0, void *arg1) 
{ 
    struct c_class *this;
    struct c_methods *cm;
    struct c_obj_db_softc *sc;
 
    this = &c_obj_db_class;
    cm = &this->c_base;
    
    sc = (*cm->cm_get)(&this->c_instances, arg1);
    
    if (sc == NULL)
        return (NULL);
    
    if ((sc->sc_co0 = arg1) == NULL)
        return (NULL);
    
    sc->sc_fn = c_obj_add;
/*
 * Release stalled execution.
 */ 
    (void)(*cm->cm_wakeup)(cm, sc);
 
    return (sc->sc_co1);
}

/*
 * Get instance.
 */
static void *
c_obj_db_get(void *arg0, void *arg1) 
{ 
    struct c_class *this;
    struct c_methods *cm;
    struct c_obj_db_softc *sc;
 
    this = &c_obj_db_class;
    cm = &this->c_base;
    
    sc = (*cm->cm_get)(&this->c_instances, arg1);
    
    if (sc == NULL)
        return (NULL);
    
    if ((sc->sc_co0 = arg1) == NULL)
        return (NULL);
    
    sc->sc_fn = c_obj_get;
/*
 * Release stalled execution.
 */ 
    (void)(*cm->cm_wakeup)(cm, sc);
 
    return (sc->sc_co1);
}

/*
 * Delete instance.
 */
static void *
c_obj_db_del(void *arg0, void *arg1) 
{ 
    struct c_class *this;
    struct c_methods *cm;
    struct c_obj_db_softc *sc;
 
    this = &c_obj_db_class;
    cm = &this->c_base;
    
    sc = (*cm->cm_get)(&this->c_instances, arg1);
    
    if (sc == NULL)
        return (NULL);
    
    if ((sc->sc_co0 = arg1) == NULL)
        return (NULL);
    
    sc->sc_fn = c_obj_del;
/*
 * Release stalled execution.
 */ 
    (void)(*cm->cm_wakeup)(cm, sc);
 
    return (sc->sc_co1);
}

/*
 * Dtor.
 */
static int 
c_obj_db_destroy(void *arg) 
{
    struct c_thr *thr;
    struct c_class *this;
    struct c_methods *cm;
    
    if ((thr = arg) == NULL)
        return (-1);
    
    this = &c_obj_db_class;
    cm = &this->c_base;
    
    return ((*cm->cm_destroy)(this, thr));
}

