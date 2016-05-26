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

#include <err.h>
#include <signal.h>
#include <stdlib.h>
#include <sysexits.h>

#include "c_obj.h"
#include "c_sigset.h"

/*
 * Component, performs signal handling.
 */

struct c_sigset_softc {
	struct c_thr 	sc_thr; 	/* binding, pthread(3) */
#define sc_id 	sc_thr.ct_co.co_id
#define sc_len 	sc_thr.ct_co.co_len	
	sigset_t    sc_sigset;		
};
#define C_SIGSET_CLASS 	1464266531
#define C_SIGSET_LEN (sizeof(struct c_sigset_softc))

static void * 	c_sigset_start(void *); 
static int     c_sigset_stop(void *);

static void * 	c_sigset_create(void);
static int 	c_sigset_add(int, void *);
static int 	c_sigset_destroy(void *); 

/******************************************************************************
 * Class-attributes.
 ******************************************************************************/
 
static struct c_sigset c_sigset_methods = {
	.c_sigset_create 		= c_sigset_create,
	.c_sigset_add        = c_sigset_add,
	.c_sigset_destroy 	= c_sigset_destroy,
};

static struct c_class c_sigset_class = {
	.c_co = {
		.co_id 		= C_SIGSET_CLASS,
		.co_len 		= C_SIGSET_LEN,
	},
	.c_public 		= &c_sigset_methods,
};

/******************************************************************************
 * Class-methods.
 ******************************************************************************/

/*
 * Initialize class properties and return public interface.
 */
 
struct c_sigset * 
c_sigset_class_init(void)
{
	struct c_class *this;
	struct c_methods *cm;

	this = &c_sigset_class;

	if ((cm = c_base_class_init()) == NULL)
		return (NULL);
	
	if ((cm = (*cm->cm_init)(this)) == NULL)
		return (NULL);

	cm->cm_start = c_sigset_start;
	cm->cm_stop = c_sigset_stop;
	
	return (this->c_public);	
}

/*
 * Unregisters class at parent class, if there are no running instances. 
 */

int  
c_sigset_class_fini(void)
{
	struct c_class *this;
	struct c_methods *cm;

	this = &c_sigset_class;
	cm = &this->c_base;
	
	return ((*cm->cm_fini)(this));	
}

/******************************************************************************
 * Public methods.
 ******************************************************************************/

/*
 * Ctor.
 */
static void *
c_sigset_create(void) 
{
	struct c_class *this;
	struct c_methods *cm;
	struct c_sigset_softc *sc;

	this = &c_sigset_class;
	cm = &this->c_base;
	
	if ((sc = (*cm->cm_create)(this)) == NULL)
	    return (NULL);
	
	if (sigfillset(&sc->sc_sigset) < 0) {
        (void)(*cm->cm_destroy)(this, sc);
		return (NULL);
    }
	return (&sc->sc_thr);
}

/*
 * Add signal on sigset.
 */
static int 
c_sigset_add(int how, void *arg) 
{ 
    struct c_thr *thr;
    struct c_class *this;
    struct c_sigset_softc *sc;
	
	if ((thr = arg) == NULL)
	    return (-1);
    
	this = &c_sigset_class;
	sc = c_cache_fn(c_cache_get, &this->c_instances, thr);
	
	if (sc == NULL)
	    return (-1);
	
	switch (how) {
	case SIGHUP:
	case SIGINT:
	case SIGKILL:	
	case SIGTERM:
		break;
	default:	
		return (-1);
	}	
	return (pthread_sigmask(how, &sc->sc_sigset, NULL));
}

/*
 * Dtor.
 */
static int 
c_sigset_destroy(void *arg) 
{
	struct c_thr *thr;
	struct c_class *this;
	struct c_methods *cm;
	
	this = &c_sigset_class;
	cm = &this->c_base;
	
	return ((*cm->cm_destroy)(this, thr));
}

/******************************************************************************
 * Private methods, implementing pthread(3) life-cycle.
 ******************************************************************************/

/*
 * By pthread_create(3) called start_routine.
 */
static void *
c_sigset_start(void *arg)
{
    struct c_sigset_softc *sc;
	int sig;
	
	if ((sc = arg) == NULL)
	    goto out;
			
	for (;;) {
		if (sigwait(&sc->sc_sigset, &sig) != 0)
			errx(EX_OSERR, "Can't select signal set");

		switch (sig) {
		case SIGHUP:
		case SIGINT:
		case SIGKILL:	
		case SIGTERM:
			exit(EX_OK);
			break;
		default:	
			break;
		}	
	}
out:	
	return (NULL);
}
 
/*
 * Implecitely called cleanup handler.
 */
static int  
c_sigset_stop(void *arg)
{

    return (0);
}


