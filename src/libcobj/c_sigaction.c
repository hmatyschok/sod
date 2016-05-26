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
#include "c_sigaction.h"

/*
 * Component, performs signal handling.
 */

struct c_sigaction_softc {
	struct c_thr 	sc_thr; 	/* binding, pthread(3) */
#define sc_id 	sc_thr.ct_co.co_id
#define sc_len 	sc_thr.ct_co.co_len	
	sigset_t    sc_sigset;		
};
#define C_SIGACTION_CLASS 	1464266531
#define C_SIGACTION_LEN (sizeof(struct c_sigaction_softc))

static void * 	c_sigaction_start(void *); 
static int     c_sigaction_stop(void *);

static void * 	c_sigaction_create(void);
static int 	c_sigaction_add(int, void *);
static int 	c_sigaction_destroy(void *); 

/******************************************************************************
 * Class-attributes.
 ******************************************************************************/
 
static struct c_sigaction c_sigaction_methods = {
	.c_sigaction_create 		= c_sigaction_create,
	.c_sigaction_add        = c_sigaction_add,
	.c_sigaction_destroy 	= c_sigaction_destroy,
};

static struct c_class c_sigaction_class = {
	.c_co = {
		.co_id 		= C_SIGACTION_CLASS,
		.co_len 		= C_SIGACTION_LEN,
	},
	.c_public 		= &c_sigaction_methods,
};

/******************************************************************************
 * Class-methods.
 ******************************************************************************/

/*
 * Initialize class properties and return public interface.
 */
 
struct c_sigaction * 
c_sigaction_class_init(void)
{
	struct c_class *this;
	struct c_methods *cm;

	this = &c_sigaction_class;

	if ((cm = c_base_class_init()) == NULL)
		return (NULL);
	
	if ((cm = (*cm->cm_init)(this)) == NULL)
		return (NULL);

	cm->cm_start = c_sigaction_start;
	cm->cm_stop = c_sigaction_stop;
	
	return (this->c_public);	
}

/*
 * Unregisters class at parent class, if there are no running instances. 
 */

int  
c_sigaction_class_fini(void)
{
	struct c_class *this;
	struct c_methods *cm;

	this = &c_sigaction_class;
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
c_sigaction_create(void) 
{
	struct c_class *this;
	struct c_methods *cm;
	struct c_sigaction_softc *sc;

	this = &c_sigaction_class;
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
c_sigaction_add(int how, void *arg) 
{ 
    struct c_thr *thr;
    struct c_class *this;
    struct c_sigaction_softc *sc;
	
	if ((thr = arg) == NULL)
	    return (-1);
    
	this = &c_sigaction_class;
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
c_sigaction_destroy(void *arg) 
{
	struct c_thr *thr;
	struct c_class *this;
	struct c_methods *cm;
	
	this = &c_sigaction_class;
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
c_sigaction_start(void *arg)
{
    struct c_sigaction_softc *sc;
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
c_sigaction_stop(void *arg)
{

    return (0);
}


