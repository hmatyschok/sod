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
#include "c_signal.h"

/*
 * Component, performs signal handling.
 *
 * XXX: under construction...
 */

struct c_signal_softc {
    struct c_thr     sc_thr;     /* binding, pthread(3) */
#define sc_id     sc_thr.ct_co.co_id
#define sc_len     sc_thr.ct_co.co_len    
    struct sigaction    sc_sigaction;
    sigset_t    sc_sigset;
};
#define C_SIGNAL_CLASS     1464266531
#define C_SIGNAL_LEN (sizeof(struct c_signal_softc))

static void *     c_signal_start(void *); 
static int     c_signal_stop(void *);

static void *     c_signal_create(void);
static int     c_signal_sigmask(int, void *);
static int     c_signal_destroy(void *); 

/******************************************************************************
 * Class-attributes.
 ******************************************************************************/
 
static struct c_signal c_signal_methods = {
    .c_signal_create         = c_signal_create,
    .c_signal_sigmask        = c_signal_sigmask,
    .c_signal_destroy     = c_signal_destroy,
};

static struct c_class c_signal_class = {
    .c_co = {
        .co_id         = C_SIGNAL_CLASS,
        .co_len         = C_SIGNAL_LEN,
    },
    .c_public         = &c_signal_methods,
};

/******************************************************************************
 * Class-methods.
 ******************************************************************************/

/*
 * Initialize class properties and return public interface.
 */
 
struct c_signal * 
c_signal_class_init(void)
{
    struct c_class *this;
    struct c_methods *cm;

    this = &c_signal_class;

   if (c_thr_class_init(this))
        return (NULL);

    cm = &this->c_base;
    cm->cm_start = c_signal_start;
    cm->cm_stop = c_signal_stop;
    
    return (this->c_public);    
}

/*
 * Unregisters class at parent class, if there are no running instances. 
 */

int  
c_signal_class_fini(void)
{
    struct c_class *this;

    this = &c_signal_class;
    
    return (c_thr_class_fini(this)); 
}

/******************************************************************************
 * Private methods.
 ******************************************************************************/

/*
 * By pthread_create(3) called start_routine.
 */
static void *
c_signal_start(void *arg)
{
    struct c_signal_softc *sc;
    int sig;
    
    if ((sc = arg) == NULL)
        goto out;
            
    for (;;) {
        if (sigwait(&sc->sc_sigset, &sig) != 0)
            errx(EX_OSERR, "Can't select signal set");
/*
 * XXX: this will be replaced by callback...
 */
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
c_signal_stop(void *arg)
{

    return (0);
}

/******************************************************************************
 * Public methods.
 ******************************************************************************/

/*
 * Ctor.
 */
static void *
c_signal_create(void) 
{
    struct c_class *this;
    struct c_methods *cm;
    struct c_signal_softc *sc;

    this = &c_signal_class;
    cm = &this->c_base;
    
    if ((sc = (*cm->cm_create)(this)) == NULL)
        goto bad;
    
    if (sigemptyset(&sc->sc_sigaction.sa_mask) < 0)
        goto bad1;
    
    if (sigfillset(&sc->sc_sigset) < 0)
        goto bad1;
    
    return (&sc->sc_thr);
bad1:    
    (void)(*cm->cm_destroy)(this, sc);
bad:
    return (NULL);
}

/*
 * Applies sigmask on calling pthread(3).
 */
static int 
c_signal_sigmask(int how, void *arg) 
{ 
    struct c_class *this;
    struct c_methods *cm;
    struct c_signal_softc *sc;
   
    this = &c_signal_class;
    cm = &this->c_base;
  
    sc = (*cm->cm_get)(&this->c_instances, arg);
    
    if (sc == NULL)
        return (-1);
    
    switch (how) {
    case SIG_BLOCK:
    case SIG_UNBLOCK:
    case SIG_SETMASK:
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
c_signal_destroy(void *arg) 
{
    struct c_thr *thr;
    struct c_class *this;
    struct c_methods *cm;
    
    if ((thr = arg) == NULL)
        return (-1);
    
    this = &c_signal_class;
    cm = &this->c_base;
    
    return ((*cm->cm_destroy)(this, thr));
}


