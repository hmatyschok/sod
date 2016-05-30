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

#include <security/pam_appl.h>
#include <sys/types.h>

#include <login_cap.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "c_obj.h"
#include "c_authenticator.h"

#define    C_AUTHENTICATOR_BACKOFF_DFLT     3
#define    C_AUTHENTICATOR_RETRIES_DFLT     10

#define    C_AUTHENTICATOR_PROMPT_DFLT        "login: "
#define    C_AUTHENTICATOR_PW_PROMPT_DFLT    "Password:"

/*
 * Recursively defined callback function. 
 */
typedef long     (*ca_state_fn_t)(void *);
typedef ca_state_fn_t     (*ca_state_t)(void *);

/*
 * Component, proxyfies pam(8) based authentication service.
 */

struct ca_softc {
    struct c_thr     sc_thr;     /* binding, pthread(3) */
#define sc_id     sc_thr.ct_co.co_id
#define sc_len     sc_thr.ct_co.co_len    
    char sc_hname[C_NMAX + 1];
    char sc_uname[C_NMAX + 1];
    const char     *sc_prompt;
    const char     *sc_pw_prompt;
    
    pam_handle_t     *sc_pamh;    
    struct pam_conv     sc_pamc;     /* during transaction used variable data */ 
    struct passwd     *sc_pwd;
    
    struct c_msg     sc_buf;     /* for transaction used buffer */

    uint32_t     sc_sock_srv;     /* fd, socket, applicant */
    uint32_t     sc_sock_rmt;     /* fd, socket, applicant */
    uint32_t     sc_eval;     /* tracks rv of pam(3) method calls */        
};
#define C_AUTHENTICATOR_CLASS     1421959420
#define C_AUTHENTICATOR_LEN (sizeof(struct ca_softc))

static int     c_authenticator_conv(int, const struct pam_message **, 
    struct pam_response **, void *);
static ca_state_fn_t     c_authenticator_response(void *);
static ca_state_fn_t     c_authenticator_authenticate(void *);
static ca_state_fn_t     c_authenticator_establish(void *);

static void *     c_authenticator_start(void *); 
static int     c_authenticator_stop(void *);

static void *     c_authenticator_create(int, int);
static int     c_authenticator_join(void *);
static int     c_authenticator_destroy(void *); 

/******************************************************************************
 * Class-attributes.
 ******************************************************************************/
 
static struct c_authenticator c_authenticator_methods = {
    .ca_create         = c_authenticator_create,
    .ca_join        = c_authenticator_join,
    .ca_destroy     = c_authenticator_destroy,
};

static struct c_class c_authenticator_class = {
    .c_co = {
        .co_id         = C_AUTHENTICATOR_CLASS,
        .co_len         = C_AUTHENTICATOR_LEN,
    },
};

static const char     *ca_prompt_default = C_AUTHENTICATOR_PROMPT_DFLT;
static const char     *ca_pw_prompt_default = C_AUTHENTICATOR_PW_PROMPT_DFLT;

/******************************************************************************
 * Class-methods.
 ******************************************************************************/

/*
 * Initialize class properties and return public interface.
 */
 
struct c_authenticator * 
c_authenticator_class_init(void)
{
    if (c_thr_class_init(NULL))
        return (NULL);
    
    if (c_thr_class_init(&c_authenticator_class))
        return (NULL);

    c_authenticator_class.c_base.cm_start = c_authenticator_start;
    c_authenticator_class.c_base.cm_stop = c_authenticator_stop;

#ifdef C_OBJ_DEBUG        
syslog(LOG_DEBUG, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */
    
    return (&c_authenticator_methods);    
}

/*
 * Unregisters class at parent class, if there are no running instances. 
 */

int  
c_authenticator_class_fini(void)
{

#ifdef C_OBJ_DEBUG        
syslog(LOG_DEBUG, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */    
    
    return (c_thr_class_fini(&c_authenticator_class));    
}

/******************************************************************************
 * Private methods, implements pthread(3) life-cycle.
 ******************************************************************************/

/*
 * By pam_vpromt(3) called conversation routine.
 * This event takes place during runtime of by
 * pam_authenticate(3) called pam_get_authtok(3).
 */
static int 
c_authenticator_conv(int num_msg, const struct pam_message **msg, 
        struct pam_response **resp, void *data) 
{
    struct ca_softc *sc = NULL;
    int pam_err = PAM_AUTH_ERR;
    int p = 1, q, i, style, j;
    struct pam_response *tok;
    
    if ((sc = data) == NULL)
        p -= 2;

    if ((q = num_msg) == p) {
        if ((tok = calloc(q, sizeof(*tok))) == NULL)
            q = 0;
    } else 
        q = 0;
        
    for (i = 0; i < q; ++i) {
        style = msg[i]->msg_style;
    
        switch (style) {
        case PAM_PROMPT_ECHO_OFF:
        case PAM_PROMPT_ECHO_ON:
        case PAM_ERROR_MSG:
        case PAM_TEXT_INFO:
            break;
        default:
            style = -1;
            break;
        }    
        
        if (style < 0)
            break; 
                    
        c_msg_prepare(msg[i]->msg, C_AUTHENTICATOR_AUTH_NAK, 
            sc->sc_id, &sc->sc_buf);
/*
 * Request PAM_AUTHTOK.
 */                
        if (c_msg_fn(c_msg_send, sc->sc_sock_rmt, &sc->sc_buf) < 0)
            break;
/*
 * Await response from applicant.
 */    
        if (c_msg_fn(c_msg_recv, sc->sc_sock_rmt, &sc->sc_buf) < 0)
            break;
    
        if (sc->sc_buf.msg_id != sc->sc_id)    
            break;    
            
        if (sc->sc_buf.msg_code != C_AUTHENTICATOR_AUTH_REQ)
            break;
    
        if ((tok[i].resp = calloc(1, C_NMAX + 1)) == NULL) 
            break;
            
#ifdef C_OBJ_DEBUG
syslog(LOG_DEBUG, "%s: rx: %s\n", __func__, sc->sc_buf.msg_tok);    
#endif /* C_OBJ_DEBUG */    
                
        (void)strncpy(tok[i].resp, sc->sc_buf.msg_tok, C_NMAX);
        (void)memset(&sc->sc_buf, 0, sizeof(sc->sc_buf));
    }
    
    if (i < q) {
/*
 * Cleanup, if something went wrong.
 */
        for (j = i, i = 0; i < j; ++i) { 
            (void)memset(tok[i].resp, 0, C_NMAX);
            free(tok[i].resp);
            tok[i].resp = NULL;
        }
        (void)memset(tok, 0, q * sizeof(*tok));
        free(tok);
        tok = NULL;
    } else {
/*
 * Self explanatory.
 */        
        if (i > 0 && p > 0) 
            pam_err = PAM_SUCCESS;    
    }    
    *resp = tok;
    return (pam_err);
}

/*
 * By pthread_create(3) called start_routine.
 */
static void *
c_authenticator_start(void *arg)
{
    ca_state_t fn;
    struct ca_softc *sc;
    
    fn = NULL;
    
    if ((sc = arg) == NULL)
        goto out;
    
    if ((*c_authenticator_class.c_base.cm_sleep)
        (&c_authenticator_class.c_base, sc) == 0)
        fn = (ca_state_t)c_authenticator_establish;    

#ifdef C_OBJ_DEBUG        
syslog(LOG_DEBUG, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */    
    
    while (fn != NULL)
        fn = (ca_state_t)(*fn)(sc);
out:    
    return (arg);
}    
 
/*
 * Inital state, rx request and state transition.
 */
static ca_state_fn_t 
c_authenticator_establish(void *arg)
{
    ca_state_fn_t state = NULL;
    struct ca_softc *sc;

    if ((sc = arg) == NULL)
        goto out;
        
#ifdef C_OBJ_DEBUG        
syslog(LOG_DEBUG, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */    
    
    if (c_msg_fn(c_msg_recv, sc->sc_sock_rmt, &sc->sc_buf) < 0) 
        goto out;

    if (sc->sc_buf.msg_id != C_MSG)
        goto out;
/*
 * State transition, if any.
 */
    if (sc->sc_buf.msg_code == C_AUTHENTICATOR_AUTH_REQ) 
        state = (ca_state_fn_t)c_authenticator_authenticate;
    
    if (state == NULL)
        goto out;
/*
 * Create < hostname, user > tuple.
 */
    if (gethostname(sc->sc_hname, C_NMAX) == 0) 
        (void)strncpy(sc->sc_uname, sc->sc_buf.msg_tok, C_NMAX);
    else
        state = NULL;
out:    
    return (state);
}

/*
 * Initialize pam(8) transaction and authenticate.
 */
static ca_state_fn_t  
c_authenticator_authenticate(void *arg)
{    
    ca_state_fn_t state;
    login_cap_t *lc;
    struct ca_softc *sc;
    int retries, backoff;
    int ask = 0, cnt = 0;
    uint32_t resp;

    state = NULL;
    lc = NULL;
    
    if ((sc = arg) == NULL)
        goto out;

#ifdef C_OBJ_DEBUG        
syslog(LOG_DEBUG, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */    
    
/*
 * Parts of in login.c defined codesections are reused here.
 */    
    lc = login_getclass(NULL);
    sc->sc_prompt = login_getcapstr(lc, "login_prompt", 
        ca_prompt_default, ca_prompt_default);
    sc->sc_pw_prompt = login_getcapstr(lc, "passwd_prompt", 
        ca_pw_prompt_default, ca_pw_prompt_default);
    retries = login_getcapnum(lc, "login-retries", 
        C_AUTHENTICATOR_RETRIES_DFLT, C_AUTHENTICATOR_RETRIES_DFLT);
    backoff = login_getcapnum(lc, "login-backoff", 
        C_AUTHENTICATOR_BACKOFF_DFLT, C_AUTHENTICATOR_BACKOFF_DFLT);
    login_close(lc);
    lc = NULL;
/*
 * Verify, if username exists in passwd database. 
 */
    if ((sc->sc_pwd = getpwnam(sc->sc_uname)) != NULL) {
/*
 * Verify, if user has UID 0, because login by UID 0 is not allowed. 
 */
        if (sc->sc_pwd->pw_uid == (uid_t)0) 
            sc->sc_eval = PAM_PERM_DENIED;
        else
            sc->sc_eval = PAM_SUCCESS;
    } else 
        sc->sc_eval = PAM_USER_UNKNOWN;
    
    endpwent();
    
    if (sc->sc_eval == PAM_SUCCESS)
        ask = 1;
    
    while (ask != 0) {
/*
 * Service name for pam(8) is defined implecitely.
 */        
        sc->sc_eval = pam_start(__func__, sc->sc_uname, 
            &sc->sc_pamc, &sc->sc_pamh);

        if (sc->sc_eval == PAM_SUCCESS) {
            sc->sc_eval = pam_set_item(sc->sc_pamh, PAM_RUSER, 
                sc->sc_uname);
        }
    
        if (sc->sc_eval == PAM_SUCCESS) {
            sc->sc_eval = pam_set_item(sc->sc_pamh, PAM_RHOST, 
                sc->sc_hname);
        }
    
        if (sc->sc_eval == PAM_SUCCESS) {
            sc->sc_eval = pam_authenticate(sc->sc_pamh, 0);
/*
 * Authenticate.
 */
            
            if (sc->sc_eval == PAM_AUTH_ERR) {                
/*
 * Reenter loop, if PAM_AUTH_ERR condition halts. 
 */
                cnt += 1;    
        
                if (cnt > backoff) 
                    (*c_authenticator_class.c_base.cm_wait)
                        (&c_authenticator_class.c_base, 
                            (u_int)((cnt - backoff) * 5), sc);
        
                if (cnt >= retries)
                    ask = 0;        
    
                (void)pam_end(sc->sc_pamh, sc->sc_eval);
        
                sc->sc_pamh = NULL;
            } else
                ask = 0;    
        } else
            ask = 0;    
    }
/*
 * Create response.
 */            
    resp = C_AUTHENTICATOR_AUTH_REJ;    
    
    if (sc->sc_eval == PAM_SUCCESS) 
        resp = C_AUTHENTICATOR_AUTH_ACK;
            
    c_msg_prepare(sc->sc_uname, resp, sc->sc_id, &sc->sc_buf);
    state = (ca_state_fn_t)c_authenticator_response;
out:    
    return (state);
}

/*
 * Send response.
 */
static ca_state_fn_t  
c_authenticator_response(void *arg)
{    
    ca_state_fn_t state = NULL;
    struct ca_softc *sc;

    if ((sc = arg) == NULL)
        goto out;
        
#ifdef C_OBJ_DEBUG        
syslog(LOG_DEBUG, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */

    (void)c_msg_fn(c_msg_send, sc->sc_sock_rmt, &sc->sc_buf);
out:    
    return (state);
}

/*
 * Implecitely called cleanup handler.
 */
static int  
c_authenticator_stop(void *arg)
{
    struct ca_softc *sc = NULL;

    if ((sc = arg) == NULL) 
        return (-1);

    if (sc->sc_pamh != NULL)
        (void)pam_end(sc->sc_pamh, sc->sc_eval);

    (void)close(sc->sc_sock_rmt);

#ifdef C_OBJ_DEBUG        
syslog(LOG_DEBUG, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */

    return (0);
}

/******************************************************************************
 * Public methods.
 ******************************************************************************/

/*
 * Ctor.
 */
static void *
c_authenticator_create(int sock_srv, int sock_rmt) 
{
    struct ca_softc *sc;
    
    sc = (*c_authenticator_class.c_base.cm_create)(&c_authenticator_class);
    
    if (sc == NULL) 
        return (NULL);

    sc->sc_sock_rmt = sock_rmt;
    sc->sc_sock_srv = sock_srv;
    sc->sc_pamc.appdata_ptr = sc;
    sc->sc_pamc.conv = c_authenticator_conv;
/*
 * Release stalled execution.
 */        
    (void)(*c_authenticator_class.c_base.cm_wakeup)
        (&c_authenticator_class.c_base, sc);

#ifdef C_OBJ_DEBUG        
syslog(LOG_DEBUG, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */

    return (&sc->sc_thr);
}

/*
 * Wrapper suspends execution of calling pthread(3).
 */
static int 
c_authenticator_join(void *arg) 
{
    struct c_thr *thr;
    void *eval;
    
    if ((thr = arg) == NULL)
        return (-1);
    
    eval = NULL;
    
    return (pthread_join(thr->ct_tid, &eval));
}

/*
 * Dtor.
 */
static int 
c_authenticator_destroy(void *arg) 
{
    struct c_thr *thr;

    if ((thr = arg) == NULL)
        return (-1);
    
#ifdef C_OBJ_DEBUG        
syslog(LOG_DEBUG, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */    

    return ((*c_authenticator_class.c_base.cm_destroy)
        (&c_authenticator_class, thr));
}
