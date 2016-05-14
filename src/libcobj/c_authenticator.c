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

#include <security/pam_appl.h>

#include <err.h>
#include <errno.h>
#include <login_cap.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include <c_authenticator.h>

#define C_AUTHENTICATOR_CLASS 	1421959420

#define	C_AUTHENTICATOR_BACKOFF_DFLT 	3
#define	C_AUTHENTICATOR_RETRIES_DFLT 	10

#define	C_AUTHENTICATOR_PROMPT_DFLT		"login: "
#define	C_AUTHENTICATOR_PW_PROMPT_DFLT	"Password:"

#define C_AUTHENTICATOR_AUTH_REQ 	0x00000001
#define C_AUTHENTICATOR_TERM_REQ 	0x00000002

#define C_AUTHENTICATOR_AUTH_ACK 	(C_AUTHENTICATOR_AUTH_REQ|C_MSG_ACK)
#define C_AUTHENTICATOR_AUTH_NAK 	(C_AUTHENTICATOR_AUTH_REQ|C_MSG_NAK)
#define C_AUTHENTICATOR_AUTH_REJ 	(C_AUTHENTICATOR_AUTH_REQ|C_MSG_REJ)
#define	C_AUTHENTICATOR_TERM_ACK 	(C_AUTHENTICATOR_TERM_REQ|C_MSG_ACK)
#define C_AUTHENTICATOR_TERM_REJ 	(C_AUTHENTICATOR_TERM_REQ|C_MSG_REJ)

/*
 * Recursively defined callback function. 
 */
typedef long 	(*ca_state_fn_t)(void *);
typedef ca_state_fn_t 	(*ca_state_t)(void *);

/*
 * Component, proxyfies pam(8) based authentication service.
 */

struct ca_softc {
	struct c_thr 	sc_thr; 	/* binding, pthread(3) */
#define sc_cookie 	sc_thr.c_obj.c_cookie
	
	char sc_hname[C_NMAX + 1];
	char sc_uname[C_NMAX + 1];
	const char 	*sc_prompt;
	const char 	*sc_pw_prompt;
	
	pam_handle_t 	*sc_pamh;	
	struct pam_conv 	sc_pamc; 	/* during transaction used variable data */ 
	struct passwd 	*sc_pwd;
	
	struct c_msg 	sc_msg; 	/* for transaction used buffer */

	uint32_t 	sc_sock_srv; 	/* fd, socket, applicant */
	uint32_t 	sc_sock_rmt; 	/* fd, socket, applicant */
	uint32_t 	sc_rv; 	/* tracks rv of pam(3) method calls */		
};
#define C_AUTHENTICATOR_SIZE (sizeof(struct ca_softc *sc,))

static int 	ca_conv(int, const struct pam_message **, 
	struct pam_response **, void *);
static ca_state_fn_t 	ca_response(struct ca_softc *);
static ca_state_fn_t 	ca_authenticate(struct ca_softc *);
static ca_state_fn_t 	ca_establish(struct ca_softc *);

static void * 	ap_start(void *); 
 
static struct c_thr * 	c_authenticator_create(int, int);
static void 	c_authenticator_destroy(struct c_thr *); 

/******************************************************************************
 * Class-attributes.
 ******************************************************************************/
 
static struct c_authenticator c_authenticator_methods = {
	.ca_create 		= c_authenticator_create,
	.ca_destroy 	= c_authenticator_destroy,
};

static struct c_class c_authenticator_class = {
	.c_obj = {
		.c_cookie 		= C_AUTHENTICATOR_CLASS,
		.c_size 		= C_AUTHENTICATOR_SIZE,
	},
	.c_methods 		= &c_authenticator_methods,
};

static const char 	*ca_default_prompt = C_AUTHENTICATOR_PROMPT_DFLT;
static const char 	*ca_default_pw_prompt = C_AUTHENTICATOR_PW_PROMPT_DFLT;

/******************************************************************************
 * Class-methods.
 ******************************************************************************/

/*
 * Initialize class properties and return public interface.
 */
 
struct c_authenticator * 
c_authenticator_class_init(void)
{
	struct c_class *this;
	struct c_methods *cm;

	this = &c_authenticator_class;
	cm = &this->c_base;

	if ((cm = c_base_class_init()) == NULL)
		return (NULL);
	
	if ((cm = (*cm->cm_class_init)(this)) == NULL)
		return (NULL);

	if ((*cm->cm_class_add)(this)) {
		(void)(*cm->cm_class_free)(this);
		return (NULL);
	}
	cm->cm_obj_start = ca_start;
	cm->cm_obj_start = ca_stop;
	
	return (this->c_methods);	
}

/*
 * Unregisters class at parent class, iff there are no running instances. 
 */

int  
c_authenticator_class_free(void)
{
	struct *c_class *this;
	struct c_methods *cm;

	this = &c_authenticator_class;
	cm = &this->c_base;

	if ((cm->cm_class_del(this)))
		return (-1);
		
	return ((*cm->cm_class_free)(this));	
}

/******************************************************************************
 * Public methods.
 ******************************************************************************/

/*
 * Ctor.
 */
static struct c_thr *
c_authenticator_create(int srv, int rmt) 
{
	struct c_class *this;
	struct c_methods *cm;
	struct ca_softc *sc;
	struct pam_conv *pamc;
	struct c_thr *thr;
	
	this = &c_authenticator_class;
	cm = &this->c_base;
	
	if ((sc = (*cm->cm_obj_create)(this)) != NULL) {
		sc->sc_sock_rmt = rmt;
		sc->sc_sock_cli = cli;
	
		pamc = &sc->sc_pamc;
		pamc->appdata_ptr = sc;
		pamc->conv = ap_conv;
		
		thr = &sc->sc_thr;
/*
 * Release stalled execution.
 */		
		(void)pthread_cond_signal(&thr->c_cv);
	} else
		thr = NULL;
	return (thr);
}

/*
 * Dtor.
 */
static int 
c_authenticator_destroy(struct c_thr *thr) 
{
	struct c_class *this = &c_authenticator_class;
	struct c_methods *base = &this->c_base;
	
	....
	
	return (0);
}

/******************************************************************************
 * Subr.
 ******************************************************************************/

/*
 * By pam_vpromt(3) called conversation routine.
 * This event takes place during runtime of by
 * pam_authenticate(3) called pam_get_authtok(3).
 */
static int 
ca_conv(int num_msg, const struct pam_message **msg, 
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
					
		c_msg_prepare(msg[i]->msg, SOD_AUTH_NAK, 
			sc->sc_cookie, sc->sc_msg);
/*
 * Request PAM_AUTHTOK.
 */				
		if (c_msg_handle(c_msg_send, sc->sc_sock_rmt, sc->sc_msg) < 0)
			break;
/*
 * Await response from applicant.
 */	
		if (c_msg_handle(c_msg_recv, sc->sc_sock_rmt, sc->sc_msg) < 0)
			break;
	
		if (sc->sc_msg->msg_id != sc->sc_cookie)	
			break;	
			
		if (sc->sc_msg->msg_code != SOD_AUTH_REQ)
			break;
	
		if ((tok[i].resp = calloc(1, C_NMAX + 1)) == NULL) 
			break;
			
#ifdef C_OBJ_DEBUG
syslog(LOG_ERR, "%s: rx: %s\n", __func__, sc->sc_msg->msg_tok);	
#endif /* C_OBJ_DEBUG */	
				
		(void)strncpy(tok[i].resp, sc->sc_msg->msg_tok, C_NMAX);
		(void)memset(sc->sc_msg, 0, sizeof(*sc->sc_msg));
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

/******************************************************************************
 * Defines pthread(3) life-cycle for promoted transaction component           *
 ******************************************************************************/
 
/*
 * By pthread_create(3) called start_routine.
 */
static void *
c_authenticator_start(void *arg)
{
	ca_state_fn_t ca_state = NULL;
	struct ca_softc *sc;
	
	if ((sc = arg) == NULL)
		goto out;
	
	pthread_mutex_lock(&sc->c_thr.c_mtx);
	
	if (pthread_cond_wait(&sc->c_thr.c_cv, &sc->c_thr.c_mtx) == 0)
		ca_state = (ca_state_fn_t)ap_establish;	
	
	while (fn != NULL)
		fn = (ca_state_t)(*fn)(sc);
		
	pthread_mutex_unlock(&sc->c_thr.c_mtx);
out:	
	return (arg);
}	
 
/*
 * Inital state, rx request and state transition.
 */
static ca_state_fn_t 
c_authenticator_establish(void *arg)
{
	ca_state_fn_t ca_state = NULL;
	struct ca_softc *sc;

	if ((sc = arg) == NULL)
		goto out;
		
#ifdef C_OBJ_DEBUG		
syslog(LOG_ERR, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */	
	
	if (c_msg_handle(c_msg_recv, sc->sc_sock_rmt, sc->sc_msg) < 0) 
		goto out;
/*
 * An running instance cannot send messages to itself.
 */	
	if (sc->sc_msg->msg_id == sc->sc_cookie)
		goto out;
/*
 * State transition, if any.
 */
	if (sc->sc_msg->msg_code == SOD_AUTH_REQ) 
		ca_state = (ca_state_fn_t)ap_authenticate;
	
	if (ca_state == NULL)
		goto out;
/*
 * Create < hostname, user > tuple.
 */
	if (gethostname(ap->sc_hname, C_NMAX) == 0) 
		(void)strncpy(ap->sc_uname, sc->sc_msg->msg_tok, C_NMAX);
	else
		ca_state = NULL;
out:	
	return (ca_state);
}

/*
 * Initialize pam(8) transaction and authenticate.
 */
static ca_state_fn_t  
c_authenticator_authenticate(void *arg)
{	
	ca_state_fn_t ca_state = NULL;
	login_cap_t *lc = NULL;
	struct ca_softc *sc;
	int retries, backoff;
	int ask = 0, cnt = 0;
	uint32_t resp;

	if ((sc = arg) == NULL)
		goto out;

#ifdef C_OBJ_DEBUG		
syslog(LOG_ERR, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */	
	
/*
 * Parts of in login.c defined codesections are reused here.
 */	
	lc = login_getclass(NULL);
	ap->sc_prompt = login_getcapstr(lc, "login_prompt", 
		ap_default_prompt, ap_default_prompt);
	ap->sc_pw_prompt = login_getcapstr(lc, "passwd_prompt", 
		ap_default_pw_prompt, ap_default_pw_prompt);
	retries = login_getcapnum(lc, "login-retries", 
		C_AUTHENTICATOR_RETRIES_DFLT, C_AUTHENTICATOR_RETRIES_DFLT);
	backoff = login_getcapnum(lc, "login-backoff", 
		C_AUTHENTICATOR_BACKOFF_DFLT, C_AUTHENTICATOR_BACKOFF_DFLT);
	login_close(lc);
	lc = NULL;
/*
 * Verify, if username exists in passwd database. 
 */
	if ((ap->sc_pwd = getpwnam(ap->sc_uname)) != NULL) {
/*
 * Verify if user has UID 0.
 */
		if (ap->sc_pwd->pw_uid == (uid_t)0) 
			ap->ap_rv = PAM_PERM_DENIED;
		else
			ap->ap_rv = PAM_SUCCESS;
	} else 
		ap->ap_rv = PAM_USER_UNKNOWN;
	
	endpwent();
	
	if (ap->ap_rv == PAM_SUCCESS)
		ask = 1;
	
	while (ask != 0) {
/*
 * Service name for pam(8) is defined implecitely.
 */		
		ap->ap_rv = pam_start(__func__, ap->sc_uname, 
			&ap->sc_pamc, &ap->sc_pamh);

		if (ap->ap_rv == PAM_SUCCESS) {
			ap->ap_rv = pam_set_item(ap->sc_pamh, PAM_RUSER, 
				ap->sc_uname);
		}
	
		if (ap->ap_rv == PAM_SUCCESS) {
			ap->ap_rv = pam_set_item(ap->sc_pamh, PAM_RHOST, 
				ap->sc_hname);
		}
	
		if (ap->ap_rv == PAM_SUCCESS) {
			ap->ap_rv = pam_authenticate(ap->sc_pamh, 0);
/*
 * Authenticate.
 */
			
			if (ap->ap_rv == PAM_AUTH_ERR) {				
/*
 * Reenter loop, if PAM_AUTH_ERR condition halts. 
 */
				cnt += 1;	
		
				if (cnt > backoff) 
					(*ap->ap_thr.cobj_wait)
						((u_int)((cnt - backoff) * 5), sc);
		
				if (cnt >= retries)
					ask = 0;		
	
				(void)pam_end(ap->sc_pamh, ap->ap_rv);
		
				ap->sc_pamh = NULL;
			} else
				ask = 0;	
		} else
			ask = 0;	
	}
/*
 * Create response.
 */			
	resp = SOD_AUTH_REJ;	
	
	if (ap->ap_rv == PAM_SUCCESS) 
		resp = SOD_AUTH_ACK;
			
	c_msg_prepare(ap->sc_uname, resp, sc, sc->sc_msg);
	ca_state = (ca_state_fn_t)ap_response;
out:	
	return (ca_state);
}

/*
 * Send response.
 */
static ca_state_fn_t  
c_authenticator_response(void *arg)
{	
	ca_state_fn_t ca_state = NULL;
	struct ca_softc *sc;

	if ((sc = arg) == NULL)
		goto out;
		
#ifdef C_OBJ_DEBUG		
syslog(LOG_ERR, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */

	if (c_msg_handle(c_msg_send, sc->sc_sock_rmt, sc->sc_msg) < 0)
		(*ap->ap_thr.cobj_exit)(EX_OSERR, __func__, sc);
out:	
	return (ca_state);
}

/*
 * By pthread_exit(3) implecitely called cleanup handler.
 */
static void  
c_authenticator_stop(void *arg)
{
	struct ca_softc *sc = NULL;

	if ((sc = arg) == NULL) 
		return;

	if (sc->sc_pamh != NULL)
		(void)pam_end(sc->sc_pamh, sc->sc_rv);

	(void)close(sc->sc_sock_cli);

#ifdef C_OBJ_DEBUG		
syslog(LOG_ERR, "%s\n", __func__);
#endif /* C_OBJ_DEBUG */

}
