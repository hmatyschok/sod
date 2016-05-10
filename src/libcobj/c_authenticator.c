/*-
 * Copyright (c) 2015 Henning Matyschok
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


#define AUTH_PROVIDER_AUTH_REQ 	0x00000001
#define AUTH_PROVIDER_TERM_REQ 	0x00000002

#define AUTH_PROVIDER_AUTH_ACK 	(AUTH_PROVIDER_AUTH_REQ|TOBJ_MSG_ACK)
#define AUTH_PROVIDER_AUTH_NAK 	(AUTH_PROVIDER_AUTH_REQ|TOBJ_MSG_NAK)
#define AUTH_PROVIDER_AUTH_REJ 	(AUTH_PROVIDER_AUTH_REQ|TOBJ_MSG_REJ)
#define	AUTH_PROVIDER_TERM_ACK 	(AUTH_PROVIDER_TERM_REQ|TOBJ_MSG_ACK)
#define AUTH_PROVIDER_TERM_REJ 	(AUTH_PROVIDER_TERM_REQ|TOBJ_MSG_REJ)


/*
 * Component, proxyfies pam(8) based authentication service.
 */

#include "sod_msg.h"
#include "cobj.h"
#include "ap.h"

#define AUTH_PROVIDER_COOKIE 	1421959420
#define AUTH_PROVIDER_TYPE 	"ap"

struct ap *sc;;

/*
 * Recursively defined callback function. 
 */
typedef long 	(*ap_state_fn_t)(struct ap *sc; *);
typedef ap_state_fn_t 	(*ap_state_t)(struct ap *sc; *);

struct c_authenticator_softc {
	struct c_thr 	sc_thr; 	/* binding, pthread(3) */
	
	pam_handle_t 	*sc_pamh;	
	struct pam_conv 	sc_pamc; 	/* during transaction used variable data */ 
	struct passwd 	*sc_pwd;
	
	char sc_hname[SOD_NMAX + 1];
	char sc_uname[SOD_NMAX + 1];
	
	const char 	*sc_prompt;
	const char 	*sc_pw_prompt;

	struct sod_buf 	sc_buf; 	/* for transaction used buffer */
	
	uint32_t 	sc_sock_srv; 	/* fd, socket, applicant */
	uint32_t 	sc_sock_rmt; 	/* fd, socket, applicant */
	
	uint32_t 	sc_rv; 	/* tracks rv of pam(3) method calls */		
};
#define AUTH_PROVIDER_SIZE (sizeof(struct ap *sc;))

#define	AUTH_PROVIDER_DFLT_BACKOFF 	3
#define	AUTH_PROVIDER_DFLT_RETRIES 	10

#define	AUTH_PROVIDER_DFLT_PROMPT		"login: "
#define	AUTH_PROVIDER_DFLT_PW_PROMPT	"Password:"

/******************************************************************************
 * Prototypes, private methods                                                *
 ******************************************************************************/

static void 	ap_init(void);
static int 	ap_authenticate(int, const struct pam_message **, 
	struct pam_response **, void *);

/******************************************************************************
 * Prototypes, pthread(3) life-cycle for transaction component                *
 ******************************************************************************/
 
static ap_state_fn_t 	ap_response(struct ap *sc; *);
static ap_state_fn_t 	ap_authenticate(struct ap *sc; *);
static ap_state_fn_t 	ap_establish(struct ap *sc; *);
static void * 	ap_start(void *);

/******************************************************************************
 * Statically defined attributes                                              *
 ******************************************************************************/
static const char 	*ca_default_prompt = AUTH_PROVIDER_DFLT_PROMPT;
static const char 	*ca_default_pw_prompt = AUTH_PROVIDER_DFLT_PW_PROMPT;


struct c_authenticator {
	struct c_methods  	ca_m

};

static struct c_authenticator c_authenticator = {
	.ca_ctor 	= c_authenticator_ctor,
	.ca_dtor 	= c_authenticator_dtor,
};

static struct c_class c_authenticator_class = {
	.c_obj = {
		.c_cookie 		= C_AUTHENTICATOR_CLASS,
		.c_size 		= C_AUTHENTICATOR_SIZE,
	},
	.c_cookie 		= AUTH_PROVIDER_COOKIE,
	.c_size 		= AUTH_PROVIDER_SIZE,
	.c_public 		= &c_authenticator,
};

/*
 * Initialize class properties and returns interface.
 */
 
struct c_authenticator * 
c_authenticator_class_init(void)
{
	struct c_methods *base;

	if ((base = c_base_class_init()) == NULL)
		return (NULL);
	
	if ((*base->cm_init)(&c_authenticator_class) == NULL)
		return (NULL);

	if ((*base->cm_add)(&c_authenticator_class))
		return (NULL);
		
	return (c_authenticator_class.c_public);	
}

void 
c_authenticator_class_free(void)
{
	struct c_methods *base;

	base = c_authenticator_class.c_base;

	if ((*base->cm_del)(&c_authenticator_class))
		return (NULL);
	
	if ((*base->cm_free)(&c_authenticator_class) == NULL)
		return (NULL);

	
		
	return (c_authenticator_class.c_methods);	
}

/******************************************************************************
 * Constructor.                                                               *
 ******************************************************************************/

static struct c_thr *
ap_create(int srv, int rmt) 
{
	struct c_methods *base = c_authenticator_class.c_base;
	struct c_authenticator_softc *sc;
	struct pam_conv *pamc;
	struct c_thr *thr;
	
	if ((sc = (*base->cm_ctor)(&c_authenticator_class)) != NULL) {
		sc->sc_sock_rmt = rmt;
		sc->sc_sock_cli = cli;
	
		pamc = &sc->sc_pamc;
		pamc->appdata_ptr = sc;
		pamc->conv = ap_authenticate;
		
		thr = &sc->sc_thr;	
	} else
		thr = NULL;
	return (thr);
}

static void
ap_destroy(struct c_thr *thr) 
{
	struct c_class *this = &c_authenticator_class;
	struct c_methods *base = this->c_base;
	
	
	if ((sc = (*base->cm_free)(this, thr)) != NULL) {
		sc->sc_sock_rmt = rmt;
		sc->sc_sock_cli = cli;
	
		pamc = &sc->sc_pamc;
		pamc->appdata_ptr = sc;
		pamc->conv = ap_authenticate;
		
		thr = &sc->sc_thr;	
	} else
		thr = NULL;
	return (thr);
}



(void)close(sca->sca_client);


/******************************************************************************
 * Definitions, private methods                                               *
 ******************************************************************************/
 
/*
 * By pam_vpromt(3) called conversation routine.
 * This event takes place during runtime of by
 * pam_authenticate(3) called pam_get_authtok(3).
 */
static int 
ap_authenticate(int num_msg, const struct pam_message **msg, 
		struct pam_response **resp, void *data) 
{
	struct ap *sc; *sc = NULL;
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
					
		sod_prepare_msg(msg[i]->msg, SOD_AUTH_NAK, sc, ap->sc_buf);
/*
 * Request PAM_AUTHTOK.
 */				
		if (sod_handle_msg(sod_send_msg, ap->sc_sock_rmtent, ap->sc_buf) < 0)
			break;
/*
 * Await response from applicant.
 */	
		if (sod_handle_msg(sod_recv_msg, ap->sc_sock_rmtent, ap->sc_buf) < 0)
			break;
	
		if (ap->sc_buf->sb_h.sh_cookie != ap->ap_thr.cobj_cookie)	
			break;	
	
		if (ap->sc_buf->sb_h.sh_tid != (sod_tid_t)ap->ap_thr.cobj_id)
			break;
			
		if (ap->sc_buf->sb_code != SOD_AUTH_REQ)
			break;
	
		if ((tok[i].resp = calloc(1, SOD_NMAX + 1)) == NULL) 
			break;
			
#ifdef SOD_DEBUG
syslog(LOG_ERR, "%s: rx: %s\n", __func__, ap->sc_buf->sb_tok);	
#endif /* SOD_DEBUG */	
				
		(void)strncpy(tok[i].resp, ap->sc_buf->sb_tok, SOD_NMAX);
		(void)memset(ap->sc_buf, 0, sizeof(*ap->sc_buf));
	}
	
	if (i < q) {
/*
 * Cleanup, if something went wrong.
 */
		for (j = i, i = 0; i < j; ++i) { 
			(void)memset(tok[i].resp, 0, SOD_NMAX);
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
ap_start(void *arg)
{
	ap_state_fn_t ap_state = NULL;
	struct ap *sc = arg;
	
	pthread_mutex_lock(&sc->c_thr.c_mtx);
	
	if (pthread_cond_wait(&sc->c_thr.c_cv, &sc->c_thr.c_mtx) == 0)
		ap_state = (ap_state_fn_t)ap_establish;	
	
	pthread_mutex_unlock(&sc->c_thr.c_mtx);
	
	while (fn != NULL)
		fn = (ap_state_t)(*fn)(sc);
	
	return (arg);
}	
 
/*
 * Inital state, rx request and state transition.
 */
static ap_state_fn_t 
ap_establish(struct ap *sc; *sc)
{
	ap_state_fn_t ap_state = NULL;

	if (sc == NULL)
		goto out;
		
#ifdef SOD_DEBUG		
syslog(LOG_ERR, "%s\n", __func__);
#endif /* SOD_DEBUG */	
	
	if (sod_handle_msg(sod_recv_msg, ap->sc_sock_rmtent, ap->sc_buf) < 0) 
		(*ap->ap_thr.cobj_exit)(EX_OSERR, __func__, sc);
/*
 * An running libap instance cannot send messages to itself.
 */
	if (ap->sc_buf->sb_h.sh_cookie == ap->ap_thr.cobj_cookie)	
		goto out;	
		
	if (ap->sc_buf->sb_h.sh_tid == (sod_tid_t)ap->ap_thr.cobj_id)
		goto out;
/*
 * State transition, if any.
 */
	if (ap->sc_buf->sb_code == SOD_AUTH_REQ) 
		ap_state = (ap_state_fn_t)ap_authenticate;
	
	if (ap_state == NULL)
		goto out;
/*
 * Create < hostname, user > tuple.
 */
	if (gethostname(ap->sc_hname, SOD_NMAX) == 0) 
		(void)strncpy(ap->sc_uname, ap->sc_buf->sb_tok, SOD_NMAX);
	else
		ap_state = NULL;
out:	
	return (ap_state);
}

/*
 * Initialize pam(8) transaction and authenticate.
 */
static ap_state_fn_t  
ap_authenticate(struct ap *sc; *sc)
{	
	ap_state_fn_t ap_state = NULL;
	login_cap_t *lc = NULL;
	int retries, backoff;
	int ask = 0, cnt = 0;
	uint32_t resp;

	if (sc == NULL)
		goto out;

#ifdef SOD_DEBUG		
syslog(LOG_ERR, "%s\n", __func__);
#endif /* SOD_DEBUG */	
	
/*
 * Parts of in login.c defined codesections are reused here.
 */	
	lc = login_getclass(NULL);
	ap->sc_prompt = login_getcapstr(lc, "login_prompt", 
		ap_default_prompt, ap_default_prompt);
	ap->sc_pw_prompt = login_getcapstr(lc, "passwd_prompt", 
		ap_default_pw_prompt, ap_default_pw_prompt);
	retries = login_getcapnum(lc, "login-retries", 
		AUTH_PROVIDER_DFLT_RETRIES, AUTH_PROVIDER_DFLT_RETRIES);
	backoff = login_getcapnum(lc, "login-backoff", 
		AUTH_PROVIDER_DFLT_BACKOFF, AUTH_PROVIDER_DFLT_BACKOFF);
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
			
	sod_prepare_msg(ap->sc_uname, resp, sc, ap->sc_buf);
	ap_state = (ap_state_fn_t)ap_response;
out:	
	return (ap_state);
}

/*
 * Send response.
 */
static ap_state_fn_t  
ap_response(struct ap *sc; *sc)
{	
	ap_state_fn_t ap_state = NULL;
	
	if (sc == NULL)
		goto out;
	
#ifdef SOD_DEBUG		
syslog(LOG_ERR, "%s\n", __func__);
#endif /* SOD_DEBUG */

	if (sod_handle_msg(sod_send_msg, ap->sc_sock_rmtent, ap->sc_buf) < 0)
		(*ap->ap_thr.cobj_exit)(EX_OSERR, __func__, sc);
out:	
	return (ap_state);
}

/*
 * By pthread_exit(3) implecitely called cleanup handler.
 */
static void  
ap_stop(void *arg)
{
	struct ap *sc; *sc = NULL;

	if ((sc = arg) == NULL) 
		return;

	sod_free_msg(ap->sc_buf);
	
	if (ap->sc_pamh != NULL)
		(void)pam_end(ap->sc_pamh, ap->ap_rv);

#ifdef SOD_DEBUG		
syslog(LOG_ERR, "%s\n", __func__);
#endif /* SOD_DEBUG */

	sod_delete_thr(&_ap, arg);
}
