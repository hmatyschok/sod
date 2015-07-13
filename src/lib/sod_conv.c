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

/*
 * Component, proxyfies pam(8) based authentication service.
 */

#include "sod_msg.h"
#include "sod_thr.h"
#include "sod_conv.h"

#define SOD_CONV_COOKIE 	1421959420
#define SOD_CONV_TYPE 	"sod_conv"

struct sod_conv;

/*
 * Recursively defined callback function. 
 */
typedef long 	(*sod_fn_t)(struct sod_conv *);
typedef sod_fn_t 	(*sod_phase_t)(struct sod_conv *);

struct sod_conv {
	struct sod_thr 	sc_thr; 	/* binding, pthread(3) */
	uint32_t 	sc_rv; 	/* tracks rv of pam(3) method calls */
	uint32_t 	sc_client; 	/* fd, socket, applicant */
	pam_handle_t 	*sc_pamh;	
	struct pam_conv 	sc_pamc; 	/* during transaction used variable data */ 
	struct sod_buf 	*sc_buf; 	/* for transaction used buffer */
	char sc_hostname[SOD_NMAX + 1];
	char sc_username[SOD_NMAX + 1];
	const char *sc_prompt;
	const char *sc_pw_prompt;
	struct passwd 	*sc_pwd;
};
#define SOD_CONV_SIZE (sizeof(struct sod_conv))

#define	SOD_DFLT_BACKOFF 	3
#define	SOD_DFLT_RETRIES 	10

#define	SOD_DFLT_PROMPT		"login: "
#define	SOD_DFLT_PW_PROMPT	"Password:"

/******************************************************************************
 * Prototypes, private methods                                                *
 ******************************************************************************/

static void 	sod_init_conv(void);
static int 	sod_authenticate_conv(int, const struct pam_message **, 
	struct pam_response **, void *);

/******************************************************************************
 * Prototypes, pthread(3) life-cycle for transaction component                *
 ******************************************************************************/
 
static void 	sod_stop_conv(void *);
static sod_fn_t 	sod_response(struct sod_conv *);
static sod_fn_t 	sod_authenticate(struct sod_conv *);
static sod_fn_t 	sod_establish(struct sod_conv *);
static void * 	sod_start_conv(void *);

/******************************************************************************
 * Statically defined attributes and promoted properties.                                                    *
 ******************************************************************************/

static struct sod_thr_attr libsod_conv_class_attr = {
	.sta_h 			= { .sh_cookie = SOD_CONV_COOKIE },
	.sta_once 		= PTHREAD_ONCE_INIT,
	.sta_init 		= sod_init_conv,
};

static struct sod_thr libsod_conv_class = {
	.st_cookie 		= SOD_CONV_COOKIE,
	.st_type 		= SOD_CONV_TYPE,
	.st_flags 		= SOD_SYNC,
	.st_size 		= SOD_CONV_SIZE,
	.st_start 		= sod_start_conv, 
	.st_stop 		= sod_stop_conv,
};

static const char 	*default_prompt = SOD_DFLT_PROMPT;
static const char 	*default_pw_prompt = SOD_DFLT_PW_PROMPT;

int 
libsod_conv_include(void *arg)
{
	return (libsod_thr_include(&libsod_conv_class, 
		&libsod_conv_class_attr, arg));
}

void 
libsod_conv_exclude(void)
{
	libsod_thr_exclude(&libsod_conv_class, &libsod_conv_class_attr);
}

/******************************************************************************
 * Constructor.                                                               *
 ******************************************************************************/

static int 
sod_promote_conv_attr(void *arg0, void *arg1)
{
	struct sod_conv_args *sca = arg1;
	struct sod_conv *sc = arg0;
	struct pam_conv *pamc = &sc->sc_pamc;
	int eval = 0;

#ifdef SOD_DEBUG		
syslog(LOG_ERR, "%s\n", __func__);
#endif /* SOD_DEBUG */
	
	sc->sc_client = sca->sca_client;
	pamc->appdata_ptr = sc;
	pamc->conv = sod_authenticate_conv;
	
	if ((sc->sc_buf = sod_alloc_msg(1)) == NULL)
		eval = -1;
	
	return (eval);
}

void 
sod_create_conv(void *arg) 
{
	struct sod_conv_args *sca = NULL;
	struct sod_thr *st = NULL;
	void *ret = NULL;
	
#ifdef SOD_DEBUG		
syslog(LOG_ERR, "%s\n", __func__);
#endif /* SOD_DEBUG */

	if ((sca = arg) == NULL)
		return;
	
	if ((sca->sca_client = accept(sca->sca_srv, NULL, NULL)) < 0) 
		return;		
/*
 * Allocate, execute and serialize.
 */		
	st = sod_create_thr(&libsod_conv_class, sod_promote_conv_attr, arg);
	if (st != NULL) 		
		(void)pthread_join(st->st_tid, &ret);
	
	(void)close(sca->sca_client);
}

/******************************************************************************
 * Definitions, private methods                                               *
 ******************************************************************************/

/*
 * Called by pthread_once(3) during sod_bind_thr.
 */
static void 
sod_init_conv(void)
{
	if (pthread_key_create(&libsod_conv_class_attr.sta_key, sod_stop_conv) != 0)
		libsod_conv_class_attr.sta_eval |= SOD_BIND_ERR;
	else
		libsod_conv_class_attr.sta_eval &= ~SOD_BIND_ERR;
}

/*
 * By pam_vpromt(3) called conversation routine.
 * This event takes place during runtime of by
 * pam_authenticate(3) called pam_get_authtok(3).
 */
static int 
sod_authenticate_conv(int num_msg, const struct pam_message **msg, 
		struct pam_response **resp, void *data) 
{
	struct sod_conv *sc = NULL;
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
					
		sod_prepare_msg(msg[i]->msg, SOD_AUTH_NAK, sc, sc->sc_buf);
/*
 * Request PAM_AUTHTOK.
 */				
		if (sod_handle_msg(sod_send_msg, sc->sc_client, sc->sc_buf) < 0)
			break;
/*
 * Await response from applicant.
 */	
		if (sod_handle_msg(sod_recv_msg, sc->sc_client, sc->sc_buf) < 0)
			break;
	
		if (sc->sc_buf->sb_h.sh_cookie != sc->sc_thr.st_cookie)	
			break;	
	
		if (sc->sc_buf->sb_h.sh_tid != (sod_tid_t)sc->sc_thr.st_tid)
			break;
			
		if (sc->sc_buf->sb_code != SOD_AUTH_REQ)
			break;
	
		if ((tok[i].resp = calloc(1, SOD_NMAX + 1)) == NULL) 
			break;
			
#ifdef SOD_DEBUG
syslog(LOG_ERR, "%s: rx: %s\n", __func__, sc->sc_buf->sb_tok);	
#endif /* SOD_DEBUG */	
				
		(void)strncpy(tok[i].resp, sc->sc_buf->sb_tok, SOD_NMAX);
		(void)memset(sc->sc_buf, 0, sizeof(*sc->sc_buf));
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
sod_start_conv(void *arg)
{
	sod_phase_t fn = (sod_phase_t)sod_establish;
	struct sod_conv *sc = NULL;

	if ((sc = arg) == NULL)
		goto out;

#ifdef SOD_DEBUG		
syslog(LOG_ERR, "%s\n", __func__);
#endif /* SOD_DEBUG */	
	
	if ((*sc->sc_thr.st_bind)(&libsod_conv_class, 
		&libsod_conv_class_attr, sc) < 0)
		goto out;
			
	while (fn != NULL)
		fn = (sod_phase_t)(*fn)(sc);
out:	
	return (NULL);
}	
 
/*
 * Inital state, rx request and state transition.
 */
static sod_fn_t 
sod_establish(struct sod_conv *sc)
{
	sod_fn_t sod_phase = NULL;

	if (sc == NULL)
		goto out;
		
#ifdef SOD_DEBUG		
syslog(LOG_ERR, "%s\n", __func__);
#endif /* SOD_DEBUG */	
	
	if (sod_handle_msg(sod_recv_msg, sc->sc_client, sc->sc_buf) < 0) 
		(*sc->sc_thr.st_exit)(EX_OSERR, __func__, sc);
/*
 * An running libsod_conv instance cannot send messages to itself.
 */
	if (sc->sc_buf->sb_h.sh_cookie == sc->sc_thr.st_cookie)	
		goto out;	
		
	if (sc->sc_buf->sb_h.sh_tid == (sod_tid_t)sc->sc_thr.st_tid)
		goto out;
/*
 * State transition, if any.
 */
	if (sc->sc_buf->sb_code == SOD_AUTH_REQ) 
		sod_phase = (sod_fn_t)sod_authenticate;
	
	if (sod_phase == NULL)
		goto out;
/*
 * Create < hostname, user > tuple.
 */
	if (gethostname(sc->sc_hostname, SOD_NMAX) == 0) 
		(void)strncpy(sc->sc_username, sc->sc_buf->sb_tok, SOD_NMAX);
	else
		sod_phase = NULL;
out:	
	return (sod_phase);
}

/*
 * Initialize pam(8) transaction and authenticate.
 */
static sod_fn_t  
sod_authenticate(struct sod_conv *sc)
{	
	sod_fn_t sod_phase = NULL;
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
	sc->sc_prompt = login_getcapstr(lc, "login_prompt", 
		default_prompt, default_prompt);
	sc->sc_pw_prompt = login_getcapstr(lc, "passwd_prompt", 
		default_pw_prompt, default_pw_prompt);
	retries = login_getcapnum(lc, "login-retries", 
		SOD_DFLT_RETRIES, SOD_DFLT_RETRIES);
	backoff = login_getcapnum(lc, "login-backoff", 
		SOD_DFLT_BACKOFF, SOD_DFLT_BACKOFF);
	login_close(lc);
	lc = NULL;
/*
 * Verify, if username exists in passwd database. 
 */
	if ((sc->sc_pwd = getpwnam(sc->sc_username)) != NULL) {
/*
 * Verify if user has UID 0.
 */
		if (sc->sc_pwd->pw_uid == (uid_t)0) 
			sc->sc_rv = PAM_PERM_DENIED;
		else
			sc->sc_rv = PAM_SUCCESS;
	} else 
		sc->sc_rv = PAM_USER_UNKNOWN;
	
	endpwent();
	
	if (sc->sc_rv == PAM_SUCCESS)
		ask = 1;
	
	while (ask != 0) {
/*
 * Service name for pam(8) is defined implecitely.
 */		
		sc->sc_rv = pam_start(__func__, sc->sc_username, 
			&sc->sc_pamc, &sc->sc_pamh);

		if (sc->sc_rv == PAM_SUCCESS) {
			sc->sc_rv = pam_set_item(sc->sc_pamh, PAM_RUSER, 
				sc->sc_username);
		}
	
		if (sc->sc_rv == PAM_SUCCESS) {
			sc->sc_rv = pam_set_item(sc->sc_pamh, PAM_RHOST, 
				sc->sc_hostname);
		}
	
		if (sc->sc_rv == PAM_SUCCESS) {
/*
 * Authenticate.
 */		
			sc->sc_rv = pam_authenticate(sc->sc_pamh, 0);
			if (sc->sc_rv == PAM_AUTH_ERR) {				
/*
 * Reenter loop, if PAM_AUTH_ERR condition halts. 
 */
				cnt += 1;	
		
				if (cnt > backoff) 
					(*sc->sc_thr.st_wait)
						((u_int)((cnt - backoff) * 5), sc);
		
				if (cnt >= retries)
					ask = 0;		
	
				(void)pam_end(sc->sc_pamh, sc->sc_rv);
		
				sc->sc_pamh = NULL;
			} else
				ask = 0;	
		} else
			ask = 0;	
	}
/*
 * Create response.
 */			
	resp = SOD_AUTH_REJ;	
	
	if (sc->sc_rv == PAM_SUCCESS) 
		resp = SOD_AUTH_ACK;
			
	sod_prepare_msg(sc->sc_username, resp, sc, sc->sc_buf);
	sod_phase = (sod_fn_t)sod_response;
out:	
	return (sod_phase);
}

/*
 * Send response.
 */
static sod_fn_t  
sod_response(struct sod_conv *sc)
{	
	sod_fn_t sod_phase = NULL;
	
	if (sc == NULL)
		goto out;
	
#ifdef SOD_DEBUG		
syslog(LOG_ERR, "%s\n", __func__);
#endif /* SOD_DEBUG */

	if (sod_handle_msg(sod_send_msg, sc->sc_client, sc->sc_buf) < 0)
		(*sc->sc_thr.st_exit)(EX_OSERR, __func__, sc);
out:	
	return (sod_phase);
}

/*
 * By pthread_exit(3) implecitely called cleanup handler.
 */
static void  
sod_stop_conv(void *arg)
{
	struct sod_conv *sc = NULL;

	if ((sc = arg) == NULL) 
		return;

	sod_free_msg(sc->sc_buf);
	
	if (sc->sc_pamh != NULL)
		(void)pam_end(sc->sc_pamh, sc->sc_rv);

#ifdef SOD_DEBUG		
syslog(LOG_ERR, "%s\n", __func__);
#endif /* SOD_DEBUG */

	sod_delete_thr(&libsod_conv_class, arg);
}
