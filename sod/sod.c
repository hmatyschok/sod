/*-
 * Copyright (c) 2015, 2016 Henning Matysphok
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following displaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 * version=0.3
 */
 
#include <sys/stat.h>

#include <security/pam_appl.h>

#include <fcntl.h>
#include <login_cap.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <sysexits.h>
#include <syslog.h>

#include "sod.h"

/*
 * Simple sign-on service on demand daemon - sod(8).
 */

struct sod_softc {
    int     sc_srv;     /* fd, socket, applicant */
    struct sod_msg     sc_buf;     /* for transaction used buffer */
    
    
    int     sc_eval;     /* tracks rv of pam(3) method calls */ 
};
#define    SOD_BACKOFF_DFLT     3
#define    SOD_RETRIES_DFLT     10

#define    SOD_PROMPT_DFLT        "login: "
#define    SOD_PW_PROMPT_DFLT    "Password:"

static pid_t     pid;
static pthread_t     tid;

static char *sod_cmd; 

static char *sod_work_dir = SOD_WORK_DIR;
static char *sod_pid_file = SOD_PID_FILE;
static char *sod_sock_file = SOD_SOCK_FILE;

static char     lock_file[PATH_MAX + 1];

static struct sockaddr_storage     sap;
static struct sockaddr_un *sun;
static size_t len;

static sigset_t signalset;

static char     *sod_prompt_default = SOD_PROMPT_DFLT;
static char     *sod_pw_prompt_default = SOD_PW_PROMPT_DFLT;

static void     sod_errx(int, const char *, ...);
static void     sod_atexit(void);
static void *    sod_sigaction(void *);

static int     sod_conv(int, const struct pam_message **, 
    struct pam_response **, void *);

static void     sod_doit(int);

/*
 * Fork.
 */
int
main(int argc, char **argv)
{
    int fd;
    
    if (getuid() != 0)
        sod_errx(EX_NOPERM, "%s", strerror(EPERM));     
    
    if ((fd = open(sod_pid_file, O_RDWR, 0640)) > -1) 
        sod_errx(EX_OSERR, "Daemon already running");    
        
    sod_cmd = argv[0];
    
    openlog(sod_cmd, LOG_CONS, LOG_DAEMON);
/*
 * Disable hang-up signal.
 */
    if (signal(SIGHUP, SIG_IGN) < 0)
        sod_errx(EX_OSERR, "Can't disable SIGHUP");
/*
 * Avoid creation of zombie processes.
 */
    if (signal(SIGCHLD, SIG_IGN) < 0)
        sod_errx(EX_OSERR, "Can't disable SIGCHLD");

    if ((pid = fork()) < 0) 
        sod_errx(EX_OSERR, "Can't fork");
    
    if (pid != 0) 
        exit(EX_OK);
/*
 * Daemonize.
 */  
    (void)umask(0);

    if (setsid() < 0)
        sod_errx(EX_OSERR, "Can't set session identifier");

    if (chdir(sod_work_dir) < 0) 
        sod_errx(EX_OSERR, "Can't change directory to %s", sod_work_dir);

    (void)close(STDIN_FILENO);
    (void)close(STDOUT_FILENO);
    (void)close(STDERR_FILENO);

    if (atexit(sod_atexit) < 0)
        sod_errx(EX_OSERR, "Can't register sod_atexit");
/* 
 * Modefy signal handling and externalize.
 */
    if (sigfillset(&signalset) < 0)
        sod_errx(EX_OSERR, "Can't initialize signal set");

    if (pthread_sigmask(SIG_BLOCK, &signalset, NULL) != 0)
        sod_errx(EX_OSERR, "Can't apply modefied signal set");    
    
    if (pthread_create(&tid, NULL, sod_sigaction, NULL) != 0)
        sod_errx(EX_OSERR, "Can't initialize signal handler");
/*
 * Create SOD_PID_FILE (lockfile).
 */        
    (void)unlink(sod_pid_file);
        
    if ((fd = open(sod_pid_file, O_RDWR|O_CREAT, 0640)) < 0)
        sod_errx(EX_OSERR, "Can't open %s", sod_pid_file);

    if (lockf(fd, F_TLOCK, 0) < 0)
        sod_errx(EX_OSERR, "Can't lock %s", sod_pid_file);

    (void)snprintf(lock_file, PATH_MAX, "%d\n", getpid());

    if (write(fd, lock_file, PATH_MAX) < 0) 
        sod_errx(EX_OSERR, "Can't write %d in %s", getpid(), sod_pid_file);
        
    (void)close(fd);    
/*
 * Create listening socket.
 */                
    (void)memset(&sap, 0, sizeof(sap));
    
    sun = (struct sockaddr_un *)&sap;
    sun->sun_family = AF_UNIX;
    len = sizeof(sun->sun_path);

    (void)strncpy(sun->sun_path, sod_sock_file, len - 1);

    len += offsetof(struct sockaddr_un, sun_path);
    
    if ((fd = socket(sun->sun_family, SOCK_STREAM, 0)) < 0) 
        sod_errx(EX_OSERR, "Can't create socket");
    
    (void)unlink(sun->sun_path);

    if (bind(fd, (struct sockaddr *)sun, len) < 0)
        sod_errx(EX_OSERR, "Can't bind %s", sun->sun_path);    
        
    if (listen(fd, SOD_MSG_QLEN) < 0) 
        sod_errx(EX_OSERR, "Can't listen %s", sun->sun_path);
/*
 * Wait until accept(2) and perform transaction.
 */
    for (;;) {
        int rmt;

        if ((rmt = accept(fd, NULL, NULL)) < 0)
            continue;        

        if (fork() == 0) 
            sod_doit(rmt);
                  
        (void)close(rmt);
    }
            /* NOT REACHED */    
}

/*
 * By child performed pam(8) transaction.
 */
static void     
sod_doit(int r)
{
    struct sod_softc sc;
    
    char host[SOD_NMAX + 1];
    char user[SOD_NMAX + 1];
    
    struct pam_conv     pamc;     /* variable data */ 
    struct passwd     *pwd;   
    
    login_cap_t *lc;
   
    const char     *prompt;
    const char     *pw_prompt;
    
    pam_handle_t     *pamh;
    
    int retries, backoff;
    int ask = 1, cnt = 0;
    int pam_err, resp;

    (void)memset(&sc, 0, sizeof(sc));
    
    sc.sc_rmt = r;
    
    pamc.appdata_ptr = &sc;
    pamc.conv = sod_conv;
/*
 * Create < hostname, user > tuple.
 */
    if (sod_msg_fn(sod_msg_recv, sc.sc_rmt, &sc.sc_buf) < 0) 
        exit(EX_OSERR);

    if (gethostname(host, SOD_NMAX) < 0) 
        exit(EX_NOHOST); 
 
    (void)strncpy(user, sc.sc_buf.sm_tok, SOD_NMAX);
/*
 * Verify, if username exists in passwd database. 
 */
    if ((pwd = getpwnam(user)) != NULL) {
/*
 * Verify, if user has UID 0, because login by UID 0 is not allowed. 
 */
        if (pwd->pw_uid == (uid_t)0) 
            pam_err = PAM_PERM_DENIED;
        else
            pam_err = PAM_SUCCESS;
    } else 
        pam_err = PAM_USER_UNKNOWN;
    
    endpwent(); 
    
    if (pam_err == PAM_SUCCESS) {
/*
 * Parts of in login.c defined codesections are reused here.
 */   
        switch (sc.sc_buf.sm_code) {
        case SOD_AUTH_REQ:  
      
            lc = login_getclass(NULL);
            prompt = login_getcapstr(lc, "login_prompt", 
                sod_prompt_default, sod_prompt_default);
            pw_prompt = login_getcapstr(lc, "passwd_prompt", 
                sod_pw_prompt_default, sod_pw_prompt_default);
            retries = login_getcapnum(lc, "login-retries", 
                SOD_RETRIES_DFLT, SOD_RETRIES_DFLT);
            backoff = login_getcapnum(lc, "login-backoff", 
                SOD_BACKOFF_DFLT, SOD_BACKOFF_DFLT);
            login_close(lc);
            lc = NULL;
       
            while (ask != 0) {
/*
 * Open pam(8) session and authenticate.
 */        
                pam_err = pam_start(sod_cmd, user, 
                    &pamc, &pamh);

                if (pam_err == PAM_SUCCESS) 
                    pam_err = pam_set_item(pamh, PAM_RUSER, user);
    
                if (pam_err == PAM_SUCCESS) 
                    pam_err = pam_set_item(pamh, PAM_RHOST, host);

                if (pam_err == PAM_SUCCESS) 
                    pam_err = pam_set_item(pamh, PAM_TTY, sod_sock_file); 

                if (pam_err == PAM_SUCCESS) {
/*
 * Authenticate.
 */                
                    pam_err = pam_authenticate(pamh, 0);
                
                    if (pam_err == PAM_AUTH_ERR) {                
/*
 * Reenter loop, if PAM_AUTH_ERR condition halts. 
 */
                        cnt += 1;    
        
                        if (cnt > backoff) 
                            (void)sleep((u_int)((cnt - backoff) * 5));
        
                        if (cnt >= retries)
                            ask = 0;        
    
                        (void)pam_end(pamh, pam_err);
        
                        pamh = NULL;
                    } else
                        ask = 0;    
                } else
                    ask = 0;    
            }

            if (pam_err == PAM_SUCCESS) 
                pam_err = pam_open_session(pamh, 0);
/*
 * Create response.
 */             
            if (pam_err == PAM_SUCCESS) 
                resp = SOD_AUTH_ACK;
            else
                resp = SOD_AUTH_REJ;    
        
            break;
        case SOD_TERM_REQ:    
            pam_err = pam_start(sod_cmd, user, &pamc, &pamh);

            if (pam_err == PAM_SUCCESS) 
                pam_err = pam_set_item(pamh, PAM_RUSER, user);
    
            if (pam_err == PAM_SUCCESS) 
                pam_err = pam_set_item(pamh, PAM_RHOST, host);

            if (pam_err == PAM_SUCCESS) 
                pam_err = pam_set_item(pamh, PAM_TTY, sod_sock_file); 

            if (pam_err == PAM_SUCCESS) 
                pam_err = pam_close_session(pamh, 0);
/*
 * Create response.
 */         
            if (pam_err == PAM_SUCCESS) 
                resp = SOD_TERM_ACK;
            else
                resp = SOD_TERM_REJ;
                  
            break;
        default:
            resp = SOD_AUTH_REJ;
            break;
        }    
    } else 
        resp = SOD_AUTH_REJ;         
/*
 * Close pam(8) session, if any.
 */
    if (pamh != NULL)
        (void)pam_end(pamh, pam_err);  
/*
 * Send response.
 */      
    sod_msg_prepare(user, resp, &sc.sc_buf);
    
    (void)sod_msg_fn(sod_msg_send, sc.sc_rmt, &sc.sc_buf);

    (void)memset(&sc, 0, sizeof(sc));

#ifdef SOD_DEBUG        
syslog(LOG_DEBUG, "%s\n", __func__);
#endif /* SOD_DEBUG */ 

    exit(EX_OK);
}

/*
 * By pam_vpromt(3) called conversation routine.
 * This event takes place during runtime of by
 * pam_authenticate(3) called pam_get_authtok(3).
 */
static int 
sod_conv(int num_msg, const struct pam_message **msg, 
        struct pam_response **resp, void *data) 
{
    struct sod_softc *sc = NULL;
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
                    
        sod_msg_prepare(msg[i]->msg, SOD_AUTH_NAK, &sc->sc_buf);
/*
 * Request PAM_AUTHTOK.
 */                
        if (sod_msg_fn(sod_msg_send, sc->sc_rmt, &sc->sc_buf) < 0)
            break;
/*
 * Await response from applicant.
 */    
        if (sod_msg_fn(sod_msg_recv, sc->sc_rmt, &sc->sc_buf) < 0)
            break; 
            
        if (sc->sc_buf.sm_code != SOD_AUTH_REQ)
            break;
    
        if ((tok[i].resp = calloc(1, SOD_NMAX + 1)) == NULL) 
            break;
            
#ifdef SOD_DEBUG
syslog(LOG_DEBUG, "%s: rx: %s\n", __func__, sc->sc_buf.sm_tok);    
#endif /* SOD_DEBUG */    
                
        (void)strncpy(tok[i].resp, sc->sc_buf.sm_tok, SOD_NMAX);
        (void)memset(&sc->sc_buf, 0, sizeof(sc->sc_buf));
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

/*
 * By pthread(3) encapsulated signal handler.
 */
static void *
sod_sigaction(void *arg)
{
    int sig;
    
    for (;;) {
        if (sigwait(&signalset, &sig) != 0)
            sod_errx(EX_OSERR, "Can't select signal set");

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
    return (NULL);
}

/*
 * Abnormal process termination.
 */
static void     
sod_errx(int eval, const char *fmt, ...)
{
    va_list ap;
    
    va_start(ap, fmt);
    vsyslog(LOG_ERR, fmt, ap);
    va_end(ap);    
    exit(eval);
}

/*
 * Close logfile on process termination. 
 */
static void 
sod_atexit(void)
{

    closelog();
}
