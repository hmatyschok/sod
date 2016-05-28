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
 * version=0.2
 */

#include <sys/stat.h>

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include <c_obj.h>
#include <c_authenticator.h>

/*
 * Simple sign-on service on demand daemon - sod
 */

#define SOD_WORK_DIR     "/"
#define SOD_PID_FILE     "/var/run/sod.pid"
#define SOD_SOCK_FILE     "/var/run/sod.sock"

static pid_t     pid;
static pthread_t     tid;

static struct c_authenticator *ca;
static struct c_signal *cs;

static char *cmd; 

static char *work_dir = SOD_WORK_DIR;
static char *pid_file = SOD_PID_FILE;
static char *sock_file = SOD_SOCK_FILE;

static char     lock_file[PATH_MAX + 1];

static struct sockaddr_storage     sap;
static struct sockaddr_un *sun;
static size_t len;

static sigset_t signalset;

static void     sod_errx(int, const char *, ...);
static void     sod_atexit(void);
static void *    sod_sigaction(void *);

/*
 * Fork.
 */
int
main(int argc, char **argv)
{
    int fd;
    
    if (getuid() != 0)
        sod_errx(EX_NOPERM, "%s", strerror(EPERM));     
    
    if ((fd = open(pid_file, O_RDWR, 0640)) > -1) 
        sod_errx(EX_OSERR, "Daemon already running");    
        
    cmd = argv[0];
    
    openlog(cmd, LOG_CONS, LOG_DAEMON);
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
        exit(0);
/*
 * Daemonize.
 */  
    (void)umask(0);

    if (setsid() < 0)
        sod_errx(EX_OSERR, "Can't set session identifier");

    if (chdir(work_dir) < 0) 
        sod_errx(EX_OSERR, "Can't change directory to %s", work_dir);

    (void)close(STDIN_FILENO);
    (void)close(STDOUT_FILENO);
    (void)close(STDERR_FILENO);

    if (atexit(sod_atexit) < 0)
        sod_errx(EX_OSERR, "Can't register sod_atexit");
/* 
 * Modefy signal handling.
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
    (void)unlink(pid_file);
        
    if ((fd = open(pid_file, O_RDWR|O_CREAT, 0640)) < 0)
        sod_errx(EX_OSERR, "Can't open %s", pid_file);

    if (lockf(fd, F_TLOCK, 0) < 0)
        sod_errx(EX_OSERR, "Can't lock %s", pid_file);

    (void)snprintf(lock_file, PATH_MAX, "%d\n", getpid());

    if (write(fd, lock_file, PATH_MAX) < 0) 
        sod_errx(EX_OSERR, "Can't write %d in %s", getpid(), pid_file);
        
    (void)close(fd);    
/*
 * Create listening socket.
 */                
    (void)memset(&sap, 0, sizeof(sap));
    
    sun = (struct sockaddr_un *)&sap;
    sun->sun_family = AF_UNIX;
    len = sizeof(sun->sun_path);

    (void)strncpy(sun->sun_path, sock_file, len - 1);

    len += offsetof(struct sockaddr_un, sun_path);
    
    if ((fd = socket(sun->sun_family, SOCK_STREAM, 0)) < 0) 
        sod_errx(EX_OSERR, "Can't create socket");
 
    (void)unlink(sun->sun_path);

    if (bind(fd, (struct sockaddr *)sun, len) < 0)
        sod_errx(EX_OSERR, "Can't bind %s", sun->sun_path);    

    if (listen(fd, C_MSG_QLEN) < 0) 
        sod_errx(EX_OSERR, "Can't listen %s", sun->sun_path);
/*
 * Fetch interface from c_authenticator_class.
 */    
     if ((ca = c_authenticator_class_init()) == NULL)
         sod_errx(EX_OSERR, "Can't initialize c_authenticator");
 
    for (;;) {
        struct c_thr *thr;
        int rmt;
/*
 * Wait until accept(2) and perform by 
 * pthread(3) embedded transaction.
 */
        if ((rmt = accept(fd, NULL, NULL)) < 0)
            continue;
        
        if ((thr = (*ca->ca_create)(fd, rmt)) != NULL) {
            (void)(*ca->ca_join)(thr);
            (void)(*ca->ca_destroy)(thr);    
        }
    }
            /* NOT REACHED */    
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
 * byr atextit(3) registered cleanup handler. 
 */
static void 
sod_atexit(void)
{
    if (ca != NULL) 
        (void)c_authenticator_class_fini(); {
        (void)c_base_class_fini();
    }
    (void)unlink(sock_file);
    (void)unlink(pid_file);
    
    closelog();
}
