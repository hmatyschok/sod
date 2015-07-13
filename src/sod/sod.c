/*-
 * Copyright (c) 2015 Henning Matysphok
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
 */

#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

/*
 * Simple sign-on service on demand daemon - sod
 */

#include <sod_msg.h>
#include <sod_conv.h>

static pid_t 	pid;
static pthread_t 	tid;

static struct sod_conv_args sca = { 0 };

static char *cmd; 

static const char *work_dir = SOD_WORK_DIR;
static const char *pid_file = SOD_PID_FILE;
static const char *sock_file = SOD_SOCK_FILE;

static char 	lock_file[PATH_MAX + 1];
static struct sockaddr_storage 	sap;

static void 	sod_errx(int, const char *, ...);
static void 	sod_atexit(void);
static void *	sod_sigaction(void *);

static void 	
sod_errx(int eval, const char *fmt, ...)
{
	va_list ap;
	
	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);	
	exit(eval);
}

static void 
sod_atexit(void)
{
	libsod_conv_exclude();
	
	(void)unlink(sock_file);
	(void)unlink(pid_file);
	
	closelog();
}

/*
 * By pthread(3) encapsulated signal handler.
 */
static void *
sod_sigaction(void *arg)
{
	struct sod_header *sh = NULL;
	int sig;

	if ((sh = arg) == NULL) 
		goto out;
		
	for (;;) {
		if (sigwait(&sh->sh_mask, &sig) != 0)
			sod_errx(EX_OSERR, "Can't select signal set");

		switch (sig) {
		case SIGHUP:
		case SIGINT:
		case SIGKILL:	
		case SIGTERM:
			exit(0);
			break;
		default:	
			break;
		}	
	}
out:	
	return (NULL);
}

/*
 * Fork.
 */
int
main(int argc, char **argv)
{
	struct sigaction sa;
	struct sockaddr_un *sun;
	size_t len;
	
	if (getuid() != 0)
		sod_errx(EX_NOPERM, "%s", strerror(EPERM));	 
	
	if ((sca.sca_srv = open(pid_file, O_RDWR, 0640)) > -1) 
		sod_errx(EX_OSERR, "Daemon already running");	
		
	cmd = argv[sca.sca_srv];
	
	openlog(cmd, LOG_CONS, LOG_DAEMON);
	sca.sca_h.sh_flags |= SOD_SYSLOG;	
/*
 * Disable hang-up signal.
 */
	sa.sa_handler = SIG_IGN;
	(void)sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGHUP, &sa, NULL) < 0)
		sod_errx(EX_OSERR, "Can't disable SIGHUP");

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
	sa.sa_handler = SIG_IGN;
	
	(void)sigemptyset(&sa.sa_mask);
	
	sa.sa_flags = 0;

	if (sigaction(SIGHUP, &sa, NULL) < 0)
		sod_errx(EX_OSERR, "Can't disable SIGHUP");
	
	if (sigfillset(&sca.sca_h.sh_mask) < 0)
		sod_errx(EX_OSERR, "Can't initialize signal set");

	if (pthread_sigmask(SIG_BLOCK, &sca.sca_h.sh_mask, NULL) != 0)
		sod_errx(EX_OSERR, "Can't apply modefied signal set");

	if (pthread_create(&tid, NULL, sod_sigaction, &sca) != 0)
		sod_errx(EX_OSERR, "Can't initialize signal handler");
/*
 * Create SOD_PID_FILE (lockfile).
 */		
	(void)unlink(pid_file);
		
	if ((sca.sca_srv = open(pid_file, O_RDWR|O_CREAT, 0640)) < 0)
		sod_errx(EX_OSERR, "Can't open %s", pid_file);

	if (lockf(sca.sca_srv, F_TLOCK, 0) < 0)
		sod_errx(EX_OSERR, "Can't lock %s", pid_file);

	(void)snprintf(lock_file, PATH_MAX, "%d\n", getpid());

	if (write(sca.sca_srv, lock_file, PATH_MAX) < 0) 
		sod_errx(EX_OSERR, "Can't write %d in %s", getpid(), pid_file);		
/*
 * Create listening socket.
 */				
	(void)memset(&sap, 0, sizeof(sap));
	
	sun = (struct sockaddr_un *)&sap;
	sun->sun_family = AF_UNIX;
	len = sizeof(sun->sun_path);

	(void)strncpy(sun->sun_path, sock_file, len - 1);

	len += offsetof(struct sockaddr_un, sun_path);
	
	if ((sca.sca_srv = socket(sun->sun_family, SOCK_STREAM, 0)) < 0) 
		sod_errx(EX_OSERR, "Can't create socket");
 
	(void)unlink(sun->sun_path);

	if (bind(sca.sca_srv, (struct sockaddr *)sun, len) < 0)
		sod_errx(EX_OSERR, "Can't bind %s", sun->sun_path);	

	if (listen(sca.sca_srv, SOD_QLEN) < 0) 
		sod_errx(EX_OSERR, "Can't listen %s", sun->sun_path);
/*
 * Initialize requested component set.
 */
	if (libsod_conv_include(&sca) < 0)
		sod_errx(EX_OSERR, "Can't initialize libsod_conv component set");
	
	for (;;) {
/*
 * Wait until accept(2) and perform by 
 * pthread(3) embedded transaction.
 */
		sod_create_conv(&sca);
	}
			/* NOT REACHED */	
}
