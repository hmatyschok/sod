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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

/*
 * Simple test.
 */
 
#include <c_msg.h>

static pthread_t 	tid;

static const int 	max_arg = 3;

static char 	cmd[C_NMAX + 1];
static char 	user[C_NMAX + 1];
static char 	pw[C_NMAX + 1];

static const char 	*sock_file = SOD_SOCK_FILE;

static struct sockaddr_storage 	sap;

static void 	cleanup(void);
static void 	usage(void);

/*
 * By pthread(3) called start routine.
 */
void * 
sod_test(void *arg)
{
	int srv;
	struct c_msg buf;
	struct sod_header sh;
	uint32_t state;
	char *tok;
	
	if (arg == NULL)
		goto out;
		
	srv = *(int *)arg;	
		
	(void)memset(&sh, 0, sizeof(sh));

	state = SOD_AUTH_REQ;
	tok = user;
	
	while (state != 0) {
/*
 * Select action.
 */
		switch (state) {	
		case SOD_AUTH_REQ:
/*
 * Create message.
 */ 
			sod_prepare_msg(tok, state, &sh, &buf);
		
			if (sod_handle_msg(sod_send_msg, srv, &buf) < 0) {
				syslog(LOG_ERR, "Can't send PAM_USER as request\n");
				state = 0;
				break;
			}
			syslog(LOG_ERR, "tx: SOD_AUTH_REQ: %s\n", buf.sb_tok);		
/*
 * Await response.
 */			
			if (sod_handle_msg(sod_recv_msg, srv, &buf) < 0) {
				syslog(LOG_ERR, "Can't receive SOD_AUTH_NAK "
					"as response");
				state = 0;
				break;
			}
			
			if (tok == user) {
/*
 * Cache for conversation need credentials.
 */
				sh.sh_cookie = buf.sb_h.sh_cookie;
				sh.sh_tid = buf.sb_h.sh_tid;
			} 
			
			if (buf.sb_h.sh_cookie != sh.sh_cookie) {
				syslog(LOG_ERR, "Invalid cookie received");
				state = 0;
				break;
			}
				
			if (buf.sb_h.sh_tid != sh.sh_tid) {
				syslog(LOG_ERR, "Invalid tid received");
				state = 0;
				break;
			}
/*
 * Determine state transition.
 */
			state = buf.sb_code;
			break;
		case SOD_AUTH_NAK:
			syslog(LOG_ERR, "rx: SOD_AUTH_NAK: %s", buf.sb_tok);
/*
 * Select for response need data.
 */		
			state = SOD_AUTH_REQ; 
			tok = pw;	
			break;
		case SOD_AUTH_ACK:
			syslog(LOG_ERR, "rx: SOD_AUTH_ACK: PAM_SUCCESS\n");
			state = 0;
			break;
		case SOD_AUTH_REJ:
			syslog(LOG_ERR, "rx: SOD_AUTH_REJ: PAM_AUTH_ERR\n");
			state = 0;
			break;
		default:
			state = 0;
			break;
		}
	}
	(void)memset(&buf, 0, sizeof(buf));
out:
	return (NULL);
}

/*
 * Establish connection with sod.
 */
int	
main(int argc, char **argv) 
{
	void *rv = NULL;
	static int s = 0;
	struct sigaction sa;
	struct sockaddr_un *sun;
	size_t len;
	
	sa.sa_handler = SIG_IGN;
	(void)sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGCHLD, &sa, NULL) < 0)
		errx(EX_OSERR, "Can't disable SIGCHLD");

	if (atexit(cleanup) < 0)
		errx(EX_OSERR, "Can't register exit handle");
	
	(void)strncpy(cmd, argv[s++], C_NMAX);
		
	if (argc != max_arg)
		usage();
/*
 * Cache arguments and prepare buffer.
 */		
	(void)strncpy(user, argv[s++], C_NMAX);
	(void)strncpy(pw, argv[s], C_NMAX);	
	(void)memset(&sap, 0, sizeof(sap));
/*
 * Connect with sod instance.
 */	
	sun = (struct sockaddr_un *)&sap;
	sun->sun_family = AF_UNIX;
	len = sizeof(sun->sun_path);
	(void)strncpy(sun->sun_path, sock_file, len - 1);
	len += offsetof(struct sockaddr_un, sun_path);
	
	if ((s = socket(sun->sun_family, SOCK_STREAM, 0)) < 0) 
		errx(EX_OSERR, "Can't create socket");
	
	if (connect(s, (struct sockaddr *)sun, len) < 0)
		errx(EX_OSERR, "Can't connect with %s", sun->sun_path);
/*
 * Execute.
 */ 
	if (pthread_create(&tid, NULL, sod_test, &s) != 0)
		errx(EX_OSERR, "Can't create pthread(3)");
/*
 * Serialize, if possible.
 */	
	if (pthread_join(tid, &rv) != 0)
		errx(EX_OSERR, "Can't serialize execution of "
			"former created pthread(3)"); 
			
	exit(0);
}

static void 
cleanup(void) 
{
	(void)memset(&sap, 0, sizeof(sap));
}

static void 
usage(void)
{
	errx(EX_USAGE, "\nusage: %s user pw\n", cmd);
}
