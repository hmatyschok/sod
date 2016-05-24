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
 *
 * version=0.2
 */

#include <err.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include <c_obj.h>
#include <c_authenticator.h>

/*
 * Simple test.
 */
 
#define SOD_SOCK_FILE 	"/var/run/sod.sock"

struct sod_test_args {
    char 	sta_user[C_NMAX + 1];
    char 	sta_pw[C_NMAX + 1];
};

static int 	max_arg = 3;
static char 	*sock_file = SOD_SOCK_FILE;

static char     cmd[C_NMAX + 1];

static struct sockaddr_storage 	sap;
static struct sockaddr_un *sun;
static size_t len;

static pthread_t 	tid;

/*
 * By pthread(3) called start routine.
 */
void * 
sod_test(void *arg)
{
	struct sod_test_args *sta;
	struct c_msg *buf;
	int s, state;
	long id;
	char *tok;
	
	if ((sta = arg) == NULL)
	    goto bad;
/*
 * Connect with sod instance.
 */	
	if ((s = socket(sun->sun_family, SOCK_STREAM, 0)) < 0) 
		goto bad;
	
	if (connect(s, (struct sockaddr *)sun, len) < 0)
		goto bad1;
		
	if ((buf = c_msg_alloc()) == NULL)
	    goto bad2;
	
	state = C_AUTHENTICATOR_AUTH_REQ;
	id = 0;	
	tok = sta->sta_user;
	
	while (state) {
/*
 * Select action.
 */
		switch (state) {	
		case C_AUTHENTICATOR_AUTH_REQ:
/*
 * Create message.
 */ 
			c_msg_prepare(tok, state, id, buf);
/*
 * Send message.
 */ 		
			if (c_msg_fn(c_msg_send, s, buf) < 0) {
				syslog(LOG_ERR, 
					"Can't send PAM_USER as request\n");
				state = 0;
				break;
			}
			syslog(LOG_ERR, 
				"tx: C_AUTHENTICATOR_AUTH_REQ: %s\n", 
				buf->msg_tok);		
/*
 * Await response.
 */			
			if (c_msg_fn(c_msg_recv, s, buf) < 0) {
				syslog(LOG_ERR, 
					"Can't receive "
					"C_AUTHENTICATOR_AUTH_NAK "
					"as response");
				state = 0;
				break;
			}
			
			if (tok == sta->sta_user) {
/*
 * Cache for conversation need credentials.
 */
				id = buf->msg_id;
			} 
				
			if (buf->msg_id != id) {
				syslog(LOG_ERR, "Invalid tid received");
				state = 0;
				break;
			}
/*
 * Determine state transition.
 */
			state = buf->msg_code;
			break;
		case C_AUTHENTICATOR_AUTH_NAK:
			syslog(LOG_ERR, 
				"rx: C_AUTHENTICATOR_AUTH_NAK: %s", 
				buf->msg_tok);
/*
 * Select for response need data.
 */		
			state = C_AUTHENTICATOR_AUTH_REQ; 
			tok = sta->sta_pw;	
			break;
		case C_AUTHENTICATOR_AUTH_ACK:
			syslog(LOG_ERR, 
				"rx: C_AUTHENTICATOR_AUTH_ACK: PAM_SUCCESS\n");
			state = 0;
			break;
		case C_AUTHENTICATOR_AUTH_REJ:
			syslog(LOG_ERR, 
				"rx: C_AUTHENTICATOR_AUTH_REJ: PAM_AUTH_ERR\n");
			state = 0;
			break;
		default:
			state = 0;
			break;
		}
	}
bad2:
	c_msg_free(buf);
bad1:
    (void)close(s);
bad:
	return (NULL);
}

/*
 * Establish connection with sod.
 */
int	
main(int argc, char **argv) 
{
	void *rv = NULL;
	struct sigaction sa;
	struct sod_test_args sta;
	
	sa.sa_handler = SIG_IGN;
	(void)sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGCHLD, &sa, NULL) < 0)
		errx(EX_OSERR, "Can't disable SIGCHLD");

	(void)strncpy(cmd, argv[0], C_NMAX);
		
	if (argc != max_arg)
		errx(EX_USAGE, "\nusage: %s user pw\n", argv[0]);
/*
 * Cache arguments and prepare buffer.
 */		
	(void)memset(&sta, 0, sizeof(sta));
	(void)strncpy(sta.sta_user, argv[1], C_NMAX);
	(void)strncpy(sta.sta_pw, argv[2], C_NMAX);	
	(void)memset(&sap, 0, sizeof(sap));
/*
 * Create socket address.
 */	
    sun = (struct sockaddr_un *)&sap;
	sun->sun_family = AF_UNIX;
	len = sizeof(sun->sun_path);
	
	(void)strncpy(sun->sun_path, sock_file, len - 1);

	len += offsetof(struct sockaddr_un, sun_path);
/*
 * Execute.
 */ 
	if (pthread_create(&tid, NULL, sod_test, &sta) != 0)
		errx(EX_OSERR, "Can't create pthread(3)");
/*
 * Serialize, if possible.
 */	
	if (pthread_join(tid, &rv) != 0)
		errx(EX_OSERR, "Can't serialize execution of "
			"former created pthread(3)"); 
			
	exit(EX_OK);
}

