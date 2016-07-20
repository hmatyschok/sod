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
 * version=0.3
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <sod.h>

/*
 * Simple test.
 */

struct sod_test_args {
    char     sta_user[SOD_NMAX + 1];
    char     sta_pw[SOD_NMAX + 1];
};
#define SOD_TEST_MAX_ARG    3

static char     sod_test_progname[SOD_NMAX + 1];

static struct sockaddr_storage     sap;
static struct sockaddr_un *sun;
static size_t len;

static void *   sod_test(void *);

/*
 * By pthread(3) called start routine.
 */
void * 
sod_test(void *arg)
{
    struct sod_test_args *sta;
    struct sod_msg *buf;
    int s, state;
    char *tok;
    
    if ((sta = arg) == NULL)
        goto bad;
/*
 * Connect with sod(8) instance.
 */    
    if ((s = socket(sun->sun_family, SOCK_STREAM, 0)) < 0) 
        goto bad;
    
    if (connect(s, (struct sockaddr *)sun, len) < 0)
        goto bad1;
        
    if ((buf = sod_msg_alloc()) == NULL)
        goto bad2;
    
    state = SOD_AUTH_REQ;
    tok = sta->sta_user;
    
    while (state) {
/*
 * Select action.
 */
        switch (state) {    
        case SOD_AUTH_REQ:
        case SOD_TERM_REQ:
/*
 * Create message.
 */ 
            sod_msg_prepare(tok, state, buf);
/*
 * Send message.
 */         
            if (sod_msg_fn(sod_msg_send, s, buf) < 0) {
                (void)printf("Can't send PAM_USER as request\n");
                state = 0;
                break;
            }
            
            if (state == SOD_AUTH_REQ)
                (void)printf("Send SOD_AUTH_REQ\n");
            else
                (void)printf("Send SOD_TERM_REQ\n");
/*
 * Await response.
 */            
            if (sod_msg_fn(sod_msg_recv, s, buf) < 0) {
                (void)printf("Can't receive response");
                state = 0;
                break;
            }
/*
 * Determine state transition.
 */
            state = buf->sm_code;
            break;
        case SOD_AUTH_NAK:
            (void)printf("Received SOD_AUTH_NAK\n");
/*
 * Select for response need data.
 */        
            state = SOD_AUTH_REQ; 
            tok = sta->sta_pw;    
            break;
        case SOD_AUTH_ACK:
            (void)printf("Received SOD_AUTH_ACK\n");
            state = SOD_TERM_REQ;
            tok = sta->sta_user;
            break;
        case SOD_AUTH_REJ:
            (void)printf("Received SOD_AUTH_REJ\n");
            state = 0;
            break;
        case SOD_TERM_ACK:
            (void)printf("Received SOD_TERM_ACK\n");
            state = 0;
            break;
        case SOD_TERM_REJ:
            (void)printf("Received SOD_TERM_REJ\n");
            state = 0;
            break;
        default:
            state = 0;
            break;
        }
    }
bad2:
    sod_msg_free(buf);
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
    pthread_t tid;
    
    sa.sa_handler = SIG_IGN;
    (void)sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGCHLD, &sa, NULL) < 0)
        errx(EX_OSERR, "Can't disable SIGCHLD");

    (void)strncpy(sod_test_progname, argv[0], SOD_NMAX);
        
    if (argc != SOD_TEST_MAX_ARG)
        errx(EX_USAGE, "\nusage: %s user pw\n", argv[0]);
/*
 * Cache arguments and prepare buffer.
 */        
    (void)memset(&sta, 0, sizeof(sta));
    (void)strncpy(sta.sta_user, argv[1], SOD_NMAX);
    (void)strncpy(sta.sta_pw, argv[2], SOD_NMAX);    
    (void)memset(&sap, 0, sizeof(sap));
/*
 * Create socket address.
 */    
    sun = (struct sockaddr_un *)&sap;
    sun->sun_family = AF_UNIX;
    len = sizeof(sun->sun_path);
    
    (void)strncpy(sun->sun_path, SOD_SOCK_FILE, len - 1);

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

