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
 
#include <err.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

/*
 * Generating set contains Message primitives.
 */

#include <c_msg.h>

/*
 * Allocate message primitive.
 */ 
struct c_msg * 
c_msg_alloc(void)
{
	struct c_msg *msg;
	
	if ((msg = calloc(1, C_MSG_LEN)) != NULL) {
		msg->msg_id = C_MSG;
		msg->msg_len = C_MSG_LEN;
	}
	return (msg);
}

/*
 * Fills message buffer with attributes, if any.
 */
void 
c_msg_prepare(const char *s, uint32_t code, long id, struct c_msg *msg)
{
	if (msg != NULL) {
		(void)memset(msg, 0, sizeof(*msg));
	
		msg->msg_id = id;
		msg->msg_code = code;
	
		if (s != NULL) 
			(void)strncpy(msg->msg_tok, s, C_NMAX);
	}
}

/*
 * Wrapper for sendmsg(2).
 */
ssize_t 
c_msg_send(int s, struct msghdr *mh, int flags)
{
	return (sendmsg(s, mh, flags));
}

/*
 * Wrapper for recvmsg(2).
 */
ssize_t 
c_msg_recv(int s, struct msghdr *mh, int flags)
{
	return (recvmsg(s, mh, flags));
}

/* 
 * Performs MPI exchange via callback.  
 */
int
c_msg_fn(c_msg_fn_t fn, int s, struct c_msg *msg)
{
	struct iovec vec;
	struct msghdr mh;
	int eval = -1;

	if (msg == NULL)
		goto out;

	if (c_msg == NULL)
		goto out;

	if ((len = msg->msg_len) != C_MSG_LEN)
		goto out;

	if (fn == c_msg_recv || fn == c_msg_send) {
		vec.iov_base = msg;
		vec.iov_len = msg->msg_len;
	
		(void)memset(&msg, 0, sizeof(mh));
	
		msg.msg_iov = &vec;
		msg.msg_iovlen = 1;			
		
		if ((*fn)(s, &mh, 0) == msg->msg_len)
			eval = 0;	
	}
out:
	return (eval);
}

/*
 * Fills buffer with zeroes and 
 * releases bound ressources.
 */
void 
c_free_msg(struct c_msg *msg)
{
	if (msg != NULL) {
		(void)memset(msg, 0, sizeof(*msg));
		free(msg);
	}
}
