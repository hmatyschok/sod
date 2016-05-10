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
 
#include <err.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

/*
 * Generating set contains SPI for MPI, sod message buffer.
 */

#include "sod_msg.h"

/*
 * Allocates n message primitives.
 */ 
struct sod_buf * 
sod_msg_alloc(size_t n)
{
	struct sod_buf *sb = NULL;
	
	if (n <= SOD_QLEN)
		sb = calloc(n, SOD_BUF_LEN);

	return (sb);
}

/*
 * Fills message buffer with attributes, if any.
 */
void 
sod_msg_prepare(const char *s, uint32_t code, void *thr, struct sod_buf *sb)
{
	struct sod_header *sh = NULL;
	
	if (sb != NULL) {
		(void)memset(sb, 0, sizeof(*sb));
	
		if ((sh = thr) != NULL) {
			sb->sb_h.sh_cookie = sh->sh_cookie;	
			sb->sb_h.sh_tid = sh->sh_tid;		
		}
		sb->sb_code = code;
	
		if (s != NULL) 
			(void)strncpy(sb->sb_tok, s, SOD_NMAX);
	}
}

/*
 * Wrapper for sendmsg(2).
 */
ssize_t 
sod_msg_send(int s, struct msghdr *msg, int flags)
{
	return (sendmsg(s, msg, flags));
}

/*
 * Wrapper for recvmsg(2).
 */
ssize_t 
sod_msg_recv(int s, struct msghdr *msg, int flags)
{
	return (recvmsg(s, msg, flags));
}

/* 
 * Performs MPI exchange via callback.  
 */
int
sod_msg_handle(sod_msg_t sod_msg, int s, struct sod_buf *sb)
{
	int eval = -1;
	ssize_t len;
	struct iovec vec;
	struct msghdr msg;

	if (sb == NULL)
		goto out;

	if (sod_msg == NULL)
		goto out;

	if ((len = sizeof(*sb)) != SOD_BUF_LEN)
		goto out;

	if (sod_msg == sod_msg_recv || sod_msg == sod_msg_send) {
		vec.iov_base = sb;
		vec.iov_len = len;
	
		(void)memset(&msg, 0, sizeof(msg));
	
		msg.msg_iov = &vec;
		msg.msg_iovlen = 1;			
		
		if ((*sod_msg)(s, &msg, 0) == len)
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
sod_free_msg(struct sod_buf *sb)
{
	if (sb != NULL) {
		(void)memset(sb, 0, sizeof(*sb));
		free(sb);
	}
}
