/*-
 * Copyright (c) 2016 Henning Matyschok
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
 * version=0.3
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <string.h>

#include "sod.h"

/*
 * Allocate message primitive.
 */ 
struct sod_msg * 
sod_msg_alloc(void)
{

    return (calloc(1, SOD_MSG_LEN));
}

/*
 * Fills message buffer with attributes, if any.
 */
void 
sod_msg_prepare(const char *s, int code, struct sod_msg *sm)
{
    if (sm != NULL) {
        (void)memset(sm, 0, sizeof(*sm));
    
        sm->sm_code = code;
  
        if (s != NULL) 
            (void)strncpy(sm->sm_tok, s, SOD_NMAX);
    }
}

/*
 * Wrapper for sendmsg(2).
 */
ssize_t 
sod_msg_send(int s, struct sod_msg *sm, int flags)
{
    return (send(s, sm, sizeof(*sm), flags));
}

/*
 * Wrapper for recvmsg(2).
 */
ssize_t 
sod_msg_recv(int s, struct sod_msg *sm, int flags)
{
    return (recv(s, sm, sizeof(*sm), flags));
}

/* 
 * Performs MPI exchange via callback.  
 */
int
sod_msg_fn(sod_msg_fn_t fn, int s, struct sod_msg *sm)
{
    if (sm == NULL) 
        return (-1)
        
    if (fn == sod_msg_recv || fn == sod_msg_send) {
        if ((*fn)(s, sm, 0) == sizeof(*sm))
            return (0);    
    }
    return (-1);
}

/*
 * Fills buffer with zeroes and 
 * releases bound ressources.
 */
void 
sod_msg_free(struct sod_msg *sm)
{
    if (sm != NULL) {
        (void)memset(sm, 0, sizeof(*sm));
        free(sm);
    }
}
