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
 * version=0.1 
 */

#include <c_msg.h>

#define C_AUTHENTICATOR_CLASS 	1421959420

#define C_AUTHENTICATOR_AUTH_REQ 	0x00000001
#define C_AUTHENTICATOR_TERM_REQ 	0x00000002

#define C_AUTHENTICATOR_AUTH_ACK 	(C_AUTHENTICATOR_AUTH_REQ|C_MSG_ACK)
#define C_AUTHENTICATOR_AUTH_NAK 	(C_AUTHENTICATOR_AUTH_REQ|C_MSG_NAK)
#define C_AUTHENTICATOR_AUTH_REJ 	(C_AUTHENTICATOR_AUTH_REQ|C_MSG_REJ)
#define	C_AUTHENTICATOR_TERM_ACK 	(C_AUTHENTICATOR_TERM_REQ|C_MSG_ACK)
#define C_AUTHENTICATOR_TERM_REJ 	(C_AUTHENTICATOR_TERM_REQ|C_MSG_REJ)

typedef struct c_thr * 	(*ca_create_t)(int, int);
typedef int 	(*ca_destroy_t)(struct c_thr *);

/*
 * Public interface.
 */

struct c_authenticator {
	struct c_obj 		ca_co;
#define ca_id 	ca_co.co_id
#define ca_len 	ca_co.co_len
	ca_create_t 	ca_create;
	ca_destroy_t 	ca_destroy;
};
#define C_AUTHENTICATOR 		1463677427
#define C_AUTHENTICATOR_LEN 		(sizeof(struct c_authenticator))

__BEGIN_DECLS
struct c_authenticator * 	c_authenticator_class_init(void);
int 	c_authenticator_class_free(void);
__END_DECLS
