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
 * version=0.2
 */

#include <stdlib.h>
#include <string.h>

#include "c_obj.h"

/*
 * Insert object.
 */
void *
c_obj_add(DB *db, DBT *key, void *arg)
{    
    struct c_obj *co;
    DBT data;
    
    if ((co = arg) == NULL)
        return (NULL);

    data.data = co;
    data.size = co->co_len;
    
    if ((*db->put)(db, key, &data, 0))
        return (NULL);
    
    return (data.data);
}

/*
 * Find requested object.
 */
void *     
c_obj_get(DB *db, DBT *key, void *arg __unused)
{    
    DBT data;

    (void)memset(&data, 0, sizeof(data));

    if ((*db->get)(db, key, &data, 0))
        return (NULL);
    
    return (data.data);
}

/*
 * Fetch requested object, but by this operation 
 * bound ressources must be released by free(3).
 */
void *     
c_obj_del(DB *db, DBT *key, void *arg __unused)
{
    DBT data;
    void *rv;
        
    (void)memset(&data, 0, sizeof(data));
    
    if ((*db->get)(db, key, &data, 0) == 0) {
       
        if ((rv = malloc(data.size)) != NULL) {
            (void)memmove(rv, data.data, data.size);
    
            if ((*db->del)(db, key, 0)) {
                free(rv);
                rv = NULL;
            }
        }    
    } else 
        rv = NULL;
    
    return (rv);
}

void *
c_obj_fn(c_obj_fn_t fn, DB *db, void *arg)
{
    struct c_obj *co;    
    DBT key;

    if ((co = arg) == NULL)
        return (NULL);
    
    key.data = &co->co_id;
    key.size = sizeof(co->co_id);
    
    return ((*fn)(db, &key, arg));
}

