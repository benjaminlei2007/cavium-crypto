/* ====================================================================
 * Copyright (c) 1998-2008 The OpenSSL Project.  All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
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
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */



#include "cvmx.h"
#include <openssl/f8-f9.h>

int uea1_init(uea1_ctx *ctx, uint32_t count, uint8_t bearer, uint8_t direction,
              uint8_t *key)
{
    uint64_t start=0x0ull;
    if(!OCTEON_IS_MODEL(OCTEON_CN58XX) &&
       !OCTEON_IS_MODEL(OCTEON_CN56XX) &&
       !OCTEON_IS_MODEL(OCTEON_CN6XXX) &&
       !OCTEON_IS_OCTEON3())
    { 
        printf("f8(uae1) supported only in "
            "CN58XX/CN56XX/CN6XXX/CN7XXX\n");
        return -1;
    }
    ctx->key0=((uint64_t *)key)[0];
    ctx->key1=((uint64_t *)key)[1];
    start=((uint64_t)count<<32)|((uint64_t)(bearer & 0x1f))<<27
          |(uint64_t)(direction&0x1)<<26;
    CVMX_MT_KAS_KEY((ctx->key0^0x5555555555555555ull),0);
    CVMX_MT_KAS_KEY((ctx->key1^0x5555555555555555ull),1) ;
    CVMX_MT_KAS_ENC(start);
    CVMX_MF_KAS_RESULT(start);
    ctx->start=start;
    ctx->blkcnt=0ull;
    ctx->pos=8;
    ctx->x.ksb=0ull;
    return 0;

}

int uea1_enc(uea1_ctx *ctx, int length, uint8_t *input, uint8_t *output)
{
    uint64_t ksb;
    uint64_t blkcnt;
    uint64_t in,out; 
    uint64_t start=ctx->start;
    int i,n;
    ksb=ctx->x.ksb;
    blkcnt=ctx->blkcnt;
    CVMX_MT_KAS_KEY(ctx->key0,0);
    CVMX_MT_KAS_KEY(ctx->key1,1);
    while(ctx->pos<8)
    {
        *output=(*input)^(ctx->x.k[ctx->pos]);
        ctx->pos++;
        length-=8;
        input++;
        output++;
    }
    while(length>=128)
    {
        in=*((uint64_t *)input);
        CVMX_MT_KAS_ENC(start^blkcnt^ksb);
        blkcnt++;
        length-=128;
        CVMX_MF_KAS_RESULT(ksb);
        CVMX_MT_KAS_ENC(start^blkcnt^ksb);
        out=in^ksb; 
        *((uint64_t *)output)=out;
        in=*((uint64_t *)(input+8));
        blkcnt++;
        CVMX_MF_KAS_RESULT(ksb);
        out=in^ksb; 
        *((uint64_t *)(output+8))=out;
        input+=16;
        output+=16;
    }
    if(length>=64)
    { 
        in=*((uint64_t *)input);
        CVMX_MT_KAS_ENC(start^blkcnt^ksb);
        out=*((uint64_t *)output);
        blkcnt++;
        length-=64;
        CVMX_MF_KAS_RESULT(ksb);
        out=in^ksb; 
        *((uint64_t *)output)=out; 
        input+=8;
        output+=8;
    }
    if(length)
    {
        CVMX_MT_KAS_ENC(start^blkcnt^ksb);
        n=(length+7)/8;
        blkcnt++;
        CVMX_MF_KAS_RESULT(ksb);
        ctx->x.ksb=ksb;
        for(i=0;i<n;i++)
            output[i]=input[i]^ctx->x.k[i]; 
        ctx->pos=n;
    }
    ctx->x.ksb=ksb;
    ctx->blkcnt=blkcnt;
    return 0;
}

int uia1_init(uia1_ctx *ctx, uint32_t count, uint32_t fresh, uint8_t direction,
              uint8_t *key)
{  
    uint64_t a=0ull;
    if(!OCTEON_IS_MODEL(OCTEON_CN58XX) &&
       !OCTEON_IS_MODEL(OCTEON_CN56XX) &&
       !OCTEON_IS_MODEL(OCTEON_CN6XXX) &&
       !OCTEON_IS_OCTEON3())
    { 
        printf("f9(uia1) supported only in "
            "CN58XX/CN56XX/CN6XXX/CN7XXX\n");
        return -1;
    }
    CVMX_MT_KAS_KEY(((uint64_t *)key)[0],0); 
    CVMX_MT_KAS_KEY(((uint64_t *)key)[1],1); 
    a=((uint64_t)count<<32|fresh)^a;
    CVMX_MT_KAS_ENC(a);
    CVMX_MF_KAS_RESULT(a);
    ctx->a=a;
    ctx->b=a;
    ctx->key0=((uint64_t *)key)[0];
    ctx->key1=((uint64_t *)key)[1];
    ctx->rem_len=0;
    ctx->x.dat=0ull;
    ctx->direction = direction;
    return 0;
}

int uia1_update(uia1_ctx *ctx, int length, uint8_t *input)
{  
    uint64_t a=0ull,b=0ull;
    uint64_t in;
    in=((uint64_t *)input)[0];
    CVMX_MT_KAS_KEY(ctx->key0,0); 
    CVMX_MT_KAS_KEY(ctx->key1,1); 
    if(ctx->rem_len)
    {
        int i,j=0;
        length+=ctx->rem_len;
        ctx->rem_len=ctx->rem_len/8;
        for(i=ctx->rem_len;i<8;i++){
            ctx->x.d[i]=input[j];  
            j++;
        }
        in=ctx->x.dat;
        ctx->rem_len=0;
        input=input+j; 
    }else
        input+=8;
    a=ctx->a;
    b=ctx->b;
    while(length>=128)
    {
        CVMX_MT_KAS_ENC(a^in);
        in=((uint64_t *)input)[0];
        CVMX_MF_KAS_RESULT(a);
        CVMX_MT_KAS_ENC(a^in);
        b=a^b;
        in=((uint64_t *)input)[1];
        input+=16;
        length-=128;
        CVMX_MF_KAS_RESULT(a);
        b=a^b;
    }
    if(length>=64)
    {
        CVMX_MT_KAS_ENC(a^in);
        in=((uint64_t *)input)[0];
        input+=8;
        length-=64;
        CVMX_MF_KAS_RESULT(a);
        b=a^b;
    }
    if(length)
        ctx->x.dat=in;
    else
        ctx->x.dat=0ull;
    ctx->a=a;
    ctx->b=b;
    ctx->rem_len=length;     
    return 0; 
}

int uia1_final(uia1_ctx *ctx, uint32_t *mac)
{
    int length=ctx->rem_len+2;
    uint64_t in=ctx->x.dat;
    uint64_t a=ctx->a;
    uint64_t b=ctx->b;
    if(!OCTEON_IS_MODEL(OCTEON_CN58XX) &&
       !OCTEON_IS_MODEL(OCTEON_CN56XX) &&
       !OCTEON_IS_MODEL(OCTEON_CN6XXX) &&
       !OCTEON_IS_OCTEON3())
    { 
        printf("f9(uia1) supported only in "
            "CN58XX/CN56XX/CN6XXX/CN7XXX\n");
        return -1;
    }
    CVMX_MT_KAS_KEY(ctx->key0,0); 
    CVMX_MT_KAS_KEY(ctx->key1,1); 
    if(length)
    {
        if(length>64){
            in|=(ctx->direction?1:0);
            CVMX_MT_KAS_ENC(a^in);
            in=0x8000000000000000ull;
            length-=64;
            CVMX_MF_KAS_RESULT(a);
            CVMX_MT_KAS_ENC(a^in);
            b=a^b;
            CVMX_MF_KAS_RESULT(a);
            b=a^b;
        }else{
            int pad_len=64-length;
            in=(in>>pad_len);
            in|=(ctx->direction?1:0)<<1|0x1;
            in=in<<pad_len;
            CVMX_MT_KAS_ENC(a^in);
            CVMX_MF_KAS_RESULT(a);
            b=a^b;
        }
    }
    CVMX_MT_KAS_KEY((ctx->key0^0xAAAAAAAAAAAAAAAAull),0);
    CVMX_MT_KAS_KEY((ctx->key1^0xAAAAAAAAAAAAAAAAull),1);
    CVMX_MT_KAS_ENC(b);
    CVMX_MF_KAS_RESULT(b);
    *mac=(b>>32);
    return 0;
}

