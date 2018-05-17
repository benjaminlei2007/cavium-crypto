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

int f8(uint32_t count, uint8_t bearer, uint8_t direction, uint8_t *key, 
       int length, uint8_t *input, uint8_t *output)
{
    f8_ctx CTX;
    int ret=-1;
    CTX.uea_rev = UEA_REV_2;
    ret = f8_init(&CTX, count, bearer, direction, key);
    if(ret)
        return ret;
    ret = f8_enc(&CTX, length, input, output);
    return ret;
}
int f9(uint32_t count, uint32_t fresh, uint8_t direction, uint8_t *key,
       int length, uint8_t *input, uint32_t *mac)
{
    f9_ctx CTX;
    int ret=-1;
    CTX.uia_rev = UIA_REV_2;
    ret = f9_init(&CTX, count, fresh, direction, key);
    if(ret) return ret;
    ret = f9_update(&CTX, length, input);
    if(ret) return ret;
    ret = f9_final(&CTX, mac);
    return ret;
}

int f8_uea1(uint32_t count, uint8_t bearer, uint8_t direction, uint8_t *key,
            int length, uint8_t *input, uint8_t *output)
{
    f8_ctx CTX;
    int ret=-1;
    CTX.uea_rev = UEA_REV_1;
    ret = f8_init(&CTX, count, bearer, direction, key);
    if(ret)
        return ret;
    ret = f8_enc(&CTX, length, input, output);
    return ret;
}
 
int f9_uia1(uint32_t count, uint32_t fresh, uint8_t direction, uint8_t *key,
            int length, uint8_t *input, uint32_t *mac)
{
    f9_ctx CTX;
    int ret=-1;
    CTX.uia_rev = UIA_REV_1;
    ret = f9_init(&CTX, count, fresh, direction, key);
    if(ret) return ret;
    ret = f9_update(&CTX, length, input);
    if(ret) return ret;
    ret = f9_final(&CTX, mac);
    return ret;
}

int f8_eea2(uint32_t count, uint8_t bearer, uint8_t direction, uint8_t *key,
            int length, uint8_t *input, uint8_t *output)
{
    f8_ctx CTX;
    int ret=-1;
    CTX.uea_rev = EEA_REV_2;
    ret = f8_init(&CTX, count, bearer, direction, key);
    if(ret)
        return ret;
    ret = f8_enc(&CTX,length, input, output);
    return ret;
} 

int f9_eia2(uint32_t count, uint32_t bearer, uint8_t direction, uint8_t *key,
            int length, uint8_t *input, uint32_t *mac)
{
    f9_ctx CTX;
    int ret=-1;
    CTX.uia_rev = EIA_REV_2;
    ret = f9_init(&CTX, count, bearer, direction, key);
    if(ret) return ret;
    ret = f9_update(&CTX, length, input);
    if(ret) return ret;
    ret = f9_final(&CTX, mac);
    return ret;
}

int f8_init(f8_ctx *ctx, uint32_t count, uint8_t bearer, uint8_t direction,
            uint8_t *key)
{
    if (ctx->uea_rev == 0)
        ctx->uea_rev=UEA_REV_2;
    if (ctx->uea_rev == UEA_REV_1)
        return uea1_init(&ctx->uea.uea1_c, count, bearer, direction, key);
    if (ctx->uea_rev == UEA_REV_2)
        return uea2_init(&ctx->uea.uea2_c, count, bearer, direction, key);
    if (ctx->uea_rev == EEA_REV_2)
        return eea2_init(&ctx->uea.eea2_c, count, bearer, direction, key);
    return -1;
}
int f8_enc(f8_ctx *ctx, int length, uint8_t *input, uint8_t *output)
{
    if (ctx->uea_rev == 0)
        ctx->uea_rev=UEA_REV_2;
    if (ctx->uea_rev == UEA_REV_1)
        return uea1_enc(&ctx->uea.uea1_c, length, input, output);
    if (ctx->uea_rev == UEA_REV_2)
        return uea2_enc(&ctx->uea.uea2_c, length, input, output);
    if (ctx->uea_rev == EEA_REV_2)
        return eea2_enc(&ctx->uea.eea2_c, length, input, output);
    return -1;
}

int f9_init(f9_ctx *ctx, uint32_t count, uint32_t fresh, uint8_t direction,
            uint8_t *key)
{  
    if (ctx->uia_rev == 0)
        ctx->uia_rev=UIA_REV_2;
    if (ctx->uia_rev == UIA_REV_1)
        return uia1_init(&ctx->uia.uia1_c, count, fresh, direction, key);
    if (ctx->uia_rev == UIA_REV_2)
        return uia2_init(&ctx->uia.uia2_c, count, fresh, direction, key);
    if (ctx->uia_rev == EIA_REV_2)
        return eia2_init(&ctx->uia.eia2_c, count, fresh, direction, key);
    return -1;
}

int f9_update(f9_ctx *ctx, int length, uint8_t *input)
{  
    if (ctx->uia_rev == 0)
        ctx->uia_rev=UIA_REV_2;
    if (ctx->uia_rev == UIA_REV_1)
        return uia1_update(&ctx->uia.uia1_c, length, input);
    if (ctx->uia_rev == UIA_REV_2)
        return uia2_update(&ctx->uia.uia2_c, length, input);
    if (ctx->uia_rev == EIA_REV_2){
        return eia2_update(&ctx->uia.eia2_c, length, input);
    }
    return -1;
}

int f9_final(f9_ctx *ctx, uint32_t *mac)
{
    if (ctx->uia_rev == 0)
        ctx->uia_rev=UIA_REV_2;
    if (ctx->uia_rev == UIA_REV_1)
        return uia1_final(&ctx->uia.uia1_c, mac);
    if (ctx->uia_rev == UIA_REV_2)
        return uia2_final(&ctx->uia.uia2_c, mac);
    if (ctx->uia_rev == EIA_REV_2)
        return eia2_final(&ctx->uia.eia2_c, mac);
    return -1;
}
