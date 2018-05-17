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

#define AES_CHUNK_SIZE 16

int eea2_init(eea2_ctx *ctx, uint32_t count, uint8_t bearer, uint8_t direction,
              uint8_t *key)
{
    uint32_t CTR[4];
    uint64_t iv[] = {0x0};
    cvm_crypto_aes_ctr_state_t *aesctx = (cvm_crypto_aes_ctr_state_t *)(ctx->state);
    /* Prepare the first counter block for eea2 initialization as in 
       section B.1.3 */
    memcpy ((ctx->aeskey).cvmkey, key, 16);
    (ctx->aeskey).cvm_keylen = 128;	

    aesctx->iv[0] = iv[0];
    aesctx->iv[1] = 0;

    memset(CTR, 0, sizeof(CTR));

    CTR[0] = count;
    CTR[1] = (bearer << 27);
    CTR[1] = CTR[1] | ((direction & 0x1) << 26);

    memcpy(aesctx->ctrblk, CTR, sizeof(CTR)); 
    aesctx->done = 0xbabe;
    return 0;
}

int eea2_enc(eea2_ctx *ctx, int length, uint8_t *input, uint8_t *output)
{
   uint8_t bits = length % 8 ;
   uint32_t inlen;
   inlen  = length/8 + !(!(length%8)); 

   cvm_crypto_aes_ctr_encrypt_update (&(ctx->aeskey), input, inlen,
                                          output, ctx->state);
   if(bits)
    {
	uint8_t rembits = 8-bits;
	uint8_t mask = (((1ULL << 8) -1) << rembits);
	uint32_t cnt = length/8;
	output[cnt] = output[cnt] & mask;
    }

   return 0;
}

int eia2_init(eia2_ctx *ctx, uint32_t count, uint32_t frash, uint8_t direction,
              uint8_t *key)
{
    uint32_t msg[2];
    ctx->flag = 0;
    memset(msg, 0, sizeof(msg));
    msg[0] = count;
    msg[1] = (frash << 27);
    msg[1] = msg[1] | ((direction & 0x1ULL) << 26);
    
    cvm_crypto_aes_cmac_init (key, 128, &(ctx->aeskey), ctx->aesctx);
    cvm_crypto_aes_cmac_update_bits(&(ctx->aeskey),(uint8_t *)msg, 64, ctx->aesctx);

    return 0;
}

int eia2_update(eia2_ctx *ctx, int length, uint8_t *input)
{
    cvm_crypto_aes_cmac_update_bits (&(ctx->aeskey),input,length, ctx->aesctx);
    return 0; 
}

int eia2_final(eia2_ctx *ctx, uint32_t *macptr)
{
    uint64_t mac[2];
    memset (mac, 0, sizeof(mac));

    cvm_crypto_aes_cmac_final (&(ctx->aeskey),ctx->aesctx,mac);
    memcpy(macptr, mac , sizeof(*macptr));

    return 0;
}
