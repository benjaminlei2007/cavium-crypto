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



#ifdef OCTEON_OPENSSL
#include <string.h>
#include <assert.h>

#include "cvmx.h"
#include "cvmx-key.h"

#include "openssl/aes.h"
#include <openssl/crypto.h>

int XTS_AES_ctx_init(uint64_t *key1,uint64_t *key2,uint32_t keylen,uint64_t dseqnum,aes_xts_ctx_t *ctx)
{
  int j; 
  uint8_t *T;

  if(!key1 || !key2 || !ctx)
    return XTS_AES_NULL_POINTER_ARGUMENT;

  if(!keylen || !((keylen==128)||(keylen==256)))
    return XTS_AES_INVALID_KEYLENGTH;

  ctx->key1[0] = key1[0];
  ctx->key1[1] = key1[1];
  ctx->key2[0] = key2[0];
  ctx->key2[1] = key2[1];
  
  if(keylen==256) {
    ctx->key1[2] = key1[2];
    ctx->key1[3] = key1[3];
    ctx->key2[2] = key2[2];
    ctx->key2[3] = key2[3];
  } else {
    ctx->key1[2] = 0;
    ctx->key1[3] = 0;
    ctx->key2[2] = 0;
    ctx->key2[3] = 0;
  }

  ctx->keylen = keylen/64-1;


  T = (uint8_t*)ctx->tweak;
  for(j=0;j<16;j++) {
    T[j] = (uint8_t)(dseqnum & 0xFF);
    dseqnum = dseqnum >> 8;
  }

  CVMX_MT_AES_KEY(ctx->key2[0],0);
  CVMX_MT_AES_KEY(ctx->key2[1],1);
  CVMX_MT_AES_KEY(ctx->key2[2],2);
  CVMX_MT_AES_KEY(ctx->key2[3],3);
  CVMX_MT_AES_KEYLENGTH(keylen/64-1);

  CVMX_MT_AES_ENC0(ctx->tweak[0]);
  CVMX_MT_AES_ENC1(ctx->tweak[1]);
  CVMX_MF_AES_RESULT(ctx->tweak[0],0);
  CVMX_MF_AES_RESULT(ctx->tweak[1],1);

  ctx->state = 0xbabe;
  return XTS_AES_SUCCESS;
}

int XTS_AES_ctx_encrypt(uint8_t *pt,uint32_t len,uint8_t *ct,aes_xts_ctx_t *ctx)
{
  uint64_t *plain;
  uint64_t *cipher;
  uint64_t *ctxtweak;
  uint64_t oldtweak[2];
  uint64_t x[2];
  uint64_t rx[2];
  int32_t j;
  uint64_t all80  = 0x8080808080808080ull;
  uint64_t all7f  = ~all80;
  uint64_t lenby8, i=0;
  uint64_t upperbits, lsb, cout;

  if(!pt || !ct || !ctx)
    return XTS_AES_NULL_POINTER_ARGUMENT;

  if(len<16)
    return XTS_AES_INVALID_DATALENGTH;

  if((ctx->state==0xdead) || (ctx->state!=0xbabe))
    return XTS_AES_INVALID_CTX;

  CVMX_PREFETCH0 (pt);

  plain = (uint64_t*)pt;
  cipher = (uint64_t*)ct;
  ctxtweak = (uint64_t*)ctx->tweak;
  
  CVMX_MT_AES_KEY(ctx->key1[0],0);  
  CVMX_MT_AES_KEY(ctx->key1[1],1);  
  CVMX_MT_AES_KEY(ctx->key1[2],2);  
  CVMX_MT_AES_KEY(ctx->key1[3],3);  
  CVMX_MT_AES_KEYLENGTH(ctx->keylen);

  /* uint64_t start,end; */
    
  lenby8 = len /16 * 2;
  lenby8 -= 2;
  
  /* start  = cvmx_get_cycle(); */

  if(len>=48) {
    x[0] = plain[0] ^ ctxtweak[0];
    x[1] = plain[1] ^ ctxtweak[1];
    
    CVMX_MT_AES_ENC0(x[0]);
    CVMX_MT_AES_ENC1(x[1]);

    oldtweak[0] = ctxtweak[0];
    oldtweak[1] = ctxtweak[1];

    upperbits = ctxtweak[0] & all80;
    ctxtweak[0] &= all7f;
    lsb = upperbits & 0xffull;
    ctxtweak[0] = (ctxtweak[0]<<1) + (upperbits>>15);

    upperbits = ctxtweak[1] & all80;
    ctxtweak[1] &= all7f;
    cout = upperbits & 0xffull;
    upperbits = (lsb<<56) | (upperbits>>8);
    ctxtweak[1] = (ctxtweak[1]<<1) + (upperbits>>7);

    ctxtweak[0] ^= (cout?0x87ull<<56:0);
    
    plain += 2;
    x[0] = plain[0] ^ ctxtweak[0];
    x[1] = plain[1] ^ ctxtweak[1];

    CVMX_MF_AES_RESULT(rx[0],0);
    CVMX_MF_AES_RESULT(rx[1],1);


    for( i = 2; i < lenby8; i += 2 ) {
      CVMX_MT_AES_ENC0(x[0]);
      CVMX_MT_AES_ENC1(x[1]);

      CVMX_PREFETCH0(plain+16);

      cipher[0] = rx[0] ^ oldtweak[0];
      cipher[1] = rx[1] ^ oldtweak[1];
      cipher += 2;
      
      oldtweak[0] = ctxtweak[0];
      oldtweak[1] = ctxtweak[1];

      upperbits = ctxtweak[0] & all80;
      ctxtweak[0] &= all7f;
      lsb = upperbits & 0xffull;
      ctxtweak[0] = (ctxtweak[0]<<1) + (upperbits>>15);

      upperbits = ctxtweak[1] & all80;
      ctxtweak[1] &= all7f;
      cout = upperbits & 0xffull;
      upperbits = (lsb<<56) | (upperbits>>8);
      ctxtweak[1] = (ctxtweak[1]<<1) + (upperbits>>7);

      ctxtweak[0] ^= (cout?0x87ull<<56:0);

      plain += 2;
      x[0] = plain[0] ^ ctxtweak[0];
      x[1] = plain[1] ^ ctxtweak[1];

      CVMX_MF_AES_RESULT(rx[0],0);
      CVMX_MF_AES_RESULT(rx[1],1);
    }

    CVMX_MT_AES_ENC0(x[0]);
    CVMX_MT_AES_ENC1(x[1]);

    cipher[0] = rx[0] ^ oldtweak[0];
    cipher[1] = rx[1] ^ oldtweak[1];
    cipher += 2;

    oldtweak[0] = ctxtweak[0];
    oldtweak[1] = ctxtweak[1];

    upperbits = ctxtweak[0] & all80;
    ctxtweak[0] &= all7f;
    lsb = upperbits & 0xffull;
    ctxtweak[0] = (ctxtweak[0]<<1) + (upperbits>>15);

    upperbits = ctxtweak[1] & all80;
    ctxtweak[1] &= all7f;
    cout = upperbits & 0xffull;
    upperbits = (lsb<<56) | (upperbits>>8);
    ctxtweak[1] = (ctxtweak[1]<<1) + (upperbits>>7);

    ctxtweak[0] ^= (cout?0x87ull<<56:0);
    
    i+=2;
    i<<=3;
    CVMX_MF_AES_RESULT(rx[0],0);
    CVMX_MF_AES_RESULT(rx[1],1);

    cipher[0] = rx[0] ^ oldtweak[0];
    cipher[1] = rx[1] ^ oldtweak[1];

  } else if(len>=32 ){

    x[0] = plain[0] ^ ctxtweak[0];
    x[1] = plain[1] ^ ctxtweak[1];
    
    CVMX_MT_AES_ENC0(x[0]);
    CVMX_MT_AES_ENC1(x[1]);

    oldtweak[0] = ctxtweak[0];
    oldtweak[1] = ctxtweak[1];

    upperbits = ctxtweak[0] & all80;
    ctxtweak[0] &= all7f;
    lsb = upperbits & 0xffull;
    ctxtweak[0] = (ctxtweak[0]<<1) + (upperbits>>15);

    upperbits = ctxtweak[1] & all80;
    ctxtweak[1] &= all7f;
    cout = upperbits & 0xffull;
    upperbits = (lsb<<56) | (upperbits>>8);
    ctxtweak[1] = (ctxtweak[1]<<1) + (upperbits>>7);

    ctxtweak[0] ^= (cout?0x87ull<<56:0);
    
    plain += 2;
    x[0] = plain[0] ^ ctxtweak[0];
    x[1] = plain[1] ^ ctxtweak[1];

    CVMX_MF_AES_RESULT(rx[0],0);
    CVMX_MF_AES_RESULT(rx[1],1);

    CVMX_MT_AES_ENC0(x[0]);
    CVMX_MT_AES_ENC1(x[1]);

    cipher[0] = rx[0] ^ oldtweak[0];
    cipher[1] = rx[1] ^ oldtweak[1];
    cipher += 2;

    oldtweak[0] = ctxtweak[0];
    oldtweak[1] = ctxtweak[1];

    upperbits = ctxtweak[0] & all80;
    ctxtweak[0] &= all7f;
    lsb = upperbits & 0xffull;
    ctxtweak[0] = (ctxtweak[0]<<1) + (upperbits>>15);

    upperbits = ctxtweak[1] & all80;
    ctxtweak[1] &= all7f;
    cout = upperbits & 0xffull;
    upperbits = (lsb<<56) | (upperbits>>8);
    ctxtweak[1] = (ctxtweak[1]<<1) + (upperbits>>7);

    ctxtweak[0] ^= (cout?0x87ull<<56:0);
    
    i=32;
    CVMX_MF_AES_RESULT(rx[0],0);
    CVMX_MF_AES_RESULT(rx[1],1);

    cipher[0] = rx[0] ^ oldtweak[0];
    cipher[1] = rx[1] ^ oldtweak[1];

  } else if(len>=16) {
    x[0] = plain[0] ^ ctxtweak[0];
    x[1] = plain[1] ^ ctxtweak[1];
    
    CVMX_MT_AES_ENC0(x[0]);
    CVMX_MT_AES_ENC1(x[1]);

    oldtweak[0] = ctxtweak[0];
    oldtweak[1] = ctxtweak[1];

    upperbits = ctxtweak[0] & all80;
    ctxtweak[0] &= all7f;
    lsb = upperbits & 0xffull;
    ctxtweak[0] = (ctxtweak[0]<<1) + (upperbits>>15);

    upperbits = ctxtweak[1] & all80;
    ctxtweak[1] &= all7f;
    cout = upperbits & 0xffull;
    upperbits = (lsb<<56) | (upperbits>>8);
    ctxtweak[1] = (ctxtweak[1]<<1) + (upperbits>>7);

    ctxtweak[0] ^= (cout?0x87ull<<56:0);
    
    i = 16;
    CVMX_MF_AES_RESULT(rx[0],0);
    CVMX_MF_AES_RESULT(rx[1],1);

    cipher[0] = rx[0] ^ oldtweak[0];
    cipher[1] = rx[1] ^ oldtweak[1];
  }
  
  /* end = cvmx_get_cycle(); */
  /* printf("cycles = %ld\n",end-start); */

  if(cvmx_unlikely(len%16)) {
    uint8_t x[16];
    uint64_t *CT;
    uint64_t *X;
    ctx->state = 0xdead;
  
    for(j=0;(i+j)<len;j++) {
      x[j] = pt[i+j] ;
      ct[i+j] = ct[i+j-16];
    }

    for(;j<16;j++) {
      x[j] = ct[i+j-16];
    }
  
    X = (uint64_t*)x;
    X[0] = X[0] ^ ctx->tweak[0];
    X[1] = X[1] ^ ctx->tweak[1];
    CVMX_MT_AES_ENC0(X[0]);
    CVMX_MT_AES_ENC1(X[1]);
    CVMX_MF_AES_RESULT(X[0],0);
    CVMX_MF_AES_RESULT(X[1],1);

    CT = (uint64_t*)&ct[i-16];

    CT[0] = X[0] ^ ctx->tweak[0];
    CT[1] = X[1] ^ ctx->tweak[1];
  } 
  
  return XTS_AES_SUCCESS;
}

int XTS_AES_ctx_decrypt(uint8_t *ct,uint32_t len,uint8_t *pt,aes_xts_ctx_t *ctx)
{
  uint64_t *plain;
  uint64_t *cipher;
  uint64_t *ctxtweak;
  uint64_t oldtweak[2];
  uint64_t x[2];
  uint64_t rx[2];
  uint64_t all80  = 0x8080808080808080ull;
  uint64_t all7f  = ~all80;
  uint64_t lenby8, i=0, j;
  uint64_t upperbits,lsb,cout;
  
  if(!pt || !ct || !ctx)
    return XTS_AES_NULL_POINTER_ARGUMENT;

  if(len<16)
    return XTS_AES_INVALID_DATALENGTH;

  if((ctx->state==0xdead) || (ctx->state!=0xbabe))
    return XTS_AES_INVALID_CTX;

  CVMX_PREFETCH0 (ct);

  plain = (uint64_t*)pt;
  cipher = (uint64_t*)ct;
  ctxtweak = (uint64_t*)ctx->tweak;
  
  CVMX_MT_AES_KEY(ctx->key1[0],0);  
  CVMX_MT_AES_KEY(ctx->key1[1],1);  
  CVMX_MT_AES_KEY(ctx->key1[2],2);  
  CVMX_MT_AES_KEY(ctx->key1[3],3);  
  CVMX_MT_AES_KEYLENGTH(ctx->keylen);

  /* uint64_t start,end; */
    
  lenby8 = len /16 * 2;
  lenby8 -= 2;
  
  /* start  = cvmx_get_cycle(); */

  if(len>=48) {
    x[0] = cipher[0] ^ ctxtweak[0];
    x[1] = cipher[1] ^ ctxtweak[1];
    
    CVMX_MT_AES_DEC0(x[0]);
    CVMX_MT_AES_DEC1(x[1]);

    oldtweak[0] = ctxtweak[0];
    oldtweak[1] = ctxtweak[1];

    upperbits = ctxtweak[0] & all80;
    ctxtweak[0] &= all7f;
    lsb = upperbits & 0xffull;
    ctxtweak[0] = (ctxtweak[0]<<1) + (upperbits>>15);

    upperbits = ctxtweak[1] & all80;
    ctxtweak[1] &= all7f;
    cout = upperbits & 0xffull;
    upperbits = (lsb<<56) | (upperbits>>8);
    ctxtweak[1] = (ctxtweak[1]<<1) + (upperbits>>7);

    ctxtweak[0] ^= (cout?0x87ull<<56:0);
    
    cipher += 2;
    x[0] = cipher[0] ^ ctxtweak[0];
    x[1] = cipher[1] ^ ctxtweak[1];

    CVMX_MF_AES_RESULT(rx[0],0);
    CVMX_MF_AES_RESULT(rx[1],1);


    for(i=2;i<lenby8;i+=2) {
      CVMX_MT_AES_DEC0(x[0]);
      CVMX_MT_AES_DEC1(x[1]);

      CVMX_PREFETCH0(cipher+16);

      plain[0] = rx[0] ^ oldtweak[0];
      plain[1] = rx[1] ^ oldtweak[1];
      plain += 2;
      
      oldtweak[0] = ctxtweak[0];
      oldtweak[1] = ctxtweak[1];

      upperbits = ctxtweak[0] & all80;
      ctxtweak[0] &= all7f;
      lsb = upperbits & 0xffull;
      ctxtweak[0] = (ctxtweak[0]<<1) + (upperbits>>15);

      upperbits = ctxtweak[1] & all80;
      ctxtweak[1] &= all7f;
      cout = upperbits & 0xffull;
      upperbits = (lsb<<56) | (upperbits>>8);
      ctxtweak[1] = (ctxtweak[1]<<1) + (upperbits>>7);

      ctxtweak[0] ^= (cout?0x87ull<<56:0);

      cipher += 2;
      x[0] = cipher[0] ^ ctxtweak[0];
      x[1] = cipher[1] ^ ctxtweak[1];

      CVMX_MF_AES_RESULT(rx[0],0);
      CVMX_MF_AES_RESULT(rx[1],1);
    }

    CVMX_MT_AES_DEC0(x[0]);
    CVMX_MT_AES_DEC1(x[1]);

    plain[0] = rx[0] ^ oldtweak[0];
    plain[1] = rx[1] ^ oldtweak[1];
    plain += 2;

    oldtweak[0] = ctxtweak[0];
    oldtweak[1] = ctxtweak[1];

    upperbits = ctxtweak[0] & all80;
    ctxtweak[0] &= all7f;
    lsb = upperbits & 0xffull;
    ctxtweak[0] = (ctxtweak[0]<<1) + (upperbits>>15);

    upperbits = ctxtweak[1] & all80;
    ctxtweak[1] &= all7f;
    cout = upperbits & 0xffull;
    upperbits = (lsb<<56) | (upperbits>>8);
    ctxtweak[1] = (ctxtweak[1]<<1) + (upperbits>>7);

    ctxtweak[0] ^= (cout?0x87ull<<56:0);
    
    i+=2;
    CVMX_MF_AES_RESULT(rx[0],0);
    CVMX_MF_AES_RESULT(rx[1],1);

    plain[0] = rx[0] ^ oldtweak[0];
    plain[1] = rx[1] ^ oldtweak[1];

  } else if(len>=32 ){

    x[0] = cipher[0] ^ ctxtweak[0];
    x[1] = cipher[1] ^ ctxtweak[1];
    
    CVMX_MT_AES_DEC0(x[0]);
    CVMX_MT_AES_DEC1(x[1]);

    oldtweak[0] = ctxtweak[0];
    oldtweak[1] = ctxtweak[1];

    upperbits = ctxtweak[0] & all80;
    ctxtweak[0] &= all7f;
    lsb = upperbits & 0xffull;
    ctxtweak[0] = (ctxtweak[0]<<1) + (upperbits>>15);

    upperbits = ctxtweak[1] & all80;
    ctxtweak[1] &= all7f;
    cout = upperbits & 0xffull;
    upperbits = (lsb<<56) | (upperbits>>8);
    ctxtweak[1] = (ctxtweak[1]<<1) + (upperbits>>7);

    ctxtweak[0] ^= (cout?0x87ull<<56:0);
    
    cipher += 2;
    x[0] = cipher[0] ^ ctxtweak[0];
    x[1] = cipher[1] ^ ctxtweak[1];

    CVMX_MF_AES_RESULT(rx[0],0);
    CVMX_MF_AES_RESULT(rx[1],1);

    CVMX_MT_AES_DEC0(x[0]);
    CVMX_MT_AES_DEC1(x[1]);

    plain[0] = rx[0] ^ oldtweak[0];
    plain[1] = rx[1] ^ oldtweak[1];
    plain += 2;

    oldtweak[0] = ctxtweak[0];
    oldtweak[1] = ctxtweak[1];

    upperbits = ctxtweak[0] & all80;
    ctxtweak[0] &= all7f;
    lsb = upperbits & 0xffull;
    ctxtweak[0] = (ctxtweak[0]<<1) + (upperbits>>15);

    upperbits = ctxtweak[1] & all80;
    ctxtweak[1] &= all7f;
    cout = upperbits & 0xffull;
    upperbits = (lsb<<56) | (upperbits>>8);
    ctxtweak[1] = (ctxtweak[1]<<1) + (upperbits>>7);

    ctxtweak[0] ^= (cout?0x87ull<<56:0);
    
    i=4;
    CVMX_MF_AES_RESULT(rx[0],0);
    CVMX_MF_AES_RESULT(rx[1],1);

    plain[0] = rx[0] ^ oldtweak[0];
    plain[1] = rx[1] ^ oldtweak[1];

  } else if(len>=16) {
    x[0] = cipher[0] ^ ctxtweak[0];
    x[1] = cipher[1] ^ ctxtweak[1];
    
    CVMX_MT_AES_DEC0(x[0]);
    CVMX_MT_AES_DEC1(x[1]);

    oldtweak[0] = ctxtweak[0];
    oldtweak[1] = ctxtweak[1];

    upperbits = ctxtweak[0] & all80;
    ctxtweak[0] &= all7f;
    lsb = upperbits & 0xffull;
    ctxtweak[0] = (ctxtweak[0]<<1) + (upperbits>>15);

    upperbits = ctxtweak[1] & all80;
    ctxtweak[1] &= all7f;
    cout = upperbits & 0xffull;
    upperbits = (lsb<<56) | (upperbits>>8);
    ctxtweak[1] = (ctxtweak[1]<<1) + (upperbits>>7);

    ctxtweak[0] ^= (cout?0x87ull<<56:0);
    
    i = 2;
    CVMX_MF_AES_RESULT(rx[0],0);
    CVMX_MF_AES_RESULT(rx[1],1);

    plain[0] = rx[0] ^ oldtweak[0];
    plain[1] = rx[1] ^ oldtweak[1];
  }
  
  if(cvmx_unlikely(len%16)) {
    uint8_t y[16];
    uint64_t *Y = (uint64_t*)y;
    uint8_t *T=(uint8_t*)oldtweak;
    
    ctx->state = 0xdead;
    x[0] = cipher[0] ^ ctx->tweak[0];
    x[1] = cipher[1] ^ ctx->tweak[1];

    CVMX_MT_AES_DEC0(x[0]);
    CVMX_MT_AES_DEC1(x[1]);

    CVMX_MF_AES_RESULT(x[0],0);
    CVMX_MF_AES_RESULT(x[1],1);

    plain[0] = x[0] ^ ctx->tweak[0];
    plain[1] = x[1] ^ ctx->tweak[1];

    i <<= 3;
    for(j=0;(i+j)<len;j++) {
      pt[i+j] = pt[i+j-16];
      y[j] = ct[i+j] ^ T[j];
    }

    for(;j<16;j++) {
      y[j] = pt[i+j-16] ^ T[j] ;
    }

    CVMX_MT_AES_DEC0(Y[0]);
    CVMX_MT_AES_DEC1(Y[1]);
    CVMX_MF_AES_RESULT(Y[0],0);
    CVMX_MF_AES_RESULT(Y[1],1);

    plain = (uint64_t*)&pt[i-16];
    plain[0] = Y[0] ^ oldtweak[0];
    plain[1] = Y[1] ^ oldtweak[1];
  } 
  
  return XTS_AES_SUCCESS;
}
int XTS_AES_encrypt(uint64_t *key1,uint64_t *key2,uint32_t keylen,uint64_t dseqnum,uint8_t *pt,uint32_t len,uint8_t *ct)
{
  aes_xts_ctx_t ctx[1];

  int ret = XTS_AES_ctx_init(key1,key2,keylen,dseqnum,ctx);

  if(ret)
    return ret;

  return XTS_AES_ctx_encrypt(pt,len,ct,ctx);
}

int XTS_AES_decrypt(uint64_t *key1,uint64_t *key2,uint32_t keylen,uint64_t dseqnum,uint8_t *ct,uint32_t len,uint8_t *pt)
{
  aes_xts_ctx_t ctx[1];

  int ret = XTS_AES_ctx_init(key1,key2,keylen,dseqnum,ctx);

  if(ret)
    return ret;

  return XTS_AES_ctx_decrypt(ct,len,pt,ctx);
}

#endif
