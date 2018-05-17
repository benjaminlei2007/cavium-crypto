/* crypto/aes/aes_ctr.c -*- mode:C; c-file-style: "eay" -*- */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
 *
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
 *
 */

#include <openssl/aes.h>
#include <openssl/modes.h>

void AES_ctr128_encrypt(const unsigned char *in, unsigned char *out,
			size_t length, const AES_KEY *key,
			unsigned char ivec[AES_BLOCK_SIZE],
			unsigned char ecount_buf[AES_BLOCK_SIZE],
			unsigned int *num) {
	CRYPTO_ctr128_encrypt(in,out,length,key,ivec,ecount_buf,num,(block128_f)AES_encrypt);
}


#ifdef OCTEON_OPENSSL
#include <string.h>
#include <assert.h>

#include "cvmx.h"
#include "cvmx-key.h"

#include "openssl/aes.h"

int
cvm_crypto_aes_ctr_encrypt (uint64_t * key,
  uint32_t bits,
  uint64_t orgiv,
  uint32_t nonce, uint64_t * data, uint32_t dlen, uint64_t * res)
{
  uint32_t keylen = bits;
  uint64_t iv[2];
  uint64_t ctrblk[2];
  int32_t nblocks, pending, lastblk; 
  int i;
  uint8_t *ct, *pt, *ctr, k;
  uint32_t last_block_len;
  uint64_t tmpctrblk[2];

  aes_assert (key, -1);
  aes_assert (((keylen == 128) || (keylen == 192) || (keylen == 256)), -1);
  aes_assert ((data), -1);
  aes_assert (res, -1);
  iv[0] = orgiv;
  iv[1] = 0;


  //step1
  //CTRBLK := NONCE || IV || ONE
  memcpy ((uint8_t *) ctrblk, &nonce, 4);
  memcpy ((uint8_t *) ctrblk + 4, iv, 8);
  memset ((uint8_t *) ctrblk + 12, 0, 4);
  ((uint8_t *) ctrblk)[15] = 0x1;

  //step2
  nblocks = dlen/16;
  pending = dlen%16;
  lastblk = nblocks;
  lastblk -= (!pending);
  cvm_crypto_aes_initialize (key,keylen);
  for(i=0;i<lastblk;i++)
  {
    uint64_t tmpctrblk[2];
    CVMX_MT_AES_ENC0 (ctrblk[0]);
    CVMX_MT_AES_ENC1 (ctrblk[1]);

	//CTRBLK := CTRBLK + 1;
    if (ctrblk[1] != 0xFFffFFffFFffFFffULL) {
      ctrblk[1]++;
    } else {
      ctrblk[1] = 0;
      ctrblk[0]++;
    }
    
    CVMX_MF_AES_RESULT (tmpctrblk[0], 0);
    CVMX_MF_AES_RESULT (tmpctrblk[1], 1);

    //CT[i] := PT[i] xor AES(CTRBLK)
	res[2 * i] = data[2 * i] ^ tmpctrblk[0];
    res[2 * i + 1] = data[2 * i + 1] ^ tmpctrblk[1];
  }
  
  //step3
  //CT[n] := PT[n] XOR TRUNC(AES(CTRBLK))

  CVMX_MT_AES_ENC0(ctrblk[0]);
  CVMX_MT_AES_ENC1(ctrblk[1]);
  CVMX_MF_AES_RESULT(tmpctrblk[0],0);
  CVMX_MF_AES_RESULT(tmpctrblk[1],1);

  ct = (uint8_t *) & res[2 * i];
  pt = (uint8_t *) & data[2 * i];
  ctr = (uint8_t *) & tmpctrblk[0];
  last_block_len = dlen % 16;
  if (!last_block_len)
    last_block_len = 16;
  for (k = 0; k < last_block_len; k++)
    ct[k] = pt[k] ^ ctr[k];
  return 0;
}


int
cvm_crypto_aes_ctr_encrypt_init (uint8_t * orgkey, uint32_t bits,
  AES_KEY * key, uint64_t iv, uint32_t nonce, void *state)
{
  cvm_crypto_aes_ctr_state_t *ctx; 
  aes_assert (orgkey, -1);
  aes_assert (key, -1);
  aes_assert (state, -1);
  aes_assert (((bits == 128) || (bits == 192) || (bits == 256)), -1);

  memcpy (key->cvmkey, orgkey, bits / 8);
  key->cvm_keylen = bits;


  ctx = (cvm_crypto_aes_ctr_state_t *) state;

  ctx->iv[0] = iv;
  ctx->iv[1] = 0;

  //step1
  //CTRBLK := NONCE || IV || ONE
  memcpy ((uint8_t *) ctx->ctrblk, &nonce, 4);
  memcpy ((uint8_t *) (ctx->ctrblk) + 4, &iv, 8);
  memset ((uint8_t *) (ctx->ctrblk) + 12, 0, 4);
  ((uint8_t *) ctx->ctrblk)[15] = 0x1;

  ctx->done = 0xbabe;
  return 0;
}

int
cvm_crypto_aes_ctr_encrypt_update (AES_KEY * key, uint8_t * data,
  uint32_t dlen, uint8_t * res, void *state)
{
  uint64_t *in, *out;  
  int32_t i, nblocks;
  cvm_crypto_aes_ctr_state_t *ctx; 
  aes_assert ((key && state), -1);
  if (dlen == 0)
    return -1;
  aes_assert ((data && res), -1);
  in = (uint64_t *) data;
  out = (uint64_t *) res;
  ctx = (cvm_crypto_aes_ctr_state_t *) state;
  if (ctx->done == 0xdead)
    return -1;
  aes_assert ((ctx->done == 0xbabe), -1);

  nblocks = dlen / 16;
  
   
  cvm_crypto_aes_initialize (key->cvmkey,key->cvm_keylen);
 
  for (i = 0; i < nblocks; i++) {
    //CT[i] := PT[i] xor AES(CTRBLK)
    uint64_t tmpctrblk[2];
    CVMX_MT_AES_ENC0 (ctx->ctrblk[0]);
    CVMX_MT_AES_ENC1 (ctx->ctrblk[1]);

    //CTRBLK := CTRBLK + 1
    if (ctx->ctrblk[1] != 0xFFFFffffFFFFffffull) {
      ctx->ctrblk[1]++;
    } else {
      ctx->ctrblk[1] = 0;
      ctx->ctrblk[0]++;
    }
    CVMX_MF_AES_RESULT(tmpctrblk[0],0);
    CVMX_MF_AES_RESULT(tmpctrblk[1],1);

    out[2 * i] = in[2 * i] ^ tmpctrblk[0];
    out[2 * i + 1] = in[2 * i + 1] ^ tmpctrblk[1];

  }

  //This could well be the last call
  if (dlen % 16) {
    uint64_t tmpctrblk[2];
    uint8_t *ct, *pt, *ctr;
    uint32_t k;
    ctx->done = 0xdead;

    CVMX_MT_AES_ENC0(ctx->ctrblk[0]);
    CVMX_MT_AES_ENC1(ctx->ctrblk[1]);
    CVMX_MF_AES_RESULT(tmpctrblk[0],0);
    CVMX_MF_AES_RESULT(tmpctrblk[1],1);

    ct = (uint8_t *) & out[2 * i];
    pt = (uint8_t *) & in[2 * i];
    ctr = (uint8_t *) & tmpctrblk[0];
    for (k = 0; k < dlen % 16; k++)
      ct[k] = pt[k] ^ ctr[k];
  }
  return 0;
}

int
cvm_crypto_aes_ctr_encrypt_final (AES_KEY * key, uint8_t * data,
  uint32_t dlen, uint8_t * res, void *state)
{
  uint64_t *out, *in;
  int32_t nblocks, pending, lastblk;
  cvm_crypto_aes_ctr_state_t *ctx;
  uint64_t tmpctrblk[2];
  int32_t i;
  uint8_t *ct, *pt, *ctr, k;
  uint32_t last_block_len;

  aes_assert ((key && data && res && state), -1);
  //You are not supposed to call final call with dlen with zero
  aes_assert (dlen, -1);
  out = (uint64_t *) res;
  in = (uint64_t *) data;

  ctx = (cvm_crypto_aes_ctr_state_t *) state;

  /* Negative test handling */
  if (ctx->done == 0xdead)
    return -1;
  aes_assert ((ctx->done == 0xbabe), -1);
  ctx->done = 0xdead;

  nblocks = dlen / 16;
  pending = dlen % 16;
  lastblk = nblocks;
  lastblk -= (!pending);

  
  cvm_crypto_aes_initialize (key->cvmkey,key->cvm_keylen);

  for (i = 0; (dlen % 16 ? (i < nblocks) : (i < nblocks - 1)); i++) {
    //CT[i] := PT[i] xor AES(CTRBLK)
    uint64_t tmpctrblk[2];

    CVMX_MT_AES_ENC0(ctx->ctrblk[0]);
    CVMX_MT_AES_ENC1(ctx->ctrblk[1]);

    //CTRBLK := CTRBLK + 1;
    if (ctx->ctrblk[1] != 0xFFFFffffFFFFffffULL) {
      ctx->ctrblk[1]++;
    } else {
      ctx->ctrblk[1] = 0;
      ctx->ctrblk[0]++;
    }

    CVMX_MF_AES_RESULT(tmpctrblk[0],0);
    CVMX_MF_AES_RESULT(tmpctrblk[1],1);

    out[2 * i] = in[2 * i] ^ tmpctrblk[0];
    out[2 * i + 1] = in[2 * i + 1] ^ tmpctrblk[1];
  }

  //step3
  //CT[n] := PT[n] XOR TRUNC(AES(CTRBLK))

  CVMX_MT_AES_ENC0(ctx->ctrblk[0]);
  CVMX_MT_AES_ENC1(ctx->ctrblk[1]);
  CVMX_MF_AES_RESULT(tmpctrblk[0],0);
  CVMX_MF_AES_RESULT(tmpctrblk[1],1);

  ct = (uint8_t *) & out[2 * i];
  pt = (uint8_t *) & in[2 * i];
  ctr = (uint8_t *) & tmpctrblk[0];
  last_block_len = dlen % 16;
  if (!last_block_len)
    last_block_len = 16;
  for (k = 0; k < last_block_len; k++)
    ct[k] = pt[k] ^ ctr[k];
  return 0;
}

#endif
