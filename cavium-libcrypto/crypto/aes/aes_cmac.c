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



//References    
//RFC4493
//http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
#ifdef OCTEON_OPENSSL

#include <string.h>

#include "cvmx.h"
#include "cvmx-key.h"

#include "openssl/aes.h"

#define LSF1(in1, in2)          \
     in1 <<= 1;                 \
     if (in2 & (0x80ULL << 56)) \
       in1 |= 0x1;              \
     in2 <<= 1;           

int
cvm_crypto_aes_cmac (uint64_t * key,
  uint32_t bits, uint64_t * data, uint32_t dlen, uint64_t * mac)
{
  uint64_t pad[] = {0x8000000000000000ULL, 0ULL};
  uint64_t lb[2];
  uint32_t nBlocks = 0;
  uint32_t flag = 0;
  register uint64_t in1, in2, in3, in4;
  unsigned char const_Rb = 0x87;

  aes_assert (key, -1);
  CVMX_PREFETCH (key, 0);
  aes_assert ((data && mac), -1);
  aes_assert (((bits == 128) || (bits == 192) || (bits == 256)), -1); 
  CVMX_MT_AES_KEY (key[0], 0);
  CVMX_MT_AES_KEY (key[1], 1);
  CVMX_MT_AES_KEY (key[2], 2);
  CVMX_MT_AES_KEY (key[3], 3);
  CVMX_MT_AES_KEYLENGTH (bits / 64 - 1);

  CVMX_MT_AES_ENC0 (0);
  CVMX_MT_AES_ENC1 (0);
  memset (lb, 0, 16);

  if (dlen != 0) {
    nBlocks = dlen / AES_BLOCK_SIZE;

    if (dlen % AES_BLOCK_SIZE) {
      nBlocks += 1;
      flag = 1;
    }
  } else {
    flag = 1;
  }

  CVMX_MF_AES_RESULT (in3, 0);
  CVMX_MF_AES_RESULT (in4, 1);

  CVMX_MT_AES_IV (0, 0);
  CVMX_MT_AES_IV (0, 1);

  while (nBlocks > 1) {
    in1 = *data;
    in2 = *(data + 1);
    CVMX_MT_AES_ENC_CBC0 (in1);
    CVMX_MT_AES_ENC_CBC1 (in2);
    nBlocks -= 1;
    dlen -= 16;
    CVMX_PREFETCH (data, 64);
    data += 2;
  }

  if (in3 & (0x80ULL << 56)) {
    LSF1 (in3, in4);
    in4 ^= const_Rb;
  } else {
    LSF1 (in3, in4);
  }
  
  if (flag) {
    if (in3 & (0x80ULL << 56)) {
      LSF1 (in3, in4);
      in4 ^= const_Rb;
    } else {
      LSF1 (in3, in4);
    }
    memcpy (lb, data, dlen); 
    memcpy ((uint8_t *)lb + dlen, pad, 16-dlen);
    lb[0] ^= in3;
    lb[1] ^= in4;
    CVMX_MT_AES_ENC_CBC0 (lb[0]);
    CVMX_MT_AES_ENC_CBC1 (lb[1]);
  } else {
    in1 = *data;
    in2 = *(data + 1);
    in1 ^= in3; 
    in2 ^= in4; 
    CVMX_MT_AES_ENC_CBC0 (in1);
    CVMX_MT_AES_ENC_CBC1 (in2);
  }

  CVMX_MF_AES_RESULT (*mac, 0);
  CVMX_MF_AES_RESULT (*(mac+1), 1);
  return 0;
}

int
cvm_crypto_aes_cmac_init (uint8_t * orgkey, uint32_t bits,
  AES_KEY * key, AES_CMAC_CTX * ctx)
{
  int res = 0; 
  aes_assert ((orgkey && key && ctx), -1);
  aes_assert (((bits == 128) || (bits == 192) || (bits == 256)), -1); 

  /* set the key */
  memset (key->cvmkey, 0, 32);
  memcpy (key->cvmkey, orgkey, bits / 8);
  key->cvm_keylen = bits;

  memset (ctx->E, 0, sizeof(ctx->E));
  memset (ctx->lb, 0, sizeof(ctx->lb));

  ctx->done = 0;
  ctx->plen = 0;

  return res;
}

int
cvm_crypto_aes_cmac_update (AES_KEY * key, uint8_t * data,
  uint32_t dlen, AES_CMAC_CTX * ctx)
{
    return cvm_crypto_aes_cmac_update_bits (key,  data,
			   dlen*8, ctx);
}

int
cvm_crypto_aes_cmac_update_bits (AES_KEY * key, uint8_t * data,
  uint32_t dlen, AES_CMAC_CTX * ctx)
{
  register uint64_t in1;
  register uint64_t in2;
  uint8_t dlen_bytes , plen_bytes;
  aes_assert ((key && ctx && data), -1);

  if (dlen == 0)
    return -1;

  /* load aes key */
  CVMX_MT_AES_KEY (key->cvmkey[0], 0);
  CVMX_MT_AES_KEY (key->cvmkey[1], 1);
  CVMX_MT_AES_KEY (key->cvmkey[2], 2);
  CVMX_MT_AES_KEY (key->cvmkey[3], 3);
  CVMX_MT_AES_KEYLENGTH (key->cvm_keylen / 64 - 1);

  CVMX_MT_AES_IV (ctx->E[0], 0);
  CVMX_MT_AES_IV (ctx->E[1], 1);

  dlen_bytes = dlen/8 + !(!(dlen%8));
  plen_bytes = ctx->plen/8 + !(!(ctx->plen%8));

  if (ctx->plen  + dlen > 128) {
    if (ctx->plen) {
      memcpy ((uint8_t *) ctx->lb + plen_bytes, data, 16 - plen_bytes);
      CVMX_MT_AES_ENC_CBC0 (ctx->lb[0]);
      CVMX_MT_AES_ENC_CBC1 (ctx->lb[1]);
      data += (16 - plen_bytes);
      dlen -= (128 - ctx->plen);
      memset(ctx->lb, 0, 16 );
      ctx->plen = 0;
    }

    while (dlen > 128) {
      in1 = ((uint64_t *) (data))[0];
      in2 = ((uint64_t *) (data))[1];
      CVMX_MT_AES_ENC_CBC0 (in1);
      CVMX_MT_AES_ENC_CBC1 (in2);
      data += 16;
      dlen -= 128;
    }
    
    if (dlen) {
      dlen_bytes = dlen/8 + !(!(dlen%8));
      memcpy ((uint8_t *) ctx->lb ,data, dlen_bytes);
      ctx->plen = dlen;
    }
    CVMX_MF_AES_RESULT (ctx->E[0], 0);
    CVMX_MF_AES_RESULT (ctx->E[1], 1);
  } else {
      memcpy ((uint8_t *) ctx->lb + plen_bytes, data, dlen_bytes);
      ctx->plen += dlen;
  }
  return 0;
}

int
cvm_crypto_aes_cmac_final (AES_KEY * key, AES_CMAC_CTX * ctx,
  uint64_t * mac)
{
  register uint64_t in1, in2;
  unsigned char const_Rb = 0x87;

  aes_assert ((key && ctx && mac), -1);
  if (ctx->done)
    return -1;
  ctx->done = 1;

  CVMX_MT_AES_KEY (key->cvmkey[0], 0);
  CVMX_MT_AES_KEY (key->cvmkey[1], 1);
  CVMX_MT_AES_KEY (key->cvmkey[2], 2);
  CVMX_MT_AES_KEY (key->cvmkey[3], 3);
  CVMX_MT_AES_KEYLENGTH (key->cvm_keylen / 64 - 1);

  CVMX_MT_AES_ENC0 (0);
  CVMX_MT_AES_ENC1 (0);

  if (ctx->plen != 128) {
     uint64_t mask = 0ULL;
     uint32_t setmask = ctx->plen >= 64 ? (128 - (ctx->plen+1)) : (64 - (ctx->plen+1)); 
     mask = 1ULL << setmask ;
     if (ctx->plen < 64) 
         ctx->lb[0] |= mask;
     else 
         ctx->lb[1] |= mask;
  }

  CVMX_MF_AES_RESULT (in1, 0);
  CVMX_MF_AES_RESULT (in2, 1);

  CVMX_MT_AES_IV (ctx->E[0], 0);
  CVMX_MT_AES_IV (ctx->E[1], 1);

  if (in1 & (0x80ULL << 56)) {
    LSF1 (in1, in2);
    in2 ^= const_Rb;
  } else {
    LSF1 (in1, in2);
  }
  
  if (ctx->plen != 128) {
    if (in1 & (0x80ULL << 56)) {
      LSF1 (in1, in2);
      in2 ^= const_Rb;
    } else {
      LSF1 (in1, in2);
    }
  }

  ctx->lb[0] ^= in1;
  ctx->lb[1] ^= in2;
  CVMX_MT_AES_ENC_CBC0 (ctx->lb[0]);
  CVMX_MT_AES_ENC_CBC1 (ctx->lb[1]);
  CVMX_MF_AES_RESULT (*mac, 0);
  CVMX_MF_AES_RESULT (*(mac+1), 1);
  return 0;
}
#endif
