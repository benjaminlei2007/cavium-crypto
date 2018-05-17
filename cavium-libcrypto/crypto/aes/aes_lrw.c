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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cvmx.h"
#include "cvmx-asm.h"

#include "openssl/aes.h"

static inline void
GHASH_init (uint16_t polynomial, void *multiplier)
{
  // Init Galois multiplier
  CVMX_MT_GFM_POLY ((uint64_t) polynomial);

  // Init multiplier
  if (multiplier) {
    uint64_t *poly = (uint64_t *) multiplier;
    CVMX_MT_GFM_MUL (poly[0], 0);
    CVMX_MT_GFM_MUL (poly[1], 1);
  }
  // Multiply by 0 to clear result
  CVMX_MT_GFM_RESINP (0, 0);
  CVMX_MT_GFM_RESINP (0, 1);
  return;
}

int
LRW_AES_set_key (uint8_t * key, uint32_t keylen, uint8_t * tweak,
  lrw_aes_ctx_t * lrw_ctx)
{
  uint64_t *kptr = (uint64_t *) key;
  uint64_t *twptr = (uint64_t *) tweak;

  if (!lrw_ctx || !key) {
    return (LRW_AES_INVALID_CTX);
  }
  memset (lrw_ctx, 0, sizeof (lrw_aes_ctx_t));

  switch (keylen) {
  case 384:
    lrw_ctx->K1.val64[3] = kptr[3];
  case 320:
    lrw_ctx->K1.val64[2] = kptr[2];
  case 256:
    lrw_ctx->K1.val64[1] = kptr[1];
    lrw_ctx->K1.val64[0] = kptr[0];
    break;
  default:
    return (LRW_AES_INVALID_KEYLENGTH);
  }
  lrw_ctx->K1_len = (keylen - 128) / 64;

  // Store K2
  lrw_ctx->K2.val64[0] = kptr[lrw_ctx->K1_len];
  lrw_ctx->K2.val64[1] = kptr[lrw_ctx->K1_len + 1];

  lrw_ctx->tweak.val64[0] = twptr[0];
  lrw_ctx->tweak.val64[1] = twptr[1];

  lrw_ctx->init_done = LRW_KEY_DONE;
  return (LRW_AES_SUCCESS);
}

int
LRW_AES_ctx_encrypt (uint8_t * pin, uint32_t plen, uint8_t * out,
  lrw_aes_ctx_t * lrw_ctx)
{
  int32_t len;
  block16_t *iptr, *optr;
  block16_t input, output, tweak, result;
  uint64_t *kptr;

  if (lrw_ctx->init_done != LRW_KEY_DONE)
    return (LRW_AES_INVALID_CTX);

  // Utilizing the commutative property of GF(2^128)
  GHASH_init (0xe100, &lrw_ctx->K2.val64[0]);

  iptr = (block16_t *) pin;
  optr = (block16_t *) out;

  tweak.val64[0] = lrw_ctx->tweak.val64[0];
  tweak.val64[1] = lrw_ctx->tweak.val64[1];

  len = (int32_t) plen;
  if (len < 0) {
    return LRW_AES_INVALID_LENGTH;
  }
  if (len < 16) {
    return LRW_AES_INVALID_LENGTH;
  }

  CVMX_MT_GFM_XOR0 (tweak.val64[0]);
  CVMX_MT_GFM_XORMUL1 (tweak.val64[1]);

  // Read input data block
  CVMX_LOADUNA_INT64 (input.val64[0], iptr, 0);
  CVMX_LOADUNA_INT64 (input.val64[1], iptr++, 8);

  tweak.val64[1]++;

  // Overflow
  if (!tweak.val64[1])
    tweak.val64[0]++;

  // Load AES Keys
  kptr = (uint64_t *) (&lrw_ctx->K1.val64[0]);

  CVMX_MT_AES_KEY (kptr[3], 3);
  CVMX_MT_AES_KEY (kptr[2], 2);
  CVMX_MT_AES_KEY (kptr[1], 1);
  CVMX_MT_AES_KEY (kptr[0], 0);
  CVMX_MT_AES_KEYLENGTH (lrw_ctx->K1_len - 1);

  // Read Galois result (GHASH_finish)
  // (have to stall here -- there is
  //  nothing else we can do)
  CVMX_MF_GFM_RESINP (result.val64[0], 0);
  CVMX_MF_GFM_RESINP (result.val64[1], 1);

  // Multiply by 0 to clear result
  CVMX_MT_GFM_RESINP (0, 0);
  CVMX_MT_GFM_RESINP (0, 1);

  input.val64[0] ^= result.val64[0];
  input.val64[1] ^= result.val64[1];

  // Start Encrypting
  CVMX_MT_AES_ENC0 (input.val64[0]);
  CVMX_MT_AES_ENC1 (input.val64[1]);

  len -= 16;

  if (len < 16)
    goto encrypt_loop_done;

  while (len >= 16) {
    // Start the GFM 
    CVMX_MT_GFM_XOR0 (tweak.val64[0]);
    CVMX_MT_GFM_XORMUL1 (tweak.val64[1]);

    // Read next input data block
    CVMX_LOADUNA_INT64 (input.val64[0], iptr, 0);
    CVMX_LOADUNA_INT64 (input.val64[1], iptr++, 8);

    tweak.val64[1]++;

    // Overflow
    if (!tweak.val64[1])
      tweak.val64[0]++;

    len -= 16;

    /* Get the previous block AES-Enc Result */
    CVMX_MF_AES_RESULT (output.val64[0], 0);
    CVMX_MF_AES_RESULT (output.val64[1], 1);

    output.val64[0] ^= result.val64[0];
    output.val64[1] ^= result.val64[1];

    // Write output
    CVMX_STOREUNA_INT64 (output.val64[0], optr, 0);
    CVMX_STOREUNA_INT64 (output.val64[1], optr++, 8);

    CVMX_MF_GFM_RESINP (result.val64[0], 0);
    CVMX_MF_GFM_RESINP (result.val64[1], 1);

    // Multiply by 0 to clear result
    CVMX_MT_GFM_RESINP (0, 0);
    CVMX_MT_GFM_RESINP (0, 1);

    input.val64[0] ^= result.val64[0];
    input.val64[1] ^= result.val64[1];

    // Start Encrypting
    CVMX_MT_AES_ENC0 (input.val64[0]);
    CVMX_MT_AES_ENC1 (input.val64[1]);
  }

encrypt_loop_done:

  /* Get the previous block AES-Enc Result */
  CVMX_MF_AES_RESULT (output.val64[0], 0);
  CVMX_MF_AES_RESULT (output.val64[1], 1);

  output.val64[0] ^= result.val64[0];
  output.val64[1] ^= result.val64[1];

  /* Exactly 16 bytes of input data */
  if (!len) {
    // Write output
    CVMX_STOREUNA_INT64 (output.val64[0], optr, 0);
    CVMX_STOREUNA_INT64 (output.val64[1], optr++, 8);
    lrw_ctx->tweak.val64[0] = tweak.val64[0];
    lrw_ctx->tweak.val64[1] = tweak.val64[1];
    return LRW_AES_SUCCESS;
  }

  /* last block(Pm) < 16 bytes */
  /* Cm = first b bits of (LRS-AES(P(m-1))
     Replace first b bits of P(m-1) with P(m)
     Cm-1 = LRS-AES(C(m-1)|P(m))
   */
  /* Now, 
     iptr  == Last [0-127) bits of input data
     optr  == Last [128-255) bits of output data
   */
  {
    block16_t outputf;
    int i;
    uint8_t iter;

    optr++;
    for (i = 0; i < len; i++) {
      iter = iptr->val8[i];
      optr->val8[i] = output.val8[i];
      output.val8[i] = iter;
    }

    // LRW Encrypt for the last time 
    CVMX_MT_GFM_XOR0 (tweak.val64[0]);
    CVMX_MT_GFM_XORMUL1 (tweak.val64[1]);
    optr--;

    tweak.val64[1]++;

    // Overflow
    if (!tweak.val64[1])
      tweak.val64[0]++;

    lrw_ctx->tweak.val64[0] = tweak.val64[0];
    lrw_ctx->tweak.val64[1] = tweak.val64[1];
    // Read Galois result (GHASH_finish)
    // (have to stall here -- there is
    //  nothing else we can do)
    CVMX_MF_GFM_RESINP (result.val64[0], 0);
    CVMX_MF_GFM_RESINP (result.val64[1], 1);

    // Multiply by 0 to clear result
    CVMX_MT_GFM_RESINP (0, 0);
    CVMX_MT_GFM_RESINP (0, 1);

    output.val64[0] ^= result.val64[0];
    output.val64[1] ^= result.val64[1];

    // Start Encrypting
    CVMX_MT_AES_ENC0 (output.val64[0]);
    CVMX_MT_AES_ENC1 (output.val64[1]);

    // Read result
    CVMX_MF_AES_RESULT (outputf.val64[0], 0);
    CVMX_MF_AES_RESULT (outputf.val64[1], 1);

    outputf.val64[0] ^= result.val64[0];
    outputf.val64[1] ^= result.val64[1];

    // Write output
    CVMX_STOREUNA_INT64 (outputf.val64[0], optr, 0);
    CVMX_STOREUNA_INT64 (outputf.val64[1], optr, 8);
  }
  return LRW_AES_SUCCESS;
}

int
LRW_AES_ctx_decrypt (uint8_t * cin, uint32_t clen, uint8_t * out,
  lrw_aes_ctx_t * lrw_ctx)
{
  int32_t len;
  block16_t *iptr, *optr;
  block16_t input, output, tweak, result;
  uint64_t *kptr;


  if (lrw_ctx->init_done != LRW_KEY_DONE)
    return (LRW_AES_INVALID_CTX);

  // Utilizing the commutative property of GF(2^128)
  GHASH_init (0xe100, &lrw_ctx->K2.val64[0]);

  iptr = (block16_t *) cin;
  optr = (block16_t *) out;

  tweak.val64[0] = lrw_ctx->tweak.val64[0];
  tweak.val64[1] = lrw_ctx->tweak.val64[1];

  len = (int32_t) clen;
  if (len < 0) {
    return LRW_AES_INVALID_LENGTH;
  }

  if (len < 16) {
    return LRW_AES_INVALID_LENGTH;
  }

  if ((len < 32) && (len != 16)) {
    /* Tweak value to be with i+m */
    tweak.val64[1]++;
    // Overflow
    if (!tweak.val64[1])
      tweak.val64[0]++;
  }

  CVMX_MT_GFM_XOR0 (tweak.val64[0]);
  CVMX_MT_GFM_XORMUL1 (tweak.val64[1]);

  // Read input data block
  CVMX_LOADUNA_INT64 (input.val64[0], iptr, 0);
  CVMX_LOADUNA_INT64 (input.val64[1], iptr++, 8);

  tweak.val64[1]++;

  // Overflow
  if (!tweak.val64[1])
    tweak.val64[0]++;

  // Load AES Keys
  kptr = (uint64_t *) (&lrw_ctx->K1.val64[0]);

  CVMX_MT_AES_KEY (kptr[3], 3);
  CVMX_MT_AES_KEY (kptr[2], 2);
  CVMX_MT_AES_KEY (kptr[1], 1);
  CVMX_MT_AES_KEY (kptr[0], 0);
  CVMX_MT_AES_KEYLENGTH (lrw_ctx->K1_len - 1);

  // Read Galois result (GHASH_finish)
  // (have to stall here -- there is
  //  nothing else we can do)
  CVMX_MF_GFM_RESINP (result.val64[0], 0);
  CVMX_MF_GFM_RESINP (result.val64[1], 1);

  // Multiply by 0 to clear result
  CVMX_MT_GFM_RESINP (0, 0);
  CVMX_MT_GFM_RESINP (0, 1);

  input.val64[0] ^= result.val64[0];
  input.val64[1] ^= result.val64[1];

  // Start Encrypting
  CVMX_MT_AES_DEC0 (input.val64[0]);
  CVMX_MT_AES_DEC1 (input.val64[1]);

  len -= 16;

  if (len < 16)
    goto decrypt_loop_done;

  while (len >= 16) {
    // Start the GFM 
    if ((len < 32) && (len != 16)) {
      /* Tweak value to be with i+m */
      tweak.val64[1]++;

      // Overflow
      if (!tweak.val64[1])
        tweak.val64[0]++;
    }
    CVMX_MT_GFM_XOR0 (tweak.val64[0]);
    CVMX_MT_GFM_XORMUL1 (tweak.val64[1]);

    // Read next input data block
    CVMX_LOADUNA_INT64 (input.val64[0], iptr, 0);
    CVMX_LOADUNA_INT64 (input.val64[1], iptr++, 8);

    tweak.val64[1]++;

    // Overflow
    if (!tweak.val64[1])
      tweak.val64[0]++;

    len -= 16;

    /* Get the previous block AES-Enc Result */
    CVMX_MF_AES_RESULT (output.val64[0], 0);
    CVMX_MF_AES_RESULT (output.val64[1], 1);

    output.val64[0] ^= result.val64[0];
    output.val64[1] ^= result.val64[1];

    // Write output
    CVMX_STOREUNA_INT64 (output.val64[0], optr, 0);
    CVMX_STOREUNA_INT64 (output.val64[1], optr++, 8);

    CVMX_MF_GFM_RESINP (result.val64[0], 0);
    CVMX_MF_GFM_RESINP (result.val64[1], 1);

    // Multiply by 0 to clear result
    CVMX_MT_GFM_RESINP (0, 0);
    CVMX_MT_GFM_RESINP (0, 1);

    input.val64[0] ^= result.val64[0];
    input.val64[1] ^= result.val64[1];

    // Start Encrypting
    CVMX_MT_AES_DEC0 (input.val64[0]);
    CVMX_MT_AES_DEC1 (input.val64[1]);
  }

decrypt_loop_done:

  /* Get the previous block AES-Enc Result */
  CVMX_MF_AES_RESULT (output.val64[0], 0);
  CVMX_MF_AES_RESULT (output.val64[1], 1);

  output.val64[0] ^= result.val64[0];
  output.val64[1] ^= result.val64[1];

  /* Exactly 16 bytes of input data */
  if (!len) {
    // Write output
    CVMX_STOREUNA_INT64 (output.val64[0], optr, 0);
    CVMX_STOREUNA_INT64 (output.val64[1], optr++, 8);
    lrw_ctx->tweak.val64[0] = tweak.val64[0];
    lrw_ctx->tweak.val64[1] = tweak.val64[1];
    return LRW_AES_SUCCESS;
  }

  /* last block(Cm) < 16 bytes */
  /* Cm = first b bits of (LRS-AES(C(m-1))
     Replace first b bits of P(m-1) with P(m)
     Cm-1 = LRS-AES(C(m-1)|P(m))
   */
  /* Now, 
     iptr  == Last [0-127) bits of input data
     optr  == Last [128-255) bits of output data
   */
  {
    block16_t outputf;
    int i;
    uint8_t iter;

    optr++;
    for (i = 0; i < len; i++) {
      iter = iptr->val8[i];
      optr->val8[i] = output.val8[i];
      output.val8[i] = iter;
    }

    // LRW Decrypt for the last time 
    if (tweak.val64[1] == 1)
      tweak.val64[0]--;
    tweak.val64[1]--;
    tweak.val64[1]--;

    CVMX_MT_GFM_XOR0 (tweak.val64[0]);
    CVMX_MT_GFM_XORMUL1 (tweak.val64[1]);

    optr--;

    lrw_ctx->tweak.val64[0] = tweak.val64[0];
    lrw_ctx->tweak.val64[1] = tweak.val64[1];
    // Read Galois result (GHASH_finish)
    // (have to stall here -- there is
    //  nothing else we can do)
    CVMX_MF_GFM_RESINP (result.val64[0], 0);
    CVMX_MF_GFM_RESINP (result.val64[1], 1);

    output.val64[0] ^= result.val64[0];
    output.val64[1] ^= result.val64[1];

    // Start Encrypting
    CVMX_MT_AES_DEC0 (output.val64[0]);
    CVMX_MT_AES_DEC1 (output.val64[1]);

    // Read result
    CVMX_MF_AES_RESULT (outputf.val64[0], 0);
    CVMX_MF_AES_RESULT (outputf.val64[1], 1);

    outputf.val64[0] ^= result.val64[0];
    outputf.val64[1] ^= result.val64[1];

    // Write output
    CVMX_STOREUNA_INT64 (outputf.val64[0], optr, 0);
    CVMX_STOREUNA_INT64 (outputf.val64[1], optr, 8);
  }
  return LRW_AES_SUCCESS;
}

int
LRW_AES_encrypt (uint8_t * key, uint32_t keylen, uint8_t * p,
  uint32_t plen, uint8_t * tweak, uint8_t * out)
{
  lrw_aes_ctx_t lrw_ctx;
  int ret;
  ret = LRW_AES_set_key (key, keylen, tweak, &lrw_ctx);
  if (ret)
    return ret;
  return LRW_AES_ctx_encrypt (p, plen, out, &lrw_ctx);
}

int
LRW_AES_decrypt (uint8_t * key, uint32_t keylen, uint8_t * c,
  uint32_t clen, uint8_t * tweak, uint8_t * out)
{
  lrw_aes_ctx_t lrw_ctx;
  int ret;
  ret = LRW_AES_set_key (key, keylen, tweak, &lrw_ctx);
  if (ret)
    return ret;
  return LRW_AES_ctx_decrypt (c, clen, out, &lrw_ctx);
}
#endif
