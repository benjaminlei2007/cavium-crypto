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

/* The output registers need to be set in clobbered  mode, so as to indicate
   compiler about not sharing the same input and output registers */
#define CVM_AES_RD_RESULT_WR_DATA(in1, in2, out1, out2) asm volatile\
                                              (".set noreorder    \n" \
                                               "dmfc2 %[r1],0x0100\n" \
                                               "dmfc2 %[r2],0x0101\n" \
                                               "dmtc2 %[r3],0x010a\n" \
                                               "dmtc2 %[r4],0x310b\n" \
                                               ".set reorder      \n" \
                                               : [r1] "=&d" (in1) , [r2] "=&d" (in2) \
                                               : [r3] "d" (out1),  [r4] "d" (out2) )

// cur_aes_ctx is used to identify the last context that used the core
aes_gcm_ctx_t *cur_aes_ctx;

static inline void
GHASH_restore (uint16_t polynomial, void *multiplier)
{
  // Init Galois multiplier
  CVMX_MT_GFM_POLY ((uint64_t) polynomial);

  // Init multiplier
  if (multiplier) {
    uint64_t *poly = (uint64_t *) multiplier;
    CVMX_MT_GFM_MUL (poly[0], 0);
    CVMX_MT_GFM_MUL (poly[1], 1);
  }
  return;
}


static inline void
GHASH_init (uint16_t polynomial, void *multiplier)
{
  GHASH_restore (polynomial, multiplier);

  // Multiply by 0 to clear result
  CVMX_MT_GFM_RESINP (0, 0);
  CVMX_MT_GFM_RESINP (0, 1);
  return;
}

static inline void
GHASH_update (uint64_t * data)
{
  // Feed data to the hash
  CVMX_MT_GFM_XOR0 (data[0]);
  CVMX_MT_GFM_XORMUL1 (data[1]);
  return;
}

static inline void
GHASH_finish (uint64_t alen, uint64_t clen, void *res)
{
  block16_t *result = (block16_t *) res;

  // Feed lengths into the hash
  CVMX_MT_GFM_XOR0 (alen);
  CVMX_MT_GFM_XORMUL1 (clen);

  // Read the result (note stalls here until MPY is finished)
  CVMX_MF_GFM_RESINP (result->val64[0], 0);
  CVMX_MF_GFM_RESINP (result->val64[1], 1);
  return;
}

int
AES_GCM_init_key (uint8_t * key, uint32_t keylen, aes_gcm_ctx_t * aes_ctx)
{
  uint64_t *kptr = (uint64_t *) key;

  if (!aes_ctx || !key) {
    return (AES_GCM_INVALID_CTX);
  }
  memset (aes_ctx, 0, sizeof (aes_gcm_ctx_t));
  // Init key
  switch (keylen) {
  case 256:
    aes_ctx->K.val64[3] = kptr[3];
    CVMX_MT_AES_KEY (kptr[3], 3);
  case 192:
    aes_ctx->K.val64[2] = kptr[2];
    CVMX_MT_AES_KEY (kptr[2], 2);
  case 128:
    aes_ctx->K.val64[0] = kptr[0];
    aes_ctx->K.val64[1] = kptr[1];
    CVMX_MT_AES_KEY (kptr[1], 1);
    CVMX_MT_AES_KEY (kptr[0], 0);
    break;
  default:
    return (AES_GCM_INVALID_KEYLENGTH);
  }

  aes_ctx->keylen = keylen / 64;
  CVMX_MT_AES_KEYLENGTH (aes_ctx->keylen - 1);

  // Run key schedule and get H
  CVMX_MT_AES_ENC0 (0);
  CVMX_MT_AES_ENC1 (0);

  CVMX_MF_AES_RESULT (aes_ctx->H.val64[0], 0);
  CVMX_MF_AES_RESULT (aes_ctx->H.val64[1], 1);

  cur_aes_ctx = aes_ctx;
  aes_ctx->done |= AES_GCM_KEY_DONE;
  // Done
  return (AES_GCM_SUCCESS);
}

static inline int
AES_GCM_set_key (aes_gcm_ctx_t * aes_ctx)
{
  // Init key
  CVMX_MT_AES_KEY (aes_ctx->K.val64[3], 3);
  CVMX_MT_AES_KEY (aes_ctx->K.val64[2], 2);
  CVMX_MT_AES_KEY (aes_ctx->K.val64[1], 1);
  CVMX_MT_AES_KEY (aes_ctx->K.val64[0], 0);

  CVMX_MT_AES_KEYLENGTH (aes_ctx->keylen - 1);
  return 0;
}

int
AES_GCM_set_iv (uint8_t * iv, uint32_t ivlen, aes_gcm_ctx_t * aes_ctx)
{
    int i;
    block16_t *ivb_ptr = (block16_t *) iv;

    if (!(aes_ctx->done & AES_GCM_KEY_DONE))
        return AES_GCM_KEY_NOT_SET;

  // Generate Y_0 as follows:
  //
  //          / IV || 0^31 || 1
  //   Y_0 = |
  //          \ GHASH(H,{},IV)

  if (ivlen == (96 / 8)) {

    // Y_O = IV || 0^31 || 1
    aes_ctx->Y_i.val64[0] = ivb_ptr->val64[0];
    aes_ctx->Y_i.val32[2] = ivb_ptr->val32[2];
    aes_ctx->Y_i.val32[3] = 1;
  } else {
    int len = ivlen;
    block16_t last_block;

    // Init GHASH
    GHASH_init (0xe100, &aes_ctx->H.val64[0]);

    // Run GHASH for blocks 1 .. n-1
    for (i = 0; i < (len - 16); i += 16) {
      GHASH_update ((uint64_t *) ivb_ptr);
      ivb_ptr++;
    }

    len = len - i;

    // Run GHASH for the last block
    last_block.val64[0] = 0;
    last_block.val64[1] = 0;
    for (i = 0; i < len; i++)
      last_block.val8[i] = ivb_ptr->val8[i];

    GHASH_update (last_block.val64);

    // Finish GHASH
    GHASH_finish (0, ivlen * 8, &aes_ctx->Y_i.val64[0]);
  }
  aes_ctx->Y_0 = aes_ctx->Y_i.val32[3];

  // Y_1 
  aes_ctx->Y_i.val32[3]++;

  GHASH_init (0xe100, &aes_ctx->H.val64[0]);

  cur_aes_ctx = aes_ctx;
  aes_ctx->done |= AES_GCM_IV_DONE;
  return AES_GCM_SUCCESS;
}

int AES_GCM_set_aad(uint8_t *ain, uint32_t alen, aes_gcm_ctx_t *aes_ctx)
{
    int len, i;
    block16_t *iptr;
    block16_t input;

    // Authentication data is optional.
    // alen is 0, implies that there is no auth data.
    if(!alen)
        goto end;

    if (!(aes_ctx->done & AES_GCM_IV_DONE))
        return AES_GCM_IV_NOT_SET;

    if(cur_aes_ctx != aes_ctx)
    {
        // Set iv from context
        GHASH_restore (0xe100, &aes_ctx->H.val64[0]);
    }

    iptr = (block16_t *) ain;
    len = alen;

    // Run GHASH for auth blocks 1 .. n-1
    for (i = 0; i < (len - 16); i += 16) {
        // Read auth data block
        CVMX_LOADUNA_INT64 (input.val64[0], iptr, 0);
        CVMX_LOADUNA_INT64 (input.val64[1], iptr++, 8);

        // GHASH Update
        CVMX_MT_GFM_XOR0 (input.val64[0]);
        CVMX_MT_GFM_XORMUL1 (input.val64[1]);
    }

    len = alen - i;

    // GHASH Update for the last auth block
    input.val64[0] = 0;
    input.val64[1] = 0;
    for (i = 0; i < len; i++)
        input.val8[i] = iptr->val8[i];

    CVMX_MT_GFM_XOR0 (input.val64[0]);
    CVMX_MT_GFM_XORMUL1 (input.val64[1]);

    if(!(aes_ctx->done & AES_GCM_SINGLE))
    {
        // Store the hash calculated up to this point in context
        CVMX_MF_GFM_RESINP (aes_ctx->E.val64[0], 0);
        CVMX_MF_GFM_RESINP (aes_ctx->E.val64[1], 1);
    }

end:
    if(!(aes_ctx->done & AES_GCM_SINGLE))
    {
      // Set key from context
      AES_GCM_set_key(aes_ctx);

      // Set iv from context
      GHASH_restore (0xe100, &aes_ctx->H.val64[0]);

      // Load the HASH into register
      CVMX_MT_GFM_RESINP (aes_ctx->E.val64[0], 0);
      CVMX_MT_GFM_RESINP (aes_ctx->E.val64[1], 1);
    }
    cur_aes_ctx = aes_ctx;
    aes_ctx->done |= AES_GCM_AAD_DONE;
    return AES_GCM_SUCCESS;
}

/**
 *
 * @param *pin pointer to plain-text data (to be encrypted)
 * @param plen size of plain-text data in bytes
 * @param *out pointer to encrypted data (output)
 * @param *aes_ctx pointer AES-GCM context
 *   
 */
int
AES_GCM_ctx_encrypt (uint8_t * pin, uint32_t plen,
  uint8_t * out, aes_gcm_ctx_t * aes_ctx)
{
  int len, i;
  block16_t *iptr, *optr;
  block16_t input, result, mask;

  if (!(aes_ctx->done & AES_GCM_AAD_DONE))
      return AES_GCM_AAD_NOT_SET;

  // Pre-fetch first cache line
  CVMX_PREFETCH0(pin);

  if(cur_aes_ctx != aes_ctx)
  {
      // Set key from context
      AES_GCM_set_key(aes_ctx);

      // Set iv from context
      GHASH_restore (0xe100, &aes_ctx->H.val64[0]);

      // Load the HASH into register
      CVMX_MT_GFM_RESINP (aes_ctx->E.val64[0], 0);
      CVMX_MT_GFM_RESINP (aes_ctx->E.val64[1], 1);
  }

  // Start encrypting 2nd counter block
  // (to be used to XOR the first input data block)
  CVMX_MT_AES_ENC0 (aes_ctx->Y_i.val64[0]);
  CVMX_MT_AES_ENC1 (aes_ctx->Y_i.val64[1]);
  
  // =================
  // encrypt-auth loop
  // =================

  iptr = (block16_t *) pin;
  optr = (block16_t *) out;
  len = plen;

  if (len < 16)
    goto encrypt_loop_done;

  do {
    // Pre-fetch next cache-line
    CVMX_PREFETCH128(iptr);

    // Update remaining length
    len -= 16;

    // Increment counter value
    aes_ctx->Y_i.val32[3]++;

    // Read input data block
    CVMX_LOADUNA_INT64 (input.val64[0], iptr, 0);
    CVMX_LOADUNA_INT64 (input.val64[1], iptr++, 8);

    // Read previous result & start encrypting next counter block
    CVM_AES_RD_RESULT_WR_DATA (result.val64[0], result.val64[1], aes_ctx->Y_i.val64[0], aes_ctx->Y_i.val64[1]);

    // XOR input with AES result
    result.val64[0] ^= input.val64[0];
    result.val64[1] ^= input.val64[1];

    // Feed XOR result to GHASH
    CVMX_MT_GFM_XOR0 (result.val64[0]);
    CVMX_MT_GFM_XORMUL1 (result.val64[1]);

    // Write output
    CVMX_STOREUNA_INT64 (result.val64[0], optr, 0);
    CVMX_STOREUNA_INT64 (result.val64[1], optr++, 8);

  } while (len >= 16);

  // ====================
  // encrypt-auth trailer
  // ====================
encrypt_loop_done:
  
  if (len == 0)
  {
      if(!(aes_ctx->done & AES_GCM_SINGLE))
      {
          // Store the hash calculated up to this point in context
          CVMX_MF_GFM_RESINP (aes_ctx->E.val64[0], 0);
          CVMX_MF_GFM_RESINP (aes_ctx->E.val64[1], 1);
      }
      cur_aes_ctx = aes_ctx;

      return AES_GCM_SUCCESS;
  }
  //  goto encrypt_done;

  mask.val64[0] = 0;
  mask.val64[1] = 0;

  // Get last input block
  for (i = 0; i < len; i++) {
    input.val8[i] = iptr->val8[i];
    mask.val8[i] = 0xff;
  }

  // Read last AES result
  CVMX_MF_AES_RESULT (result.val64[0], 0);
  CVMX_MF_AES_RESULT (result.val64[1], 1);

  // XOR input with last AES result
  result.val64[0] ^= input.val64[0];
  result.val64[1] ^= input.val64[1];

  // Mask last XOR result
  result.val64[0] &= mask.val64[0];
  result.val64[1] &= mask.val64[1];

  // Feed last XOR result to GHASH
  CVMX_MT_GFM_XOR0 (result.val64[0]);
  CVMX_MT_GFM_XORMUL1 (result.val64[1]);

  if(!(aes_ctx->done & AES_GCM_SINGLE))
  {
      // Store the hash calculated up to this point in context
      CVMX_MF_GFM_RESINP (aes_ctx->E.val64[0], 0);
      CVMX_MF_GFM_RESINP (aes_ctx->E.val64[1], 1);
  }

  cur_aes_ctx = aes_ctx;

  // Write out last result
  for (i = 0; i < len; i++)
    optr->val8[i] = result.val8[i];
  return AES_GCM_SUCCESS;
}

/*AES_GCM_ctx_final*/
/**
 *
 * @param plen size of plain-text data in bytes
 * @param alen size of auth-only data in bytes
 * @param *tag pointer to 16-byte tag value (output)
 * @param *aes_ctx pointer AES-GCM context
 *   
 */

int
AES_GCM_ctx_final(uint32_t plen, uint32_t alen, uint8_t * tag, aes_gcm_ctx_t * aes_ctx)
{
  block16_t input, result;
  {     
    uint32_t Y_t;

    // Restore 1st counter value
    Y_t = aes_ctx->Y_i.val32[3];
    aes_ctx->Y_i.val32[3] = aes_ctx->Y_0;

    if(cur_aes_ctx != aes_ctx)
    {
        // Set key from context
        AES_GCM_set_key(aes_ctx);

        // Set iv from context
        GHASH_restore (0xe100, &aes_ctx->H.val64[0]);

        // Load the HASH into register
        CVMX_MT_GFM_RESINP (aes_ctx->E.val64[0], 0);
        CVMX_MT_GFM_RESINP (aes_ctx->E.val64[1], 1);
    }
    cur_aes_ctx = NULL;

    // Encrypt first counter block (Y_0)
    CVMX_MT_AES_ENC0 (aes_ctx->Y_i.val64[0]);
    CVMX_MT_AES_ENC1 (aes_ctx->Y_i.val64[1]);

    // Feed lengths to GHASH
    CVMX_MT_GFM_XOR0 ((uint64_t) alen * 8);
    CVMX_MT_GFM_XORMUL1 ((uint64_t) plen * 8);

    aes_ctx->Y_i.val32[3] = Y_t;

    // Read AES result
    CVMX_MF_AES_RESULT (input.val64[0], 0);
    CVMX_MF_AES_RESULT (input.val64[1], 1);

    // Read Galois result (GHASH_finish)
    // (have to stall here -- there is
    //  nothing else we can do)
    CVMX_MF_GFM_RESINP (result.val64[0], 0);
    CVMX_MF_GFM_RESINP (result.val64[1], 1);

    // Construct tag
    result.val64[0] ^= input.val64[0];
    result.val64[1] ^= input.val64[1];

    // Write out tag
    CVMX_STOREUNA_INT64 (result.val64[0], tag, 0);
    CVMX_STOREUNA_INT64 (result.val64[1], tag, 8);
  }
  return AES_GCM_SUCCESS;
}


/**
 *
 * @param *cin pointer to encrypted-text data (to be decrypted)
 * @param clen size of plain-text data in bytes
 * @param *out pointer to decrypted data (output)
 * @param *aes_ctx pointer AES-GCM context
 *   
 */
int
AES_GCM_ctx_decrypt (uint8_t * cin, uint32_t clen,
  uint8_t * out, aes_gcm_ctx_t * aes_ctx)
{
  int len, i;
  block16_t *iptr, *optr;
  block16_t input, result, mask;

  if (!(aes_ctx->done & AES_GCM_AAD_DONE))
      return AES_GCM_AAD_NOT_SET;

  // Pre-fetch first cache line
  CVMX_PREFETCH0(cin);

  if(cur_aes_ctx != aes_ctx)
  {
      // Set key from context
      AES_GCM_set_key(aes_ctx);

      // Set iv from context
      GHASH_restore (0xe100, &aes_ctx->H.val64[0]);

      // Load the HASH into register
      CVMX_MT_GFM_RESINP (aes_ctx->E.val64[0], 0);
      CVMX_MT_GFM_RESINP (aes_ctx->E.val64[1], 1);
  }

  // Start encrypting block
  // (to be used to XOR the first input data block)
  CVMX_MT_AES_ENC0 (aes_ctx->Y_i.val64[0]);
  CVMX_MT_AES_ENC1 (aes_ctx->Y_i.val64[1]);

  // =================
  // decrypt-auth loop
  // =================

  iptr = (block16_t *) cin;
  optr = (block16_t *) out;
  len = clen;

  if (len < 16)
    goto decrypt_loop_done;

  do {

    // Pre-fetch next cache-line
    CVMX_PREFETCH128(iptr);

    // Update remaining length
    len -= 16;

    // Increment counter value
    aes_ctx->Y_i.val32[3]++;

    // Read input data block
    CVMX_LOADUNA_INT64 (input.val64[0], iptr, 0);
    CVMX_LOADUNA_INT64 (input.val64[1], iptr++, 8);

    // Read previous result & start encrypting next counter block
    CVM_AES_RD_RESULT_WR_DATA (result.val64[0], result.val64[1], aes_ctx->Y_i.val64[0], aes_ctx->Y_i.val64[1]);

    // Feed XOR result to GHASH
    CVMX_MT_GFM_XOR0 (input.val64[0]);
    CVMX_MT_GFM_XORMUL1 (input.val64[1]);

    // XOR input with AES result
    result.val64[0] ^= input.val64[0];
    result.val64[1] ^= input.val64[1];

    // Write output
    CVMX_STOREUNA_INT64 (result.val64[0], optr, 0);
    CVMX_STOREUNA_INT64 (result.val64[1], optr++, 8);

  } while (len >= 16);

  // ====================
  // decrypt-auth trailer
  // ====================
decrypt_loop_done:

  if (len == 0)
  {
      if(!(aes_ctx->done & AES_GCM_SINGLE))
      {
          // Store the hash calculated up to this point in context
          CVMX_MF_GFM_RESINP (aes_ctx->E.val64[0], 0);
          CVMX_MF_GFM_RESINP (aes_ctx->E.val64[1], 1);
      }
      cur_aes_ctx = aes_ctx;
      return AES_GCM_SUCCESS;
  }
   // goto decrypt_done;

  mask.val64[0] = 0;
  mask.val64[1] = 0;

  input.val64[0] = 0;
  input.val64[1] = 0;

  // Get last input block
  for (i = 0; i < len; i++) {
    input.val8[i] = iptr->val8[i];
    mask.val8[i] = 0xff;
  }

  // Feed last XOR result to GHASH
  CVMX_MT_GFM_XOR0 (input.val64[0]);
  CVMX_MT_GFM_XORMUL1 (input.val64[1]);

  if(!(aes_ctx->done & AES_GCM_SINGLE))
  {
      // Store the hash calculated up to this point in context
      CVMX_MF_GFM_RESINP (aes_ctx->E.val64[0], 0);
      CVMX_MF_GFM_RESINP (aes_ctx->E.val64[1], 1);
  }

  // Read last AES result
  CVMX_MF_AES_RESULT (result.val64[0], 0);
  CVMX_MF_AES_RESULT (result.val64[1], 1);

  // XOR input with last AES result
  result.val64[0] ^= input.val64[0];
  result.val64[1] ^= input.val64[1];

  // Mask last XOR result
  result.val64[0] &= mask.val64[0];
  result.val64[1] &= mask.val64[1];

  cur_aes_ctx = aes_ctx;

  // Write out last result
  for (i = 0; i < len; i++)
    optr->val8[i] = result.val8[i];
  return AES_GCM_SUCCESS;
}

int
AES_GCM_encrypt (uint8_t * key, uint32_t keylen, uint8_t * iv,
  uint32_t ivlen, uint8_t * ain, uint32_t alen, uint8_t * pin,
  uint32_t plen, uint8_t * out, uint8_t * tag)
{
  aes_gcm_ctx_t aes_ctx;
  int ret;
  ret = AES_GCM_init_key (key, keylen, &aes_ctx);
  if (ret)
    return ret;
  // This flag identifies whether it is a single call or multicall.
  // Kept this here to save some cycles in single call.
  aes_ctx.done |= AES_GCM_SINGLE;
  ret = AES_GCM_set_iv (iv, ivlen, &aes_ctx);
  if (ret)
    return ret;
  ret = AES_GCM_set_aad(ain, alen, &aes_ctx);
  if (ret)
      return ret;
  AES_GCM_ctx_encrypt (pin, plen, out, &aes_ctx);
  return AES_GCM_ctx_final(plen, alen, tag, &aes_ctx);
}

int
AES_GCM_decrypt (uint8_t * key, uint32_t keylen, uint8_t * iv,
  uint32_t ivlen, uint8_t * ain, uint32_t alen, uint8_t * cin,
  uint32_t clen, uint8_t * out, uint8_t * tag)
{
  aes_gcm_ctx_t aes_ctx;
  int ret;

  ret = AES_GCM_init_key (key, keylen, &aes_ctx);
  if (ret)
    return ret;
  // This flag identifies whether it is a single call or multicall.
  // Kept this here to save some cycles in single call.
  aes_ctx.done |= AES_GCM_SINGLE;
  ret = AES_GCM_set_iv (iv, ivlen, &aes_ctx);
  if (ret)
    return ret;
  ret = AES_GCM_set_aad (ain, alen, &aes_ctx);
  if (ret)
    return ret;
  
   AES_GCM_ctx_decrypt (cin, clen, out, &aes_ctx);
  return AES_GCM_ctx_final(clen, alen, tag, &aes_ctx);
}

int
AES_GMAC_ctx_tag(uint8_t *ain, uint32_t alen, uint8_t *tag,
                 aes_gcm_ctx_t *aes_ctx)
{
  block16_t *iptr;  
  block16_t input, result;
  uint32_t len;
  uint32_t i;

  if (!(aes_ctx->done & AES_GCM_IV_DONE))
      return AES_GCM_IV_NOT_SET;

  /* set up AES key */
  AES_GCM_set_key(aes_ctx);

  GHASH_init(0xe100, &aes_ctx->H.val64[0]);

  if (alen == 0)
    goto auth_done;

  iptr = (block16_t *)ain;
  len = alen;

  // Run GHASH for auth blocks 1 .. n-1
  for (i = 0; i < (len - 16); i += 16) {
    // Read auth data block
    CVMX_LOADUNA_INT64 (input.val64[0], iptr, 0);
    CVMX_LOADUNA_INT64 (input.val64[1], iptr++, 8);

    // GHASH Update
    CVMX_MT_GFM_XOR0 (input.val64[0]);
    CVMX_MT_GFM_XORMUL1 (input.val64[1]);
  }

  len = alen - i;

  // GHASH Update for the last auth block
  input.val64[0] = 0;
  input.val64[1] = 0;
  for (i = 0; i < len; i++)
    input.val8[i] = iptr->val8[i];

  CVMX_MT_GFM_XOR0 (input.val64[0]);
  CVMX_MT_GFM_XORMUL1 (input.val64[1]);

auth_done:
  // Feed lengths to GHASH
  CVMX_MT_GFM_XOR0 ((uint64_t) alen * 8);
  CVMX_MT_GFM_XORMUL1 ((uint64_t) 0x0ull);

  aes_ctx->Y_i.val32[3] = aes_ctx->Y_0;

  // Encrypt first counter block (Y_0)
  CVMX_MT_AES_ENC0 (aes_ctx->Y_i.val64[0]);
  CVMX_MT_AES_ENC1 (aes_ctx->Y_i.val64[1]);

  CVMX_MF_GFM_RESINP (result.val64[0], 0);
  CVMX_MF_GFM_RESINP (result.val64[1], 1);

  // Read AES result
  CVMX_MF_AES_RESULT (input.val64[0], 0);
  CVMX_MF_AES_RESULT (input.val64[1], 1);

  // Construct tag
  result.val64[0] ^= input.val64[0];
  result.val64[1] ^= input.val64[1];

  // Write out tag
  CVMX_STOREUNA_INT64 (result.val64[0], tag, 0);
  CVMX_STOREUNA_INT64 (result.val64[1], tag, 8);

  return AES_GMAC_SUCCESS;
}

int
AES_GMAC_tag(uint8_t *key, uint32_t keylen, uint8_t *iv, uint32_t ivlen,
             uint8_t *ain, uint32_t alen, uint8_t *tag)
{
  aes_gcm_ctx_t aes_ctx;
  int ret;

  ret = AES_GCM_init_key(key, keylen, &aes_ctx);
  if (ret)
    return ret;

  ret = AES_GCM_set_iv(iv, ivlen, &aes_ctx);
  if (ret)
    return ret;

  return AES_GMAC_ctx_tag(ain, alen, tag, &aes_ctx);
}
#endif
