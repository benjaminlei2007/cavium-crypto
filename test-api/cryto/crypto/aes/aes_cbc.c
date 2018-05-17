/* crypto/aes/aes_cbc.c -*- mode:C; c-file-style: "eay" -*- */
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

#ifdef OCTEON_OPENSSL
#include "cvmx.h"
#include "cvmx-key.h"
#endif

void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
		     size_t len, const AES_KEY *key,
		     unsigned char *ivec, const int enc) {

#ifndef OCTEON_OPENSSL
	if (enc)
		CRYPTO_cbc128_encrypt(in,out,len,key,ivec,(block128_f)AES_encrypt);
	else
		CRYPTO_cbc128_decrypt(in,out,len,key,ivec,(block128_f)AES_decrypt);
#else
  uint64_t *iv;
  uint64_t *inp, *outp;
  uint64_t i0, i1, r0, r1;
  //unsigned long len = length;

  inp = (uint64_t *) in;
  outp = (uint64_t *) out;
  iv = (uint64_t *) ivec;
  CVMX_MT_AES_IV (iv[0], 0);
  CVMX_MT_AES_IV (iv[1], 1);

  /* Initialise the keys */
  CVMX_MT_AES_KEY (key->cvmkey[0], 0);
  CVMX_MT_AES_KEY (key->cvmkey[1], 1);
  CVMX_MT_AES_KEY (key->cvmkey[2], 2);
  CVMX_MT_AES_KEY (key->cvmkey[3], 3);
  CVMX_MT_AES_KEYLENGTH (key->cvm_keylen / 64 - 1);
  i0 = inp[0];
  i1 = inp[1];
  if (AES_ENCRYPT == enc) {
    if (len >= 32) {
      CVMX_MT_AES_ENC_CBC0 (i0);
      CVMX_MT_AES_ENC_CBC1 (i1);
      //  unrolled the loop. The first iteration doesn't store data
      /* The crypto takes 24 cycles so do some stuffs in the gap */
      len -= 16;
      inp += 2;
      outp += 2;
      if (len >= 16) {
        i0 = inp[0];
        i1 = inp[1];
        CVMX_MF_AES_RESULT (r0, 0);
        CVMX_MF_AES_RESULT (r1, 1);
        CVMX_MT_AES_ENC_CBC0 (i0);
        CVMX_MT_AES_ENC_CBC1 (i1);

        while (1) {
          outp[-2] = r0;
          outp[-1] = r1;
          len -= 16;
          inp += 2;
          outp += 2;
          if (len < 16)
            break;
          i0 = inp[0];
          i1 = inp[1];
          CVMX_PREFETCH (inp, 64);

          CVMX_MF_AES_RESULT (r0, 0);
          CVMX_MF_AES_RESULT (r1, 1);
          CVMX_MT_AES_ENC_CBC0 (i0);
          CVMX_MT_AES_ENC_CBC1 (i1);
        }
      }
      CVMX_MF_AES_RESULT (r0, 0);
      CVMX_MF_AES_RESULT (r1, 1);
      outp[-2] = r0;
      outp[-1] = r1;
    }

    if (len) {
      if (len <= 16) {
        uint64_t in64[2] = { 0, 0 };
        memcpy (&(in64[0]), inp, len);
        CVMX_MT_AES_ENC_CBC0 (in64[0]);
        CVMX_MT_AES_ENC_CBC1 (in64[1]);
        CVMX_MF_AES_RESULT (*(outp), 0);
        CVMX_MF_AES_RESULT (*(outp + 1), 1);
        memcpy (iv, outp, 16);
      }
      else {
        uint64_t in64[2] = { 0, 0 };
        CVMX_MT_AES_ENC_CBC0 (i0);
        CVMX_MT_AES_ENC_CBC1 (i1);
        CVMX_MF_AES_RESULT (*(outp), 0);
        CVMX_MF_AES_RESULT (*(outp + 1), 1);
        inp += 2;
        outp += 2;
        len -= 16;
        memcpy (&(in64[0]), inp, len);
        CVMX_MT_AES_ENC_CBC0 (in64[0]);
        CVMX_MT_AES_ENC_CBC1 (in64[1]);
        CVMX_MF_AES_RESULT (*(outp), 0);
        CVMX_MF_AES_RESULT (*(outp + 1), 1);
        memcpy (iv, outp, 16);
      }
    } else {
      memcpy (iv, (outp - 2), 16);
    }
  } else {
    /* Decrypt */
    if (len >= 32) {
      CVMX_MT_AES_DEC_CBC0 (i0);
      CVMX_MT_AES_DEC_CBC1 (i1);

      len -= 16;
      outp += 2;
      inp += 2;

      if (len >= 16) {
        /* Load ahead */
        i0 = inp[0];
        i1 = inp[1];
        CVMX_MF_AES_RESULT (r0, 0);
        CVMX_MF_AES_RESULT (r1, 1);

        CVMX_MT_AES_DEC_CBC0 (i0);
        CVMX_MT_AES_DEC_CBC1 (i1);
        while (1) {
          outp[-2] = r0;
          outp[-1] = r1;
          len -= 16;
          outp += 2;
          inp += 2;
          if (len < 16)
            break;
          i0 = inp[0];
          i1 = inp[1];
          CVMX_PREFETCH (inp, 64);
          CVMX_MF_AES_RESULT (r0, 0);
          CVMX_MF_AES_RESULT (r1, 1);
          CVMX_MT_AES_DEC_CBC0 (i0);
          CVMX_MT_AES_DEC_CBC1 (i1);
        }
      }
      /* Fetch the result of the last 16B in the 16B stuff */
      CVMX_MF_AES_RESULT (r0, 0);
      CVMX_MF_AES_RESULT (r1, 1);
      memcpy (iv, (inp - 2), 16);
      outp[-2] = r0;
      outp[-1] = r1;
    }
    if (len) {
      if (len <= 16) {
        /* To avoid len>16  tat is when len=17-31 
         * to enter into this loop */
        uint64_t in64[2] = { 0, 0 };
        memcpy (iv, inp, 16);
        memcpy (&(in64[0]), inp, len);
        CVMX_MT_AES_DEC_CBC0 (in64[0]);
        CVMX_MT_AES_DEC_CBC1 (in64[1]);
        CVMX_MF_AES_RESULT (*outp, 0);
        CVMX_MF_AES_RESULT (*(outp + 1), 1);
      }
    }
  }
#endif
}
