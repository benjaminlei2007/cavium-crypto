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
//RFC3566
#ifdef OCTEON_OPENSSL

#include <string.h>
#include <assert.h>

#include "cvmx.h"
#include "cvmx-key.h"

#include "openssl/aes.h"

int
cvm_crypto_aes_xcbc_prf128 (uint64_t * orgkey,
  uint32_t bits, uint64_t * data, uint32_t dlen, uint64_t * mac)
{
  uint32_t keylen = bits;
  uint64_t const1A[2];
  uint64_t const1B[2];
  uint64_t const2[2];
  uint64_t const3[2];
  aes_assert (orgkey, -1);
  aes_assert (data, -1);
  aes_assert (mac, -1);
  aes_assert ((keylen <= 256), -1);

  memset (const1A, 0x01, 16);
  memset (const1B, 0x01, 16);
  memset (const2, 0x02, 16);
  memset (const3, 0x03, 16);

  if (keylen < 128) {
    uint64_t key[4];
    memset (key, 0, sizeof (key));
    memcpy (key, orgkey, keylen / 8);
    cvm_crypto_aes_xcbc_mac_nist_generic (key, 16, const1A, const1B,
      const2, const3, data, dlen, mac);
  } else if (keylen == 128) {
    uint64_t *key = orgkey;
    cvm_crypto_aes_xcbc_mac_nist_generic (key, 16, const1A, const1B,
      const2, const3, data, dlen, mac);
  } else {
    //step1
    uint64_t zerokey[2] = { 0, 0 };
    uint64_t tmpmac[2];
    cvm_crypto_aes_xcbc_mac_nist_generic (zerokey, 16, const1A, const1B,
      const2, const3, orgkey, keylen / 8, tmpmac);

    //step2
    cvm_crypto_aes_xcbc_mac_nist_generic (tmpmac, 16, const1A, const1B,
      const2, const3, data, dlen, mac);
  }
  return 0;
}


int
cvm_crypto_aes_xcbc_prf128_init (uint8_t * orgkey, uint32_t bits,
  AES_KEY * key, AES_XCBC_MAC_CTX * ctx)
{
  
  uint64_t tmpkey[4];
  aes_assert (orgkey, -1);
  aes_assert (key, -1);
  aes_assert (ctx, -1);
  aes_assert ((bits <= 256), -1);

  memset (tmpkey, 0, sizeof (key));
  memcpy (tmpkey, orgkey, bits / 8);
  if (bits < 128) {
    cvm_crypto_aes_xcbc_mac_init ((uint8_t *) tmpkey, bits, key, ctx);
  } else if (bits == 128) {
    cvm_crypto_aes_xcbc_mac_init ((uint8_t *) tmpkey, bits, key, ctx);
  } else {
    uint64_t zerokey[2] = { 0, 0 };
    uint64_t tmpmac[2];
    AES_XCBC_MAC_CTX tmpstate[1];
    AES_KEY tmpaeskey;
    cvm_crypto_aes_xcbc_mac_init ((uint8_t *) zerokey, 128/8, &tmpaeskey,
      tmpstate);
    cvm_crypto_aes_xcbc_mac_update (&tmpaeskey, orgkey, bits / 8,
      tmpstate);
    cvm_crypto_aes_xcbc_mac_final (&tmpaeskey, tmpstate, tmpmac);
    /* Note that as per RFC this tmpmac is the new key for rest of the multicall.
     * It  has also been explicitly mentioned that AES_KEY *key becomes invalid 
     * after the final call
     */
    cvm_crypto_aes_xcbc_mac_init ((uint8_t *) tmpmac, 128/8, key, ctx);
  }
  return 0;
}


int
cvm_crypto_aes_xcbc_prf128_update (AES_KEY * key, uint8_t * data,
  uint32_t dlen, AES_XCBC_MAC_CTX * ctx)
{
  return cvm_crypto_aes_xcbc_mac_update (key, data, dlen, ctx);
}


int
cvm_crypto_aes_xcbc_prf128_final (AES_KEY * key, AES_XCBC_MAC_CTX * ctx,
  uint64_t * mac)
{
  return cvm_crypto_aes_xcbc_mac_final (key, ctx, mac);
}


#endif
