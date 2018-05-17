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
cvm_crypto_aes_xcbc_mac (uint64_t * key,
  uint32_t bytes, uint64_t * data, uint32_t dlen, uint64_t * mac)
{
  uint32_t orgkeylen = bytes;
  uint64_t const1A[2];
  uint64_t const1B[2];
  uint64_t const2[2];
  uint64_t const3[2];

  aes_assert (((orgkeylen == 16) || (orgkeylen == 24) ||
      (orgkeylen == 32)), -1);
  memset (const1A, 0x01, 16);
  memset (const1B, 0x01, 16);
  memset (const2, 0x02, 16);
  memset (const3, 0x03, 16);

  return cvm_crypto_aes_xcbc_mac_nist_generic (key, orgkeylen, const1A,
    const1B, const2, const3, data, dlen, mac);
}


int
cvm_crypto_aes_xcbc_mac_init (uint8_t * orgkey, uint32_t bytes,
  AES_KEY * key, AES_XCBC_MAC_CTX * ctx)
{
  aes_assert ((orgkey && key && ctx), -1);
  /* This assert will be removed once RFC 3566 is updated to support 192/256 bit keys */
  aes_assert ((bytes == 16), -1);

  /* set the key */
  memset (key->cvmkey, 0, 32);
  memcpy (key->cvmkey, orgkey, bytes);
  key->cvm_keylen = bytes * 8;

  /* initialize the constants and IV */
  memset (ctx->const1A, 0x01, 16);
  memset (ctx->const1B, 0x01, 16);
  memset (ctx->const2, 0x2, 16);
  memset (ctx->const3, 0x3, 16);
  memset (ctx->iv, 0, 16);
  memset (ctx->E, 0, 16);

  /* 
   * K1 = (0x01) repeated 16 times encrypted by K || (const1B) encrypted by K
   * K2 = (0x02) repeated 16 times encrypted by K
   * K3 = (0x03) repeated 16 times encrypted by K
   * ctx->const1A,const2,const3 will now be used as keys in update and final functions
   */
  cvm_octeon_crypto_aes_encrypt_cbc (key->cvmkey, key->cvm_keylen, ctx->iv,
    ctx->const1A, 16);
  cvm_octeon_crypto_aes_encrypt_cbc (key->cvmkey, key->cvm_keylen, ctx->iv,
    ctx->const1B, 16);
  cvm_octeon_crypto_aes_encrypt_cbc (key->cvmkey, key->cvm_keylen, ctx->iv,
    ctx->const2, 16);
  cvm_octeon_crypto_aes_encrypt_cbc (key->cvmkey, key->cvm_keylen, ctx->iv,
    ctx->const3, 16);

  ctx->done = 0;
  ctx->plen = 0;
  return 0;
}
int
cvm_crypto_aes_xcbc_mac_update (AES_KEY * key, uint8_t * data,
  uint32_t dlen, AES_XCBC_MAC_CTX * ctx)
{
  aes_assert ((key && ctx), -1);
  if (dlen == 0)
    return -1;
  aes_assert ((data), -1);

  if (ctx->plen + dlen > 16) {
    if (ctx->plen) {
      memcpy ((uint8_t *) ctx->lb + ctx->plen, data, 16 - ctx->plen);
      data += (16 - ctx->plen);
      dlen -= (16 - ctx->plen);
      ctx->plen = 0;

      ctx->E[0] ^= ctx->lb[0];
      ctx->E[1] ^= ctx->lb[1];
      cvm_octeon_crypto_aes_encrypt_cbc (ctx->const1A, key->cvm_keylen,
        ctx->iv, ctx->E, 16);
    }

    while (dlen > 16) {
      ctx->E[0] ^= ((uint64_t *) (data))[0];
      ctx->E[1] ^= ((uint64_t *) (data))[1];
      cvm_octeon_crypto_aes_encrypt_cbc (ctx->const1A, key->cvm_keylen,
        ctx->iv, ctx->E, 16);
      data += 16;
      dlen -= 16;
    }

    if (dlen) {
      memcpy ((uint8_t *) ctx->lb, data, dlen);
      ctx->plen = dlen;
    }
  } else {
    memcpy ((uint8_t *) ctx->lb + ctx->plen, data, dlen);
    ctx->plen += dlen;
  }
  return 0;
}

int
cvm_crypto_aes_xcbc_mac_final (AES_KEY * key, AES_XCBC_MAC_CTX * ctx,
  uint64_t * mac)
{
  aes_assert ((key && ctx && mac), -1);
  if (ctx->done)
    return -1;
  ctx->done = 1;
  if (ctx->plen == 16) {
    ctx->E[0] ^= ctx->lb[0];
    ctx->E[1] ^= ctx->lb[1];

    ctx->E[0] ^= ctx->const2[0];
    ctx->E[1] ^= ctx->const2[1];

    cvm_octeon_crypto_aes_encrypt_cbc (ctx->const1A, key->cvm_keylen,
      ctx->iv, ctx->E, 16);
  } else {
    memset ((uint8_t *) ctx->lb + ctx->plen, 0, 16 - ctx->plen);
    ((uint8_t *) ctx->lb)[ctx->plen] = 0x80;

    ctx->E[0] ^= ctx->lb[0];
    ctx->E[1] ^= ctx->lb[1];

    ctx->E[0] ^= ctx->const3[0];
    ctx->E[1] ^= ctx->const3[1];

    cvm_octeon_crypto_aes_encrypt_cbc (ctx->const1A, key->cvm_keylen,
      ctx->iv, ctx->E, 16);
  }
  memcpy (mac, ctx->E, 16);
  return 0;
}
#endif
