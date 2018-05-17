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


#ifndef HEADER_GCM_H
#define HEADER_GCM_H


  typedef union {
    uint64_t val64[2];
    uint32_t val32[4];
    uint8_t val8[16];
  } block16_t;

  typedef union {
    uint64_t val64[4];
    uint32_t val32[8];
    uint8_t val8[32];
  } block32_t;

  typedef struct aes_gcm_ctx_type {
    // Counter value Y_i (128 bits)
    block16_t Y_i;

    // AES Key (128, 192, or 256 bits)
    block32_t K;

    // H (128 bits)
    block16_t H;

    // Calculated HASH
    block16_t E;

    // (used at the end to XOR with GHASH output to form auth tag)
    uint32_t Y_0;

    // AES key length
    uint32_t keylen;

    // state
    uint32_t done;

  } aes_gcm_ctx_t;

// context flags (bit fields)
#define AES_GCM_SINGLE   0x1
#define AES_GCM_KEY_DONE 0x2
#define AES_GCM_IV_DONE  0x4
#define AES_GCM_AAD_DONE 0x8
  // Return codes
#define AES_GCM_SUCCESS              0
#define AES_GCM_INVALID_KEYLENGTH   -1
#define AES_GCM_INVALID_CTX         -2
#define AES_GCM_IV_NOT_SET          -3
#define AES_GCM_KEY_NOT_SET         -4
#define AES_GCM_NOT_SUPPORTED       -5
#define AES_GCM_AAD_NOT_SET         -6
#define AES_GMAC_SUCCESS             0

/**
 * AES GCM Initialization of the key
 * @param key pointer to Key of size keylen bits (Input)
 * @param keylen Length of the key in bits (Input)
 * @param aes_ctx pointer to aes_gcm_ctx_t structure. 
 *        This is an opaque pointer to the user (Input)
 * @return AES_GCM_SUCCESS (0)             
 *         AES_GCM_INVALID_KEYLENGTH (-1)
 */
  int AES_GCM_init_key (uint8_t * key, uint32_t keylen,
    aes_gcm_ctx_t * aes_ctx);
/**
 * AES GCM Set the IV
 * @param iv pointer to "iv" of size "ivlen" bytes (Input)
 * @param ivlen Length of the iv in bytes (Input)
 * @param aes_ctx pointer to aes_gcm_ctx_t structure. 
 *        This is an opaque pointer to the user (Input)
 * @return AES_GCM_SUCCESS (0)             
 *         AES_GCM_INVALID_CTX (-2)
 *         AES_GCM_KEY_NOT_SET (-4)
 */
  int AES_GCM_set_iv (uint8_t * iv, uint32_t ivlen,
    aes_gcm_ctx_t * aes_ctx);

/**
 * AES GCM Set AAD
 * @param ain pointer to Authentication data of size "alen" bytes (Input)
 * @param alen Length of the Authentication data in bytes (Input)
 * @param aes_ctx pointer to aes_gcm_ctx_t structure.
 *      This is an opaque pointer to the user (Input)
 * @return AES_GCM_SUCCESS (0)
 *      AES_GCM_IV_NOT_SET (-5)
 */
  int AES_GCM_set_aad (uint8_t *ain, uint32_t alen, 
          aes_gcm_ctx_t *aes_ctx);

/**
 * AES GCM Encryption + Authentication operation 
 *          (Multiple calls for same key)
 *          This encrypts plain input and authenticates the input
 *          authentication data. One or both of these inputs can
 *          be given together.
 * @param pin pointer to Plain input of size "plen" bytes (Input)
 * @param plen Length of the Plain input in bytes (Input)
 * @param out pointer to Ciphered output of size "plen" bytes (Output)
 * @param aes_ctx pointer to aes_gcm_ctx_t structure. 
 *        This is an opaque pointer to the user (Input)
 * @return AES_GCM_SUCCESS (0)             
 *         AES_GCM_INVALID_CTX (-2)
 *         AES_GCM_IV_NOT_SET  (-3)
 *         AES_GCM_KEY_NOT_SET (-4)
 */
  int AES_GCM_ctx_encrypt (uint8_t * pin, uint32_t plen,
    uint8_t * out, aes_gcm_ctx_t * aes_ctx);

/**
 * AES GCM final MAC calulation
 * @param plen Length of the Plain input in bytes (Input)
 * @param alen Length of the Authentication data in bytes (Input)
 * @param tag Pointer to 16 bytes of generated authentication tag (Output)
 * @param aes_ctx pointer to aes_gcm_ctx_t structure.
 */
  int AES_GCM_ctx_final(uint32_t plen, uint32_t alen, uint8_t * tag,
    aes_gcm_ctx_t * aes_ctx);


/**
 * AES GCM Decryption + Authentication operation
 *          (Multiple calls for same key)
 *          This decrypts ciphered input and authenticates the input
 *          authentication data. One or both of these inputs can
 *          be given together.
 * @param cin pointer to Ciphered input of size "clen" bytes (Input)
 * @param clen Length of the Ciphered input in bytes (Input)
 * @param out pointer to Plain output of size "clen" bytes (Output)
 * @param aes_ctx pointer to aes_gcm_ctx_t structure. 
 *        This is an opaque pointer to the user (Input)
 * @return AES_GCM_SUCCESS (0)             
 *         AES_GCM_INVALID_KEYLENGTH (-1)
 *         AES_GCM_INVALID_CTX (-2)
 *         AES_GCM_IV_NOT_SET  (-3)
 *         AES_GCM_KEY_NOT_SET (-4)
 */
  int AES_GCM_ctx_decrypt (uint8_t * cin, uint32_t clen,
    uint8_t * out, aes_gcm_ctx_t * aes_ctx);
/**
 * AES GCM Encryption + Authentication operation
 *          This encrypts plain input and authenticates the input
 *          authentication data. One or both of these inputs can
 *          be given together.
 * @param key pointer to Key of size keylen bits (Input)
 * @param keylen Length of the key in bits (Input)
 * @param iv pointer to "iv" of size "ivlen" bytes (Input)
 * @param ivlen Length of the iv in bytes (Input)
 * @param ain pointer to Authentication data of size "alen" bytes (Input)
 * @param alen Length of the Authentication data in bytes (Input)
 * @param pin pointer to Plain input of size "plen" bytes (Input)
 * @param plen Length of the Plain input in bytes (Input)
 * @param out pointer to Ciphered output of size "plen" bytes (Output)
 * @param tag Pointer to 16 bytes of generated authentication tag (Output)
 * @return AES_GCM_SUCCESS (0)             
 *         AES_GCM_INVALID_KEYLENGTH (-1)
 *         AES_GCM_INVALID_CTX (-2)
 *         AES_GCM_IV_NOT_SET  (-3)
 *         AES_GCM_KEY_NOT_SET (-4)
 */
  int AES_GCM_encrypt (uint8_t * key, uint32_t keylen, uint8_t * iv,
    uint32_t ivlen, uint8_t * ain, uint32_t alen, uint8_t * pin,
    uint32_t plen, uint8_t * out, uint8_t * tag);
/**
 * AES GCM Decryption + Authentication operation
 *          This decrypts ciphered input and authenticates the input
 *          authentication data. One or both of these inputs can
 *          be given together.
 * @param key pointer to Key of size keylen bits (Input)
 * @param keylen Length of the key in bits (Input)
 * @param iv pointer to "iv" of size "ivlen" bytes (Input)
 * @param ivlen Length of the iv in bytes (Input)
 * @param cin pointer to Ciphered input of size "clen" bytes (Input)
 * @param clen Length of the Ciphered input in bytes (Input)
 * @param ain pointer to Authentication data of size "alen" bytes (Input)
 * @param alen Length of the Authentication data in bytes (Input)
 * @param out pointer to Plain output of size "clen" bytes (Output)
 * @param tag Pointer to 16 bytes of generated authentication tag (Output)
 * @return AES_GCM_SUCCESS (0)             
 *         AES_GCM_INVALID_KEYLENGTH (-1)
 *         AES_GCM_INVALID_CTX (-2)
 *         AES_GCM_IV_NOT_SET  (-3)
 *         AES_GCM_KEY_NOT_SET (-4)
 */
  int AES_GCM_decrypt (uint8_t * key, uint32_t keylen, uint8_t * iv,
    uint32_t ivlen, uint8_t * ain, uint32_t alen, uint8_t * cin,
    uint32_t clen, uint8_t * out, uint8_t * tag);

/**
 * AES GMAC Authentication operation
 *          This authenticates the authentication data.
 * @param key pointer to Key of size keylen bits (Input)
 * @param keylen Length of the key in bits (Input)
 * @param iv pointer to "iv" of size "ivlen" bytes (Input)
 * @param ivlen Length of the iv in bytes (Input)
 * @param ain pointer to Authentication data of size "alen" bytes (Input)
 * @param alen Length of the Authentication data in bytes (Input)
 * @param tag Pointer to 16 bytes of generated authentication tag (Output)
 * @return AES_GMAC_SUCCESS (0)             
 *         AES_GCM_INVALID_KEYLENGTH (-1)
 *         AES_GCM_INVALID_CTX (-2)
 *         AES_GCM_IV_NOT_SET  (-3)
 *         AES_GCM_KEY_NOT_SET (-4)
 */
int
AES_GMAC_tag(uint8_t *key, uint32_t keylen, uint8_t *iv, uint32_t ivlen,
             uint8_t *ain, uint32_t alen, uint8_t *tag);

/**
 * AES GMAC Authentication operation
 *          (Multiple calls for same key)
 * @param ain pointer to Authentication data of size "alen" bytes (Input)
 * @param alen Length of the Authentication data in bytes (Input)
 * @param tag Pointer to 16 bytes of generated authentication tag (Output)
 * @param aes_ctx pointer to aes_gcm_ctx_t structure. 
 *        This is an opaque pointer to the user (Input)
 * @return AES_GMAC_SUCCESS (0)             
 *         AES_GCM_IV_NOT_SET  (-3)
 */
int
AES_GMAC_ctx_tag(uint8_t *ain, uint32_t alen, uint8_t *tag,
                 aes_gcm_ctx_t *aes_ctx);

void
GHASH_restore (uint16_t polynomial, void *multiplier);

int
AES_GCM_set_key (aes_gcm_ctx_t * aes_ctx);
  
  typedef struct {
    // Key 1 ( first 128, 192 or 256 bits)
    block32_t K1;

    // Key 2 (last 128 bits)
    block16_t K2;

    // Key1 Length (Total key length - 128)
    uint32_t K1_len;

    // Last Tweak value used
    block16_t tweak;

    // state
    uint32_t init_done;

  } lrw_aes_ctx_t;

#endif
