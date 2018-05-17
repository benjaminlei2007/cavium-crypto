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


/** 
 * AES-CBC-SHA1 Encryption
 * This function creates an IPSEC outbound packet using AES-CBC & HMAC-SHA1 keys provided
 * @param aes_key_len   [in] AES CBC encryption key length
 * @param aes_key      [in] AES CBC encryption key
 * @param sha1_keylen  [in] HMAC-SHA1 key length
 * @param sha1_key     [in] HMAC-SHA1 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet.
 * @param aes_iv           [in] Initialization vector (must be of AES_BLOCK_SIZE 
 * in length). It is placed after ESP header in the output packet
 * @param pktptr        [in] Pointer to the input payload (to be encrypted)
 * @param pktlen     [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of AES block size. 
 * This function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AES_CBC_SHA_SUCCESS (0)
 *                     AES_CBC_SHA_FAILURE (-1)
**/

  int AES_cbc_sha1_encrypt(uint16_t aes_key_len, uint8_t *aes_key,  
   uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *aes_iv,
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);

/**
 * AES-CBC-SHA1 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using 
 * the AES-CBC and HMAC-SHA1 keys provided
 * @param aes_key_len   [in] AES CBC decryption key length
 * @param aes_key      [in] AES CBC decryption key
 * @param sha1_keylen [in] HMAC-SHA1 key length
 * @param sha1_key     [in] HMAC-SHA1 key
 * @param aes_iv           [in] Initialization vector (must be of AES_BLOCK_SIZE 
 * in length).
 * @param    pktptr     [in] Pointer to the IPSEC packet (i.e, points to 
 * ESP header)
 * @param pktlen        [in] Length of IPSEC packet pointed to by input. It 
 * should include the i
 * ESP header (8 bytes) + IV (AES_BLOCK_SIZE) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr        [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             AES_CBC_SHA_SUCCESS (0)
 *                     AES_CBC_SHA_FAILURE (-1)
*/

  int AES_cbc_sha1_decrypt(uint16_t aes_key_len, uint8_t *aes_key, 
   uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv, uint8_t *pktptr, 
   uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest);


/** 
 * 3DES-CBC-SHA1 Encryption
 * This function creates an IPSEC outbound packet using 3DES-CBC & HMAC-SHA1 
 * keys provided
 * @param des_key      [in] 3DES encryption key (must be of 24 bytes in length)
 * @param sha1_keylen  [in] HMAC-SHA1 key length
 * @param sha1_key     [in] HMAC-SHA1 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in
 * length). It is placed at the start of the output packet
 * @param des_iv       [in] Initialization vector(must be of 8 bytes in length).
 *                     It is placed after ESP header in the output packet
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of DES block size. This
 * function doesn't pad anything at the end of the input
 * @param outptr       [out] Pointer to the output buffer where encrypted and
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             DES_CBC_SHA_SUCCESS (0)
 *                     DES_CBC_SHA_FAILURE (-1)
*/

  int DES_ede3_cbc_sha1_encrypt(uint8_t *des_key, uint16_t sha1_keylen, 
   uint8_t *sha1_key, uint8_t *espheader, uint8_t *des_iv, uint8_t *pktptr, 
   uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);

/** 
 * 3DES-CBC-SHA1 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the
 * 3DES-CBC and HMAC-SHA1 keys provided
 * @param des_key       [in] 3DES decryption key (must be of 24 bytes in length)
 * @param sha1_keylen   [in] HMAC-SHA1 key length
 * @param sha1_key      [in] HMAC-SHA1 key
 * @param des_iv        [in] Initialization vector (must be of 8 bytes in length).
 * @param pktptr        [in] Pointer to the IPSEC packet (i.e, points to ESP header)
 * @param pktlen        [in] Length of IPSEC packet pointed to by input. It should
 * include the 
 * ESP header (8 bytes) + IV (8 bytes) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr        [out] Pointer to the output buffer where decrypted and
 * authenticated  packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             DES_CBC_SHA_SUCCESS (0)
 *                     DES_CBC_SHA_FAILURE (-1)
*/

  int DES_ede3_cbc_sha1_decrypt(uint8_t *des_key, uint16_t sha1_keylen, 
   uint8_t *sha1_key, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen,
   uint8_t *outptr, uint16_t *outlen,uint8_t compdigest);


/** 
 * 3DES-CBC-MD5 Encryption
 * This function creates an IPSEC outbound packet using 3DES-CBC & HMAC-MD5
 * keys provided
 * @param des_key      [in] 3DES encryption key (must be of 24 bytes in length)
 * @param auth_keylen  [in] HMAC-MD5 key length
 * @param auth_key     [in] HMAC-MD5 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet
 * @param des_iv       [in] Initialization vector(must be of 8 bytes in length).
 *                     It is placed after ESP header in the output packet
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of DES block size. 
 * This function doesn't pad anything at the end of the input
 * @param outptr       [out] Pointer to the output buffer where encrypted and
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             DES_CBC_MD5_SUCCESS (0)
 *                     DES_CBC_MD5_FAILURE (-1)
*/

  int DES_ede3_cbc_md5_encrypt(uint8_t *des_key, uint16_t auth_keylen, 
   uint8_t *auth_key, uint8_t *espheader, uint8_t *des_iv, uint8_t *pktptr, 
   uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);

/** 
 * 3DES-CBC-MD5 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the
 * 3DES-CBC and HMAC-MD5 keys provided
 * @param des_key      [in] 3DES decryption key (must be of 24 bytes in length)
 * @param auth_keylen  [in] HMAC-MD5 key length
 * @param auth_key     [in] HMAC-MD5 key
 * @param des_iv       [in] Initialization vector (must be of 8 bytes in length).
 * @param pktptr       [in] Pointer to the IPSEC packet (i.e, points to ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It should
 * include the 
 * ESP header (8 bytes) + IV (8 bytes) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             DES_CBC_MD5_SUCCESS (0)
 *                     DES_CBC_MD5_FAILURE (-1)
*/


  int DES_ede3_cbc_md5_decrypt(uint8_t *des_key, uint16_t auth_keylen, 
   uint8_t *auth_key, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen,
   uint8_t *outptr, uint16_t *outlen,uint8_t compdigest);

/** 
 * AES-CBC-MD5 Encryption
 * This function creates an IPSEC outbound packet using AES-CBC & HMAC-MD5
 * keys provided
 * @param aes_key_len   [in] AES CBC encryption key length
 * @param aes_key      [in] AES CBC encryption key
 * @param auth_keylen  [in] HMAC-MD5 key length
 * @param auth_key     [in] HMAC-MD5 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet.
 * @param aes_iv           [in] Initialization vector (must be of AES_BLOCK_SIZE 
 * in length). It is placed after ESP header in the output packet
 * @param pktptr        [in] Pointer to the input payload (to be encrypted)
 * @param pktlen     [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of AES block size. 
 * This function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AES_CBC_MD5_SUCCESS (0)
 *                     AES_CBC_MD5_FAILURE (-1)
 **/

 int AES_cbc_md5_encrypt(uint16_t aes_key_len, uint8_t *aes_key,  
  uint16_t auth_keylen, uint8_t *auth_key, uint8_t *espheader, uint8_t *aes_iv,
  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);

/**
 * AES-CBC-MD5 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using 
 * the AES-CBC and HMAC-MD5 keys provided
 * @param aes_key_len   [in] AES CBC decryption key length
 * @param aes_key      [in] AES CBC decryption key
 * @param auth_keylen  [in] HMAC-MD5 key length
 * @param auth_key     [in] HMAC-MD5 key
 * @param aes_iv       [in] Initialization vector (must be of AES_BLOCK_SIZE 
 * in length).
 * @param  pktptr      [in] Pointer to the IPSEC packet (i.e, points to 
 * ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include the i
 * ESP header (8 bytes) + IV (AES_BLOCK_SIZE) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * packet.
 * @return             AES_CBC_MD5_SUCCESS (0)
 *                     AES_CBC_MD5_FAILURE (-1)
*/

 int AES_cbc_md5_decrypt(uint16_t aes_key_len, uint8_t *aes_key, 
  uint16_t auth_keylen, uint8_t *auth_key, uint8_t *aes_iv, uint8_t *pktptr, 
  uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest);

/** 
 * NULL-MD5 Encryption
 * This function creates an IPSEC outbound packet using  HMAC-MD5
 * keys provided
 * @param auth_keylen  [in] HMAC-MD5 key length
 * @param auth_key     [in] HMAC-MD5 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet.
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter.  
 * This function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             NULL_MD5_SUCCESS (0)
 *                     NULL_MD5_FAILURE (-1)
 **/
int NULL_md5_encrypt ( uint16_t auth_keylen, uint8_t *auth_key, uint8_t *espheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);

/**
 * NULL-MD5 Decryption
 * This function authenticates  an inbound IPSEC packet using 
 * the HMAC-MD5 keys provided
 * @param auth_keylen  [in] HMAC-MD5 key length
 * @param auth_key     [in] HMAC-MD5 key
 * in length).
 * @param  pktptr      [in] Pointer to the IPSEC packet (i.e, points to 
 * ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include the i
 * ESP header (8 bytes) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             NULL_MD5_SUCCESS (0)
 *                     NULL_MD5_FAILURE (-1)
*/

 int NULL_md5_decrypt (uint16_t auth_keylen, uint8_t *auth_key, uint8_t *pktptr,
   uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest);

/** 
 * NULL-SHA1 Encryption
 * This function creates an IPSEC outbound packet using  HMAC-SHA1
 * keys provided
 * @param sha1_keylen  [in] HMAC-SHA1 key length
 * @param sha1_key     [in] HMAC-SHA1 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet.
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter.  
 * This function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             NULL_SHA1_SUCCESS (0)
 *                     NULL_SHA1_FAILURE (-1)
 **/


  int NULL_sha1_encrypt ( uint16_t sha1_keylen, uint8_t *sha1_key, 
   uint8_t *espheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, 
   uint16_t *outlen);

/**
 * NULL-SHA1 Decryption
 * This function authenticates  an inbound IPSEC packet using 
 * the HMAC-SHA1 keys provided
 * @param sha1_keylen  [in] HMAC-SHA1 key length
 * @param sha1_key     [in] HMAC-SHA1 key
 * in length).
 * @param  pktptr      [in] Pointer to the IPSEC packet (i.e, points to 
 * ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include 
 * ESP header (8 bytes) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             NULL_SHA1_SUCCESS (0)
 *                     NULL_SHA1_FAILURE (-1)
*/

  int NULL_sha1_decrypt (uint16_t sha1_keylen, uint8_t *sha1_key, 
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, 
   uint8_t  compdigest);

/** 
 * NULL-SHA224 Encryption
 * This function creates an IPSEC outbound packet using  HMAC-SHA224
 * keys provided
 * @param sha2_keylen  [in] HMAC-SHA224 key length
 * @param sha2_key     [in] HMAC-SHA224 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet.
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter.  
 * This function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             NULL_SHA224_SUCCESS (0)
 *                     NULL_SHA224_FAILURE (-1)
 **/

  int NULL_sha224_encrypt ( uint16_t sha2_keylen, uint8_t *sha2_key, 
   uint8_t *espheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, 
   uint16_t *outlen);

/**
 * NULL-SHA224 Decryption
 * This function authenticates  an inbound IPSEC packet using 
 * the HMAC-SHA224 keys provided
 * @param sha2_keylen  [in] HMAC-SHA224 key length
 * @param sha2_key     [in] HMAC-SHA224 key
 * in length).
 * @param  pktptr      [in] Pointer to the IPSEC packet (i.e, points to 
 * ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include 
 * ESP header (8 bytes) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             NULL_SHA224_SUCCESS (0)
 *                     NULL_SHA224_FAILURE (-1)
*/

  int NULL_sha224_decrypt (uint16_t sha2_keylen, uint8_t *sha2_key, 
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, 
   uint8_t  compdigest);

/** 
 * NULL-SHA256 Encryption
 * This function creates an IPSEC outbound packet using  HMAC-SHA256
 * keys provided
 * @param sha2_keylen  [in] HMAC-SHA256 key length
 * @param sha2_key     [in] HMAC-SHA256 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet.
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter.  
 * This function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             NULL_SHA256_SUCCESS (0)
 *                     NULL_SHA256_FAILURE (-1)
 **/

  int NULL_sha256_encrypt ( uint16_t sha2_keylen, uint8_t *sha2_key, 
   uint8_t *espheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, 
   uint16_t *outlen);

/**
 * NULL-SHA256 Decryption
 * This function authenticates  an inbound IPSEC packet using 
 * the HMAC-SHA256 keys provided
 * @param sha2_keylen  [in] HMAC-SHA256 key length
 * @param sha2_key     [in] HMAC-SHA256 key
 * in length).
 * @param  pktptr      [in] Pointer to the IPSEC packet (i.e, points to 
 * ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include 
 * ESP header (8 bytes) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             NULL_SHA256_SUCCESS (0)
 *                     NULL_SHA256_FAILURE (-1)
*/

  int NULL_sha256_decrypt (uint16_t sha2_keylen, uint8_t *sha2_key, 
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, 
   uint8_t  compdigest);

/** 
 * NULL-SHA384 Encryption
 * This function creates an IPSEC outbound packet using  HMAC-SHA384
 * keys provided
 * @param sha2_keylen  [in] HMAC-SHA384 key length
 * @param sha2_key     [in] HMAC-SHA384 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet.
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter.  
 * This function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             NULL_SHA384_SUCCESS (0)
 *                     NULL_SHA384_FAILURE (-1)
 **/


  int NULL_sha384_encrypt ( uint16_t sha2_keylen, uint8_t *sha2_key, 
   uint8_t *espheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, 
   uint16_t *outlen);

/**
 * NULL-SHA384 Decryption
 * This function authenticates  an inbound IPSEC packet using 
 * the HMAC-SHA384 keys provided
 * @param sha2_keylen  [in] HMAC-SHA384 key length
 * @param sha2_key     [in] HMAC-SHA384 key
 * in length).
 * @param  pktptr      [in] Pointer to the IPSEC packet (i.e, points to 
 * ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include 
 * ESP header (8 bytes) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             NULL_SHA384_SUCCESS (0)
 *                     NULL_SHA384_FAILURE (-1)
*/

  int NULL_sha384_decrypt (uint16_t sha2_keylen, uint8_t *sha2_key, 
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, 
   uint8_t  compdigest);

/** 
 * NULL-SHA512 Encryption
 * This function creates an IPSEC outbound packet using  HMAC-SHA512
 * keys provided
 * @param sha2_keylen  [in] HMAC-SHA512 key length
 * @param sha2_key     [in] HMAC-SHA512 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet.
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter.  
 * This function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             NULL_SHA512_SUCCESS (0)
 *                     NULL_SHA512_FAILURE (-1)
 **/

  int NULL_sha512_encrypt ( uint16_t sha2_keylen, uint8_t *sha2_key, 
   uint8_t *espheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, 
   uint16_t *outlen);

/**
 * NULL-SHA512 Decryption
 * This function authenticates  an inbound IPSEC packet using 
 * the HMAC-SHA512 keys provided
 * @param sha2_keylen  [in] HMAC-SHA512 key length
 * @param sha2_key     [in] HMAC-SHA512 key
 * in length).
 * @param  pktptr      [in] Pointer to the IPSEC packet (i.e, points to 
 * ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include 
 * ESP header (8 bytes) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             NULL_SHA512_SUCCESS (0)
 *                     NULL_SHA512_FAILURE (-1)
*/

  int NULL_sha512_decrypt (uint16_t sha2_keylen, uint8_t *sha2_key, 
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, 
   uint8_t  compdigest);

/** 
 * AH-OUTBOUND-SHA1 
 * This function creates an IPSEC outbound packet using  HMAC-SHA1
 * keys provided
 * @param sha1_keylen  [in] HMAC-SHA1 key length
 * @param sha1_key     [in] HMAC-SHA1 key
 * @param ahheader     [in] Pointer to the AH header (must be of 12 bytes in 
 * length). It is placed after IPHEADER in the output packet.
 * @param pktptr       [in] Pointer to the input payload (to be authenticated)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter.   
 * This function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AH_SHA1_SUCCESS (0)
 *                     AH_SHA1_FAILURE (-1)
 **/


 int AH_outbound_sha1 ( uint16_t sha1_keylen, uint8_t *sha1_key,  
  uint8_t *ahheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, 
  uint16_t *outlen);

/**
 * AH-INBOUND-SHA1 
 * This function authenticates  an inbound IPSEC packet using 
 * the HMAC-SHA1 keys provided
 * @param sha1_keylen [in] HMAC-SHA1 key length
 * @param sha1_key    [in] HMAC-SHA1 key
 * in length).
 * @param  pktptr      [in] Pointer to the IPSEC packet (i.e, points to 
 * ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include 
 * IP_HEADER_LENGTH + AH_HEADER_LENGTH + PAYLOAD length 
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated.   
 * @return             AH_SHA1_SUCCESS (0)
 *                     AH_SHA1_FAILURE (-1)
*/

  int AH_inbound_sha1 ( uint16_t sha1_keylen, uint8_t *sha1_key,  
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen,
   int compdigest);

/** 
 * AH-OUTBOUND-SHA256 
 * This function creates an IPSEC outbound packet using  HMAC-SHA256
 * keys provided
 * @param sha256_keylen  [in] HMAC-SHA256 key length
 * @param sha256_key     [in] HMAC-SHA256 key
 * @param ahheader     [in] Pointer to the AH header (must be of 12 bytes in 
 * length). It is placed after IPHEADER in the output packet.
 * @param pktptr       [in] Pointer to the input payload (to be authenticated)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter.   
 * This function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AH_SHA256_SUCCESS (0)
 *                     AH_SHA256_FAILURE (-1)
 **/


 int AH_outbound_sha256 ( uint16_t sha256_keylen, uint8_t *sha256_key,  
  uint8_t *ahheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, 
  uint16_t *outlen);

/**
 * AH-INBOUND-SHA256 
 * This function authenticates  an inbound IPSEC packet using 
 * the HMAC-SHA keys provided
 * @param sha256_keylen [in] HMAC-SHA256 key length
 * @param sha256_key    [in] HMAC-SHA256 key
 * in length).
 * @param  pktptr      [in] Pointer to the IPSEC packet (i.e, points to 
 * ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include 
 * IP_HEADER_LENGTH + AH_HEADER_LENGTH + PAYLOAD length 
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated.   
 * @return             AH_SHA256_SUCCESS (0)
 *                     AH_SHA256_FAILURE (-1)
*/

  int AH_inbound_sha256 ( uint16_t sha256_keylen, uint8_t *sha256_key,
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen,
   int compdigest);


/** 
 * AH-OUTBOUND-SHA384 
 * This function creates an IPSEC outbound packet using  HMAC-SHA384
 * keys provided
 * @param sha384_keylen  [in] HMAC-SHA384 key length
 * @param sha384_key     [in] HMAC-SHA384 key
 * @param ahheader     [in] Pointer to the AH header (must be of 12 bytes in 
 * length). It is placed after IPHEADER in the output packet.
 * @param pktptr       [in] Pointer to the input payload (to be authenticated)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter.   
 * This function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AH_SHA384_SUCCESS (0)
 *                     AH_SHA384_FAILURE (-1)
 **/

 int AH_outbound_sha384 ( uint16_t sha384_keylen, uint8_t *sha384_key,  
  uint8_t *ahheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, 
  uint16_t *outlen);

/**
 * AH-INBOUND-SHA384 
 * This function authenticates  an inbound IPSEC packet using 
 * the HMAC-SHA keys provided
 * @param sha384_keylen [in] HMAC-SHA384 key length
 * @param sha384_key    [in] HMAC-SHA384 key
 * in length).
 * @param  pktptr      [in] Pointer to the IPSEC packet (i.e, points to 
 * ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include 
 * IP_HEADER_LENGTH + AH_HEADER_LENGTH + PAYLOAD length 
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated.   
 * @return             AH_SHA384_SUCCESS (0)
 *                     AH_SHA384_FAILURE (-1)
*/


  int AH_inbound_sha384 ( uint16_t sha384_keylen, uint8_t *sha384_key,  
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen,
   int compdigest);

/** 
 * AH-OUTBOUND-SHA512 
 * This function creates an IPSEC outbound packet using  HMAC-SHA512
 * keys provided
 * @param sha512_keylen  [in] HMAC-SHA512 key length
 * @param sha512_key     [in] HMAC-SHA512 key
 * @param ahheader     [in] Pointer to the AH header (must be of 12 bytes in 
 * length). It is placed after IPHEADER in the output packet.
 * @param pktptr       [in] Pointer to the input payload (to be authenticated)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter.   
 * This function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AH_SHA512_SUCCESS (0)
 *                     AH_SHA512_FAILURE (-1)
 **/
 
 int AH_outbound_sha512 ( uint16_t sha512_keylen, uint8_t *sha512_key,  
  uint8_t *ahheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, 
  uint16_t *outlen);

/**
 * AH-INBOUND-SHA512 
 * This function authenticates  an inbound IPSEC packet using 
 * the HMAC-SHA keys provided
 * @param sha512_keylen [in] HMAC-SHA512 key length
 * @param sha512_key    [in] HMAC-SHA512 key
 * in length).
 * @param  pktptr      [in] Pointer to the IPSEC packet (i.e, points to 
 * ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include 
 * IP_HEADER_LENGTH + AH_HEADER_LENGTH + PAYLOAD length 
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated.   
 * @return             AH_SHA512_SUCCESS (0)
 *                     AH_SHA512_FAILURE (-1)
*/

  int AH_inbound_sha512 ( uint16_t sha512_keylen, uint8_t *sha512_key,  
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen,
   int compdigest);



/** 
 * AH-OUTBOUND-MD5 
 * This function creates an IPSEC outbound packet using  HMAC-MD5
 * keys provided
 * @param auth_keylen  [in] HMAC-MD5 key length
 * @param auth_key     [in] HMAC-MD5 key
 * @param ahheader     [in] Pointer to the AH header (must be of 12 bytes in 
 * length). It is placed after IPHEADER in the output packet.
 * @param pktptr       [in] Pointer to the input payload (to be authenticated)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter.   
 * This function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AH_MD5_SUCCESS (0)
 *                     AH_MD5_FAILURE (-1)
*/

 int AH_outbound_md5 ( uint16_t auth_keylen, uint8_t *auth_key,  
  uint8_t *ahheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, 
  uint16_t *outlen);

/**
 * AH-INBOUND-MD5 
 * This function authenticates  an inbound IPSEC packet using 
 * the HMAC-MD5 keys provided
 * @param auth_keylen  [in] HMAC-MD5 key length
 * @param auth_key     [in] HMAC-MD5 key
 * in length).
 * @param  pktptr      [in] Pointer to the IPSEC packet (i.e, points to 
 * ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include 
 * IP_HEADER_LENGTH + AH_HEADER_LENGTH + PAYLOAD length 
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated.   
 * @return             AH_MD5_SUCCESS (0)
 *                     AH_MD5_FAILURE (-1)
*/

  int AH_inbound_md5 ( uint16_t auth_keylen, uint8_t *auth_key,  
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen,
   int compdigest);



/** 
 * AES-CTR-MD5 Encryption
 * This function creates an IPSEC outbound packet using AES-CNTR & HMAC-MD5 
 * keys provided
 * @param aes_key     [in] AES-CNTR encryption key
 * @param aes_key_len  [in] AES-CNTR key length
 * @param nonce       [in] value of nonce (Refer RFC 3686)
 * @param hash_keylen [in] HMAC-MD5 key length
 * @param hash_key    [in] HMAC-MD5 key
 * @param espheader   [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet
 * @param aes_iv      [in] Initialization vector(must be of 8 bytes in length).
 *                     It is placed after ESP header in the output packet
 * @param pktptr      [in] Pointer to the input payload (to be encrypted)
 * @param pktlen      [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of AES block size. This 
 * function doesn't pad anything at the end of the input
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AES_CTR_SHA_SUCCESS (0)
 *                     AES_CTR_SHA_FAILURE(-1)
*/

   int AES_ctr_md5_encrypt(uint64_t *aes_key, uint32_t aes_key_len, 
   uint32_t nonce, uint16_t hash_keylen, uint8_t *hash_key, uint8_t *espheader,
   uint8_t *aes_iv,  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, 
   uint16_t *outlen);

/** 
 * AES-CNTR-MD5 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the 
 * AES-CNTR  and HMAC-MD5 keys provided
 * @param aes_key     [in] AES-CNTR encryption key
 * @param aes_key_len  [in] AES-CNTR key length
 * @param nonce       [in] value of nonce (Refer RFC 3686)
 * @param hash_keylen [in] HMAC-MD5 key length
 * @param hash_key    [in] HMAC-MD5 key
 * @param aes_iv      [in] Initialization vector (must be of 8 bytes in length).
 * @param pktptr      [in] Pointer to the IPSEC packet (i.e, points to ESP header)
 * @param pktlen      [in] Length of IPSEC packet pointed to by input. It should 
 * include the 
 * ESP header (8 bytes) + IV (AES_BLOCK_SIZE) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr      [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             AES_CTR_SHA_SUCCESS (0)
 *                     AES_CTR_SHA_FAILURE (-1)
*/

  int AES_ctr_md5_decrypt(uint64_t *aes_key, uint32_t aes_key_len, 
  uint32_t nonce, uint16_t hash_keylen, uint8_t *hash_key, uint8_t *aes_iv,  
  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, 
  uint8_t  compdigest);

/** 
 * AES-CTR-SHA1 Encryption
 * This function creates an IPSEC outbound packet using AES-CNTR & HMAC-SHA1 
 * keys provided
 * @param aes_key     [in] AES-CNTR encryption key
 * @param aes_key_len  [in] AES-CNTR key length
 * @param nonce       [in] value of nonce (Refer RFC 3686)
 * @param sha1_keylen [in] HMAC-SHA1 key length
 * @param sha1_key    [in] HMAC-SHA1 key
 * @param espheader   [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet
 * @param aes_iv      [in] Initialization vector(must be of 8 bytes in length).
 *                     It is placed after ESP header in the output packet
 * @param pktptr      [in] Pointer to the input payload (to be encrypted)
 * @param pktlen      [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of AES block size. This 
 * function doesn't pad anything at the end of the input
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AES_CTR_SHA_SUCCESS (0)
 *                     AES_CTR_SHA_FAILURE(-1)
*/

   int AES_ctr_sha1_encrypt(uint64_t *aes_key, uint32_t aes_key_len, 
   uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader,
   uint8_t *aes_iv,  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, 
   uint16_t *outlen);

/** 
 * AES-CNTR-SHA1 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the 
 * AES-CNTR  and HMAC-SHA512 keys provided
 * @param aes_key     [in] AES-CNTR encryption key
 * @param aes_key_len  [in] AES-CNTR key length
 * @param nonce       [in] value of nonce (Refer RFC 3686)
 * @param sha1_keylen [in] HMAC-SHA1 key length
 * @param sha1_key    [in] HMAC-SHA1 key
 * @param aes_iv      [in] Initialization vector (must be of 8 bytes in length).
 * @param pktptr      [in] Pointer to the IPSEC packet (i.e, points to ESP header)
 * @param pktlen      [in] Length of IPSEC packet pointed to by input. It should 
 * include the 
 * ESP header (8 bytes) + IV (AES_BLOCK_SIZE) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr      [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             AES_CTR_SHA_SUCCESS (0)
 *                     AES_CTR_SHA_FAILURE (-1)
*/

  int AES_ctr_sha1_decrypt(uint64_t *aes_key, uint32_t aes_key_len, 
  uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv,  
  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, 
  uint8_t  compdigest);


/** 
 * 3DES-CBC-SHA256 Encryption
 * This function creates an IPSEC outbound packet using 3DES-CBC & HMAC-SHA256
 * keys provided
 * @param des_key      [in] 3DES encryption key (must be of 24 bytes in length)
 * @param sha1_keylen  [in] HMAC-SHA256 key length
 * @param sha1_key     [in] HMAC-SHA256 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in
 * length). It is placed at the start of the output packet
 * @param des_iv       [in] Initialization vector(must be of 8 bytes in length).
 *                     It is placed after ESP header in the output packet
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of DES block size. 
 * This function doesn't pad anything at the end of the input
 * @param outptr       [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             DES_CBC_SHA_SUCCESS (0)
 *                     DES_CBC_SHA_FAILURE (-1)
*/

  int DES_ede3_cbc_sha256_encrypt(uint8_t *des_key, uint16_t sha1_keylen, 
   uint8_t *sha1_key, uint8_t *espheader, uint8_t *des_iv, uint8_t *pktptr, 
   uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);


/** 
 * 3DES-CBC-SHA256 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the
 * 3DES-CBC and HMAC-SHA256 keys provided
 * @param des_key      [in] 3DES decryption key (must be of 24 bytes in length)
 * @param sha1_keylen  [in] HMAC-SHA256 key length
 * @param sha1_key     [in] HMAC-SHA256 key
 * @param des_iv       [in] Initialization vector (must be of 8 bytes in length).
 * @param pktptr       [in] Pointer to the IPSEC packet (i.e, points to ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It should
 * include the 
 * ESP header (8 bytes) + IV (8 bytes) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             DES_CBC_SHA_SUCCESS (0)
 *                     DES_CBC_SHA_FAILURE (-1)
*/


  int DES_ede3_cbc_sha256_decrypt(uint8_t *des_key, uint16_t sha1_keylen, 
   uint8_t *sha1_key, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen,
   uint8_t *outptr, uint16_t *outlen,uint8_t compdigest);

/** 
 * AES-CBC-SHA256 Encryption
 * This function creates an IPSEC outbound packet using AES-CBC & HMAC-SHA256 
 * keys provided
 * @param aes_key_len   [in] AES CBC encryption key length
 * @param aes_key      [in] AES CBC encryption key
 * @param sha1_keylen  [in] HMAC-SHA256 key length
 * @param sha1_key     [in] HMAC-SHA256 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes 
 * in length). It is placed at the start of the output packet
 * @param aes_iv       [in] Initialization vector (must be of AES_BLOCK_SIZE 
 * in length). It is placed after ESP header in the output packet
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of AES block size. 
 * This function doesn't pad anything at the end of the input.
 * @param outptr       [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AES_CBC_SHA_SUCCESS (0)
 *                     AES_CBC_SHA_FAILURE (-1)
*/

   int AES_cbc_sha256_encrypt(uint16_t aes_key_len, uint8_t *aes_key,  
   uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *aes_iv,
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);

/**
 * AES-CBC-SHA256 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the 
 * AES-CBC and HMAC-SHA256 keys provided
 * @param aes_key_len   [in] AES CBC decryption key length
 * @param aes_key      [in] AES CBC decryption key
 * @param sha1_keylen  [in] HMAC-SHA256 key length
 * @param sha1_key     [in] HMAC-SHA256 key
 * @param aes_iv       [in] Initialization vector (must be of AES_BLOCK_SIZE 
 * in length).
 * @param pktptr       [in] Pointer to the IPSEC packet (i.e, points to ESP 
 * header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. 
 * It should include the 
 * ESP header (8 bytes) + IV (AES_BLOCK_SIZE) + PAYLOAD length+ HMAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated  packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             AES_CBC_SHA_SUCCESS (0)
 *                     AES_CBC_SHA_FAILURE (-1)
*/

   int AES_cbc_sha256_decrypt(uint16_t aes_key_len, uint8_t *aes_key, 
   uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv, uint8_t *pktptr, 
   uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest);

/** 
 * AES-CNTR-SHA256 Encryption
 * This function creates an IPSEC outbound packet using AES-CNTR & HMAC-SHA256
 * keys provided
 * @param aes_key     [in] AES-CNTR encryption key
 * @param aes_key_len  [in] AES-CNTR key length
 * @param nonce       [in] value of nonce (Refer RFC 3686)
 * @param sha1_keylen [in] HMAC-SHA256 key length
 * @param sha1_key    [in] HMAC-SHA256 key
 * @param espheader   [in] Pointer to the ESP header (must be of 8 bytes in
 * length). It is placed at the start of the output packet
 * @param aes_iv      [in] Initialization vector(must be of 8 bytes in length).
 *                     It is placed after ESP header in the output packet
 * @param pktptr      [in] Pointer to the input payload (to be encrypted)
 * @param pktlen      [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of AES block size. This
 * function doesn't pad anything at the end of the input
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AES_CTR_SHA_SUCCESS (0)
 *                     AES_CTR_SHA_FAILURE (-1)
*/

  int AES_ctr_sha256_encrypt(uint64_t *aes_key, uint32_t aes_key_len,
  uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, 
  uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, 
  uint16_t *outlen);

/** 
 * AES-CNTR-SHA256 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the
 * AES-CNTR and HMAC-SHA512 keys provided
 * @param aes_key     [in] AES-CNTR encryption key
 * @param aes_key_len [in] AES-CNTR key length
 * @param nonce       [in] value of nonce (Refer RFC 3686)
 * @param sha1_keylen [in] HMAC-SHA256 key length
 * @param sha1_key    [in] HMAC-SHA256 key
 * @param aes_iv      [in] Initialization vector (must be of 8 bytes in length).
 * @param pktptr      [in] Pointer to the IPSEC packet (i.e, points to ESP header)
 * @param pktlen      [in] Length of IPSEC packet pointed to by input. It should
 * include the 
 * ESP header (8 bytes) + IV (AES_BLOCK_SIZE) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr      [out] Pointer to the output buffer where decrypted and
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             AES_CTR_SHA_SUCCESS (0)
 *                     AES_CTR_SHA_FAILURE (-1)
*/

  int AES_ctr_sha256_decrypt(uint64_t *aes_key, uint32_t aes_key_len,
  uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv, 
  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, 
  uint8_t  compdigest);


/** 
 * 3DES-CBC-SHA512 Encryption
 * This function creates an IPSEC outbound packet using 3DES-CBC & HMAC-SHA512
 * keys provided
 * @param des_key      [in] 3DES encryption key (must be of 24 bytes in length)
 * @param sha1_keylen  [in] HMAC-SHA512 key length
 * @param sha1_key     [in] HMAC-SHA512 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in
 * length). It is placed at the start of the output packet
 * @param des_iv       [in] Initialization vector(must be of 8 bytes in length).
 *                     It is placed after ESP header in the output packet
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of DES block size. This
 * function doesn't pad anything at the end of the input
 * @param outptr       [out] Pointer to the output buffer where encrypted and
 * authenticated packet should be placed 
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             DES_CBC_SHA_SUCCESS (0)
 *                     DES_CBC_SHA_FAILURE (-1)
*/

  int DES_ede3_cbc_sha512_encrypt(uint8_t *des_key, uint16_t sha1_keylen, 
   uint8_t *sha1_key, uint8_t *espheader, uint8_t *des_iv, uint8_t *pktptr, 
   uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);

/** 
 * 3DES-CBC-SHA512 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the
 * 3DES-CBC and HMAC-SHA512 keys provided
 * @param des_key      [in] 3DES decryption key (must be of 24 bytes in length)
 * @param sha1_keylen  [in] HMAC-SHA512 key length
 * @param sha1_key     [in] HMAC-SHA512 key
 * @param des_iv       [in] Initialization vector (must be of 8 bytes in length).
 * @param pktptr       [in] Pointer to the IPSEC packet (i.e, points to ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. 
 * It should include the
 * ESP header (8 bytes) + IV (8 bytes) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             DES_CBC_SHA_SUCCESS (0)
 *                     DES_CBC_SHA_FAILURE (-1)
*/

  int DES_ede3_cbc_sha512_decrypt(uint8_t *des_key, uint16_t sha1_keylen, 
   uint8_t *sha1_key, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen,
   uint8_t *outptr, uint16_t *outlen,uint8_t compdigest);

/** 
 * AES-CBC-SHA512 Encryption
 * This function creates an IPSEC outbound packet using AES-CBC & HMAC-SHA512 
 * keys provided
 * @param aes_key_len  [in] AES CBC encryption key length
 * @param aes_key      [in] AES CBC encryption key
 * @param sha1_keylen  [in] HMAC-SHA512 key length
 * @param sha1_key     [in] HMAC-SHA512 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet
 * @param aes_iv       [in] Initialization vector (must be of AES_BLOCK_SIZE 
 * in length).It is placed after ESP header in the output packet
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of AES block size. 
 * This function doesn't pad anything at the end of the input.
 * @param outptr       [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AES_CBC_SHA_SUCCESS (0)
 *                     AES_CBC_SHA_FAILURE (-1)
 **/

   int AES_cbc_sha512_encrypt(uint16_t aes_key_len, uint8_t *aes_key,  
   uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *aes_iv,
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);

/**
 * AES-CBC-SHA512 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the 
 * AES-CBC and HMAC-SHA512 keys provided
 * @param aes_key_len  [in] AES CBC decryption key length
 * @param aes_key      [in] AES CBC decryption key
 * @param sha1_keylen  [in] HMAC-SHA512 key length
 * @param sha1_key     [in] HMAC-SHA512 key
 * @param aes_iv       [in] Initialization vector (must be of AES_BLOCK_SIZE 
 * in length).
 * @param pktptr       [in] Pointer to the IPSEC packet (i.e, points to ESP 
 * header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include the 
 * ESP header (8 bytes) + IV (AES_BLOCK_SIZE) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where decrypted and i
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             AES_CBC_SHA_SUCCESS (0)
 *                     AES_CBC_SHA_FAILURE (-1)
*/

  int AES_cbc_sha512_decrypt(uint16_t aes_key_len, uint8_t *aes_key, 
  uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv, uint8_t *pktptr, 
  uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest);


/** 
 * AES-CNTR-SHA512 Encryption
 * This function creates an IPSEC outbound packet using AES-CNTR & HMAC-SHA512 
 * keys provided
 * @param aes_key     [in] AES-CNTR encryption key
 * @param aes_key_len [in] AES-CNTR key length
 * @param nonce       [in] value of nonce (Refer RFC 3686)
 * @param sha1_keylen [in] HMAC-SHA512 key length
 * @param sha1_key    [in] HMAC-SHA512 key
 * @param espheader   [in] Pointer to the ESP header (must be of 8 bytes in
 * length). It is placed at the start of the output packet
 * @param aes_iv      [in] Initialization vector(must be of 8 bytes in length).
 *                     It is placed after ESP header in the output packet
 * @param pktptr      [in] Pointer to the input payload (to be encrypted)
 * @param pktlen      [in] Length of input data (in bytes) pointed to by i
 * input parameter. The inputlen should be a multiple of AES block size. This
 * function doesn't pad anything at the end of the input
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AES_CTR_SHA_SUCCESS (0)
 *                     AES_CTR_SHA_FAILURE (-1)
*/

  int AES_ctr_sha512_encrypt(uint64_t *aes_key, uint32_t aes_key_len, 
   uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader,
   uint8_t *aes_iv,  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, 
   uint16_t *outlen);

/** 
 * AES-CNTR-SHA512 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the
 * AES-CNTR and HMAC-SHA512 keys provided
 * @param aes_key     [in] AES-CNTR encryption key
 * @param aes_key_len [in] AES-CNTR key length
 * @param nonce       [in] value of nonce (Refer RFC 3686)
 * @param sha1_keylen [in] HMAC-SHA512 key length
 * @param sha1_key    [in] HMAC-SHA512 key
 * @param aes_iv      [in] Initialization vector (must be of 8 bytes in length).
 * @param pktptr      [in] Pointer to the IPSEC packet (i.e, points to ESP header)
 * @param pktlen      [in] Length of IPSEC packet pointed to by input. It should
 * include the 
 * ESP header (8 bytes) + IV (AES_BLOCK_SIZE) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr      [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             AES_CTR_SHA_SUCCESS (0)
 *                     AES_CTR_SHA_FAILURE (-1)
*/

  int AES_ctr_sha512_decrypt(uint64_t *aes_key, uint32_t aes_key_len,
   uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv,  
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, 
   uint8_t  compdigest);

/** 
 * 3DES-CBC-SHA224 Encryption
 * This function creates an IPSEC outbound packet using 3DES-CBC & HMAC-SHA224
 * keys provided
 * @param des_key      [in] 3DES encryption key (must be of 24 bytes in length)
 * @param sha1_keylen  [in] HMAC-SHA224 key length
 * @param sha1_key     [in] HMAC-SHA224 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet
 * @param des_iv       [in] Initialization vector(must be of 8 bytes in length).
 *                     It is placed after ESP header in the output packet
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of DES block size. This
 * function doesn't pad anything at the end of the input
 * @param outptr       [out] Pointer to the output buffer where encrypted and
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             DES_CBC_SHA_SUCCESS (0)
 *                     DES_CBC_SHA_FAILURE (-1)
*/

   int DES_ede3_cbc_sha224_encrypt(uint8_t *des_key, uint16_t sha1_keylen, 
    uint8_t *sha1_key, uint8_t *espheader, uint8_t *des_iv, uint8_t *pktptr, 
    uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);

/** 
 * 3DES-CBC-SHA224 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the
 * 3DES-CBC and HMAC-SHA224 keys provided
 * @param des_key       [in] 3DES decryption key (must be of 24 bytes in length)
 * @param sha1_keylen   [in] HMAC-SHA224 key length
 * @param sha1_key      [in] HMAC-SHA224 key
 * @param des_iv        [in] Initialization vector (must be of 8 bytes in length).
 * @param pktptr        [in] Pointer to the IPSEC packet (i.e, points to ESP header)
 * @param pktlen        [in] Length of IPSEC packet pointed to by input. It should 
 * include the 
 * ESP header (8 bytes) + IV (8 bytes) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr        [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             DES_CBC_SHA_SUCCESS (0)
 *                     DES_CBC_SHA_FAILURE (-1)
*/

  int DES_ede3_cbc_sha224_decrypt(uint8_t *des_key, uint16_t sha1_keylen, 
   uint8_t *sha1_key, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen,
   uint8_t *outptr, uint16_t *outlen,uint8_t compdigest);

/** 
 * AES-CBC-SHA224 Encryption
 * This function creates an IPSEC outbound packet using AES-CBC & HMAC-SHA224 
 * keys provided
 * @param aes_key_len  [in] AES CBC encryption key length
 * @param aes_key      [in] AES CBC encryption key
 * @param sha1_keylen  [in] HMAC-SHA224 key length
 * @param sha1_key     [in] HMAC-SHA224 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet
 * @param aes_iv       [in] Initialization vector (must be of AES_BLOCK_SIZE
 * in length). It is placed after ESP header in the output packet
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of AES block size. 
 * This function doesn't pad anything at the end of the input.
 * @param outptr       [out] Pointer to the output buffer where encrypted 
 * and authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AES_CBC_SHA_SUCCESS (0)
 *                     AES_CBC_SHA_FAILURE (-1)
*/

  int AES_cbc_sha224_encrypt(uint16_t aes_key_len, uint8_t *aes_key,  
  uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *aes_iv,
  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);

/**
 * AES-CBC-SHA224 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the 
 * AES-CBC and HMAC-SHA224 keys provided
 * @param aes_key_len  [in] AES CBC decryption key length
 * @param aes_key      [in] AES CBC decryption key
 * @param sha1_keylen  [in] HMAC-SHA224 key length
 * @param sha1_key     [in] HMAC-SHA224 key
 * @param aes_iv       [in] Initialization vector (must be of AES_BLOCK_SIZE 
 * in length).
 * @param pktptr       [in] Pointer to the IPSEC packet (i.e, points to ESP 
 * header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include the 
 * ESP header (8 bytes) + IV (AES_BLOCK_SIZE) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             AES_CBC_SHA_SUCCESS (0)
 *                     AES_CBC_SHA_FAILURE(-1)
*/

  int AES_cbc_sha224_decrypt(uint16_t aes_key_len, uint8_t *aes_key, 
  uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv, uint8_t *pktptr, 
  uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest);


/** 
 * AES-CNTR-SHA224 Encryption
 * This function creates an IPSEC outbound packet using AES-CNTR & HMAC-SHA224 
 * keys provided
 * @param aes_key     [in] AES-CNTR encryption key
 * @param aes_key_len [in] AES-CNTR key length
 * @param nonce       [in] value of nonce (Refer RFC 3686)
 * @param sha1_keylen [in] HMAC-SHA224 key length
 * @param sha1_key    [in] HMAC-SHA224 key
 * @param espheader   [in] Pointer to the ESP header (must be of 8 bytes in
 * length). It is placed at the start of the output packet
 * @param aes_iv      [in] Initialization vector(must be of 8 bytes in length).
 *                     It is placed after ESP header in the output packet
 * @param pktptr      [in] Pointer to the input payload (to be encrypted)
 * @param pktlen      [in] Length of input data (in bytes) pointed to by
 * input parameter. The inputlen should be a multiple of AES block size. This 
 * function doesn't pad anything at the end of the input
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AES_CTR_SHA_SUCCESS (0)
 *                     AES_CTR_SHA_FAILURE (-1)
*/

  int AES_ctr_sha224_encrypt(uint64_t *aes_key, uint32_t aes_key_len,
  uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, 
  uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, 
  uint16_t *outlen);

/** 
 * AES-CNTR-SHA224 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the
 * AES-CNTR and HMAC-SHA512 keys provided
 * @param aes_key     [in] AES-CNTR encryption key
 * @param aes_key_len  [in] AES-CNTR key length
 * @param nonce       [in] value of nonce (Refer RFC 3686)
 * @param sha1_keylen [in] HMAC-SHA224 key length
 * @param sha1_key    [in] HMAC-SHA224 key
 * @param aes_iv      [in] Initialization vector (must be of 8 bytes in length).
 * @param pktptr      [in] Pointer to the IPSEC packet (i.e, points to ESP header)
 * @param pktlen      [in] Length of IPSEC packet pointed to by input. It should 
 * include the 
 * ESP header (8 bytes) + IV (AES_BLOCK_SIZE) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr      [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             AES_CTR_SHA_SUCCESS (0)
 *                     AES_CTR_SHA_FAILURE (-1)
*/

    int AES_ctr_sha224_decrypt(uint64_t *aes_key, uint32_t aes_key_len,
    uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv, 
    uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, 
    uint8_t  compdigest);


/** 
 * 3DES-CBC-SHA384 Encryption
 * This function creates an IPSEC outbound packet using 3DES-CBC & HMAC-SHA384
 * keys provided
 * @param des_key      [in] 3DES encryption key (must be of 24 bytes in length)
 * @param sha1_keylen  [in] HMAC-SHA384 key length
 * @param sha1_key     [in] HMAC-SHA384 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet
 * @param des_iv       [in] Initialization vector(must be of 8 bytes in length).
 *                     It is placed after ESP header in the output packet
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by
 * input parameter. The inputlen should be a multiple of DES block size.
 * This function doesn't pad anything at the end of the input
 * @param outptr       [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             DES_CBC_SHA_SUCCESS (0)
 *                     TDES_CBC_SHA_FAILURE (-1)
*/

  int DES_ede3_cbc_sha384_encrypt(uint8_t *des_key, uint16_t sha1_keylen, 
   uint8_t *sha1_key, uint8_t *espheader, uint8_t *des_iv, uint8_t *pktptr, 
   uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);


/** 
 * 3DES-CBC-SHA384 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the
 * 3DES-CBC and HMAC-SHA384 keys provided
 * @param des_key      [in] 3DES decryption key (must be of 24 bytes in length)
 * @param sha1_keylen  [in] HMAC-SHA384 key length
 * @param sha1_key     [in] HMAC-SHA384 key
 * @param des_iv       [in] Initialization vector (must be of 8 bytes in length)
 * @param pktptr       [in] Pointer to the IPSEC packet (i.e, points to ESP 
 * header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. 
 * It should include the 
 * ESP header (8 bytes) + IV (8 bytes) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr      [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             DES_CBC_SHA_SUCCESS (0)
 *                     DES_CBC_SHA_FAILURE (-1)
 **/

  int DES_ede3_cbc_sha384_decrypt(uint8_t *des_key, uint16_t sha1_keylen, 
   uint8_t *sha1_key, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen,
   uint8_t *outptr, uint16_t *outlen,uint8_t compdigest);


/** 
 * AES-CBC-SHA384 Encryption
 * This function creates an IPSEC outbound packet using AES-CBC & HMAC-SHA384
 * keys provided
 * @param aes_key_len  [in] AES CBC encryption key length
 * @param aes_key      [in] AES CBC encryption key
 * @param sha1_keylen  [in] HMAC-SHA384 key length
 * @param sha1_key     [in] HMAC-SHA384 key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet
 * @param aes_iv       [in] Initialization vector (must be of AES_BLOCK_SIZE 
 * in length). It is placed after ESP header in the output packet
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of AES block size. This 
 * function doesn't pad anything at the end of the input.
 * @param outptr       [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AES_CBC_SHA_SUCCESS (0)
 *                     AES_CBC_SHA_FAILURE (-1)
*/

  int AES_cbc_sha384_encrypt(uint16_t aes_key_len, uint8_t *aes_key,  
  uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *aes_iv,
  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);


/**
 * AES-CBC-SHA384 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the 
 * AES-CBC and HMAC-SHA384 keys provided
 * @param aes_key_len  [in] AES CBC decryption key length
 * @param aes_key      [in] AES CBC decryption key
 * @param sha1_keylen  [in] HMAC-SHA384 key length
 * @param sha1_key     [in] HMAC-SHA384 key
 * @param aes_iv       [in] Initialization vector (must be of AES_BLOCK_SIZE 
 * in length).
 * @param pktptr       [in] Pointer to the IPSEC packet (i.e, points to ESP 
 * header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include the 
 * ESP header (8 bytes) + IV (AES_BLOCK_SIZE) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             AES_CBC_SHA_SUCCESS (0)
 *                     AES_CBC_SHA_FAILURE (-1)
*/

  int AES_cbc_sha384_decrypt(uint16_t aes_key_len, uint8_t *aes_key, 
  uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv, uint8_t *pktptr, 
  uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest);

/** 
 * AES-CNTR-SHA384 Encryption
 * This function creates an IPSEC outbound packet using AES-CNTR & HMAC-SHA384
 * keys provided
 * @param aes_key     [in] AES-CNTR encryption key
 * @param aes_key_len [in] AES-CNTR key length
 * @param nonce       [in] value of nonce (Refer RFC 3686)
 * @param sha1_keylen [in] HMAC-SHA384 key length
 * @param sha1_key    [in] HMAC-SHA384 key
 * @param espheader   [in] Pointer to the ESP header (must be of 8 bytes in
 * length). It is placed at the start of the output packet
 * @param aes_iv      [in] Initialization vector(must be of 8 bytes in length).
 *                     It is placed after ESP header in the output packet
 * @param pktptr      [in] Pointer to the input payload (to be encrypted)
 * @param pktlen      [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of AES block size. 
 * This function doesn't pad anything at the end of the input
 * @param outptr      [out] Pointer to the output buffer where encrypted and
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             AES_CTR_SHA_SUCCESS (0)
 *                     AES_CTR_SHA_FAILURE (-1)
*/

  int AES_ctr_sha384_encrypt( uint64_t *aes_key, uint32_t aes_key_len, 
   uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader,
   uint8_t *aes_iv,  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, 
   uint16_t *outlen);

/** 
 * AES-CNTR-SHA384 Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the
 * AES-CNTR and HMAC-SHA512 keys provided
 * @param aes_key     [in] AES-CNTR encryption key
 * @param aes_key_len [in] AES-CNTR key length
 * @param nonce       [in] value of nonce (Refer RFC 3686)
 * @param sha1_keylen [in] HMAC-SHA384 key length
 * @param sha1_key    [in] HMAC-SHA384 key
 * @param aes_iv      [in] Initialization vector (must be of 8 bytes in length).
 * @param pktptr      [in] Pointer to the IPSEC packet (i.e, points to ESP header)
 * @param pktlen      [in] Length of IPSEC packet pointed to by input. It should
 * include the 
 * ESP header (8 bytes) + IV (AES_BLOCK_SIZE) + PAYLOAD length + HMAC (12 bytes)
 * @param outptr      [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated.  
 * HMAC is placed at the end of the output packet 
 * @return             AES_CTR_SHA_SUCCESS (0)
 *                     AES_CTR_SHA_FAILURE (-1)
*/

  int AES_ctr_sha384_decrypt(uint64_t *aes_key, uint32_t aes_key_len, 
   uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv,  
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, 
   uint8_t  compdigest);

/** 
 * AES-CBC-AES_XCBC Encryption
 * This function creates an IPSEC outbound packet using AES-CBC & AES-XCBC
 * keys provided
 * @param aes_key_len   [in] AES CBC encryption key length
 * @param aes_key      [in] AES CBC encryption key
 * @param auth_keylen  [in] AES-XCBC authentication key length
 * @param auth_key     [in] AES-XCBC authentication key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet.
 * @param aes_iv           [in] Initialization vector (must be of AES_BLOCK_SIZE 
 * in length). It is placed after ESP header in the output packet
 * @param pktptr        [in] Pointer to the input payload (to be encrypted)
 * @param pktlen     [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of AES block size. 
 * This function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed.
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             (0) on SUCCESS
 *                     (-1) on FAILURE 
 **/

  int AES_cbc_aes_xcbc_encrypt(uint16_t aes_key_len, uint8_t *aes_key,  
   uint16_t auth_keylen, uint8_t *auth_key, uint8_t *espheader, uint8_t *aes_iv,
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);

/**
 * AES-CBC-AES-XCBC Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using 
 * the AES-CBC and AES-XCBC keys provided
 * @param aes_key_len   [in] AES CBC decryption key length
 * @param aes_key      [in] AES CBC decryption key
 * @param auth_keylen  [in] AES XCBC authentication key length
 * @param auth_key     [in] AES XCBC authentication key
 * @param aes_iv       [in] Initialization vector (must be of AES_BLOCK_SIZE 
 * in length).
 * @param  pktptr      [in] Pointer to the IPSEC packet (i.e, points to 
 * ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include the 
 * ESP header (8 bytes) + IV (AES_BLOCK_SIZE) + PAYLOAD length + AES XCBC MAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed.
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated  
 * and AES-XCBC MAC is placed at the end of the output packet.
 * packet.
 * @return             (0) on SUCCESS
 *                     (-1) on FAILURE 
*/

  int AES_cbc_aes_xcbc_decrypt(uint16_t aes_key_len, uint8_t *aes_key, 
   uint16_t auth_keylen, uint8_t *auth_key, uint8_t *aes_iv, uint8_t *pktptr, 
   uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest);

/** 
 * NULL-AES-XCBC Encryption
 * This function creates an IPSEC outbound packet using AES-XCBC 
 * keys provided
 * @param auth_keylen  [in] AES-XCBC key length
 * @param auth_key     [in] AES-XCBC key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet.
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter.  
 * This function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where 
 * authenticated packet should be placed.
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             (0) on SUCCESS
 *                     (-1) on FAILURE 
 **/
  int NULL_aes_xcbc_encrypt(uint16_t auth_keylen, uint8_t *auth_key,
   uint8_t *espheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);

/**
 * NULL-AES-XCBC Decryption
 * This function authenticates  an inbound IPSEC packet using 
 * the AES-XCBC keys provided
 * @param auth_keylen  [in] AES-XCBC key length
 * @param auth_key     [in] AES-XCBC key
 * in length).
 * @param  pktptr      [in] Pointer to the IPSEC packet (i.e, points to 
 * ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include the 
 * ESP header (8 bytes) + PAYLOAD length + AES XCBC MAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated 
 * and AES-XCBC MAC is placed at the end of the output packet.
 * @return             (0) on SUCCESS
 *                     (-1) on FAILURE 
*/
  int NULL_aes_xcbc_decrypt(uint16_t auth_keylen, uint8_t *auth_key, 
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest);

/** 
 * 3DES-CBC-AES-XCBC Encryption
 * This function creates an IPSEC outbound packet using 3DES-CBC & AES-XCBC 
 * keys provided
 * @param des_key      [in] 3DES encryption key (must be of 24 bytes in length)
 * @param auth_keylen  [in] AES-XCBC authentication key length
 * @param auth_key     [in] AES-XCBC authentication key
 * @param espheader    [in] Pointer to the ESP header (must be of 8 bytes in 
 * length). It is placed at the start of the output packet
 * @param des_iv       [in] Initialization vector(must be of 8 bytes in length).
 *                     It is placed after ESP header in the output packet
 * @param pktptr       [in] Pointer to the input payload (to be encrypted)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of DES block size. 
 * This function doesn't pad anything at the end of the input
 * @param outptr       [out] Pointer to the output buffer where encrypted and
 * authenticated packet should be placed.
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             (0) on SUCCESS
 *                     (-1) on FAILURE 
*/

  int DES_ede3_cbc_aes_xcbc_encrypt(uint8_t *des_key, uint16_t auth_keylen, 
   uint8_t *auth_key, uint8_t *espheader, uint8_t *des_iv, uint8_t *pktptr, 
   uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);

/** 
 * 3DES-CBC-AES-XCBC Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the
 * 3DES-CBC and AES-XCBC keys provided
 * @param des_key      [in] 3DES decryption key (must be of 24 bytes in length)
 * @param auth_keylen  [in] ASE-XCBC authentication key length
 * @param auth_key     [in] ASE-XCBC authentication key
 * @param des_iv       [in] Initialization vector (must be of 8 bytes in length).
 * @param pktptr       [in] Pointer to the IPSEC packet (i.e, points to ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It should
 * include the 
 * ESP header (8 bytes) + IV (8 bytes) + PAYLOAD length + AES XCBC MAC (12 bytes)
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed.
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated  
 * and AES-XCBC MAC is placed at the end of the output packet.
 * @return             (0) on SUCCESS
 *                     (-1) on FAILURE 
*/
  int DES_ede3_cbc_aes_xcbc_decrypt(uint8_t *des_key, uint16_t auth_keylen, 
   uint8_t *auth_key, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen,
   uint8_t *outptr, uint16_t *outlen,uint8_t compdigest);

/** 
 * AES-CNTR-AES-XCBC Encryption
 * This function creates an IPSEC outbound packet using AES-CNTR & AES-XCBC 
 * keys provided
 * @param aes_key     [in] AES-CNTR encryption key
 * @param aes_key_len [in] AES-CNTR key length
 * @param nonce       [in] value of nonce (Refer RFC 3686)
 * @param auth_keylen [in] AES-XCBC key length
 * @param auth_key    [in] AES-XCBC key
 * @param espheader   [in] Pointer to the ESP header (must be of 8 bytes in
 * length). It is placed at the start of the output packet.
 * @param aes_iv      [in] Initialization vector(must be of 8 bytes in length).
 *                     It is placed after ESP header in the output packet
 * @param pktptr      [in] Pointer to the input payload (to be encrypted).
 * @param pktlen      [in] Length of input data (in bytes) pointed to by 
 * input parameter. The inputlen should be a multiple of AES block size. This
 * function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             (0) on SUCCESS
 *                     (-1) on FAILURE 
*/
  int AES_ctr_aes_xcbc_encrypt(uint64_t *aes_key, uint32_t aes_key_len, 
   uint32_t nonce, uint16_t auth_keylen, uint8_t *auth_key, uint8_t *espheader, 
   uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);

/** 
 * AES-CNTR-AES-XCBC Decryption
 * This function authenticates & decrypts an inbound IPSEC packet using the
 * AES-CNTR and AES-XCBC keys provided
 * @param aes_key     [in] AES-CNTR encryption key
 * @param aes_key_len [in] AES-CNTR key length
 * @param nonce       [in] value of nonce (Refer RFC 3686)
 * @param auth_keylen [in] AES-XCBC authentication key length
 * @param auth_key    [in] AES-XCBC authentication key
 * @param aes_iv      [in] Initialization vector (must be of 8 bytes in length).
 * @param pktptr      [in] Pointer to the IPSEC packet (i.e, points to ESP header)
 * @param pktlen      [in] Length of IPSEC packet pointed to by input. It should
 * include the 
 * ESP header (8 bytes) + IV (AES_BLOCK_SIZE) + PAYLOAD length + AES XCBC MAC (12 bytes)
 * @param outptr      [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed.
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated. If this is 0, then the IPSEC packet is not authenticated and 
 * AES-XCBC MAC is placed at the end of the output packet 
 * @return             (0) on SUCCESS
 *                     (-1) on FAILURE 
*/
  int AES_ctr_aes_xcbc_decrypt(uint64_t *aes_key, uint32_t aes_key_len, 
   uint32_t nonce, uint16_t auth_keylen, uint8_t *auth_key, uint8_t *aes_iv, 
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest);

/** 
 * AH-OUTBOUND-AES-XCBC
 * This function creates an IPSEC outbound packet using AES-XCBC 
 * keys provided
 * @param auth_keylen  [in] AES-XCBC authentication key length
 * @param auth_key     [in] AES-XCBC authentication key
 * @param ah_header     [in] Pointer to the AH header (must be of 12 bytes in 
 * length). It is placed after IPHEADER in the output packet.
 * @param pktptr       [in] Pointer to the input payload (to be authenticated)
 * @param pktlen       [in] Length of input data (in bytes) pointed to by 
 * input parameter.   
 * This function doesn't pad anything at the end of the input.
 * @param outptr      [out] Pointer to the output buffer where encrypted and 
 * authenticated packet should be placed
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @return             (0) on SUCCESS
 *                     (-1) on FAILURE 
*/

  int AH_outbound_aes_xcbc( uint16_t auth_keylen, uint8_t *auth_key,  
   uint8_t *ah_header, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen);

/**
 * AH-INBOUND-AES-XCBC
 * This function authenticates  an inbound IPSEC packet using 
 * the AES-XCBC keys provided
 * @param auth_keylen  [in] AES-XCBC authentication key length
 * @param auth_key     [in] AES-XCBC authentication key
 * in length).
 * @param  pktptr      [in] Pointer to the IPSEC packet (i.e, points to 
 * ESP header)
 * @param pktlen       [in] Length of IPSEC packet pointed to by input. It 
 * should include 
 * IP_HEADER_LENGTH + AH_HEADER_LENGTH + PAYLOAD length 
 * @param outptr       [out] Pointer to the output buffer where decrypted and 
 * authenticated packet should be placed.
 * if outptr== NULL output is placed in input pointer. 
 * @param outlen      [out] Length of output buffer (in bytes). The 
 * function returns the number of bytes placed in the output buffer. 
 * @param compdigest   If this is non-zero, then the IPSEC packet is 
 * autenticated.   
 * @return             AH_MD5_SUCCESS (0)
 *                     AH_MD5_FAILURE (-1)
*/

  int AH_inbound_aes_xcbc ( uint16_t auth_keylen, uint8_t *auth_key,  
   uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen,int compdigest);

