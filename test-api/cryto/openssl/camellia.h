/* crypto/camellia/camellia.h -*- mode:C; c-file-style: "eay" -*- */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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

#ifndef HEADER_CAMELLIA_H
#define HEADER_CAMELLIA_H

#include <openssl/opensslconf.h>
#ifdef OCTEON_OPENSSL
#include "cvmx.h"
#include "cvmx-asm.h"
#endif /* OCTEON_OPENSSL */

#ifdef OPENSSL_NO_CAMELLIA
#error CAMELLIA is disabled.
#endif

#include <stddef.h>

#define CAMELLIA_ENCRYPT	1
#define CAMELLIA_DECRYPT	0

/* Because array size can't be a const in C, the following two are macros.
   Both sizes are in bytes. */

#ifdef  __cplusplus
extern "C" {
#endif

/* This should be a hidden type, but EVP requires that the size be known */

#define CAMELLIA_BLOCK_SIZE 16
#define CAMELLIA_TABLE_BYTE_LEN 272
#define CAMELLIA_TABLE_WORD_LEN (CAMELLIA_TABLE_BYTE_LEN / 4)

typedef unsigned int KEY_TABLE_TYPE[CAMELLIA_TABLE_WORD_LEN]; /* to match with WORD */

struct camellia_key_st 
	{
	union	{
		double d;	/* ensures 64-bit align */
		KEY_TABLE_TYPE rd_key;
		} u;
	int grand_rounds;
#ifdef OCTEON_OPENSSL
	uint64_t cvmkey[4];
	int cvm_key_len;
	uint64_t round_keys[34];
#endif
	};
typedef struct camellia_key_st CAMELLIA_KEY;

#ifdef OPENSSL_FIPS
int private_Camellia_set_key(const unsigned char *userKey, const int bits,
	CAMELLIA_KEY *key);
#endif

/**
 * Expand the cipher key into the encryption key schedule.
 * @param userKey	The input key for Camellia operation
 * @param bits		Key length in bits, can be 128,192 or 256
 * @param key		store the key stream to architecture specific
 *
 * @return 0 on success and error code on failure.
 * @return  Failure: Non-zero (@ref cerr for Error codes)
 */
int Camellia_set_key(const unsigned char *userKey, const int bits,
	CAMELLIA_KEY *key);

/**
 * Camellia_encrypt
 *
 * Encrypts the CAMELLIA_BLOCK_SIZE (16Bytes) of data.
 *
 * @param in		pointer to input data
 * @param out		pointer to output data
 * @param key		pointer to the Camellia key
 */
void Camellia_encrypt(const unsigned char *in, unsigned char *out,
	const CAMELLIA_KEY *key);
/**
 * Camellia_decrypt
 *
 * Decrypts the CAMELLIA_BLOCK_SIZE (16Bytes) of data.
 *
 * @param in		pointer to input data
 * @param out		pointer to output data
 * @param key		pointer to the Camellia key
 */
void Camellia_decrypt(const unsigned char *in, unsigned char *out,
	const CAMELLIA_KEY *key);

/**
 * Camellia Electronic Cook Book Format(ECB) encrypt or decrypt
 *
 * @param in		The input buffer to be encrypted or decrypted 
 *			based on enc parameter
 * @param out 		The result is stored in the out buffer
 * @param key		The key for CAMELLIA operation
 * @param enc		enc is either CAMELLIA_ENCRYPT for encryption
 * 			or CAMELLIA_DECRYPT for decryption.
*/
void Camellia_ecb_encrypt(const unsigned char *in, unsigned char *out,
	const CAMELLIA_KEY *key, const int enc);
/**
 * Camellia chain blocking cipher (CBC) encrypt or decrypt
 *
 * @param in		The input buffer to be encrypted or decrypted 
 *			based on enc parameter
 * @param out 		The result is stored in the out buffer
 * @param length	Length of the input
 * @param key		The key for Camellia operation
 * @param ivec		The Initialisation vector
 * @param enc		enc is either CAMELLIA_ENCRYPT for encryption
 * 			or CAMELLIA_DECRYPT for decryption.
*/
void Camellia_cbc_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const CAMELLIA_KEY *key,
	unsigned char *ivec, const int enc);
/**
 * Camellia cipher feedback mode (CFB) encrypt or decrypt
 * processes 128 bits in one go.
 *
 * @param in		The input buffer to be encrypted or decrypted 
 *			based on enc parameter
 * @param out 		The result is stored in the out buffer
 * @param length	Length of the input
 * @param key		The key for Camellia operation
 * @param ivec		The Initialisation vector
 * @param num		The num parameter
 * @param enc		enc is either CAMELLIA_ENCRYPT for encryption
 * 			or CAMELLIA_DECRYPT for decryption.
*/
void Camellia_cfb128_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const CAMELLIA_KEY *key,
	unsigned char *ivec, int *num, const int enc);
/**
 * Camellia cipher feedback mode (CFB) encrypt or decrypt
 * bit by bit processing of the data.
 *
 * @param in		The input buffer to be encrypted or decrypted 
 *			based on enc parameter
 * @param out 		The result is stored in the out buffer
 * @param length	Length of the input
 * @param key		The key for Camellia operation
 * @param ivec		The Initialisation vector
 * @param num		The num parameter
 * @param enc		enc is either CAMELLIA_ENCRYPT for encryption
 * 			or CAMELLIA_DECRYPT for decryption.
*/
void Camellia_cfb1_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const CAMELLIA_KEY *key,
	unsigned char *ivec, int *num, const int enc);
/**
 * Camellia cipher feedback mode (CFB) encrypt or decrypt
 * 8 bits are  processed in one go.
 *
 * @param in		The input buffer to be encrypted or decrypted 
 *			based on enc parameter
 * @param out 		The result is stored in the out buffer
 * @param length	Length of the input
 * @param key		The key for Camellia operation
 * @param ivec		The Initialisation vector
 * @param num		The num parameter
 * @param enc		enc is either CAMELLIA_ENCRYPT for encryption
 * 			or CAMELLIA_DECRYPT for decryption.
*/
void Camellia_cfb8_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const CAMELLIA_KEY *key,
	unsigned char *ivec, int *num, const int enc);
/**
 * Camellia_ofb128_encrypt
 *
 * Camellia output feedback mode (OFB) encrypt or decrypt
 *
 * @param in		The input buffer to be encrypted or decrypted 
 *			based on enc parameter
 * @param out 		The result is stored in the out buffer
 * @param length	Length of the input
 * @param key		The key for Camellia operation
 * @param ivec		The Initialisation vector
 * @param num		The num parameter
*/
void Camellia_ofb128_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const CAMELLIA_KEY *key,
	unsigned char *ivec, int *num);
/**
 * Camellia_ctr128_encrypt
 *
 * Encrypts/Decrypts the data.
 *
 * @param in            input data pointer
 * @param length        length of data in bytes
 * @param key           pointer to key
 * @param ivec          16 bytes initial vector
 * @param out           pointer to byte array where result of
 *                      encryption should be written
 * @param ecount_buf    temporary buffer.
 * @param num           pointer to the starting counter.
 */
void Camellia_ctr128_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const CAMELLIA_KEY *key,
	unsigned char ivec[CAMELLIA_BLOCK_SIZE],
	unsigned char ecount_buf[CAMELLIA_BLOCK_SIZE],
	unsigned int *num);

#ifdef  __cplusplus
}
#endif

#endif /* !HEADER_Camellia_H */
