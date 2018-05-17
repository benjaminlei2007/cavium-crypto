/* crypto/aes/aes.h -*- mode:C; c-file-style: "eay" -*- */
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

#ifndef HEADER_AES_H
#define HEADER_AES_H

#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_AES
#error AES is disabled.
#endif

#include <stddef.h>

#define AES_ENCRYPT	1
#define AES_DECRYPT	0

/* Because array size can't be a const in C, the following two are macros.
   Both sizes are in bytes. */
#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16

#ifdef OCTEON_OPENSSL
#include <stdio.h>
#include "cvmx.h"
#include "cvmx-key.h"
#endif


#ifdef  __cplusplus
extern "C" {
#endif

/* This should be a hidden type, but EVP requires that the size be known */
struct aes_key_st {
#ifdef AES_LONG
    unsigned long rd_key[4 *(AES_MAXNR + 1)];
#else
    unsigned int rd_key[4 *(AES_MAXNR + 1)];
#endif
#ifdef OCTEON_OPENSSL
    uint64_t cvmkey[4];
    int cvm_keylen;
#endif
    int rounds;
};
typedef struct aes_key_st AES_KEY;

const char *AES_options(void);

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
	AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
	AES_KEY *key);

int private_AES_set_encrypt_key(const unsigned char *userKey, const int bits,
	AES_KEY *key);
int private_AES_set_decrypt_key(const unsigned char *userKey, const int bits,
	AES_KEY *key);

void AES_encrypt(const unsigned char *in, unsigned char *out,
	const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out,
	const AES_KEY *key);

void AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
	const AES_KEY *key, const int enc);
void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const AES_KEY *key,
	unsigned char *ivec, const int enc);
void AES_cfb128_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const AES_KEY *key,
	unsigned char *ivec, int *num, const int enc);
void AES_cfb1_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const AES_KEY *key,
	unsigned char *ivec, int *num, const int enc);
void AES_cfb8_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const AES_KEY *key,
	unsigned char *ivec, int *num, const int enc);
void AES_ofb128_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const AES_KEY *key,
	unsigned char *ivec, int *num);
void AES_ctr128_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const AES_KEY *key,
	unsigned char ivec[AES_BLOCK_SIZE],
	unsigned char ecount_buf[AES_BLOCK_SIZE],
	unsigned int *num);
/* NB: the IV is _two_ blocks long */
void AES_ige_encrypt(const unsigned char *in, unsigned char *out,
		     size_t length, const AES_KEY *key,
		     unsigned char *ivec, const int enc);
/* NB: the IV is _four_ blocks long */
void AES_bi_ige_encrypt(const unsigned char *in, unsigned char *out,
			size_t length, const AES_KEY *key,
			const AES_KEY *key2, const unsigned char *ivec,
			const int enc);

int AES_wrap_key(AES_KEY *key, const unsigned char *iv,
		unsigned char *out,
		const unsigned char *in, unsigned int inlen);
int AES_unwrap_key(AES_KEY *key, const unsigned char *iv,
		unsigned char *out,
		const unsigned char *in, unsigned int inlen);

#ifdef OCTEON_OPENSSL

struct _cvm_crypto_aes_xcbc_mac_state {
    uint64_t const1A[2];
    uint64_t const1B[2];
    uint64_t const2[2];
    uint64_t const3[2];
    uint64_t lb[2];
    uint64_t iv[2];
    uint64_t E[2];
    uint32_t plen;
    uint32_t done;
    uint64_t reserved;
};

typedef struct _cvm_crypto_aes_xcbc_mac_state AES_XCBC_MAC_CTX;

typedef struct {
    uint64_t lb[2];
    uint64_t E[2];
    uint32_t plen;
    uint32_t done;
    uint64_t reserved;
} cvm_crypto_aes_cmac_state_t;

typedef cvm_crypto_aes_cmac_state_t AES_CMAC_CTX;

typedef struct {
    uint64_t ctrblk[2];
    uint64_t iv[2];
    uint64_t reserved;
    uint64_t done;
} cvm_crypto_aes_ctr_state_t;

typedef cvm_crypto_aes_ctr_state_t AES_CTR_CTX;
typedef cvm_crypto_aes_ctr_state_t AES_ICM_CTX;

  /* All these are internal functions and not API's */
#ifndef CAV_NO_ERR_MSG
#define aes_assert(aexpr,rexpr) {if(!(aexpr)) {printf("Assertion %s Failed\n",#aexpr); return rexpr ;}}
#else
#define aes_assert(aexpr,rexpr) {if(!(aexpr)) {return rexpr ;}}
#endif
  void cvm_crypto_aes_initialize (uint64_t * key, uint32_t keylen);
  void cvm_crypto_aes_encrypt (uint64_t * data, uint32_t data_len);
  void cvm_crypto_aes_decrypt (uint64_t * data, uint32_t data_len);
  void cvm_crypto_aes_encrypt_cbc (uint64_t * iv, uint64_t * data,
    uint32_t data_len);
  void cvm_crypto_aes_decrypt_cbc (uint64_t * iv, uint64_t * data,
    uint32_t data_len);

#define cvm_octeon_crypto_aes_encrypt(key,klen,iv,data,dlen) \
{\
    cvm_crypto_aes_initialize(key,klen);\
    cvm_crypto_aes_encrypt(data,dlen);\
}

#define cvm_octeon_crypto_aes_decrypt(key,klen,iv,data,dlen) \
{\
    cvm_crypto_aes_initialize(key,klen);\
    cvm_crypto_aes_decrypt(data,dlen);\
}

#define cvm_octeon_crypto_aes_encrypt_cbc(key,klen,iv,data,dlen) \
{\
    cvm_crypto_aes_initialize(key,klen);\
    cvm_crypto_aes_encrypt_cbc(iv,data,dlen);\
}

#define  cvm_octeon_crypto_aes_decrypt_cbc(key,klen,iv,data,dlen)\
{\
    cvm_crypto_aes_initialize(key,klen);\
    cvm_crypto_aes_decrypt_cbc(iv,data,dlen);\
}

  int cvm_crypto_aes_xcbc_mac_nist_generic (uint64_t * key,
    uint32_t orgkeylen, uint64_t * const1A, uint64_t * const1B,
    uint64_t * const2, uint64_t * const3, uint64_t * data, uint32_t dlen,
    uint64_t * mac);

  void cvm_AES_encrypt (const unsigned char *in, unsigned char *out,
    const AES_KEY * key);

  /* These are API's exposed */

/**
 * cvm_crypto_aes_xcbc_mac
 *
 * AES XCBC MAC based on RFC 3566 generates a mac of 96 bits.
 *
 * @param key Pointer to keybytes (keylength in bits should be 128)
 * @param bits key length in bits (expected 16*8)
 * @param data pointer to data for which MAC should be computed
 * @param dlen data length in bytes
 * @param mac pointer where AES XCBC MAC should be written
 * @return 0 on success, -1 on failure
 */
  int cvm_crypto_aes_xcbc_mac (uint64_t * key, uint32_t bits,
    uint64_t * data, uint32_t dlen, uint64_t * mac);

/**
 * cvm_crypto_aes_xcbc_prf128
 *
 * Pseudo-Random Function based on RFC 4434 generating the output
 * of 128 bits.
 *
 * @param orgkey pointer to key
 * @param bits key length in bits, 8<=orgkeylength<=256
 * @param data pointer to data,for which prf128 should be calculated
 * @param dlen number of valid bytes pointed by data(need not be 8 multiple)
 * @param mac result pointer where mac should be written
 * @return 0 on success, -1 on failure
 */
  int cvm_crypto_aes_xcbc_prf128 (uint64_t * orgkey, uint32_t bits,
    uint64_t * data, uint32_t dlen, uint64_t * mac);

/**
 * cvm_crypto_aes_ctr_encrypt
 *
 * Encrypts the data and is based on RFC-3686 standards.
 *
 * @param key pointer to key
 * @param bits length of key in bits (should be 16*8 or 24*8 or 32*8)
 * @param orgiv eight byte initial vector
 * @param nonce initial nonce(refer RFC 3686)
 * @param data data pointer
 * @param dlen length of data in bytes
 * @param res pointer to byte array where result of encryption should be written
 * @return 0 on success, -1 on failure
 */
  int cvm_crypto_aes_ctr_encrypt (uint64_t * key, uint32_t bits,
    uint64_t orgiv, uint32_t nonce, uint64_t * data, uint32_t dlen,
    uint64_t * res);

  
/** 
 * cvm_crypto_aes_ctr_decrypt
 *
 * Decrypts the data and is based on RFC-3686 standards.
 *
 * RFC3686 implementation,parameter types are same as in cvm_crypto_aes_ctr_encrypt
 * @param key pointer to key 
 * @param bits length of key in bits (should be 16*8 or 24*8 or 32*8)
 * @param orgiv eight byte initial vector
 * @param nonce initial nonce(refer RFC 3686)
 * @param data data pointer
 * @param dlen length of data in bytes
 * @param res pointer to byte array where result of decryption should be written
 * @return 0 on success, -1 on failure
 */
  static inline int cvm_crypto_aes_ctr_decrypt (uint64_t * key,
    uint32_t bits, uint64_t orgiv, uint32_t nonce, uint64_t * data,
    uint32_t dlen, uint64_t * res) {
    return cvm_crypto_aes_ctr_encrypt (key, bits, orgiv, nonce, data, dlen,
      res);
  }


/**
 * AES ICM Single Call API
 * http://www.mindspring.com/~dmcgrew/draft-mcgrew-saag-icm-01.txt . 
 * @param key pointer to key
 * @param bits length of key in bits (should be 16*8 or 24*8 or 32*8)
 * @param iv pointer to 16 byte initial vector
 * @param data data pointer
 * @param dlen length of data in bytes
 * @param res pointer to byte array where result of encryption should be written
 * @return 0 on success, -1 on failure
 */

  int cvm_crypto_aes_icm_encrypt(uint64_t *key, uint32_t bits,
    uint64_t *iv, uint64_t *data, uint32_t dlen, uint64_t *res);

/**
 * AES ICM Implementation Single Call API
 * http://www.mindspring.com/~dmcgrew/draft-mcgrew-saag-icm-01.txt
 * Document Adapted to AES
 * @param key pointer to key
 * @param bits length of key in bits (should be 16*8 or 24*8 or 32*8)
 * @param iv Also termed as offset in the above draft,16 byte
 * @param data data pointer
 * @param dlen length of data in bytes
 * @param res pointer to byte array where result of decyrption should be written
 * @return 0 on success, -1 on failure
 */
  static inline int cvm_crypto_aes_icm_decrypt(uint64_t * key,
    uint32_t bits, uint64_t *iv, uint64_t *data, uint32_t dlen, uint64_t *res)
  {
    return cvm_crypto_aes_icm_encrypt(key,bits,iv,data,dlen,res);
  }

/**
 * AES CMAC Implementation
 * http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
 * @param key Pointer to keybytes
 * @param bits key length in bits (should be 16*8 0r 24*8 or 32*8)
 * @param data pointer to data for which MAC should be computed
 * @param dlen data length in bytes
 * @param mac pointer where AES CMAC should be written
 * @return 0 on success, -1 on failure
 */
  int cvm_crypto_aes_cmac (uint64_t * key, uint32_t bits,
    uint64_t * data, uint32_t dlen, uint64_t * mac);

  /* MultiCall API's */
/**
 * Multicall AES XCBC MAC Implementation
 * @param orgkey key byte array pointer
 * @param bits No of bits in the key (only 128 is supported right now)
 * @param key AES_KEY to be initialized, similar to AES_set_encrypt_key etc.
 * @param ctx pointer to preallocated 128 byte array,opaque quantity for user.
 * @return 0 on success, -1 on failure
 */
    int cvm_crypto_aes_xcbc_mac_init (uint8_t * orgkey, uint32_t bits,
    AES_KEY * key, AES_XCBC_MAC_CTX * ctx);

/**
 * Multicall update function
 * @param key AES_KEY that was passed to cvm_crypto_aes_xcbc_mac_init function
 * @param data pointer to data
 * @param dlen length of data
 * @param ctx PreAllocated context that was passed to cvm_crypto_aes_xcbc_mac_init function.
 * @return 0 on success, -1 on failure
 */
  int cvm_crypto_aes_xcbc_mac_update (AES_KEY * key, uint8_t * data,
    uint32_t dlen, AES_XCBC_MAC_CTX * ctx);

/**
 * Multicall final function, should be called at last
 * @param key AES_KEY that was passed to cvm_crypto_aes_xcbc_mac_init function
 * @param ctx context pointer passed to cvm_crypto_aes_xcbc_mac_init function
 * @param mac 16 byte preallocated location,where mac will be written after the call
 * @return 0 on success, -1 on failure
 */
  int cvm_crypto_aes_xcbc_mac_final (AES_KEY * key, AES_XCBC_MAC_CTX * ctx,
    uint64_t * mac);

/**
 * cvm_crypto_aes_cmac_init
 *
 * Initializes the context parameters with the given set of keys.
 *
 * Multicall AES CMAC Implementation
 * @param orgkey key byte array pointer
 * @param bits No of bits in the key (128/192/256 are supported)
 * @param key AES_KEY to be initialized, similar to AES_set_encrypt_key etc.
 * @param ctx pointer to be preallocated,opaque quantity for user.
 * @return 0 on success, -1 on failure
 */
    int cvm_crypto_aes_cmac_init (uint8_t * orgkey, uint32_t bits,
      AES_KEY * key, AES_CMAC_CTX * ctx);

/**
 * cvm_crypto_aes_cmac_update
 *
 * Encrypts the data.
 * Multicall update function
 *
 * @param key AES_KEY that was passed to cvm_crypto_aes_cmac_init function
 * @param data pointer to data
 * @param dlen length of data in bytes
 * @param ctx PreAllocated context that was passed to cvm_crypto_aes_cmac_init function.
 * @return 0 on success, -1 on failure
 */
  int cvm_crypto_aes_cmac_update (AES_KEY * key, uint8_t * data,
    uint32_t dlen, AES_CMAC_CTX * ctx);

/**
 * cvm_crypto_aes_cmac_update_bits
 *
 * Encrypts the data if its size is given in bits
 *
 * Multicall update function for bit length.
 *
 * @param key AES_KEY that was passed to cvm_crypto_aes_cmac_init function
 * @param data pointer to data
 * @param dlen length of data in bits
 * @param ctx PreAllocated context that was passed to cvm_crypto_aes_cmac_init function.
 * @return 0 on success, -1 on failure
 */
  int cvm_crypto_aes_cmac_update_bits (AES_KEY * key, uint8_t * data,
    uint32_t dlen, AES_CMAC_CTX * ctx);

/**
 * cvm_crypto_aes_cmac_final
 *
 * Finishes the encryption process and generates a mac.
 *
 * Multicall final function, should be called at last
 *
 * @param key AES_KEY that was passed to cvm_crypto_aes_cmac_init function
 * @param ctx context pointer passed to cvm_crypto_aes_cmac_init function
 * @param mac 16 byte preallocated location,where mac will be written after the call
 * @return 0 on success, -1 on failure
 */
  int cvm_crypto_aes_cmac_final (AES_KEY * key, AES_CMAC_CTX * ctx,
    uint64_t * mac);

/**
 * cvm_crypto_aes_xcbc_prf128_init
 *
 * Initiliazes the context variables.
 *
 * Multicall AES XCBC PRF128 Implementation
 *
 * @param orgkey key byte array pointer
 * @param bits No of bits in the key (only 128 is supported right now)
 * @param key AES_KEY to be initialized, opaque to the user, becomes invalid after cvm_crypto_aes_xcbc_prf128_final call
 * @param ctx context pointer to store intermediate state.
 * @return 0 on success, -1 on failure
 */
  int cvm_crypto_aes_xcbc_prf128_init (uint8_t * orgkey, uint32_t bits,
    AES_KEY * key, AES_XCBC_MAC_CTX * ctx);

/**
 * cvm_crypto_aes_xcbc_prf128_update
 *
 * Takes the input data in order to generate the MAC.
 *
 * Multicall update function
 * @param key AES_KEY that was passed to cvm_crypto_aes_xcbc_prf128_init function
 * @param data pointer to data
 * @param dlen data length
 * @param ctx context pointer passed during init.
 * @return 0 on success, -1 on failure
 */
  int cvm_crypto_aes_xcbc_prf128_update (AES_KEY * key, uint8_t * data,
    uint32_t dlen, AES_XCBC_MAC_CTX * ctx);

/**
 * cvm_crypto_aes_xcbc_prf128_final
 *
 * Generates the MAC of given data.
 *
 * Multicall final function, should be called at last
 * @param key AES_KEY that was passed to cvm_crypto_aes_xcbc_prf128_init function,becomes invalid after this call.
 * @param ctx context pointer passed during init.
 * @param mac 16 byte preallocated location,where mac will be written after the call
 * @return 0 on success, -1 on failure
 */
  int cvm_crypto_aes_xcbc_prf128_final (AES_KEY * key,
    AES_XCBC_MAC_CTX * ctx, uint64_t * mac);


/**
 * cvm_crypto_aes_ctr_encrypt_init
 *
 * Initializes the state variables.
 *
 * RFC3686 implementation,Multicall fashion
 * @param orgkey pointer to key
 * @param bits length of key in bits (128,192,256 are only allowed values)
 * @param key pointer to AES_KEY structure to be initialized
 * @param iv 8 byte initialization vector
 * @param nonce initial nonce(refer RFC 3686)
 * @param state pointer to Pre-Allocated AES_CTR_CTX structure, opaque quantity to user
 * @return 0 on success,-1 on failure.
 */
  int cvm_crypto_aes_ctr_encrypt_init (uint8_t * orgkey, uint32_t bits,
    AES_KEY * key, uint64_t iv, uint32_t nonce, void *state);



/**
 * cvm_crypto_aes_ctr_encrypt_update
 * 
 * Generates the encrypted output of the partial data given.
 *
 * RFC3686 implementation,Multicall fashion
 * @param key pointer to AES_KEY structure passed to cvm_crypto_aes_ctr_init function
 * @param data pointer to plain text to be encrypted
 * @param dlen length of data pointed to by data. If dlen is not a multiple of 16 this is considered as the final call,no further update/final functions should be called
 * @param dlen Note that if total dlen is a multiple of 16, atleast one final call is mandatory
 * @param res pointer to location where encrypted text should be written
 * @param state Pre-Allocated AES_CTR_CTX pointer that was passed to init function
 * @return 0 on success,-1 on failure
 */
  int cvm_crypto_aes_ctr_encrypt_update (AES_KEY * key, uint8_t * data,
    uint32_t dlen, uint8_t * res, void *state);

/**
 * cvm_crypto_aes_ctr_encrypt_final
 *
 * Completes the encryption process and delivers the encrypted
 * result of the input data.
 *
 * RFC3686 implementation,Multicall fashion
 * After this call no update/final should be called
 * @param key pointer to AES_KEY structure passed to cvm_crypto_aes_ctr_init function
 * @param data pointer to plain text to be encrypted
 * @param dlen length of data pointed to by data(should be non-zero).
 * @param dlen Note that if total dlen is a multiple of 16, atleast one final call is mandatory
 * @param res pointer to location where encrypted text should be written
 * @param state Pre-Allocated AES_CTR_CTX pointer that was passed to init function
 * @return 0 on success, -1 on failure
 */
  int cvm_crypto_aes_ctr_encrypt_final (AES_KEY * key, uint8_t * data,
    uint32_t dlen, uint8_t * res, void *state);

/**
 * AES ICM implementation,Multicall fashion
 * @param orgkey pointer to key
 * @param bits length of key in bits (128,192,256 are only allowed values)
 * @param key pointer to AES_KEY structure to be initialized
 * @param iv pointer to 16 byte initialization vector
 * @param state pointer to Pre-Allocated AES_ICM_CTX structure, opaque quantity to user
 * @return 0 on success,-1 on failure.
 */
  int cvm_crypto_aes_icm_encrypt_init (uint8_t * orgkey, uint32_t bits,
    AES_KEY * key, uint64_t *iv, void *state);

/**
 * AES ICM implementation,Multicall fashion
 * @param key pointer to AES_KEY structure passed to cvm_crypto_aes_icm_encrypt_init function
 * @param data pointer to text to be encrypted
 * @param dlen length of data pointed to by data. If dlen is not a multiple of 16 this is considered as the final call,no further update/final functions should be called
 * @param dlen Note that if total dlen is a multiple of 16, atleast one final call is mandatory 
 * @param res pointer to encrypted text to be written
 * @param state Pre-allocated AES_ICM_CTX pointer that was passed to init function
 * @return 0 on success, -1 on failure
 */
  static inline int cvm_crypto_aes_icm_encrypt_update (AES_KEY * key, 
    uint8_t * data, uint32_t dlen, uint8_t * res, void *state)
  {
    return cvm_crypto_aes_ctr_encrypt_update(key,data,dlen,res,state);
  }



/**
 * AES ICM implementation,Multicall fashion
 * After this call no update/final should be called
 * @param key pointer to AES_KEY structure passed to cvm_crypto_aes_icm_encrypt_init function
 * @param data pointer to text to be encrypted
 * @param dlen length of data pointed to by data(should be non-zero).
 * @param dlen Note that if total dlen is a multiple of 16, atleast one final call is mandatory 
 * @param res pointer to location where encrypted text should be written
 * @param state AES_ICM_CTX pointer that was passed to init function
 * @return 0 on success, -1 on failure
 */


  static inline int cvm_crypto_aes_icm_encrypt_final (AES_KEY * key,
    uint8_t * data, uint32_t dlen, uint8_t * res, void *state)
  {
    return cvm_crypto_aes_ctr_encrypt_final(key,data,dlen,res,state);
  }

/**
 * cvm_crypto_aes_ctr_decrypt_init
 *
 * Initializes the state variables.
 *
 * RFC3686 implementation,Multicall fashion
 * @param orgkey pointer to key
 * @param bits length of key in bits (128,192,256 are only allowed values)
 * @param key pointer to AES_KEY structure to be initialized
 * @param nonce initial nonce(refer RFC 3686)
 * @param iv 8 byte initialization vector
 * @param state pointer to Pre-Allocated AES_CTR_CTX structure,opaque quantity to user
 * @return 0 on success,-1 on failure
 */

  static inline int cvm_crypto_aes_ctr_decrypt_init (uint8_t * orgkey,
    uint32_t bits, AES_KEY * key, uint64_t iv, uint32_t nonce,
    void *state) {
    return cvm_crypto_aes_ctr_encrypt_init (orgkey, bits, key, iv, nonce,
      state);
  }


/**
 * cvm_crypto_aes_ctr_decrypt_update
 * 
 * Generates the decrypted output of the partial data given.
 *
 * RFC3686 implementation,Multicall fashion
 * @param key pointer to AES_KEY structure passed to cvm_crypto_aes_ctr_init function
 * @param data pointer to text to be encrypted
 * @param dlen length of data pointed to by data. If dlen is not a multiple of 16 this is considered as the final call,no further update/final functions should be called
 * @param dlen Note that if total dlen is a multiple of 16, atleast one final call is mandatory 
 * @param res pointer to decrypted text to be written
 * @param state Pre-allocated AES_CTR_CTX pointer that was passed to init function
 * @return 0 on success, -1 on failure
 */

  static inline int cvm_crypto_aes_ctr_decrypt_update (AES_KEY * key,
    uint8_t * data, uint32_t dlen, uint8_t * res, void *state) {
    return cvm_crypto_aes_ctr_encrypt_update (key, data, dlen, res, state);
  }

/**
 * cvm_crypto_aes_ctr_decrypt_final
 *
 * Completes the decryption process and delivers the encrypted
 * result of the input data.
 *
 * RFC3686 implementation,Multicall fashion
 * After this call no update/final should be called
 * @param key pointer to AES_KEY structure passed to cvm_crypto_aes_ctr_init function
 * @param data pointer to text to be decrypted
 * @param dlen length of data pointed to by data(should be non-zero).
 * @param dlen Note that if total dlen is a multiple of 16, atleast one final call is mandatory 
 * @param res pointer to location where decrypted text should be written
 * @param state AES_CTR_CTX pointer that was passed to init function
 * @return 0 on success, -1 on failure
 */

  static inline int cvm_crypto_aes_ctr_decrypt_final (AES_KEY * key,
    uint8_t * data, uint32_t dlen, uint8_t * res, void *state) {
    return cvm_crypto_aes_ctr_encrypt_final (key, data, dlen, res, state);
  }

/** 
 * AES ICM implementation,Multicall fashion
 * @param orgkey pointer to key
 * @param bits length of key in bits (128,192,256 are only allowed values)
 * @param key pointer to AES_KEY structure to be initialized
 * @param iv pointer to 16 byte initialization vector
 * @param state pointer to Pre-Allocated AES_ICM_CTX structure, opaque quantity to user
 * @return 0 on success,-1 on failure.
 */

  static inline int cvm_crypto_aes_icm_decrypt_init (uint8_t * orgkey, 
    uint32_t bits, AES_KEY * key, uint64_t *iv, void *state)
  {
    return cvm_crypto_aes_icm_encrypt_init(orgkey,bits,key,iv,state);
  }

/**
 * AES ICM implementation,Multicall fashion
 * @param key pointer to AES_KEY structure passed to cvm_crypto_aes_icm_decrypt_init function
 * @param data pointer to text to be decrypted
 * @param dlen length of data pointed to by data. If dlen is not a multiple of 16 this is considered as the final call,no further update/final functions should be called
 * @param dlen Note that if total dlen is a multiple of 16, atleast one final call is mandatory 
 * @param res pointer to decrypted text to be written
 * @param state Pre-allocated AES_ICM_CTX pointer that was passed to init function
 * @return 0 on success, -1 on failure
 */

  static inline int cvm_crypto_aes_icm_decrypt_update (AES_KEY * key, 
    uint8_t * data, uint32_t dlen, uint8_t * res, void *state)
  {
    return cvm_crypto_aes_icm_encrypt_update(key,data,dlen,res,state);
  }

/**
 * AES ICM implementation,Multicall fashion
 * After this call no update/final should be called
 * @param key pointer to AES_KEY structure passed to cvm_crypto_aes_icm_decrypt_init function
 * @param data pointer to text to be decrypted
 * @param dlen length of data pointed to by data(should be non-zero).
 * @param dlen Note that if total dlen is a multiple of 16, atleast one final call is mandatory 
 * @param res pointer to location where decrypted text should be written
 * @param state AES_ICM_CTX pointer that was passed to init function
 * @return 0 on success, -1 on failure
 */


  static inline int cvm_crypto_aes_icm_decrypt_final (AES_KEY * key,
    uint8_t * data, uint32_t dlen, uint8_t * res, void *state)
  {
    return cvm_crypto_aes_icm_encrypt_final(key,data,dlen,res,state);
  }

//return codes
#define AES_CCM_ENCRYPT_SUCCESS    0
#define AES_CCM_DECRYPT_SUCCESS    0
#define AES_CCM_INVALID_AUTH_DATA -1
#define AES_CCM_AUTH_CHECK_FAILED -2

// Represents First Byte of the Authentication Block and Encryptio Block 
typedef union {
   uint8_t val;
   struct {
      uint8_t reserved : 1;
      uint8_t adata    : 1;
      uint8_t m        : 3;
      uint8_t l        : 3;
   } s;
} flags_t;

//Represents Authentication length Encode Block
typedef union {
   uint64_t val[2];
   struct {
      uint16_t two_octets;
      uint8_t adata[14];
   } s;
   struct {
      uint8_t two_octets[2];
      uint8_t four_octets[4];
      uint8_t  adata[10];
   }s1;
   struct {
      uint8_t two_octets[2];
      uint8_t eight_octets[8];
      uint8_t  adata[6];
   }s2;
   uint8_t byte[16];
} auth_len_encode1_t;

typedef auth_len_encode1_t nonce_t;

//AES CCM Context Structure
typedef struct aes_ccm_ctx_t {
      uint64_t b0high;
      uint64_t b0low;
      uint64_t a0high;
      uint64_t a0low;
      uint64_t s0;
      uint64_t s1;
      uint64_t r0;
      uint64_t r1;
      flags_t b0_flags;
      flags_t a0_flags;
      auth_len_encode1_t block64_t;
      nonce_t nonce;	
      uint8_t offset;
      uint8_t mac_length;
      uint8_t no_alen;
} aes_ccm_ctx;

/**
* Initiates the First MAC and Encryption Operations on Initial Blocks and 
* stores into the context
* @param aes_ctx AES_CCM context pointer 
**/
   int AES_CCM_init(aes_ccm_ctx *aes_ctx);

/**
* Intitates the AES Key into the registers
* @param K key pointer to Key of size keylen bits (Input)
* @param klen keylen Length of the key in bits (Input)
**/
   int AES_CCM_set_key(uint64_t *K, uint32_t klen);

/**
* Setsup the Basic Blocks for AES_CCM Operation
* @param m Length of MAC (Message Authentication Code)
* @param l Bytes to represent plen
* @param ain pointer to Authentication data of size "alen" bytes (Input)
* @param alen Length of the Authentication data in bytes (Input)
* @param plen Length of the Plain input in bytes (Input)
* @param nonce_val Nonce pointer (Input)
* @param aes_ctx AES_CCM context pointer 
**/

   int AES_CCM_setup_blocks(uint8_t m, uint8_t l,uint8_t *ain, uint64_t alen,	           uint64_t plen, uint64_t *nonce_val, aes_ccm_ctx * aes_ctx);

/**
 * AES CCM Encryption + Authentication operation
 *          This encrypts plain input and authenticates the input
 *          authentication data. One or both of these inputs can
 *          be given together.
 * @param m size of MAC (Input)
 * @param l size of nonce (Input)
 * @param nonce Nonce pointer (Input)
 * @param key pointer to Key of size keylen bits (Input)
 * @param keylen Length of the key in bits (Input)
 * @param pin pointer to Plain input of size "plen" bytes (Input)
 * @param plen Length of the Plain input in bytes (Input)
 * @param ain pointer to Authentication data of size "alen" bytes (Input)
 * @param alen Length of the Authentication data in bytes (Input)
 * @param out pointer to Ciphered output of size "plen" bytes (Output)
 * @param auth Pointer to m bytes of generated authentication output (Output)
 * @return AES_CCM_SUCCESS (0)             
 *         AES_CCM_INVALID_KEYLENGTH (-1)
 *         AES_CCM_INVALID_CTX (-2)
 *         AES_CCM_IV_NOT_SET  (-3)
 *         AES_CCM_KEY_NOT_SET (-4)
 */
  int AES_CCM_encrypt (uint8_t m, uint8_t l, uint8_t *nonce, uint8_t * key, uint32_t keylen, uint8_t * pin, uint64_t plen, uint8_t * ain,
    uint64_t alen, uint8_t * out, uint8_t * auth);
/**
 * AES CCM Decryption + Authentication operation
 *          This decrypts cipher input and checks the authentication
 *          given as input from encryption function data. 
 *          be given together.
 * @param m size of MAC (Input)
 * @param l size of nonce (Input)
 * @param nonce Nonce pointer (Input)
 * @param key pointer to Key of size keylen bits (Input)
 * @param keylen Length of the key in bits (Input)
 * @param cin pointer to Cipher input of size "plen" bytes (Input)
 * @param plen Length of the Plain input in bytes (Input)
 * @param ain pointer to Authentication data of size "alen" bytes (Input)
 * @param alen Length of the Authentication data in bytes (Input)
 * @param out pointer to decrypted output of size "plen" bytes (Output)
 * @param auth Pointer to m bytes of generated authentication output (Output)
 * @return AES_CCM_SUCCESS (0)             
 *         AES_CCM_INVALID_KEYLENGTH (-1)
 *         AES_CCM_INVALID_CTX (-2)
 *         AES_CCM_IV_NOT_SET  (-3)
 *         AES_CCM_KEY_NOT_SET (-4)
 */
  int AES_CCM_decrypt (uint8_t m, uint8_t l, uint8_t* nonce, uint8_t * key, uint32_t keylen, uint8_t * cin, uint64_t plen, uint8_t * ain,
        uint64_t alen, uint8_t * out, uint8_t * auth);

/**
 * AES CCM Encryption + Authentication operation for Multi Call Operation
 *          This encrypts plain input and authenticates the input
 *          authentication data. One or both of these inputs can
 *          be given together.
 * @param pin pointer to Plain input of size "plen" bytes (Input)
 * @param plen Length of the Plain input in bytes (Input)
 * @param ain pointer to Authentication data of size "alen" bytes (Input)
 * @param alen Length of the Authentication data in bytes (Input)
 * @param out pointer to Ciphered output of size "plen" bytes (Output)
 * @param auth Pointer to m bytes of generated authentication (Output)
 * @param aes_ctx AES_CCM context pointer 
 * @return Success: 0
 * @return  Failure: Non-zero
 */

  int AES_CCM_ctx_encrypt (uint8_t * pin, uint64_t plen, uint8_t * ain,
    uint64_t alen, uint8_t * out, uint8_t * auth, aes_ccm_ctx *aes_ctx);

/**
 * AES CCM Decryption + Authentication operation for Multi Call Operation
 *          This encrypts plain input and authenticates the input
 *          authentication data. One or both of these inputs can
 *          be given together.
 * @param cin pointer to Plain input of size "plen" bytes (Input)
 * @param plen Length of the Plain input in bytes (Input)
 * @param ain pointer to Authentication data of size "alen" bytes (Input)
 * @param alen Length of the Authentication data in bytes (Input)
 * @param out pointer to Ciphered output of size "plen" bytes (Output)
 * @param auth Pointer to m bytes of generated authentication (Output)
 * @param aes_ctx AES_CCM context pointer 
 * @return Success: 0
 * @return  Failure: Non-zero
 */

  int AES_CCM_ctx_decrypt (uint8_t * cin, uint64_t plen, uint8_t * ain,
        uint64_t alen, uint8_t * out, uint8_t * auth, aes_ccm_ctx *aes_ctx);


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

#define LRW_AES_SUCCESS              0
#define LRW_AES_INVALID_KEYLENGTH   -1
#define LRW_AES_INVALID_CTX         -2
#define LRW_AES_INVALID_LENGTH      -3

#define LRW_KEY_DONE                0xBEAD

/**
 * LRW AES Sets the key in the context
 * @param key pointer to Key(AES-KEY followed by 128 bit Tweak key) 
 *        of total size keylen bits (Input)
 * @param keylen Length of the key in bits(Valid values: 256,320,384)(Input)
 * @param i Pointer to 16 byte Initial tweak value (Input)
 * @param lrw_ctx pointer to lrw_aes_ctx_t structure. 
 *        This is an opaque pointer to the user (Input)
 * @return LRW_AES_SUCCESS (0)             
 *         LRW_AES_INVALID_KEYLENGTH (-1)
 */
  int LRW_AES_set_key (uint8_t * key, uint32_t keylen, uint8_t * i,
    lrw_aes_ctx_t * lrw_ctx);
/**
 * LRW AES Encryption (Multiple calls for same key)
 *          This encrypts plain input.
 * @param pin pointer to Plain input of size "plen" bytes (Input)
 * @param plen Length of the Plain input in bytes (Input)
 * @param out pointer to Ciphered output of size "plen" bytes (Output)
 * @param lrw_ctx pointer to lrw_aes_ctx_t structure. 
 *        This is an opaque pointer to the user (Input)
 * @return LRW_AES_SUCCESS (0)             
 *         LRW_AES_INVALID_CTX (-2)
 *         LRW_AES_INVALID_LENGTH (-3)
 */
  int LRW_AES_ctx_encrypt (uint8_t * pin, uint32_t plen, uint8_t * out,
    lrw_aes_ctx_t * lrw_ctx);
/**
 * LRW AES Decryption (Multiple calls for same key)
 *          This decrypts Ciphered input.
 * @param cin pointer to Ciphered input of size "clen" bytes (Input)
 * @param clen Length of the Ciphered input in bytes (Input)
 * @param out pointer to Plain output of size "clen" bytes (Output)
 * @param lrw_ctx pointer to lrw_aes_ctx_t structure. 
 *        This is an opaque pointer to the user (Input)
 * @return LRW_AES_SUCCESS (0)             
 *         LRW_AES_INVALID_CTX (-2)
 *         LRW_AES_INVALID_LENGTH (-3)
 */
  int LRW_AES_ctx_decrypt (uint8_t * cin, uint32_t clen, uint8_t * out,
    lrw_aes_ctx_t * lrw_ctx);
/**
 * LRW AES Encryption 
 *          This encrypts plain input.
 * @param key pointer to Key (AES-KEY followed by 128 bit Tweak key) of total size keylen bits (Input)
 * @param keylen Length of the key in bits (Input)
 * @param plain pointer to Plain input of size "plen" bytes (Input)
 * @param plen Length of the Plain input in bytes (Input)
 * @param tweak Pointer to 16 byte Initial tweak value (Input)
 * @param out pointer to Ciphered output of size "plen" bytes (Output)
 * @return LRW_AES_SUCCESS (0)             
 *         LRW_AES_INVALID_KEYLENGTH (-1)
 *         LRW_AES_INVALID_CTX (-2)
 *         LRW_AES_INVALID_LENGTH (-3)
 */
  int LRW_AES_encrypt (uint8_t * key, uint32_t keylen, uint8_t * plain,
    uint32_t plen, uint8_t * tweak, uint8_t * out);
/**
 * LRW AES Decryption 
 *          This decrypts Ciphered input.
 * @param key pointer to Key (AES-KEY followed by 128 bit Tweak key) of total size keylen bits (Input)
 * @param keylen Length of the key in bits (Input)
 * @param c pointer to Ciphered input of size "clen" bytes (Input)
 * @param clen Length of the Ciphered input in bytes (Input)
 * @param tweak Pointer to 16 byte Initial tweak value (Input)
 * @param out pointer to Plain output of size "clen" bytes (Output)
 * @return LRW_AES_SUCCESS (0)             
 *         LRW_AES_INVALID_KEYLENGTH (-1)
 *         LRW_AES_INVALID_CTX (-2)
 *         LRW_AES_INVALID_LENGTH (-3)
 */
  int LRW_AES_decrypt (uint8_t * key, uint32_t keylen, uint8_t * c,
    uint32_t clen, uint8_t * tweak, uint8_t * out);

#define AES_CBC_SHA_SUCCESS             0
#define AES_CBC_SHA_INVALID_ARGUMENT   -1
#define AES_CBC_SHA_INVALID_KEYLENGTH  -2
#define AES_CBC_SHA_BUFFER_TOO_SMALL   -3

   
#define AES_CTR_SHA_SUCCESS             0
#define AES_CTR_SHA_INVALID_ARGUMENT   -1
#define AES_CTR_SHA_INVALID_KEYLENGTH  -2
#define AES_CTR_SHA_BUFFER_TOO_SMALL   -3

/*
 * XTS AES APIs
 * Based on IEEE Draft P1619/D11 December 2006
 */
typedef struct{
  uint64_t key1[4];
  uint64_t key2[4];
  /* last tweak */
  uint64_t tweak[2];
  uint32_t keylen;
  uint32_t state;
}aes_xts_ctx_t;
typedef aes_xts_ctx_t AES_XTS_CTX;

#define XTS_AES_SUCCESS 0
#define XTS_AES_NULL_POINTER_ARGUMENT -1
#define XTS_AES_INVALID_KEYLENGTH -2
#define XTS_AES_INVALID_CTX -3
#define XTS_AES_INVALID_DATALENGTH -4

/* Multicall APIs */
/**
 * XTS AES Sets the key in the context
 * @param key1 [in] pointer to key1 of size keylen bits
 * @param key2 [in] pointer to key2 of size keylen bits
 * @param keylen [in] length of the key in bits(Valid values: 128/256)
 * @param dseqnum [in] data sequence number from which tweak is derived
 * @param ctx [in/out] pointer to preallocated aes_xts_ctx_t structure.
 *        This is an opaque pointer to the user
 * @return XTS_AES_SUCCESS (0)
 *         XTS_AES_NULL_POINTER_ARGUMENT (-1)
 *         XTS_AES_INVALID_KEYLENGTH (-2)
 */
int XTS_AES_ctx_init(uint64_t *key1,uint64_t *key2,uint32_t keylen,uint64_t dseqnum,aes_xts_ctx_t *ctx);

/**
 * XTS AES Multicall Encryption API
 * Based on IEEE Draft P1619/D11 December 2006
 * This can be called multiple times
 * len should >=16 in any call
 * if (len%16)!=0 then this is considered as final call
 * @param pt [in] pointer to plain text
 * @param len [in] length of plain text in bytes >=16
 * @param ct [out] pointer to location where cipher text will be written
 * @param ctx [in/out] context pointer passed to XTS_AES_ctx_init 
 * @return XTS_AES_SUCCESS (0)
 *         XTS_AES_NULL_POINTER_ARGUMENT (-1)
 *         XTS_AES_INVALID_CTX (-3)
 *         XTS_AES_INVALID_DATALENGTH (-4)
 */
int XTS_AES_ctx_encrypt(uint8_t *pt,uint32_t len,uint8_t *ct,aes_xts_ctx_t *ctx);

/**
 * XTS AES Multicall Decryption API
 * Based on IEEE Draft P1619/D11 December 2006
 * This can be called multiple times
 * len should >=16 in any call
 * if (len%16)!=0 then this is considered as final call
 * @param ct [in] pointer to cipher text
 * @param len [in] length of cipher text in bytes >=16
 * @param pt [out] pointer to location where plain text will be written
 * @param ctx [in/out] context pointer passed to XTS_AES_ctx_init 
 * @return XTS_AES_SUCCESS (0)
 *         XTS_AES_NULL_POINTER_ARGUMENT (-1)
 *         XTS_AES_INVALID_CTX (-3)
 *         XTS_AES_INVALID_DATALENGTH (-4)
 */

int XTS_AES_ctx_decrypt(uint8_t *ct,uint32_t len,uint8_t *pt,aes_xts_ctx_t *ctx);

/* SingleCall APIs*/

/**
 * XTS AES SingleCall Encryption API
 * Based on IEEE Draft P1619/D11 December 2006
 * @param key1 [in] pointer to key1 of size keylen bits
 * @param key2 [in] pointer to key2 of size keylen bits
 * @param keylen [in] length of the key in bits(Valid values: 128/256)
 * @param dseqnum [in] data sequence number from which tweak is derived
 * @param pt [in] pointer to plain text
 * @param len [in] length of plain text in bytes >=16
 * @param ct [out] pointer to location where cipher text will be written
 * @return XTS_AES_SUCCESS (0)
 *         XTS_AES_NULL_POINTER_ARGUMENT (-1)
 *         XTS_AES_INVALID_KEYLENGTH (-2)
 *         XTS_AES_INVALID_DATALENGTH (-4)
 */
int XTS_AES_encrypt(uint64_t *key1,uint64_t *key2,uint32_t keylen,uint64_t dseqnum,uint8_t *pt,uint32_t len,uint8_t *ct);

/**
 * XTS AES SingleCall Decryption API
 * Based on IEEE Draft P1619/D11 December 2006
 * @param key1 [in] pointer to key1 of size keylen bits
 * @param key2 [in] pointer to key2 of size keylen bits
 * @param keylen [in] length of the key in bits(Valid values: 128/256)
 * @param dseqnum [in] data sequence number from which tweak is derived
 * @param ct [in] pointer to cipher text
 * @param len [in] length of cipher text in bytes >=16
 * @param pt [out] pointer to location where plain text will be written
 * @return XTS_AES_SUCCESS (0)
 *         XTS_AES_NULL_POINTER_ARGUMENT (-1)
 *         XTS_AES_INVALID_KEYLENGTH (-2)
 *         XTS_AES_INVALID_DATALENGTH (-4)
 */
int XTS_AES_decrypt(uint64_t *key1,uint64_t *key2,uint32_t keylen,uint64_t dseqnum,uint8_t *ct,uint32_t len,uint8_t *pt);

/**
 * AES-XCB Wide Block Encryption algorithm.
 * Based on IEEE Draft P1619.2 Draft 10 June 2009.
 *
 * @param in            Text data to be encrypted. (Min 16 bytes).
 * @param in_len        Text data length in bytes.
 * @param key           Key Pointer.
 * @param key_len       Length of the Key in bits. (Either 128 or 256).
 * @param zdata         Associated Data Pointer.
 * @param zdata_len     length of Associated Data in bytes.
 * @param out           Pointer used to store the Encrypted Text.
 * @return              Success:  0
 * @return              Failure: -1 (invalid key_len or invalid in_len) 
 *                               -2 (Either in or key or out or zdata is NULL.
 *                                   zdata can be null if zdata_len == 0)
 */

int AES_XCB_encrypt(const unsigned char *in, const uint64_t in_len,
                    const unsigned char *key, const uint32_t key_len,
                    const unsigned char *zdata, const uint64_t zdata_len,
                    unsigned char *out);

/**
 * AES-XCB Wide Block Decryption algorithm.
 * Based on IEEE Draft P1619.2 Draft 10 June 2009.
 *
 * @param in            Text data to be decrypted. (Min 16 bytes).
 * @param in_len        Text data length in bytes.
 * @param key           Key Pointer.
 * @param key_len       Length of the Key in bits. (Either 128 or 256).
 * @param zdata         Associated Data Pointer.
 * @param zdata_len     length of Associated Data in bytes.
 * @param out           Pointer used to store the Decrypted Text.
 * @return              Success:  0
 * @return              Failure: -1 (invalid key_len or invalid in_len) 
 *                               -2 (Either in or key or out or zdata is NULL.
 *                                   zdata can be null if zdata_len == 0)
 */

int AES_XCB_decrypt(const unsigned char *in, const uint64_t in_len,
                    const unsigned char *key, const uint32_t key_len,
                    const unsigned char *zdata, const uint64_t zdata_len,
                    unsigned char *out);
#endif

#ifdef  __cplusplus
}
#endif

#endif /* !HEADER_AES_H */
