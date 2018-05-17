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



#ifndef __CRYPTO_GENERIC_API__
#define __CRYPTO_GENERIC_API__

#include <openssl/hmac.h>
#include <openssl/des.h>
#include <openssl/dsa.h>
#include <openssl/aes.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#define HMACMD5         0
#define HMACSHA1        1
#define HMACSHA224      2
#define HMACSHA256      3
#define HMACSHA384      4
#define HMACSHA512      5

#define SINGLEDES       0
#define TRIPLEDES       1
#define DES_BLOCK_SIZE  8

#define AES128_CBC      0
#define AES192_CBC      1
#define AES256_CBC      2
#define AES_BLOCK_SIZE  16


/* Library Codes */
#define CGAPI_ERR_LIB_RSA       100
#define CGAPI_ERR_LIB_DH        101
#define CGAPI_ERR_LIB_AES       102
#define CGAPI_ERR_LIB_DES       103
#define CGAPI_ERR_LIB_BIGNUM    104
#define CGAPI_ERR_LIB_HMAC      105


/* Function Codes */
#define RSA_F_CGAPI_RSA_GENERATE_KEY_PAIR    500
#define RSA_F_CGAPI_RSA_PRIVATE_DECRYPT      501
#define RSA_F_CGAPI_RSA_PRIVATE_ENCRYPT      502
#define RSA_F_CGAPI_RSA_PUBLIC_DECRYPT       503
#define RSA_F_CGAPI_RSA_PUBLIC_ENCRYPT       504

#define DH_F_CGAPI_DH_GENERATE_KEY_PAIR      505
#define DH_F_CGAPI_DH_GENERATE_SHARED_SECRET 506

#define AES_F_CGAPI_ENCRYPT                  507
#define AES_F_CGAPI_DECRYPT                  508

#define DES_F_CGAPI_ENCRYPT                  509
#define DES_F_CGAPI_DECRYPT                  510

#define HMAC_F_CGAPI                         511

#define DSA_F_GENERATE_PARAMETERS            512

/* Reason Codes */
#define RSA_R_CGAPI_BAD_GENERATOR            500
#define RSA_R_CGAPI_BAD_PRIVATE_ENCRYPT      501
#define RSA_R_CGAPI_BAD_PUBLIC_ENCRYPT       502
#define RSA_R_CGAPI_BAD_PRIVATE_DECRYPT      503
#define RSA_R_CGAPI_BAD_PUBLIC_DECRYPT       504

#define DH_R_CGAPI_BAD_GENERATOR             505
#define DH_R_CGAPI_BAD_SHARED_KEY            506

#define DES_R_CGAPI_WRONG_KEY                507
#define DES_R_CGAPI_WRONGDES                 508

#define AES_R_CGAPI_WRONG_KEY                509
#define AES_R_CGAPI_WRONGAES                 510

#define HMAC_F_CGAPI_WRONG_HMAC              511

#define CGAPI_R_BAD_BIN2BN                   512
#define CGAPI_R_BAD_BN2BIN                   513

#define CGAPI_R_MEMORY_ALLOC_FAIL            514
#define CGAPI_R_INVALID_BLOCK_OF_INPUT_SIZE  515   /* Input size must be multiple of block size for block ciphers */
#define CGAPI_R_INSUFFICIENT_OUTBUF          516


typedef void (*callback_handle_t)(int method, int failure_code);

typedef struct rsa_st_ {
  unsigned int modulus_length;   /**< Length in bits of the key's modulus */
  unsigned long *e_ptr;    /**< pointer to the exponent to be used */
  unsigned char *n_ptr;    /**< pointer to a buffer where newly created modulus will be written */
  unsigned char *p_ptr;    /**< pointer to a buffer where the newly created RSA prime p will be written */
  unsigned char *q_ptr;    /**< pointer to a buffer where the newly created RSA prime q will be written */
  unsigned char *d_ptr;    /**< pointer to a buffer where the newly created private exponent d will be written */
  unsigned char *dp_ptr;    /**< pointer to a buffer where the newly created RSA private exponent dp will be written */
  unsigned char *dq_ptr;    /**< pointer to a buffer where the newly created RSA private exponent dq will be written */
  unsigned char *pinv;    /**< pointer to a buffer where the newly created RSA coefficient pinv will be written */
  unsigned int nlen;    /**< length of the newly created modulus */
  unsigned int plen;    /**< length of the newly created RSA prime p */
  unsigned int qlen;    /**< length of the newly created RSA prime q */
  unsigned int dlen;    /**< length of the newly created private exponent d */
  unsigned int dplen;   /**< length of the newly created private exponent dp */
  unsigned int dqlen;   /**< length of the newly created private exponent dq */
  unsigned int pinvlen;   /**< length of the newly created RSA coefficient pinv */
} rsa_st_t;

typedef struct buffers {
  int size;                /**< size of the data */
  unsigned char *data;     /**< pointer to the input buffer */
  struct buffers *next;    /**< pointer to the next buffer in the linked list */
} buffers_t;



/**
 * This API performs the first step of a Diffie-Hellman key exchange by
 * generating private and public DH values.
 *
 * @param modlen  [in] length of the modulus (or prime) in bytes
 * @param modulus [in] pointer to buffer which contains the modulus
 * @param baselen [in] length in bytes of the base (or generator) in bytes
 * @param base    [in] pointer to buffer which contains the base
 *
 * @param pubkeylen [out] valid pointer to integer where length of public key is returned
 * @param pubkey    [out] valid pointer to buffer of atleast modlen bytes where public key will be written
 *
 * @param privkeylen [inout] valid pointer to integer.
 * If The integer at the pointer is set to zero before call,length of the private key is set on return
 * If the integer at the pointer is set to non-zero multiple of 8,it is unaltered on return and privkey
 * of this length is only valid
 *
 * @param privkey    [out] valid pointer to buffer of where private key will be written.
 * If privkeylen points to an integer of zero value,length of this buffer should be atleast modlen bytes.
 * If privkeylen points to an integer of non-zero multiple of 8,length of this buffer should be that integer.
 *
 * @param callback   [in] Callback function pointer. This function is called whenever a CRNG test failure occurs, can be NULL.
 * @return 0 on success and error code on failure.
 * @return  Failure: Non-zero (@ref cerr for Error codes)
 */
int dh_generate_key_pair_generic(unsigned int  modlen,
                                 unsigned char *modulus,
                                 unsigned int  baselen,
                                 unsigned char *base,
                                 unsigned int  *pubkeylen,
                                 unsigned char *pubkey,
                                 unsigned int  *privkeylen,
                                 unsigned char *privkey,
                                 callback_handle_t callback);
/**
 * This API performs the first step of a Deffie-Hellman key exchange by 
 * generating private and public DH values.
 * 
 * Input arguments :
 * @param modulus_byte_length the length in bytes of the modulus.
 * @param modulus the pointer to a buffer which contains the modulus.
 * @param base_byte_length the length in bytes of the base.
 * @param base the pointer to a buffer which contains the base output.
 *
 * Output arguments :
 * @param public_key the pointer to an pre-allocated buffer which will 
 * save the public key generated by this function. The size of the buffer 
 * is same as the modulus. If the size is not the same as modulus, use
 * dh_generate_key_pair2()
 * @param private_key the pointer to an pre-allocated buffer which will 
 * save the private key generated by this function. The size of the buffer
 * is same as the base. If the size is not the same as base, use
 * dh_generate_key_pair2()
 *
 * @return 0 on success and error code on failure.
 * @return  Failure: Non-zero (@ref cerr for Error codes)
*/
static inline int dh_generate_key_pair (int modulus_byte_length,
  unsigned char *modulus,
  int base_byte_length,
  unsigned char *base,
  unsigned char *public_key, unsigned char *private_key)
{
   unsigned int public_key_len = 0, priv_key_len = 0;
	return dh_generate_key_pair_generic(modulus_byte_length, modulus,
	                                    base_byte_length, base,
													&public_key_len, public_key, 
													&priv_key_len, private_key,
													NULL);
}



/**
 * This API performs the first step of a Diffie-Hellman key exchange by
 * generating private and public DH values.
 *
 * @param modlen  [in] length of the modulus (or prime) in bytes
 * @param modulus [in] pointer to buffer which contains the modulus
 * @param baselen [in] length in bytes of the base (or generator) in bytes
 * @param base    [in] pointer to buffer which contains the base
 *
 * @param pubkeylen [out] valid pointer to integer where length of public key is returned
 * @param pubkey    [out] valid pointer to buffer of atleast modlen bytes where public key will be written
 *
 * @param privkeylen [inout] valid pointer to integer.
 * If The integer at the pointer is set to zero before call,length of the private key is set on return
 * If the integer at the pointer is set to non-zero multiple of 8,it is unaltered on return and privkey
 * of this length is only valid
 *
 * @param privkey    [out] valid pointer to buffer of where private key will be written.
 * If privkeylen points to an integer of zero value,length of this buffer should be atleast modlen bytes.
 * If privkeylen points to an integer of non-zero multiple of 8,length of this buffer should be that integer.
 *
 * @return 0 on success and error code on failure.
 * @return  Failure: Non-zero (@ref cerr for Error codes)
 */

static inline int dh_generate_key_pair2(unsigned int  modlen,
                                        unsigned char *modulus,
                                        unsigned int  baselen,
                                        unsigned char *base,
                                        unsigned int  *pubkeylen,
                                        unsigned char *pubkey,
                                        unsigned int  *privkeylen,
                                        unsigned char *privkey)
{
    return dh_generate_key_pair_generic(modlen, modulus, baselen, base,
	                                     pubkeylen, pubkey, privkeylen,
													 privkey, NULL);
}



/**
 * It computes the shared secret from the private DH value and the other 
 * party's public key value and stores it in shared_secret.
 * 
 * Input arguments :
 * @param modulus_length the length in bytes of the modulus.
 * @param modulus the pointer to a buffer which contains the modulus.
 * @param peer_public_key the pointer to a buffer which contains the peer 
 * public key, whose size must match the size of the modulus. If the size
 * does not match, use dh_generate_shared_secret2()
 * @param my_private_key the pointer to a buffer which contains the 
 * private key whose size is same as the base.
 *
 * Output argument :
 * @param shared_secret the pointer to a pre-allocate buffer which will 
 *  save the shared secret generated from this function. The size of the 
 *  ouput is same as modulus.
 *
 * @return 0 on success and error code on failure.
 * @return  Failure: Non-zero (@ref cerr for Error codes)
*/
int dh_generate_shared_secret (int modulus_length,
  unsigned char *modulus,
  unsigned char *peer_public_key,
  unsigned char *my_private_key, unsigned char *shared_secret);


/**
 * It computes the shared secret from the private DH value and the
 * other party's public key value and stores it in shared_secret.
 *
 * @param modlen [in] length of modulus in bytes
 * @param mod    [in] pointer to buffer which contains the modulus
 * @param peerpubkeylen [in] length of the peer's public key in bytes
 * @param peerpubkey    [in] pointer to buffer which contains the peer public key
 * @param myprivkeylen  [in] length of our private in bytes
 * @param myprivkey     [in] pointer to buffer which contains our private key
 *
 * @param shared_secret_len [out] pointer to integer where the length of the shared secret will be returned.
 * @param shared_secret     [out] pointer to buffer of atleast modlen bytes,where shared secret will be written.
 *
 * @return 0 on success and error code on failure.
 * @return  Failure: Non-zero (@ref cerr for Error codes)
 */

int dh_generate_shared_secret2(
  unsigned int  modlen,
  unsigned char *mod,
  unsigned int  peerpubkeylen,
  unsigned char *peerpubkey,
  unsigned int  myprivkeylen,
  unsigned char *myprivkey,
  unsigned int  *shared_secret_len,
  unsigned char *shared_secret
);



/** 
 * It generates a key pair. Key sizes with modulus_length less than 1024 
 * bits should be considered insecure.
 * 
 * Input arguments :
 * @param rsast pointer to rsa_st_t structure having following parameters.
 *
 * rsast.modulus_length pointer to a buffer where the newly created 
 * modulus will be written.
 * rsast.e_ptr pointer to a buffer where the exponent to be used. 
 *
 * Output arguments :
 * rsast.n_ptr pointer to a buffer where the newly created modulus 
 * will be written.
 *
 * rsast.p_ptr pointer to a buffer where the newly created RSA prime 
 * p will be written.
 *
 * rsast.q_ptr pionter to a buffer where the newly created RSA prime 
 * q will be written.
 *
 * rsast.d_ptr pointer to a buffer where the newly created RSA private 
 * exponent d will be written.
 *
 * rsast.dp_ptr pointer to a buffer where the newly created RSA private 
 * exponent dp will be written.
 *
 * rsast.dq_ptr pointer to a buffer where the newly created RSA private 
 * dq will be written.
 *
 * rsast.pinv_ptr pointer to a buffer where the newly created RSA 
 * coefficient 'pinv' will be written.
 *
 * rsast.nlen length of the newly created modulus.
 *
 * rsast.plen length of the newly created RSA prime p.
 *
 * rsast.qlen length of the newly created RSA prime q.
 *
 * rsast.dlen length of the newly created private exponent d.
 *
 * rsast.dplen length of the newly created private exponent dp.
 *
 * rsast.dqlen length of the newly created RSA private exponent dq.
 *
 * rsast.pinvlen length of the newly created RSA coefficient pinv.
 *
 * @param cb [in] Callback function pointer. This function is called whenever a CRNG test failure
 *                         occurs. Can be NULL.
 * @return 0 on success and error code on failure.
 * @return 0 on success and error code on failure.
 * @return  Failure: Non-zero (@ref cerr for Error codes)
 * 
 * Note : It is the responsibility of the application to allocate sufficient 
 * memory to above parameters before calling this API.
 */
int rsa_create_key_pair_generic(rsa_st_t * rsast, callback_handle_t cb);

static inline int rsa_create_key_pair(rsa_st_t *rsast)
{
	return rsa_create_key_pair_generic(rsast, NULL);
}


/**
 * This encrypts the 'input_data_length' bytes at 'input_data' using the 
 * private key 'rsast' and stores the result in 'output_data'.
 *
 * Input arguments : 
 * @param rsast RSA parameters which have been generated, including the 
 * private key.
 * @param input_data_length the number of bytes of input data.
 * @param input_data the pointer to the buffer containing the data.
 *
 * Output arguments :
 * @param output_data the pointer to the buffer containing the encrypted data.
 * @param output_data_length pointer to the output data length.
 * @param padding either RSA_PKCS1_PADDING or RSA_NO_PADDING
 *
 * @return 0 on success and error code on failure.
 * @return  Failure: Non-zero (@ref cerr for Error codes)
 */
int rsa_encrypt_with_private_key (rsa_st_t * rsast,
  unsigned int input_data_length,
  unsigned char *input_data,
  unsigned int *output_data_length, unsigned char *output_data,
  int padding);


/**
 * This decrypts the 'input_data_length' bytes at 'input_data' using the 
 * private key 'rsast' and stores the result in 'output_data'.
 *
 * Input arguments : 
 * @param rsast RSA parameters which have been generated, including the 
 * private key.
 * @param input_data_length the number of bytes of input data.
 * @param input_data the pointer to the buffer containing the data.
 *
 * Output arguments :
 * @param output_data the pointer to the buffer containing the decrypted data.
 * @param output_data_length pointer to the output data length.
 * @param padding either RSA_PKCS1_PADDING or RSA_NO_PADDING
 *
 * @return 0 on success .
 * @return  Failure: Non-zero (@ref cerr for Error codes)
 */
int rsa_decrypt_with_private_key (rsa_st_t * rsast,
  unsigned int input_data_length,
  unsigned char *input_data,
  unsigned int *output_data_length, unsigned char *output_data,
  int padding);

/**
 * This API encrypts 'input_data_length' bytes at 'input_data' using 
 * public key 'rsa' and stores the result in 'ouput_data'.
 * 
 * Input arguments :
 * @param rsast RSA parameters which have been generated, including public key.
 * @param input_data_length the length of the input buffer.
 * @param input_data the pointer to the input buffer.
 *
 * Output arguments :
 * @param output_data the pointer to the ouput buffer containing the 
 * encrypted data.
 * @param output_data_length pointer to the length of the output data.
 * @param padding either RSA_PKCS1_PADDING or RSA_NO_PADDING
 * @param callback   Callback function pointer. This function is called whenever a CRNG test failure occurs, can be NULL.
 * @return 0 on success and error code on failure.
 *
 * @return 0 on success and error code on failure.
 * @return  Failure: Non-zero (@ref cerr for Error codes)
 */
int rsa_encrypt_with_public_key_generic(rsa_st_t * rsast,
  unsigned int input_data_length,
  unsigned char *input_data,
  unsigned int *output_data_length, unsigned char *output_data,
  int padding, callback_handle_t callback);

/**
 * This API encrypts 'input_data_length' bytes at 'input_data' using 
 * public key 'rsa' and stores the result in 'ouput_data'.
 * 
 * Input arguments :
 * @param rsast RSA parameters which have been generated, including public key.
 * @param input_data_length the length of the input buffer.
 * @param input_data the pointer to the input buffer.
 *
 * Output arguments :
 * @param output_data the pointer to the ouput buffer containing the 
 * encrypted data.
 * @param output_data_length pointer to the length of the output data.
 * @param padding either RSA_PKCS1_PADDING or RSA_NO_PADDING
 *
 * @return 0 on success and error code on failure.
 * @return  Failure: Non-zero (@ref cerr for Error codes)
 */
static inline int rsa_encrypt_with_public_key (rsa_st_t * rsast,
  unsigned int input_data_length,
  unsigned char *input_data,
  unsigned int *output_data_length, unsigned char *output_data,
  int padding) {
	return rsa_encrypt_with_public_key_generic(rsast,
			input_data_length, input_data,
			output_data_length, output_data,
			padding, NULL);
}


/**
 * This API decrypts 'input_data_length' bytes at 'input_data' using 
 * public key 'rsa' and stores the result in 'ouput_data'.
 * 
 * Input arguments :
 * @param rsast RSA parameters which have been generated, including public key.
 * @param input_data_length the length of the input buffer.
 * @param input_data the pointer to the input buffer.
 *
 * Output arguments :
 * @param output_data the pointer to the ouput buffer containing the 
 * decrypted data.
 * @param output_data_length pointer to the length of the output data.
 * @param padding either RSA_PKCS1_PADDING or RSA_NO_PADDING
 *
 * @return 0 on success and error code on failure.
 * @return  Failure: Non-zero (@ref cerr for Error codes)
 */
int rsa_decrypt_with_public_key (rsa_st_t * rsast,
  unsigned int input_data_length,
  unsigned char *input_data,
  unsigned int *output_data_length, unsigned char *output_data,
  int padding);

/*
 * Generates primes p, q and generator g for use in the DSA.
 *
 * @param bits [in] Length of prime to be generated
 * @param seed [in] seed will be used to generate the primes,can be NULL.
 * @param seed_len [in] Length of seed in bytes
 * @param counter_ret [out] iteration count is placed here
 * @param h_ret [out]  counter used for generating g is placed here.
 * @param callback [in] callback function pointer when CRNG test fails. can be NULL.
 * @param status [out] If function fails, the error code is placed in *status.
 * @return DSA   pointer to the dsa structure
 * @return  NULL on failure, the status field points to the error condition
 */
DSA *
dsa_generate_params(int bits, unsigned char *seed, int seed_len,
                    int *counter_ret, unsigned long *h_ret,
						  callback_handle_t callback, int *status);

/**
 * This API is used for message authentication, which is based on hash 
 * algorithm type.
 * 
 * Input arguments : 
 * @param type type of the hashing value (HMACMD5 or HMACSHA1)
 * @param key_length the length of the key string.
 * @param key pointer to the hmac key string.
 * @param inbuff pointer to the list of input buffers where each buffer is a 
 * struct of (size, data and next), where size is the size of data, 
 * 'data' is the pointer to the buffer and 'next' is the pointer to the 
 * next buffer.
 * 
 * Output arguments :
 * @param hash_result pointer to the bufffer containing the hash result. 
 * The size of the buffer must match the hash algorithm type.
 *
 * @return 0 on success and error code on failure.
 * @return  Failure: Non-zero (@ref cerr for Error codes)
 */
int hmac (int type, int key_length, unsigned char *key,
  buffers_t * inbuff, unsigned char *hash_result);


/**
 * This API encrypts the input data in 'inbuff' (struct containing size, 
 * data and next pointer) and stores the resultant encrypted data in 
 * 'outbuff' (struct containing size, data and next pointer). 
 *
 * Input arguments :
 * @param type DES algorithm type (SINGLEDES or TRIPLEDES)
 * @param key pointer to the key string. Size of the key should match DES 
 * algorithm type.
 * @param iv pointer to the IV string whose size must match the algorithm 
 * type. 'iv' will change after computation.
 * @param inbuff pointer to the list of input buffers which are the struct 
 * of (size, data and next), where size is the size of the data contained in
 * the buffer; 'data' is the pointer to the buffer; and 'next' is the 
 * pointer to the next buffer. Input size should be multiple of block size.
 *
 * Output arguments :
 * @param outbuff pointer to the list of output buffers.
 *
 * @return 0 on success and error code on failure.
 * @return  Failure: Non-zero (@ref cerr for Error codes)
 *
 */
int des_encrypt (int type, unsigned char *key, unsigned char *iv,
  buffers_t * inbuff, buffers_t * outbuff);


/**
 * This API decrypts the encrypted data in 'inbuff' (struct containing size, 
 * data and next pointer) and stores the resultant decrypted data in 
 * 'outbuff' (struct containing size, data and next pointer). 
 *
 * Input arguments :
 * @param type DES algorithm type (SINGLEDES or TRIPLEDES)
 * @param key pointer to the key string. Size of the key should match DES 
 * algorithm type.
 * @param iv pointer to the IV string whose size must match the algorithm 
 * type. 'iv' will change after computation.
 * @param inbuff pointer to the list of input buffers which are the struct 
 * of (size, data and next), where size is the size of the data contained in
 * the buffer; 'data' is the pointer to the buffer; and 'next' is the 
 * pointer to the next buffer. Input size should be multiple of block size. 
 *
 * Output arguments :
 * @param outbuff pointer to the list of output buffers.
 *
 * @return 0 on success and error code on failure.
 * @return  Failure: Non-zero (@ref cerr for Error codes)
 */
int des_decrypt (int type, unsigned char *key, unsigned char *iv,
  buffers_t * inbuff, buffers_t * outbuff);


/**
 * This API encrypts the input data in 'inbuff' (struct containing size, 
 * data and next pointer) and stores the resultant encrypted data in 
 * 'outbuff' (struct containing size, data and next pointer). 
 *
 * Input arguments : 
 * @param type AES algorithm type (AES128_CBC, AES192_CBC, AES256_CBC)
 * @param key pointer to the key string. Size of the key should match the DES
 * algorithm type.
 * @param iv pointer to the IV string whose size must match the algorithm i
 * type. iv will change after computation.
 * @param inbuff pointer to the list of input buffers which are the struct 
 * of (size, data and next), where size is the size of the data contained in
 * the buffer; 'data' is the pointer to the buffer; and 'next' is the 
 * pointer to the next buffer. Input size should be multiple of block size.
 *
 * Output arguments : 
 * @param outbuff pointer to the list of output buffers (struct containing 
 * size, data and next pointer).
 * 
 * @return 0 on success and error code on failure.
 * @return  Failure: Non-zero (@ref cerr for Error codes)
 */
int aes_encrypt (int type, unsigned char *key, unsigned char *iv,
  buffers_t * inbuff, buffers_t * outbuff);


/**
 * This API decrypts the input data in 'inbuff' (struct containing size, 
 * data and next pointer) and stores the resultant decrypted data in 
 * 'outbuff' (struct containing size, data and next pointer). 
 *
 * Input arguments : 
 * @param type AES algorithm type (AES128_CBC, AES192_CBC, AES256_CBC)
 * @param key pointer to the key string. Size of the key should match the
 * AES algorithm type.
 * @param iv pointer to the IV string whose size must match the algorithm 
 * type. iv will change after computation.
 * @param inbuff pointer to the list of input buffers which are the struct 
 * of (size, data and next), where size is the size of the data contained in
 * the buffer; 'data' is the pointer to the buffer; and 'next' is the 
 * pointer to the next buffer. Input size should be multiple of block size. 
 *
 * Output arguments : 
 * @param outbuff pointer to the list of output buffers (struct containing 
 * size, data and next pointer).
 * 
 * @return 0 on success and error code on failure.
 * @return  Failure: Non-zero (@ref cerr for Error codes)
 */
int aes_decrypt (int type, unsigned char *key, unsigned char *iv,
  buffers_t * inbuff, buffers_t * outbuff);

/**
 * @page cerr How to Interpret the API Errors.
 *
 * The return value is an error code from the thread's error queue.
 *
 * To interpret the Error Number:
 *
 *       ERR_error_sting needs to be called with error code returned
 * as the first argument.
 *
 * Example:
 * @code
 *        printf("Error is %s: \n", ERR_error_string(ret, NULL));
 * @endcode
 *   
 * Sample output for errno (0x0306E06C):
 * @code
 *     Error is error:0306E06C:lib(3):func(110):reason(108)
 * @endcode
 *
 *  Open the file include/openssl/err.h
 *   and search for the library numbers
 *
 * In this example library number returned is 3
 * @code
 *       #define ERR_LIB_BN        3
 * @endcode       
 *        So the error is in BN library.
 *
 * Now open corresponding header files.
 *   In this case, it is include/openssl/bn.h 
 * 
 * Search for Function codes and Reason codes section.
 *
 *     In this case, 
 *           Function code = 110 and  Reason code = 108
 *
 * @code
 *        #define BN_F_BN_MOD_INVERSE                              110
 *        #define BN_R_NO_INVERSE                                  108
 * @endcode
 *
 * So, the function which caused the error is BN_mod_inverse() and the
 * reason is "No Inverse" was found.
 *    
 **/

/**
 * Note : It is responsibility of the application to allocate sufficient 
 * memory to input and output buffers for all the APIs. In case of 
 * input/output buffer being linked lists, it is the responsibity of the 
 * application to terminate it properly.
 */
#endif
