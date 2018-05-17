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


#include <string.h>
#include "openssl/crypto-generic-api.h"

#define DH_err(f,r)  ERR_PUT_error(CGAPI_ERR_LIB_DH,(f),(r),__FILE__,__LINE__)
#define RSA_err(f,r) ERR_PUT_error(CGAPI_ERR_LIB_RSA,(f),(r),__FILE__,__LINE__)
#define DES_err(f,r) ERR_PUT_error(CGAPI_ERR_LIB_DES,(f),(r),__FILE__,__LINE__)
#define AES_err(f,r) ERR_PUT_error(CGAPI_ERR_LIB_AES,(f),(r),__FILE__,__LINE__)
#define HMAC_err(f,r) ERR_PUT_error(CGAPI_ERR_LIB_HMAC,(f),(r),__FILE__,__LINE__)

#define AES_KEY_Check \
if (ret != 0)  { \
    AES_err (AES_F_CGAPI_ENCRYPT, AES_R_CGAPI_WRONG_KEY); \
    goto err; \
}

#define RSASetKey(rsa) \
    rsa->n = BN_bin2bn (rsast->n_ptr, rsast->nlen, NULL);  \
    rsa->e = BN_bin2bn ((unsigned char*)rsast->e_ptr, sizeof(unsigned long), NULL);    \
    rsa->p = BN_bin2bn (rsast->p_ptr, rsast->plen, NULL); \
    rsa->q = BN_bin2bn (rsast->q_ptr, rsast->qlen, NULL); \
    rsa->d = BN_bin2bn (rsast->d_ptr, rsast->dlen, NULL); \
    rsa->dmp1 = BN_bin2bn (rsast->dp_ptr, rsast->dplen, NULL);  \
    rsa->dmq1 = BN_bin2bn (rsast->dq_ptr, rsast->dqlen, NULL); \
    rsa->iqmp = BN_bin2bn (rsast->pinv, rsast->pinvlen, NULL); \
    \
    if ((rsa->n == NULL) || (rsa->e == NULL) || (rsa->p == NULL) || \
        (rsa->q == NULL) || (rsa->d == NULL) || (rsa->dmp1 == NULL) || \
        (rsa->dmq1 == NULL) || (rsa->iqmp == NULL))  { \
        RSA_err (RSA_F_CGAPI_RSA_PRIVATE_ENCRYPT, CGAPI_R_BAD_BIN2BN); \
        goto err;  \
    }

typedef void (*FuncPtr) (unsigned char *, unsigned char *, int,
  unsigned char *, void *, void *, void *);


int dh_generate_key_pair_generic(
  unsigned int  modlen,
  unsigned char *modulus,
  unsigned int  baselen,
  unsigned char *base,
  unsigned int  *pubkeylen,
  unsigned char *pubkey,
  unsigned int  *privkeylen,
  unsigned char *privkey,
  callback_handle_t callback
)
{
  DH *dh = NULL;
  int ret = 0;

  dh = DH_new ();
  if (dh == NULL) {
    DH_err (DH_F_CGAPI_DH_GENERATE_KEY_PAIR, CGAPI_R_MEMORY_ALLOC_FAIL);
    goto err;
  }

  dh->p = BN_bin2bn (modulus, modlen, NULL);
  if (dh->p == NULL) {
    DH_err (DH_F_CGAPI_DH_GENERATE_KEY_PAIR, CGAPI_ERR_LIB_BIGNUM);
    goto err1;
  }

  dh->g = BN_bin2bn (base, baselen, NULL);
  if (dh->g == NULL) {
    DH_err (DH_F_CGAPI_DH_GENERATE_KEY_PAIR, CGAPI_ERR_LIB_BIGNUM);
    goto err1;
  }

  if(*privkeylen==0) {
    ERR_clear_error();
    ret = DH_generate_key(dh);
    while (!ret) {
      ret = ERR_get_error();
      if (ret != OCT_CRNG_FAIL_CODE) {
         DH_err (DH_F_CGAPI_DH_GENERATE_KEY_PAIR, DH_R_CGAPI_BAD_GENERATOR);
         goto err1;
      }
      if (callback)
         callback(DH_F_CGAPI_DH_GENERATE_KEY_PAIR, ERR_R_RAND_CRNG_FAILURE);
       
      ERR_clear_error();
      ret = DH_generate_key(dh);
    }
    *privkeylen = BN_num_bytes(dh->priv_key);
  } else {
    dh->length = (*privkeylen)*8;
    ERR_clear_error();
    ret = DH_generate_key(dh);
    while (!ret) {
      ret = ERR_get_error();
       if (ret != OCT_CRNG_FAIL_CODE) {
         DH_err (DH_F_CGAPI_DH_GENERATE_KEY_PAIR, DH_R_CGAPI_BAD_GENERATOR);
         goto err1;
      }
      if (callback)
         callback(DH_F_CGAPI_DH_GENERATE_KEY_PAIR, ERR_R_RAND_CRNG_FAILURE);
       
      ERR_clear_error();
      ret = DH_generate_key(dh);
    }
  }

  if (!BN_bn2bin (dh->priv_key, privkey)) {
    DH_err (DH_F_CGAPI_DH_GENERATE_KEY_PAIR, CGAPI_ERR_LIB_BIGNUM);
    goto err1;
  }

  if (!BN_bn2bin (dh->pub_key, pubkey)) {
    DH_err (DH_F_CGAPI_DH_GENERATE_KEY_PAIR, CGAPI_ERR_LIB_BIGNUM);
    goto err1;
  }
  *pubkeylen = BN_num_bytes(dh->pub_key);

  DH_free (dh);
  return 0;

err1:
  DH_free (dh);

err:
  if (!ret)
    ret = ERR_get_error ();
  ERR_clear_error();
  return ret;
}
int
dh_generate_shared_secret (int modulus_length, unsigned char *modulus,
  unsigned char *peer_public_key, unsigned char *my_private_key, 
  unsigned char *shared_secret)
{
  DH *dh = NULL;
  int dhsize, ret;
  BIGNUM *pub = NULL;

  ERR_clear_error();
  dh = DH_new ();
  if (dh == NULL) {
    DH_err (DH_F_CGAPI_DH_GENERATE_SHARED_SECRET,
      CGAPI_R_MEMORY_ALLOC_FAIL);
    goto err;
  }


  dh->p = BN_bin2bn (modulus, modulus_length, NULL);
  if (dh->p == NULL) {
    DH_err (DH_F_CGAPI_DH_GENERATE_SHARED_SECRET, CGAPI_ERR_LIB_BIGNUM);
    goto err1;
  }

  dh->priv_key = BN_bin2bn (my_private_key, modulus_length, NULL);
  if (dh->priv_key == NULL) {
    DH_err (DH_F_CGAPI_DH_GENERATE_SHARED_SECRET, CGAPI_ERR_LIB_BIGNUM);
    goto err1;
  }

  pub = BN_bin2bn (peer_public_key, modulus_length, NULL);
  if (pub == NULL) {
    DH_err (DH_F_CGAPI_DH_GENERATE_SHARED_SECRET, CGAPI_ERR_LIB_BIGNUM);
    goto err1;
  }

  dhsize = DH_compute_key (shared_secret, pub, dh);
  if (dhsize > DH_size (dh)) {
    DH_err (DH_F_CGAPI_DH_GENERATE_SHARED_SECRET,
      DH_R_CGAPI_BAD_SHARED_KEY);
    goto err1;
  }

  if(dhsize<0) {
    DH_err (DH_F_CGAPI_DH_GENERATE_SHARED_SECRET,
      DH_R_CGAPI_BAD_SHARED_KEY);
    goto err1;
  }

  if(dhsize<modulus_length) {
    memmove(shared_secret+(modulus_length-dhsize),shared_secret,dhsize);
    memset(shared_secret,0,(modulus_length-dhsize));
  }


  BN_free (pub);
  DH_free (dh);
  return 0;

err1:
  DH_free (dh);

err:
  ret = ERR_get_error ();
  ERR_clear_error();
  return ret;
}

int dh_generate_shared_secret2(
  unsigned int  modlen,
  unsigned char *mod,
  unsigned int  peerpubkeylen,
  unsigned char *peerpubkey,
  unsigned int  myprivkeylen,
  unsigned char *myprivkey,
  unsigned int  *shared_secret_len,
  unsigned char *shared_secret
)
{
  DH *dh = NULL;
  int dhsize, ret;
  BIGNUM *pub = NULL;

  ERR_clear_error();
  dh = DH_new ();
  if (dh == NULL) {
    DH_err (DH_F_CGAPI_DH_GENERATE_SHARED_SECRET,
      CGAPI_R_MEMORY_ALLOC_FAIL);
    goto err;
  }


  dh->p = BN_bin2bn (mod,modlen, NULL);
  if (dh->p == NULL) {
    DH_err (DH_F_CGAPI_DH_GENERATE_SHARED_SECRET, CGAPI_ERR_LIB_BIGNUM);
    goto err1;
  }

  dh->priv_key = BN_bin2bn (myprivkey,myprivkeylen, NULL);
  if (dh->priv_key == NULL) {
    DH_err (DH_F_CGAPI_DH_GENERATE_SHARED_SECRET, CGAPI_ERR_LIB_BIGNUM);
    goto err1;
  }

  pub = BN_bin2bn (peerpubkey,peerpubkeylen, NULL);
  if (pub == NULL) {
    DH_err (DH_F_CGAPI_DH_GENERATE_SHARED_SECRET, CGAPI_ERR_LIB_BIGNUM);
    goto err1;
  }

  dhsize = DH_compute_key (shared_secret, pub, dh);
  if (dhsize > DH_size (dh)) {
    DH_err (DH_F_CGAPI_DH_GENERATE_SHARED_SECRET,
      DH_R_CGAPI_BAD_SHARED_KEY);
    goto err1;
  }

  if(dhsize<0) {
    DH_err (DH_F_CGAPI_DH_GENERATE_SHARED_SECRET,
      DH_R_CGAPI_BAD_SHARED_KEY);
    goto err1;
  }

  *shared_secret_len = dhsize;

  BN_free (pub);
  DH_free (dh);
  return 0;

err1:
  DH_free (dh);

err:
  ret = ERR_get_error ();
  ERR_clear_error();
  return ret;
}

int
rsa_create_key_pair_generic(rsa_st_t * rsast, callback_handle_t callback)
{
  RSA *rsa = NULL;
  int ret = 0;

  ERR_clear_error();
  rsa = RSA_generate_key_generic (rsast->modulus_length, *rsast->e_ptr, NULL, NULL, 
                                  callback, RSA_F_CGAPI_RSA_GENERATE_KEY_PAIR);
  while (rsa == NULL) {
    ret = ERR_get_error();
    if (ret != OCT_CRNG_FAIL_CODE) {
       ERR_clear_error();
       return ret;
    }
    if (callback)
       callback(RSA_F_CGAPI_RSA_GENERATE_KEY_PAIR, ERR_R_RAND_CRNG_FAILURE);
    ERR_clear_error();
    rsa = RSA_generate_key_generic (rsast->modulus_length, *rsast->e_ptr, NULL, NULL,
                                    callback, RSA_F_CGAPI_RSA_GENERATE_KEY_PAIR);
  }

  rsast->nlen = BN_bn2bin (rsa->n, rsast->n_ptr);
  rsast->plen = BN_bn2bin (rsa->p, rsast->p_ptr);
  rsast->qlen = BN_bn2bin (rsa->q, rsast->q_ptr);
  rsast->dlen = BN_bn2bin (rsa->d, rsast->d_ptr);
  rsast->dplen = BN_bn2bin (rsa->dmp1, rsast->dp_ptr);
  rsast->dqlen = BN_bn2bin (rsa->dmq1, rsast->dq_ptr);
  rsast->pinvlen = BN_bn2bin (rsa->iqmp, rsast->pinv);

  if ((rsast->nlen != (unsigned int )BN_num_bytes (rsa->n)) ||
    (rsast->plen != (unsigned int )BN_num_bytes (rsa->p)) ||
    (rsast->qlen != (unsigned int )BN_num_bytes (rsa->q)) ||
    (rsast->dlen != (unsigned int )BN_num_bytes (rsa->d)) ||
    (rsast->dplen != (unsigned int )BN_num_bytes (rsa->dmp1)) ||
    (rsast->dqlen != (unsigned int )BN_num_bytes (rsa->dmq1)) ||
    (rsast->pinvlen != (unsigned int )BN_num_bytes (rsa->iqmp))) {
    RSA_err (RSA_F_CGAPI_RSA_GENERATE_KEY_PAIR, CGAPI_ERR_LIB_BIGNUM);
    goto err1;
  }

  RSA_free (rsa);
  return 0;

err1:
  RSA_free (rsa);

  ret = ERR_get_error ();
  return ret;
}


int
rsa_encrypt_with_private_key (rsa_st_t * rsast,
  unsigned int input_data_length, unsigned char *input_data,
  unsigned int *output_data_length, unsigned char *output_data,
  int padding)
{
  RSA *rsa = NULL;
  int ret;

  ERR_clear_error();
  rsa = RSA_new ();
  if (rsa == NULL) {
    RSA_err (RSA_F_CGAPI_RSA_PRIVATE_ENCRYPT, CGAPI_R_MEMORY_ALLOC_FAIL);
    goto err;
  }

  RSASetKey (rsa);

  *output_data_length = RSA_private_encrypt (input_data_length,
    input_data, output_data, rsa, padding);

  if (*output_data_length != (unsigned int)RSA_size (rsa)) {
    RSA_err (RSA_F_CGAPI_RSA_PRIVATE_ENCRYPT,
      RSA_R_CGAPI_BAD_PRIVATE_ENCRYPT);
    goto err1;
  }

  RSA_free (rsa);
  return 0;

err1:
  RSA_free (rsa);

err:
  ret = ERR_get_error ();
  ERR_clear_error();
  return ret;
}


int
rsa_decrypt_with_public_key (rsa_st_t * rsast,
  unsigned int input_data_length, unsigned char *input_data,
  unsigned int *output_data_length, unsigned char *output_data,
  int padding)
{
  RSA *rsa = NULL;
  int ret;

  ERR_clear_error();
  rsa = RSA_new ();
  if (rsa == NULL) {
    RSA_err (RSA_F_CGAPI_RSA_PUBLIC_DECRYPT, CGAPI_R_MEMORY_ALLOC_FAIL);
    goto err;
  }

  RSASetKey (rsa);

  *output_data_length = RSA_public_decrypt (input_data_length,
    input_data, output_data, rsa, padding);

/*  if (*output_data_length == -1) {
    RSA_err (RSA_F_CGAPI_RSA_PUBLIC_DECRYPT,
      RSA_R_CGAPI_BAD_PUBLIC_DECRYPT);
    goto err1;
  }
*/
  RSA_free (rsa);
  return 0;

//err1:
 // RSA_free (rsa);

err:
  ret = ERR_get_error ();
  ERR_clear_error();
  return ret;
}



int
rsa_encrypt_with_public_key_generic (rsa_st_t * rsast,
  unsigned int input_data_length, unsigned char *input_data,
  unsigned int *output_data_length, unsigned char *output_data,
  int padding, callback_handle_t callback)
{
  RSA *rsa = NULL;
  int ret = 0;

  ERR_clear_error();
  rsa = RSA_new ();
  if (rsa == NULL) {
    RSA_err (RSA_F_CGAPI_RSA_PUBLIC_ENCRYPT, CGAPI_R_MEMORY_ALLOC_FAIL);
    goto err;
  }

  RSASetKey (rsa);

  do {
     *output_data_length = RSA_public_encrypt (input_data_length,
                                               input_data, output_data,
                                               rsa, padding);
     if (*output_data_length == (unsigned int) RSA_size (rsa))
        break;
     ret = ERR_get_error();
     if (ret != OCT_CRNG_FAIL_CODE)
        goto err1;
     if (callback)
        callback(RSA_F_CGAPI_RSA_PUBLIC_ENCRYPT,
                 ERR_R_RAND_CRNG_FAILURE);
     ERR_clear_error();
  } while (1);

  RSA_free (rsa);
  return 0;

err1:
  RSA_free (rsa);

err:
  if (!ret)
     ret = ERR_get_error ();
  ERR_clear_error();
  return ret;
}

int
rsa_decrypt_with_private_key (rsa_st_t * rsast,
  unsigned int input_data_length, unsigned char *input_data,
  unsigned int *output_data_length, unsigned char *output_data,
  int padding)
{
  RSA *rsa = NULL;
  int ret;

  ERR_clear_error();
  rsa = RSA_new ();
  if (rsa == NULL) {
    RSA_err (RSA_F_CGAPI_RSA_PRIVATE_DECRYPT, CGAPI_R_MEMORY_ALLOC_FAIL);
    goto err;
  }

  RSASetKey (rsa);

  *output_data_length = RSA_private_decrypt (input_data_length,
    input_data, output_data, rsa, padding);
/*  if (*output_data_length == -1) {
    RSA_err (RSA_F_CGAPI_RSA_PRIVATE_DECRYPT,
      RSA_R_CGAPI_BAD_PRIVATE_DECRYPT);
    goto err1;
  }
*/
  RSA_free (rsa);
  return 0;

/*err1:
  RSA_free (rsa);
*/
err:
  ret = ERR_get_error ();
  ERR_clear_error();
  return ret;
}


int
hmac (int type, int key_length, unsigned char *key, 
  buffers_t * inbuff, unsigned char *hash_result)
{
  unsigned int md_len = EVP_MAX_MD_SIZE;
  HMAC_CTX hmac_ctx;
  int ret;

  ERR_clear_error();
  HMAC_CTX_init (&hmac_ctx);

  if (HMACMD5 == type) {
    HMAC_Init (&hmac_ctx, key, key_length, EVP_md5 ());
  } else if (HMACSHA1 == type) {
    HMAC_Init (&hmac_ctx, key, key_length, EVP_sha1 ());
  } else if (HMACSHA224 == type) {
    HMAC_Init (&hmac_ctx, key, key_length, EVP_sha224 ());
  } else if (HMACSHA256 == type) {
    HMAC_Init (&hmac_ctx, key, key_length, EVP_sha256 ());
  } else if (HMACSHA384 == type) {
    HMAC_Init (&hmac_ctx, key, key_length, EVP_sha384 ());
  } else if (HMACSHA512 == type) {
    HMAC_Init (&hmac_ctx, key, key_length, EVP_sha512 ());
  } else {
    HMAC_err (HMAC_F_CGAPI, HMAC_F_CGAPI_WRONG_HMAC);
    goto err;
  }

  while (inbuff != NULL) {
    HMAC_Update (&hmac_ctx, inbuff->data, inbuff->size);
    inbuff = inbuff->next;
  }
  HMAC_Final (&hmac_ctx, hash_result, &md_len);
  HMAC_CTX_cleanup (&hmac_ctx);

  return 0;

err:
  ret = ERR_get_error ();
  ERR_clear_error();
  return ret;
}

DSA *
dsa_generate_params(int bits, unsigned char *seed, int seed_len,
                    int *counter_ret, unsigned long *h_ret,
                    callback_handle_t callback, int *status)
{
    DSA *dsa;

    ERR_clear_error();
    dsa = DSA_generate_parameters_generic(bits, seed, seed_len, 
                                       counter_ret, h_ret,
                                       NULL, NULL,
                                       callback, DSA_F_GENERATE_PARAMETERS);
    while (dsa == NULL) {
       int ret = ERR_get_error();
       if (ret != OCT_CRNG_FAIL_CODE) {
         *status = ret;
         ERR_clear_error();
         return dsa;
      }
      if (callback)
         callback(DSA_F_GENERATE_PARAMETERS, ERR_R_RAND_CRNG_FAILURE);
      ERR_clear_error();
      dsa = DSA_generate_parameters(bits, seed, seed_len, 
                                    counter_ret, h_ret,
                                     NULL, NULL);
    }
    return dsa;
}


inline static void
DesncbcEncrypt (unsigned char *in_ptr, unsigned char *out_ptr,
  int block_size, unsigned char *iv, void *ks1, void *ks2, void *ks3)
{
  DES_ncbc_encrypt (in_ptr, out_ptr, block_size, (DES_key_schedule *) ks1,
    (DES_cblock *) iv, DES_ENCRYPT);
}


inline static void
DesncbcDecrypt (unsigned char *in_ptr,
  unsigned char *out_ptr, int block_size, unsigned char *iv, 
  void *ks1, void *ks2, void *ks3)
{
  DES_ncbc_encrypt (in_ptr, out_ptr, block_size, (DES_key_schedule *) ks1,
    (DES_cblock *) iv, DES_DECRYPT);
}


inline static void
DesEde3CbcEncrypt (unsigned char *in_ptr,
  unsigned char *out_ptr, int block_size, unsigned char *iv, 
  void *ks1, void *ks2, void *ks3)
{
  DES_ede3_cbc_encrypt (in_ptr, out_ptr, block_size,
    (DES_key_schedule *) ks1, (DES_key_schedule *) ks2,
    (DES_key_schedule *) ks3, (DES_cblock *) iv, DES_ENCRYPT);
}


inline static void
DesEde3CbcDecrypt (unsigned char *in_ptr,
  unsigned char *out_ptr, int block_size, unsigned char *iv, 
  void *ks1, void *ks2, void *ks3)
{
  DES_ede3_cbc_encrypt (in_ptr, out_ptr, block_size,
    (DES_key_schedule *) ks1, (DES_key_schedule *) ks2,
    (DES_key_schedule *) ks3, (DES_cblock *) iv, DES_DECRYPT);
}


inline static void
AesCbcEncrypt (unsigned char *in_ptr,
  unsigned char *out_ptr, int block_size, unsigned char *iv, 
  void *key1, void *key2, void *key3)
{
  AES_cbc_encrypt (in_ptr, out_ptr, block_size, (AES_KEY *) key1,
    iv, AES_ENCRYPT);
}


inline static void
AesCbcDecrypt (unsigned char *in_ptr, unsigned char *out_ptr, 
  int block_size, unsigned char *iv, 
  void *key1, void *key2, void *key3)
{
  AES_cbc_encrypt (in_ptr, out_ptr, block_size, (AES_KEY *) key1,
    iv, AES_DECRYPT);
}


inline static int
min_block (int insize, int outsize, int block)
{
  int ret = (insize < outsize ? insize : outsize);
  if (ret < block) {
    return block;
  }
  if (ret % block) {
    ret = (ret / block) * block;
  }
  return ret;
}


static int
Parse_Link_List (buffers_t * inbuff, buffers_t * outbuff, 
  int block_size, FuncPtr pF, unsigned char *iv, 
  void *key1, void *key2, void *key3)
{
  unsigned char *indata_walk = NULL, *outdata_walk = NULL;
  unsigned char *in_ptr = NULL, *out_ptr = NULL;
  unsigned char buff_in[100], buff_out[100];
  int insize = inbuff->size;
  int outsize = outbuff->size;
  int outflag = 0, prev_size = 0;
  int this_loop_size = 0;

  in_ptr = inbuff->data;
  out_ptr = outbuff->data;
  indata_walk = inbuff->data;
  outdata_walk = outbuff->data;

  while (inbuff != NULL) {
    outflag = 0;
    this_loop_size = min_block (insize, outsize, block_size);
    if (insize >= block_size) {
      in_ptr = indata_walk;
      indata_walk += this_loop_size;
      insize -= this_loop_size;
    } else {
      memset (buff_in, 0, sizeof (buff_in));
      memcpy (buff_in, indata_walk, insize);
      inbuff = inbuff->next;
      if (inbuff == NULL)
        return -1;

      indata_walk = inbuff->data;
      do {
        if ((this_loop_size - insize) <= inbuff->size) {
          memcpy (buff_in + insize, indata_walk, this_loop_size - insize);
          prev_size = this_loop_size - insize;
          insize += (this_loop_size - insize);
          indata_walk += prev_size;
        } else {
          memcpy (buff_in + insize, indata_walk, inbuff->size);
          insize += inbuff->size;
          inbuff = inbuff->next;
          if (inbuff == NULL)
            return -1;

          indata_walk = inbuff->data;
        }
      } while (insize != this_loop_size);
      insize = inbuff->size - prev_size;
      in_ptr = buff_in;
    }

    if (outsize >= block_size) {
      out_ptr = outdata_walk;
      outdata_walk += this_loop_size;
      outsize -= this_loop_size;
      outflag = 0;
    } else {
      memset (buff_out, 0, sizeof (buff_out));
      out_ptr = buff_out;
      outflag = 1;
    }

    pF (in_ptr, out_ptr, this_loop_size, iv, key1, key2, key3);

    if (insize == 0) {
      inbuff = inbuff->next;
      if (inbuff != NULL) {
        insize = inbuff->size;
        indata_walk = inbuff->data;
      }
    }

    if (outflag == 1) {
      memcpy (outdata_walk, out_ptr, outsize);
      outbuff = outbuff->next;
      if ((outbuff == NULL) && (inbuff != NULL))
        return -2;

      outdata_walk = outbuff->data;
      do {
        if ((this_loop_size - outsize) <= outbuff->size) {
          memcpy (outdata_walk, out_ptr + outsize,
            (this_loop_size - outsize));
          prev_size = this_loop_size - outsize;
          outsize += (this_loop_size - outsize);
          outdata_walk += prev_size;
        } else {
          memcpy (outdata_walk, out_ptr + outsize, outbuff->size);
          outsize += outbuff->size;
          outbuff = outbuff->next;
          if ((outbuff == NULL) && (inbuff != NULL))
            return -2;
          outdata_walk = outbuff->data;
        }
      } while (outsize != this_loop_size);
      outsize = outbuff->size - prev_size;
    }
    if (outsize == 0) {
      outbuff = outbuff->next;
      if (outbuff != NULL) {
        outsize = outbuff->size;
        outdata_walk = outbuff->data;
      }
      if ((outbuff == NULL) && (inbuff != NULL))
        return -2;
    }
  }
  return 0;
}


int
des_encrypt (int type, unsigned char *key, unsigned char *iv, 
  buffers_t * inbuff, buffers_t * outbuff)
{
  int ret;
  unsigned char key1[8], key2[8], key3[8];
  DES_key_schedule ks1, ks2, ks3;

  memcpy (key1, key, 8);
  ERR_clear_error();

  ret = DES_set_key_checked ((const_DES_cblock *) key1, &ks1);
  if (ret != 0) {
    DES_err (DES_F_CGAPI_ENCRYPT, DES_R_CGAPI_WRONG_KEY);
    goto err;
  }
  if (SINGLEDES == type) {
    ret = Parse_Link_List (inbuff, outbuff, DES_BLOCK_SIZE, DesncbcEncrypt, iv,
            &ks1, NULL, NULL);
  } else if (TRIPLEDES == type) {
    memcpy (key2, key + 8, 8);
    memcpy (key3, key + 16, 8);

    ret = DES_set_key_checked ((const_DES_cblock *) key2, &ks2);
    if (ret != 0) {
      DES_err (DES_F_CGAPI_ENCRYPT, DES_R_CGAPI_WRONG_KEY);
      goto err;
    }

    ret = DES_set_key_checked ((const_DES_cblock *) key3, &ks3);
    if (ret != 0) {
      DES_err (DES_F_CGAPI_ENCRYPT, DES_R_CGAPI_WRONG_KEY);
      goto err;
    }

    ret = Parse_Link_List (inbuff, outbuff, DES_BLOCK_SIZE, DesEde3CbcEncrypt,
      iv, &ks1, &ks2, &ks3);
  } else {
    DES_err (DES_F_CGAPI_ENCRYPT, DES_R_CGAPI_WRONGDES);
    goto err;
  }

  /* Check return value from Parse_Link_List function */
  if (ret == -1) {    
    DES_err (DES_F_CGAPI_ENCRYPT, CGAPI_R_INVALID_BLOCK_OF_INPUT_SIZE);
    goto err;
  } else if (ret == -2) {
    DES_err (DES_F_CGAPI_ENCRYPT, CGAPI_R_INSUFFICIENT_OUTBUF);
    goto err;
  }

  return 0;

err:
  ret = ERR_get_error ();
  ERR_clear_error();
  return ret;
}


int
des_decrypt (int type, unsigned char *key, unsigned char *iv, 
  buffers_t * inbuff, buffers_t * outbuff)
{
  unsigned char key1[8], key2[8], key3[8];
  DES_key_schedule ks1, ks2, ks3;
  int ret;

  ERR_clear_error();

  memcpy (key1, key, 8);

  ret = DES_set_key_checked ((const_DES_cblock *) key1, &ks1);
  if (ret != 0) {
    DES_err (DES_F_CGAPI_DECRYPT, DES_R_CGAPI_WRONG_KEY);
    goto err;
  }

  if (SINGLEDES == type) {
    Parse_Link_List (inbuff, outbuff, DES_BLOCK_SIZE, DesncbcDecrypt, iv,
      &ks1, NULL, NULL);
  } else if (TRIPLEDES == type) {
    memcpy (key2, key + 8, 8);
    memcpy (key3, key + 16, 8);

    ret = DES_set_key_checked ((const_DES_cblock *) key2, &ks2);
    if (ret != 0) {
      DES_err (DES_F_CGAPI_DECRYPT, DES_R_CGAPI_WRONG_KEY);
      goto err;
    }

    ret = DES_set_key_checked ((const_DES_cblock *) key3, &ks3);
    if (ret != 0) {
      DES_err (DES_F_CGAPI_DECRYPT, DES_R_CGAPI_WRONG_KEY);
      goto err;
    }

    Parse_Link_List (inbuff, outbuff, DES_BLOCK_SIZE, DesEde3CbcDecrypt,
      iv, &ks1, &ks2, &ks3);
  } else {
    DES_err (DES_F_CGAPI_ENCRYPT, DES_R_CGAPI_WRONGDES);
    goto err;
  }

  /* Check return value from Parse_Link_List function */
  if (ret == -1) {    
    DES_err (DES_F_CGAPI_DECRYPT, CGAPI_R_INVALID_BLOCK_OF_INPUT_SIZE);
    goto err;
  } else if (ret == -2) {
    DES_err (DES_F_CGAPI_DECRYPT, CGAPI_R_INSUFFICIENT_OUTBUF);
    goto err;
  }

  return 0;

err:
  ret = ERR_get_error ();
  ERR_clear_error();
  return ret;
}


int
aes_encrypt (int type, unsigned char *key, unsigned char *iv, 
  buffers_t * inbuff, buffers_t * outbuff)
{
  AES_KEY akey;
  int ret;

  ERR_clear_error();
  if (AES128_CBC == type) {
    ret = AES_set_encrypt_key (key, 128, &akey);
    AES_KEY_Check;
  } else if (AES192_CBC == type) {
    ret = AES_set_encrypt_key (key, 192, &akey);
    AES_KEY_Check;
  } else if (AES256_CBC == type) {
    ret = AES_set_encrypt_key (key, 256, &akey);
    AES_KEY_Check;
  } else {
    AES_err (AES_F_CGAPI_ENCRYPT, AES_R_CGAPI_WRONGAES);
    goto err;
  }

  ret = Parse_Link_List (inbuff, outbuff, AES_BLOCK_SIZE, AesCbcEncrypt, iv,
    &akey, NULL, NULL);

  if (ret == -1)  {
    AES_err (AES_F_CGAPI_ENCRYPT, CGAPI_R_INVALID_BLOCK_OF_INPUT_SIZE);
    goto err;
  } else if (ret == -2)  {
    AES_err (AES_F_CGAPI_ENCRYPT, CGAPI_R_INSUFFICIENT_OUTBUF);
    goto err;
  }

  return 0;

err:
  ret = ERR_get_error ();
  ERR_clear_error();
  return ret;
}


int
aes_decrypt (int type, unsigned char *key, unsigned char *iv, 
  buffers_t * inbuff, buffers_t * outbuff)
{
  AES_KEY akey;
  int ret;

  ERR_clear_error();
  if (AES128_CBC == type) {
    ret = AES_set_decrypt_key (key, 128, &akey);
    AES_KEY_Check;
  } else if (AES192_CBC == type) {
    ret = AES_set_decrypt_key (key, 192, &akey);
    AES_KEY_Check;
  } else if (AES256_CBC == type) {
    ret = AES_set_decrypt_key (key, 256, &akey);
    AES_KEY_Check;
  } else {
    AES_err (AES_F_CGAPI_DECRYPT, AES_R_CGAPI_WRONGAES);
    goto err;
  }

  ret = Parse_Link_List (inbuff, outbuff, AES_BLOCK_SIZE, AesCbcDecrypt, iv,
          &akey, NULL, NULL);

  if (ret == -1)  {
    AES_err (AES_F_CGAPI_DECRYPT, CGAPI_R_INVALID_BLOCK_OF_INPUT_SIZE);
    goto err;
  } else if (ret == -2)  {
    AES_err (AES_F_CGAPI_DECRYPT, CGAPI_R_INSUFFICIENT_OUTBUF);
    goto err;
  }

  return 0;

err:
  ret = ERR_get_error ();
  ERR_clear_error();
  return ret;
}
