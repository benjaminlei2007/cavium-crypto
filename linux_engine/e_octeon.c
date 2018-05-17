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

/* @file e_octeon.c 
 *         OpenSSL Engine 
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <openssl/engine.h>
#include <openssl/des.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "cvmx.h"
#include "e_octeon_err.c"
#include "aes_gcm.h"
#ifdef OCTEON3
#include <camellia.h>
#endif
#include "des.h"
#include "modexp.h"
#include "aes.h"
#include "sha.h"
#include "md5.h"
#include "cryptolinux.h"

/*engine static variables */
static const char *octeon_engine_id = "octeon";
static const char *octeon_engine_name = "Cavium Octeon hardware Crypto support";
uint32_t cvmx_app_init_processor_id = 0;
#if _MIPS_SIM == _ABIN32
typedef uint32_t cvm_ptr_long_t;
#elif _MIPS_SIM == _ABI64
typedef uint64_t cvm_ptr_long_t;
#else
#error "Unsupported ABI"
#endif

//#define OCT_ENGINE_DEBUG
#ifdef OCT_ENGINE_DEBUG
#define DBG(fmt, arg...) do {					\
    printf("[%s:%d] " fmt "\n", __func__, __LINE__, ##arg);	\
} while (0)
#else
#define DBG(fmt, arg...)
#endif

/**
 * Initialization function
 *
 * @param e pointer to Engine structure which stores implementations 
 *          of various crypto  algorithms and functions.
 * 
 * @return 1 on success, 0 on failure
 */
static int
octeon_init(ENGINE *e)
{
    printf("Octeon_init success\n");
    return OCT_SUCCESS;
}

/**
 * Shutdown function
 *
 * @param e pointer to Engine structure which stores implementations 
 *          of various crypto  algorithms and functions.
 *
 * @return 1 on success, 0 on failure
 */
static int
octeon_shutdown(ENGINE *e)
{
    return OCT_SUCCESS;
}
/**
 * Unloads Octeon error Strings
 *
 * @param e pointer to Engine structure which stores implementations 
 *          of various crypto  algorithms and functions.
 * 
 * @return 1 on success, 0 on failure
 */
static int
octeon_destroy(ENGINE *e)
{
    ERR_unload_OCTEON_strings();
    return OCT_SUCCESS;
}

/**
 * Control Commands that can be sent by applications (Not used as of now)
 */
static int
octeon_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    return OCT_SUCCESS;
}

#ifndef OPENSSL_NO_RSA

/** 
 * oct_eng_rsa_mod_exp
 *
 * RSA computation of r0 = r0 ^ I mod rsa->n  
 *
 * \retval SUCCESS 1
 * \retval FAILURE 0
 */
static int
oct_eng_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
   int ret;
   ret = oct_mod_exp_crt(r0, (BIGNUM *)I, rsa);
   if (ret != OCT_SUCCESS)
      OCTEONerr(OCTEON_F_OCT_ENG_RSA_MOD_EXP, OCTEON_R_MOD_EXP_CRT_FAILURE);
   return ret;
}

/** 
 *   oct_eng_bn_mod_exp
 *  
 *   RSA computation of r = a ^ p mod m  
 *   \retval SUCCESS 1
 *   \retval FAILURE 0
 */

static int
oct_eng_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
                   BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
   int ret;
   ret = oct_mod_exp(r, (BIGNUM *)a, (BIGNUM *)p, (BIGNUM *)m, ctx);
   if (ret != OCT_SUCCESS)
      OCTEONerr(OCTEON_F_OCT_ENG_BN_MOD_EXP, OCTEON_R_MOD_EXP_FAILURE);
   return ret;
}

/* RSA Method providing pointers to the offloaded functions */
static RSA_METHOD octeon_rsa =
{
   "Octeon RSA Method",
   NULL,                                      /* RSA Public Encrypt */
   NULL,                                       /* RSA Public Decrypt */
   NULL,                                      /* RSA Private Encrypt */
   NULL,                                      /* RSA Private Decrypt */
   oct_eng_rsa_mod_exp,                      /* RSA Mod Exp (ModExp CRT) */
   oct_eng_bn_mod_exp,                       /* BN Mod Exp (ModExp) */
   NULL,                                     /* Init */
   NULL,                                     /* Finish */
   0,                                          /* Flags : Calls 
                             sign/verify instead of pub_decrypt/priv_encr */
   NULL,                                       /* app_data: ?? */
   NULL,                                       /* RSA sign */
   NULL,                                      /* RSA verify */
   NULL
};

#endif /* OPENSSL_NO_RSA */

#ifndef OPENSSL_NO_DSA
/** 
 *   oct_eng_dsa_bn_mod_exp
 *     
 *   DSA computation of r = a ^ p mod m  
 *   \retval SUCCESS 1
 *   \retval FAILURE 0
 */   
static int
oct_eng_dsa_bn_mod_exp(DSA *dsa, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
   int ret;
   ret = oct_mod_exp(r, a, (BIGNUM *)p, (BIGNUM *)m, ctx);
   if (ret != OCT_SUCCESS)
      OCTEONerr(OCTEON_F_OCT_ENG_DSA_BN_MOD_EXP, OCTEON_R_MOD_EXP_FAILURE);
   return ret;
}
/** 
 *   oct_eng_dsa_mod_exp
 *     
 *   DSA computation of rr = a1^p1 * a2^p2 mod m  
 *   \retval SUCCESS 1
 *   \retval FAILURE 0
 */
static int oct_eng_dsa_mod_exp(DSA *dsa, BIGNUM *rr, BIGNUM *a1, BIGNUM *p1,
                               BIGNUM *a2, BIGNUM *p2, BIGNUM *m, BN_CTX *ctx,
                               BN_MONT_CTX *in_mont)
{
   BIGNUM t2;
   int ret = OCT_FAILURE;
   /* rr = t1, a1 = dsa->g , p1 =u1 , a2 = dsa->pub_key, p2 = u2, m = dsa->p*/
   BN_init(&t2);
   /* let rr = g ^ p1 mod m */
   if (!oct_mod_exp(rr,dsa->g,p1,dsa->p, ctx)) goto err;
   /* let t2 = a2 ^ p2 mod m */
   if (!oct_mod_exp(&t2,dsa->pub_key,p2,dsa->p,ctx)) goto err;
   /* let rr = rr * t2 mod m */
   if (!BN_mod_mul(rr,rr,&t2,dsa->p,ctx)) goto err;
   ret = OCT_SUCCESS;
err:
   BN_free(&t2);
   if (ret != OCT_SUCCESS)
      OCTEONerr(OCTEON_F_OCT_ENG_DSA_MOD_EXP, OCTEON_R_MOD_EXP_FAILURE);
   return ret;
}

/* DSA Method providing pointers to the offloaded functions */

static DSA_METHOD octeon_dsa =
{
   "Octeon DSA Method",
   NULL,                           /* DSA_do sign */
   NULL,
   NULL,                         /* DSA_do_verify */
   oct_eng_dsa_mod_exp,          /* DSA ModExp */
   oct_eng_dsa_bn_mod_exp,       /* ModExp */
   NULL,                         /* Init */
   NULL,                         /* Finish */
   0,                            /* Flags */
   NULL                          /* app_data ?? */
};
#endif /* OPENSSL_NO_DSA */

#ifndef OPENSSL_NO_DH
/**
 *   oct_eng_dh_mod_exp
 *   DH computaion of r = a ^ p mod m
 *   \retval SUCCESS 1
 *   \retval FAILURE 0
 */ 
static int
oct_eng_dh_mod_exp(const DH *dh, BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                   const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
   int ret;
   ret = oct_mod_exp(r, (BIGNUM *)a, (BIGNUM *)p, (BIGNUM *)m, ctx);
   if (ret != OCT_SUCCESS)
      OCTEONerr(OCTEON_F_OCT_ENG_DH_MOD_EXP, OCTEON_R_MOD_EXP_FAILURE);
   return ret;
}

/* DH Method providing pointers to the offloaded functions */

static DH_METHOD octeon_dh =
{
   "Octeon DH Method",
   NULL,                           /* Octeon DH generate key */
   NULL,                           /* Octeon DH compute key */
   oct_eng_dh_mod_exp,           /* ModExp */
   NULL,                         /* Init */
   NULL,                         /* Finish */
   0,                            /* Flags */
   NULL,                         /* app_data ?? */
   NULL            /* Generate parameters */
};
#endif /* OPENSSL_NO_DH */

#ifndef OCTEON_NO_CIPHERS

/**
 *   DES_EDE3 cipher structure: Contains info about des-ede3 cipher data
 */

typedef struct {
   int init_done;                           /* Initialization done */
   uint64_t iv;                             /* Running IV */
   uint64_t orig_iv;                        /* Inital IV */
   uint64_t key1;
   uint64_t key2;
   uint64_t key3;
}oct_des_ede3_cipher_data; 

#define OCT_DES_EDE3_CTX_SIZE sizeof(oct_des_ede3_cipher_data)
/**
 *  octeon_des_ede3_init
 *
 *  DES-EDE3 cipher initialisation function for Octeon engine
 *
 * \retval SUCCESS 1
 * \retval FAILURE 0
 */
static int
octeon_des_ede3_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                      const unsigned char *iv, int enc)
{
   uint64_t *key64 = (uint64_t *)key;
   oct_des_ede3_cipher_data *cipher_state = (oct_des_ede3_cipher_data *)ctx->cipher_data;

   cipher_state->key1      = key64[0];
   cipher_state->key2      = key64[1];
   cipher_state->key3      = key64[2];
   cipher_state->iv        = *(uint64_t *)iv;
   cipher_state->orig_iv   = cipher_state->iv;
   cipher_state->init_done = 1;
   return OCT_SUCCESS;
}

/* TODO: to figure out if this is better or writing separately for
 encrypt and decrypt
 would be better in terms of performance */
#define cvm_3des_enc_dec(enc, r) \
{ \
   if (enc) \
      CVMX_MT_3DES_ENC_CBC((r)); \
   else \
      CVMX_MT_3DES_DEC_CBC((r)); \
}
/**
 *
 *  octeon_des_ede3_do_cipher
 *
 *  DES-EDE3 cipher implementation function for Octeon engine
 *  \retval SUCCESS 1
 *  \retval FAILURE 0
 */
static int
octeon_des_ede3_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t inl)
{
    oct_des_ede3_cipher_data *cipher_state = (oct_des_ede3_cipher_data *)ctx->cipher_data;
    uint64_t *inp64 = (uint64_t *)in;
    uint64_t *outp64 = (uint64_t *)out;
    int enc;

    DBG();
    if (cipher_state->init_done != 1) {
        OCTEONerr(OCTEON_F_OCTEON_DES_EDE3_DO_CIPHER, OCTEON_R_DES_EDE3_INIT_NOT_DONE);
        return OCT_FAILURE;  
    }
    if (!inl)
        return OCT_SUCCESS;
  
    enc = ctx->encrypt;

	Oct_DES_ede3_cbc_encrypt(inp64, outp64, inl, &cipher_state->key1, &cipher_state->key2,
			&cipher_state->key3, &cipher_state->iv, enc);

    return OCT_SUCCESS;
}
/**
 * octeon_des_ede3_cleanup
 *
 * DES-EDE3 cipher cleanup function for Octeon engine
 *
 * \retval SUCCESS 1
 * \retval FAILURE 0
 *
 */
static int
octeon_des_ede3_cleanup(EVP_CIPHER_CTX *ctx)
{
   oct_des_ede3_cipher_data *cipher_state = (oct_des_ede3_cipher_data *)ctx->cipher_data;
   cipher_state->init_done = -1;
   return OCT_SUCCESS;
}

/* EVP CIPHER providing info about DES-EDE3 cipher offloaded functions */

static const EVP_CIPHER octeon_des_ede3 = 
{
   NID_des_ede3_cbc,                     /* NID */
   8,                                    /* Block size */
   24,                                 /* Key Length */
   8,                                    /* IV Length */
   EVP_CIPH_CBC_MODE,                  /* Flags (Only CBC) */
   octeon_des_ede3_init,               /* DES Init Key */
   octeon_des_ede3_do_cipher,            /* DES EDE3 Encrypt/Decrypt */
   octeon_des_ede3_cleanup,            /* Cleanup */
   OCT_DES_EDE3_CTX_SIZE,
   EVP_CIPHER_set_asn1_iv,
   EVP_CIPHER_get_asn1_iv,
   NULL,
   NULL                                 /* app_data ?? */
};

/**
 *  DES cipher structure: Contains info about des cipher data
 */

typedef struct {
   int init_done;                           /* Initialization done */
   uint64_t iv;                             /* Running IV */
   uint64_t orig_iv;                        /* orig IV */
   uint64_t key;                            /* DES key */
} oct_des_cipher_data; 

#define OCT_DES_CTX_SIZE sizeof(oct_des_cipher_data)
/**
 * octeon_des_init 
 *
 * DES-CBC cipher initialisation function for Octeon engine
 *
 * \retval SUCCESS 1
 * \retval FAILURE 0
 */
static int
octeon_des_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                const unsigned char *iv, int enc)
{
    uint64_t key64[] = { *(uint64_t *)key, *(uint64_t *)key, *(uint64_t *)key };
    return octeon_des_ede3_init(ctx, (unsigned char *)&key64[0], iv, enc);
}

/**
 *  octeon_des_do_cipher 
 *  
 *  DES-CBC cipher implementation function for Octeon engine
 *  
 *  \retval SUCCESS 1
 *  \retval FAILURE 0
 */
static int
octeon_des_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                     const unsigned char *in, size_t inl)
{
    return octeon_des_ede3_do_cipher(ctx, out, in, inl);
}
/**
 *  octeon_des_cleanup 
 *  
 *  DES-CBC cipher cleanup function for Octeon engine
 *  
 *  \retval SUCCESS 1
 *  \retval FAILURE 0
 */
static int
octeon_des_cleanup(EVP_CIPHER_CTX *ctx)
{
    return octeon_des_ede3_cleanup(ctx);
}

/* EVP CIPHER providing info about DES cipher offloaded functions */

static const EVP_CIPHER octeon_des = 
{
   NID_des_cbc,                        /* NID */
   8,                                    /* Block size */
   8,                                    /* Key Length */
   8,                                    /* IV Length */
   EVP_CIPH_CBC_MODE,                  /* Flags (Only CBC) */
   octeon_des_init,               /* DES Init Key */
   octeon_des_do_cipher,            /* DES EDE3 Encrypt/Decrypt */
   octeon_des_cleanup,            /* Cleanup */
   OCT_DES_EDE3_CTX_SIZE,
   EVP_CIPHER_set_asn1_iv,
   EVP_CIPHER_get_asn1_iv,
   NULL,
   NULL                                 /* app_data ?? */
};

/**
 *  AES-GCM cipher structure: Contains info about aes-gcm cipher data
 */
typedef struct {
   aes_gcm_ctx_t aes_ctx;
   block16_t len;
   int key_set;
   int iv_set;
   unsigned char *iv;
   int ivlen;
   int taglen;
   int iv_gen;
   int tls_aad_len;
}oct_aes_gcm_cipher_data;

static void ctr64_inc(unsigned char *counter) {
    int n=8;
    unsigned char  c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c) return;
    } while (n);
}
#define OCT_AES_GCM_CTX_SIZE sizeof(oct_aes_gcm_cipher_data)

static int
octeon_aes_gcm_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                const unsigned char *iv, int enc)
{
   oct_aes_gcm_cipher_data *gctx = ctx->cipher_data;
   if(!iv && !key)
      return 1;
   if(key)
   {
      //Init key, Run key schedule and get and set H
      //It will set K,H,keylen,done field of gctx->aes_ctx
      if(AES_GCM_init_key ((uint8_t *)key, (uint32_t)ctx->key_len*8, &gctx->aes_ctx))
         return 0;

      if(iv == NULL && gctx->iv_set)
         iv = gctx->iv;
      if(iv)
      {
         //It will set Y_i, Y_0, done field of gctx->aes_ctx
         if(AES_GCM_set_iv ((uint8_t *)iv,(uint32_t)gctx->ivlen, &gctx->aes_ctx))
            return 0;
         gctx->iv_set = 1;
      }
      gctx->key_set = 1;
   }
   else
   {
      if(gctx->key_set)
      {
         if(AES_GCM_set_iv ((uint8_t *)iv,gctx->ivlen, &gctx->aes_ctx))
            return 0;
      }
      else
         memcpy(gctx->iv,iv,gctx->ivlen);
      gctx->iv_set = 1;
      gctx->iv_gen = 0;
   }
   return 1;
}

static int
aes_gmac_ctx_aad(uint8_t *ain, int alen, aes_gcm_ctx_t *aes_ctx)
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

        // Set iv from context
        GHASH_restore (0xe100, &aes_ctx->H.val64[0]);

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
    aes_ctx->done |= AES_GCM_AAD_DONE;
    return AES_GCM_SUCCESS;
}

static int octeon_aes_gcm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
      const unsigned char *in, size_t len)
{
   oct_aes_gcm_cipher_data *gctx = ctx->cipher_data;
    int rv = -1;
    /* Encrypt/decrypt must be performed in place */
    if (out != in || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN+EVP_GCM_TLS_TAG_LEN))
        return -1;
    /* Set IV from start of buffer or generate IV and write to start
     * of buffer.
     */
    if (EVP_CIPHER_CTX_ctrl(ctx, ctx->encrypt ?
                EVP_CTRL_GCM_IV_GEN : EVP_CTRL_GCM_SET_IV_INV,
                EVP_GCM_TLS_EXPLICIT_IV_LEN, out) <= 0)
        goto err;
    /* Use saved AAD */
   unsigned long alen = gctx->len.val64[0];
   alen += gctx->tls_aad_len;
   if (alen>((unsigned long)(1)<<61) || (sizeof(len)==8 && alen<gctx->tls_aad_len))
        goto err;
   gctx->len.val64[0] = alen;
   if(aes_gmac_ctx_aad(ctx->buf, gctx->tls_aad_len, &gctx->aes_ctx))
        goto err;
    /* Fix buffer and length to point to payload */
    in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    if (ctx->encrypt)
        {
        /* Encrypt payload */
      unsigned long mlen = gctx->len.val64[1];
      mlen += len;
      if(mlen>(((unsigned long)(1)<<36)-32) || (sizeof(len)==8 && mlen<len))
           goto err;
      gctx->len.val64[1] = mlen;
      if(AES_GCM_ctx_encrypt((uint8_t *) in,len,(uint8_t *) out,&gctx->aes_ctx))
           goto err;
        out += len;
        /* Finally write tag */
      AES_GCM_ctx_final(gctx->len.val64[1],gctx->len.val64[0],out,&gctx->aes_ctx);
        rv = len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
        }
    else
        {
        /* Decrypt */
         unsigned long mlen = gctx->len.val64[1];
         mlen += len;
         if(mlen>(((unsigned long)(1)<<36)-32) || (sizeof(len)==8 && mlen<len))
            return -1;
         gctx->len.val64[1] = mlen;
         if(AES_GCM_ctx_decrypt((uint8_t *) in,len,(uint8_t *) out,&gctx->aes_ctx))
                goto err;
        /* Retrieve tag */
      AES_GCM_ctx_final(gctx->len.val64[1],gctx->len.val64[0],ctx->buf,&gctx->aes_ctx);
        /* If tag mismatch wipe buffer */
        if (memcmp(ctx->buf, in + len, EVP_GCM_TLS_TAG_LEN))
            {
            OPENSSL_cleanse(out, len);
            goto err;
            }
        rv = len;
        }

    err:
    gctx->iv_set = 0;
    gctx->tls_aad_len = -1;
    return rv;
}

static int
octeon_aes_gcm_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                     const unsigned char *in, size_t len)
{
   oct_aes_gcm_cipher_data *gctx = ctx->cipher_data;
   /* If not set up,return error */
   if(!gctx->key_set)
        return -1;

   if(gctx->tls_aad_len >= 0)
      return octeon_aes_gcm_tls_cipher(ctx,out,in,len);

   if(!gctx->iv_set)
      return -1;

   if(in)
   {
      if(out == NULL)
      {
         unsigned long alen = gctx->len.val64[0];
         alen += len;
         if (alen>((unsigned long)(1)<<61) || (sizeof(len)==8 && alen<len))
            return -1;
         gctx->len.val64[0] = alen;
         if(aes_gmac_ctx_aad((uint8_t *)in,len,&gctx->aes_ctx))
            return -1;
      }
      else if(ctx->encrypt)
      {
         unsigned long mlen = gctx->len.val64[1];
         mlen += len;
         if(mlen>(((unsigned long)(1)<<36)-32) || (sizeof(len)==8 && mlen<len))
            return -1;
         gctx->len.val64[1] = mlen;
         if(AES_GCM_ctx_encrypt((uint8_t *) in,len,(uint8_t *) out,&gctx->aes_ctx))
            return -1;
      }
      else
      {
         unsigned long mlen = gctx->len.val64[1];
         mlen += len;
         if(mlen>(((unsigned long)(1)<<36)-32) || (sizeof(len)==8 && mlen<len))
            return -1;
         gctx->len.val64[1] = mlen;
         if(AES_GCM_ctx_decrypt((uint8_t *) in,len,(uint8_t *) out,&gctx->aes_ctx))
            return -1;
      }
      return len;
   }
   else
   {
      if(!ctx->encrypt)
      {
         uint8_t tag[128];
         AES_GCM_ctx_final(gctx->len.val64[1],gctx->len.val64[0],tag,&gctx->aes_ctx);
         if(memcmp(tag,ctx->buf,gctx->taglen))
            return -1;

         gctx->iv_set = 0;
         return 0;
      }
      AES_GCM_ctx_final(gctx->len.val64[1],gctx->len.val64[0],ctx->buf,&gctx->aes_ctx);
      gctx->taglen = 16;
      /* Don't resue the IV */
      gctx->iv_set = 0;
      return 0;
   }
}

static int
octeon_aes_gcm_cleanup(EVP_CIPHER_CTX *ctx)
{
   oct_aes_gcm_cipher_data *gctx = ctx->cipher_data;
   OPENSSL_cleanse(&gctx->aes_ctx, sizeof(gctx->aes_ctx));
   if (gctx->iv != ctx->iv)
      OPENSSL_free(gctx->iv);
   return 1;
}

static int 
octeon_aes_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
   oct_aes_gcm_cipher_data *gctx = c->cipher_data;
   switch(type)
   {
   case EVP_CTRL_INIT:
      gctx->key_set = 0;
      gctx->iv_set = 0;
      gctx->ivlen = c->cipher->iv_len;
      gctx->iv = c->iv;
      gctx->taglen = -1;
      gctx->iv_gen = 0;
      gctx->len.val64[0] = 0;
      gctx->len.val64[1] = 0;
      gctx->tls_aad_len = -1;
      return 1;

   case EVP_CTRL_GCM_SET_IVLEN:
      if(arg <= 0)
         return 0;

        /* Allocate memory for IV if needed */
      if((arg > EVP_MAX_IV_LENGTH) && (arg > gctx->ivlen))
      {
         if(gctx->iv != c->iv)
            OPENSSL_free(gctx->iv);
         gctx->iv = OPENSSL_malloc(arg);
         if(!gctx->iv)
            return 0;
      }
      gctx->ivlen = arg;
      return 1;
   
   case EVP_CTRL_GCM_SET_TAG:
      if(arg <= 0 || arg > 16 || c->encrypt)
         return 0;
      memcpy(c->buf,ptr,arg);
      gctx->taglen =arg;
      return 1;

   case EVP_CTRL_GCM_GET_TAG:
      if(arg <= 0 || arg > 16 || !c->encrypt || gctx->taglen < 0)
         return 0;
      memcpy(ptr,c->buf,arg);
      return 1;

   case EVP_CTRL_GCM_SET_IV_FIXED:
        /* Special case: -1 length restores whole IV */
        if (arg == -1)
            {
            memcpy(gctx->iv, ptr, gctx->ivlen);
            gctx->iv_gen = 1;
            return 1;
            }
        /* Fixed field must be at least 4 bytes and invocation field
         * at least 8.
         */
        if ((arg < 4) || (gctx->ivlen - arg) < 8)
            return 0;
        if (arg)
            memcpy(gctx->iv, ptr, arg);
        if (c->encrypt &&
            RAND_bytes(gctx->iv + arg, gctx->ivlen - arg) <= 0)
            return 0;
        gctx->iv_gen = 1;
        return 1;

   case EVP_CTRL_GCM_IV_GEN:
        if (gctx->iv_gen == 0 || gctx->key_set == 0)
            return 0;
        gctx->len.val64[0] = 0;
        gctx->len.val64[1] = 0;
        gctx->aes_ctx.done = AES_GCM_KEY_DONE;
        if(AES_GCM_set_iv (gctx->iv,gctx->ivlen, &gctx->aes_ctx))
            return 0;

        if (arg <= 0 || arg > gctx->ivlen)
            arg = gctx->ivlen;
        memcpy(ptr, gctx->iv + gctx->ivlen - arg, arg);
        /* Invocation field will be at least 8 bytes in size and
         * so no need to check wrap around or increment more than
         * last 8 bytes.
         */
        ctr64_inc(gctx->iv + gctx->ivlen - 8);
        gctx->iv_set = 1;
        return 1;

   case EVP_CTRL_GCM_SET_IV_INV:
        if (gctx->iv_gen == 0 || gctx->key_set == 0 || c->encrypt)
            return 0;
        gctx->len.val64[0] = 0;
        gctx->len.val64[1] = 0;
       
        memcpy(gctx->iv + gctx->ivlen - arg, ptr, arg);
        gctx->aes_ctx.done = AES_GCM_KEY_DONE;
        if(AES_GCM_set_iv (gctx->iv,gctx->ivlen, &gctx->aes_ctx))
            return 0;
        gctx->iv_set = 1;
        return 1;

   case EVP_CTRL_AEAD_TLS1_AAD:
        /* Save the AAD for later use */
        if (arg != 13)
            return 0;
        memcpy(c->buf, ptr, arg);
        gctx->tls_aad_len = arg;
            {
            unsigned int len=c->buf[arg-2]<<8|c->buf[arg-1];
            /* Correct length for explicit IV */
            len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
            /* If decrypting correct for tag too */
            if (!c->encrypt)
                len -= EVP_GCM_TLS_TAG_LEN;
            c->buf[arg-2] = len>>8;
            c->buf[arg-1] = len & 0xff;
            }
        /* Extra padding: tag appended to record */
        return EVP_GCM_TLS_TAG_LEN;

   default:
      return -1;
   }
}


/* EVP CIPHER providing info about AES128 cipher offloaded functions */
//0x4000 | 0x200000 | 0x1000 | 0x10 | 0x100000 | 0x20 | 0x40 | 0x6
#define GCM_FLAGS ( EVP_CIPH_FLAG_FIPS | EVP_CIPH_FLAG_AEAD_CIPHER \
                  | EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CUSTOM_IV \
                  | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT \
                  | EVP_CIPH_CTRL_INIT | EVP_CIPH_GCM_MODE )
static const EVP_CIPHER octeon_aes_gcm_128= 
   {
   NID_aes_128_gcm,                     /* NID */
   1,                                    /* Block size */
   16,                                    /* Key Length */
   12,                                    /* IV Length */
   GCM_FLAGS,                             /* Flags */
   octeon_aes_gcm_init,                     /* AES Init Key */
   octeon_aes_gcm_do_cipher,            /* AES Encrypt/Decrypt */
   octeon_aes_gcm_cleanup,            /* Cleanup */
   OCT_AES_GCM_CTX_SIZE,
   EVP_CIPHER_set_asn1_iv,
   EVP_CIPHER_get_asn1_iv,
   octeon_aes_gcm_ctrl,                 /* Miscellaneous operations */
   NULL                                 /* app_data ?? */
   };

static const EVP_CIPHER octeon_aes_gcm_192= 
   {
   NID_aes_192_gcm,                     /* NID */
   1,                                    /* Block size */
   24,                                    /* Key Length */
   12,                                    /* IV Length */
   GCM_FLAGS,                  /* Flags */
   octeon_aes_gcm_init,                     /* AES Init Key */
   octeon_aes_gcm_do_cipher,            /* AES Encrypt/Decrypt */
   octeon_aes_gcm_cleanup,            /* Cleanup */
   OCT_AES_GCM_CTX_SIZE,
   EVP_CIPHER_set_asn1_iv,
   EVP_CIPHER_get_asn1_iv,
   octeon_aes_gcm_ctrl,                 /* Miscellaneous operations */
   NULL                                 /* app_data ?? */
   };

static const EVP_CIPHER octeon_aes_gcm_256= 
   {
   NID_aes_256_gcm,                     /* NID */
   1,                                    /* Block size */
   32,                                    /* Key Length */
   12,                                    /* IV Length */
   GCM_FLAGS,                  /* Flags */
   octeon_aes_gcm_init,                     /* AES Init Key */
   octeon_aes_gcm_do_cipher,            /* AES Encrypt/Decrypt */
   octeon_aes_gcm_cleanup,            /* Cleanup */
   OCT_AES_GCM_CTX_SIZE,
   EVP_CIPHER_set_asn1_iv,
   EVP_CIPHER_get_asn1_iv,
   octeon_aes_gcm_ctrl,                 /* Miscellaneous operations */
   NULL                                 /* app_data ?? */
   };

/**
 *  AES cipher structure: Contains info about aes cipher data
 */

typedef struct {
   int init_done;                           /* Initialization done */
   int key_len;                            /* length of AES key  */
   unsigned char iv[16];                   /* Running IV */
   unsigned char orig_iv[16];              /* Original IV */
   uint64_t key[4];                        /* AES key */
} oct_aes_cipher_data; 

#define OCT_AES_CTX_SIZE sizeof(oct_aes_cipher_data)
/**
 *  octeon_aes_init 
 * 
 *  AES cipher initialisation function for Octeon engine
 * 
 *  \retval SUCCESS 1
 *  \retval FAILURE 0
 */
static int
octeon_aes_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                const unsigned char *iv, int enc)
{
    oct_aes_cipher_data *cipher_state = (oct_aes_cipher_data *)ctx->cipher_data;
    int aes_len = ctx->key_len;

    memcpy(cipher_state->iv, iv, 16);
    memcpy(cipher_state->orig_iv, iv, 16);
    memset(cipher_state->key, 0, 4*sizeof(uint64_t));
    memcpy(cipher_state->key, key, aes_len);
    cipher_state->init_done = 1;
    cipher_state->key_len = aes_len;

    return OCT_SUCCESS;
}

#define cvm_aes_enc_dec0(enc, l) \
{ \
   if (enc)  { \
      CVMX_MT_AES_ENC_CBC0((l)); \
   } else { \
      CVMX_MT_AES_DEC_CBC0((l)); \
   } \
}
      
#define cvm_aes_enc_dec1(enc, l) \
{ \
   if (enc)  { \
      CVMX_MT_AES_ENC_CBC1((l)); \
   } else { \
      CVMX_MT_AES_DEC_CBC1((l)); \
   } \
}
/**
 *  octeon_aes_do_cipher 
 *  
 *  AES cipher implementation function for Octeon engine
 *  
 *  \retval SUCCESS 1
 *  \retval FAILURE 0
 */
static int
octeon_aes_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                     const unsigned char *in, size_t inl)
{
    oct_aes_cipher_data *cipher_state = (oct_aes_cipher_data *)ctx->cipher_data;
    uint64_t *inp64 = (uint64_t *)in;
    uint64_t *outp64 = (uint64_t *)out;
    uint64_t *iv = NULL;
    int enc, ret;

    if (cipher_state->init_done != 1) {
        OCTEONerr(OCTEON_F_OCTEON_AES_DO_CIPHER, OCTEON_R_AES_INIT_NOT_DONE);
        return 0;  
    }
    if (!inl)
        return OCT_SUCCESS;
  
    enc = ctx->encrypt;
    iv  = (uint64_t *)&cipher_state->iv[0];

	ret = Oct_AES_cbc_encrypt(inp64, outp64, inl, (uint64_t *)&cipher_state->key, cipher_state->key_len, iv, enc);
    
	return ret;
}

/**
 *  octeon_aes_cleanup 
 *    
 *  AES cipher cleanup function for Octeon engine
 *   
 *  \retval SUCCESS 1
 *  \retval FAILURE 0
 */
static int
octeon_aes_cleanup(EVP_CIPHER_CTX *ctx)
{
   oct_aes_cipher_data *cipher_state = (oct_aes_cipher_data *)ctx->cipher_data;
   cipher_state->init_done = -1;
   return OCT_SUCCESS;
}

/* EVP CIPHER providing info about AES128 cipher offloaded functions */

static const EVP_CIPHER octeon_aes128= 
   {
   NID_aes_128_cbc,                     /* NID */
   16,                                    /* Block size */
   16,                                    /* Key Length */
   16,                                    /* IV Length */
   EVP_CIPH_CBC_MODE,                  /* Flags (Only CBC) */
   octeon_aes_init,                     /* AES Init Key */
   octeon_aes_do_cipher,            /* AES Encrypt/Decrypt */
   octeon_aes_cleanup,            /* Cleanup */
   OCT_AES_CTX_SIZE,
   EVP_CIPHER_set_asn1_iv,
   EVP_CIPHER_get_asn1_iv,
   NULL,
   NULL                                 /* app_data ?? */
   };

/* EVP CIPHER providing info about AES192 cipher offloaded functions */

static const EVP_CIPHER octeon_aes192 = 
   {
   NID_aes_192_cbc,                     /* NID */
   16,                                    /* Block size */
   24,                                    /* Key Length */
   16,                                    /* IV Length */
   EVP_CIPH_CBC_MODE,                  /* Flags (Only CBC) */
   octeon_aes_init,                     /* AES Init Key */
   octeon_aes_do_cipher,            /* AES Encrypt/Decrypt */
   octeon_aes_cleanup,            /* Cleanup */
   OCT_AES_CTX_SIZE,
   EVP_CIPHER_set_asn1_iv,
   EVP_CIPHER_get_asn1_iv,
   NULL,
   NULL                                 /* app_data ?? */
   };

/* EVP CIPHER providing info about AES256 cipher offloaded functions */

static const EVP_CIPHER octeon_aes256 = 
   {
   NID_aes_256_cbc,                     /* NID */
   16,                                    /* Block size */
   32,                                    /* Key Length */
   16,                                    /* IV Length */
   EVP_CIPH_CBC_MODE,                  /* Flags (Only CBC) */
   octeon_aes_init,                     /* AES Init Key */
   octeon_aes_do_cipher,            /* AES Encrypt/Decrypt */
   octeon_aes_cleanup,            /* Cleanup */
   OCT_AES_CTX_SIZE,
   EVP_CIPHER_set_asn1_iv,
   EVP_CIPHER_get_asn1_iv,
   NULL,
   NULL                                 /* app_data ?? */
   };

// aes-ecb : start
static int
octeon_aes_ecb_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                const unsigned char *iv, int enc)
{
    oct_aes_cipher_data *cipher_state = (oct_aes_cipher_data *)ctx->cipher_data;
    int aes_len = ctx->key_len;

//    memcpy(cipher_state->iv, iv, 16);
//    memcpy(cipher_state->orig_iv, iv, 16);
    memset(cipher_state->key, 0, 4*sizeof(uint64_t));
    memcpy(cipher_state->key, key, aes_len);
    cipher_state->init_done = 1;
    cipher_state->key_len = aes_len;

    return OCT_SUCCESS;
}

/**
 *  octeon_aes_do_cipher 
 *  
 *  AES cipher implementation function for Octeon engine
 *  
 *  \retval SUCCESS 1
 *  \retval FAILURE 0
 */
static int
octeon_aes_ecb_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                     const unsigned char *in, size_t inl)
{
    oct_aes_cipher_data *cipher_state = (oct_aes_cipher_data *)ctx->cipher_data;
    int enc, i;
	OCT_AES_KEY akey_ecb;

    memset(akey_ecb.cvmkey, 0, 4*sizeof(uint64_t));
    memcpy(akey_ecb.cvmkey, cipher_state->key, cipher_state->key_len);
	akey_ecb.cvm_keylen = cipher_state->key_len * 8;


    if (cipher_state->init_done != 1) {
        OCTEONerr(OCTEON_F_OCTEON_AES_DO_CIPHER, OCTEON_R_AES_INIT_NOT_DONE);
        return 0;  
    }
    if (!inl)
        return OCT_SUCCESS;
  
    enc = ctx->encrypt;

	for(i = 0; i < inl; i += AES_CHUNK_SIZE)
		Oct_AES_ecb_encrypt(in+i, out+i, &akey_ecb, enc);
    
	return OCT_SUCCESS;
}

/**
 *  octeon_aes_cleanup 
 *    
 *  AES cipher cleanup function for Octeon engine
 *   
 *  \retval SUCCESS 1
 *  \retval FAILURE 0
 */
static int
octeon_aes_ecb_cleanup(EVP_CIPHER_CTX *ctx)
{
   oct_aes_cipher_data *cipher_state = (oct_aes_cipher_data *)ctx->cipher_data;
   cipher_state->init_done = -1;
   return OCT_SUCCESS;
}

/* EVP CIPHER providing info about AES128 cipher offloaded functions */

static const EVP_CIPHER octeon_aes128_ecb= 
   {
   NID_aes_128_ecb,                     /* NID */
   16,                                    /* Block size */
   16,                                    /* Key Length */
   16,                                    /* IV Length */
   EVP_CIPH_ECB_MODE,                  /* Flags (Only CBC) */
   octeon_aes_ecb_init,                     /* AES Init Key */
   octeon_aes_ecb_do_cipher,            /* AES Encrypt/Decrypt */
   octeon_aes_ecb_cleanup,            /* Cleanup */
   OCT_AES_CTX_SIZE,
   EVP_CIPHER_set_asn1_iv,
   EVP_CIPHER_get_asn1_iv,
   NULL,
   NULL                                 /* app_data ?? */
   };

/* EVP CIPHER providing info about AES192 cipher offloaded functions */

static const EVP_CIPHER octeon_aes192_ecb = 
   {
   NID_aes_192_ecb,                     /* NID */
   16,                                    /* Block size */
   24,                                    /* Key Length */
   16,                                    /* IV Length */
   EVP_CIPH_ECB_MODE,                  /* Flags (Only CBC) */
   octeon_aes_ecb_init,                     /* AES Init Key */
   octeon_aes_ecb_do_cipher,            /* AES Encrypt/Decrypt */
   octeon_aes_ecb_cleanup,            /* Cleanup */
   OCT_AES_CTX_SIZE,
   EVP_CIPHER_set_asn1_iv,
   EVP_CIPHER_get_asn1_iv,
   NULL,
   NULL                                 /* app_data ?? */
   };

/* EVP CIPHER providing info about AES256 cipher offloaded functions */

static const EVP_CIPHER octeon_aes256_ecb = 
   {
   NID_aes_256_ecb,                     /* NID */
   16,                                    /* Block size */
   32,                                    /* Key Length */
   16,                                    /* IV Length */
   EVP_CIPH_ECB_MODE,                  /* Flags (Only CBC) */
   octeon_aes_ecb_init,                     /* AES Init Key */
   octeon_aes_ecb_do_cipher,            /* AES Encrypt/Decrypt */
   octeon_aes_ecb_cleanup,            /* Cleanup */
   OCT_AES_CTX_SIZE,
   EVP_CIPHER_set_asn1_iv,
   EVP_CIPHER_get_asn1_iv,
   NULL,
   NULL                                 /* app_data ?? */
   };

#ifdef OCTEON3
// camellia support - start
typedef struct {
    int init_done;
    int key_len;
    uint64_t key[4];
    unsigned char iv[16];
    unsigned char orig_iv[16];
    CAMELLIA_KEY *cmll_key;
    int ofb_num;
}oct_cmll_cipher_data;

#define OCTEON_CMLL_CTX_SIZE sizeof(oct_cmll_cipher_data)

// Camellia - CBC
static int octeon_cmll_cbc_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
        const unsigned char *iv, int enc)
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    CAMELLIA_KEY *cmll_key=NULL;
    int cmll_len = ctx->key_len;

    cmll_key=(CAMELLIA_KEY *)malloc(sizeof(CAMELLIA_KEY));
    memset(cmll_key,0,sizeof(CAMELLIA_KEY));

    memcpy(cipher_state->iv, iv, 16);
    memcpy(cipher_state->orig_iv, iv, 16);
    memset(cipher_state->key, 0, 4*sizeof(uint64_t));
    memcpy(cipher_state->key, key, cmll_len);
    cipher_state->init_done = 1;
    cipher_state->key_len = cmll_len;

    Oct_Camellia_set_key(key, cmll_len*8, cmll_key);
    cipher_state->cmll_key = cmll_key;

    return OCT_SUCCESS;
}

static int octeon_cmll_cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
        const unsigned char *in, size_t inl)
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    int enc = ctx->encrypt;
	
	if(!cipher_state->init_done)
	{
		printf("Cipher not initialized.\n");
		return 0;
	}
	
    if(enc)
        Oct_Camellia_cbc_encrypt((uint8_t *)in, (uint8_t *)out, inl, cipher_state->cmll_key, cipher_state->iv, 1);
    else
        Oct_Camellia_cbc_encrypt((uint8_t *)in, (uint8_t *)out, inl, cipher_state->cmll_key, cipher_state->iv, 0);
    
	return 1;
}

static int octeon_cmll_cbc_cleanup(EVP_CIPHER_CTX *ctx)
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    cipher_state->init_done = -1;
	free(cipher_state->cmll_key);

    return OCT_SUCCESS;
}

static const EVP_CIPHER octeon_cmll_128_cbc = {
    NID_camellia_128_cbc,
    16,
    16,
    16,
    EVP_CIPH_CBC_MODE,
    octeon_cmll_cbc_init,
    octeon_cmll_cbc_do_cipher,
    octeon_cmll_cbc_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

static const EVP_CIPHER octeon_cmll_192_cbc = {
    NID_camellia_192_cbc,
    16,
    24,
    16,
    EVP_CIPH_CBC_MODE,
    octeon_cmll_cbc_init,
    octeon_cmll_cbc_do_cipher,
    octeon_cmll_cbc_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

static const EVP_CIPHER octeon_cmll_256_cbc = {
    NID_camellia_256_cbc,
    16,
    32,
    16,
    EVP_CIPH_CBC_MODE,
    octeon_cmll_cbc_init,
    octeon_cmll_cbc_do_cipher,
    octeon_cmll_cbc_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

// Camellia - ECB
static int octeon_cmll_ecb_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
        const unsigned char *iv, int enc) 
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    CAMELLIA_KEY *cmll_key=NULL;
    int cmll_len = ctx->key_len;

    cmll_key=(CAMELLIA_KEY *)malloc(sizeof(CAMELLIA_KEY));
    memset(cmll_key,0,sizeof(CAMELLIA_KEY));
    
    memcpy(cipher_state->iv, iv, 16); 
    memcpy(cipher_state->orig_iv, iv, 16); 
    memset(cipher_state->key, 0, 4*sizeof(uint64_t));
    memcpy(cipher_state->key, key, cmll_len);
    cipher_state->init_done = 1; 
    cipher_state->key_len = cmll_len;
    
    Oct_Camellia_set_key(key, cmll_len*8, cmll_key);
    cipher_state->cmll_key = cmll_key;

    return OCT_SUCCESS;
}

static int octeon_cmll_ecb_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
        const unsigned char *in, size_t inl) 
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    int k = 0, enc = ctx->encrypt; 
    int bs = ctx->cipher->block_size;
    
	if(!cipher_state->init_done)
	{
		printf("Cipher not initialized.\n");
		return 0;
	}
	
	if(enc)
    {    
        do { 
            Oct_Camellia_ecb_encrypt((uint8_t *)&in[k], (uint8_t *)&out[k], cipher_state->cmll_key, 1);
            k += bs;
        }while(k<inl);
    }
    else
    {
        do {
            Oct_Camellia_ecb_encrypt((uint8_t *)&in[k], (uint8_t *)&out[k], cipher_state->cmll_key, 0);
            k += bs;
        }while(k<inl);
    }
    return 1;
}

static int octeon_cmll_ecb_cleanup(EVP_CIPHER_CTX *ctx)
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    cipher_state->init_done = -1;
	free(cipher_state->cmll_key);
    
	return OCT_SUCCESS;
}

static const EVP_CIPHER octeon_cmll_128_ecb = {
    NID_camellia_128_ecb,
    16,
    16,
    16,
    EVP_CIPH_ECB_MODE,
    octeon_cmll_ecb_init,
    octeon_cmll_ecb_do_cipher,
    octeon_cmll_ecb_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

static const EVP_CIPHER octeon_cmll_192_ecb = {
    NID_camellia_192_ecb,
    16,
    24,
    16,
    EVP_CIPH_ECB_MODE,
    octeon_cmll_ecb_init,
    octeon_cmll_ecb_do_cipher,
    octeon_cmll_ecb_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

static const EVP_CIPHER octeon_cmll_256_ecb = {
    NID_camellia_256_ecb,
    16,
    32,
    16,
    EVP_CIPH_ECB_MODE,
    octeon_cmll_ecb_init,
    octeon_cmll_ecb_do_cipher,
    octeon_cmll_ecb_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

// Camellia - OFB128
static int octeon_cmll_ofb128_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
        const unsigned char *iv, int enc)
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    CAMELLIA_KEY *cmll_key=NULL;
    int cmll_len = ctx->key_len;

    cmll_key=(CAMELLIA_KEY *)malloc(sizeof(CAMELLIA_KEY));
    memset(cmll_key,0,sizeof(CAMELLIA_KEY));

    memcpy(cipher_state->iv, iv, 16);
    memcpy(cipher_state->orig_iv, iv, 16);
    memset(cipher_state->key, 0, 4*sizeof(uint64_t));
    memcpy(cipher_state->key, key, cmll_len);
    cipher_state->init_done = 1;
    cipher_state->key_len = cmll_len;
    cipher_state->ofb_num = 0;

    Oct_Camellia_set_key(key, cmll_len*8, cmll_key);
    cipher_state->cmll_key = cmll_key;

    return OCT_SUCCESS;
}

static int octeon_cmll_ofb128_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
        const unsigned char *in, size_t inl)
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;

	if(!cipher_state->init_done)
	{
		printf("Cipher not initialized.\n");
		return 0;
	}
	
    Oct_Camellia_ofb128_encrypt((uint8_t *)in, (uint8_t *)out, inl, cipher_state->cmll_key, cipher_state->iv, &(cipher_state->ofb_num));
    return 1;
}

static int octeon_cmll_ofb128_cleanup(EVP_CIPHER_CTX *ctx)
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    cipher_state->init_done = -1;
	free(cipher_state->cmll_key);
    
    return OCT_SUCCESS;
}

static const EVP_CIPHER octeon_cmll_128_ofb128 = {
    NID_camellia_128_ofb128,
    1,
    16,
    16,
    EVP_CIPH_OFB_MODE,
    octeon_cmll_ofb128_init,
    octeon_cmll_ofb128_do_cipher,
    octeon_cmll_ofb128_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

static const EVP_CIPHER octeon_cmll_192_ofb128 = {
    NID_camellia_192_ofb128,
    1,
    24,
    16,
    EVP_CIPH_OFB_MODE,
    octeon_cmll_ofb128_init,
    octeon_cmll_ofb128_do_cipher,
    octeon_cmll_ofb128_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

static const EVP_CIPHER octeon_cmll_256_ofb128 = {
    NID_camellia_256_ofb128,
    1,
    32,
    16,
    EVP_CIPH_OFB_MODE,
    octeon_cmll_ofb128_init,
    octeon_cmll_ofb128_do_cipher,
    octeon_cmll_ofb128_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

// Camellia - CFB128
static int octeon_cmll_cfb128_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
        const unsigned char *iv, int enc)
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    CAMELLIA_KEY *cmll_key=NULL;
    int cmll_len = ctx->key_len;

    cmll_key=(CAMELLIA_KEY *)malloc(sizeof(CAMELLIA_KEY));
    memset(cmll_key,0,sizeof(CAMELLIA_KEY));

    memcpy(cipher_state->iv, iv, 16);
    memcpy(cipher_state->orig_iv, iv, 16);
    memset(cipher_state->key, 0, 4*sizeof(uint64_t));
    memcpy(cipher_state->key, key, cmll_len);
    cipher_state->init_done = 1;
    cipher_state->key_len = cmll_len;
    cipher_state->ofb_num = 0;

    Oct_Camellia_set_key(key, cmll_len*8, cmll_key);
    cipher_state->cmll_key = cmll_key;

    return OCT_SUCCESS;
}

static int octeon_cmll_cfb128_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
        const unsigned char *in, size_t inl)
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    int enc = ctx->encrypt;

    Oct_Camellia_cfb128_encrypt((uint8_t *)in, (uint8_t *)out, inl, cipher_state->cmll_key, cipher_state->iv, &(cipher_state->ofb_num), enc);

    return 1;
}

static int octeon_cmll_cfb128_cleanup(EVP_CIPHER_CTX *ctx)
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    cipher_state->init_done = -1;
	free(cipher_state->cmll_key);
    
	return OCT_SUCCESS;
}

static const EVP_CIPHER octeon_cmll_128_cfb128 = {
    NID_camellia_128_cfb128,
    1,
    16,
    16,
    EVP_CIPH_CFB_MODE,
    octeon_cmll_cfb128_init,
    octeon_cmll_cfb128_do_cipher,
    octeon_cmll_cfb128_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

static const EVP_CIPHER octeon_cmll_192_cfb128 = {
    NID_camellia_192_cfb128,
    1,
    24,
    16,
    EVP_CIPH_CFB_MODE,
    octeon_cmll_cfb128_init,
    octeon_cmll_cfb128_do_cipher,
    octeon_cmll_cfb128_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

static const EVP_CIPHER octeon_cmll_256_cfb128 = {
    NID_camellia_256_cfb128,
    1,
    32,
    16,
    EVP_CIPH_CFB_MODE,
    octeon_cmll_cfb128_init,
    octeon_cmll_cfb128_do_cipher,
    octeon_cmll_cfb128_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

// Camellia - CFB1
static int octeon_cmll_cfb1_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
        const unsigned char *iv, int enc)
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    CAMELLIA_KEY *cmll_key=NULL;
    int cmll_len = ctx->key_len;

    cmll_key=(CAMELLIA_KEY *)malloc(sizeof(CAMELLIA_KEY));
    memset(cmll_key,0,sizeof(CAMELLIA_KEY));

    memcpy(cipher_state->iv, iv, 16);
    memcpy(cipher_state->orig_iv, iv, 16);
    memset(cipher_state->key, 0, 4*sizeof(uint64_t));
    memcpy(cipher_state->key, key, cmll_len);
    cipher_state->init_done = 1;
    cipher_state->key_len = cmll_len;
    cipher_state->ofb_num = 0;

    Oct_Camellia_set_key(key, cmll_len*8, cmll_key);
    cipher_state->cmll_key = cmll_key;

    return OCT_SUCCESS;
}

static int octeon_cmll_cfb1_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
        const unsigned char *in, size_t inl)
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    int enc = ctx->encrypt;

    Oct_Camellia_cfb1_encrypt((uint8_t *)in, (uint8_t *)out, inl*8, cipher_state->cmll_key, cipher_state->iv, &(cipher_state->ofb_num), enc);

    return 1;
}

static int octeon_cmll_cfb1_cleanup(EVP_CIPHER_CTX *ctx)
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    cipher_state->init_done = -1;
	free(cipher_state->cmll_key);
    
	return OCT_SUCCESS;
}

static const EVP_CIPHER octeon_cmll_128_cfb1 = {
    NID_camellia_128_cfb1,
    1,
    16,
    16,
    EVP_CIPH_CFB_MODE,
    octeon_cmll_cfb1_init,
    octeon_cmll_cfb1_do_cipher,
    octeon_cmll_cfb1_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

static const EVP_CIPHER octeon_cmll_192_cfb1 = {
    NID_camellia_192_cfb1,
    1,
    24,
    16,
    EVP_CIPH_CFB_MODE,
    octeon_cmll_cfb1_init,
    octeon_cmll_cfb1_do_cipher,
    octeon_cmll_cfb1_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

static const EVP_CIPHER octeon_cmll_256_cfb1 = {
    NID_camellia_256_cfb1,
    1,
    32,
    16,
    EVP_CIPH_CFB_MODE,
    octeon_cmll_cfb1_init,
    octeon_cmll_cfb1_do_cipher,
    octeon_cmll_cfb1_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

// Camellia - CFB8
static int octeon_cmll_cfb8_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
        const unsigned char *iv, int enc)
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    CAMELLIA_KEY *cmll_key=NULL;
    int cmll_len = ctx->key_len;

    cmll_key=(CAMELLIA_KEY *)malloc(sizeof(CAMELLIA_KEY));
    memset(cmll_key,0,sizeof(CAMELLIA_KEY));

    memcpy(cipher_state->iv, iv, 16);
    memcpy(cipher_state->orig_iv, iv, 16);
    memset(cipher_state->key, 0, 4*sizeof(uint64_t));
    memcpy(cipher_state->key, key, cmll_len);
    cipher_state->init_done = 1;
    cipher_state->key_len = cmll_len;
    cipher_state->ofb_num = 0;

    Oct_Camellia_set_key(key, cmll_len*8, cmll_key);
    cipher_state->cmll_key = cmll_key;

    return OCT_SUCCESS;
}

static int octeon_cmll_cfb8_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
        const unsigned char *in, size_t inl)
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    int enc = ctx->encrypt;

    Oct_Camellia_cfb8_encrypt((uint8_t *)in, (uint8_t *)out, inl, cipher_state->cmll_key, cipher_state->iv, &(cipher_state->ofb_num), enc);

    return 1;
}

static int octeon_cmll_cfb8_cleanup(EVP_CIPHER_CTX *ctx)
{
    oct_cmll_cipher_data *cipher_state = (oct_cmll_cipher_data *)ctx->cipher_data;
    cipher_state->init_done = -1;
	free(cipher_state->cmll_key);
    
	return OCT_SUCCESS;
}

static const EVP_CIPHER octeon_cmll_128_cfb8 = {
    NID_camellia_128_cfb8,
    1,
    16,
    16,
    EVP_CIPH_CFB_MODE,
    octeon_cmll_cfb8_init,
    octeon_cmll_cfb8_do_cipher,
    octeon_cmll_cfb8_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

static const EVP_CIPHER octeon_cmll_192_cfb8 = {
    NID_camellia_192_cfb8,
    1,
    24,
    16,
    EVP_CIPH_CFB_MODE,
    octeon_cmll_cfb8_init,
    octeon_cmll_cfb8_do_cipher,
    octeon_cmll_cfb8_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

static const EVP_CIPHER octeon_cmll_256_cfb8 = {
    NID_camellia_256_cfb8,
    1,
    32,
    16,
    EVP_CIPH_CFB_MODE,
    octeon_cmll_cfb8_init,
    octeon_cmll_cfb8_do_cipher,
    octeon_cmll_cfb8_cleanup,
    OCTEON_CMLL_CTX_SIZE,
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

#endif
// camellia support - end

#endif /* OCTEON_NO_CIPHERS */

#ifndef OCTEON_NO_CIPHERS
/* List of Octeon supported ciphers NID's */
static int octeon_cipher_nids[] = 
   { 
     NID_des_ede3_cbc,    /* DES EDE3 */
     NID_des_cbc,         /* DES CBC */
     NID_aes_128_cbc,   /* AES 128 */
     NID_aes_192_cbc,   /* AES 192 */
     NID_aes_256_cbc,   /* AES 256 */
     NID_aes_128_gcm,   /* AES-GCM 128 */
     NID_aes_192_gcm,   /* AES-GCM 192 */
     NID_aes_256_gcm,   /* AES-GCM 256 */
     NID_aes_128_ecb,   /* AES 128 ecb*/
     NID_aes_192_ecb,   /* AES 192 ecb*/
     NID_aes_256_ecb,   /* AES 256 ecb*/
#ifdef OCTEON3
    NID_camellia_128_cbc,
    NID_camellia_192_cbc,
    NID_camellia_256_cbc,
    NID_camellia_128_ecb,
    NID_camellia_192_ecb,
    NID_camellia_256_ecb,
    NID_camellia_128_ofb128,
    NID_camellia_192_ofb128,
    NID_camellia_256_ofb128,
    NID_camellia_128_cfb128,
    NID_camellia_192_cfb128,
    NID_camellia_256_cfb128,
    NID_camellia_128_cfb1,
    NID_camellia_192_cfb1,
    NID_camellia_256_cfb1,
    NID_camellia_128_cfb8,
    NID_camellia_192_cfb8,
    NID_camellia_256_cfb8,
#endif
   };

static int octeon_cipher_nids_number = sizeof(octeon_cipher_nids)/sizeof(int);

/**
 *  Cipher Registration 
 *
 * \retval SUCCESS 1
 * \retval FAILURE 0
 */
static int
octeon_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
   if (!cipher) {
      /* A List of supported NID's are returned */
      *nids = octeon_cipher_nids;
      return octeon_cipher_nids_number;
   }

   switch(nid) {
   case NID_des_ede3_cbc:
      *cipher = &octeon_des_ede3;
      break;
   case NID_des_cbc:
      *cipher = &octeon_des;
      break;
   case NID_aes_128_cbc:
      *cipher = &octeon_aes128;
      break;
   case NID_aes_192_cbc:
      *cipher = &octeon_aes192;
      break;
   case NID_aes_256_cbc:
      *cipher = &octeon_aes256;
      break;
   case NID_aes_128_gcm:
      *cipher = &octeon_aes_gcm_128;
      break;
   case NID_aes_192_gcm:
      *cipher = &octeon_aes_gcm_192;
      break;
   case NID_aes_256_gcm:
      *cipher = &octeon_aes_gcm_256;
      break;
   case NID_aes_128_ecb:
      *cipher = &octeon_aes128_ecb;
      break;
   case NID_aes_192_ecb:
      *cipher = &octeon_aes192_ecb;
      break;
   case NID_aes_256_ecb:
      *cipher = &octeon_aes256_ecb;
      break;
#ifdef OCTEON3
   case NID_camellia_128_cbc:
       *cipher = &octeon_cmll_128_cbc;
       break;
   case NID_camellia_192_cbc:
       *cipher = &octeon_cmll_192_cbc;
       break;
   case NID_camellia_256_cbc:
       *cipher = &octeon_cmll_256_cbc;
       break;
   case NID_camellia_128_ecb:
       *cipher = &octeon_cmll_128_ecb;
       break;
   case NID_camellia_192_ecb:
       *cipher = &octeon_cmll_192_ecb;
       break;
   case NID_camellia_256_ecb:
       *cipher = &octeon_cmll_256_ecb;
       break;
   case NID_camellia_128_ofb128:
       *cipher = &octeon_cmll_128_ofb128;
       break;
   case NID_camellia_192_ofb128:
       *cipher = &octeon_cmll_192_ofb128;
       break;
   case NID_camellia_256_ofb128:
       *cipher = &octeon_cmll_256_ofb128;
       break;
   case NID_camellia_128_cfb128:
       *cipher = &octeon_cmll_128_cfb128;
       break;
   case NID_camellia_192_cfb128:
       *cipher = &octeon_cmll_192_cfb128;
       break;
   case NID_camellia_256_cfb128:
       *cipher = &octeon_cmll_256_cfb128;
       break;
   case NID_camellia_128_cfb1:
       *cipher = &octeon_cmll_128_cfb1;
       break;
   case NID_camellia_192_cfb1:
       *cipher = &octeon_cmll_192_cfb1;
       break;
   case NID_camellia_256_cfb1:
       *cipher = &octeon_cmll_256_cfb1;
       break;
   case NID_camellia_128_cfb8:
       *cipher = &octeon_cmll_128_cfb8;
       break;
   case NID_camellia_192_cfb8:
       *cipher = &octeon_cmll_192_cfb8;
       break;
   case NID_camellia_256_cfb8:
       *cipher = &octeon_cmll_256_cfb8;
       break;
#endif
   default:
      return 0;
   }
   return OCT_SUCCESS;
}
#endif /* OCTEON_NO_CIPHERS */

#ifndef OCTEON_NO_DIGEST

#define OCTEON_SHA_CTX_SIZE    sizeof(oct_sha_ctx_data)

/**
 *  octeon_sha1_init 
 * 
 *  SHA1 digest initialisation function for Octeon engine
 *
 * 
 *  \retval SUCCESS 1
 *  \retval FAILURE 0
 */
static int
octeon_sha1_init(EVP_MD_CTX *ctx)
{
   oct_sha_ctx_data *digest_data = (oct_sha_ctx_data *)ctx->md_data;
   digest_data->H1 = 0x67452301EFCDAB89ull;
   digest_data->H2 = 0x98BADCFE10325476ull;
   digest_data->H3 = 0xC3D2E1F000000000ull;
   digest_data->init_done = 1;
   digest_data->total = 0;
   digest_data->pending = 0;
   return OCT_SUCCESS;
}

/**
 *  Can be called repeatedly with chunks of message to be hashed using sha1.
 * 
 * @param ctx     context structure which stores the state
 * @param data    Input data to be hashed
 * @param count   Size of the input data
 * @return 1 on success, 0 on failure
 */
static int
octeon_sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
   oct_sha_ctx_data *digest_data = (oct_sha_ctx_data *)ctx->md_data;
   int ret = 0;

   if (!count)
     return OCT_SUCCESS;

   ret = Oct_SHA1_Update(digest_data, (uint64_t *)data, count);

   return ret;
}

/**
 * Places the sha1 message digest in md
 * 
 * @param ctx    context structure which stores the state
 * @param md     Place where digest is stored, which must have space for 20 bytes of output
 * @return 1 on success, 0 on failure
 *
 */
static int
octeon_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
   oct_sha_ctx_data *digest_data = (oct_sha_ctx_data *)ctx->md_data;
   int ret = 0;

   ret = Oct_SHA1_Final(digest_data, md);
   return ret;
}

/* EVP DIGEST providing info about SHA1 digest offloaded functions */

static const EVP_MD octeon_sha =
   {
      NID_sha1,
      NID_sha1WithRSAEncryption,
      SHA_DIGEST_LENGTH,
      EVP_MD_FLAG_PKEY_METHOD_SIGNATURE|EVP_MD_FLAG_DIGALGID_ABSENT,
      octeon_sha1_init,
      octeon_sha1_update,
      octeon_sha1_final,
      NULL,
      NULL,
      EVP_PKEY_RSA_method,
      SHA_CBLOCK,
      sizeof(EVP_MD) + OCTEON_SHA_CTX_SIZE,
   };

#define OCTEON_SHA256_CTX_SIZE sizeof(oct_sha256_ctx_data)

#define OCTEON_SHA512_CTX_SIZE sizeof(oct_sha512_ctx_data)

/**
 *  octeon_sha256_init 
 * 
 *  SHA256 digest initialisation function for Octeon engine
 *
 * 
 *  \retval SUCCESS 1
 *  \retval FAILURE 0
 */
static int
octeon_sha256_init(EVP_MD_CTX *ctx)
{
  oct_sha256_ctx_data *digest_data=(oct_sha256_ctx_data *)ctx->md_data;
  digest_data->iv[0] = 0x6a09e667bb67ae85ull; 
  digest_data->iv[1] = 0x3c6ef372a54ff53aull;
  digest_data->iv[2] = 0x510e527f9b05688cull;
  digest_data->iv[3] = 0x1f83d9ab5be0cd19ull;
  digest_data->total = 0;
  digest_data->init_done = 1;
  digest_data->pending = 0;
  digest_data->sha256 = 1;
 
  return OCT_SUCCESS;

}

/**
 *  Can be called repeatedly with chunks of message to be hashed using sha256.
 * 
 * @param ctx     context structure which stores the state
 * @param data    Input data to be hashed
 * @param count   Size of the input data
 * @return 1 on success, 0 on failure
 */
static int
octeon_sha256_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
   oct_sha256_ctx_data *digest_data = (oct_sha256_ctx_data *)ctx->md_data;
   int ret = 0;

   if (!count)
     return OCT_SUCCESS;

   ret = Oct_SHA256_Update(digest_data, (uint64_t *)data, count);
   return ret;
}

/**
 * Places the sha256 message digest in md
 * 
 * @param ctx    context structure which stores the state
 * @param md     Place where digest is stored, which must have space for 32 bytes of output
 * @return 1 on success, 0 on failure
 *
 */
static int
octeon_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
   oct_sha256_ctx_data *digest_data = (oct_sha256_ctx_data *)ctx->md_data;
   int ret = 0;

   ret = Oct_SHA256_Final(digest_data, md);
   return ret;
}

/**
 *  octeon_sha224_init 
 * 
 *  SHA224 digest initialisation function for Octeon engine
 *
 * 
 *  \retval SUCCESS 1
 *  \retval FAILURE 0
 */
static int
octeon_sha224_init(EVP_MD_CTX *ctx)
{
  oct_sha256_ctx_data *digest_data=(oct_sha256_ctx_data *)ctx->md_data;
  digest_data->iv[0] = 0xc1059ed8367cd507ull;
  digest_data->iv[1] = 0x3070dd17f70e5939ull;
  digest_data->iv[2] = 0xffc00b3168581511ull;
  digest_data->iv[3] = 0x64f98fa7befa4fa4ull;
  digest_data->total = 0;
  digest_data->init_done = 1;
  digest_data->pending = 0;
  digest_data->sha256 = 0;
  
  return OCT_SUCCESS;

}

/**
 *  Can be called repeatedly with chunks of message to be hashed using sha224.
 * 
 * @param ctx     context structure which stores the state
 * @param data    Input data to be hashed
 * @param count   Size of the input data
 * @return 1 on success, 0 on failure
 */
static int
octeon_sha224_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return octeon_sha256_update (ctx, data, count);
}

/**
 * Places the sha224 message digest in md
 * 
 * @param ctx    context structure which stores the state
 * @param md     Place where digest is stored, which must have space for 28 bytes of output
 * @return 1 on success, 0 on failure
 *
 */
static int
octeon_sha224_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return octeon_sha256_final (ctx,md);
}

/* EVP DIGEST providing info about SHA224 digest offloaded functions */

static const EVP_MD octeon_sha224 =
   {
      NID_sha224,
      NID_sha224WithRSAEncryption,
      SHA224_DIGEST_LENGTH,
      EVP_MD_FLAG_PKEY_METHOD_SIGNATURE|EVP_MD_FLAG_DIGALGID_ABSENT,
      octeon_sha224_init,
      octeon_sha224_update,
      octeon_sha224_final,
      NULL,
      NULL,
      EVP_PKEY_RSA_method,
      64,
      sizeof(EVP_MD) + OCTEON_SHA256_CTX_SIZE,
   };

/* EVP DIGEST providing info about SHA256 digest offloaded functions */

static const EVP_MD octeon_sha256 =
   {
      NID_sha256,
      NID_sha256WithRSAEncryption,
      SHA256_DIGEST_LENGTH, 
      EVP_MD_FLAG_PKEY_METHOD_SIGNATURE|EVP_MD_FLAG_DIGALGID_ABSENT,
      octeon_sha256_init,
      octeon_sha256_update,
      octeon_sha256_final,
      NULL,
      NULL,
      EVP_PKEY_RSA_method,
      SHA256_CBLOCK,
      sizeof(EVP_MD) + OCTEON_SHA256_CTX_SIZE,
   };

/**
 *  octeon_sha512_init 
 * 
 *  SHA512 digest initialisation function for Octeon engine
 *
 * 
 *  \retval SUCCESS 1
 *  \retval FAILURE 0
 */
static int
octeon_sha512_init(EVP_MD_CTX *ctx)
{
  oct_sha512_ctx_data *digest_data=(oct_sha512_ctx_data *)ctx->md_data;
  digest_data->iv[0] = 0x6a09e667f3bcc908ull; 
  digest_data->iv[1] = 0xbb67ae8584caa73bull;
  digest_data->iv[2] = 0x3c6ef372fe94f82bull;
  digest_data->iv[3] = 0xa54ff53a5f1d36f1ull;
  digest_data->iv[4] = 0x510e527fade682d1ull;
  digest_data->iv[5] = 0x9b05688c2b3e6c1full;
  digest_data->iv[6] = 0x1f83d9abfb41bd6bull;
  digest_data->iv[7] = 0x5be0cd19137e2179ull;
  digest_data->total = 0;
  digest_data->init_done = 1;
  digest_data->pending = 0;
  digest_data->sha512 = 1;

  return OCT_SUCCESS;
}

/**
 *  Can be called repeatedly with chunks of message to be hashed using sha512.
 * 
 * @param ctx     context structure which stores the state
 * @param data    Input data to be hashed
 * @param count   Size of the input data
 * @return 1 on success, 0 on failure
 */
static int
octeon_sha512_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
   oct_sha512_ctx_data *digest_data = (oct_sha512_ctx_data *)ctx->md_data;
   int ret = 0;

   if (!count)
     return OCT_SUCCESS;

   ret = Oct_SHA512_Update(digest_data, (uint64_t *)data, count);
   return ret;
}

/**
 * Places the sha512 message digest in md
 * 
 * @param ctx    context structure which stores the state
 * @param md     Place where digest is stored, which must have space for 64 bytes of output
 * @return 1 on success, 0 on failure
 *
 */
static int
octeon_sha512_final(EVP_MD_CTX *ctx, unsigned char *md)
{
   oct_sha512_ctx_data *digest_data = (oct_sha512_ctx_data *)ctx->md_data;
   int ret = 0;

   ret = Oct_SHA512_Final(digest_data, md);
   return ret;
}

/**
 *  octeon_sha384_init 
 * 
 *  SHA384 digest initialisation function for Octeon engine
 *
 * 
 *  \retval SUCCESS 1
 *  \retval FAILURE 0
 */
static int
octeon_sha384_init(EVP_MD_CTX *ctx)
{
  oct_sha512_ctx_data *digest_data=(oct_sha512_ctx_data *)ctx->md_data;
  digest_data->iv[0] = 0xcbbb9d5dc1059ed8ull; 
  digest_data->iv[1] = 0x629a292a367cd507ull;
  digest_data->iv[2] = 0x9159015a3070dd17ull;
  digest_data->iv[3] = 0x152fecd8f70e5939ull;
  digest_data->iv[4] = 0x67332667ffc00b31ull;
  digest_data->iv[5] = 0x8eb44a8768581511ull;
  digest_data->iv[6] = 0xdb0c2e0d64f98fa7ull;
  digest_data->iv[7] = 0x47b5481dbefa4fa4ull;
  digest_data->total = 0;
  digest_data->init_done = 1;
  digest_data->pending = 0;
  digest_data->sha512 = 0;
  return OCT_SUCCESS;
}

/**
 *  Can be called repeatedly with chunks of message to be hashed using sha384.
 * 
 * @param ctx     context structure which stores the state
 * @param data    Input data to be hashed
 * @param count   Size of the input data
 * @return 1 on success, 0 on failure
 */
static int
octeon_sha384_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return octeon_sha512_update (ctx, data, count);
}

/**
 * Places the sha384 message digest in md
 * 
 * @param ctx    context structure which stores the state
 * @param md     Place where digest is stored, which must have space for 48 bytes of output
 * @return 1 on success, 0 on failure
 *
 */
static int
octeon_sha384_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return octeon_sha512_final (ctx,md);
}

/* EVP DIGEST providing info about SHA384 digest offloaded functions */

static const EVP_MD octeon_sha384 =
   {
      NID_sha384,
      NID_sha384WithRSAEncryption,
      SHA384_DIGEST_LENGTH,
      EVP_MD_FLAG_PKEY_METHOD_SIGNATURE|EVP_MD_FLAG_DIGALGID_ABSENT,
      octeon_sha384_init,
      octeon_sha384_update,
      octeon_sha384_final,
      NULL,
      NULL,
      EVP_PKEY_RSA_method,
      SHA512_CBLOCK,
      sizeof(EVP_MD) + OCTEON_SHA512_CTX_SIZE,
   };

/* EVP DIGEST providing info about SHA512 digest offloaded functions */

static const EVP_MD octeon_sha512 =
   {
      NID_sha512,
      NID_sha512WithRSAEncryption,
      SHA512_DIGEST_LENGTH, 
      EVP_MD_FLAG_PKEY_METHOD_SIGNATURE|EVP_MD_FLAG_DIGALGID_ABSENT,
      octeon_sha512_init,
      octeon_sha512_update,
      octeon_sha512_final,
      NULL,
      NULL,
      EVP_PKEY_RSA_method,
      SHA512_CBLOCK,
      sizeof(EVP_MD) + OCTEON_SHA512_CTX_SIZE,
   };


#define OCTEON_MD5_CTX_SIZE    sizeof(oct_md5_ctx_data)

/**
 *  octeon_md5_init 
 * 
 *  MD5 digest initialisation function for Octeon engine
 *
 * 
 *  \retval SUCCESS 1
 *  \retval FAILURE 0
 */
static int
octeon_md5_init(EVP_MD_CTX *ctx)
{
   oct_md5_ctx_data *digest_data = (oct_md5_ctx_data *)ctx->md_data;
   digest_data->H1 = 0x0123456789abcdefull;
   digest_data->H2 = 0xfedcba9876543210ull;
   digest_data->pending = 0;
   digest_data->total = 0;
   digest_data->init_done = 1;
   return OCT_SUCCESS;
}

/**
 *    Can be called repeatedly with chunks of message to be hashed using md5.
 *  
 *    @param ctx      context structure which stores the state
 *    @param data     pointer to Input data to be hashed
 *    @param count    Size of the input data
 *    @return         1 on success, 0 on failure
 */
static int
octeon_md5_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
   oct_md5_ctx_data *digest_data = (oct_md5_ctx_data *)ctx->md_data;
   int ret = 0;

   if (!count)
      return OCT_SUCCESS;

   ret = Oct_MD5_Update(digest_data, (uint64_t *)data, count);
   return ret;
}

/**
 *  Places the message digest in md
 *  
 *  @param  ctx     context structure which stores the state
 *  @param  md      Place where digest is stored, which must have space for 16 bytes of output
 *  @return         1 on success, 0 on failure
 */

static int
octeon_md5_final(EVP_MD_CTX *ctx, unsigned char *md)
{
   oct_md5_ctx_data *digest_data = (oct_md5_ctx_data *)ctx->md_data;
   int ret = 0;

   ret = Oct_MD5_Final(digest_data, md);
   return ret;
}

/* EVP DIGEST providing info about MD5 digest offloaded functions */

static const EVP_MD octeon_md5 =
   {
      NID_md5,
      NID_md5WithRSAEncryption,
      MD5_DIGEST_LENGTH,
      0,
      octeon_md5_init,
      octeon_md5_update,
      octeon_md5_final,
      NULL,
      NULL,
      EVP_PKEY_RSA_method,
      MD5_CBLOCK,
      sizeof(EVP_MD) + OCTEON_MD5_CTX_SIZE
   };

static const EVP_MD octeon_dss1_md=
        {
        NID_dsa,
        NID_dsaWithSHA1,
        SHA_DIGEST_LENGTH,
        0,
        octeon_sha1_init,
        octeon_sha1_update,
        octeon_sha1_final,
        NULL,
        NULL,
        EVP_PKEY_DSA_method,
        SHA_CBLOCK,
        sizeof(EVP_MD *)+sizeof(SHA_CTX),
        };

/* List of Octeon supported digests NID's */
static int octeon_digest_nids[] =
{
      NID_sha1,
      NID_md5,
      NID_sha224,
      NID_sha256,
      NID_sha384,
      NID_sha512,
      NID_dsa 
};

static int octeon_digest_nids_number = sizeof(octeon_digest_nids)/sizeof(int);

/**
 *  Digests Registration 
 *  
 *  \retval SUCCESS 1
 *  \retval FAILURE 0
 *
 */
static int
octeon_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
   if (!digest) {
      /* A List of supported NID's are returned */
      *nids = octeon_digest_nids;
      return octeon_digest_nids_number;
   }

   switch(nid) {
   case NID_sha1:
      *digest = &octeon_sha;
      break;
   case NID_md5:
      *digest = &octeon_md5;
      break;
   case NID_sha224:
      *digest = &octeon_sha224;
      break;
   case NID_sha256:
      *digest = &octeon_sha256;
      break;
   case NID_sha384:
      *digest = &octeon_sha384;
      break;
   case NID_sha512:
      *digest = &octeon_sha512;
      break;
   case NID_dsa:
      *digest = &octeon_dss1_md;
      break;

   default:
      return 0;
   }
   return OCT_SUCCESS;
}
#endif /* OCTEON_NO_DIGEST */

static int
octeon_bind_helper(ENGINE *e)
{
#ifndef OPENSSL_NO_RSA
   {
      const RSA_METHOD *def_meth = RSA_PKCS1_SSLeay();
      octeon_rsa.rsa_pub_enc =  def_meth->rsa_pub_enc;
      octeon_rsa.rsa_pub_dec =  def_meth->rsa_pub_dec;
      octeon_rsa.rsa_priv_enc = def_meth->rsa_priv_enc;
      octeon_rsa.rsa_priv_dec = def_meth->rsa_priv_dec;
      octeon_rsa.rsa_sign = def_meth->rsa_sign;
      octeon_rsa.rsa_verify = def_meth->rsa_verify;
      octeon_rsa.rsa_keygen = def_meth->rsa_keygen;
   }
#endif
#ifndef OPENSSL_NO_DH
   {
      const DH_METHOD * meth = DH_OpenSSL();
      octeon_dh.generate_key = meth->generate_key;
      octeon_dh.compute_key = meth->compute_key;
   }
#endif
#ifndef OPENSSL_NO_DSA
   {
      const DSA_METHOD *meth = DSA_OpenSSL();
      octeon_dsa.dsa_do_sign = meth->dsa_do_sign;
      octeon_dsa.dsa_sign_setup = meth->dsa_sign_setup;
      octeon_dsa.dsa_do_verify = meth->dsa_do_verify;
      octeon_dsa.dsa_keygen = meth->dsa_keygen;
   }
#endif

   if (!ENGINE_set_id(e, octeon_engine_id) ||
       !ENGINE_set_name(e, octeon_engine_name) ||
#ifndef OPENSSL_NO_RSA
       !ENGINE_set_RSA(e, &octeon_rsa) ||
#endif
#ifndef OPENSSL_NO_DH
       !ENGINE_set_DH(e, &octeon_dh) ||
#endif
#ifndef OPENSSL_NO_DSA
       !ENGINE_set_DSA(e, &octeon_dsa) ||
#endif
       !ENGINE_set_init_function(e, octeon_init) ||
       !ENGINE_set_ctrl_function(e, octeon_ctrl) ||
       !ENGINE_set_destroy_function(e, octeon_destroy) ||
#ifndef OCTEON_NO_CIPHERS
       !ENGINE_set_ciphers(e, octeon_ciphers) ||
#endif
#ifndef OCTEON_NO_DIGEST
       !ENGINE_set_digests(e, octeon_digests) ||
#endif
       !ENGINE_set_finish_function(e, octeon_shutdown)) {
         printf("octeon_bind helper returning error \n");
          return 0;
   } 

   FILE *infile = fopen("/proc/octeon_info", "r");
   if (infile) {
      while (!feof(infile)) {
           char buffer[80];
           if (fgets(buffer, sizeof(buffer), infile)) {
              const char *field = strtok(buffer, " ");
              const char * valueS = strtok(NULL, " ");
              unsigned long long value;
              if (field == NULL)
                 continue;
              if (valueS == NULL)
                 continue;
              sscanf(valueS, "%lli", &value);
              if (strcmp(field, "processor_id:") == 0) {
                 cvmx_app_init_processor_id = value;
                        break;
              }
           }
      }
      fclose(infile);   
   }
   ERR_load_OCTEON_strings();
   return OCT_SUCCESS;
}

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *
engine_octeon(void)
{
   ENGINE *ret = ENGINE_new();
   if (!ret) {
      return NULL;
   }
   if (!octeon_bind_helper(ret)) {
      ENGINE_free(ret);
      return NULL;
   }
   return ret;
}

void 
ENGINE_load_octeon()
{
   ENGINE *ret = engine_octeon();
   if (!ret)
      return; 
   ENGINE_add(ret);
   ENGINE_free(ret);
   ERR_clear_error();
}
#else /* OPENSSL_NO_DYNAMIC_ENGINE */
static int bind_fn(ENGINE *e, const char *id)
{
   if (id && (strcmp(id, octeon_engine_id) != 0))
      return 0;
   if (!octeon_bind_helper(e))
      return 0;
   return OCT_SUCCESS;
}
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif /* ! OPENSSL_NO_DYNAMIC_ENGINE */
