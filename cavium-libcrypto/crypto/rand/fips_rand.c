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
 * @file fips_rand.c
 * API for generating random numbers
*/

#include "cvmx.h"
#include "cvmx-rng.h"
#include <openssl/des.h>
#include <openssl/fips_random.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define ROUNDUP8(val) (((val) + 7)&0xfffffff8)

/* #define V_IS_CRNG */
/* Define this if CRNG Testing is required */
/* #define CRNG_TEST */
/* Define this for CRNG Error Injection :
 *          Zero is not a proper value 
 */
/* #define CRNG_ERROR_FREQ    3  */

#ifdef NO_CRNG_TEST
#undef CRNG_TEST
#endif

static CVMX_SHARED uint8_t oct_rng_enabled = 0;
#ifdef CRNG_TEST
static CVMX_SHARED uint8_t oct_fipsrand_start = 0;
static CVMX_SHARED uint8_t oct_prev_crng_rand[16];
static CVMX_SHARED uint64_t oct_prev_hwrng_rand = 0;
#endif
#ifdef CRNG_ERROR_FREQ
static CVMX_SHARED int oct_rng_calls = 0;
static CVMX_SHARED int oct_is_hwrng_fail = 1; /* 1 for hw rng, 
                                             0 for rand */ 
#endif

static inline int
cvm_rand_hwbug(void)
{
   if (OCTEON_IS_MODEL(OCTEON_CN56XX_PASS1))
      return 1;
   return 0;
}
/**
 * Generates Random number of given length
 * @param len      Size of random number required in Bytes
 * @param output   Output where random number is stored
 * @return       length of random bytes generated on Success
*/

int
oct_rand_generate(uint8_t * output, uint64_t len)
{
  uint64_t out;
  if (cvmx_unlikely(cvm_rand_hwbug())) {
     uint64_t cycle = cvmx_get_cycle();
     uint32_t seed = (uint32_t)cycle;
     srand(seed);
     while (len >= 4) {
        *(uint32_t *) output = rand();
        len -= 4;
        output += 4;
     }
     /* check remainig Non 8B boundary */
     if (len) {
        out = rand();
        *(uint32_t *) output =
           *(uint32_t *) output | (out << (32 - (len << 2)));
     }
     return 0;
   }

   /* Check if this core RNG is enabled else call rand_init */
   if (cvmx_unlikely(!oct_rng_enabled)) {
      cvmx_rng_enable();
#ifdef CRNG_TEST
      oct_prev_hwrng_rand = cvmx_rng_get_random64();
#endif
      oct_rng_enabled = 1;
   }

  while (len >= 8) {
    out = cvmx_rng_get_random64 ();
#ifdef CRNG_TEST
    if (out == oct_prev_hwrng_rand) 
       return OCT_RAND_CRNG_FAILURE;
    oct_prev_hwrng_rand = out;
#ifdef CRNG_ERROR_FREQ
    if (oct_is_hwrng_fail && 
        (oct_rng_calls == CRNG_ERROR_FREQ)) {
       oct_rng_calls = 0;
       oct_is_hwrng_fail = 0;
       return OCT_RAND_CRNG_FAILURE;
    } 
#endif
#endif
    *(uint64_t *) output = out;
    len -= 8;
    output += 8;
  }
  /* check remainig Non 8B boundary */
  if (len) {
    out = cvmx_rng_get_random64 ();
#ifdef CRNG_TEST
    if (out == oct_prev_hwrng_rand) 
       return OCT_RAND_CRNG_FAILURE;
    oct_prev_hwrng_rand = out;
#ifdef CRNG_ERROR_FREQ
    if (oct_is_hwrng_fail && 
        (oct_rng_calls == CRNG_ERROR_FREQ)) {
       oct_rng_calls = 0;
       oct_is_hwrng_fail = 0;
       return OCT_RAND_CRNG_FAILURE;
     }
#endif
#endif
    *(uint64_t *) output =
      *(uint64_t *) output | (out << (64 - (len << 3)));
  }
  return 0;
}

#ifndef CRNG_TEST
#define CRNG_AES_VERIFY(res0, res1, cmp0, cmp1)   
#define CRNG_TDES_VERIFY(res0, cmp0) 
#else 
/* CRNG_TEST defined */
#ifndef CRNG_ERROR_FREQ
#define CRNG_AES_VERIFY(res0, res1, cmp0, cmp1) \
   if ((res0 == cmp0) && (res1 == cmp1)) \
      return OCT_RAND_CRNG_FAILURE; \
   cmp0 = res0;  \
   cmp1 = res1;  

#define CRNG_TDES_VERIFY(res0, cmp0) \
   if (res0 == cmp0) \
      return OCT_RAND_CRNG_FAILURE; \
   cmp0 = res0;  
#else
/* CRNG_ERROR_FREQ defined .. 
   Error frequency checks are done here instead
   of in oct_fipsrand_generate() just to consolidate
   the crng failures here only. This makes things
   look clumsier, but it should do the work.
 */
#define CRNG_AES_VERIFY(res0, res1, cmp0, cmp1) \
   if ((res0 == cmp0) && (res1 == cmp1)) \
      return OCT_RAND_CRNG_FAILURE; \
   cmp0 = res0;  \
   cmp1 = res1;  \
   if (!oct_is_hwrng_fail &&  \
       (oct_rng_calls == CRNG_ERROR_FREQ)) { \
      oct_rng_calls = 0; \
      oct_is_hwrng_fail = 1; \
      return OCT_RAND_CRNG_FAILURE; \
   }

#define CRNG_TDES_VERIFY(res0, cmp0) \
   if (res0 == cmp0) \
      return OCT_RAND_CRNG_FAILURE; \
   cmp0 = res0;  \
   if (!oct_is_hwrng_fail &&  \
       (oct_rng_calls == CRNG_ERROR_FREQ)) { \
      oct_rng_calls = 0; \
      oct_is_hwrng_fail = 1; \
      return OCT_RAND_CRNG_FAILURE; \
   }

#endif /* CRNG_ERROR_FREQ */
#endif /* CRNG_TEST */

/*
 * NIST Recommended RNG based on ANSI X9.31 Appendix A2.4
 */
static int
oct_fipsrand_aes256_gen(uint64_t *K, uint64_t *DT, uint64_t *V,
                        uint8_t *rand, uint64_t len,
                        uint64_t *DT_out, uint64_t *V_out)  
{
   uint64_t r0, r1, i0, i1, dt0, dt1, v0, v1,zero = 0;
   uint64_t *pr = (uint64_t *)rand;
   int bl_rem = len & 0xF;

   for (;bl_rem > 0; bl_rem--) {
        rand[len - bl_rem] = 0;
   }

   CVMX_MT_AES_KEY(K[0], 0);
   CVMX_MT_AES_KEY(K[1], 1);
   CVMX_MT_AES_KEY(K[2], 2);
   CVMX_MT_AES_KEY(K[3], 3);
   CVMX_MT_AES_KEYLENGTH(3);

   dt0 = DT[0];
   dt1 = DT[1];

   CVMX_MT_AES_IV(zero, 0);
   CVMX_MT_AES_IV(zero, 1);

   CVMX_MT_AES_ENC_CBC0(dt0);
   CVMX_MT_AES_ENC_CBC1(dt1);

   v0 = V[0];
   v1 = V[1];

   CVMX_MF_AES_RESULT(i0, 0);
   CVMX_MF_AES_RESULT(i1, 1);

   while(1) {
      CVMX_MT_AES_ENC_CBC0(v0);
      CVMX_MT_AES_ENC_CBC1(v1);
      dt1++;
      if (cvmx_unlikely(dt1 == 0))
         dt0 += 1;

      CVMX_MF_AES_RESULT(r0, 0);
      CVMX_MF_AES_RESULT(r1, 1);

      CVMX_MT_AES_ENC_CBC0(i0);
      CVMX_MT_AES_ENC_CBC1(i1);

      CRNG_AES_VERIFY(r0, r1, oct_prev_crng_rand[0], oct_prev_crng_rand[1]);
      if (len == 16) {
         len = 0;
         break;
      }
      if (len < 16)
         break;

      len -= 16;

      pr[0] = r0;
      pr[1] = r1;
      pr +=2;

      CVMX_MF_AES_RESULT(v0, 0);
      CVMX_MF_AES_RESULT(v1, 1);

      CVMX_MT_AES_IV(zero, 0);
      CVMX_MT_AES_IV(zero, 1);

      CVMX_MT_AES_ENC_CBC0(dt0);
      CVMX_MT_AES_ENC_CBC1(dt1);
   
      CVMX_MF_AES_RESULT(i0, 0);
      CVMX_MF_AES_RESULT(i1, 1);
   }

   if (!len) {
      pr[0] = r0;
      pr[1] = r1;
   } else {
      /* Non 16 byte multiple */
      /* Avoiding memcpy */
      if (len <= 8) {
          *pr = *pr | (r0 << (64 - (len << 3)));
      } else {
         *pr = r0;
         pr++;
         len -= 8;
          *pr = *pr | (r1 << (64 - (len << 3)));
      }
   }

   CVMX_MF_AES_RESULT(v0, 0);
   CVMX_MF_AES_RESULT(v1, 1);

   if (V_out) {
      V_out[0] = v0;
      V_out[1] = v1;
   }
   if (DT_out) {
      DT_out[0] = dt0;
      DT_out[1] = dt1;
   }

   return 0;
}

static int
oct_fipsrand_aes192_gen(uint64_t *K, uint64_t *DT, uint64_t *V,
                        uint8_t *rand, uint64_t len,
                        uint64_t *DT_out, uint64_t *V_out)  
{
   uint64_t r0, r1, i0, i1, dt0, dt1, v0, v1,zero = 0;
   uint64_t *pr = (uint64_t *)rand;
   int bl_rem = len & 0xF;

   for (;bl_rem > 0; bl_rem--) {
      rand[len - bl_rem] = 0;
   }

   CVMX_MT_AES_KEY(K[0], 0);
   CVMX_MT_AES_KEY(K[1], 1);
   CVMX_MT_AES_KEY(K[2], 2);
   CVMX_MT_AES_KEY((uint64_t)0, 3);   
   CVMX_MT_AES_KEYLENGTH(2);

   dt0 = DT[0];
   dt1 = DT[1];

   CVMX_MT_AES_IV(zero, 0);
   CVMX_MT_AES_IV(zero, 1);

   CVMX_MT_AES_ENC_CBC0(dt0);
   CVMX_MT_AES_ENC_CBC1(dt1);

   v0 = V[0];
   v1 = V[1];

   CVMX_MF_AES_RESULT(i0, 0);
   CVMX_MF_AES_RESULT(i1, 1);

   while(1) {
      CVMX_MT_AES_ENC_CBC0(v0);
      CVMX_MT_AES_ENC_CBC1(v1);

      dt1++;
      if (cvmx_unlikely(dt1 == 0))
         dt0 += 1;

      CVMX_MF_AES_RESULT(r0, 0);
      CVMX_MF_AES_RESULT(r1, 1);

      CRNG_AES_VERIFY(r0, r1, oct_prev_crng_rand[0], oct_prev_crng_rand[1]);
      CVMX_MT_AES_ENC_CBC0(i0);
      CVMX_MT_AES_ENC_CBC1(i1);

      if (len == 16) {
         len = 0;
         break;
      }
      if (len < 16)
         break;

      len -= 16;

      pr[0] = r0;
      pr[1] = r1;
      pr +=2;

      CVMX_MT_AES_IV(zero, 0);
      CVMX_MT_AES_IV(zero, 1);

      CVMX_MT_AES_ENC_CBC0(dt0);
      CVMX_MT_AES_ENC_CBC1(dt1);
   
      CVMX_MF_AES_RESULT(i0, 0);
      CVMX_MF_AES_RESULT(i1, 1);
   }

   if (!len) {
      pr[0] = r0;
      pr[1] = r1;
   } else {
      /* Non 16 byte multiple */
      /* Avoiding memcpy */
      if (len <= 8) {
          *pr = *pr | (r0 << (64 - (len << 3)));
      } else {
         *pr = r0;
         pr++;
         len -= 8;
          *pr = *pr | (r1 << (64 - (len << 3)));
      }
   }

   CVMX_MF_AES_RESULT(v0, 0);
   CVMX_MF_AES_RESULT(v1, 1);

   if (V_out) {
      V_out[0] = v0;
      V_out[1] = v1;
   }
   if (DT_out) {
      DT_out[0] = dt0;
      DT_out[1] = dt1;
   }

   return 0;
}

static int
oct_fipsrand_aes128_gen(uint64_t *K, uint64_t *DT, uint64_t *V,
                        uint8_t *rand, uint64_t len,
                        uint64_t *DT_out, uint64_t *V_out)  
{
   uint64_t r0, r1, i0, i1, dt0, dt1, v0, v1,zero = 0;
   uint64_t *pr = (uint64_t *)rand;
   int bl_rem = len & 0xF;

   for (;bl_rem > 0; bl_rem--) {
      rand[len - bl_rem] = 0;
   }


   CVMX_MT_AES_KEY(K[0], 0);
   CVMX_MT_AES_KEY(K[1], 1);
   CVMX_MT_AES_KEY((uint64_t)0, 2);   
   CVMX_MT_AES_KEY((uint64_t)0, 3);   
   CVMX_MT_AES_KEYLENGTH(1);

   dt0 = DT[0];
   dt1 = DT[1];

   CVMX_MT_AES_IV(zero, 0);
   CVMX_MT_AES_IV(zero, 1);

   CVMX_MT_AES_ENC_CBC0(dt0);
   CVMX_MT_AES_ENC_CBC1(dt1);

   v0 = V[0];
   v1 = V[1];

   CVMX_MF_AES_RESULT(i0, 0);
   CVMX_MF_AES_RESULT(i1, 1);

   while(1) {
      CVMX_MT_AES_ENC_CBC0(v0);
      CVMX_MT_AES_ENC_CBC1(v1);

      dt1++;
      if (cvmx_unlikely(dt1 == 0))
         dt0 += 1;

      CVMX_MF_AES_RESULT(r0, 0);
      CVMX_MF_AES_RESULT(r1, 1);

      CRNG_AES_VERIFY(r0, r1, oct_prev_crng_rand[0], oct_prev_crng_rand[1]);
      CVMX_MT_AES_ENC_CBC0(i0);
      CVMX_MT_AES_ENC_CBC1(i1);

      if (len == 16) {
         len = 0;
         break;
      }
      if (len < 16)
         break;
      len -= 16;

      pr[0] = r0;
      pr[1] = r1;
      pr +=2;

      CVMX_MF_AES_RESULT(v0, 0);
      CVMX_MF_AES_RESULT(v1, 1);

      CVMX_MT_AES_IV(zero, 0);
      CVMX_MT_AES_IV(zero, 1);

      CVMX_MT_AES_ENC_CBC0(dt0);
      CVMX_MT_AES_ENC_CBC1(dt1);
   
      CVMX_MF_AES_RESULT(i0, 0);
      CVMX_MF_AES_RESULT(i1, 1);
   }

   if (!len) {
      pr[0] = r0;
      pr[1] = r1;
   } else {
      /* Non 16 byte multiple */
      /* Avoiding memcpy */
      if (len <= 8) {
          *pr = *pr | (r0 << (64 - (len << 3)));
      } else {
         *pr = r0;
         pr++;
         len -= 8;
          *pr = *pr | (r1 << (64 - (len << 3)));
      }
   }

   CVMX_MF_AES_RESULT(v0, 0);
   CVMX_MF_AES_RESULT(v1, 1);

   if (V_out) {
      V_out[0] = v0;
      V_out[1] = v1;
   }
   if (DT_out) {
      DT_out[0] = dt0;
      DT_out[1] = dt1;
   }

   return 0;
}

static int
oct_fipsrand_3des_gen(uint64_t *K, uint64_t *DT, uint64_t *V,
                      uint8_t *rand, uint64_t len,
                      uint64_t *DT_out, uint64_t *V_out)  
{
   register uint64_t i, dt, v, r;
   uint64_t *pr = (uint64_t *)rand;
   uint64_t zero = 0;
   int bl_rem = len & 0x7;

   for (;bl_rem > 0; bl_rem--) {
      rand[len - bl_rem] = 0;
   }

   CVMX_MT_3DES_KEY(K[0], 0);
   CVMX_MT_3DES_KEY(K[1], 1);
   CVMX_MT_3DES_KEY(K[2], 2);

   dt = DT[0];

   CVMX_MT_3DES_IV(zero);

   CVMX_MT_3DES_ENC_CBC(dt);

   v = V[0];

   CVMX_MF_3DES_RESULT(i);

   while(1) {
      CVMX_MT_3DES_ENC_CBC(v);

      dt++;

      CVMX_MF_3DES_RESULT(r);

      CRNG_TDES_VERIFY(r, oct_prev_crng_rand[0]);

      CVMX_MT_3DES_ENC_CBC(i);

      if (len == 8) {
         len = 0;
         break;
      }
      if (len < 8)
         break;
      len -= 8;

      pr[0] = r;
      pr++;

      CVMX_MF_3DES_RESULT(v);

      CVMX_MT_3DES_IV(zero);
      CVMX_MT_3DES_ENC_CBC(dt);
      CVMX_MF_3DES_RESULT(i);
   }

   if (!len) {
      pr[0] = r;
   } else {
      /* Non 8 byte multiple */
      /* Avoiding memcpy */
      *pr = *pr | (r << (64 - (len << 3)));
   }
   CVMX_MF_3DES_RESULT(v);
   if (V_out) {
      V_out[0] = v;
   }
   if (DT_out) {
      DT_out[0] = dt;
   }

   return 0;
}

int
oct_fipsrand_init(oct_fipsrand_algo_t algo, uint8_t *K, uint8_t *DT, 
                  uint8_t *V, oct_fipsrand_ctx_t *ctx)
{
   int key_len, dt_v_len;
   if (ctx == NULL) {
      return -1;
   }

   switch (algo) {
      case OCT_FIPSRAND_3DES:
         key_len = 24;
         dt_v_len = 8;
         break;
      case OCT_FIPSRAND_AES128:
         key_len = 16;
         dt_v_len = 16;
         break;
      case OCT_FIPSRAND_AES192:
         key_len = 24;
         dt_v_len = 16;
         break;
      case OCT_FIPSRAND_AES256:
         key_len = 32;
         dt_v_len = 16;
         break;
      default:
         return -1;
   }
   memset(ctx, 0, sizeof(oct_fipsrand_ctx_t));

   memcpy((uint8_t *)(ctx->K), K, key_len);
   memcpy((uint8_t *)(ctx->DT), DT, dt_v_len);
   memcpy((uint8_t *)(ctx->V), V, dt_v_len);
   ctx->algo = algo;
   ctx->init_sig = OCT_FIPS_RAND_SIG;
   return 0;
}
                  

int
oct_fipsrand_generate(uint8_t *rand, uint64_t len, void *ctx)
{
   oct_fipsrand_ctx_t *rctx = (oct_fipsrand_ctx_t *)ctx;
   int (*fn)(uint64_t *K, uint64_t *DT, uint64_t *V, 
             uint8_t *rand, uint64_t len, uint64_t *DT_out, uint64_t *V_out);


   if (cvmx_likely(rctx == NULL)) {
      /* Using Local variables to avoid using OPENSSL_malloc for ctx */
      uint8_t K[32], DT[16], V[16];
      int ret;

#ifdef CRNG_ERROR_FREQ
      oct_rng_calls++;
      if (cvmx_unlikely(oct_rng_calls > CRNG_ERROR_FREQ)) {
         oct_rng_calls = 0;
      }
#endif
      ret = oct_rand_generate(K, 32);
      if (ret)
          return ret;
      ret = oct_rand_generate(DT, 16);
      if (ret)
          return ret;
      ret = oct_rand_generate(V, 16);
      if (ret)
          return ret;
#ifdef CRNG_TEST
      if (cvmx_unlikely(!oct_fipsrand_start)) {
         oct_fipsrand_aes256_gen((uint64_t *)K,
                                 (uint64_t *)DT,
                                 (uint64_t *)V,
                                 oct_prev_crng_rand, 16,
                                 (uint64_t *)NULL, 
                                 (uint64_t *)NULL);
         oct_fipsrand_start = 1;
      }
#endif
#ifdef V_IS_CRNG
      ret = oct_fipsrand_aes256_gen((uint64_t *)K,
                                    (uint64_t *)DT,
                                    (uint64_t *)V,
                                    V, 16,
                                    (uint64_t *)NULL, 
                                    (uint64_t *)NULL);
      if (ret) return ret;
#endif
      return oct_fipsrand_aes256_gen((uint64_t *)K,
                                     (uint64_t *)DT,
                                     (uint64_t *)V,
                                     rand, len,
                                     (uint64_t *)NULL, 
                                     (uint64_t *)NULL);
   } else {
      if (rctx->init_sig != OCT_FIPS_RAND_SIG)
         return -1;
      
      switch (rctx->algo) {
         case OCT_FIPSRAND_3DES:
            fn = oct_fipsrand_3des_gen;
            break;
         case OCT_FIPSRAND_AES128:
            fn = oct_fipsrand_aes128_gen;
            break;
         case OCT_FIPSRAND_AES192:
            fn = oct_fipsrand_aes192_gen;
            break;
         case OCT_FIPSRAND_AES256:
            fn = oct_fipsrand_aes256_gen;
            break;
         default:
            return -1;
      }
#ifdef CRNG_TEST
      if (cvmx_unlikely(!oct_fipsrand_start)) {
         fn(rctx->K,
            rctx->DT,
            rctx->V,
            oct_prev_crng_rand, 16,
            rctx->DT,
            rctx->V);
         oct_fipsrand_start = 1;
      }
#endif
      return fn(rctx->K,
                rctx->DT,
                rctx->V,
                rand,
                len,
                rctx->DT, 
                rctx->V);
   }
}

/**
 * DRBG specific
 */

static int AES256_BCC(uint8_t *inp, int inlen, uint8_t *output)
{
	uint64_t res0 = 0x0ull, res1 = 0x0ull, *p = (uint64_t *)inp;

	/* Load key */
	/* Assuming key loaded already */

	#ifdef USE_CBC
 	/* Load IV as zero */
    	CVMX_MT_AES_IV(0x0ull,0);
    	CVMX_MT_AES_IV(0x0ull,1);
	#endif

	/* Start chaining process - CBC*/
	while (inlen) {
		#ifdef USE_CBC
        	CVMX_MT_AES_ENC_CBC0(*p);
        	CVMX_MT_AES_ENC_CBC1(*(p+1));
		#else
		res0 = res0 ^ p[0];
		res1 = res1 ^ p[1];
		CVMX_MT_AES_ENC0(res0);
		CVMX_MT_AES_ENC1(res1);
		#endif
		inlen -= 16;
		p += 2;
		/* Discarding output - not required */
		CVMX_MF_AES_RESULT(res0, 0);
		CVMX_MF_AES_RESULT(res1, 1);

	}

	/* Get result into output */
	*(uint64_t *) output = res0;
	*(uint64_t *) (output + 8) = res1;

	return 0;
}

static int AES256_df(uint8_t *str, int strlen, uint8_t *output, int outplen)
{
//	uint8_t S[16 + 384/8 + 16]; 
	uint8_t S[16 + MAX_LEN + 16]; /* 16 bytes initial for IV, last 16 bytes is to round it off to next outlen (128 bits) */	
	uint64_t X[2];
	uint64_t K[4];
	volatile uint32_t *p = (uint32_t *)S;

	if (strlen > MAX_LEN) {
		printf("error strlen %d %d\n", strlen, MAX_LEN);
		return -1;
	}

	memset(S, 0, 16 + MAX_LEN + 16);
	*p = 0; /* IV: starts with zero will be filled in later */
	p+=4;
	*p = strlen;
	p++;
	*p = outplen;
	p++;
	memcpy(S + 24, str, strlen);
	S[strlen + 24] = 0x80;

	/* Load new key 0x0001.. 0x1F*/
	CVMX_MT_AES_KEY(0x0001020304050607ull, 0);
	CVMX_MT_AES_KEY(0x08090a0b0c0d0e0full, 1);
	CVMX_MT_AES_KEY(0x1011121314151617ull, 2);
	CVMX_MT_AES_KEY(0x18191a1b1c1d1e1full, 3);
	CVMX_MT_AES_KEYLENGTH(256/64 - 1);


	/* Do thrice bcc function */
	p = (uint32_t *)S;
	AES256_BCC(S, 16 + strlen + 16, (uint8_t *)K);


	/* next IV : Check compiler might optimize this, and lose this */	
	*p = 1;
	AES256_BCC(S, 16 + strlen + 16, (uint8_t *)&K[2]);

	/* next IV : Check compiler might optimize this, and lose this */	
	*p = 2;
	AES256_BCC(S, 16 + strlen + 16, (uint8_t *)X);

	/* Load new key */
	CVMX_MT_AES_KEY(K[0], 0);
	CVMX_MT_AES_KEY(K[1], 1);
	CVMX_MT_AES_KEY(K[2], 2);
	CVMX_MT_AES_KEY(K[3], 3);
	CVMX_MT_AES_KEYLENGTH(256/64 - 1);

	while (outplen >= 16) {
		CVMX_MT_AES_ENC0(X[0]);
		CVMX_MT_AES_ENC1(X[1]);
		CVMX_MF_AES_RESULT(X[0], 0);
		CVMX_MF_AES_RESULT(X[1], 1);
		memcpy(output, X, 16);
		output += 16;
		outplen -=16;
	}

	if (outplen) {
		CVMX_MT_AES_ENC0(X[0]);
		CVMX_MT_AES_ENC1(X[1]);
		CVMX_MF_AES_RESULT(X[0], 0);
		CVMX_MF_AES_RESULT(X[1], 1);
		memcpy(output, X, outplen);
	}

	return 0;
}

static int ctr_drbg_update(uint8_t *str, int strlen, ctr_drbg_state_t *s)
{
	uint64_t *p, res[384/64]; /* Seedlen = 384 bits = 48 bytes = 6 dwords */
	int i;

	if (strlen != 384/8)
		return ERR_UPDATE_PARAMS; 

	CVMX_MT_AES_KEY(s->k[0], 0);
	CVMX_MT_AES_KEY(s->k[1], 1);
	CVMX_MT_AES_KEY(s->k[2], 2);
	CVMX_MT_AES_KEY(s->k[3], 3);
	/* AES keysize of 256bits */
	CVMX_MT_AES_KEYLENGTH(256/64 - 1);

	/* 
 	 * Encrypt three blocks:
	 * From the spec, while len(temp) < seedlen 
	 * where(for AES-256) seedlen = outlen(128) + keylen(256) = 384bits(48bytes)
	 */
	s->vl++;
	if (!s->vl)
		s->vh++;

	/*Encrypt v, with Key */
	CVMX_MT_AES_ENC0(s->vh);
	CVMX_MT_AES_ENC1(s->vl);


	s->vl++;
	if (!s->vl)
		s->vh++;
	
	CVMX_MF_AES_RESULT(res[0], 0);
	CVMX_MF_AES_RESULT(res[1], 1);

	/*Encrypt v, with Key */
	CVMX_MT_AES_ENC0(s->vh);
	CVMX_MT_AES_ENC1(s->vl);

	s->vl++;
	if (!s->vl)
		s->vh++;

	CVMX_MF_AES_RESULT(res[2], 0);
	CVMX_MF_AES_RESULT(res[3], 1);

	/*Encrypt v, with Key */
	CVMX_MT_AES_ENC0(s->vh);
	CVMX_MT_AES_ENC1(s->vl);

	/* Get result in res */
	CVMX_MF_AES_RESULT(res[4], 0);
	CVMX_MF_AES_RESULT(res[5], 1);

	/* XOR result with provided data (str) */
	p = (uint64_t *)str;
	for (i = 0; i < 6; i++) {
		res[i] ^= p[i];
	}

	/* Get New Key and V */
	memcpy(s->k, res, 32);
	memcpy(s->v.u8, &res[32/8], 16);
	return 0;
}

int ctr_drbg_df_instantiate(uint8_t *entropy, int entlen, uint8_t *nonce, int nlen, uint8_t *pers_str, int perslen, ctr_drbg_state_t *s)
{
   int ret;
	#if 0
	uint8_t seed_mat[384/8];
	if (entlen + nlen + perslen != (384/8)) 
		return ERR_UPDATE_PARAMS; 
	#else
	uint8_t seed_mat[1000];
	if (entlen + nlen + perslen > 1000) 
		return ERR_UPDATE_PARAMS; 
	#endif

    if((entlen+nlen+perslen) % 16)
    {
        printf("\nSum of lengths of entropy, nonce and personalization string should be multiple of 16.\n");
        return ERR_UPDATE_PARAMS;
    }

	/* 1: seed_material = entropy_input || nonce || personalization_string */
	if (entlen)
		memcpy(seed_mat, entropy, entlen);
	if (nlen)
		memcpy(seed_mat + entlen, nonce, nlen);
	if (perslen)
		memcpy(seed_mat + entlen + nlen, pers_str, perslen);
	
	/* [2] seed_material = Block_Cipher_df(seed_material, seedlen) */
	ret = AES256_df(seed_mat, entlen + nlen + perslen, seed_mat, 384/8);
   if(ret)
       return ret;
	
	memset(s->k, 0, 32);
	s->vh = 0x0ul;
	s->vl = 0x0ul;
	
	ctr_drbg_update(seed_mat, 384/8, s);
	return 0;
}

int ctr_drbg_df_generate(ctr_drbg_state_t *s, int rand_bytes_req, uint8_t *addl_inp, int addl_inp_len, uint8_t *rand)
{
	uint64_t *p = (uint64_t *)rand;
	uint8_t lcl_addl_inp[384/8];
	int no_of_loops, last_blk_data_len, ret;

    if(addl_inp_len % 16)
    {
        printf("\nLength of additional input should be multiple of 16.\n");
        return ERR_UPDATE_PARAMS;
    }

	if (addl_inp_len) {
		ret = AES256_df(addl_inp, addl_inp_len, lcl_addl_inp, 384/8);
       if(ret)
           return ret;
		ctr_drbg_update(lcl_addl_inp, 384/8, s);
	} else 
		memset(lcl_addl_inp, 0,384/8);

	no_of_loops = rand_bytes_req/16;
	last_blk_data_len = (rand_bytes_req & 0xf);
	if (last_blk_data_len) 
		no_of_loops++;

	CVMX_MT_AES_KEY(s->k[0], 0);
	CVMX_MT_AES_KEY(s->k[1], 1);
	CVMX_MT_AES_KEY(s->k[2], 2);
	CVMX_MT_AES_KEY(s->k[3], 3);
	CVMX_MT_AES_KEYLENGTH(256/64 - 1);


	while (no_of_loops) {
		s->vl++;
		if (!s->vl)
			s->vh++;
		/*Encrypt v, with Key */
		CVMX_MT_AES_ENC0(s->vh);
		CVMX_MT_AES_ENC1(s->vl);

		/* get result */
		no_of_loops --;
		if (!no_of_loops && last_blk_data_len) {
			uint64_t res[2];
			CVMX_MF_AES_RESULT(res[0], 0);
			CVMX_MF_AES_RESULT(res[1], 1);
			memcpy(p, res, last_blk_data_len);
			break;
		}
		CVMX_MF_AES_RESULT(*p, 0);
		p++;
		CVMX_MF_AES_RESULT(*p, 1);
		p++;
	}
	ctr_drbg_update(lcl_addl_inp, 384/8, s);

	return 0;
}

int ctr_drbg_df_reseed(uint8_t *ent, int entlen, uint8_t *addl_inp, int addlinplen, ctr_drbg_state_t *s)
{
	uint8_t seedmat[1000];
   int ret;
    
    if((entlen+addlinplen) % 16)
    {
        printf("\nSum of lengths of entropy and additional input should be multiple of 16.\n");
        return ERR_UPDATE_PARAMS;
    }

	memcpy(seedmat, ent, entlen);
	if (addlinplen)
		memcpy(seedmat + entlen, addl_inp, addlinplen);
	
	ret = AES256_df(seedmat, entlen + addlinplen, seedmat, 384/8);
   if(ret)
       return ret;
	ctr_drbg_update(seedmat, 384/8, s);
	return 0;
}
