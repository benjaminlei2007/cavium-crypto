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




#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#include "cvmx.h"
#include "cvmx-key.h"
#include <openssl/rsa.h>
#include "cryptlib.h"

#define MUL_PAD 8

#if !defined(USER_SPACE_MODEXP)
extern int cryptfd;

typedef struct mulparams {
  uint64_t *product;
  uint64_t *mpcand;
  uint64_t *mplier;
  uint64_t *mod;
  uint64_t *recip;
  int len;
  int elen;
  int mlen;
  int blen;
} mulparams;

typedef struct crtparams {
  uint64_t *product;
  uint64_t *base;
  cvm_rsa_key_t *rkey;
  int nonwalign;
} crtparams;
#endif

#define ROUNDUP2(v)	((((v) + 1) / 2) * 2)
 
int MontMul576(uint64_t * product, uint64_t * mpcand, uint64_t * mplier,
  uint64_t * mod, uint64_t * recip);
int MontMul512(uint64_t * product, uint64_t * mpcand, uint64_t * mplier,
  uint64_t * mod, uint64_t * recip);
int MontMul(uint64_t * product, uint64_t * mpcand, uint64_t * mplier,
  uint64_t * mod, uint64_t * recip, int len);
int MontMul_O3(uint64_t * product, uint64_t * mpcand, uint64_t * mplier,
  uint64_t * mod, uint64_t * recip, int len);
extern int Vadd(uint64_t * accum, uint64_t * addend, int len);
extern int Vsub(uint64_t * accum, uint64_t * addend, int len);

#if !defined(USER_SPACE_MODEXP)
#if defined(__linux__)
#include "cryptolinux.h"
#endif
#endif

#define SPEEDUP_CODE
#ifdef SPEEDUP_CODE
#define MAX_BUF_SIZE				(256)

void
overlap_move(void *buf, size_t len)
{
    uint64_t *b = (uint64_t *)buf;
    register uint64_t t0, t1;
    size_t i;

    t0 = *b;
    t1 = *(b + 1);

    for(i = 0; i < (len - 2); i++)
    {
        *(b + i + 1) = t0;
        t0 = t1;
        t1 = *(b + i + 2);
    }

    *(b + i + 1) = t0;
    *(b + i + 2) = t1;
}

#define ZERO_CACHE_BLOCK(b)				\
	asm volatile("zcb (%[rs])" : : [rs] "d" (b))
#define ZERO_CACHE_BLOCK_THROUGH(b)			\
	asm volatile("zcbt (%[rs])" : : [rs] "d" (b))

int
zero_cache_lines(void *addr, int n_cache_lines)
{
    int i;
    unsigned char *base = (unsigned char *)addr;

    for(i = 0; i < n_cache_lines; i++)
        ZERO_CACHE_BLOCK((base + (128 * i)));

    return 1;
}
#endif

int
find_msw (uint64_t * wptr)
{
    int i = 0;

    while(wptr[i++])
        ;

    return i - 1;
}

void
cvm_bn2bin(uint64_t *from, uint8_t *to, int len)
{
    int n, i;
    uint64_t l;

    i = n = len;

    while(i-- > 0)
    {
        l = from[i / BN_BYTES];
        *(to++) = (unsigned char)(l >> (8 * (i % BN_BYTES))) & 0xff;
    }
}


#ifdef PRINT_DEBUG
/* PRINT_DEBUG: Internal flag. Need not be enabled for functionality */
void
DebugBreakFunc (const char *module, int line)
{
  printf ("\nFatal error is %s line %d\n", module, line);
}
//#define FATAL_ERROR DebugBreakFunc(__FILE__,__LINE__)
#else
#define FATAL_ERROR
#endif


#ifndef OCTEON_IS_MODEL
#define OCTEON_IS_MODEL(x) OCTEON_MATCH_MODEL(OCTEON_MODEL,x)
#endif


#if !defined(USER_SPACE_MODEXP)
void
VMulWord(uint64_t *product, const uint64_t *mpcand,
    const uint64_t mplier, int len)
{
    int i;

    CVMX_MTM0(mplier);

    for(i = 0; i < len; i++)
    {
        CVMX_MTM1(0);
        CVMX_MTM2(0);

        CVMX_V3MULU(product[i], mpcand[i], 0);
    }

    CVMX_V3MULU(product[i], 0, 0);
}
#else
void
VMulWord (uint64_t * product, const uint64_t * mpcand,
  const uint64_t mplier, int len)
{
  int i;

  CVMX_MTM2(0);
  CVMX_MTM1(0);

  CVMX_MTM0(mplier);
  for (i = 0; i < len; i++) {
    CVMX_V3MULU (product[i], mpcand[i], 0);
  }
  CVMX_V3MULU (product[i], 0, 0);
}
#endif

#if !defined(USER_SPACE_MODEXP)

void
VMul(uint64_t *product, const uint64_t *mpcand, const uint64_t *mplier, int len)
{
    int i, k;

    for(i = 0; i < len * 2; i++)
        product[i] = 0;

    for(k = 0; k < len; k++) {
        CVMX_MTM0(mplier[k]);
        CVMX_MTM1(0);
        CVMX_MTM2(0);

        for(i = 0; i < len; i++)
            CVMX_V3MULU(product[i + k], mpcand[i], product[i + k]);

        CVMX_V3MULU(product[i + k], 0, product[i + k]);
    }
}
#else
void
VMul(uint64_t * product, const uint64_t * mpcand, const uint64_t * mplier,
  int len)
{
    int i, k;

    for (i = 0; i < len * 2; i++) {
        product[i] = 0;
    }

    CVMX_MTM2(0, 0);
    CVMX_MTM1(0, 0);

    for (k = 0; k < len; k++) {
        CVMX_MTM0(mplier[k]);

        for (i = 0; i < len; i++) {
            CVMX_V3MULU (product[i + k], mpcand[i], product[i + k]);
        }

        CVMX_V3MULU (product[i + k], 0, product[i + k]);
    }
}
#endif

int64_t
VCmp(const uint64_t *a, const uint64_t *b, int len)
{
    int i = 0;

    for(i = len - 1; i >= 0; i--) {
        if(a[i] != b[i]) {
            if(a[i] > b[i]) {
                return 1;
            } else {
                return -1;
            }
        }
    }

    return 0;
}


//#define STACK_VARIABLE_ALLOC

void
MMLoop(uint64_t * product, const uint64_t * base,
    const uint64_t * exponent, const uint64_t * mod, const uint64_t * recip,
    int len, int elen)
{
#ifndef SPEEDUP_CODE
    uint64_t *temp;
#else
    static uint64_t temp[MAX_BUF_SIZE] __attribute__ ((aligned(128)));
#endif

    int i, j, size, bits;
    int lenx8 = len * sizeof(uint64_t);

#ifdef STACK_VARIABLE_ALLOC
    int psize;
    uint64_t precompute[16][128 + 8];
#else
    uint64_t *precompute[16];
    int max_size = sizeof(uint64_t) * (128 + 6);
#endif
    
    size = sizeof(uint64_t) * (len + 6);

#ifndef STACK_VARIABLE_ALLOC
    for(i = 0; i < 16; i++) {
        precompute[i] = (uint64_t *)OPENSSL_malloc(max_size);
        if(!precompute[i]) {
            for(j = i - 1; j >= 0; j--) {
                OPENSSL_free(precompute[j]);
            }
            return;
        }
        memset(precompute[i], 0, max_size);
    }
#endif

#ifndef SPEEDUP_CODE
    if((temp = (uint64_t *)OPENSSL_malloc(size)) == NULL) {
        printf("memory allocation failed\n");
        return;
    }
    memset(temp, 0, size);
#endif

#ifdef STACK_VARIABLE_ALLOC
    psize = (int)sizeof(precompute[0]);
    memset(precompute[0], 0, psize);
    memset(precompute[1], 0, psize);
#endif

    memcpy(precompute[0], product, size);
    memcpy(precompute[1], base, size);

    for(i = 2; i < 16; i++) {
#ifdef SPEEDUP_CODE
        if(len <= 8)
            MontMul576((uint64_t *)precompute[i], (uint64_t *)precompute[i - 1],
                (uint64_t *)base, (uint64_t *)mod, (uint64_t *)recip);
        else
            MontMul((uint64_t *)precompute[i], (uint64_t *)precompute[i - 1],
                (uint64_t *)base, (uint64_t *)mod, (uint64_t *)recip, len);
#else
#ifdef STACK_VARIABLE_ALLOC
        memset(precompute[i], 0, psize);
#endif
        memcpy(temp, precompute[i - 1], lenx8);

        if(len <= 8)
        {
            MontMul576((uint64_t *)precompute[i], (uint64_t *)temp,
                (uint64_t *)base, (uint64_t *)mod, (uint64_t *)recip);
        }
        else
        {
            MontMul((uint64_t *)precompute[i], (uint64_t *)temp,
                (uint64_t *)base, (uint64_t *)mod, (uint64_t *)recip, len);
        }
#endif
    }

    for(i = (len * 16) - 1; i >= 0; i--)
    {
        bits = (int)((exponent[i / 16] >> ((i & 0xf) << 2)) & 0xf);

        if(bits) break;
    }

    for(; i >= 0; i--)
    {
        bits = (exponent[i / 16] >> ((i & 15) << 2)) & 0xf;

        if(len <= 8)
        {
            MontMul576((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)product, (uint64_t *)mod, (uint64_t *)recip);

            MontMul576((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)temp, (uint64_t *)mod, (uint64_t *)recip);

            MontMul576((uint64_t *)temp,(uint64_t *)product,
                (uint64_t *)product, (uint64_t *)mod, (uint64_t *)recip);

            MontMul576((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)temp, (uint64_t *)mod, (uint64_t *)recip);

        }
        else
        {
            MontMul((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)product, (uint64_t *)mod, (uint64_t *)recip, len);

            MontMul((uint64_t *)product, (uint64_t *)temp,(uint64_t *)temp,
                (uint64_t *)mod,(uint64_t *)recip,len);

            MontMul((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)product, (uint64_t *)mod, (uint64_t *)recip, len);

            MontMul((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)temp, (uint64_t *)mod, (uint64_t *)recip, len);
        }

        if(len <= 8)
        {
            MontMul576((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)precompute[bits], (uint64_t *)mod,
                (uint64_t *)recip);
        }
        else
        {
            MontMul((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)precompute[bits], (uint64_t *)mod,
                (uint64_t *)recip, len);
        }
        memcpy(product, temp, lenx8);
    }

#ifndef SPEEDUP_CODE
    if(temp) OPENSSL_free(temp);
#endif

#ifndef STACK_VARIABLE_ALLOC
    for(i = 0; i < 16; i++)
        OPENSSL_free(precompute[i]);
#endif
}


static int
_cvm_ModExp_octeon2(uint64_t *product, uint64_t *base, uint64_t *exponent,
    uint64_t *mod, int len, int elen, int mlen, int blen, int convert)
{
    int success = 0;
#if !defined(TARGET_LINUX) || defined(USER_SPACE_MODEXP)
    if(1)
#else
    if(!cvm_crypto_vmul_hwbug())
#endif
    {
#ifndef SPEEDUP_CODE
        uint64_t recip[6];
#else
        static uint64_t residue[MAX_BUF_SIZE] __attribute__ ((aligned(128)));
        static uint64_t temp[MAX_BUF_SIZE] __attribute__ ((aligned(128)));
        static uint64_t negmod[MAX_BUF_SIZE] __attribute__ ((aligned(128)));
        static uint64_t temp_base[MAX_BUF_SIZE] __attribute__ ((aligned(128)));
        static uint64_t recip[16] __attribute__ ((aligned(128)));
        int cache_lines;
#endif
        // first compute montgomery reciprocal
        int i, r, size;
        int lenx8 = len * sizeof(uint64_t);
        int msw = 0;
        uint64_t junk = 0;
        int normalize = 0; 
#ifndef SPEEDUP_CODE
        uint64_t *residue = NULL, *temp = NULL,
                  *negmod = NULL, *temp_base = NULL;
#endif
        uint64_t q[4] = {0, 0, 0, 0};
      
        len  = (len + 3) & 0xfffc;
        size = sizeof(uint64_t) * (len + 6);

#ifdef SPEEDUP_CODE
        cache_lines = (size + 127) >> 7;
        zero_cache_lines((void *)residue, cache_lines);
        zero_cache_lines((void *)temp, cache_lines);
        zero_cache_lines((void *)negmod, cache_lines);
        zero_cache_lines((void *)temp_base, cache_lines);
        zero_cache_lines((void *)recip, sizeof(recip) >> 7);
#else
        /* Moved the memory from stack to heap */
        residue   = (uint64_t *)OPENSSL_malloc(size);
        temp      = (uint64_t *)OPENSSL_malloc(size);
        negmod    = (uint64_t *)OPENSSL_malloc(size);
        temp_base = (uint64_t *)OPENSSL_malloc(size);

        if(!temp || !negmod || !residue || !temp_base)
        {
            printf("memory allocation failed\n");
            goto err;
        }

        memset(residue,   0, size);
        memset(temp,      0, size);
        memset(negmod,    0, size);
        memset(temp_base, 0, size);
        memset(recip,     0, sizeof(recip));
#endif

        for(i = 0; i < len; i++)
        {
            negmod[i] = 0;
            if(mod[i] != 0) break;
        }

        negmod[i] = ~mod[i] + 1;

        for(i++; i < len; i++)
            negmod[i] = ~mod[i];

        negmod[len] = ~(uint64_t)0;

        /* I need to know where most significant word of the modulus is */
        for(msw = len - 1; msw >= 0; msw--)
            if(mod[msw])
            {
                break;
            }

/*
        if(0 && msw == len - 1 && (mod[msw] >> 36))
        {
            FATAL_ERROR;     //len needs to be incremented by 1
        }
*/

        normalize = mod[msw] < ((uint64_t)1 << 32);

        if(normalize)
        {
            for(i = msw; i >= 1; i--)
                negmod[i] = (negmod[i] << 32) | (negmod[i - 1] >> 32);

            negmod[0] = negmod[0] << 32;
        }

        recip[0] = 0;
        recip[1] = 0;

        CVMX_MTM2(0); //70XX adjustment

        junk = 0;

        for(i = 63; i >= 0; i--)
        {
            recip[1] |= (uint64_t)1 << i;

            CVMX_MTM0(recip[0]);
            CVMX_MTM1(recip[1]);
            CVMX_MTM2(0); // 70XX adjustment

            CVMX_V3MULU(junk, negmod[msw - 1], 0);
            CVMX_V3MULU(junk, negmod[msw], 0);
            CVMX_V3MULU(junk, (int64_t)-1, 0);
            CVMX_V3MULU(junk, (int64_t)-1, (uint64_t)1 << 32);

            if((junk >> 63))
                recip[1] ^= (uint64_t)1 << i;
        }

        junk = 0;

        for(i = 63; i >= 0; i--)
        {
            recip[0] |= (uint64_t) 1 << i;

            CVMX_MTM0(recip[0]);
            CVMX_MTM1(recip[1]);
            CVMX_MTM2(0); // 70XX adjustment

            CVMX_V3MULU(junk, negmod[msw - 1], 0);
            CVMX_V3MULU(junk, negmod[msw], 0);
            CVMX_V3MULU(junk, (int64_t)-1, 0);
            CVMX_V3MULU(junk, (int64_t)-1, (uint64_t)1 << 32);

            if((junk >> 63))
                recip[0] ^= (uint64_t)1 << i;
        }

        //memset(residue,0,sizeof(uint64_t)*(len+1));
        residue[0] = 0;

        r = (len <= 8) ? 8 : ((len + 2) / 3) * 3;
        r = r * 2;

        residue[msw] = normalize ? ((uint64_t)1 << 32) : 1;
        r -= msw;


        /* Each iteration I'll left shift things 64 bits and do
         * a modular reduction.
         */
        for(i = 0; i < r; i++)
        {
            int k;
#ifdef SPEEDUP_CODE
            overlap_move(residue, len);
#else
            memmove(residue + 1, residue, lenx8);
#endif
            residue[0] = 0;

            CVMX_MTM0(recip[0]);
            CVMX_MTM1(recip[1]);
            CVMX_MTM2(0);

            CVMX_V3MULU(q[0], (residue[msw] >> 32) | (residue[msw + 1] << 32), 0);
            CVMX_V3MULU(q[1],(residue[msw + 1] >> 32),0);
            CVMX_V3MULU(q[2], 0, 0);
            CVMX_V3MULU(q[3], 0, 0);

            CVMX_MTM0(q[2]);
            CVMX_MTM1(q[3]);
            CVMX_MTM2(0);

#ifdef SPEEDUP_CODE
            {
                uint64_t n0, n1, r0, r1;

                n0 = negmod[0];
                r0 = residue[0];
                n1 = negmod[1];
                r1 = residue[1];

                CVMX_V3MULU(r0, n0, r0);

                for(k = 1; k < len; k++)
                {
                    residue[k - 1] = r0;

                    CVMX_V3MULU(r0, n1, r1);

                    n1 = negmod[k + 1];
                    r1 = residue[k + 1];
                }

                residue[len - 1] = r0;

                CVMX_V3MULU(r0, n1, r1);

                residue[len] = r0;
            }
#else
            for(k = 0; k < len + 1; k++)
                CVMX_V3MULU(residue[k], negmod[k], residue[k]);
#endif

            if(residue[len] > 1)
                {
                    FATAL_ERROR;
                }
        }

        if(normalize)
        {
            if(residue[0] << 32)
            {
                FATAL_ERROR;
            }    

            for(i = 0; i < len; i++)
                residue[i] = (residue[i] >> 32) | (residue[i + 1] << 32);

            residue[len] = 0;
        }

        if(len <= 8)
        {
#ifdef SPEEDUP_CODE
            recip[0] = 0;
            recip[1] = 0;

            CVMX_MTM0(mod[0]);
            CVMX_MTM1(0);

#if defined(USER_SPACE_MODEXP)
            CVMX_MTM1(0);
            CVMX_MTM2(0);
#endif

            for(i = 0; i < 64; i++)
            {
                uint64_t *sub = &recip[0];
                uint64_t p0;
                char undo = 0;
                *sub |= (uint64_t) 1 << (i & 63);

                CVMX_MTM1(0); //70XX adjustment
                CVMX_MTM2(0);  // clr product regs, stay in order

#if !defined(USER_SPACE_MODEXP)
                CVMX_V3MULU(p0, recip[0], 1);
#else
                CVMX_V3MULU(p0, recip[0], 1);
#endif
                undo = undo || (p0 << (63 - (i & 63)));

                if(undo)
                    *sub ^= (uint64_t)1 << (i & 63);
            }

#else /* !SPEEDUP_CODE */

            recip[0] = 0;
            recip[1] = 0;
#if defined(USER_SPACE_MODEXP)
            CVMX_MTM2(0);
            CVMX_MTM1(0);
#endif
            for(i = 0; i < 64; i++)
            {
                uint64_t *sub = &recip[0];
                int k;
                char undo = 0;
                *sub |= (uint64_t) 1 << (i & 63);

                CVMX_MTM0(recip[0]);
#if !defined(USER_SPACE_MODEXP)
                CVMX_VMULU(product[0], mod[0], 1);
#else
                CVMX_MTM1(0);
                CVMX_MTM2(0);
                CVMX_V3MULU(product[0], mod[0], 1);
#endif

                for(k = 0; k < (i / 64); k++)
                    undo = undo || product[k];

                undo = undo || (product[i / 64] << (63 - (i & 63)));

                if(undo)
                    *sub ^= (uint64_t) 1 << (i & 63);
            }
#endif
        }
        else
        {
#ifdef SPEEDUP_CODE

	        register uint64_t m2 = mod[2];
            zero_cache_lines((void *)recip, 1);

            CVMX_MTM0(mod[0]);
            CVMX_MTM1(mod[1]);
            CVMX_MTM2(m2);

            for(i = 0; i < 192; i++)
            {
                uint64_t *sub = &recip[i / 64];
                int k;
                char undo = 0;

                *sub |= (uint64_t)1 << (i & 63);


	    	{
		        register uint64_t p0,p1,p2;

                    CVMX_MTM2(m2);

                    CVMX_V3MULU(p0, recip[0], 1);
                    CVMX_V3MULU(p1, recip[1], 0);
                    CVMX_V3MULU(p2, recip[2], 0);

                    k = i / 64;

                    if(k == 0)
                    {
                        undo = undo || (p0 << (63 - (i & 63)));
                    }
                    else if(k == 1)
                    {
                        undo = undo || p0;
                        undo = undo || (p1 << (63 - (i & 63)));
                    }
                    else
                    {
                        undo = undo || p0;
                        undo = undo || p1;
                        undo = undo || (p2 << (63 - (i & 63)));
                    }
                }

                if(undo)
                    *sub ^= (uint64_t)1 << (i & 63);
            }
	    
#else
            memset(recip, 0, sizeof(recip));

            for(i = 0; i < 192; i++)
            {
                uint64_t *sub = &recip[i / 64];
                int k;
                char undo = 0;
                *sub |= (uint64_t)1 << (i & 63);

                CVMX_MTM0(recip[0]);
                CVMX_MTM1(recip[1]);
                CVMX_MTM2(recip[2]);

                CVMX_V3MULU(product[0], mod[0], 1);
                CVMX_V3MULU(product[1], mod[1], 0);
                CVMX_V3MULU(product[2], mod[2], 0);

                for(k = 0; k < (i / 64); k++)
                    undo = undo || product[k];

                undo = undo || (product[i / 64] << (63 - (i & 63)));

                if(undo)
                    *sub ^= (uint64_t)1 << (i & 63);
            }
#endif
        }

#ifndef SPEEDUP_CODE
        memset(product, 0, size);
#endif

        if(len <= 8)
            MontMul576((uint64_t *)product,(uint64_t *)base,
                (uint64_t *)residue,(uint64_t *)mod,(uint64_t *)recip);
        else
            MontMul((uint64_t *)product, (uint64_t *)base,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip, len);

        memcpy(temp_base, product, lenx8);
        memset(temp, 0, size);

        temp[0] = 1;

        if(len <= 8)
            MontMul576((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip);
        else
            MontMul((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip, len);

        MMLoop(product, temp_base, exponent, mod, recip, len, elen);

#ifdef SPEEDUP_CODE
        zero_cache_lines((void *)residue, cache_lines);
#else
        memset(residue, 0, size);
#endif

        residue[0] = 1;

        if(len <= 8)
        {
            MontMul576((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip);
        }
        else
        {
            MontMul((uint64_t *)temp, (uint64_t *)product, (uint64_t *)residue,
                (uint64_t *)mod, (uint64_t *)recip, len);
        }

        memcpy(product, temp, lenx8);

        Vsub(temp, mod, len + 1);

        if(!(temp[len] >> 63))
            memcpy(product, temp, lenx8);

        success = 1;

#ifndef SPEEDUP_CODE
err:
        if(residue)    OPENSSL_free(residue);
        if(temp)       OPENSSL_free(temp);
        if(negmod)     OPENSSL_free(negmod);
        if(temp_base)  OPENSSL_free(temp_base);
#endif
    }
#if defined(TARGET_LINUX)
 else {
     int retc=0;
     cvm_crypto_op_t tokernel;
     
     if (cryptfd <= 0) {
       retc = crypto_init();
       if (retc <= 0) {
         return retc;
       }
     }
   
   #if _MIPS_SIM == _MIPS_SIM_NABI32
     tokernel.sizeofptr = sizeof (void *);
     tokernel.arg1 = (uint64_t) (uint32_t) product;
     tokernel.arg2 = (uint64_t) (uint32_t) base;
     tokernel.arg3 = (uint64_t) (uint32_t) exponent;
     tokernel.arg4 = (uint64_t) (uint32_t) mod;
     tokernel.arg5 = (uint64_t) (uint32_t) 0;      /* recip */
     tokernel.arg6 = (int64_t) len;
     tokernel.arg7 = (int64_t) elen;
     tokernel.arg8 = (int64_t) mlen;
     tokernel.arg9 = (int64_t) blen;
     success = !crypto_mult (CRYPT_MODEXP, (uint64_t) (uint32_t) & tokernel);
     #else
     tokernel.sizeofptr = sizeof (void *);
     tokernel.arg1 = (uint64_t) product;
     tokernel.arg2 = (uint64_t) base;
     tokernel.arg3 = (uint64_t) exponent;
     tokernel.arg4 = (uint64_t) mod;
     tokernel.arg5 = (uint64_t) 0; /* recip */
     tokernel.arg6 = (int64_t) len;
     tokernel.arg7 = (int64_t) elen;
     tokernel.arg8 = (int64_t) mlen;
     tokernel.arg9 = (int64_t) blen;
     success = !crypto_mult (CRYPT_MODEXP, (uint64_t) & tokernel);
   #endif
 }
#endif
  return success;
}

#define STACK_VARIABLE_ALLOC

void
MMLoop_O3(uint64_t *product, const uint64_t *base, const uint64_t *exponent,
    const uint64_t *mod, const uint64_t *recip, int len, int elen)
{
#ifndef SPEEDUP_CODE
    uint64_t *temp;
#else
    static uint64_t temp[MAX_BUF_SIZE] __attribute__ ((aligned(128)));
#endif

    int i, size, bits, psize;
    int lenx8 = len * sizeof(uint64_t);
    uint64_t precompute[16][128 + 8];

    size = sizeof(uint64_t) * (len + 6);


#ifndef SPEEDUP_CODE
    if((temp = OPENSSL_malloc(size)) == NULL)
    {
        printf("memory allocation failed\n");
        return;
    }
    memset(temp, 0, size);
#endif

    psize = (int)sizeof(precompute[0]);
    memset(precompute[0], 0, psize);
    memset(precompute[1], 0, psize);

    memcpy(precompute[0], product, size);
    memcpy(precompute[1], base, size);

    for(i = 2; i < 16; i++)
    {
#ifdef SPEEDUP_CODE
        if(len <= 8)
            MontMul512((uint64_t *)precompute[i], (uint64_t *)precompute[i - 1],
                (uint64_t *)base, (uint64_t *)mod, (uint64_t *)recip);
        else
            MontMul_O3((uint64_t *)precompute[i], (uint64_t *)precompute[i - 1],
                (uint64_t *)base, (uint64_t *)mod, (uint64_t *)recip, len);
#else
#ifdef STACK_VARIABLE_ALLOC
        //memset(precompute[i], 0, psize);
#endif
        memcpy(temp, precompute[i - 1], lenx8);

        if(len <= 8)
        {
            MontMul512((uint64_t *)precompute[i], (uint64_t *)temp,
                (uint64_t *)base, (uint64_t *)mod, (uint64_t *)recip);
        }
        else
        {
            MontMul_O3((uint64_t *)precompute[i], (uint64_t *)temp,
                (uint64_t *)base, (uint64_t *)mod, (uint64_t *)recip, len);
        }
#endif
    }

    for(i = (len * 16) - 1; i >= 0; i--)
    {
        bits = ((exponent[i / 16] >> ((i & 15) << 2)) & 0xf);

        if(bits) break;
    }

    for(; i >= 0; i--)
    {
        bits = (exponent[i / 16] >> ((i & 15) << 2)) & 0xf;

        if(len <= 8)
        {
            MontMul512((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)product, (uint64_t *)mod, (uint64_t *)recip);

            MontMul512((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)temp, (uint64_t *)mod, (uint64_t *)recip);

            MontMul512((uint64_t *)temp,(uint64_t *)product,
                (uint64_t *)product, (uint64_t *)mod, (uint64_t *)recip);

            MontMul512((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)temp, (uint64_t *)mod, (uint64_t *)recip);

        }
        else
        {
            MontMul_O3((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)product, (uint64_t *)mod, (uint64_t *)recip, len);

            MontMul_O3((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)temp, (uint64_t *)mod,(uint64_t *)recip, len);

            MontMul_O3((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)product, (uint64_t *)mod, (uint64_t *)recip, len);

            MontMul_O3((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)temp, (uint64_t *)mod, (uint64_t *)recip, len);
        }

        if(len <= 8)
        {
            MontMul512((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)precompute[bits], (uint64_t *)mod,
                (uint64_t *)recip);
        }
        else
        {
            MontMul_O3((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)precompute[bits], (uint64_t *)mod,
                (uint64_t *)recip, len);
        }

        memcpy(product, temp, lenx8);
    }

#ifndef SPEEDUP_CODE
    if(temp) OPENSSL_free(temp);
#endif

}


static int
_cvm_ModExp_octeon3(uint64_t *product, uint64_t *base, uint64_t *exponent,
    uint64_t *mod, int len, int elen, int mlen, int blen, int convert)
{
#if defined(_MIPS_ARCH_OCTEON3)
    int success = 0;
#if !defined(TARGET_LINUX) || defined(USER_SPACE_MODEXP)
    if(1)
#else
    if(!cvm_crypto_vmul_hwbug())
#endif
    {
#ifndef SPEEDUP_CODE
        uint64_t recip[6];
#endif
        // first compute montgomery reciprocal
        int i, size;
        int lenx8;
        int msw = 0;
        uint64_t junk = 0;
        int normalize, r; 
#ifndef SPEEDUP_CODE
        uint64_t *residue = NULL, *temp = NULL,
                  *negmod = NULL, *temp_base = NULL;
#else                           
        int cache_lines;

        static uint64_t residue[MAX_BUF_SIZE] __attribute__ ((aligned(128)));
        static uint64_t temp[MAX_BUF_SIZE] __attribute__ ((aligned(128)));
        static uint64_t negmod[MAX_BUF_SIZE] __attribute__ ((aligned(128)));
        static uint64_t temp_base[MAX_BUF_SIZE] __attribute__ ((aligned(128)));
        static uint64_t recip[16] __attribute__ ((aligned(128)));
#endif

        lenx8 = sizeof(uint64_t) * len;
        len   = (len + 3) & 0xfffc;
        size  = sizeof(uint64_t) * (len + 6);

#ifndef SPEEDUP_CODE
        /* Moved the memory from stack to heap */
        residue   = (uint64_t *)OPENSSL_malloc(size);
        temp      = (uint64_t *)OPENSSL_malloc(size);
        negmod    = (uint64_t *)OPENSSL_malloc(size);
        temp_base = (uint64_t *)OPENSSL_malloc(size);

        if(!temp || !negmod || !residue || !temp_base)
        {
            printf("memory allocation failed\n");
            goto err;
        }

        memset(residue,   0, size);
        memset(temp,      0, size);
        memset(negmod,    0, size);
        memset(temp_base, 0, size);
        memset(recip,     0, sizeof(recip));
#else
        cache_lines = (size + 127) >> 7;
        zero_cache_lines((void *)residue, cache_lines);
        zero_cache_lines((void *)temp, cache_lines);
        zero_cache_lines((void *)negmod, cache_lines);
        zero_cache_lines((void *)temp_base, cache_lines);
        zero_cache_lines((void *)recip, sizeof(recip) >> 7);
#endif

        for(i = 0; i < len; i++)
        {
            negmod[i] = 0;
            if(mod[i] != 0) break;
        }

        negmod[i] = ~mod[i] + 1;

        for(i++; i < len; i++)
            negmod[i] = ~mod[i];

        negmod[len] = ~(uint64_t)0;

        /* I need to know where most significant word of the modulus is */
        for(msw = len - 1; msw >= 0; msw--)
            if(mod[msw])
                break;

        normalize = mod[msw] < ((uint64_t)1 << 32);

        if(normalize)
        {
            for(i = msw; i >= 1; i--)
                negmod[i] = (negmod[i] << 32) | (negmod[i - 1] >> 32);

            negmod[0] = (negmod[0] << 32);
        }

        recip[0] = 0;
        recip[1] = 0;

        junk = 0;
        CVMX_MTM2_V3(0, 0);

        for(i = 63; i >= 0; i--)
        {
            recip[1] |= (uint64_t)1 << i;

            CVMX_MTM0_V3(recip[0], 0);
            CVMX_MTM1_V3(recip[1], 0);

            CVMX_VMULU(junk, negmod[msw - 1], 0);
            CVMX_VMULU(junk, negmod[msw], 0);
            CVMX_VMULU(junk, (int64_t)-1, 0);
            CVMX_VMULU(junk, (int64_t)-1, (uint64_t)1 << 32);

            if((junk >> 63))
                recip[1] ^= (uint64_t)1 << i;
        }

        junk = 0;

        for(i = 63; i >= 0; i--)
        {
            recip[0] |= (uint64_t)1 << i;

            CVMX_MTM0_V3(recip[0], 0);
            CVMX_MTM1_V3(recip[1], 0);

            CVMX_VMULU(junk, negmod[msw - 1], 0);
            CVMX_VMULU(junk, negmod[msw], 0);
            CVMX_VMULU(junk, (int64_t)-1, 0);
            CVMX_VMULU(junk, (int64_t)-1, (uint64_t)1 << 32);

            if((junk >> 63))
                recip[0] ^= (uint64_t)1 << i;
        }

        r = (len <= 8) ? 8 : ((len + 5) / 6) * 6;
        r = r * 2;

        residue[msw] = (normalize ? ((uint64_t)1 << 32) : 1);
        r -= msw;


        /* Each iteration I'll left shift things 64 bits and do
         * a modular reduction.
         */
        for(i = 0; i < r; i++)
        {
            int k;
            uint64_t q[4] = {0, 0, 0, 0};
#ifdef SPEEDUP_CODE
            overlap_move(residue, len);
#else
            memmove(residue + 1, residue, lenx8);
#endif
            residue[0] = 0;

            CVMX_MTM0_V3(recip[0], 0);
            CVMX_MTM1_V3(recip[1], 0);
            CVMX_MTM2_V3(0, 0);

            CVMX_VMULU(q[0], (residue[msw] >> 32) | (residue[msw + 1] << 32), 0);
            CVMX_VMULU(q[1], (residue[msw + 1] >> 32), 0);
            CVMX_VMULU(q[2], 0, 0);
            CVMX_VMULU(q[3], 0, 0);

            CVMX_MTM0_V3(q[2], 0);
            CVMX_MTM1_V3(q[3], 0);
            CVMX_MTM2_V3(0, 0);

#ifdef SPEEDUP_CODE
            {
                uint64_t n0, n1, r0, r1;

                CVMX_MTM2_V3(0, 0);

                n0 = negmod[0];
                r0 = residue[0];
                n1 = negmod[1];
                r1 = residue[1];

                CVMX_V3MULU(r0, n0, r0);

                for(k = 1; k < len; k++)
                {
                    residue[k - 1] = r0;
                    CVMX_V3MULU(r0, n1, r1);
                    n1 = negmod[k + 1];
                    r1 = residue[k + 1];
                }

                residue[len - 1] = r0;

                CVMX_V3MULU(r0, n1, r1);

                residue[len] = r0;
            }
#else
            for(k = 0; k < len + 1; k++)
                CVMX_VMULU(residue[k], negmod[k], residue[k]);
#endif

            if(residue[len] > 1)
             {
                 FATAL_ERROR;
             }
        }

        if(normalize)
        {
            if(residue[0] << 32)
            {
                FATAL_ERROR;
            }

            for(i = 0; i < len; i++)
                residue[i] = (residue[i] >> 32) | (residue[i + 1] << 32);

            residue[len] = 0;
        }

        if(len <= 8)
        {
            recip[0] = 0;
            recip[1] = 0;

            CVMX_MTM2_V3(0, 0);

#if defined(USER_SPACE_MODEXP)
            CVMX_MTM0_V3(0, 0);
            CVMX_MTM1_V3(0, 0);
            CVMX_MTM2_V3(0, 0);
#endif

            for(i = 0; i < 128; i++)
            {
                uint64_t *sub = &recip[i / 64];
                int k;
                char undo = 0;
                uint64_t p[2];
                *sub |= (uint64_t)1 << (i & 63);

                CVMX_MTM0_V3(recip[0], 0);
                CVMX_MTM1_V3(recip[1], 0);

#if !defined(USER_SPACE_MODEXP)
                CVMX_VMULU(p[0], mod[0], 1);
                CVMX_VMULU(p[1], mod[1], 0);
#else
                CVMX_MTM2_V3(0, 0);
                CVMX_V3MULU(p[0], mod[0], 1);
                CVMX_V3MULU(p[1], mod[1], 0);
#endif

                for(k = 0; k < (i / 64); k++)
                    undo = undo || p[k];

                undo = undo || (p[i / 64] << (63 - (i & 63)));

                if(undo)
                    *sub ^= (uint64_t)1 << (i & 63);
            }
        }
        else
        {
#ifdef SPEEDUP_CODE
            zero_cache_lines(recip, sizeof(recip) >> 7);
#else
            for(i = 0; i < 6; i++)
                recip[i] = (uint64_t)0;
#endif

            for(i = 0; i < 384; i++)
            {
                uint64_t *sub = &recip[i / 64];
                int k;
                char undo = 0;
                uint64_t p[6];

                *sub |= ((uint64_t)1 << (i & 63));

                CVMX_MTM0_V3(recip[0], recip[3]);
                CVMX_MTM1_V3(recip[1], recip[4]);
                CVMX_MTM2_V3(recip[2], recip[5]);

                CVMX_V3MULU(p[0], mod[0], 1);
                CVMX_V3MULU(p[1], mod[1], 0);
                CVMX_V3MULU(p[2], mod[2], 0);
                CVMX_V3MULU(p[3], mod[3], 0);
                CVMX_V3MULU(p[4], mod[4], 0);
                CVMX_V3MULU(p[5], mod[5], 0);

                for(k = 0; k < (i / 64); k++)
                    undo = undo || p[k];

                undo = undo || (p[i / 64] << (63 - (i & 63)));

                if(undo)
                    *sub ^= ((uint64_t)1 << (i & 63));
            }
        }

        if(len <= 8)
        {
            MontMul512((uint64_t *)product, (uint64_t *)base,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip);
        }
        else
        {
            MontMul_O3((uint64_t *)product, (uint64_t *)base,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip, len);
        }

        memcpy(temp_base, product, lenx8);

#if 0
#ifdef SPEEDUP_CODE
        zero_cache_lines(temp, cache_lines);
#else
        memset(temp, 0, size);
#endif
#endif

        temp[0] = 1;

        if(len <= 8)
        {
            MontMul512((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip);
        }
        else
        {
            MontMul_O3((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip, len);
        }

        MMLoop_O3(product, temp_base, exponent, mod, recip, len, elen);

#ifdef SPEEDUP_CODE
        zero_cache_lines((void *)residue, cache_lines);
#else
        memset(residue, 0, size);
#endif

        residue[0] = 1;
        memset(temp, 0, size);

        if(len <= 8)
        {
            MontMul512((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip);
        }
        else
        {
            MontMul_O3((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip, len);
        }

        memcpy(product, temp, lenx8);

        Vsub(temp, mod, len + 1);

        if(!(temp[len] >> 63))
            memcpy(product, temp, lenx8);

        success = 1;

#ifndef SPEEDUP_CODE
err:
        if(residue)    OPENSSL_free(residue);
        if(temp)       OPENSSL_free(temp);
        if(negmod)     OPENSSL_free(negmod);
        if(temp_base)  OPENSSL_free(temp_base);
#endif
    }
#if defined(TARGET_LINUX)
    else
    {
        int retc=0;
	cvm_crypto_op_t tokernel;
     
	if(cryptfd <= 0)
        {
            retc = crypto_init();
            if(retc <= 0)
            {
                return retc;
            }
        }
#if _MIPS_SIM == _MIPS_SIM_NABI32
        tokernel.sizeofptr = sizeof (void *);
        tokernel.arg1 = (uint64_t) (uint32_t) product;
        tokernel.arg2 = (uint64_t) (uint32_t) base;
        tokernel.arg3 = (uint64_t) (uint32_t) exponent;
        tokernel.arg4 = (uint64_t) (uint32_t) mod;
        tokernel.arg5 = (uint64_t) (uint32_t) 0;      /* recip */
        tokernel.arg6 = (int64_t) len;
        tokernel.arg7 = (int64_t) elen;
        tokernel.arg8 = (int64_t) mlen;
        tokernel.arg9 = (int64_t) blen;
        success = !crypto_mult (CRYPT_MODEXP, (uint64_t) (uint32_t) & tokernel);
#else
        tokernel.sizeofptr = sizeof (void *);
        tokernel.arg1 = (uint64_t) product;
        tokernel.arg2 = (uint64_t) base;
        tokernel.arg3 = (uint64_t) exponent;
        tokernel.arg4 = (uint64_t) mod;
        tokernel.arg5 = (uint64_t) 0; /* recip */
        tokernel.arg6 = (int64_t) len;
        tokernel.arg7 = (int64_t) elen;
        tokernel.arg8 = (int64_t) mlen;
        tokernel.arg9 = (int64_t) blen;
        success = !crypto_mult (CRYPT_MODEXP, (uint64_t) & tokernel);
#endif
    }
#endif
    return success;
#else
    return 0;
#endif
}



static int
_cvm_ModExp(uint64_t * product, uint64_t * base, uint64_t * exponent,
    uint64_t * mod, int len, int elen, int mlen, int blen, int convert)
{


    if(OCTEON_IS_OCTEON3())
    {
            return _cvm_ModExp_octeon3(product, base, exponent, mod,
                            len, elen, mlen, blen, convert);
    }
    else
    {
        return _cvm_ModExp_octeon2(product, base, exponent, mod,
                    len, elen, mlen, blen, convert);
    }
}

/**
 * cvm_ModExp function
 * 
 * Function which performs modulus exponent operation
 *
 * Prerequisites to use this function:
 * Parameters(mod,exponent,base) should be padded with 64 bytes of data. Also 
 * the parameters should be reversed taken 8 bytes at a time before 
 * passing to this function.
 *
 * @param  product  pointer to result of modular exponent operation.
 * @param  base     pointer to base value used in modular exponent operation.
 * @param  exponent pointer to exponent value used for modular exponent operation.
 * @param  mod      pointer to modulus value used in modular exponent operation.
 * @param  len      length  of product buffer
 * @param  elen     length  of exponent buffer
 * @param  mlen     length  of modulus buffer
 * @param  blen     length  of base buffer
 *
 *
 * @return 0 on success, -1 on failure
 */

int
cvm_ModExp (uint64_t * product, uint64_t * base, uint64_t * exponent,
  uint64_t * mod, int len, int elen, int mlen, int blen)
{
    return _cvm_ModExp(product, base, exponent, mod, len, elen, mlen, blen, 0);
}

int
cav_mod_exp(BIGNUM * res, const BIGNUM * base, const BIGNUM * exp,
            const BIGNUM * mod, BN_CTX * ctx)
{
  uint8_t *copy_base = NULL;
  uint8_t *copy_exp = NULL;
  uint8_t *copy_mod = NULL;
  int ret = 0;                  //BN_mod_exp returns 1 on success and 0 on error
  int mlen, elen, blen;
  int len;

  copy_base = (uint8_t *)OPENSSL_malloc((ROUNDUP2(mod->top) + MUL_PAD) * 8);
  copy_exp  = (uint8_t *)OPENSSL_malloc((ROUNDUP2(mod->top) + MUL_PAD) * 8);
  copy_mod  = (uint8_t *)OPENSSL_malloc((ROUNDUP2(mod->top) + MUL_PAD) * 8);

  if (copy_base == NULL || copy_exp == NULL || copy_mod == NULL) 
    goto modexp_err;

  memset(copy_base, 0, (ROUNDUP2(mod->top) + MUL_PAD) * 8);
  memset(copy_exp,  0, (ROUNDUP2(mod->top) + MUL_PAD) * 8);
  memset(copy_mod,  0, (ROUNDUP2(mod->top) + MUL_PAD) * 8);

  memcpy(copy_exp,  exp->d,  exp->top  * sizeof (BN_ULONG));
  memcpy(copy_mod,  mod->d,  mod->top  * sizeof (BN_ULONG));
  memcpy(copy_base, base->d, base->top * sizeof (BN_ULONG));

  if (bn_wexpand(res, ROUNDUP2(mod->dmax) + MUL_PAD) == NULL)
    goto modexp_err;

  memset(res->d, 0, (ROUNDUP2(mod->dmax) + MUL_PAD) * sizeof(BN_ULONG));

  mlen = ROUNDUP8(mod->top  * sizeof (BN_ULONG));
  elen = ROUNDUP8(exp->top  * sizeof (BN_ULONG));
  blen = ROUNDUP8(base->top * sizeof (BN_ULONG));
  len  = ((((mod->top * sizeof(BN_ULONG)) * 8) + 63) / 64);

  _cvm_ModExp((uint64_t *)res->d, (uint64_t *)copy_base,
    (uint64_t *)copy_exp, (uint64_t *)copy_mod,
    len, elen, mlen, blen, 1);

  res->top = mod->top;
  ret = 1;                      // Success
modexp_err:
  if (copy_base)
    OPENSSL_free (copy_base);
  if (copy_exp)
    OPENSSL_free (copy_exp);
  if (copy_mod)
    OPENSSL_free (copy_mod);
  return ret;
}


void
ModReduce(uint64_t *result, uint64_t *base, int baselen,
    uint64_t *mod, int modlen)
{
#ifndef SPEEDUP_CODE
    uint64_t *tmp = NULL;
    uint64_t *negmod = NULL;
#endif
    uint64_t recip[3];
    int i, size, negsize;
    int msw, msm;
    int len = baselen;
    unsigned char normalize; 
#ifdef SPEEDUP_CODE
    static uint64_t tmp[MAX_BUF_SIZE] __attribute__ ((aligned(128)));
    static uint64_t negmod[MAX_BUF_SIZE] __attribute__ ((aligned(128)));
#endif

    size    = (baselen * 8) + MODEXP_GUARD;
    negsize = (baselen * 8 * 3);

#ifdef SPEEDUP_CODE
    zero_cache_lines(tmp, (size + 127) >> 7);
    zero_cache_lines(negmod, (negsize + 127) >> 7);
#else
    tmp    = (uint64_t *)OPENSSL_malloc(size);
    negmod = (uint64_t *)OPENSSL_malloc(negsize);

    if(tmp == NULL || negmod == NULL)
        goto err;

    memset(tmp, 0, size);
    memset(negmod, 0, negsize);
#endif

    /* Calculates negmod i.e. -1 * modulus */
    for(i = 0; i < modlen; i++)
    {
        negmod[i] = 0;
        if(mod[i] != 0)
            break;
    }

    negmod[i] = ~mod[i] + 1;

    for(i++; i < modlen + 1; i++)
        negmod[i] = ~mod[i];

    /* Finding most significant bit of modulus */
    // I need to know where most significant word of the modulus is
    for(msm = modlen - 1; msm >= 0; msm--)
    {
        if(mod[msm]) break;
    }

    if((msm == len - 1) && (mod[msm] >> 36))
    {
        return;  /* len needs to be incremented by 1 */
    }

    // I also need to put the modulus msb into the high 32b
    normalize = !(mod[msm] >> 32);
    if(normalize)
    {
        for(i = len * 3 - 1; i >= 1; i--)
        {
            negmod[i] = (negmod[i] << 32) | (negmod[i - 1] >> 32);
        }

        negmod[0] = negmod[0] << 32;
    }

    /* Calculating reciprocal of mod */
    recip[0] = 0;
    recip[1] = 0;
    recip[2] = 0;


    for(i = 63; i >= 0; i--)
    {
        uint64_t junk;
        recip[1] |= (uint64_t)1 << i;

        CVMX_MTM0(recip[0]);
        CVMX_MTM1(recip[1]);
        CVMX_MTM2(0);

        CVMX_V3MULU(junk, negmod[msm - 1], 0);
        CVMX_V3MULU(junk, negmod[msm], 0);
        CVMX_V3MULU(junk, (int64_t) - 1, 0);
        CVMX_V3MULU(junk, (int64_t) - 1, (uint64_t) 1 << 32);

        if(junk >> 63)
            recip[1] ^= (uint64_t) 1 << i;
    }

    for(i = 63; i >= 0; i--)
    {
        uint64_t junk;
        recip[0] |= (uint64_t)1 << i;
        CVMX_MTM0(recip[0]);
        CVMX_MTM1(recip[1]);
        CVMX_MTM2(0);

        CVMX_V3MULU(junk, negmod[msm - 1], 0);
        CVMX_V3MULU(junk, negmod[msm], 0);
        CVMX_V3MULU(junk, (int64_t) -1, 0);
        CVMX_V3MULU(junk, (int64_t) -1, (uint64_t)1 << 32);

        if(junk >> 63)
            recip[0] ^= (uint64_t)1 << i;
    }

    /*
     * This is equivalent to the standard paper-pencil division method
     * Starting from the highest bits of base, calculate quotient,
     * subtract (quotient * mod ) from base. Now we have a base with
     * fewer bits than the original. Keep going till base < mod
     */
    {
        uint64_t q[4];
        int k;

#ifndef SPEEDUP_CODE
        uint64_t *temp = NULL;
        temp = (uint64_t *)OPENSSL_malloc(size);
        if(temp == NULL) 
            goto err;
#endif

        if(normalize)
        {
            for(i = len * 3 - 1; i >= 1; i--)
                result[i] = (base[i] << 32) | (base[i - 1] >> 32);

            result[0] = base[0] << 32;
        }
        else
            memcpy(result, base, sizeof(uint64_t) * (len + 1));

        result[len] = 0;

#ifndef SPEEDUP_CODE
        CVMX_MTM0(recip[0]);
        CVMX_MTM1(recip[1]);
        CVMX_MTM2(0);

        for(k = 0; k < modlen; k++)
            CVMX_V3MULU(temp[k], mod[k], 0);

        CVMX_V3MULU(temp[k], 0, 0);
        ++k;
        CVMX_V3MULU(temp[k], 0, 0);
        ++k;
#endif

        /* Find out where msw of base is */
        msw = baselen - 1;
        do {
#ifndef SPEEDUP_CODE
            memset(temp, 0, size);
#endif

            /* Take reciprocal and multiply with high bits of "base",
               to get Q ~= base/mod */
            CVMX_MTM0(recip[0]);
            CVMX_MTM1(recip[1]);
            CVMX_MTM2(0);

            CVMX_V3MULU(q[0], (result[msw] >> 32) | (result[msw + 1] << 32), 0);
            CVMX_V3MULU(q[1], (result[msw + 1] >> 32), 0);
            CVMX_V3MULU(q[2], 0, 0);
            CVMX_V3MULU(q[3], 0, 0);

            CVMX_MTM0(q[2]);
            CVMX_MTM1(q[3]);
            CVMX_MTM2(0);

#ifndef SPEEDUP_CODE
            for(k = 0; k < baselen; k++)
                CVMX_V3MULU(temp[k], mod[k], 0);

            for(k = 0; k < baselen; k++)
                CVMX_V3MULU(temp[k], negmod[k], 0);

            for(k = 0; k < baselen; k++)    // could be smarter and stop earlier
            {
                CVMX_V3MULU(result[k + msw - msm], negmod[k],
                    result[k + msw - msm]);
            }
#else
            {
                uint64_t n0, n1, r0, r1;

                n0 = negmod[0];
                r0 = result[msw - msm];
                n1 = negmod[1];
                r1 = result[1 + msw - msm];

                CVMX_V3MULU(r0, n0, r0);

                for(k = 1; k < baselen - 1; k++)
                {
                    result[k - 1 + msw - msm] = r0;

                    CVMX_V3MULU(r0, n1, r1);

                    n1 = negmod[k + 1];
                    r1 = result[k + 1 + msw - msm];
                }

                result[baselen - 2 + msw - msm] = r0;

                CVMX_V3MULU(r0, n1, r1);

                result[baselen - 1 + msw - msm] = r0;
            }
#endif

            result[msw + 4] = 0;
            result[msw + 3] = 0;
            // this gets rid of junk left behind because 
            //negmod was signextended out to baselen bits
            result[msw + 2] = 0;
            msw--;
        } while(msw >= (modlen - 1));

#ifndef SPEEDUP_CODE
        OPENSSL_free(temp);
#endif
    }

    if(normalize)
    {
        for(i = 0; i < len * 3; i++)
            result[i] = (result[i + 1] << 32) | (result[i] >> 32);
    }

    memcpy(tmp, result, len * sizeof(uint64_t));

    /* Now finish off by subtracting modulus */
    while(1)
    {
        Vsub(tmp, mod, modlen + 2);

        if(tmp[modlen] >> 63)
            break;
        else
            memcpy(result, tmp, modlen * sizeof(uint64_t));
    }

#ifndef SPEEDUP_CODE
err:
    if(tmp)
        OPENSSL_free(tmp);
    if(negmod)
        OPENSSL_free(negmod);
#endif
}

/*
   CRT Algorithm:
   m1 = c^dP mod p
   m2 = c^dQ mod q
   h = qInv(m1 - m2) mod p
   m = m2 + hq
 */
int
_cvm_ModExpCrt (uint64_t * product, uint64_t * base,
  cvm_rsa_key_t * rkey, int nonwalign, int convert)
{
    int retc=1; 
#if !defined(TARGET_LINUX) || defined(USER_SPACE_MODEXP)
    if(1)
#else
    if(!cvm_crypto_vmul_hwbug())
#endif
    {
        uint64_t *mod1 = NULL;
        uint64_t *mod2 = NULL;
        uint64_t *tmp = NULL;
        int len = (rkey->len + 1) / 2, size = 0, tmpsize;
        int wlen = (rkey->len / 2) >> 3;      // length in (8 byte) words
        int blen = rkey->len >> 3;
        int wlen1;

        len = len << 3;
        if(nonwalign)
        {
            wlen++;
            blen += 2;                  //zero extended in case of non 8B 
        }
        else if(rkey->len % 16)
        {
            wlen++;
            blen += 2;                  //zero extended in case of non 8B 
        }

        size    = (blen * 8) + MODEXP_GUARD;
        tmpsize = (blen * 24);

        mod1 = (uint64_t *)OPENSSL_malloc(size);
        mod2 = (uint64_t *)OPENSSL_malloc(size);
        tmp  = (uint64_t *)OPENSSL_malloc(tmpsize);

        if(mod1 == NULL || mod2 == NULL || tmp == NULL)
            goto err;

        /* First do modular reduction */
        ModReduce(tmp, base, blen, rkey->p, wlen);

        if(cvm_ModExp(mod1, tmp, rkey->expp, rkey->p, (len + 63) / 64,
            rkey->eplen * 8, rkey->len, wlen * 8) <= 0)
        {
            return 0;
        }

        /* Same procedure for second round */
        wlen1 = find_msw (rkey->q);
        ModReduce(tmp, base, blen, rkey->q, wlen1);
        if(cvm_ModExp (mod2, tmp, rkey->expq, rkey->q, (len + 63) / 64,
            rkey->eqlen * 8, rkey->len, wlen * 8) <= 0)
        {
            return 0;
        }

        if(VCmp (mod1, mod2, wlen) < 0)
        {
            memcpy(tmp, mod2, wlen * sizeof (uint64_t));
            Vsub(tmp, mod1, wlen);
            /* Since it is negative, add p to make it positive ?? */
            if(VCmp(rkey->p, tmp, wlen) < 0)
            {
                /* p is less than tmp, so a single correction will not make it
                   positive */
                memcpy (mod1, rkey->p, wlen * sizeof (uint64_t));
                Vadd(mod1, rkey->p, wlen);

                mod1[wlen + 1] = 0;
                tmp[wlen] = 0;

                Vsub(mod1, tmp, wlen + 1);
            }
            else
            {
                memcpy (mod1, rkey->p, wlen * sizeof (uint64_t));
                mod1[wlen] = 0;
                tmp[wlen] = 0;

                Vsub(mod1, tmp, wlen + 1);
            }
        }
        else
        {
            Vsub(mod1, mod2, wlen);
        }

        /* zero off any higher bytes that might have been set during
         * mod operations
         */
        memset(&mod1[wlen], 0, wlen * sizeof (uint64_t));
        memset(&mod2[wlen], 0, wlen * sizeof (uint64_t));

        VMul(product, mod1, rkey->coeff, wlen);

        ModReduce(tmp, product, wlen * 2, rkey->p, wlen);

        /* Multiply tmp & rkey->q and put result in product */
        VMul(product, tmp, rkey->q, wlen);

        /* Assuming Vadd needs length in words */
        Vadd(product, mod2, wlen * 2);

err:
        if(mod1)
          OPENSSL_free(mod1);
        if(mod2)
          OPENSSL_free(mod2);
        if(tmp)
          OPENSSL_free(tmp);
    }
#if defined(TARGET_LINUX)
  else {

     cvm_crypto_op_t tokernel;
     if (cryptfd <= 0) {
       retc = crypto_init ();
       if (retc <= 0) {
       #ifdef PRINT_DEBUG
         printf ("Create device /dev/octcrypto \n");
       #endif
        return 0;
       }
     }
#if _MIPS_SIM == _MIPS_SIM_NABI32
     tokernel.sizeofptr = sizeof (void *);
     tokernel.arg1 = (uint64_t) (uint32_t) product;
     tokernel.arg2 = (uint64_t) (uint32_t) base;
     tokernel.arg3 = (uint64_t) (uint32_t) rkey;
     tokernel.arg6 = (int64_t) nonwalign;
     //ioctl on success returns 0
     crypto_mult (CRYPT_MODEXPCRT, (uint64_t) (uint32_t) & tokernel);
#else
     tokernel.sizeofptr = sizeof (void *);
     tokernel.arg1 = (uint64_t) product;
     tokernel.arg2 = (uint64_t) base;
     tokernel.arg3 = (uint64_t) rkey;
     tokernel.arg6 = (int64_t) nonwalign;
     //ioctl on success returns 0
     crypto_mult (CRYPT_MODEXPCRT, (uint64_t) & tokernel);

#endif
  }
#endif
  return retc;
}

/* In the case of octeon2, this API calls CRT implementation which uses vmul
 * insead of v3mul for multiplication.  This is because Vmul  based 
 * implementation is faster than V3mul implementation. In the case of octeon3,
 * default API is used which works as fast as VMUL implementation.
*/
int
cvm_ModExpCrt (uint64_t * product, uint64_t * base,
  cvm_rsa_key_t * rkey, int nonwalign)
{
#if defined(_MIPS_ARCH_OCTEON3) || !defined(TARGET_LINUX) 
  return _cvm_ModExpCrt (product, base, rkey, nonwalign, 0);
#else
  return _cvm_ModExpCrt_vmul (product, base, rkey, nonwalign, 0);
#endif
}
