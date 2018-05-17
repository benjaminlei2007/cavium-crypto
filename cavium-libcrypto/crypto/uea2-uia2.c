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



#include "cvmx.h"
#include <openssl/f8-f9.h>

static inline void stream_xor(uint8_t *in, uint8_t *out, uint8_t *KS, int bytes)
{
    int j = 0;
    uint64_t *in8, *ou8;
    uint32_t *in4, *ou4;
    in8 = (uint64_t *)in;
    ou8 = (uint64_t *)out;
    in4 = (uint32_t *)in;
    ou4 = (uint32_t *)out;

    if (cvmx_likely(bytes >= 8))
    {
        /* use 64-bit loads/stores if possible */
        if (!(((uint64_t)(unsigned long)in8) & 0x7) && 
            !(((uint64_t)(unsigned long)ou8) & 0x7))
            *ou8 = *in8^((uint64_t*)KS)[0];
        else if (!(((uint64_t)(unsigned long)in4) & 0x3) && 
                 !(((uint64_t)(unsigned long)ou4) & 0x3))
        {
            /* use 32-bit loads/stores if possible */
            *ou4 = *in4^((uint32_t*)KS)[0];
            *(ou4+1) = *(in4+1)^((uint32_t*)KS)[1];
        }
        else
        {
        for (j = 0; j < 8; j++)
            out[j] = in[j]^KS[j];
        }
    }
    else
    {
        for (j = 0; j < bytes; j++)
        {
            out[j] = in[j]^KS[j];
        }
    }
}

int uea2_init(uea2_ctx *ctx, uint32_t count, uint8_t bearer, uint8_t direction,
              uint8_t *key)
{
    uint32_t K[4], IV[4];
    if(!OCTEON_IS_MODEL(OCTEON_CN6XXX) && !OCTEON_IS_OCTEON3())
    { 
        printf("f8(uea2) supported only in CN6XXX/CN7XXX\n");
        return -1;
    }

    /* Load the confidentiality key for 
     * SNOW 3G initialization as in section 3.4.*/
    memcpy(K+3,key+0,4);  /* K[3] = key[0]; 
                          we assume K[3]=key[0]||key[1]||...||key[31],
                          with key[0] the most important bit of key */
    memcpy(K+2,key+4,4);  /* K[2] = key[1]; */
    memcpy(K+1,key+8,4);  /* K[1] = key[2]; */
    memcpy(K+0,key+12,4); /* K[0] = key[3]; we assume
                             K[0]=key[96]||key[97]||...||key[127],
                             with key[127] the least important bit of key */
                                                                               
  /* Prepare the initialization vector (IV) for SNOW 3G initialization as in 
     section 3.4. */
    IV[3] = count;
    IV[2] = (bearer << 27) | ((direction & 0x1) << 26);
    IV[1] = IV[3];
    IV[0] = IV[2];

    CVMX_MT_SNOW3G_RESULT(IV[0]);
    CVMX_MT_SNOW3G_FSM(IV[1], 0);
    CVMX_MT_SNOW3G_FSM(IV[2], 1);
    CVMX_MT_SNOW3G_FSM(IV[3], 2);

    CVMX_MT_SNOW3G_LFSR((((uint64_t)(K[0] ^ 0xffffffff) << 32) | (K[1] ^ 0xffffffff)), 0);
    CVMX_MT_SNOW3G_LFSR((((uint64_t)(K[2] ^ 0xffffffff) << 32) | (K[3] ^ 0xffffffff)), 1);
    CVMX_MT_SNOW3G_LFSR((((uint64_t)K[0] << 32) | K[1]), 2);
    CVMX_MT_SNOW3G_LFSR((((uint64_t)K[2] << 32) | K[3]), 3);
    CVMX_MT_SNOW3G_LFSR((((uint64_t)(K[0] ^ 0xffffffff) << 32) | (K[1] ^ 0xffffffff ^ IV[3])), 4);
    CVMX_MT_SNOW3G_LFSR((((uint64_t)(K[2] ^ 0xffffffff ^ IV[2]) << 32) | (K[3] ^ 0xffffffff)), 5);
    CVMX_MT_SNOW3G_LFSR((((uint64_t)(K[0] ^ IV[1]) << 32) | (K[1])), 6);
    CVMX_MT_SNOW3G_START(((uint64_t)K[2] << 32) | (K[3] ^ IV[0]));

    return 0;
}

int uea2_enc(uea2_ctx *ctx, int length, uint8_t *input, uint8_t *output)
{
    int n = (length + 31) / 32;
    int i = 0;
    uint8_t KS[8];

    CVMX_MF_SNOW3G_RESULT(((uint64_t *)KS)[0]);
    stream_xor(&input[i*8], &output[i*8], KS, 8);

    for (i=1;i<(n+1)/2;i++)
    {
        CVMX_MT_SNOW3G_MORE(0);
        CVMX_MF_SNOW3G_RESULT(((uint64_t *)KS)[0]);
        stream_xor(&input[i*8], &output[i*8], KS, n*4 - i*8);
    }

    return 0;
}

int uia2_init(uia2_ctx *ctx, uint32_t count, uint32_t fresh, uint8_t direction,
              uint8_t *key)
{  
    uint32_t K[4], IV[4];
    if(!OCTEON_IS_MODEL(OCTEON_CN6XXX) && !OCTEON_IS_OCTEON3())
    { 
        printf("f9(uia2) supported only in CN6XXX/CN7XXX\n");
        return -1;
    }

    /* Load the Integrity Key for SNOW3G initialization as in section 4.4. */
    memcpy(K+3,key+0,4); /*K[3] = key[0]; we assume
                             K[3]=key[0]||key[1]||...||key[31] , with key[0] the
                          * most important bit of
                          * key*/
    memcpy(K+2,key+4,4); /*K[2] = key[1];*/
    memcpy(K+1,key+8,4); /*K[1] = key[2];*/
    memcpy(K+0,key+12,4); /*K[0] = key[3]; we assume
                    K[0]=key[96]||key[97]||...||key[127] , with key[127] the
                           * least important
                           * bit of key*/
    /* Prepare the Initialization Vector (IV) for SNOW3G  initialization as in
     * section 4.4. */
    IV[3] = count;
    IV[2] = fresh;
    IV[1] = count ^ ( direction << 31 ) ;
    IV[0] = fresh ^ (direction << 15);

    CVMX_MT_SNOW3G_RESULT(IV[0]);
    CVMX_MT_SNOW3G_FSM(IV[1], 0);
    CVMX_MT_SNOW3G_FSM(IV[2], 1);
    CVMX_MT_SNOW3G_FSM(IV[3], 2);

    CVMX_MT_SNOW3G_LFSR((((uint64_t)(K[0] ^ 0xffffffff) << 32) | (K[1] ^ 0xffffffff)), 0);
    CVMX_MT_SNOW3G_LFSR((((uint64_t)(K[2] ^ 0xffffffff) << 32) | (K[3] ^ 0xffffffff)), 1);
    CVMX_MT_SNOW3G_LFSR((((uint64_t)K[0] << 32) | K[1]), 2);
    CVMX_MT_SNOW3G_LFSR((((uint64_t)K[2] << 32) | K[3]), 3);
    CVMX_MT_SNOW3G_LFSR((((uint64_t)(K[0] ^ 0xffffffff) << 32) | (K[1] ^ 0xffffffff ^ IV[3])), 4);
    CVMX_MT_SNOW3G_LFSR((((uint64_t)(K[2] ^ 0xffffffff ^ IV[2]) << 32) | (K[3] ^ 0xffffffff)), 5);
    CVMX_MT_SNOW3G_LFSR((((uint64_t)(K[0] ^ IV[1]) << 32) | (K[1])), 6);
    CVMX_MT_SNOW3G_START(((uint64_t)K[2] << 32) | (K[3] ^ IV[0]));

    return 0;
}

static inline uint64_t bitswap64 (uint64_t x) 
{
    uint64_t res = 0;
    uint32_t output=0, output2=0;

    uint32_t input  = x & 0xffffffff;

    uint32_t input2 = (x >> 32) & 0xffffffff;

    CVMX_MT_CRC_IV_REFLECT(input);
    CVMX_MF_CRC_IV(output);
    CVMX_ES32(output, output);
    CVMX_MT_CRC_IV_REFLECT(input2);
    CVMX_MF_CRC_IV(output2);
    CVMX_ES32(output2, output2);

    res = ((uint64_t) output << 32) | ((uint64_t) output2);

    return(res);
}

static inline uint64_t MUL64_GF(uint64_t V, uint64_t P, uint64_t c)
{
    uint64_t ret;
    //c = endian_swap(c);
    c = 0x00d8;

    V = bitswap64(V);
    P = bitswap64(P);

    // Init Galois multiplier
    CVMX_MT_GFM_POLY (c);

    CVMX_MT_GFM_MUL (P, 0);
    CVMX_MT_GFM_MUL (0, 1);

    CVMX_MT_GFM_RESINP(0, 0);
    CVMX_MT_GFM_RESINP(0, 1);

    CVMX_MT_GFM_XORMUL1 (V); 
    CVMX_MF_GFM_RESINP (ret, 1);

    return bitswap64 (ret);
}

/* mask64bit.
 * Input n: an integer in 0-64.
 * Output : a 64 bit mask.
 * Prepares a 64 bit mask with required number of 1 bits on the MSB side.
 */
static inline uint64_t mask64bit(int n)
{
    return ~((1ULL<<(64-n))-1);
}

int uia2_update(uia2_ctx *ctx, int length, uint8_t *input)
{  
    uint64_t P, Q, EVAL, V=0, c, M_D_2;
    uint32_t z4[2];
    int D, rem_bits = 0;
    int i;

    CVMX_MF_SNOW3G_RESULT(P);
    CVMX_MT_SNOW3G_MORE(0);
    CVMX_MF_SNOW3G_RESULT(Q);
    CVMX_MT_SNOW3G_MORE(0);
    CVMX_MF_SNOW3G_RESULT(((uint64_t*)z4)[0]);

    /* Calculation */
    D = ((length+63)/64)+1;                         
    EVAL = 0;
    c = 0x1b;

    /* for 0 <= i <= D-3 */
    for (i=0;i<D-2;i++)
    {
        /* use 64-bit loads if possible */
        if (!(((uint64_t)(unsigned long)input) & 0x7))
            V = EVAL ^ (((uint64_t *)input)[i]);
        else if (!(((uint64_t)(unsigned long)input) & 0x3))
        {
            /* use 32-bit loads if possible */
            ((uint32_t *)&V)[0] = ((uint32_t *)&EVAL)[0] ^ (((uint32_t *)input)[i*2]);
            ((uint32_t *)&V)[1] = ((uint32_t *)&EVAL)[1] ^ (((uint32_t *)input)[i*2+1]);
        }
        else
        {
            int j = 0;
            for (j = 0; j < 8; j++)
                ((uint8_t *)&V)[j] = ((uint8_t *)&EVAL)[j] ^ ((uint8_t *)input)[i*8+j];
        }
        EVAL = MUL64_GF(V,P,c);
    }

    /* for D-2 */
    rem_bits = length % 64;
    if (rem_bits == 0)
        rem_bits = 64;

    M_D_2 = ((uint64_t *)input)[i] & mask64bit(rem_bits);
    V = EVAL ^ M_D_2;
    EVAL = MUL64_GF(V,P,c);

    /* for D-1 */
    EVAL ^= length; 

    /* Multiply by Q */
    EVAL = MUL64_GF(EVAL,Q,c);

    ctx->mac_i = (uint32_t)(EVAL >> 32) ^ z4[0];

    return 0; 
}

int uia2_final(uia2_ctx *ctx, uint32_t *mac)
{
       if(!OCTEON_IS_MODEL(OCTEON_CN6XXX) && !OCTEON_IS_OCTEON3()) { 
        printf("f9(uia2) supported only in CN6XXX/CN7XXX\n");
        return -1;
    }
    *mac=ctx->mac_i;
    return 0;
}

