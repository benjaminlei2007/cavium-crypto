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
#include <assert.h>

#include "cvmx.h"
#include "cvmx-asm.h"
#include "cvmx-key.h"

//#define AES_XCB_DEBUG
//#define AES_XCB_TEST_CPU_CYCLES
#ifdef AES_XCB_TEST_CPU_CYCLES
static uint64_t start_cycle = 0, end_cycle = 0;
#endif

#ifdef AES_XCB_DEBUG
static void
hex_dump (uint8_t * inp, uint32_t len, const char *s)
{
    int i;
    printf ("%s : ", s);
    for (i = 0; i < len; i++)
        printf ("%02x", *(inp + i));
    printf ("\n");
    return;
}
#endif


/**
 * AES-XCB Wide Block Encryption algorithm.
 * Based on IEEE Draft P1619.2 Draft 10 June 2009.
 *
 * @param in            Text data to be encrypted. (Min 16 bytes).
 * @param in_len        Text data length in bytes.
 * @param key            Key Pointer.
 * @param key_len        Length of the Key in bits. (Either 128 or 256).
 * @param zdata            Associated Data Pointer.
 * @param zdata_len        length of Associated Data in bytes.
 * @param out            Pointer used to store the Encrypted Text.
 */

int
AES_XCB_encrypt (const unsigned char *in, const uint64_t in_len,
                 const unsigned char *key, const uint32_t key_len,
                 const unsigned char *zdata, const uint64_t zdata_len,
                 unsigned char *out)
{
    uint64_t K1[4], K2[4], K3[4], H[2], zeroes[2], i, zblks, *E, *tmp;
    uint8_t zres, bigkey;
#ifdef AES_XCB_TEST_CPU_CYCLES
    start_cycle = cvmx_get_cycle ();
#endif

    if (key)
        CVMX_PREFETCH0 ((uint64_t *) key);
    else
        return -2;
    if ((key_len != 128 && key_len != 256) || (in_len < 16))
        return -1;

    bigkey = (key_len == 256);

    if (bigkey)
    {
        CVMX_MT_AES_KEY (*((uint64_t *) key), 0);
        CVMX_MT_AES_KEY (*((uint64_t *) key + 1), 1);
        CVMX_MT_AES_KEY (*((uint64_t *) key + 2), 2);
        CVMX_MT_AES_KEY (*((uint64_t *) key + 3), 3);
        CVMX_MT_AES_KEYLENGTH (3);
    }
    else
    {
        CVMX_MT_AES_KEY (*((uint64_t *) key), 0);
        CVMX_MT_AES_KEY (*((uint64_t *) key + 1), 1);
        CVMX_MT_AES_KEY (0, 2);
        CVMX_MT_AES_KEY (0, 3);
        CVMX_MT_AES_KEYLENGTH (1);
    }

    CVMX_MT_AES_ENC0 (0);
    CVMX_MT_AES_ENC1 (0);
    CVMX_PREFETCH0 (H);
    /* Prev instruction should take about 100 cycles, as per the CNXXXX spec */

    zblks = zdata_len / 16;
    zres = zdata_len % 16;
    zeroes[0] = 0;
    zeroes[1] = 0;
    K1[2] = 0;
    K1[3] = 0;

    CVMX_MT_GFM_POLY ((uint64_t) 0xE100);       /* For GF (2^128) */
    CVMX_MT_GFM_RESINP (0, 0);  /* Resetting the result to 0 */
    CVMX_MT_GFM_RESINP (0, 1);
    CVMX_MF_AES_RESULT (H[0], 0);
    CVMX_MF_AES_RESULT (H[1], 1);
    CVMX_MT_AES_ENC0 (0);
    CVMX_MT_AES_ENC1 (1);

/* 125 cycles till here */

    CVMX_MT_GFM_MUL (H[0], 0);  /* Loading the Multiplier */
    CVMX_MT_GFM_MUL (H[1], 1);
    CVMX_MT_GFM_XOR0 (0);       /* Feeding 0^128 to the GHASH */
    CVMX_MT_GFM_XORMUL1 (0);

    CVMX_MF_AES_RESULT (K1[0], 0);
    CVMX_MF_AES_RESULT (K1[1], 1);
    if (bigkey)
    {
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (2);
    }

    /* Feeding padded Z (associated data) */

    for (i = 0; i < (zblks * 2); i += 2)
    {
        uint64_t r0, r1;
        if (!zdata)
            return -2;
        r0 = *((uint64_t *) zdata + i);
        r1 = *((uint64_t *) zdata + i + 1);
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
    }

    if (zres)
    {
        if (!zdata)
            return -2;
        memcpy ((uint8_t *) zeroes, zdata + zblks * 16, zres);
        CVMX_MT_GFM_XOR0 (zeroes[0]);
        CVMX_MT_GFM_XORMUL1 (zeroes[1]);
    }

    if (bigkey)
    {
        CVMX_MF_AES_RESULT (K1[2], 0);
        CVMX_MF_AES_RESULT (K1[3], 1);
    }
    CVMX_MT_AES_ENC0 (0);
    CVMX_MT_AES_ENC1 (5);

    zblks = (in_len - 16) / 16;
    zres = (in_len - 16) % 16;
    zeroes[0] = zeroes[1] = i = 0;
    tmp = (uint64_t *) in;
    if (zres)
        memcpy ((uint8_t *) zeroes, (uint8_t *) in + (zblks * 16), zres);

    /* The following if statement takes 1200 cycles for 512Bytes */
    if (cvmx_likely (zblks > 3))
    {
        uint64_t r0, r1;
        if (!tmp)
            return -2;
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        CVMX_MF_AES_RESULT (K2[0], 0);  // K2 here is equivalent to Kc
        CVMX_MF_AES_RESULT (K2[1], 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (6);
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        CVMX_MF_AES_RESULT (K2[2], 0);  // K2 here is equivalent to Kc
        CVMX_MF_AES_RESULT (K2[3], 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (3);
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        CVMX_MF_AES_RESULT (K3[0], 0);
        CVMX_MF_AES_RESULT (K3[1], 1);  //K3 is equivalent to Kd
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (4);
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        CVMX_MF_AES_RESULT (K3[2], 0);
        CVMX_MF_AES_RESULT (K3[3], 1);  //K3 is equivalent to Kd
        CVMX_MT_AES_KEY (K1[0], 0);
        CVMX_MT_AES_KEY (K1[1], 1);
        CVMX_MT_AES_KEY (K1[2], 2);
        CVMX_MT_AES_KEY (K1[3], 3);
        CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
        r0 = *((uint64_t *) (in + in_len - 16));
        r1 = *((uint64_t *) (in + in_len - 16) + 1);
        CVMX_MT_AES_ENC0 (r0);
        CVMX_MT_AES_ENC1 (r1);
        i += 8;
        /* The following loop takes about 1000 cycles for 512B data */
        while (i < (zblks * 2))
        {
            r0 = *tmp++;
            r1 = *tmp++;
            i += 2;
            CVMX_MT_GFM_XOR0 (r0);
            CVMX_MT_GFM_XORMUL1 (r1);
        }
        CVMX_MF_AES_RESULT (K1[0], 0);
        CVMX_MF_AES_RESULT (K1[1], 1);
        CVMX_MT_AES_KEY (K2[0], 0);
        CVMX_MT_AES_KEY (K2[1], 1);
        CVMX_MT_AES_KEY (K2[2], 2);
        CVMX_MT_AES_KEY (K2[3], 3);
        CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (0);   // Dummy encrypt
    }
    else if (zblks > 2)
    {
        uint64_t r0, r1;
        if (!tmp)
            return -2;
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MF_AES_RESULT (K2[0], 0);  // K2 here is equivalent to Kc
        CVMX_MF_AES_RESULT (K2[1], 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (6);
        CVMX_MF_AES_RESULT (K2[2], 0);  // K2 here is equivalent to Kc
        CVMX_MF_AES_RESULT (K2[3], 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (3);
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        CVMX_MF_AES_RESULT (K3[0], 0);
        CVMX_MF_AES_RESULT (K3[1], 1);  //K3 is equivalent to Kd
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (4);
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        r0 = *((uint64_t *) (in + in_len - 16));
        r1 = *((uint64_t *) (in + in_len - 16) + 1);
        CVMX_MF_AES_RESULT (K3[2], 0);
        CVMX_MF_AES_RESULT (K3[3], 1);  //K3 is equivalent to Kd
        CVMX_MT_AES_KEY (K1[0], 0);
        CVMX_MT_AES_KEY (K1[1], 1);
        CVMX_MT_AES_KEY (K1[2], 2);
        CVMX_MT_AES_KEY (K1[3], 3);
        CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
        CVMX_MT_AES_ENC0 (r0);
        CVMX_MT_AES_ENC1 (r1);
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        CVMX_MF_AES_RESULT (K1[0], 0);
        CVMX_MF_AES_RESULT (K1[1], 1);
        CVMX_MT_AES_KEY (K2[0], 0);
        CVMX_MT_AES_KEY (K2[1], 1);
        CVMX_MT_AES_KEY (K2[2], 2);
        CVMX_MT_AES_KEY (K2[3], 3);
        CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (0);   // Dummy encrypt
    }
    else if (zblks > 1)
    {
        uint64_t r0, r1;
        if (!tmp)
            return -2;
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MF_AES_RESULT (K2[0], 0);  // K2 here is equivalent to Kc
        CVMX_MF_AES_RESULT (K2[1], 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (6);
        CVMX_MF_AES_RESULT (K2[2], 0);  // K2 here is equivalent to Kc
        CVMX_MF_AES_RESULT (K2[3], 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (3);
        CVMX_MF_AES_RESULT (K3[0], 0);
        CVMX_MF_AES_RESULT (K3[1], 1);  //K3 is equivalent to Kd
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (4);
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        CVMX_MF_AES_RESULT (K3[2], 0);
        CVMX_MF_AES_RESULT (K3[3], 1);  //K3 is equivalent to Kd
        CVMX_MT_AES_KEY (K1[0], 0);
        CVMX_MT_AES_KEY (K1[1], 1);
        CVMX_MT_AES_KEY (K1[2], 2);
        CVMX_MT_AES_KEY (K1[3], 3);
        CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
        r0 = *((uint64_t *) (in + in_len - 16));
        r1 = *((uint64_t *) (in + in_len - 16) + 1);
        CVMX_MT_AES_ENC0 (r0);
        CVMX_MT_AES_ENC1 (r1);
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        CVMX_MF_AES_RESULT (K1[0], 0);
        CVMX_MF_AES_RESULT (K1[1], 1);
        CVMX_MT_AES_KEY (K2[0], 0);
        CVMX_MT_AES_KEY (K2[1], 1);
        CVMX_MT_AES_KEY (K2[2], 2);
        CVMX_MT_AES_KEY (K2[3], 3);
        CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (0);   // Dummy encrypt
    }
    else
    {
        uint64_t r0, r1;
        CVMX_MF_AES_RESULT (K2[0], 0);  // K2 here is equivalent to Kc
        CVMX_MF_AES_RESULT (K2[1], 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (6);
        CVMX_MF_AES_RESULT (K2[2], 0);  // K2 here is equivalent to Kc
        CVMX_MF_AES_RESULT (K2[3], 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (3);
        CVMX_MF_AES_RESULT (K3[0], 0);
        CVMX_MF_AES_RESULT (K3[1], 1);  //K3 is equivalent to Kd
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (4);
        if (zblks)
        {
            if (!tmp)
                return -2;
            CVMX_MT_GFM_XOR0 (*tmp++);
            CVMX_MT_GFM_XORMUL1 (*tmp++);
        }
        CVMX_MF_AES_RESULT (K3[2], 0);
        CVMX_MF_AES_RESULT (K3[3], 1);  //K3 is equivalent to Kd
        CVMX_MT_AES_KEY (K1[0], 0);
        CVMX_MT_AES_KEY (K1[1], 1);
        CVMX_MT_AES_KEY (K1[2], 2);
        CVMX_MT_AES_KEY (K1[3], 3);
        CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
        r0 = *((uint64_t *) (in + in_len - 16));
        r1 = *((uint64_t *) (in + in_len - 16) + 1);
        CVMX_MT_AES_ENC0 (r0);
        CVMX_MT_AES_ENC1 (r1);
        CVMX_MF_AES_RESULT (K1[0], 0);
        CVMX_MF_AES_RESULT (K1[1], 1);
        CVMX_MT_AES_KEY (K2[0], 0);
        CVMX_MT_AES_KEY (K2[1], 1);
        CVMX_MT_AES_KEY (K2[2], 2);
        CVMX_MT_AES_KEY (K2[3], 3);
        CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (0);   // Dummy encrypt
    }

    if (zres)
    {
        CVMX_MT_GFM_XOR0 (zeroes[0]);
        CVMX_MT_GFM_XORMUL1 (zeroes[1]);
    }

    CVMX_MT_GFM_XOR0 (0);
    CVMX_MT_GFM_XORMUL1 (0);

    CVMX_MT_GFM_XOR0 (128 + zdata_len * 8);
    CVMX_MT_GFM_XORMUL1 (zblks * 128 + (zres ? 128 : 0) + 128);


    CVMX_MF_GFM_RESINP (K1[2], 0);
    CVMX_MF_GFM_RESINP (K1[3], 1);
    K1[0] ^= K1[2];
    K1[1] ^= K1[3];
    K1[2] = K1[0];
    K1[3] = K1[1];

/* 1550 cycles from prev check point  for 512B*/
    E = (uint64_t *) out;

    /* Compute E = B ^ c(Kc,D,#B) */

    i = 0;
    if (!E)
        return -2;
    {
        uint64_t t0, t1;
        uint32_t lower;
        t0 = K1[0];
        t1 = K1[1];
        lower = K1[1] & 0x00000000ffffffffULL;
        while (i < 2 * (zblks + (zres ? 1 : 0)))
        {
            uint64_t r0, r1;
            CVMX_MT_AES_ENC0 (t0);
            CVMX_MT_AES_ENC1 (t1);
            t1 = (t1 & 0xffffffff00000000ULL) | ++lower;
            r0 = *((uint64_t *) in + i);
            r1 = *((uint64_t *) in + i + 1);
            CVMX_MF_AES_RESULT (E[i], 0);
            CVMX_MF_AES_RESULT (E[i + 1], 1);
            E[i] ^= r0;
            E[i + 1] ^= r1;
            i += 2;
        }
    }
    /* 1400 cycles from prev check point for 512B */

    zblks = zdata_len / 16;
    zres = zdata_len % 16;
    i = zeroes[0] = 0;
    zeroes[1] = 0;
    if (zres)
        memcpy ((uint8_t *) zeroes, zdata + zblks * 16, zres);

    /* Computing F = D ^ h2 (H,Z,E) */
    CVMX_MT_GFM_POLY ((uint64_t) 0xE100);       // For GF (2^128)
    CVMX_MT_GFM_MUL (H[0], 0);
    CVMX_MT_GFM_MUL (H[1], 1);
    CVMX_MT_GFM_RESINP (0, 0);
    CVMX_MT_GFM_RESINP (0, 1);
    /* Feeding (Z | 0^128) to the Hash */
    while (i < (zblks * 2))
    {
        CVMX_MT_GFM_XOR0 (*((uint64_t *) zdata + i));
        CVMX_MT_GFM_XORMUL1 (*((uint64_t *) zdata + i + 1));
        i += 2;
    }

    if (zres)
    {
        CVMX_MT_GFM_XOR0 (zeroes[0]);
        CVMX_MT_GFM_XORMUL1 (zeroes[1]);
    }
    zblks = (in_len - 16) / 16;
    zres = (in_len - 16) % 16;

    CVMX_MT_GFM_XOR0 (0);
    CVMX_MT_GFM_XORMUL1 (0);

    zeroes[0] = zeroes[1] = 0;
    if (zres)
        memcpy ((uint8_t *) zeroes, (uint8_t *) E + (zblks * 16), zres);

    CVMX_MT_AES_KEY (K3[0], 0);
    CVMX_MT_AES_KEY (K3[1], 1);
    CVMX_MT_AES_KEY (K3[2], 2);
    CVMX_MT_AES_KEY (K3[3], 3);
    CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
    CVMX_MT_AES_DEC0 (0);
    CVMX_MT_AES_DEC1 (0);       // Dummy encrypt to use away first encryption 

    tmp = (uint64_t *) E;
    i = 0;
    /* Following loop takes 1277 cycles for 512B data */
    while (i < (zblks * 2))
    {
        uint64_t r0 = *tmp++;
        uint64_t r1 = *tmp++;
        i += 2;
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
    }

    if (zres)
    {
        CVMX_MT_GFM_XOR0 (zeroes[0]);
        CVMX_MT_GFM_XORMUL1 (zeroes[1]);
    }

    CVMX_MT_GFM_XOR0 (128 + zdata_len * 8);
    CVMX_MT_GFM_XORMUL1 ((in_len - 16) << 3);

    CVMX_MT_GFM_XOR0 (128 + zdata_len * 8);
    CVMX_MT_GFM_XORMUL1 (zblks * 128 + (zres ? 128 : 0) + 128);

    CVMX_MF_AES_RESULT (K1[0], 0);
    CVMX_MF_AES_RESULT (K1[1], 1);

    CVMX_MF_GFM_RESINP (H[0], 0);
    CVMX_MF_GFM_RESINP (H[1], 1);

    H[0] ^= K1[2];
    H[1] ^= K1[3];
/* 1500 from prev check point for 512B */

    CVMX_MT_AES_DEC0 (H[0]);
    CVMX_MT_AES_DEC1 (H[1]);
    CVMX_MF_AES_RESULT (K1[0], 0);
    CVMX_MF_AES_RESULT (K1[1], 1);

    memcpy ((uint8_t *) E + in_len - 16, (uint8_t *) K1, 16);
#ifdef AES_XCB_TEST_CPU_CYCLES
    end_cycle = cvmx_get_cycle ();
    printf ("AES_Enc cycles %ld\n", end_cycle - start_cycle);
#endif
    /* 4574 cycles for 512B */
    return 0;

}


/**
 * AES-XCB Wide Block Decryption algorithm.
 * Based on IEEE Draft P1619.2 Draft 10 June 2009.
 *
 * @param in            Text data to be decrypted. (Min 16 bytes).
 * @param in_len        Text data length in bytes.
 * @param key            Key Pointer.
 * @param key_len        Length of the Key in bits. (Either 128 or 256).
 * @param zdata            Associated Data Pointer.
 * @param zdata_len        length of Associated Data in bytes.
 * @param out            Pointer used to store the Decrypted Text.
 */

int
AES_XCB_decrypt (const unsigned char *in, const uint64_t in_len,
                 const unsigned char *key, const uint32_t key_len,
                 const unsigned char *zdata, const uint64_t zdata_len,
                 unsigned char *out)
{
    uint64_t K1[4], K2[4], K3[4], H[2], zeroes[2], i, zblks, *E, *tmp;
    uint8_t zres, bigkey;
#ifdef AES_XCB_TEST_CPU_CYCLES
    start_cycle = cvmx_get_cycle ();
#endif

    if (key)
        CVMX_PREFETCH0 ((uint64_t *) key);
    else
        return -2;

    if ((key_len != 128 && key_len != 256) || (in_len < 16))
        return -1;

    bigkey = (key_len == 256);

    if (bigkey)
    {
        CVMX_MT_AES_KEY (*((uint64_t *) key), 0);
        CVMX_MT_AES_KEY (*((uint64_t *) key + 1), 1);
        CVMX_MT_AES_KEY (*((uint64_t *) key + 2), 2);
        CVMX_MT_AES_KEY (*((uint64_t *) key + 3), 3);
        CVMX_MT_AES_KEYLENGTH (3);
    }
    else
    {
        CVMX_MT_AES_KEY (*((uint64_t *) key), 0);
        CVMX_MT_AES_KEY (*((uint64_t *) key + 1), 1);
        CVMX_MT_AES_KEY (0, 2);
        CVMX_MT_AES_KEY (0, 3);
        CVMX_MT_AES_KEYLENGTH (1);
    }

    CVMX_MT_AES_ENC0 (0);
    CVMX_MT_AES_ENC1 (0);
    CVMX_PREFETCH0 (H);
    /* Prev instruction should take about 100 cycles, as per the CNXXXX spec */

    zblks = zdata_len / 16;
    zres = zdata_len % 16;
    zeroes[0] = 0;
    zeroes[1] = 0;
    K1[2] = 0;
    K1[3] = 0;

    CVMX_MT_GFM_POLY ((uint64_t) 0xE100);       /* For GF (2^128) */
    CVMX_MT_GFM_RESINP (0, 0);  /* Resetting the result to 0 */
    CVMX_MT_GFM_RESINP (0, 1);
    CVMX_MF_AES_RESULT (H[0], 0);
    CVMX_MF_AES_RESULT (H[1], 1);
    CVMX_MT_AES_ENC0 (0);
    CVMX_MT_AES_ENC1 (1);

    CVMX_MT_GFM_MUL (H[0], 0);  /* Loading the Multiplier */
    CVMX_MT_GFM_MUL (H[1], 1);

    for (i = 0; i < (zblks * 2); i += 2)
    {
        uint64_t r0, r1;
        if (!zdata)
            return -2;
        r0 = *((uint64_t *) zdata + i);
        r1 = *((uint64_t *) zdata + i + 1);
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
    }

    if (zres)
    {
        if (!zdata)
            return -2;
        memcpy ((uint8_t *) zeroes, zdata + zblks * 16, zres);
        CVMX_MT_GFM_XOR0 (zeroes[0]);
        CVMX_MT_GFM_XORMUL1 (zeroes[1]);
    }

    CVMX_MF_AES_RESULT (K1[0], 0);
    CVMX_MF_AES_RESULT (K1[1], 1);
    if (bigkey)
    {
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (2);
    }

    CVMX_MT_GFM_XOR0 (0);       /* Feeding 0^128 to the GHASH */
    CVMX_MT_GFM_XORMUL1 (0);

    if (bigkey)
    {
        CVMX_MF_AES_RESULT (K1[2], 0);
        CVMX_MF_AES_RESULT (K1[3], 1);
    }
    CVMX_MT_AES_ENC0 (0);
    CVMX_MT_AES_ENC1 (5);

    zblks = (in_len - 16) / 16;
    zres = (in_len - 16) % 16;
    zeroes[0] = zeroes[1] = i = 0;
    tmp = (uint64_t *) in;
    if (zres)
        memcpy ((uint8_t *) zeroes, (uint8_t *) in + (zblks * 16), zres);

    if (cvmx_likely (zblks > 3))
    {
        uint64_t r0, r1;
        if (!tmp)
            return -2;
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        CVMX_MF_AES_RESULT (K2[0], 0);  // K2 here is equivalent to Kc
        CVMX_MF_AES_RESULT (K2[1], 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (6);
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        CVMX_MF_AES_RESULT (K2[2], 0);  // K2 here is equivalent to Kc
        CVMX_MF_AES_RESULT (K2[3], 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (3);
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        CVMX_MF_AES_RESULT (K3[0], 0);
        CVMX_MF_AES_RESULT (K3[1], 1);  //K3 is equivalent to Kd
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (4);
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        CVMX_MF_AES_RESULT (K3[2], 0);
        CVMX_MF_AES_RESULT (K3[3], 1);  //K3 is equivalent to Kd
        CVMX_MT_AES_KEY (K3[0], 0);
        CVMX_MT_AES_KEY (K3[1], 1);
        CVMX_MT_AES_KEY (K3[2], 2);
        CVMX_MT_AES_KEY (K3[3], 3);
        CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
        r0 = *((uint64_t *) (in + in_len - 16));
        r1 = *((uint64_t *) (in + in_len - 16) + 1);
        CVMX_MT_AES_ENC0 (r0);
        CVMX_MT_AES_ENC1 (r1);
        i += 8;
        /* The following loop takes about 1000 cycles for 512B data */
        while (i < (zblks * 2))
        {
            r0 = *tmp++;
            r1 = *tmp++;
            i += 2;
            CVMX_MT_GFM_XOR0 (r0);
            CVMX_MT_GFM_XORMUL1 (r1);
        }
        CVMX_MF_AES_RESULT (K3[0], 0);
        CVMX_MF_AES_RESULT (K3[1], 1);
        CVMX_MT_AES_KEY (K2[0], 0);
        CVMX_MT_AES_KEY (K2[1], 1);
        CVMX_MT_AES_KEY (K2[2], 2);
        CVMX_MT_AES_KEY (K2[3], 3);
        CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (0);   // Dummy encrypt
    }
    else if (zblks > 2)
    {
        uint64_t r0, r1;
        if (!tmp)
            return -2;
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MF_AES_RESULT (K2[0], 0);  // K2 here is equivalent to Kc
        CVMX_MF_AES_RESULT (K2[1], 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (6);
        CVMX_MF_AES_RESULT (K2[2], 0);  // K2 here is equivalent to Kc
        CVMX_MF_AES_RESULT (K2[3], 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (3);
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        CVMX_MF_AES_RESULT (K3[0], 0);
        CVMX_MF_AES_RESULT (K3[1], 1);  //K3 is equivalent to Kd
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (4);
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        r0 = *((uint64_t *) (in + in_len - 16));
        r1 = *((uint64_t *) (in + in_len - 16) + 1);
        CVMX_MF_AES_RESULT (K3[2], 0);
        CVMX_MF_AES_RESULT (K3[3], 1);  //K3 is equivalent to Kd
        CVMX_MT_AES_KEY (K3[0], 0);
        CVMX_MT_AES_KEY (K3[1], 1);
        CVMX_MT_AES_KEY (K3[2], 2);
        CVMX_MT_AES_KEY (K3[3], 3);
        CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
        CVMX_MT_AES_ENC0 (r0);
        CVMX_MT_AES_ENC1 (r1);
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        CVMX_MF_AES_RESULT (K3[0], 0);
        CVMX_MF_AES_RESULT (K3[1], 1);
        CVMX_MT_AES_KEY (K2[0], 0);
        CVMX_MT_AES_KEY (K2[1], 1);
        CVMX_MT_AES_KEY (K2[2], 2);
        CVMX_MT_AES_KEY (K2[3], 3);
        CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (0);   // Dummy encrypt
    }
    else if (zblks > 1)
    {
        uint64_t r0, r1;
        if (!tmp)
            return -2;
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MF_AES_RESULT (K2[0], 0);  // K2 here is equivalent to Kc
        CVMX_MF_AES_RESULT (K2[1], 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (6);
        CVMX_MF_AES_RESULT (K2[2], 0);  // K2 here is equivalent to Kc
        CVMX_MF_AES_RESULT (K2[3], 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (3);
        CVMX_MF_AES_RESULT (K3[0], 0);
        CVMX_MF_AES_RESULT (K3[1], 1);  //K3 is equivalent to Kd
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (4);
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        CVMX_MF_AES_RESULT (K3[2], 0);
        CVMX_MF_AES_RESULT (K3[3], 1);  //K3 is equivalent to Kd
        CVMX_MT_AES_KEY (K3[0], 0);
        CVMX_MT_AES_KEY (K3[1], 1);
        CVMX_MT_AES_KEY (K3[2], 2);
        CVMX_MT_AES_KEY (K3[3], 3);
        CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
        r0 = *((uint64_t *) (in + in_len - 16));
        r1 = *((uint64_t *) (in + in_len - 16) + 1);
        CVMX_MT_AES_ENC0 (r0);
        CVMX_MT_AES_ENC1 (r1);
        r0 = *tmp++;
        r1 = *tmp++;
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
        CVMX_MF_AES_RESULT (K3[0], 0);
        CVMX_MF_AES_RESULT (K3[1], 1);
        CVMX_MT_AES_KEY (K2[0], 0);
        CVMX_MT_AES_KEY (K2[1], 1);
        CVMX_MT_AES_KEY (K2[2], 2);
        CVMX_MT_AES_KEY (K2[3], 3);
        CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (0);   // Dummy encrypt
    }
    else
    {
        uint64_t r0, r1;
        CVMX_MF_AES_RESULT (K2[0], 0);  // K2 here is equivalent to Kc
        CVMX_MF_AES_RESULT (K2[1], 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (6);
        CVMX_MF_AES_RESULT (K2[2], 0);  // K2 here is equivalent to Kc
        CVMX_MF_AES_RESULT (K2[3], 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (3);
        CVMX_MF_AES_RESULT (K3[0], 0);
        CVMX_MF_AES_RESULT (K3[1], 1);  //K3 is equivalent to Kd
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (4);
        if (zblks)
        {
            if (!tmp)
                return -2;
            CVMX_MT_GFM_XOR0 (*tmp++);
            CVMX_MT_GFM_XORMUL1 (*tmp++);
        }
        CVMX_MF_AES_RESULT (K3[2], 0);
        CVMX_MF_AES_RESULT (K3[3], 1);  //K3 is equivalent to Kd
        CVMX_MT_AES_KEY (K3[0], 0);
        CVMX_MT_AES_KEY (K3[1], 1);
        CVMX_MT_AES_KEY (K3[2], 2);
        CVMX_MT_AES_KEY (K3[3], 3);
        CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
        r0 = *((uint64_t *) (in + in_len - 16));
        r1 = *((uint64_t *) (in + in_len - 16) + 1);
        CVMX_MT_AES_ENC0 (r0);
        CVMX_MT_AES_ENC1 (r1);
        CVMX_MF_AES_RESULT (K3[0], 0);
        CVMX_MF_AES_RESULT (K3[1], 1);
        CVMX_MT_AES_KEY (K2[0], 0);
        CVMX_MT_AES_KEY (K2[1], 1);
        CVMX_MT_AES_KEY (K2[2], 2);
        CVMX_MT_AES_KEY (K2[3], 3);
        CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
        CVMX_MT_AES_ENC0 (0);
        CVMX_MT_AES_ENC1 (0);   // Dummy encrypt
    }

    if (zres)
    {
        CVMX_MT_GFM_XOR0 (zeroes[0]);
        CVMX_MT_GFM_XORMUL1 (zeroes[1]);
    }

    CVMX_MT_GFM_XOR0 (128 + zdata_len * 8);
    CVMX_MT_GFM_XORMUL1 ((in_len - 16) << 3);

    CVMX_MT_GFM_XOR0 (128 + zdata_len * 8);
    CVMX_MT_GFM_XORMUL1 (zblks * 128 + (zres ? 128 : 0) + 128);

    CVMX_MF_GFM_RESINP (K3[2], 0);
    CVMX_MF_GFM_RESINP (K3[3], 1);
    K3[0] ^= K3[2];
    K3[1] ^= K3[3];
    K3[2] = K3[0];
    K3[3] = K3[1];

    E = (uint64_t *) out;
    i = 0;

    if (!E)
        return -2;
    {
        uint64_t t0, t1;
        uint32_t lower;
        t0 = K3[0];
        t1 = K3[1];
        lower = K3[1] & 0x00000000ffffffffULL;
        while (i < 2 * (zblks + (zres ? 1 : 0)))
        {
            uint64_t r0, r1;
            CVMX_MT_AES_ENC0 (t0);
            CVMX_MT_AES_ENC1 (t1);
            t1 = (t1 & 0xffffffff00000000ULL) | ++lower;
            r0 = *((uint64_t *) in + i);
            r1 = *((uint64_t *) in + i + 1);
            CVMX_MF_AES_RESULT (E[i], 0);
            CVMX_MF_AES_RESULT (E[i + 1], 1);
            E[i] ^= r0;
            E[i + 1] ^= r1;
            i += 2;
        }
    }

    zblks = zdata_len / 16;
    zres = zdata_len % 16;
    i = zeroes[0] = 0;
    zeroes[1] = 0;
    if (zres)
        memcpy ((uint8_t *) zeroes, zdata + zblks * 16, zres);

    /* Computing F = D ^ h2 (H,Z,E) */
    CVMX_MT_GFM_POLY ((uint64_t) 0xE100);       // For GF (2^128)
    CVMX_MT_GFM_MUL (H[0], 0);
    CVMX_MT_GFM_MUL (H[1], 1);
    CVMX_MT_GFM_RESINP (0, 0);
    CVMX_MT_GFM_RESINP (0, 1);
    CVMX_MT_GFM_XOR0 (0);       /* Feeding 0^128 to the GHASH */
    CVMX_MT_GFM_XORMUL1 (0);
    while (i < (zblks * 2))
    {
        CVMX_MT_GFM_XOR0 (*((uint64_t *) zdata + i));
        CVMX_MT_GFM_XORMUL1 (*((uint64_t *) zdata + i + 1));
        i += 2;
    }

    if (zres)
    {
        CVMX_MT_GFM_XOR0 (zeroes[0]);
        CVMX_MT_GFM_XORMUL1 (zeroes[1]);
    }

    zblks = (in_len - 16) / 16;
    zres = (in_len - 16) % 16;
    zeroes[0] = zeroes[1] = 0;
    if (zres)
        memcpy ((uint8_t *) zeroes, (uint8_t *) E + (zblks * 16), zres);

    CVMX_MT_AES_KEY (K1[0], 0);
    CVMX_MT_AES_KEY (K1[1], 1);
    CVMX_MT_AES_KEY (K1[2], 2);
    CVMX_MT_AES_KEY (K1[3], 3);
    CVMX_MT_AES_KEYLENGTH (bigkey ? 3 : 1);
    CVMX_MT_AES_DEC0 (0);
    CVMX_MT_AES_DEC1 (0);       // Dummy encrypt to use away first encryption 

    tmp = (uint64_t *) E;
    i = 0;

    while (i < (zblks * 2))
    {
        uint64_t r0 = *tmp++;
        uint64_t r1 = *tmp++;
        i += 2;
        CVMX_MT_GFM_XOR0 (r0);
        CVMX_MT_GFM_XORMUL1 (r1);
    }

    if (zres)
    {
        CVMX_MT_GFM_XOR0 (zeroes[0]);
        CVMX_MT_GFM_XORMUL1 (zeroes[1]);
    }

    CVMX_MT_GFM_XOR0 (0);
    CVMX_MT_GFM_XORMUL1 (0);

    CVMX_MT_GFM_XOR0 (128 + zdata_len * 8);
    CVMX_MT_GFM_XORMUL1 (zblks * 128 + (zres ? 128 : 0) + 128);

    CVMX_MF_AES_RESULT (K3[0], 0);
    CVMX_MF_AES_RESULT (K3[1], 1);

    CVMX_MF_GFM_RESINP (H[0], 0);
    CVMX_MF_GFM_RESINP (H[1], 1);

    H[0] ^= K3[2];
    H[1] ^= K3[3];

    CVMX_MT_AES_DEC0 (H[0]);
    CVMX_MT_AES_DEC1 (H[1]);
    CVMX_MF_AES_RESULT (K3[0], 0);
    CVMX_MF_AES_RESULT (K3[1], 1);

    memcpy ((uint8_t *) E + in_len - 16, (uint8_t *) K3, 16);
#ifdef AES_XCB_TEST_CPU_CYCLES
    end_cycle = cvmx_get_cycle ();
    printf ("AES_Dec cycles %ld\n", end_cycle - start_cycle);
#endif
    return 0;
}
