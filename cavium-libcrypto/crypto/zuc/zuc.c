#include <stdio.h>
#include <stdlib.h>

#include "openssl/crypto.h"
#include "openssl/zuc.h"
#include "cvmx.h"

uint64_t array[25]; /* save the state */

uint32_t EK_d[16] =
{
    0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
    0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC
};

void ZUC_finish(void)
{
    CVMX_MF_SHA3_DAT(array[ 0],   0);
    CVMX_MF_SHA3_DAT(array[ 1],   1);
    CVMX_MF_SHA3_DAT(array[ 2],   2);
    CVMX_MF_SHA3_DAT(array[ 3],   3);
    CVMX_MF_SHA3_DAT(array[ 4],   4);
    CVMX_MF_SHA3_DAT(array[ 5],   5);
    CVMX_MF_SHA3_DAT(array[ 6],   6);
    CVMX_MF_SHA3_DAT(array[ 7],   7);
    CVMX_MF_SHA3_DAT(array[ 8],   8);
    CVMX_MF_SHA3_DAT(array[ 9],   9);
    CVMX_MF_SHA3_DAT(array[10],  10);
    CVMX_MF_SHA3_DAT(array[11],  11);
    CVMX_MF_SHA3_DAT(array[12],  12);
    CVMX_MF_SHA3_DAT(array[13],  13);
    CVMX_MF_SHA3_DAT(array[14],  14);
    CVMX_MF_SHA3_DAT(array[15],  15);
    CVMX_MF_SHA3_DAT(array[16],  16);
    CVMX_MF_SHA3_DAT(array[17],  17);
    CVMX_MF_SHA3_DAT(array[18],  18);
    CVMX_MF_SHA3_DAT(array[19],  19);
    CVMX_MF_SHA3_DAT(array[20],  20);
    CVMX_MF_SHA3_DAT(array[21],  21);
    CVMX_MF_SHA3_DAT(array[22],  22);
    CVMX_MF_SHA3_DAT(array[23],  23);
    CVMX_MF_SHA3_DAT(array[24],  24);
}

void ZUC_init(void)
{
    CVMX_MT_SHA3_DAT(array[ 0],   0);
    CVMX_MT_SHA3_DAT(array[ 1],   1);
    CVMX_MT_SHA3_DAT(array[ 2],   2);
    CVMX_MT_SHA3_DAT(array[ 3],   3);
    CVMX_MT_SHA3_DAT(array[ 4],   4);
    CVMX_MT_SHA3_DAT(array[ 5],   5);
    CVMX_MT_SHA3_DAT(array[ 6],   6);
    CVMX_MT_SHA3_DAT(array[ 7],   7);
    CVMX_MT_SHA3_DAT(array[ 8],   8);
    CVMX_MT_SHA3_DAT(array[ 9],   9);
    CVMX_MT_SHA3_DAT(array[10],  10);
    CVMX_MT_SHA3_DAT(array[11],  11);
    CVMX_MT_SHA3_DAT(array[12],  12);
    CVMX_MT_SHA3_DAT(array[13],  13);
    CVMX_MT_SHA3_DAT(array[14],  14);
    CVMX_MT_SHA3_DAT(array[15],  15);
    CVMX_MT_SHA3_DAT(array[16],  16);
    CVMX_MT_SHA3_DAT(array[17],  17);
    CVMX_MT_SHA3_DAT(array[18],  18);
    CVMX_MT_SHA3_DAT(array[19],  19);
    CVMX_MT_SHA3_DAT(array[20],  20);
    CVMX_MT_SHA3_DAT(array[21],  21);
    CVMX_MT_SHA3_DAT(array[22],  22);
    CVMX_MT_SHA3_DAT(array[23],  23);
    CVMX_MT_SHA3_DAT(array[24],  24);
}

static inline void
zuc_initialize(unsigned char *key, unsigned char *iv)
{
    uint64_t LFSR[8];
    int i;

    if(!key || !iv) return;

    for(i = 0; i < 16; i += 2)
        LFSR[i / 2] = MAKELFSR(key[i], EK_d[i], iv[i], key[i + 1], EK_d[i + 1], iv[i + 1]);

    CVMX_MT_ZUC_LFSR(LFSR[0], 0);
    CVMX_MT_ZUC_LFSR(LFSR[1], 1);
    CVMX_MT_ZUC_LFSR(LFSR[2], 2);
    CVMX_MT_ZUC_LFSR(LFSR[3], 3);
    CVMX_MT_ZUC_LFSR(LFSR[4], 4);
    CVMX_MT_ZUC_LFSR(LFSR[5], 5);
    CVMX_MT_ZUC_LFSR(LFSR[6], 6);
    CVMX_MT_ZUC_START(LFSR[7]);
}

static inline void
zuc_generatekeystream(uint64_t *ks, unsigned int n)
{
    uint64_t result;
    uint64_t *key_stream = (uint64_t *)ks;

    for(; n > 0; n--)
    {
        CVMX_MF_ZUC_RESULT(result);
        CVMX_MT_ZUC_MORE_NO_T;

        *key_stream = result;
        key_stream++;
    }
}

int ZUC(unsigned char *key, unsigned char *iv, unsigned int *ks, int len)
{
    if(!OCTEON_IS_OCTEON3())
    {
        printf("ZUC Algorithm is supported only on CN7XXX chips.\n");
        return 1;
    }

    memset(array, 0xff, sizeof(array));

    ZUC_init();

    if(!key || !iv || !ks)
        return -1;

    zuc_initialize(key, iv);

    len = (len + 63) >> 6;

    zuc_generatekeystream((uint64_t *)ks, (unsigned int)len);

    ZUC_finish();

    return 0;
}

/**
 * ZUC_encrypt
 * len   the length of the message 'in' in bits.
 */
int ZUC_encrypt(const unsigned char *in, unsigned int len, unsigned char *out,
    unsigned char *key, unsigned int count, unsigned int bearer,
    unsigned int direction)
{
    unsigned char iv[ZUC_IV_LEN];
    int n, i;
    uint64_t *inp, *outp;

    inp  = (uint64_t *)in;
    outp = (uint64_t *)out;

    if(!OCTEON_IS_OCTEON3())
    {
        printf("ZUC Algorithm is supported only on CN7XXX chips.\n");
        return 1;
    }
#if 0
    len*=8;
#endif

    iv[ 0] = (unsigned char)(count >> 24) & 0xff;
    iv[ 1] = (unsigned char)(count >> 16) & 0xff;
    iv[ 2] = (unsigned char)(count >>  8) & 0xff;
    iv[ 3] = (unsigned char)(count >>  0) & 0xff;

    iv[ 4] = (unsigned char)((bearer << 3) | ((direction & 1) << 2)) & 0xfc;
    iv[ 5] = 0;
    iv[ 6] = 0;
    iv[ 7] = 0;

    for(i = 0; i < 8; i++)
        iv[i + 8] = iv[i];

    zuc_initialize(key, iv);

    n = (len + 63) >> 6;

    zuc_generatekeystream(outp, n);

    for(i = 0; i < n; i++)
        outp[i] ^= inp[i];

    outp[n - 1] &= ~(0xffffffffffffffffull >> (len & 0x3f));

    return 0;
}

/**
 * ZUC_mac
 * len   the length of the message 'in' in bits.
 */
int ZUC_mac(const unsigned char *in, unsigned int len, unsigned char *mac,
    unsigned char *ikey, unsigned int count, unsigned int bearer,
    unsigned int direction)
{
    unsigned char iv[ZUC_IV_LEN];
    int i, extrabits;
    int lastz_shift;
    uint64_t lastm = 0, lastz = 0;
    uint64_t T64 = 0;
    unsigned int words = 0;
    uint32_t *mac32 = (uint32_t *)mac;
    uint64_t *inp64 = (uint64_t *)in;

    if(!OCTEON_IS_OCTEON3())
    {
        printf("ZUC Algorithm is supported only on CN7XXX chips.\n");
        return 1;
    }

#ifdef ZUC_DEBUG
    {
        int z;
        printf("%s:\n",__func__);
        printf("count 0x%08lx bearer 0x%08lx dir 0x%08lx len %d\n",
            count,bearer,direction,len);
        printf("IKEY:\n");
        for(z = 0; z < 16; z++)
            printf("%02x%c", ikey[z], (z + 1) % 16 ? ' ' : '\n');
        printf("\n");
        printf("IN:\n");
        for(z = 0; z < len / 8; z++)
            printf("%02x%c", in[z], (z + 1) % 16 ? ' ' : '\n');
        printf("\n");
    }
#endif

    iv[ 0] = (unsigned char)((count >> 24) & 0xff);
    iv[ 1] = (unsigned char)((count >> 16) & 0xff);
    iv[ 2] = (unsigned char)((count >>  8) & 0xff);
    iv[ 3] = (unsigned char)((count >>  0) & 0xff);

    iv[ 4] = (unsigned char)((bearer << 3) & 0xff);
    iv[ 5] = 0;
    iv[ 6] = 0;
    iv[ 7] = 0;

    iv[ 8] = (unsigned char)(iv[0] ^ ((direction & 1) << 7));
    iv[ 9] = iv[1];
    iv[10] = iv[2];
    iv[11] = iv[3];

    iv[12] = iv[4];
    iv[13] = iv[5];
    iv[14] = iv[6] ^ ((direction & 1) << 7);
    iv[15] = iv[7];

    zuc_initialize(ikey, iv);

    words = (len - 1) >> 6;

    for(i = 0; i < (int)words; i++)
        CVMX_MT_ZUC_MORE(inp64[i]);

    extrabits = (int)len & 0x3f;

    lastm = inp64[words];

    if(extrabits)
    {
        int next_bits = 63 - extrabits;
        uint64_t mask = 0xffffffffffffffffull << next_bits;
        uint64_t nbit = 0x1ull                << next_bits;

        CVMX_MT_ZUC_MORE((lastm & mask) | nbit);

        lastz_shift = ((len - 1) & 0x20) ^ 0x20;

        CVMX_MF_ZUC_RESULT(lastz);
        CVMX_MF_ZUC_TRESULT(T64);
    }
    else
    {
        CVMX_MT_ZUC_MORE(lastm);

        lastz_shift = 0;

        CVMX_MF_ZUC_RESULT(lastz);
        CVMX_MF_ZUC_TRESULT(T64);

        T64 ^= (lastz >> 32);
    }

    T64 ^= (lastz >> lastz_shift);

    *mac32 = (uint32_t)T64;

    return 0;
}
