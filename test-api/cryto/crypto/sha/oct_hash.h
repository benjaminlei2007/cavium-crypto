/***********************license start***************
 * Copyright (c) 2003-2010  Cavium Networks (support@cavium.com). All rights
 * reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.

 *   * Neither the name of Cavium Networks nor the names of
 *     its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written
 *     permission.

 * This Software, including technical data, may be subject to U.S. export  control
 * laws, including the U.S. Export Administration Act and its  associated
 * regulations, and may be subject to export or import  regulations in other
 * countries.

 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
 * AND WITH ALL FAULTS AND CAVIUM  NETWORKS MAKES NO PROMISES, REPRESENTATIONS OR
 * WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT TO
 * THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY REPRESENTATION OR
 * DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM
 * SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,
 * MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF
 * VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
 * CORRESPONDENCE TO DESCRIPTION. THE ENTIRE  RISK ARISING OUT OF USE OR
 * PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
 ***********************license end**************************************/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "cvmx.h"

/* MD5 defines */
#define MD5_BLOCK_SIZE          64
#define MD5_DIGEST_LENGTH       16

#define MD5_H1_MAGIC            (0x0123456789abcdefull)
#define MD5_H2_MAGIC            (0xfedcba9876543210ull)

/* SHA1 defines */
#define SHA_BLOCK_SIZE          64
#define SHA_DIGEST_LENGTH       20

#define SHA1_H1_MAGIC           (0x67452301EFCDAB89ull)
#define SHA1_H2_MAGIC           (0x98BADCFE10325476ull)
#define SHA1_H3_MAGIC           (0xC3D2E1F000000000ull)

/* SHA224 defines */
#define SHA224_H1_MAGIC         (0xc1059ed8367cd507ull)
#define SHA224_H2_MAGIC         (0x3070dd17f70e5939ull)
#define SHA224_H3_MAGIC         (0xffc00b3168581511ull)
#define SHA224_H4_MAGIC         (0x64f98fa7befa4fa4ull)
#define SHA224_BLOCK_SIZE       64
#define SHA224_DIGEST_LENGTH    28

/* SHA256 defines */
#define SHA256_H1_MAGIC         (0x6a09e667bb67ae85ull)
#define SHA256_H2_MAGIC         (0x3c6ef372a54ff53aull)
#define SHA256_H3_MAGIC         (0x510e527f9b05688cull)
#define SHA256_H4_MAGIC         (0x1f83d9ab5be0cd19ull)
#define SHA256_BLOCK_SIZE       64
#define SHA256_DIGEST_LENGTH    32

/* SHA384 defines */
#define SHA384_H1_MAGIC         (0xcbbb9d5dc1059ed8ull)
#define SHA384_H2_MAGIC         (0x629a292a367cd507ull)
#define SHA384_H3_MAGIC         (0x9159015a3070dd17ull)
#define SHA384_H4_MAGIC         (0x152fecd8f70e5939ull)
#define SHA384_H5_MAGIC         (0x67332667ffc00b31ull)
#define SHA384_H6_MAGIC         (0x8eb44a8768581511ull)
#define SHA384_H7_MAGIC         (0xdb0c2e0d64f98fa7ull)
#define SHA384_H8_MAGIC         (0x47b5481dbefa4fa4ull)
#define SHA384_DIGEST_LENGTH    48
#define SHA384_BLOCK_SIZE       128
#define CVMX_MT_HSH_STARTSHA384 CVMX_MT_HSH_STARTSHA512

/* SHA512 defines */
#define SHA512_H1_MAGIC         (0x6a09e667f3bcc908ull)
#define SHA512_H2_MAGIC         (0xbb67ae8584caa73bull)
#define SHA512_H3_MAGIC         (0x3c6ef372fe94f82bull)
#define SHA512_H4_MAGIC         (0xa54ff53a5f1d36f1ull)
#define SHA512_H5_MAGIC         (0x510e527fade682d1ull)
#define SHA512_H6_MAGIC         (0x9b05688c2b3e6c1full)
#define SHA512_H7_MAGIC         (0x1f83d9abfb41bd6bull)
#define SHA512_H8_MAGIC         (0x5be0cd19137e2179ull)
#define SHA512_DIGEST_LENGTH    64
#define SHA512_BLOCK_SIZE       128

#define UINT64_MUL(abhi, ablo, a, b)                                    \
{                                                                       \
    asm volatile("dmultu %[rs],%[rt]" :: [rs] "d" (a), [rt] "d" (b) );  \
    asm volatile("mfhi %[rd] " : [rd] "=d" (abhi) : );                  \
    asm volatile("mflo %[rd] " : [rd] "=d" (ablo) : );                  \
}     


#define UINT64_SIZE             sizeof(uint64_t)
#define UINT8_SIZE              sizeof(uint8_t)

typedef enum {
        OCT_SUCCESS = 0,
        OCT_FAILURE,
        OCT_ERR_INPUT_DATA_LEN,
        OCT_ERR_NULL_KEY,
        OCT_ERR_ILLEGAL_ARGS
} oct_hash_error_t;

int
octeon_sha1(const uint64_t *data, uint64_t len, uint64_t *hash);
int
octeon_sha224(const uint64_t *data, uint64_t len, uint64_t *hash);
int
octeon_sha256(const uint64_t *data, uint64_t len, uint64_t *hash);
int
octeon_sha384(const uint64_t *data, uint64_t len, uint64_t *hash);
int
octeon_sha512(const uint64_t *data, uint64_t len, uint64_t *hash);


int
octeon_md5(const uint64_t *data, uint64_t len, uint64_t *hash);
int
octeon_hmac_md5(const uint64_t *data, uint64_t len, uint64_t *key, uint64_t key_len, uint64_t *hash);
int
octeon_hmac_sha1(const uint64_t *data, uint64_t len, uint64_t *key, uint64_t key_len, uint64_t *hash);
int
octeon_hmac_sha256(const uint64_t *data, uint64_t len, uint64_t *key,
                uint64_t key_len, uint64_t *hash);
int
octeon_hmac_sha384(const uint64_t *data, uint64_t len, uint64_t *key,
                uint64_t key_len, uint64_t *hash);
int
octeon_hmac_sha512(const uint64_t *data, uint64_t len, uint64_t *key,
                   uint64_t key_len, uint64_t *hash);

#define GET_56BYTES_DATA(dptr, offset)                          \
{                                                               \
        CVMX_MT_HSH_DAT(dptr[offset + 0], 0);                   \
        CVMX_MT_HSH_DAT(dptr[offset + 1], 1);                   \
        CVMX_MT_HSH_DAT(dptr[offset + 2], 2);                   \
        CVMX_MT_HSH_DAT(dptr[offset + 3], 3);                   \
        CVMX_MT_HSH_DAT(dptr[offset + 4], 4);                   \
        CVMX_MT_HSH_DAT(dptr[offset + 5], 5);                   \
        CVMX_MT_HSH_DAT(dptr[offset + 6], 6);                   \
}

#define START_HASH(name, data)          CVMX_MT_HSH_START##name(data)


#define MD5_HASH_128BYTES(dptr, dlen)                           \
{                                                               \
        GET_56BYTES_DATA(dptr, 0);                              \
        START_HASH(MD5, dptr[7]);                               \
        GET_56BYTES_DATA(dptr, 8);                              \
        START_HASH(MD5, dptr[15]);                              \
        dptr += 16; dlen -= 128;                                \
}

#define MD5_HASH_64BYTES(dptr, dlen)                            \
{                                                               \
        GET_56BYTES_DATA(dptr, 0);                              \
        START_HASH(MD5, dptr[7]);                               \
        dptr += 8; dlen -= 64;                                  \
}

#define SHA_HASH_128BYTES(dptr, dlen)                           \
{                                                               \
        GET_56BYTES_DATA(dptr, 0);                              \
        START_HASH(SHA, dptr[7]);                               \
        GET_56BYTES_DATA(dptr, 8);                              \
        START_HASH(SHA, dptr[15]);                              \
        dptr += 16; dlen -= 128;                                \
}

#define SHA_HASH_64BYTES(dptr, dlen)                            \
{                                                               \
        GET_56BYTES_DATA(dptr, 0);                              \
        START_HASH(SHA, dptr[7]);                               \
        dptr += 8; dlen -= 64;                                  \
}

#define SHA256_HASH_128BYTES(dptr, dlen)                        \
{                                                               \
        GET_56BYTES_DATA(dptr, 0);                              \
        START_HASH(SHA256, dptr[7]);                            \
        GET_56BYTES_DATA(dptr, 8);                              \
        START_HASH(SHA256, dptr[15]);                           \
        dptr += 16; dlen -= 128;                                \
}

#define SHA256_HASH_64BYTES(dptr, dlen)                         \
{                                                               \
        GET_56BYTES_DATA(dptr, 0);                              \
        START_HASH(SHA256, dptr[7]);                            \
        dptr += 8; dlen -= 64;                                  \
}

#define GET_112BYTES_DATA_SHA2(dptr)                            \
{                                                               \
        CVMX_MT_HSH_DATW(dptr[0], 0);                           \
        CVMX_MT_HSH_DATW(dptr[1], 1);                           \
        CVMX_MT_HSH_DATW(dptr[2], 2);                           \
        CVMX_MT_HSH_DATW(dptr[3], 3);                           \
        CVMX_MT_HSH_DATW(dptr[4], 4);                           \
        CVMX_MT_HSH_DATW(dptr[5], 5);                           \
        CVMX_MT_HSH_DATW(dptr[6], 6);                           \
        CVMX_MT_HSH_DATW(dptr[7], 7);                           \
        CVMX_MT_HSH_DATW(dptr[8], 8);                           \
        CVMX_MT_HSH_DATW(dptr[9], 9);                           \
        CVMX_MT_HSH_DATW(dptr[10], 10);                         \
        CVMX_MT_HSH_DATW(dptr[11], 11);                         \
        CVMX_MT_HSH_DATW(dptr[12], 12);                         \
        CVMX_MT_HSH_DATW(dptr[13], 13);                         \
        CVMX_MT_HSH_DATW(dptr[14], 14);                         \
}

#define SHA384_HASH_128BYTES(dptr, dlen)                        \
{                                                               \
        GET_112BYTES_DATA_SHA2(dptr);                           \
        START_HASH(SHA384, dptr[15]);                           \
        dptr += 16; dlen -= 128;                                \
}

#define SHA512_HASH_128BYTES(dptr, dlen)                        \
{                                                               \
        GET_112BYTES_DATA_SHA2(dptr);                           \
        START_HASH(SHA512, dptr[15]);                           \
        dptr += 16; dlen -= 128;                                \
}
