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

#include "oct_hash.h"


#ifndef OCTEON_NO_DIGEST

static inline uint64_t swap64(uint64_t v)
{
        return ((((v >> 56) & 0xfful) <<  0) | 
                (((v >> 48) & 0xfful) <<  8) |
                (((v >> 40) & 0xfful) << 16) |
                (((v >> 32) & 0xfful) << 24) |
                (((v >> 24) & 0xfful) << 32) |
                (((v >> 16) & 0xfful) << 40) |
                (((v >>  8) & 0xfful) << 48) |
                (((v >>  0) & 0xfful) << 56));
}

int
octeon_sha1(const uint64_t *data, uint64_t len, uint64_t *hash)
{
        int totlen = len;
        uint64_t bits = len * 8;
        const uint64_t *ptr = (uint64_t *)data;
        uint8_t chunk[SHA_BLOCK_SIZE];
        uint64_t tmp;

        CVMX_MT_HSH_IV(SHA1_H1_MAGIC, 0);
        CVMX_MT_HSH_IV(SHA1_H2_MAGIC, 1);
        CVMX_MT_HSH_IV(SHA1_H3_MAGIC, 2);

        CVMX_PREFETCH0(ptr);

        while(totlen >= 128) {
                CVMX_PREFETCH128(ptr);
                SHA_HASH_128BYTES(ptr, totlen);
        }

        if(totlen >= 64) SHA_HASH_64BYTES(ptr, totlen);
        if(totlen >= 64) SHA_HASH_64BYTES(ptr, totlen);

        if(totlen > 0)
                memcpy(chunk, ptr, totlen);

        memset(chunk + totlen + 1, 0, SHA_BLOCK_SIZE - totlen - 1);

        chunk[totlen] = 0x80;

        ptr = (const uint64_t *)chunk;
        CVMX_MT_HSH_DAT(*ptr++, 0);
        CVMX_MT_HSH_DAT(*ptr++, 1);
        CVMX_MT_HSH_DAT(*ptr++, 2);
        CVMX_MT_HSH_DAT(*ptr++, 3);
        CVMX_MT_HSH_DAT(*ptr++, 4);
        CVMX_MT_HSH_DAT(*ptr++, 5);
        CVMX_MT_HSH_DAT(*ptr++, 6);

        if(totlen < (SHA_BLOCK_SIZE - 8))
                CVMX_MT_HSH_STARTSHA(bits);
        else {
                CVMX_MT_HSH_STARTSHA(*ptr);
                CVMX_MT_HSH_DATZ(0);
                CVMX_MT_HSH_DATZ(1);
                CVMX_MT_HSH_DATZ(2);
                CVMX_MT_HSH_DATZ(3);
                CVMX_MT_HSH_DATZ(4);
                CVMX_MT_HSH_DATZ(5);
                CVMX_MT_HSH_DATZ(6);
                CVMX_MT_HSH_STARTSHA(bits);
        }
                
        CVMX_MF_HSH_IV(((uint64_t *)hash)[0], 0);
        CVMX_MF_HSH_IV(((uint64_t *)hash)[1], 1);
        CVMX_MF_HSH_IV(tmp, 2);
        ((uint32_t *)hash)[4] = tmp >> 32;

        return OCT_SUCCESS;
}

int
octeon_sha224(const uint64_t *data, uint64_t len, uint64_t *hash)
{
        int totlen = len;
        uint64_t bits = len * 8;
        const uint64_t *ptr;
        uint8_t chunk[SHA224_BLOCK_SIZE];


        CVMX_MT_HSH_IV(SHA224_H1_MAGIC, 0);
        CVMX_MT_HSH_IV(SHA224_H2_MAGIC, 1);
        CVMX_MT_HSH_IV(SHA224_H3_MAGIC, 2);
        CVMX_MT_HSH_IV(SHA224_H4_MAGIC, 3);

        ptr = (const uint64_t *)data;

        CVMX_PREFETCH0(ptr);

        while(totlen >= 128) {
                CVMX_PREFETCH128(ptr);
                SHA256_HASH_128BYTES(ptr, totlen);
        }

        if(totlen >= 64) SHA256_HASH_64BYTES(ptr, totlen);
        if(totlen >= 64) SHA256_HASH_64BYTES(ptr, totlen);
        
        if(totlen > 0)
                memcpy(chunk, ptr, totlen);

        memset(chunk + totlen + 1, 0, SHA224_BLOCK_SIZE - totlen - 1);
        chunk[totlen] = 0x80;

        ptr = (const uint64_t *)chunk;
        CVMX_MT_HSH_DAT(*ptr++, 0);
        CVMX_MT_HSH_DAT(*ptr++, 1);
        CVMX_MT_HSH_DAT(*ptr++, 2);
        CVMX_MT_HSH_DAT(*ptr++, 3);
        CVMX_MT_HSH_DAT(*ptr++, 4);
        CVMX_MT_HSH_DAT(*ptr++, 5);
        CVMX_MT_HSH_DAT(*ptr++, 6);

        if(totlen < (SHA224_BLOCK_SIZE - 8))
                CVMX_MT_HSH_STARTSHA256(bits);
        else {
                CVMX_MT_HSH_STARTSHA256(*ptr);
                CVMX_MT_HSH_DATZ(0);
                CVMX_MT_HSH_DATZ(1);
                CVMX_MT_HSH_DATZ(2);
                CVMX_MT_HSH_DATZ(3);
                CVMX_MT_HSH_DATZ(4);
                CVMX_MT_HSH_DATZ(5);
                CVMX_MT_HSH_DATZ(6);
                CVMX_MT_HSH_STARTSHA256(bits);
        }

        CVMX_MF_HSH_IV(hash[0], 0);
        CVMX_MF_HSH_IV(hash[1], 1);
        CVMX_MF_HSH_IV(hash[2], 2);
        CVMX_MF_HSH_IV(hash[3], 3);

        return OCT_SUCCESS;
}

int
octeon_sha256(const uint64_t *data, uint64_t len, uint64_t *hash)
{
        int totlen = len;
        uint64_t bits = len * 8;
        const uint64_t *ptr;
        uint8_t chunk[SHA256_BLOCK_SIZE];


        CVMX_MT_HSH_IV(SHA256_H1_MAGIC, 0);
        CVMX_MT_HSH_IV(SHA256_H2_MAGIC, 1);
        CVMX_MT_HSH_IV(SHA256_H3_MAGIC, 2);
        CVMX_MT_HSH_IV(SHA256_H4_MAGIC, 3);

        ptr = (const uint64_t *)data;

        CVMX_PREFETCH0(ptr);

        while(totlen >= 128) {
                CVMX_PREFETCH128(ptr);
                SHA256_HASH_128BYTES(ptr, totlen);
        }

        if(totlen >= 64) SHA256_HASH_64BYTES(ptr, totlen);
        if(totlen >= 64) SHA256_HASH_64BYTES(ptr, totlen);
        
        if(totlen > 0)
                memcpy(chunk, ptr, totlen);

        memset(chunk + totlen + 1, 0, SHA256_BLOCK_SIZE - totlen - 1);
        chunk[totlen] = 0x80;

        ptr = (const uint64_t *)chunk;
        CVMX_MT_HSH_DAT(*ptr++, 0);
        CVMX_MT_HSH_DAT(*ptr++, 1);
        CVMX_MT_HSH_DAT(*ptr++, 2);
        CVMX_MT_HSH_DAT(*ptr++, 3);
        CVMX_MT_HSH_DAT(*ptr++, 4);
        CVMX_MT_HSH_DAT(*ptr++, 5);
        CVMX_MT_HSH_DAT(*ptr++, 6);

        if(totlen < (SHA256_BLOCK_SIZE - 8))
                CVMX_MT_HSH_STARTSHA256(bits);
        else {
                CVMX_MT_HSH_STARTSHA256(*ptr);
                CVMX_MT_HSH_DATZ(0);
                CVMX_MT_HSH_DATZ(1);
                CVMX_MT_HSH_DATZ(2);
                CVMX_MT_HSH_DATZ(3);
                CVMX_MT_HSH_DATZ(4);
                CVMX_MT_HSH_DATZ(5);
                CVMX_MT_HSH_DATZ(6);
                CVMX_MT_HSH_STARTSHA256(bits);
        }

        CVMX_MF_HSH_IV(hash[0], 0);
        CVMX_MF_HSH_IV(hash[1], 1);
        CVMX_MF_HSH_IV(hash[2], 2);
        CVMX_MF_HSH_IV(hash[3], 3);

        return OCT_SUCCESS;
}


int
octeon_sha384(const uint64_t *data, uint64_t len, uint64_t *hash)
{
        uint64_t totlen = len;
        const uint64_t *ptr;
        uint8_t chunk[SHA384_BLOCK_SIZE];


        CVMX_MT_HSH_IVW(SHA384_H1_MAGIC, 0);
        CVMX_MT_HSH_IVW(SHA384_H2_MAGIC, 1);
        CVMX_MT_HSH_IVW(SHA384_H3_MAGIC, 2);
        CVMX_MT_HSH_IVW(SHA384_H4_MAGIC, 3);
        CVMX_MT_HSH_IVW(SHA384_H5_MAGIC, 4);
        CVMX_MT_HSH_IVW(SHA384_H6_MAGIC, 5);
        CVMX_MT_HSH_IVW(SHA384_H7_MAGIC, 6);
        CVMX_MT_HSH_IVW(SHA384_H8_MAGIC, 7);

        ptr = (const uint64_t *)data;

        CVMX_PREFETCH0(ptr);
        
        while(totlen >= 128) {
                CVMX_PREFETCH128(ptr);
                SHA384_HASH_128BYTES(ptr, totlen);
        }

        if(totlen > 0)
                memcpy(chunk, ptr, totlen);

        memset(chunk + totlen + 1, 0, SHA384_BLOCK_SIZE - totlen - 1);
        chunk[totlen] = 0x80;

        ptr = (const uint64_t *)chunk;
        CVMX_MT_HSH_DATW(*ptr++, 0);
        CVMX_MT_HSH_DATW(*ptr++, 1);
        CVMX_MT_HSH_DATW(*ptr++, 2);
        CVMX_MT_HSH_DATW(*ptr++, 3);
        CVMX_MT_HSH_DATW(*ptr++, 4);
        CVMX_MT_HSH_DATW(*ptr++, 5);
        CVMX_MT_HSH_DATW(*ptr++, 6);
        CVMX_MT_HSH_DATW(*ptr++, 7);
        CVMX_MT_HSH_DATW(*ptr++, 8);
        CVMX_MT_HSH_DATW(*ptr++, 9);
        CVMX_MT_HSH_DATW(*ptr++, 10);
        CVMX_MT_HSH_DATW(*ptr++, 11);
        CVMX_MT_HSH_DATW(*ptr++, 12);
        CVMX_MT_HSH_DATW(*ptr++, 13);

        if(totlen < (SHA384_BLOCK_SIZE - 16)) {
                uint64_t ab[2];
                UINT64_MUL(ab[0], ab[1], len, 8);
                CVMX_MT_HSH_DATW(ab[0], 14);
                CVMX_MT_HSH_STARTSHA384(ab[1]);
        } else {
                uint64_t ab[2];
                CVMX_MT_HSH_DATW(*ptr++, 14);
                CVMX_MT_HSH_STARTSHA384(*ptr);
                CVMX_MT_HSH_DATWZ(0);
                CVMX_MT_HSH_DATWZ(1);
                CVMX_MT_HSH_DATWZ(2);
                CVMX_MT_HSH_DATWZ(3);
                CVMX_MT_HSH_DATWZ(4);
                CVMX_MT_HSH_DATWZ(5);
                CVMX_MT_HSH_DATWZ(6);
                CVMX_MT_HSH_DATWZ(7);
                CVMX_MT_HSH_DATWZ(8);
                CVMX_MT_HSH_DATWZ(9);
                CVMX_MT_HSH_DATWZ(10);
                CVMX_MT_HSH_DATWZ(11);
                CVMX_MT_HSH_DATWZ(12);
                CVMX_MT_HSH_DATWZ(13);

                UINT64_MUL(ab[0], ab[1], len, 8);
                CVMX_MT_HSH_DATW(ab[0], 14);
                CVMX_MT_HSH_STARTSHA384(ab[1]);
        }

        CVMX_MF_HSH_IVW(hash[0], 0);
        CVMX_MF_HSH_IVW(hash[1], 1);
        CVMX_MF_HSH_IVW(hash[2], 2);
        CVMX_MF_HSH_IVW(hash[3], 3);
        CVMX_MF_HSH_IVW(hash[4], 4);
        CVMX_MF_HSH_IVW(hash[5], 5);

        return OCT_SUCCESS;
}

int
octeon_sha512(const uint64_t *data, uint64_t len, uint64_t *hash)
{
        int totlen = len;
        const uint64_t *ptr;
        uint8_t chunk[SHA512_BLOCK_SIZE];


        CVMX_MT_HSH_IVW(SHA512_H1_MAGIC, 0);
        CVMX_MT_HSH_IVW(SHA512_H2_MAGIC, 1);
        CVMX_MT_HSH_IVW(SHA512_H3_MAGIC, 2);
        CVMX_MT_HSH_IVW(SHA512_H4_MAGIC, 3);
        CVMX_MT_HSH_IVW(SHA512_H5_MAGIC, 4);
        CVMX_MT_HSH_IVW(SHA512_H6_MAGIC, 5);
        CVMX_MT_HSH_IVW(SHA512_H7_MAGIC, 6);
        CVMX_MT_HSH_IVW(SHA512_H8_MAGIC, 7);

        ptr = (const uint64_t *)data;

        CVMX_PREFETCH0(ptr);

        while(totlen >= 128) {
                CVMX_PREFETCH128(ptr);
                SHA512_HASH_128BYTES(ptr, totlen);
        }
        
        if(totlen > 0)
                memcpy(chunk, ptr, totlen);

        memset(chunk + totlen + 1, 0, SHA512_BLOCK_SIZE - totlen - 1);
        chunk[totlen] = 0x80;

        ptr = (const uint64_t *)chunk;
        CVMX_MT_HSH_DATW(*ptr++, 0);
        CVMX_MT_HSH_DATW(*ptr++, 1);
        CVMX_MT_HSH_DATW(*ptr++, 2);
        CVMX_MT_HSH_DATW(*ptr++, 3);
        CVMX_MT_HSH_DATW(*ptr++, 4);
        CVMX_MT_HSH_DATW(*ptr++, 5);
        CVMX_MT_HSH_DATW(*ptr++, 6);
        CVMX_MT_HSH_DATW(*ptr++, 7);
        CVMX_MT_HSH_DATW(*ptr++, 8);
        CVMX_MT_HSH_DATW(*ptr++, 9);
        CVMX_MT_HSH_DATW(*ptr++, 10);
        CVMX_MT_HSH_DATW(*ptr++, 11);
        CVMX_MT_HSH_DATW(*ptr++, 12);
        CVMX_MT_HSH_DATW(*ptr++, 13);

        if(totlen < (SHA512_BLOCK_SIZE - 16)) {
                uint64_t ab[2];
                UINT64_MUL(ab[0], ab[1], len, 8);
                CVMX_MT_HSH_DATW(ab[0], 14);
                CVMX_MT_HSH_STARTSHA384(ab[1]);
        } else {
                
                uint64_t ab[2];
		CVMX_MT_HSH_DATW(*ptr++, 14);
                CVMX_MT_HSH_STARTSHA512(*ptr);
                CVMX_MT_HSH_DATWZ(0);
                CVMX_MT_HSH_DATWZ(1);
                CVMX_MT_HSH_DATWZ(2);
                CVMX_MT_HSH_DATWZ(3);
                CVMX_MT_HSH_DATWZ(4);
                CVMX_MT_HSH_DATWZ(5);
                CVMX_MT_HSH_DATWZ(6);
                CVMX_MT_HSH_DATWZ(7);
                CVMX_MT_HSH_DATWZ(8);
                CVMX_MT_HSH_DATWZ(9);
                CVMX_MT_HSH_DATWZ(10);
                CVMX_MT_HSH_DATWZ(11);
                CVMX_MT_HSH_DATWZ(12);
                CVMX_MT_HSH_DATWZ(13);

                UINT64_MUL(ab[0], ab[1], len, 8);
                CVMX_MT_HSH_DATW(ab[0], 14);
                CVMX_MT_HSH_STARTSHA512(ab[1]);
        }

        CVMX_MF_HSH_IVW(hash[0], 0);
        CVMX_MF_HSH_IVW(hash[1], 1);
        CVMX_MF_HSH_IVW(hash[2], 2);
        CVMX_MF_HSH_IVW(hash[3], 3);
        CVMX_MF_HSH_IVW(hash[4], 4);
        CVMX_MF_HSH_IVW(hash[5], 5);
        CVMX_MF_HSH_IVW(hash[6], 6);
        CVMX_MF_HSH_IVW(hash[7], 7);

        return OCT_SUCCESS;
}

int
octeon_md5(const uint64_t *data, uint64_t len, uint64_t *hash)
{
        int totlen;
        uint64_t bits;
        const uint64_t *ptr;
        uint8_t chunk[MD5_BLOCK_SIZE] = { 0 };

        if(!data || !len || !hash)
                return OCT_ERR_ILLEGAL_ARGS;

        ptr = (const uint64_t *)data;
        bits = swap64(len * 8);
        totlen = len;

        CVMX_MT_HSH_IV(MD5_H1_MAGIC, 0);
        CVMX_MT_HSH_IV(MD5_H2_MAGIC, 1);

        CVMX_PREFETCH0(ptr);

        while(totlen >= 128) {
                CVMX_PREFETCH128(ptr);
                MD5_HASH_128BYTES(ptr, totlen);
        }

        if(totlen >= 64) MD5_HASH_64BYTES(ptr, totlen);
        if(totlen >= 64) MD5_HASH_64BYTES(ptr, totlen);

        if(totlen > 0)
                memcpy(chunk, ptr, totlen);

        memset(chunk + totlen + 1, 0, MD5_BLOCK_SIZE - totlen - 1);

        chunk[totlen] = 0x80;

        ptr = (const uint64_t *)chunk;
        CVMX_MT_HSH_DAT(*ptr++, 0);
        CVMX_MT_HSH_DAT(*ptr++, 1);
        CVMX_MT_HSH_DAT(*ptr++, 2);
        CVMX_MT_HSH_DAT(*ptr++, 3);
        CVMX_MT_HSH_DAT(*ptr++, 4);
        CVMX_MT_HSH_DAT(*ptr++, 5);
        CVMX_MT_HSH_DAT(*ptr++, 6);

        if(totlen < (MD5_BLOCK_SIZE - 8))
                CVMX_MT_HSH_STARTMD5(bits);
        else {
                CVMX_MT_HSH_STARTMD5(*ptr);
                CVMX_MT_HSH_DATZ(0);
                CVMX_MT_HSH_DATZ(1);
                CVMX_MT_HSH_DATZ(2);
                CVMX_MT_HSH_DATZ(3);
                CVMX_MT_HSH_DATZ(4);
                CVMX_MT_HSH_DATZ(5);
                CVMX_MT_HSH_DATZ(6);
                CVMX_MT_HSH_STARTMD5(bits);
        }

        /* Seriously, I need some hash! */
        CVMX_MF_HSH_IV(hash[0], 0);
        CVMX_MF_HSH_IV(hash[1], 1);

        return OCT_SUCCESS;
}


static int
hmac_md5(const uint64_t *data, uint64_t len, uint64_t *iv, int stored,
         int final)
{
        int totlen;
        const uint64_t *ptr;

        if(!data || !len)
                return OCT_ERR_ILLEGAL_ARGS;

        ptr = (const uint64_t *)data;
        totlen = len;

        CVMX_MT_HSH_IV(iv[0], 0);
        CVMX_MT_HSH_IV(iv[1], 1);

        CVMX_PREFETCH0(ptr);

        while(totlen >= 128) {
                CVMX_PREFETCH128(ptr);
                MD5_HASH_128BYTES(ptr, totlen);
        }

        if(totlen >= 64) MD5_HASH_64BYTES(ptr, totlen);
        if(totlen >= 64) MD5_HASH_64BYTES(ptr, totlen);

        if(final) {
                uint8_t chunk[MD5_BLOCK_SIZE];
                uint64_t bits = swap64((stored + len) * 8);

                if(totlen > 0)
                        memcpy(chunk, ptr, totlen);

                memset(chunk + totlen + 1, 0, MD5_BLOCK_SIZE - totlen - 1);

                chunk[totlen] = 0x80;

                ptr = (const uint64_t *)chunk;
                CVMX_MT_HSH_DAT(*ptr++, 0);
                CVMX_MT_HSH_DAT(*ptr++, 1);
                CVMX_MT_HSH_DAT(*ptr++, 2);
                CVMX_MT_HSH_DAT(*ptr++, 3);
                CVMX_MT_HSH_DAT(*ptr++, 4);
                CVMX_MT_HSH_DAT(*ptr++, 5);
                CVMX_MT_HSH_DAT(*ptr++, 6);

                if(totlen < (MD5_BLOCK_SIZE - 8))
                        CVMX_MT_HSH_STARTMD5(bits);
                else {
                        CVMX_MT_HSH_STARTMD5(*ptr);
                        CVMX_MT_HSH_DATZ(0);
                        CVMX_MT_HSH_DATZ(1);
                        CVMX_MT_HSH_DATZ(2);
                        CVMX_MT_HSH_DATZ(3);
                        CVMX_MT_HSH_DATZ(4);
                        CVMX_MT_HSH_DATZ(5);
                        CVMX_MT_HSH_DATZ(6);
                        CVMX_MT_HSH_STARTMD5(bits);
                }
        }

        CVMX_MF_HSH_IV(iv[0], 0);
        CVMX_MF_HSH_IV(iv[1], 1);

        return OCT_SUCCESS;
}

/**
 * Calculate the HMAC-MD5
 *
 * @param data Input data pointer
 * @param len  Input data length
 * @param key  Input key pointer
 * @param ke_len Input key length
 * @param hash Output buffer to hold the calculated HMAC-MD5
 *
 * @return OCT_SUCCESS upon success error otherwise
 */
int
octeon_hmac_md5(const uint64_t *data, uint64_t len, uint64_t *key, uint64_t key_len, uint64_t *hash)
{
        uint64_t k_ipad[8];
        uint64_t k_opad[8];
        uint64_t tk[2];
        uint64_t iv[2];
        int i;

        memset(k_ipad, 0, UINT64_SIZE * 8);
        memset(k_opad, 0, UINT64_SIZE * 8);

        /* in bytes */
        if(key_len > MD5_BLOCK_SIZE) {
                memset(tk, 0, UINT64_SIZE * 2);

                tk[0] = MD5_H1_MAGIC;
                tk[1] = MD5_H2_MAGIC;
                
                hmac_md5(key, key_len, tk, 0, 1);

                key = tk;
                key_len = MD5_DIGEST_LENGTH;
        }

        memcpy((uint8_t *)k_ipad, (uint8_t *)key, key_len);
        memcpy((uint8_t *)k_opad, (uint8_t *)key, key_len);

        for(i = 0; i < 8; i++) {
                k_ipad[i] ^= (uint64_t)0x3636363636363636;
                k_opad[i] ^= (uint64_t)0x5c5c5c5c5c5c5c5c;
        }

        iv[0] = MD5_H1_MAGIC;
        iv[1] = MD5_H2_MAGIC;

        /* update the MD5 engine */
        hmac_md5(k_ipad, 64, iv, 0, 0);
        /* final call to the MD5 engine */
        hmac_md5(data, len, iv, 64, 1);

        memcpy((uint8_t *)hash, (uint8_t *)iv, MD5_DIGEST_LENGTH);

        iv[0] = MD5_H1_MAGIC;
        iv[1] = MD5_H2_MAGIC;

        hmac_md5(k_opad, 64, iv, 0, 0);
        hmac_md5(hash, MD5_DIGEST_LENGTH, iv, 64, 1);

        memcpy(hash, iv, MD5_DIGEST_LENGTH);

        return OCT_SUCCESS;
}

/**
 * Internal API's to calculate the HMAC-SHA1
 *
 * @param data Input data pointer
 * @param len  Input data length
 * @param iv   IV for the initialization of SHA1 engine
 * @param stored Bytes processed in the update call
 * @param flag Signals for update/final call
 *
 * @return OCT_SUCCESS on return, error otherwise.
 */

static int
hmac_sha1(const uint64_t *data, uint64_t len, uint64_t *iv, uint64_t stored,
          int final)
{
        int totlen = len;
        const uint64_t *ptr = (uint64_t *)data;

        CVMX_MT_HSH_IV(iv[0], 0);
        CVMX_MT_HSH_IV(iv[1], 1);
        CVMX_MT_HSH_IV(iv[2], 2);

        CVMX_PREFETCH0(ptr);

        while(totlen >= 128) {
                CVMX_PREFETCH128(ptr);
                SHA_HASH_128BYTES(ptr, totlen);
        }

        if(totlen >= 64) SHA_HASH_64BYTES(ptr, totlen);
        if(totlen >= 64) SHA_HASH_64BYTES(ptr, totlen);

        if(final) {
                uint64_t bits = (stored + len) * 8;
                uint8_t chunk[SHA_BLOCK_SIZE];

                if(totlen > 0)
                        memcpy(chunk, ptr, totlen);

                memset(chunk + totlen + 1, 0, SHA_BLOCK_SIZE - totlen - 1);

                chunk[totlen] = 0x80;

                ptr = (const uint64_t *)chunk;
                CVMX_MT_HSH_DAT(*ptr++, 0);
                CVMX_MT_HSH_DAT(*ptr++, 1);
                CVMX_MT_HSH_DAT(*ptr++, 2);
                CVMX_MT_HSH_DAT(*ptr++, 3);
                CVMX_MT_HSH_DAT(*ptr++, 4);
                CVMX_MT_HSH_DAT(*ptr++, 5);
                CVMX_MT_HSH_DAT(*ptr++, 6);

                if(totlen < (SHA_BLOCK_SIZE - 8))
                        CVMX_MT_HSH_STARTSHA(bits);
                else {
                        CVMX_MT_HSH_STARTSHA(*ptr);
                        CVMX_MT_HSH_DATZ(0);
                        CVMX_MT_HSH_DATZ(1);
                        CVMX_MT_HSH_DATZ(2);
                        CVMX_MT_HSH_DATZ(3);
                        CVMX_MT_HSH_DATZ(4);
                        CVMX_MT_HSH_DATZ(5);
                        CVMX_MT_HSH_DATZ(6);
                        CVMX_MT_HSH_STARTSHA(bits);
                }
        }
                
        CVMX_MF_HSH_IV(iv[0], 0);
        CVMX_MF_HSH_IV(iv[1], 1);
        CVMX_MF_HSH_IV(iv[2], 2);

        return OCT_SUCCESS;
}

/**
 * Calculate the HMAC-SHA1
 *
 * @param data Input data pointer
 * @param len  Input data length
 * @param key  Input key pointer
 * @param ke_len Input key length
 * @param hash Output buffer to hold the calculated HMAC-SHA1
 *
 * @return OCT_SUCCESS upon success error otherwise
 */
int
octeon_hmac_sha1(const uint64_t *data, uint64_t len, uint64_t *key,
                uint64_t key_len, uint64_t *hash)
{
        uint64_t k_ipad[8];
        uint64_t k_opad[8];
        uint64_t tk[3];
        uint64_t iv[3];
        int i;

        memset(k_ipad, 0, UINT64_SIZE * 8);
        memset(k_opad, 0, UINT64_SIZE * 8);

        /* in bytes */
        if(key_len > SHA_BLOCK_SIZE) {
                memset(tk, 0, UINT64_SIZE * 3);

                tk[0] = SHA1_H1_MAGIC;
                tk[1] = SHA1_H2_MAGIC;
                tk[2] = SHA1_H3_MAGIC;

                hmac_sha1(key, key_len, tk, 0, 1); 

                key = tk;
                key_len = SHA_DIGEST_LENGTH;
        }

        memcpy((uint8_t *)k_ipad, (uint8_t *)key, key_len);
        memcpy((uint8_t *)k_opad, (uint8_t *)key, key_len);

        for(i = 0; i < 8; i++) {
                k_ipad[i] ^= (uint64_t)0x3636363636363636;
                k_opad[i] ^= (uint64_t)0x5c5c5c5c5c5c5c5c;
        }

        iv[0] = SHA1_H1_MAGIC;
        iv[1] = SHA1_H2_MAGIC;
        iv[2] = SHA1_H3_MAGIC;
        /* update call for SHA engine */
        hmac_sha1(k_ipad, 64, iv, 0, 0);
        /* final call for SHA engine */
        hmac_sha1(data, len, iv, 64, 1);

        memcpy(hash, iv, SHA_DIGEST_LENGTH);

        iv[0] = SHA1_H1_MAGIC;
        iv[1] = SHA1_H2_MAGIC;
        iv[2] = SHA1_H3_MAGIC;
        hmac_sha1(k_opad, 64, iv, 0, 0);
        hmac_sha1(hash, SHA_DIGEST_LENGTH, iv, 64, 1);

        memcpy(hash, iv, SHA_DIGEST_LENGTH);

        return OCT_SUCCESS;
}


static int
hmac_sha256(const uint64_t *data, uint64_t len, uint64_t *iv, uint64_t stored,
            int final)
{
        int totlen = len;
        const uint64_t *ptr;

        CVMX_MT_HSH_IV(iv[0], 0);
        CVMX_MT_HSH_IV(iv[1], 1);
        CVMX_MT_HSH_IV(iv[2], 2);
        CVMX_MT_HSH_IV(iv[3], 3);

        ptr = (const uint64_t *)data;

        CVMX_PREFETCH0(ptr);

        while(totlen >= 128) {
                CVMX_PREFETCH128(ptr);
                SHA256_HASH_128BYTES(ptr, totlen);
        }

        if(totlen >= 64) SHA256_HASH_64BYTES(ptr, totlen);
        if(totlen >= 64) SHA256_HASH_64BYTES(ptr, totlen);
        
        if(final) {
                uint8_t chunk[SHA256_BLOCK_SIZE];
                uint64_t bits = (stored + len) * 8;

                if(totlen > 0)
                        memcpy(chunk, ptr, totlen);

                memset(chunk + totlen + 1, 0, SHA256_BLOCK_SIZE - totlen - 1);
                chunk[totlen] = 0x80;

                ptr = (const uint64_t *)chunk;
                CVMX_MT_HSH_DAT(*ptr++, 0);
                CVMX_MT_HSH_DAT(*ptr++, 1);
                CVMX_MT_HSH_DAT(*ptr++, 2);
                CVMX_MT_HSH_DAT(*ptr++, 3);
                CVMX_MT_HSH_DAT(*ptr++, 4);
                CVMX_MT_HSH_DAT(*ptr++, 5);
                CVMX_MT_HSH_DAT(*ptr++, 6);

                if(totlen < (SHA256_BLOCK_SIZE - 8))
                        CVMX_MT_HSH_STARTSHA256(bits);
                else {
                        CVMX_MT_HSH_STARTSHA256(*ptr);
                        CVMX_MT_HSH_DATZ(0);
                        CVMX_MT_HSH_DATZ(1);
                        CVMX_MT_HSH_DATZ(2);
                        CVMX_MT_HSH_DATZ(3);
                        CVMX_MT_HSH_DATZ(4);
                        CVMX_MT_HSH_DATZ(5);
                        CVMX_MT_HSH_DATZ(6);
                        CVMX_MT_HSH_STARTSHA256(bits);
                }
        }

        CVMX_MF_HSH_IV(iv[0], 0);
        CVMX_MF_HSH_IV(iv[1], 1);
        CVMX_MF_HSH_IV(iv[2], 2);
        CVMX_MF_HSH_IV(iv[3], 3);

        return OCT_SUCCESS;
}


int
octeon_hmac_sha256(const uint64_t *data, uint64_t len, uint64_t *key,
                uint64_t key_len, uint64_t *hash)
{
        int blocksize = SHA256_BLOCK_SIZE / 8;
        uint64_t k_ipad[blocksize];
        uint64_t k_opad[blocksize];
        uint64_t tk[4];
        uint64_t iv[4];
        int i;

        memset(k_ipad, 0, UINT64_SIZE * blocksize);
        memset(k_opad, 0, UINT64_SIZE * blocksize);

        /* in bytes */
        if(key_len > SHA256_BLOCK_SIZE) {
                memset(tk, 0, UINT64_SIZE * 4);

                tk[0] = SHA256_H1_MAGIC;
                tk[1] = SHA256_H2_MAGIC;
                tk[2] = SHA256_H3_MAGIC;
                tk[3] = SHA256_H4_MAGIC;

                hmac_sha256(key, key_len, tk, 0, 1); 

                key = tk;
                key_len = SHA256_DIGEST_LENGTH;
        }

        memcpy((uint8_t *)k_ipad, (uint8_t *)key, key_len);
        memcpy((uint8_t *)k_opad, (uint8_t *)key, key_len);

        for(i = 0; i < blocksize; i++) {
                k_ipad[i] ^= (uint64_t)0x3636363636363636ull;
                k_opad[i] ^= (uint64_t)0x5c5c5c5c5c5c5c5cull;
        }

        iv[0] = SHA256_H1_MAGIC;
        iv[1] = SHA256_H2_MAGIC;
        iv[2] = SHA256_H3_MAGIC;
        iv[3] = SHA256_H4_MAGIC;
        /* update call for SHA engine */
        hmac_sha256(k_ipad, SHA256_BLOCK_SIZE, iv, 0, 0);
        /* final call for SHA engine */
        hmac_sha256(data, len, iv, SHA256_BLOCK_SIZE, 1);

        hash[0] = iv[0];
        hash[1] = iv[1];
        hash[2] = iv[2];
        hash[3] = iv[3];
        
        iv[0] = SHA256_H1_MAGIC;
        iv[1] = SHA256_H2_MAGIC;
        iv[2] = SHA256_H3_MAGIC;
        iv[3] = SHA256_H4_MAGIC;

        hmac_sha256(k_opad, SHA256_BLOCK_SIZE, iv, 0, 0);
        hmac_sha256(hash, SHA256_DIGEST_LENGTH, iv, SHA256_BLOCK_SIZE, 1);

        memcpy(hash, iv, SHA256_DIGEST_LENGTH);

        return OCT_SUCCESS;
}

static int
hmac_sha384(const uint64_t *data, uint64_t len, uint64_t *iv, uint64_t stored,
            int final)
{
        uint64_t totlen = len;
        const uint64_t *ptr;

        CVMX_MT_HSH_IVW(iv[0], 0);
        CVMX_MT_HSH_IVW(iv[1], 1);
        CVMX_MT_HSH_IVW(iv[2], 2);
        CVMX_MT_HSH_IVW(iv[3], 3);
        CVMX_MT_HSH_IVW(iv[4], 4);
        CVMX_MT_HSH_IVW(iv[5], 5);
        CVMX_MT_HSH_IVW(iv[6], 6);
        CVMX_MT_HSH_IVW(iv[7], 7);

        ptr = (const uint64_t *)data;

        CVMX_PREFETCH0(ptr);

        while(totlen >= 128) {
                CVMX_PREFETCH128(ptr);
                SHA384_HASH_128BYTES(ptr, totlen);
        }

        if(final) {
                uint8_t chunk[SHA384_BLOCK_SIZE];
                uint64_t total_bytes = (stored + len);

                if(totlen > 0)
                        memcpy(chunk, ptr, totlen);

                memset(chunk + totlen + 1, 0, SHA384_BLOCK_SIZE - totlen - 1);
                chunk[totlen] = 0x80;

                ptr = (const uint64_t *)chunk;
                CVMX_MT_HSH_DATW(*ptr++, 0);
                CVMX_MT_HSH_DATW(*ptr++, 1);
                CVMX_MT_HSH_DATW(*ptr++, 2);
                CVMX_MT_HSH_DATW(*ptr++, 3);
                CVMX_MT_HSH_DATW(*ptr++, 4);
                CVMX_MT_HSH_DATW(*ptr++, 5);
                CVMX_MT_HSH_DATW(*ptr++, 6);
                CVMX_MT_HSH_DATW(*ptr++, 7);
                CVMX_MT_HSH_DATW(*ptr++, 8);
                CVMX_MT_HSH_DATW(*ptr++, 9);
                CVMX_MT_HSH_DATW(*ptr++, 10);
                CVMX_MT_HSH_DATW(*ptr++, 11);
                CVMX_MT_HSH_DATW(*ptr++, 12);
                CVMX_MT_HSH_DATW(*ptr++, 13);

                if(totlen < (SHA384_BLOCK_SIZE - 16)) {
                        uint64_t ab[2];
                        UINT64_MUL(ab[0], ab[1], total_bytes, 8);
                        CVMX_MT_HSH_DATW(ab[0], 14);
                        CVMX_MT_HSH_STARTSHA384(ab[1]);
                } else {
                        
                        uint64_t ab[2];
			CVMX_MT_HSH_DATW(*ptr++, 14);
                        CVMX_MT_HSH_STARTSHA384(*ptr);
                        CVMX_MT_HSH_DATWZ(0);
                        CVMX_MT_HSH_DATWZ(1);
                        CVMX_MT_HSH_DATWZ(2);
                        CVMX_MT_HSH_DATWZ(3);
                        CVMX_MT_HSH_DATWZ(4);
                        CVMX_MT_HSH_DATWZ(5);
                        CVMX_MT_HSH_DATWZ(6);
                        CVMX_MT_HSH_DATWZ(7);
                        CVMX_MT_HSH_DATWZ(8);
                        CVMX_MT_HSH_DATWZ(9);
                        CVMX_MT_HSH_DATWZ(10);
                        CVMX_MT_HSH_DATWZ(11);
                        CVMX_MT_HSH_DATWZ(12);
                        CVMX_MT_HSH_DATWZ(13);

                        UINT64_MUL(ab[0], ab[1], total_bytes, 8);
                        CVMX_MT_HSH_DATW(ab[0], 14);
                        CVMX_MT_HSH_STARTSHA384(ab[1]);
                }
        }

        CVMX_MF_HSH_IVW(iv[0], 0);
        CVMX_MF_HSH_IVW(iv[1], 1);
        CVMX_MF_HSH_IVW(iv[2], 2);
        CVMX_MF_HSH_IVW(iv[3], 3);
        CVMX_MF_HSH_IVW(iv[4], 4);
        CVMX_MF_HSH_IVW(iv[5], 5);
        if(!final) {
                CVMX_MF_HSH_IVW(iv[6], 6);
                CVMX_MF_HSH_IVW(iv[7], 7);
        }

        return OCT_SUCCESS;
}

int
octeon_hmac_sha384(const uint64_t *data, uint64_t len, uint64_t *key,
                uint64_t key_len, uint64_t *hash)
{
        int blocksize = SHA384_BLOCK_SIZE / 8;
        uint64_t k_ipad[blocksize];
        uint64_t k_opad[blocksize];
        uint64_t tk[6];
        uint64_t iv[8];
        int i;

        memset(k_ipad, 0, UINT64_SIZE * blocksize);
        memset(k_opad, 0, UINT64_SIZE * blocksize);

        /* in bytes */
        if(key_len > SHA384_BLOCK_SIZE) {
                memset(tk, 0, UINT64_SIZE * 6);

                iv[0] = SHA384_H1_MAGIC;
                iv[1] = SHA384_H2_MAGIC;
                iv[2] = SHA384_H3_MAGIC;
                iv[3] = SHA384_H4_MAGIC;
                iv[4] = SHA384_H5_MAGIC;
                iv[5] = SHA384_H6_MAGIC;
                iv[6] = SHA384_H7_MAGIC;
                iv[7] = SHA384_H8_MAGIC;

                hmac_sha384(key, key_len, iv, 0, 1); 

                memcpy((uint8_t *)tk, (uint8_t *)iv, SHA384_DIGEST_LENGTH);
                key = tk;
                key_len = SHA384_DIGEST_LENGTH; /* in bytes */
        }

        memcpy((uint8_t *)k_ipad, (uint8_t *)key, key_len);
        memcpy((uint8_t *)k_opad, (uint8_t *)key, key_len);

        for(i = 0; i < blocksize; i++) {
                k_ipad[i] ^= (uint64_t)0x3636363636363636ull;
                k_opad[i] ^= (uint64_t)0x5c5c5c5c5c5c5c5cull;
        }

        iv[0] = SHA384_H1_MAGIC;
        iv[1] = SHA384_H2_MAGIC;
        iv[2] = SHA384_H3_MAGIC;
        iv[3] = SHA384_H4_MAGIC;
        iv[4] = SHA384_H5_MAGIC;
        iv[5] = SHA384_H6_MAGIC;
        iv[6] = SHA384_H7_MAGIC;
        iv[7] = SHA384_H8_MAGIC;

        /* update call for SHA engine */
        hmac_sha384(k_ipad, SHA384_BLOCK_SIZE, iv, 0, 0);
        /* final call for SHA engine */
        hmac_sha384(data, len, iv, SHA384_BLOCK_SIZE, 1);

        hash[0] = iv[0];
        hash[1] = iv[1];
        hash[2] = iv[2];
        hash[3] = iv[3];
        hash[4] = iv[4];
        hash[5] = iv[5];
        
        iv[0] = SHA384_H1_MAGIC;
        iv[1] = SHA384_H2_MAGIC;
        iv[2] = SHA384_H3_MAGIC;
        iv[3] = SHA384_H4_MAGIC;
        iv[4] = SHA384_H5_MAGIC;
        iv[5] = SHA384_H6_MAGIC;
        iv[6] = SHA384_H7_MAGIC;
        iv[7] = SHA384_H8_MAGIC;

        hmac_sha384(k_opad, SHA384_BLOCK_SIZE, iv, 0, 0);
        hmac_sha384(hash, SHA384_DIGEST_LENGTH, iv, SHA384_BLOCK_SIZE, 1);

        hash[0] = iv[0];
        hash[1] = iv[1];
        hash[2] = iv[2];
        hash[3] = iv[3];
        hash[4] = iv[4];
        hash[5] = iv[5];

        return OCT_SUCCESS;
}


int
hmac_sha512(const uint64_t *data, uint64_t len, uint64_t *iv, uint64_t stored,
            int final)
{
        int totlen = len;
        const uint64_t *ptr;

        CVMX_MT_HSH_IVW(iv[0], 0);
        CVMX_MT_HSH_IVW(iv[1], 1);
        CVMX_MT_HSH_IVW(iv[2], 2);
        CVMX_MT_HSH_IVW(iv[3], 3);
        CVMX_MT_HSH_IVW(iv[4], 4);
        CVMX_MT_HSH_IVW(iv[5], 5);
        CVMX_MT_HSH_IVW(iv[6], 6);
        CVMX_MT_HSH_IVW(iv[7], 7);

        ptr = (const uint64_t *)data;

        CVMX_PREFETCH0(ptr);

        while(totlen >= 128) {
                CVMX_PREFETCH128(ptr);
                SHA512_HASH_128BYTES(ptr, totlen);
        }

        if(final) {
                uint64_t total_bytes = (stored + len);
                uint8_t chunk[SHA512_BLOCK_SIZE];

                if(totlen > 0)
                        memcpy(chunk, ptr, totlen);

                memset(chunk + totlen + 1, 0, SHA512_BLOCK_SIZE - totlen - 1);
                chunk[totlen] = 0x80;

                ptr = (const uint64_t *)chunk;
                CVMX_MT_HSH_DATW(*ptr++, 0);
                CVMX_MT_HSH_DATW(*ptr++, 1);
                CVMX_MT_HSH_DATW(*ptr++, 2);
                CVMX_MT_HSH_DATW(*ptr++, 3);
                CVMX_MT_HSH_DATW(*ptr++, 4);
                CVMX_MT_HSH_DATW(*ptr++, 5);
                CVMX_MT_HSH_DATW(*ptr++, 6);
                CVMX_MT_HSH_DATW(*ptr++, 7);
                CVMX_MT_HSH_DATW(*ptr++, 8);
                CVMX_MT_HSH_DATW(*ptr++, 9);
                CVMX_MT_HSH_DATW(*ptr++, 10);
                CVMX_MT_HSH_DATW(*ptr++, 11);
                CVMX_MT_HSH_DATW(*ptr++, 12);
                CVMX_MT_HSH_DATW(*ptr++, 13);

                if(totlen < (SHA512_BLOCK_SIZE - 16)) {
                        uint64_t ab[2];
                        UINT64_MUL(ab[0], ab[1], total_bytes, 8);
                        CVMX_MT_HSH_DATW(ab[0], 14);
                        CVMX_MT_HSH_STARTSHA512(ab[1]);
                } else {
                        
                        uint64_t ab[2];
			CVMX_MT_HSH_DATW(*ptr++, 14);
                        CVMX_MT_HSH_STARTSHA512(*ptr);
                        CVMX_MT_HSH_DATWZ(0);
                        CVMX_MT_HSH_DATWZ(1);
                        CVMX_MT_HSH_DATWZ(2);
                        CVMX_MT_HSH_DATWZ(3);
                        CVMX_MT_HSH_DATWZ(4);
                        CVMX_MT_HSH_DATWZ(5);
                        CVMX_MT_HSH_DATWZ(6);
                        CVMX_MT_HSH_DATWZ(7);
                        CVMX_MT_HSH_DATWZ(8);
                        CVMX_MT_HSH_DATWZ(9);
                        CVMX_MT_HSH_DATWZ(10);
                        CVMX_MT_HSH_DATWZ(11);
                        CVMX_MT_HSH_DATWZ(12);
                        CVMX_MT_HSH_DATWZ(13);

                        UINT64_MUL(ab[0], ab[1], total_bytes, 8);
                        CVMX_MT_HSH_DATW(ab[0], 14);
                        CVMX_MT_HSH_STARTSHA512(ab[1]);
                }
        }

        CVMX_MF_HSH_IVW(iv[0], 0);
        CVMX_MF_HSH_IVW(iv[1], 1);
        CVMX_MF_HSH_IVW(iv[2], 2);
        CVMX_MF_HSH_IVW(iv[3], 3);
        CVMX_MF_HSH_IVW(iv[4], 4);
        CVMX_MF_HSH_IVW(iv[5], 5);
        CVMX_MF_HSH_IVW(iv[6], 6);
        CVMX_MF_HSH_IVW(iv[7], 7);

        return OCT_SUCCESS;
}


int
octeon_hmac_sha512(const uint64_t *data, uint64_t len, uint64_t *key,
                   uint64_t key_len, uint64_t *hash)
{
        int blocksize = SHA512_BLOCK_SIZE / 8;
        uint64_t k_ipad[blocksize];
        uint64_t k_opad[blocksize];
        uint64_t tk[8];
        uint64_t iv[8];
        int i;

        memset(k_ipad, 0, UINT64_SIZE * blocksize);
        memset(k_opad, 0, UINT64_SIZE * blocksize);

        /* in bytes */
        if(key_len > SHA512_BLOCK_SIZE) {
                memset(tk, 0, UINT64_SIZE * 8);

                iv[0] = SHA512_H1_MAGIC;
                iv[1] = SHA512_H2_MAGIC;
                iv[2] = SHA512_H3_MAGIC;
                iv[3] = SHA512_H4_MAGIC;
                iv[4] = SHA512_H5_MAGIC;
                iv[5] = SHA512_H6_MAGIC;
                iv[6] = SHA512_H7_MAGIC;
                iv[7] = SHA512_H8_MAGIC;

                hmac_sha512(key, key_len, iv, 0, 1); 

                memcpy((uint8_t *)tk, (uint8_t *)iv, SHA512_DIGEST_LENGTH);
                key = tk;
                key_len = SHA512_DIGEST_LENGTH; /* in bytes */
        }

        memcpy((uint8_t *)k_ipad, (uint8_t *)key, key_len);
        memcpy((uint8_t *)k_opad, (uint8_t *)key, key_len);

        for(i = 0; i < blocksize; i++) {
                k_ipad[i] ^= (uint64_t)0x3636363636363636ull;
                k_opad[i] ^= (uint64_t)0x5c5c5c5c5c5c5c5cull;
        }


        iv[0] = SHA512_H1_MAGIC;
        iv[1] = SHA512_H2_MAGIC;
        iv[2] = SHA512_H3_MAGIC;
        iv[3] = SHA512_H4_MAGIC;
        iv[4] = SHA512_H5_MAGIC;
        iv[5] = SHA512_H6_MAGIC;
        iv[6] = SHA512_H7_MAGIC;
        iv[7] = SHA512_H8_MAGIC;

        /* update call for SHA engine */
        hmac_sha512(k_ipad, SHA512_BLOCK_SIZE, iv, 0, 0);
        /* final call for SHA engine */
        hmac_sha512(data, len, iv, SHA512_BLOCK_SIZE, 1);

        memcpy(hash, iv, SHA512_DIGEST_LENGTH);

        iv[0] = SHA512_H1_MAGIC;
        iv[1] = SHA512_H2_MAGIC;
        iv[2] = SHA512_H3_MAGIC;
        iv[3] = SHA512_H4_MAGIC;
        iv[4] = SHA512_H5_MAGIC;
        iv[5] = SHA512_H6_MAGIC;
        iv[6] = SHA512_H7_MAGIC;
        iv[7] = SHA512_H8_MAGIC;

        hmac_sha512(k_opad, SHA512_BLOCK_SIZE, iv, 0, 0);
        hmac_sha512(hash, SHA512_DIGEST_LENGTH, iv, SHA512_BLOCK_SIZE, 1);

        memcpy(hash, iv, SHA512_DIGEST_LENGTH);

        return OCT_SUCCESS;
}

#endif /* OCTEON_NO_DIGEST */
 
