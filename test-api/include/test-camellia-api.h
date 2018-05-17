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


#include "test-crypto-common.h"

#define CMLL_IV_LEN			(16)
#define CMLL_MAX_KEY_LEN		(32)
#define MASK8(x)			(((int)x)%0xff)
#define MAX_BUFFER_LEN			(16*1024)
#define START_BUFFER_LEN		(16)
#define END_BUFFER_LEN			(2*START_BUFFER_LEN)
#define INCR_BUFFER_LEN			START_BUFFER_LEN
#define CMLL_BLOCK_LENGTH		(16)

#ifdef TEST_CPU_CYCLES
	static uint64_t start_cycle ;
	static uint64_t end_cycle ;
	static uint64_t cpucycles = 0;
	static uint64_t mbps = 0;
	static int iter;	
	unsigned int core;
	cvmx_sysinfo_t *sysinfo;
#endif


#ifdef TEST_CPU_CYCLES
	#define START_CYCLE_ENC  \
 		sysinfo = cvmx_sysinfo_get();\
		start_cycle = end_cycle = 0;  \
 		for (iter = 0; iter < MAX_ITERATIONS; iter++) {  \
			memcpy(enciv, origiv, 16); \
        	start_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE);
	
	#define START_CYCLE_CTR  \
 		sysinfo = cvmx_sysinfo_get();\
 		start_cycle = end_cycle = 0;  \
 		for (iter = 0; iter < MAX_ITERATIONS; iter++) {  \
 			memcpy(enciv, camellia_test_ctr_nonce_counter[i], 16); \
        	start_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE);

	#define START_CYCLE_CTR1 \
 		sysinfo = cvmx_sysinfo_get();\
 		start_cycle = end_cycle = 0;  \
 		for (iter = 0; iter < MAX_ITERATIONS; iter++) {  \
 			memcpy(deciv, camellia_test_ctr_nonce_counter[i], 16); \
        	start_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE);

	#define START_CYCLE_DEC  \
 		sysinfo = cvmx_sysinfo_get();\
 		start_cycle = end_cycle = 0;  \
 		for (iter = 0; iter < MAX_ITERATIONS; iter++) {  \
			memcpy(deciv, origiv, 16); \
        	start_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE);

	#define END_CYCLE(str) \
    	end_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE); \
	 	} \
		cpucycles = (end_cycle - start_cycle)/MAX_ITERATIONS; \
		mbps  = (inlen * cpufreq * 8)/cpucycles; \
		for (core = 0; core < CVMX_MAX_CORES; core++) {\
			if (cvmx_coremask_is_core_set(&sysinfo->core_mask, core) && core == cvmx_get_core_num()){ \
				total_cpucycles+=cpucycles;\
				total_mbps +=mbps;\
			}\
			cvmx_coremask_barrier_sync(&sysinfo->core_mask);\
		}\
		cvmx_coremask_barrier_sync(&sysinfo->core_mask);\
		if(cvmx_is_init_core()){\
 			printf ("API :%-20s total mbps :%-10lu average values per core    cpucycles :%lu mbps :%lu\n", str, total_mbps, (total_cpucycles/numcores), (total_mbps/numcores));\
			total_cpucycles = 0;\
			total_mbps = 0;\
		}
		
	#define END_CYCLE_AES(str,keylen) \
    	end_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE); \
 		} \
 		cpucycles = (end_cycle - start_cycle)/MAX_ITERATIONS; \
 		mbps = (inlen * cpufreq * 8) / cpucycles;\
 		for (core = 0; core < CVMX_MAX_CORES; core++) {\
			if (cvmx_coremask_is_core_set(&sysinfo->core_mask, core) && core == cvmx_get_core_num()){ \
				total_cpucycles+=cpucycles;\
				total_mbps +=mbps;\
			}\
			cvmx_coremask_barrier_sync(&sysinfo->core_mask);\
		}\
		cvmx_coremask_barrier_sync(&sysinfo->core_mask);\
		if(cvmx_is_init_core()){\
 			printf ("API :%-20s Key length :%-10d total mbps :%-10lu average values per core    cpucycles :%lu mbps :%lu\n", str, keylen, total_mbps, (total_cpucycles/numcores), (total_mbps/numcores));\
			total_cpucycles = 0;\
			total_mbps = 0;\
		}

#else
	#define START_CYCLE_ENC
	#define START_CYCLE_CTR
	#define START_CYCLE_CTR1
	#define START_CYCLE_DEC
	#define END_CYCLE(str) 	
	#define END_CYCLE_AES(str,keylen)
#endif

#ifdef TEST_CPU_CYCLES
	#define PRINT_HDR \
		if(cvmx_is_init_core()) {\
			printf ("\n\n###################################################\n"); \
        	printf ("Printing CPU cycles for packet length :%u bytes\n", inlen ); \
        	printf ("###################################################\n");\
		}
#else
    #define PRINT_HDR
#endif


    #define CHECK_RESULT(str) \
		if (ret) { \
			printf ("Result of %-15s : %s\n", str, "Failed"); \
		}

#if 0
static void hex_print(const char *msg,unsigned char *buff,uint32_t len)
{
    uint32_t i;
    if(!buff||!len) return;

    printf("%s(%d):\n",msg,(int)len);
    for(i=0;i<len;i++)
        printf("%02x%c",buff[(int)i],(i+1)%16?' ':'\n');

    printf("\n");

}
#endif
/* ECB TEST DATA */

	uint8_t camellia_test_ecb_key[3][2][32] =
	{
		{
			{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
         	 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 },
        	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
	    },
	    {
	        { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	          0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	          0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 },
	        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
	    },
	    {
	        { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	          0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	          0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	          0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
	        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
	    },
	};

	uint8_t camellia_test_ecb_plain[][16] =
	{
	    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 },
	    { 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
	};

	uint8_t camellia_test_ecb_cipher[3][2][16] =
	{
	    {
	        { 0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73,
	          0x08, 0x57, 0x06, 0x56, 0x48, 0xea, 0xbe, 0x43 },
	        { 0x38, 0x3C, 0x6C, 0x2A, 0xAB, 0xEF, 0x7F, 0xDE,
	          0x25, 0xCD, 0x47, 0x0B, 0xF7, 0x74, 0xA3, 0x31 }
	    },
	    {
	        { 0xb4, 0x99, 0x34, 0x01, 0xb3, 0xe9, 0x96, 0xf8,
	          0x4e, 0xe5, 0xce, 0xe7, 0xd7, 0x9b, 0x09, 0xb9 },
	        { 0xD1, 0x76, 0x3F, 0xC0, 0x19, 0xD7, 0x7C, 0xC9,
	          0x30, 0xBF, 0xF2, 0xA5, 0x6F, 0x7C, 0x93, 0x64 }
	    },
	    {
	        { 0x9a, 0xcc, 0x23, 0x7d, 0xff, 0x16, 0xd7, 0x6c,
	          0x20, 0xef, 0x7c, 0x91, 0x9e, 0x3a, 0x75, 0x09 },
	        { 0x05, 0x03, 0xFB, 0x10, 0xAB, 0x24, 0x1E, 0x7C,
	          0xF4, 0x5D, 0x8C, 0xDE, 0xEE, 0x47, 0x43, 0x35 }
	    }
	};

/* CBC TEST DATA */

	uint8_t camellia_cbc_key[][32] =
   	{
   		{
	    	 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
         	0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    	},
    	{ 
         	0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
         	0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
         	0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
    	},
    	{ 
        	0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
        	0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
         	0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
         	0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
    	}
 	};

    uint8_t camellia_cbc_plain[][16] =
    {
        {
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
            0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A
        },
        {
            0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
            0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51
        },
        {
            0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
            0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF
        }
    };

uint8_t camellia_cbc_cipher[][3][16] =
    {
        {
            {
                0x16, 0x07, 0xCF, 0x49, 0x4B, 0x36, 0xBB, 0xF0,
                0x0D, 0xAE, 0xB0, 0xB5, 0x03, 0xC8, 0x31, 0xAB
            },
            {
                0xA2, 0xF2, 0xCF, 0x67, 0x16, 0x29, 0xEF, 0x78,
                0x40, 0xC5, 0xA5, 0xDF, 0xB5, 0x07, 0x48, 0x87
            },
            {
                0x0F, 0x06, 0x16, 0x50, 0x08, 0xCF, 0x8B, 0x8B,
                0x5A, 0x63, 0x58, 0x63, 0x62, 0x54, 0x3E, 0x54
            }
        },
        {
            {
                0x2A, 0x48, 0x30, 0xAB, 0x5A, 0xC4, 0xA1, 0xA2,
                0x40, 0x59, 0x55, 0xFD, 0x21, 0x95, 0xCF, 0x93
            },
            {
                0x5D, 0x5A, 0x86, 0x9B, 0xD1, 0x4C, 0xE5, 0x42,
                0x64, 0xF8, 0x92, 0xA6, 0xDD, 0x2E, 0xC3, 0xD5
            },
            {
                0x37, 0xD3, 0x59, 0xC3, 0x34, 0x98, 0x36, 0xD8,
                0x84, 0xE3, 0x10, 0xAD, 0xDF, 0x68, 0xC4, 0x49
            }
        },
        {
            {
                0xE6, 0xCF, 0xA3, 0x5F, 0xC0, 0x2B, 0x13, 0x4A,
                0x4D, 0x2C, 0x0B, 0x67, 0x37, 0xAC, 0x3E, 0xDA
            },
            {
                0x36, 0xCB, 0xEB, 0x73, 0xBD, 0x50, 0x4B, 0x40,
                0x70, 0xB1, 0xB7, 0xDE, 0x2B, 0x21, 0xEB, 0x50
            },
            {
                0xE3, 0x1A, 0x60, 0x55, 0x29, 0x7D, 0x96, 0xCA,
                0x33, 0x30, 0xCD, 0xF1, 0xB1, 0x86, 0x0A, 0x83
            }
        }
    };
 
/* CTR Test Data*/

	static const unsigned char camellia_test_ctr_key[3][16] =
	{
	    { 0xAE, 0x68, 0x52, 0xF8, 0x12, 0x10, 0x67, 0xCC,
	      0x4B, 0xF7, 0xA5, 0x76, 0x55, 0x77, 0xF3, 0x9E },
	    { 0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7,
	      0x43, 0xD6, 0xCE, 0x1F, 0x32, 0x53, 0x91, 0x63 },
	    { 0x76, 0x91, 0xBE, 0x03, 0x5E, 0x50, 0x20, 0xA8,
	      0xAC, 0x6E, 0x61, 0x85, 0x29, 0xF9, 0xA0, 0xDC }
	};
	
	static const unsigned char camellia_test_ctr_nonce_counter[3][16] =
	{
	    { 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
	    { 0x00, 0x6C, 0xB6, 0xDB, 0xC0, 0x54, 0x3B, 0x59,
	      0xDA, 0x48, 0xD9, 0x0B, 0x00, 0x00, 0x00, 0x01 },
	    { 0x00, 0xE0, 0x01, 0x7B, 0x27, 0x77, 0x7F, 0x3F,
	      0x4A, 0x17, 0x86, 0xF0, 0x00, 0x00, 0x00, 0x01 }
	};
	
	static const unsigned char camellia_test_ctr_pt[3][48] =
	{
	    { 0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62,
	      0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67 },
	
	    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F },
	
	    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	      0x20, 0x21, 0x22, 0x23 }
	};

//#ifndef TEST_CPU_CYCLES
	static unsigned char camellia_test_ctr_ct[3][48] =
	{
	    { 0xD0, 0x9D, 0xC2, 0x9A, 0x82, 0x14, 0x61, 0x9A,
	      0x20, 0x87, 0x7C, 0x76, 0xDB, 0x1F, 0x0B, 0x3F },
	    { 0xDB, 0xF3, 0xC7, 0x8D, 0xC0, 0x83, 0x96, 0xD4,
	      0xDA, 0x7C, 0x90, 0x77, 0x65, 0xBB, 0xCB, 0x44,
	      0x2B, 0x8E, 0x8E, 0x0F, 0x31, 0xF0, 0xDC, 0xA7,
	      0x2C, 0x74, 0x17, 0xE3, 0x53, 0x60, 0xE0, 0x48 },
	    { 0xB1, 0x9D, 0x1F, 0xCD, 0xCB, 0x75, 0xEB, 0x88,
	      0x2F, 0x84, 0x9C, 0xE2, 0x4D, 0x85, 0xCF, 0x73,
	      0x9C, 0xE6, 0x4B, 0x2B, 0x5C, 0x9D, 0x73, 0xF1,
	      0x4F, 0x2D, 0x5D, 0x9D, 0xCE, 0x98, 0x89, 0xCD,
	      0xDF, 0x50, 0x86, 0x96 }
	};
//#endif



