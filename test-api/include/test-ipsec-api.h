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

#define PACKET_LENGTH         1024 
#define IP_HEADER_LEN         20
#define AES_CBC_IV_LEN        16
#define HMAC_LENGTH           32
#define AH_HEADER_LEN         12 
#define AES_CTR_IV_LEN        8
#define DES_IV_LEN            8
#define ESP_HEADER_LEN        8
#define COMP_DIGEST           1

#define MAX_OUT_PACKET_LENGTH (MAX_BUFF_SIZE+200)
#define HASH_KEY_LEN          64


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
    #define COPY_API(str) \
        memset (apiname, 0, sizeof(apiname)); \
        memcpy (apiname, api, strlen((const char *)api)); \
        memcpy ((apiname+strlen((const char *)api)), str, strlen((const char *)str)); 
#else
    #define COPY_API(str)    
#endif



#ifdef TEST_CPU_CYCLES  
	#define START_CYCLE \
 		sysinfo = cvmx_sysinfo_get();\
		start_cycle = end_cycle = 0;  \
		for (iter = 0; iter < MAX_ITERATIONS; iter++) {  \
		start_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE);

	#define START_CYCLE_AES_CBC \
 		sysinfo = cvmx_sysinfo_get();\
		start_cycle = end_cycle = 0;  \
		for (iter = 0; iter < MAX_ITERATIONS; iter++) {  \
			memcpy (iv, aes_iv, AES_CBC_IV_LEN); \
			start_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE);

	#define START_CYCLE_AES_CTR \
 		sysinfo = cvmx_sysinfo_get();\
		start_cycle = end_cycle = 0;  \
		for (iter = 0; iter < MAX_ITERATIONS; iter++) {  \
			memcpy (iv, aesctr_iv, AES_CTR_IV_LEN); \
			start_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE);

	#define START_CYCLE_3DES \
 		sysinfo = cvmx_sysinfo_get();\
		start_cycle = end_cycle = 0;  \
		for (iter = 0; iter < MAX_ITERATIONS; iter++) {  \
			memcpy (iv, des_iv, DES_IV_LEN); \
			start_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE);

	#define END_CYCLE(str) \
		end_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE); \
		} \
		cpucycles = (long)(end_cycle - start_cycle)/MAX_ITERATIONS; \
		mbps = pktlen * cpufreq * 8 / cpucycles; \
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

	#define END_CYCLE_AES(str, keylen) \
		end_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE);  \
		} \
		cpucycles = (long)(end_cycle - start_cycle)/MAX_ITERATIONS; \
    	mbps = pktlen * cpufreq * 8 / cpucycles; \
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
    #define START_CYCLE
	#define START_CYCLE_AES_CBC
	#define START_CYCLE_AES_CTR
	#define START_CYCLE_3DES
    #define END_CYCLE(str)
    #define END_CYCLE_AES(str,keylen)
#endif

#ifdef TEST_CPU_CYCLES
    #define PRINT_HDR \
		if(cvmx_is_init_core()) {\
			printf ("\n\n####################################################################\n"); \
        	printf ("Printing CPU cycles for packet length :%u bytes And Hashkey len %u\n",(unsigned int)pktlen,(unsigned int)hash_keylen); \
        	printf ("####################################################################\n");\
		}
#else
    #define PRINT_HDR
#endif

#ifdef TEST_CPU_CYCLES
    #define COPY_API(str) \
        memset (apiname, 0, sizeof(apiname)); \
        memcpy (apiname, api, strlen((const char *)api)); \
        memcpy ((apiname+strlen((const char *)api)), str, strlen((const char *)str)); 
#else
    #define COPY_API(str)    
#endif



#define CHECK_RETURN_VAL(str) \
    if (ret != 0)  {  \
        printf ("%s Failed (Line:%d)\n", str, __LINE__);  \
        ret = -1; \
        goto End; \
    }

#define CHECK_RESULT(str)  \
    if (ret != 0)  {  \
        printf ("%s Encrypt/Decrypt Failed... Aborting Test\n", str); \
        return -1; \
    } 
/*
static void hex_print (uint8_t *buff, uint32_t len)
{
    uint32_t cnt = 0;
    for (cnt = 0; cnt < len; cnt++) 
        printf ("%02x", buff[cnt]);
    printf ("\n");
}
*/

uint8_t aes_key[][32] = {
    /* 128 bit key */
    {0x09,0x28,0x34,0x74,0x00,0x12,0xab,0x45,
     0x93,0x67,0x56,0x37,0xca,0xaf,0xff,0xbb},
    /* 192 bit key */
    {0x23,0x98,0x74,0xaa,0xbd,0xef,0xad,0x94,
     0x8b,0xcd,0xf7,0x36,0x4b,0xca,0xc7,0xbc,
     0x84,0xd8,0x47,0x46,0x69,0x47,0x00,0xcd},
    /* 256 bit key */
    {0x91,0x28,0x73,0x48,0x72,0x13,0x46,0x87,
     0x16,0xab,0xde,0x84,0x7b,0xc4,0x87,0xad,
     0x98,0x8d,0xdf,0xff,0xf7,0x38,0x46,0xbc,
     0xad,0xef,0x54,0x76,0x84,0x73,0x64,0x78}
};

uint8_t aes_iv[16] = {
    0x08,0x93,0x78,0x67,0x49,0x32,0x87,0x21,0x67,0xab,0xcd,0xef,0xaf,0xcd,0xef,0xff
};

uint8_t aesctr_key[][32] = {
    /* AES 128 bit key */
    {0xae,0x68,0x52,0xf8,0x12,0x10,0x67,0xcc,
     0x4b,0xf7,0xa5,0x76,0x55,0x77,0xf3,0x9e},
    /* AES 192 bit key */
    {0x16,0xaf,0x5b,0x14,0x5f,0xc9,0xf5,0x79,
     0xc1,0x75,0xf9,0x3e,0x3b,0xfb,0x0e,0xed,
     0x86,0x3d,0x06,0xcc,0xfd,0xb7,0x85,0x15},
    /* AES 256 bit key */
    {0x77,0x6b,0xef,0xf2,0x85,0x1d,0xb0,0x6f,
     0x4c,0x8a,0x05,0x42,0xc8,0x69,0x6f,0x6c,
     0x6a,0x81,0xaf,0x1e,0xec,0x96,0xb4,0xd3,
     0x7f,0xc1,0xd6,0x89,0xe6,0xc1,0xc1,0x04}
};

uint8_t aesctr_iv[] = { 
   0x36,0x73,0x3c,0x14,0x7d,0x6d,0x93,0xcb
};

uint32_t nonce = 0x12abcd48;

uint8_t espheader[8] = { 
    0xab,0xcd,0xef,0x12,0x34,0x56,0x78,0x90
};

uint8_t ah_header[12] = {
    0xff,0x78,0x59,0x44,0xcb,0xfe,0x39,0x91,0xcb,0xaf,0xee,0xce
}; 

uint8_t des_key[24] = { 
    0xf2,0xe0,0xd5,0xc2,0xb5,0xa1,0x97,0x85,
    0x31,0xe3,0xd0,0x51,0xb3,0xa4,0x97,0x83,
    0xf2,0xe0,0xd5,0xc2,0xb5,0xa1,0x97,0x85
};

uint8_t des_iv[8] = { 
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
};


/* IPSec API function pointers */

typedef int (*AesCbcEncFuncPtr) (uint16_t, uint8_t *,  uint16_t, uint8_t *, 
                                 uint8_t *, uint8_t *, uint8_t *, uint16_t, 
                                 uint8_t *, uint16_t *);
typedef int (*AesCbcDecFuncPtr) (uint16_t, uint8_t *, uint16_t, uint8_t *, 
                                 uint8_t *, uint8_t *, uint16_t, uint8_t *, 
                                 uint16_t *, uint8_t);
typedef int (*AesCtrEncFuncPtr) (uint64_t *, uint32_t, uint32_t, uint16_t, 
                                 uint8_t *, uint8_t *, uint8_t *, uint8_t *,
                                 uint16_t, uint8_t *, uint16_t *);
typedef int (*AesCtrDecFuncPtr) (uint64_t *, uint32_t, uint32_t, uint16_t, 
                                 uint8_t *, uint8_t *,  uint8_t *, uint16_t,
                                 uint8_t *, uint16_t *, uint8_t);
typedef int (*DesEncFuncPtr) (uint8_t *, uint16_t, uint8_t *, uint8_t *, 
                              uint8_t *, uint8_t *, uint16_t, uint8_t *, 
                              uint16_t *);
typedef int (*DesDecFuncPtr) (uint8_t *, uint16_t , uint8_t *, uint8_t *,
                              uint8_t *, uint16_t ,uint8_t *, uint16_t *,
                              uint8_t);
typedef int (*EncNULLFuncPtr) (uint16_t, uint8_t *, uint8_t *, uint8_t *,
                               uint16_t, uint8_t *, uint16_t *);
typedef int (*DecNULLFuncPtr) (uint16_t, uint8_t *, uint8_t *, uint16_t,
                               uint8_t *, uint16_t *, uint8_t);
typedef int (*OutbAHFuncPtr) (uint16_t, uint8_t *,  uint8_t *, uint8_t *, 
                              uint16_t , uint8_t *, uint16_t *);
typedef int (*InbAHFuncPtr) (uint16_t, uint8_t *,  uint8_t *, uint16_t , 
                             uint8_t *, uint16_t *,int);

