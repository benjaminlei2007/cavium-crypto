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


#define BUFF_SIZE 32   /* in Bytes */


/* Funtion tp print char buffer */
void hex_print (uint8_t *val, int count)
{
    int i;
    for (i=0;i< count; i++)
        printf("%02x ", *(val+i));
    printf("\n");
    return;
}

#define START_ADD_SIZE 32
#define MAX_ADD_SIZE 256


#ifdef TEST_CPU_CYCLES                         
	static uint64_t start_cycle = 0;
	static uint64_t end_cycle = 0;
	static int iter;
	static uint64_t cpucycles, mbps;   	
	unsigned int core;
	cvmx_sysinfo_t *sysinfo;
#endif 

#ifdef TEST_CPU_CYCLES                         
	#define START_CYCLE \
 	sysinfo = cvmx_sysinfo_get();\
	start_cycle = end_cycle = 0; \
 	for (iter = 0; iter < MAX_ITERATIONS; iter++) {  \
        start_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE);
 
	#define END_CYCLE(str,len) \
    	end_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE); \
    } \
    cpucycles = (long)(end_cycle - start_cycle)/MAX_ITERATIONS; \
    mbps = len * cpufreq * 8 / cpucycles; \
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
#else
	#define START_CYCLE
	#define END_CYCLE(str,len)
#endif                                                        

#ifdef TEST_CPU_CYCLES
    #define PRINT_HDR \
		if (cvmx_is_init_core()) {\
			printf ("\n\n###################################################\n"); \
        	printf ("Printing CPU cycles for packet length :%u bytes\n",(unsigned int)add_len); \
        	printf ("###################################################\n"); \
		}
#else
    #define PRINT_HDR
#endif






/* CTR DRBG Knonw Answers Test */
typedef struct __ctr_drbg_KAT  
{
    uint32_t entropy_len;                /* EntropyInput Length */
    uint8_t  entropy[BUFF_SIZE];         /* EntropyInput */
    uint8_t  ent_reseed[BUFF_SIZE];      /* EntropyInputReseed */
    uint32_t nonce_len;                  /* Nonce Length */
    uint8_t  nonce[BUFF_SIZE];           /* Nonce */
    uint32_t pstr_len;                   /* PersonalizationString Length */
    uint8_t  pstr[BUFF_SIZE];            /* PersonalizationString */
    uint32_t add_len;                    /* AdditionalInput Length */
    uint8_t  add_inp1[BUFF_SIZE];        /* AdditionalInput */
    uint8_t  add_reseed[BUFF_SIZE];      /* AdditionalInputReseed */
    uint8_t  add_inp2[BUFF_SIZE];        /* AdditionalInput */
    uint32_t random_len;                 /* Returned Random bytes length */
    uint8_t  ReturnedRand[BUFF_SIZE*4];  /* Returned Random bytes */
} ctr_drbg_KAT;

typedef struct ctr_drbg_nist {
	char * entropy_input;
	char * nonce;
	char * pr_str;
	char * entropyinputreseed;
	char * add_in_reseed;
	char * add_input;
	char * add_input1;
	char * ret_bits;
}ctr_drbg_nist_t;


/* CTR_DRBG test vectors from NIST, considered some of the 
 * test cases of AES-256 use df in CTR_DRBG.rsp, where 
 * PredictionResistance is False
 */

# define TOTAL_TEST_VECTORS 16

ctr_drbg_KAT drgb_test_vector[] = {
/* Test Sample #1 */
{
    32, /* Entropy Len */
    /* Entropy */
    "\x5a\x19\x4d\x5e\x2b\x31\x58\x14\x54\xde\xf6\x75\xfb\x79\x58\xfe\xc7\xdb\x87\x3e\x56\x89\xfc\x9d\x03\x21\x7c\x68\xd8\x03\x38\x20",
     /* Entropy Reseed */
    "\xf9\xe6\x5e\x04\xd8\x56\xf3\xa9\xc4\x4a\x4c\xbd\xc1\xd0\x08\x46\xf5\x98\x3d\x77\x1c\x1b\x13\x7e\x4e\x0f\x9d\x8e\xf4\x09\xf9\x2e",
    16,/* Nonce Length */
    /* Nonce */
    "\x1b\x54\xb8\xff\x06\x42\xbf\xf5\x21\xf1\x5c\x1c\x0b\x66\x5f\x3f",
    0, /* PersonalizationString Length */
    "", /* PersonalizationString */
    0, /* Additional Input Length */
    "", /* Additional Input1 */
    "", /* Additional Reseed */
    "", /* Additional Input2 */
    16,
    "\xa0\x54\x30\x3d\x8a\x7e\xa9\x88\x9d\x90\x3e\x07\x7c\x6f\x21\x8f"
},
/* Test Sample #2 */
{
    32, /* Entropy Len */
    /* Entropy */
    "\x93\xb7\x05\x5d\x78\x88\xae\x23\x4b\xfb\x43\x1e\x37\x90\x69\xd0\x0a\xe8\x10\xfb\xd4\x8f\x2e\x06\xc2\x04\xbe\xae\x3b\x0b\xfa\xf0",
     /* Entropy Reseed */
    "\x91\xd1\xd0\xe8\x53\x52\x5e\xad\x0e\x7f\x79\xab\xb0\xf0\xbf\x68\x06\x45\x76\x33\x9c\x35\x85\xcf\xd6\xd9\xb5\x5d\x4f\x39\x27\x8d",
    16,/* Nonce Length */
    /* Nonce */
    "\x90\xbc\x3b\x55\x5b\x9d\x6b\x6a\xeb\x17\x74\xa5\x83\xf9\x8c\xad",
    0, /* PersonalizationString Length */
    "", /* PersonalizationString */
    0, /* Additional Input Length */
    "", /* Additional Input1 */
    "", /* Additional Reseed */
    "", /* Additional Input2 */
    16,
    "\xaa\xf2\x7f\xc2\xbf\x64\xb0\x32\x0d\xd3\x56\x4b\xb9\xb0\x33\x77"
},
/* Test Sample #3 */
{
    32, /* Entropy Len */
    /* Entropy */
    "\xe5\x0c\x31\xeb\xbb\x73\x5c\x4a\x53\xfc\x05\x35\x64\x7a\xe1\xff\xf7\xa5\xac\x4f\xa4\x06\x8b\xa9\x0f\x1f\xa0\x3c\xa4\xdd\xed\xec",
     /* Entropy Reseed */
    "\xd5\xb1\x89\x8d\x5e\x38\x18\x50\x54\xb0\xde\x7e\x34\x80\x34\xb5\x70\x67\xa8\x2a\x47\x8b\x00\x57\xe0\xc4\x6d\xe4\xa7\x28\x0c\xd9",
    16,/* Nonce Length */
    /* Nonce */
    "\x4b\x1e\xdd\x0f\x53\xbf\x4e\x01\x2d\xef\x80\xef\xd7\x40\x14\x0b",
    0, /* PersonalizationString Length */
    "", /* PersonalizationString */
    32, /* Additional Input Length */
    "\xe7\x15\x4e\xc1\xf7\xac\x36\x9d\x0b\xd4\x12\x38\xf6\x03\xb5\x31\x53\x14\xd1\xdc\x82\xf7\x11\x91\xde\x9e\x74\x36\x42\x26\xeb\x09", 
    "\x94\x44\x23\x8b\xd2\x7c\x45\x12\x8a\x25\xd5\x5e\x07\x34\xd3\xad\xaf\xec\xcc\xb2\xc2\x4a\xbd\xaa\x50\xac\x2c\xa4\x79\xc3\x83\x0b", 
    "\xab\x24\x88\xc8\xb7\xe8\x19\xd8\xce\x5e\xc1\xff\xb7\x7e\xfc\x77\x04\x53\x97\x0d\x6b\x85\x2b\x49\x64\x26\xd5\xdb\x05\xc0\x39\x47",
    16,
    "\xa4\x88\xa8\x7c\x04\xeb\x1c\x75\x86\xb8\x14\x1e\xd4\x5e\x77\x61"
},

/* Test Sample #4 */
{
    32, /* Entropy Len */
    /* Entropy */
    "\x5e\x02\x9c\x17\x3d\xc2\x8a\xb1\x98\x51\xa8\xdb\x00\x8e\xfb\xcf\x86\x2f\x41\x87\xfc\xa8\x4e\x4e\x6f\x5b\xa6\x86\xe3\x00\x5d\xba",
     /* Entropy Reseed */
    "\x5b\x95\xc5\xa0\xbc\xf7\x8f\xb3\x5a\xda\x34\x7a\xf5\x8e\xc0\xac\xa0\x9e\xd4\x79\x9c\xd8\xa7\x34\x73\x9f\x3c\x42\x52\x73\xe4\x41",
    16,/* Nonce Length */
    /* Nonce */
    "\x1f\x89\xc9\x14\x64\x9a\xe8\xa2\x34\xc0\xe9\x23\x0f\x34\x60\xf9",
    0, /* PersonalizationString Length */
    "", /* PersonalizationString */
    32, /* Additional Input Length */
    "\xb5\x1f\x5f\xd5\x88\x85\x52\xaf\x0e\x9b\x66\x7c\x27\x50\xc7\x91\x06\xce\x37\xc0\x0c\x85\x0a\xfb\xe3\x77\x67\x46\xd8\xc3\xbc\xe1", 
    "\x9b\x13\x2a\x2c\xbf\xfb\x84\x07\xaa\x06\x95\x4a\xe6\xeb\xee\x26\x5f\x98\x66\x66\x75\x7b\x54\x53\x60\x12\x07\xe0\xcb\xb4\x87\x1b",
    "\xf1\xc4\x35\xe2\xeb\xf0\x83\xa2\x22\x21\x8e\xe4\x60\x22\x63\x87\x2a\x2d\x3e\x09\x7b\x53\x6a\x8c\xc3\x2a\x5a\x22\x20\xb8\x06\x5f",
    16,
    "\xa0\x65\xcc\x20\x38\x81\x25\x4c\xa8\x1b\xd9\x59\x55\x15\xe7\x05"
},

/* Test Sample #5 */
{
    32, /* Entropy Len */
    /* Entropy */
    "\x6a\x08\x73\x63\x40\x94\xbe\x70\x28\xb8\x85\xc3\x45\xcd\x50\x16\x29\x5e\xec\x5e\x52\x4f\x06\x9d\xe6\x51\x0a\xe8\xac\x84\x3d\xba",
     /* Entropy Reseed */
    "\x2c\xc0\x5c\x10\xba\xa8\xaa\xd7\x5e\xac\x8e\x8d\x1a\x85\x70\xf4\xd2\xa3\xcf\x71\x89\x14\xa1\x99\xde\xb3\xed\xf8\xc9\x93\xa8\x22",
    16,/* Nonce Length */
    /* Nonce */
    "\x2e\xa7\x86\x1e\x37\x42\x32\xcb\x8c\xee\xcb\xbd\x9a\x18\xfc\x1f",
    32, /* PersonalizationString Length */
    /* PersonalizationString */
    "\x63\xc3\x1f\x83\x3f\xe3\x94\xf1\xe1\x9c\x8e\xf6\x10\x92\xa5\x6f\x28\x34\x2f\xa5\xb5\x91\xf7\xb9\x51\x58\x3d\x50\xc1\x2e\xf0\x81",
    0, /* Additional Input Length */
    "", /* Additional Input1 */
    "", /* Additional Reseed */
    "", /* Additional Input2 */
    16,
    "\xc0\x08\xf4\x6a\x24\x2a\xe0\xba\xba\xd1\x72\x68\xc9\xe0\x83\x9a"
},

/* Test Sample #6 */
{
    32, /* Entropy Len */
    /* Entropy */
    "\xfa\xe3\xd5\x54\xd1\x2a\x14\xe2\x9d\xe1\xb6\x22\x92\x2f\x27\x55\x95\x59\xca\x15\x18\xc9\xf8\x00\x37\x5a\x37\xa2\x12\xe8\xb9\xa6",
     /* Entropy Reseed */
    "\x53\xcc\x37\x00\x22\x3e\x94\x04\xd5\xbf\x78\x1d\x15\xfc\xcf\x63\x80\x50\xa1\x39\x45\x92\xca\xba\x00\x1c\xfc\x65\xd6\x1e\xf9\x0b",
    16,/* Nonce Length */
    /* Nonce */
    "\xf3\x0a\x18\xd5\x97\xd8\x59\x1a\x22\xde\xe9\x08\xde\x95\xc5\xaf",
    32, /* PersonalizationString Length */
    "\x74\x88\x4b\x02\x5f\x39\xb4\xf6\x70\x7d\x28\x44\x7d\x9d\x0a\x31\x14\xa5\x7b\xc2\xd9\xee\xd8\xe6\x21\xec\x75\xe8\xce\x38\x9a\x16", 
    32, /* Additional Input Length */
    "\x54\x24\x0e\xdd\x89\x01\x6e\xd2\x7e\x3b\xb3\x97\x7a\x20\x68\x36\xf5\xef\x1f\xba\x0f\x00\x0a\xf9\x53\x37\xd7\x9c\xac\xa9\xcf\x71", 
    "\x25\x06\x11\xe5\x18\x52\xd9\x33\xff\x1a\x17\x7b\x50\x9c\x05\xe3\x22\x8c\xb9\xf4\x6d\xfb\x7b\x26\x84\x8a\x68\xaa\xd2\xce\x47\x79", 
    "\xf8\xb6\x02\xd8\x9f\xa1\xa0\xbf\xb3\x1d\x0b\xd4\x92\x46\xb4\x58\x20\x0a\x1a\xdb\x28\xb6\x4a\x68\xf7\xc1\x97\xf3\x35\xd6\x97\x06", 
    16,
    "\x7b\x63\xbf\xb3\x25\xba\xfe\x7d\x9e\xf3\x42\xcd\x14\xea\x40\xa4"
},

/* Test Sample #7 */
{
    32, /* Entropy Len */
    /* Entropy */
    "\x0e\xc7\xc6\x17\xf8\x5b\xec\x74\x04\x41\x11\x02\x0c\x97\x7b\xe3\x2a\xb8\x05\x0b\x32\x6e\xbc\x03\x71\x5b\xbb\xff\xa5\xa3\x46\x22",
     /* Entropy Reseed */
    "\xf2\x26\x4d\x4b\x51\x41\xb7\x88\x32\x81\xc2\x1e\xa9\x19\x81\x15\x5a\x64\xfb\x7b\x90\x2e\x67\x4e\x9a\x41\xa8\xa8\x6c\x32\x05\x2b",
    16,/* Nonce Length */
    /* Nonce */
    "\xea\x1f\x47\xfe\x5e\x28\x11\x36\x70\x64\x19\xea\x9b\x65\x29\x67",
    0, /* PersonalizationString Length */
    "", /* PersonalizationString */
    0, /* Additional Input Length */
    "", /* Additional Input1 */
    "", /* Additional Reseed */
    "", /* Additional Input2 */
    16,
    "\xda\xf7\x5b\x82\x88\xfc\x66\x80\x2b\x23\xaf\x5f\xd0\x4a\x94\x34"
},

/* Test Sample #8 */
{
    32, /* Entropy Len */
    /* Entropy */
    "\xab\x7b\xca\x55\x95\x08\x4b\xcc\xdb\xa8\x0a\xde\x7a\xc3\xdf\x2a\x0c\xe1\x98\xfa\x49\xd2\x94\x14\xc0\x24\x9e\xc3\xd1\xc5\x0d\x27",
     /* Entropy Reseed */
    "\x1c\xa7\x4b\xa5\xc3\x52\x15\x76\xa8\x9a\x19\x64\xe6\xde\xde\xd2\xd5\xba\x7f\xf2\x8a\x36\x4a\x8f\x92\x35\x98\x1b\xec\x1b\xed\xfa",
    16,/* Nonce Length */
    /* Nonce */
    "\x43\x85\x2c\x53\x04\x1a\x3a\x4f\x71\x04\x35\xdb\xd3\xe4\x38\x2b",
    0, /* PersonalizationString Length */
    "", /* PersonalizationString */
    32, /* Additional Input Length */
    "\xc5\x61\x2a\x95\x40\xb6\x4f\xc1\x34\x07\x4c\xb3\x6f\x4c\x9e\xa6\x2f\xff\x99\x39\x38\x70\x9b\x5d\x35\x4a\x91\x7e\x52\x65\xad\xee", 
    "\xee\xe2\x25\x8a\xba\x66\x5a\xa6\xd3\xf5\xb8\xc2\x20\x7f\x13\x52\x76\xf5\x97\xad\xb2\xa0\xfb\xfb\x16\xa2\x04\x60\xe8\xcc\x3c\x68", 
    "\xa6\xd6\xd1\x26\xbe\xd1\x3d\xbc\xf2\xb3\x27\xaa\x88\x4b\x72\x60\xa9\xc3\x88\xcb\x03\x75\x1d\xbe\x9f\xeb\x28\xa3\xfe\x35\x1d\x62", 
    16,
    "\xe0\x4c\x3d\xe5\x1a\x1f\xfe\x8c\xda\x89\xe8\x81\xc3\x96\x58\x4b"
},

/* Test Sample #9 */
{
    32, /* Entropy Len */
    /* Entropy */
    "\xfd\xae\x5f\x1e\xa2\x53\x10\x8f\xcb\x25\x5d\x21\x5a\x3c\xe1\xdc\x1d\x10\x1a\xcf\x89\xde\x44\x23\xb7\x5a\x74\x61\x9e\x95\xf3\xfe",
     /* Entropy Reseed */
    "\xaa\x35\xb5\xe0\xbe\xc4\x30\xb0\xad\x95\x67\xdf\x81\x89\x89\xc3\x6c\x77\x74\x21\x29\xaf\x33\x5c\x90\xce\xb6\xdd\x79\xc7\xd2\xc4",
    16,/* Nonce Length */
    /* Nonce */
    "\xa2\xe4\x45\x29\x0f\xed\x81\x87\xdf\x6d\x2a\x57\xe6\x83\x85\xbb",
    32, /* PersonalizationString Length */
    "\x62\xd7\x00\xcb\x8f\x14\x04\x10\x76\x6b\x53\xe6\x9e\x6a\x0f\x29\x39\xbb\xfa\x7c\xe0\x91\x52\x5c\x90\x51\xf0\x64\xe3\x83\xa2\xe1",
    0, /* Additional Input Length */
    "", /* Additional Input1 */
    "", /* Additional Reseed */
    "", /* Additional Input2 */
    16,
    "\x38\x41\xe2\xd7\x95\xb1\x7c\xb9\xa2\x08\x1d\x60\x16\xa1\xa7\x1d"
},

/* Test Sample #10 */
{
    32, /* Entropy Len */
    /* Entropy */
    "\x77\xbe\xf8\x84\xa9\x11\x26\x56\x4b\x32\x14\x02\x9a\xc6\x84\x2d\x86\xe4\xc1\xfa\x28\x3e\x33\xd6\x82\x8d\x42\x83\x77\x41\x6f\x66",
     /* Entropy Reseed */
    "\x94\x7e\x39\xa4\xa6\x70\x8e\x10\xbf\xda\xe8\x33\x7a\x6f\x30\x24\x20\xa6\x64\x9f\xc1\x09\xd0\xf0\x94\xc1\x8c\x1e\x93\x61\x37\x5a",
    16,/* Nonce Length */
    /* Nonce */
    "\xbc\x88\x54\x54\xe3\x85\xd9\x11\x33\x6d\xda\x9b\x7a\x60\x9a\x6a",
    32, /* PersonalizationString Length */
    "\x70\x79\xa4\xa5\xa8\x60\xfc\xd7\x04\x16\x1c\x34\x65\x8b\xd9\x86\x85\xbb\x03\x41\x8b\x7f\x24\xf2\xed\x94\x75\xeb\x8c\xeb\x23\x2e",
    0, /* Additional Input Length */
    "", /* Additional Input1 */
    "", /* Additional Reseed */
    "", /* Additional Input2 */
    16,
    "\xea\x20\x78\x0e\xd2\x80\xd8\x10\x9f\x81\x1a\x6a\x39\x8c\x3e\x76"
},

/* Test Sample #11 */
{
    32, /* Entropy Len */
    /* Entropy */
    "\x5d\x85\xc5\x6d\x0d\x20\xee\x39\x95\x8a\x90\xf3\x01\xd2\xf8\xbb\x13\x6f\xa3\x4d\x09\xb4\x1a\x0c\x93\x75\x11\x4a\x0d\xf9\xc1\xdc",
     /* Entropy Reseed */
    "\xdb\x2a\x62\xc4\xbe\x39\x8d\x9e\xaf\x24\x40\x94\x9b\x80\x6f\x0e\x5a\x97\x7d\xa6\x08\xee\xb6\x52\xa4\x17\x11\xd1\xe9\xb7\x26\x55",
    16,/* Nonce Length */
    /* Nonce */
    "\x19\xb8\x3c\x0d\xee\xa6\x46\x3a\x39\x12\xd2\x1f\xfc\x8d\x80\x41",
    32, /* PersonalizationString Length */
    "\xa5\xb3\x06\x40\x35\x2a\xbc\x96\x52\x77\x0c\xfc\xa9\x9d\xc5\x3c\x9c\x09\x94\x2d\xdd\x67\xb9\x1f\x4d\xa5\x0a\x86\x15\x46\x2c\xe4",
    32, /* Additional Input Length */
    "\x9c\x1d\xb9\x28\xb9\x5c\x84\xcb\x67\x40\x60\xa6\xd2\xf6\xb7\xa6\xa5\xd4\x3e\x9e\xe9\x67\xe9\xf8\x21\xbf\x30\x9c\xa5\xf8\x82\x1f",
    "\xa3\x11\x1c\xb5\x73\x65\xc6\x17\xdf\x0b\x0b\xb3\xa1\xaa\xda\x49\xca\x78\x9b\xc7\x59\x03\xee\xb2\x1e\x42\xa7\xd3\xd0\xdd\x08\x25", 
    "\xce\x7f\x55\x7c\x70\x67\x69\x87\xd1\x3a\xca\x60\xbc\x45\x85\x14\x7e\xfe\xed\x97\xbe\x13\x98\x71\xa1\xb2\x9c\xaa\x1e\x18\x0a\xf9", 
    16,
    "\x4a\x49\x43\x02\x77\xd6\x44\x46\xe2\xfa\x75\x76\x3e\xb7\x9e\xc6"
},

/* Test Sample #12 */
{
    32, /* Entropy Len */
    /* Entropy */
    "\x28\xe5\x92\xfd\x9d\xb7\x2b\x40\xae\x48\x88\x07\x8a\xed\xde\x26\x0f\x6d\xe4\xf0\x47\x2a\x76\x01\x25\x8e\x69\x4d\x7b\xb6\xaf\x68",
     /* Entropy Reseed */
    "\x10\xff\x4e\xab\xdf\xfb\x33\x29\x32\x76\x5f\xa1\xd6\x66\x50\xfb\x78\xcc\x2b\xe4\x84\xc0\xba\x80\x3e\xb9\xa2\x50\x20\x20\xe8\x65",
    16,/* Nonce Length */
    /* Nonce */
    "\x01\x30\x21\x7d\x4a\x39\x45\x40\x2e\xd9\x9d\x7b\x85\x04\xfe\x4b",
    0, /* PersonalizationString Length */
    "", /* PersonalizationString */
    0, /* Additional Input Length */
    "", /* Additional Input1 */
    "", /* Additional Reseed */
    "", /* Additional Input2 */
    16,
    "\x46\x52\xf0\x54\x53\x85\xfd\xbe\x02\xd0\x5a\xec\x21\x66\x86\x08"
},

/* Test Sample #13 */
{
    32, /* Entropy Len */
    /* Entropy */
    "\xbe\x67\x43\x4a\xc4\xd7\x7f\x0f\x50\xec\x5b\xac\xc8\x11\x2d\x14\x80\xbd\x9f\x20\xd6\xb4\xea\x76\x8d\x9b\x51\xbb\x69\xc1\xdf\xfc",
     /* Entropy Reseed */
    "\xd8\xc3\x0e\x44\x12\x12\x76\x44\xaa\xa6\xfc\x45\x3e\x59\xfb\x63\x3f\x6a\x5a\x8c\x2f\x69\xe4\x0d\x18\x63\xe3\x5d\x4d\x4c\x02\x27",
    16,/* Nonce Length */
    /* Nonce */
    "\x5e\xf9\x7f\x7a\xf7\xdf\x5c\xc6\xfa\x94\xf8\x42\x8e\xc7\xbe\x5c",
    0, /* PersonalizationString Length */
    "", /* PersonalizationString */
    32, /* Additional Input Length */
    "\xa6\x41\x95\xb1\xe5\x6c\xf9\x7f\xd8\x1e\x99\xfa\x18\x33\xd1\x91\xfa\xf6\x2f\x53\x4c\x87\x4d\xef\x4b\x8b\xed\x0a\xe7\x19\x5a\xc7", 
    "\x35\x3c\xd3\xa8\xd9\xcd\x92\xbc\xe8\x2c\xd8\xd1\xcc\x19\x8b\xaa\x92\x76\xdb\x47\x8b\x0c\xfe\x50\x24\x9e\x30\xc3\x04\x2e\xe9\xdb",
    "\x39\x3a\xb4\x72\x6f\x08\x8f\xdf\xeb\x4d\xf7\x52\xe1\xb2\xae\xc6\x78\xe4\x1f\xa6\x07\x81\xbc\x5e\x91\x42\x96\x22\x7d\x6b\x3d\xfc",
    16,
    "\x24\xbd\xc2\xca\xd5\xdc\xcd\x23\x09\x42\x5f\x11\xa2\x4c\x8c\x39"
},

/* Test Sample #14 */
{
    32, /* Entropy Len */
    /* Entropy */
    "\x1d\x0d\xd1\xa8\x7d\x59\xc6\x9f\x28\xe1\x18\xe1\x08\x3d\x65\xf1\xee\x0d\xf3\x1f\x63\x08\xa9\x2d\xcc\x47\x50\x3e\xc4\xd2\x0a\x01",
     /* Entropy Reseed */
    "\x8d\x98\x21\xc6\xa7\xd6\x43\x85\x72\x4f\x0e\x94\x12\x31\x42\x6e\x02\x8e\xfe\x6d\x75\xe5\x3f\xf8\xed\xf0\x95\xef\x1b\xaf\x26\x56",
    16,/* Nonce Length */
    /* Nonce */
    "\xa5\x3c\x18\x13\xc0\x6b\x60\x9e\xff\x9d\xdc\x77\x20\x4b\x08\x5c",
    32, /* PersonalizationString Length */
    "\xa9\x85\xf2\x21\x70\xb8\xec\xfc\xbb\xf4\x5e\xa1\x1c\x45\xc2\x4f\xcf\x25\xbc\x33\x15\x0f\x9f\x97\xce\x48\x24\x4d\x5b\xeb\x68\x5c",
    0, /* Additional Input Length */
    "", /* Additional Input1 */
    "", /* Additional Reseed */
    "", /* Additional Input2 */
    16,
    "\x03\x5c\xec\x3a\x24\xba\x7c\x44\xe5\xc1\x94\x36\xc2\x68\x9a\x75"
},

/* Test Sample #15 */
{
    32, /* Entropy Len */
    /* Entropy */
    "\xda\x5f\x9b\x2d\xb1\x3d\x05\x55\x84\x6c\x00\xda\x96\x11\x50\x36\xbb\x75\xac\xe6\x6d\x56\xfc\x58\x2d\x6c\xd0\x17\x1e\x3e\x23\x33",
     /* Entropy Reseed */
    "\x5c\x5c\x2b\x86\x91\xe5\x8a\xf8\x89\x9e\xd0\x20\x43\x16\x47\x9f\x84\x9c\xa6\xf4\x73\x09\xca\xe5\x71\xcc\xb4\x2d\x3d\x35\xc1\x66",
    16,/* Nonce Length */
    /* Nonce */
    "\xd4\x45\xa3\xd9\x33\x2c\x85\x77\x71\x5c\x1e\x93\xf1\x19\x52\x1b",
    32, /* PersonalizationString Length */
    "\xd3\x1a\x46\x4d\xb0\x8c\xdb\xd7\x3d\x50\x08\x0d\x62\xd5\xa4\x8f\xba\x4c\xef\x2d\xd0\x97\xec\x74\x99\x73\x03\x7e\x33\xe8\xd6\xfa", 
    32, /* Additional Input Length */
    "\x79\x34\x63\x94\xf7\x95\xf0\x5c\x5a\x51\x99\x42\x36\x49\xb8\xb5\x34\x53\x55\xef\x11\xeb\x42\x39\xdb\x1c\x76\x7c\x68\xaf\xa7\x0a", 
    "\xc2\x28\x10\xde\x99\x87\xb2\x28\xc1\x96\x80\xeb\x04\x4d\xa2\x2a\x08\x03\x21\x48\xa6\x01\x5f\x35\x88\x49\xd6\xd6\x08\xa2\x14\xb9", 
    "\x77\x47\xd6\x8c\xa8\xbc\xb4\x39\x31\xf1\xed\xce\x4f\x8c\x97\x27\xdd\x56\xc1\xd1\xd2\x60\x0a\xd1\xfb\x76\x7e\xb4\xfb\xc7\xb2\xd6", 
    16,
    "\xf5\xc4\x0b\xab\xbe\xc9\x7c\xb6\x0b\xa6\x52\x00\xe8\x2d\x7a\x68"
},

/* Test Sample #16 */
{
    32, /* Entropy Len */
    /* Entropy */
    "\xd6\x63\xd2\xcf\xcd\xdf\x40\xff\x61\x37\x7c\x38\x11\x26\x6d\x92\x7a\x5d\xfc\x7b\x73\xcf\x54\x9e\x67\x3e\x5a\x15\xf4\x05\x6a\xd1",
     /* Entropy Reseed */
    "\xf9\x73\x3c\x8e\xd8\x75\xff\x77\x92\x82\x84\xdc\x1c\xdb\x33\xac\xcc\x47\x97\x1d\x36\x26\x61\x5a\x45\xb9\xa1\x6d\x9b\xaf\x42\x6e",
    16,/* Nonce Length */
    /* Nonce */
    "\x27\x28\xbe\x06\x79\x6e\x2a\x77\xc6\x0a\x40\x17\x52\xcd\x36\xe4",
    32, /* PersonalizationString Length */
    "\xa0\x51\x72\x4a\xa3\x27\x6a\x14\x6b\x4b\x35\x10\x17\xee\xe7\x9c\x82\x57\x39\x8c\x61\x2f\xc1\x12\x9c\x0e\x74\xec\xef\x45\x5c\xd3", 
    32, /* Additional Input Length */
    "\x62\x34\x9e\xfb\xac\x4a\x47\x47\xd0\xe9\x27\x27\xc6\x7a\x6b\xc7\xf8\x40\x4c\xf7\x46\x00\x2e\x7d\x3e\xef\xfb\x9a\x9b\xe0\xbb\xdc", 
    "\x38\x1c\x0c\xff\xbd\xfa\x61\xa6\xaf\x3f\x11\xcc\xd0\xe5\x43\x20\x8b\x58\x4c\x3f\x52\x01\x30\xe3\x36\x17\x56\x4e\xc7\xa4\x8c\xf7", 
    "\x69\x74\x04\x33\x62\xf8\x34\xfd\x79\x3d\xe0\x7c\xee\xbd\x05\x15\x99\x16\x3d\x50\x48\x94\x41\x00\x5a\xfc\x9d\xb0\x9a\x9a\xb4\x4f", 
    16,
    "\xdf\x78\x94\x74\x6c\x59\x9e\x02\xd9\x85\xb1\x95\xca\x3b\x48\x63"
},

};

ctr_drbg_nist_t ctr_drbg [] = {
	{
		"c2a150932af1eb7028b67e2bce659a8bbc42e501b3df3e3b5fd02d085fb28f6d",
		"ba9fcb9de3d1d7a54731a10c5714c8ef",
		"52cb80ca786829b3fcd35a635eb043c43548869c7ac226e415a1b267a77fb19d",
		"6e584c2d5a971d77b5d9fc62dc103e622384c511d2831d7a5e4cd6a8eb372270",
		"55e5cd16ffeb595b2c144fc832a73abf6d41e2e175bfa3a1a06a090ab962aece",
		"12c8165e2eab3b7a82a231b30096799ac9b62ae146c5274b87a4a1dada1dce36",
		"e649783afd9900b379a373ed0654914c679073c4852f38efbd36ed6f6959bc85",
		"1ff307d99cc3cf2bbc085a9a9fc56d4636f5fae94caba1d487c574d42c8958de3f706812b04086ebd082a8a09c0db9d938878fbf09a82f34786377d216bce75b"
	},
	{
		"02a402dec987862c7fa9a97b5c0613794a60d1052629babe34ae03cde28720f0",
		"403561aa360bcc99d90b5e31eb0476e2",
		"e33ed03cfb1c326975a2e1173ce67a4dc7d2fff09a48758d0196bd69091bb1cd",
		"d1e70cacff290d64b60509b8b0a4ee4035fc0f6e9902c062f81232f1309d8ff2",
		"aa1ac40132f003f14bbdfef20a8c03d1fc3c6bff2034bae1254afa58e4ef5391",
		"dd4e9bfae6eab9060c8fcea6edc4a77acfd6d1399988aefc14fddacb61e4be67",
		"b3d29e22754dd9027defd7b256446327d5bfa6900e69449b99cbb307051bdd69",
		"e6ceb53f5ec834d58b39dcb09c16be0d94bf9f038609065facf5d4eadca891c4dd25dfc3ee44b6305c6b8baf1104a62ccf11db27f72c80424ed87250ac25de3c"
		
	}
};


