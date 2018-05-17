
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
	#define PRINT_HDR \
		if(cvmx_is_init_core()) {\
			printf ("\n\n###################################################\n"); \
        	printf ("Printing CPU cycles for packet length :%u bytes\n", inlen ); \
        	printf ("###################################################\n");\
		}
#else
    #define PRINT_HDR
#endif

#ifdef TEST_CPU_CYCLES
	#define START_CYCLE  \
 	start_cycle = end_cycle = 0;  \
 	sysinfo = cvmx_sysinfo_get();\
	for (iter = 0; iter < MAX_ITERATIONS; iter++) {  \
     	start_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE);
	
	#define END_CYCLE(str) \
    	end_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE); \
 	} \
    cpucycles = (long)(end_cycle - start_cycle)/MAX_ITERATIONS; \
    mbps = inlen * cpufreq * 8 / cpucycles; \
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
#define END_CYCLE(str)
#endif
/* 
  These test vectors are taken from 
 "3GPP TS 35.203 V3.1.1 (2001-07)" document 
*/

typedef struct __F8TestVectors {
	uint8_t key[16];
	uint32_t count;
	uint8_t bearer;
	uint8_t direction;
	uint32_t length;
	uint8_t plaintext[1024];
	uint8_t ciphertext[1024];
} F8TestVectors;

F8TestVectors f8_test[] = {
	// Test Vector #1
	{
	"\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48",
	0x72A4F20F,
	0x0C,
	0x1,
	798,
	"\x7E\xC6\x12\x72\x74\x3B\xF1\x61\x47\x26\x44\x6A\x6C\x38\xCE\xD1\x66\xF6\xCA\x76\xEB\x54\x30\x04\x42\x86\x34\x6C\xEF\x13\x0F\x92\x92\x2B\x03\x45\x0D\x3A\x99\x75\xE5\xBD\x2E\xA0\xEB\x55\xAD\x8E\x1B\x19\x9E\x3E\xC4\x31\x60\x20\xE9\xA1\xB2\x85\xE7\x62\x79\x53\x59\xB7\xBD\xFD\x39\xBE\xF4\xB2\x48\x45\x83\xD5\xAF\xE0\x82\xAE\xE6\x38\xBF\x5F\xD5\xA6\x06\x19\x39\x01\xA0\x8F\x4A\xB4\x1A\xAB\x9B\x13\x48\x80",
	"\xD1\xE2\xDE\x70\xEE\xF8\x6C\x69\x64\xFB\x54\x2B\xC2\xD4\x60\xAA\xBF\xAA\x10\xA4\xA0\x93\x26\x2B\x7D\x19\x9E\x70\x6F\xC2\xD4\x89\x15\x53\x29\x69\x10\xF3\xA9\x73\x01\x26\x82\xE4\x1C\x4E\x2B\x02\xBE\x20\x17\xB7\x25\x3B\xBF\x93\x09\xDE\x58\x19\xCB\x42\xE8\x19\x56\xF4\xC9\x9B\xC9\x76\x5C\xAF\x53\xB1\xD0\xBB\x82\x79\x82\x6A\xDB\xBC\x55\x22\xE9\x15\xC1\x20\xA6\x18\xA5\xA7\xF5\xE8\x97\x08\x93\x39\x65\x0F"
	},

	// Test Vector #2
	{
	"\xEF\xA8\xB2\x22\x9E\x72\x0C\x2A\x7C\x36\xEA\x55\xE9\x60\x56\x95",
	0xE28BCF7B,
	0x18,
	0x0,
	510,
	"\x10\x11\x12\x31\xE0\x60\x25\x3A\x43\xFD\x3F\x57\xE3\x76\x07\xAB\x28\x27\xB5\x99\xB6\xB1\xBB\xDA\x37\xA8\xAB\xCC\x5A\x8C\x55\x0D\x1B\xFB\x2F\x49\x46\x24\xFB\x50\x36\x7F\xA3\x6C\xE3\xBC\x68\xF1\x1C\xF9\x3B\x15\x10\x37\x6B\x02\x13\x0F\x81\x2A\x9F\xA1\x69\xD8",
	"\x3D\xEA\xCC\x7C\x15\x82\x1C\xAA\x89\xEE\xCA\xDE\x9B\x5B\xD3\x61\x4B\xD0\xC8\x41\x9D\x71\x03\x85\xDD\xBE\x58\x49\xEF\x1B\xAC\x5A\xE8\xB1\x4A\x5B\x0A\x67\x41\x52\x1E\xB4\xE0\x0B\xB9\xEC\xF3\xE9\xF7\xCC\xB9\xCA\xE7\x41\x52\xD7\xF4\xE2\xA0\x34\xB6\xEA\x00\xEC"
	},

	// Test Vector #3
	{
	"\x5A\xCB\x1D\x64\x4C\x0D\x51\x20\x4E\xA5\xF1\x45\x10\x10\xD8\x52",
	0xFA556B26,
	0x03,
	0x1,
	120,
	"\xAD\x9C\x44\x1F\x89\x0B\x38\xC4\x57\xA4\x9D\x42\x14\x07\xE8",
	"\x9B\xC9\x2C\xA8\x03\xC6\x7B\x28\xA1\x1A\x4B\xEE\x5A\x0C\x25"
	},

	// Test Vector #4
	{
	"\xD3\xC5\xD5\x92\x32\x7F\xB1\x1C\x40\x35\xC6\x68\x0A\xF8\xC6\xD1",
	0x398A59B4,
	0x05,
	0x1,
	253,
	"\x98\x1B\xA6\x82\x4C\x1B\xFB\x1A\xB4\x85\x47\x20\x29\xB7\x1D\x80\x8C\xE3\x3E\x2C\xC3\xC0\xB5\xFC\x1F\x3D\xE8\xA6\xDC\x66\xB1\xF0",
	"\x5B\xB9\x43\x1B\xB1\xE9\x8B\xD1\x1B\x93\xDB\x7C\x3D\x45\x13\x65\x59\xBB\x86\xA2\x95\xAA\x20\x4E\xCB\xEB\xF6\xF7\xA5\x10\x15\x12"
	},

	// Test Vector #5
	{
	"\x60\x90\xEA\xE0\x4C\x83\x70\x6E\xEC\xBF\x65\x2B\xE8\xE3\x65\x66",
	0x72A4F20F,
	0x09,
	0x0,
	837,
	"\x40\x98\x1B\xA6\x82\x4C\x1B\xFB\x42\x86\xB2\x99\x78\x3D\xAF\x44\x2C\x09\x9F\x7A\xB0\xF5\x8D\x5C\x8E\x46\xB1\x04\xF0\x8F\x01\xB4\x1A\xB4\x85\x47\x20\x29\xB7\x1D\x36\xBD\x1A\x3D\x90\xDC\x3A\x41\xB4\x6D\x51\x67\x2A\xC4\xC9\x66\x3A\x2B\xE0\x63\xDA\x4B\xC8\xD2\x80\x8C\xE3\x3E\x2C\xCC\xBF\xC6\x34\xE1\xB2\x59\x06\x08\x76\xA0\xFB\xB5\xA4\x37\xEB\xCC\x8D\x31\xC1\x9E\x44\x54\x31\x87\x45\xE3\x98\x76\x45\x98\x7A\x98\x6F\x2C\xB0",
	"\xDD\xB3\x64\xDD\x2A\xAE\xC2\x4D\xFF\x29\x19\x57\xB7\x8B\xAD\x06\x3A\xC5\x79\xCD\x90\x41\xBA\xBE\x89\xFD\x19\x5C\x05\x78\xCB\x9F\xDE\x42\x17\x56\x61\x78\xD2\x02\x40\x20\x6D\x07\xCF\xA6\x19\xEC\x05\x9F\x63\x51\x44\x59\xFC\x10\xD4\x2D\xC9\x93\x4E\x56\xEB\xC0\xCB\xC6\x0D\x4D\x2D\xF1\x74\x77\x4C\xBD\xCD\x5D\xA4\xA3\x50\x31\x7A\x7F\x12\xE1\x94\x94\x71\xF8\xA2\x95\xF2\x72\xE6\x8F\xC0\x71\x59\xB0\x7D\x8E\x2D\x26\xE4\x59\x9E"
	}
};

typedef struct __F9TestVectors {
	uint8_t   key[16];
	uint32_t  count;
	uint32_t  fresh;
	uint8_t   direction;
	uint32_t  length;
	uint8_t   message[1024];
	uint32_t  expected_mac; 
} F9TestVectors;

F9TestVectors f9_test[] = {
	// Test Vector #1
	{
	"\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48",
	0x38A6F056,
	0x05D2EC49,
	0x0,
	189,
	"\x6B\x22\x77\x37\x29\x6F\x39\x3C\x80\x79\x35\x3E\xDC\x87\xE2\xE8\x05\xD2\xEC\x49\xA4\xF2\xD8\xE0",
	0xF63BD72C
	},

	// Test Vector #2
	{
	"\xD4\x2F\x68\x24\x28\x20\x1C\xAF\xCD\x9F\x97\x94\x5E\x6D\xE7\xB7",
	0x3EDC87E2,
	0xA4F2D8E2,
	0x1,
	254,
	"\xB5\x92\x43\x84\x32\x8A\x4A\xE0\x0B\x73\x71\x09\xF8\xB6\xC8\xDD\x2B\x4D\xB6\x3D\xD5\x33\x98\x1C\xEB\x19\xAA\xD5\x2A\x5B\x2B\xC0",
	0xA9DAF1FF
	},

	// Test Vector #3
	{
	"\xFD\xB9\xCF\xDF\x28\x93\x6C\xC4\x83\xA3\x18\x69\xD8\x1B\x8F\xAB",
	0x36AF6144,
	0x9838F03A,
	0x01,
	319,
	"\x59\x32\xBC\x0A\xCE\x2B\x0A\xBA\x33\xD8\xAC\x18\x8A\xC5\x4F\x34\x6F\xAD\x10\xBF\x9D\xEE\x29\x20\xB4\x3B\xD0\xC5\x3A\x91\x5C\xB7\xDF\x6C\xAA\x72\x05\x3A\xBF\xF2",
	0x1537D316
	},

	// Test Vector #4
	{
	"\xC7\x36\xC6\xAA\xB2\x2B\xFF\xF9\x1E\x26\x98\xD2\xE2\x2A\xD5\x7E",
	0x14793E41,
	0x0397E8FD,
	0x01,
	384,
	"\xD0\xA7\xD4\x63\xDF\x9F\xB2\xB2\x78\x83\x3F\xA0\x2E\x23\x5A\xA1\x72\xBD\x97\x0C\x14\x73\xE1\x29\x07\xFB\x64\x8B\x65\x99\xAA\xA0\xB2\x4A\x03\x86\x65\x42\x2B\x20\xA4\x99\x27\x6A\x50\x42\x70\x09",
	0xDD7DFADD
	},

	// Test Vector #5
	{
	"\xF4\xEB\xEC\x69\xE7\x3E\xAF\x2E\xB2\xCF\x6A\xF4\xB3\x12\x0F\xFD",
	0x296F393C,
	0x6B227737,
	0x01,
	1000,
	"\x10\xBF\xFF\x83\x9E\x0C\x71\x65\x8D\xBB\x2D\x17\x07\xE1\x45\x72\x4F\x41\xC1\x6F\x48\xBF\x40\x3C\x3B\x18\xE3\x8F\xD5\xD1\x66\x3B\x6F\x6D\x90\x01\x93\xE3\xCE\xA8\xBB\x4F\x1B\x4F\x5B\xE8\x22\x03\x22\x32\xA7\x8D\x7D\x75\x23\x8D\x5E\x6D\xAE\xCD\x3B\x43\x22\xCF\x59\xBC\x7E\xA8\x4A\xB1\x88\x11\xB5\xBF\xB7\xBC\x55\x3F\x4F\xE4\x44\x78\xCE\x28\x7A\x14\x87\x99\x90\xD1\x8D\x12\xCA\x79\xD2\xC8\x55\x14\x90\x21\xCD\x5C\xE8\xCA\x03\x71\xCA\x04\xFC\xCE\x14\x3E\x3D\x7C\xFE\xE9\x45\x85\xB5\x88\x5C\xAC\x46\x06\x8B",
	0xC383839D
	},
};

/*
static void hex_print (uint8_t *buff, uint32_t len)
{
	uint32_t cnt = 0;
	for (cnt = 0; cnt < len; cnt++)  {
		if ((cnt % 16) == 0)  printf ("\n");
			printf ("%02x ", buff[cnt]);
	}
	printf ("\n");
}
*/


