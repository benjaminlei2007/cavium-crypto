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
	static int iter;
	unsigned int core;
	extern uint32_t numcores;
	cvmx_sysinfo_t *sysinfo;
#endif


#ifdef TEST_CPU_CYCLES
	uint64_t tps ;
	#define START_CYCLE  \
    	start_cycle = end_cycle = 0;  \
 		sysinfo = cvmx_sysinfo_get();\
		start_cycle = cvmx_clock_get_count (CVMX_CLOCK_CORE); \
		for (iter = 0; iter < MAX_ITERATIONS; iter++) {  

	#define END_CYCLE(str)  \
    	} \
    	end_cycle = cvmx_clock_get_count (CVMX_CLOCK_CORE); \
    	cpucycles = (long)(end_cycle - start_cycle)/MAX_ITERATIONS; \
    	tps = cpufreq * 1000000 / cpucycles; \
 		for (core = 0; core < CVMX_MAX_CORES; core++) {\
			if (cvmx_coremask_is_core_set(&sysinfo->core_mask, core) && core == cvmx_get_core_num()){ \
				total_cpucycles+=cpucycles;\
				total_tps +=tps;\
			}\
			cvmx_coremask_barrier_sync(&sysinfo->core_mask);\
		}\
		cvmx_coremask_barrier_sync(&sysinfo->core_mask);\
		if(cvmx_is_init_core()){\
 			printf ("API :%-20s total tps :%-10lu average values per core    cpucycles :%lu tps :%lu\n", str, total_tps, (total_cpucycles/numcores), (total_tps/numcores));\
			total_cpucycles = 0;\
			total_tps = 0;\
		}
#else
#define START_CYCLE
#define END_CYCLE(str)
#endif

#undef ASSYMETRIC

typedef struct nist_rsa {
	char * hash;
	int mod_len;
	char * msg;
} nist_rsa_t;

nist_rsa_t rsa_nist [] = {
	{
		"SHA1",
		1024,
		"3e472dab0ff8ef2b8209beefe228e81f86dd20b3570521898c8194b4b82f341807193034c4edd03e1fae5c752ea83ab331a956411a6ec7f04d5caf65a47162b5b679cb3259850c84659965fbbba5572386b60999c16eea1efab298ea55a20142d3cec84dd4a6ea24db33a128920588980e6d006353ecd33a1bea18ead3ab57e9"
	},
	{
		"SHA224",
		2048,
		"74230447bcd492f2f8a8c594a04379271690bf0c8a13ddfc1b7b96413e77ab2664cba1acd7a3c57ee5276e27414f8283a6f93b73bd392bd541f07eb461a080bb667e5ff095c9319f575b3893977e658c6c001ceef88a37b7902d4db31c3e34f3c164c47bbeefde3b946bad416a752c2cafcee9e401ae08884e5b8aa839f9d0b5"
	},
	{
		"SHA256",
		3072,
		"bcf6074333a7ede592ffc9ecf1c51181287e0a69363f467de4bf6b5aa5b03759c150c1c2b23b023cce8393882702b86fb0ef9ef9a1b0e1e01cef514410f0f6a05e2252fd3af4e566d4e9f79b38ef910a73edcdfaf89b4f0a429614dabab46b08da94405e937aa049ec5a7a8ded33a338bb9f1dd404a799e19ddb3a836aa39c77"
	}


};


typedef struct nist_dsa {
	char * hash;
	int mod_len;
	char * msg;
} nist_dsa_t;
nist_dsa_t dsa_nist [] = {
	{
		"SHA1",
		1024,
		"3b46736d559bd4e0c2c1b2553a33ad3c6cf23cac998d3d0c0e8fa4b19bca06f2f386db2dcff9dca4f40ad8f561ffc308b46c5f31a7735b5fa7e0f9e6cb512e63d7eea05538d66a75cd0d4234b5ccf6c1715ccaaf9cdc0a2228135f716ee9bdee7fc13ec27a03a6d11c5c5b3685f51900b1337153bc6c4e8f52920c33fa37f4e7"
	},
	{
		"SHA224",
		2048,
		"503f2042358f7e414296ab2d41f3a1f3f11182eca6c82b2ae6ee833dd737bcb34691793e30110036ae54d403a5ea45cbf3e5515bbf80b1af139853f506792df7ff5235995e080f82b562326adaf321159adeef20388024509f225e8c5235368a7b045d69e472e6b2ad7d470a11f6aa8d4ca6c6cdb0f3ed4e06fb9a95e2cf200c",
	},
	{
		"SHA256",
		3072,
		"b216a035b0ff29feaf7d4c34eeb1604155c90338006753ee2b36062d72f62b524504659f70b976c68952a62c2b9a2a00cf0066a5e5098a632df2ee56dd1a140a98f7b3ac12db3576b610d76563e4621637da1098aa20f3c83247b7278860417cecf7e137194cf1bae12bbc63a7bae02c906d503f694dea3bd534718e37704962"
	}

};
