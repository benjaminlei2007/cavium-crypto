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




#define CHUNK_SIZE      8
#define START_DATA_SIZE        256
#define MAX_DATA_SIZE          (1024)

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
	#define START_CYCLE  \
    	start_cycle = end_cycle = 0;  \
    	start_cycle = cvmx_clock_get_count (CVMX_CLOCK_CORE); \
 		sysinfo = cvmx_sysinfo_get();\
		for (iter = 0; iter < MAX_ITERATIONS; iter++) {  

		#define END_CYCLE(str) \
     	} \
     	end_cycle = cvmx_clock_get_count (CVMX_CLOCK_CORE); \
     	cpucycles = (end_cycle - start_cycle)/MAX_ITERATIONS; \
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
		
		#define END_CYCLE_AES(str,keylen) \
 		} \
    	end_cycle += cvmx_clock_get_count (CVMX_CLOCK_CORE); \
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
    #define START_CYCLE 
    #define END_CYCLE(inlen) 
	#define END_CYCLE_AES(str,keylen)
#endif

#if 0
#ifdef TEST_CPU_CYCLES
    #define PRINT_HDR(str)  \
        printf ("\n\n######### %s CPU Cycles #########\n", str);
#else
    #define PRINT_HDR(str)
#endif
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
    #define CHECK_RESULT(str) 
#else
    #define CHECK_RESULT(str) \
        printf ("Result of %-15s : %s\n", str, (ret==0)?"Passed":"Failed");
#endif
	char *evp_hash[] = {
		"EVP_MD5",
		"EVP_SHA1",
		"EVP_SHA224",
		"EVP_SHA256",
		"EVP_SHA384",
		"EVP_SHA512"
	};

typedef struct sha1_nist {
	int len;
	char * hash;
	char * msg;
	char * digest;
}sha1_nist_t;

const sha1_nist_t sha_nist [] = {
	{
		1304,
		"SHA1",
		"7c9c67323a1df1adbfe5ceb415eaef0155ece2820f4d50c1ec22cba4928ac656c83fe585db6a78ce40bc42757aba7e5a3f582428d6ca68d0c3978336a6efb729613e8d9979016204bfd921322fdd5222183554447de5e6e9bbe6edf76d7b71e18dc2e8d6dc89b7398364f652fafc734329aafa3dcd45d4f31e388e4fafd7fc6495f37ca5cbab7f54d586463da4bfeaa3bae09f7b8e9239d832b4f0a733aa609cc1f8d4",
		"d8fd6a91ef3b6ced05b98358a99107c1fac8c807"
	},
	{
		1304,
		"SHA224",
		"f149e41d848f59276cfddd743bafa9a90e1ee4a263a118142b33e3702176ef0a59f8237a1cb51b42f3ded6b202d9af0997898fdd03cf60bda951c514547a0850cec25444ae2f24cb711bfbafcc3956c941d3de69f155e3f8b10f06db5f37359b772ddd43e1035a0a0d3db33242d5843033833b0dd43b870c6bf60e8deab55f317cc3273f5e3ba747f0cb65050cb7228796210d9254873643008d45f29cfd6c5b060c9a",
		"9db6dc3a23abd7b6c3d72c38f4843c7de48a71d0ba91a86b18393e5f"
	},
	{
		1304,
		"SHA256",
		"451101250ec6f26652249d59dc974b7361d571a8101cdfd36aba3b5854d3ae086b5fdd4597721b66e3c0dc5d8c606d9657d0e323283a5217d1f53f2f284f57b85c8a61ac8924711f895c5ed90ef17745ed2d728abd22a5f7a13479a462d71b56c19a74a40b655c58edfe0a188ad2cf46cbf30524f65d423c837dd1ff2bf462ac4198007345bb44dbb7b1c861298cdf61982a833afc728fae1eda2f87aa2c9480858bec",
		"3c593aa539fdcdae516cdf2f15000f6634185c88f505b39775fb9ab137a10aa2"
	},
	#if 0 
	{
		710,
		"SHA1",
		"6cb70d19c096200f9249d2dbc04299b0085eb068257560be3a307dbd741a3378ebfa03fcca610883b07f7fea563a866571822472dade8a0bec4b98202d47a344312976a7bcb3964427eacb5b0525db22066599b81be41e5adaf157d925fac04b06eb6e01deb753babf33be16162b214e8db017212fafa512cdc8c0d0a15c10f632e8f4f47792c64d3f026004d173df50cf0aa7976066a79a8d78deeeec951dab7cc90f68d16f786671feba0b7d269d92941c4f02f432aa5ce2aab6194dcc6fd3ae36c8433274ef6b1bd0d314636be47ba38d1948343a38bf9406523a0b2a8cd78ed6266ee3c9b5c60620b308cc6b3a73c6060d5268a7d82b6a33b93a6fd6fe1de55231d12c97",
		"4a75a406f4de5f9e1132069d66717fc424376388"
	},
	#endif 

	{
		1816,
		"SHA384",
		"62c6a169b9be02b3d7b471a964fc0bcc72b480d26aecb2ed460b7f50016ddaf04c51218783f3aadfdff5a04ded030d7b3fb7376b61ba30b90e2da921a4470740d63fb99fa16cc8ed81abaf8ce4016e50df81da832070372c24a80890aa3a26fa675710b8fb718266249d496f313c55d0bada101f8f56eeccee4345a8f98f60a36662cfda794900d12f9414fcbdfdeb85388a814996b47e24d5c8086e7a8edcc53d299d0d033e6bb60c58b83d6e8b57f6c258d6081dd10eb942fdf8ec157ec3e75371235a8196eb9d22b1de3a2d30c2abbe0db7650cf6c7159bacbe29b3a93c92100508",
		"0730e184e7795575569f87030260bb8e54498e0e5d096b18285e988d245b6f3486d1f2447d5f85bcbe59d5689fc49425"
	},
	{
		1816,
		"SHA512",
		"4f05600950664d5190a2ebc29c9edb89c20079a4d3e6bc3b27d75e34e2fa3d02768502bd69790078598d5fcf3d6779bfed1284bbe5ad72fb456015181d9587d6e864c940564eaafb4f2fead4346ea09b6877d9340f6b82eb1515880872213da3ad88feba9f4f13817a71d6f90a1a17c43a15c038d988b5b29edffe2d6a062813cedbe852cde302b3e33b696846d2a8e36bd680efcc6cd3f9e9a4c1ae8cac10cc5244d131677140399176ed46700019a004a163806f7fa467fc4e17b4617bbd7641aaff7ff56396ba8c08a8be100b33a20b5daf134a2aefa5e1c3496770dcf6baa4f7bb",
		"a9db490c708cc72548d78635aa7da79bb253f945d710e5cb677a474efc7c65a2aab45bc7ca1113c8ce0f3c32e1399de9c459535e8816521ab714b2a6cd200525"
	}

};

typedef struct sha_monte {
	char * hash;
	char * seed;
	char * exp1;
	char * exp2;
	char * exp3;
}sha_monte_t;

const sha_monte_t monte [] = {
	{
		"SHA1",
		"dd4df644eaf3d85bace2b21accaa22b28821f5cd",
		"11f5c38b4479d4ad55cb69fadf62de0b036d5163",
		"5c26de848c21586bec36995809cb02d3677423d9",
		"453b5fcf263d01c891d7897d4013990f7c1fb0ab"
	},
	{
		"SHA224",
		"ed2b70d575d9d0b4196ae84a03eed940057ea89cdd729b95b7d4e6a5",
		"cd94d7da13c030208b2d0d78fcfe9ea22fa8906df66aa9a1f42afa70",
		"555846e884633639565d5e0c01dd93ba58edb01ee18e68ccca28f7b8",
		"44d5f4a179b33231f24cc209ed2542ddb931391f2a2d604f80ed460b"
	},
	{
		"SHA256",
		"6d1e72ad03ddeb5de891e572e2396f8da015d899ef0e79503152d6010a3fe691",
		"e93c330ae5447738c8aa85d71a6c80f2a58381d05872d26bdd39f1fcd4f2b788",
		"2e78f8c8772ea7c9331d41ed3f9cdf27d8f514a99342ee766ee3b8b0d0b121c0",
		"d6a23dff1b7f2eddc1a212f8a218397523a799b07386a30692fd6fe9d2bf0944"
	},
	{
		"SHA384",
		"edff07255c71b54a9beae52cdfa083569a08be89949cbba73ddc8acf429359ca5e5be7a673633ca0d9709848f522a9df",
		"e81b86c49a38feddfd185f71ca7da6732a053ed4a2640d52d27f53f9f76422650b0e93645301ac99f8295d6f820f1035",
		"1d6bd21713bffd50946a10c39a7742d740e8f271f0c8f643d4c95375094fd9bf29d89ee61a76053f22e44a4b058a64ed",
		"425167b66ae965bd7d68515b54ebfa16f33d2bdb2147a4eac515a75224cd19cea564d692017d2a1c41c1a3f68bb5a209"
	},
	{
		"SHA512",
		"5c337de5caf35d18ed90b5cddfce001ca1b8ee8602f367e7c24ccca6f893802fb1aca7a3dae32dcd60800a59959bc540d63237876b799229ae71a2526fbc52cd",
		"ada69add0071b794463c8806a177326735fa624b68ab7bcab2388b9276c036e4eaaff87333e83c81c0bca0359d4aeebcbcfd314c0630e0c2af68c1fb19cc470e",
		"ef219b37c24ae507a2b2b26d1add51b31fb5327eb8c3b19b882fe38049433dbeccd63b3d5b99ba2398920bcefb8aca98cd28a1ee5d2aaf139ce58a15d71b06b4",
		"c3d5087a62db0e5c6f5755c417f69037308cbce0e54519ea5be8171496cc6d18023ba15768153cfd74c7e7dc103227e9eed4b0f82233362b2a7b1a2cbcda9daf"
	}
	
};

typedef struct hmac_nist {
	char * evp;
	unsigned int klen;
	unsigned int tlen;
	char * key;
	char * msg;
	char * mac;
}hmac_nist_t;

const hmac_nist_t hmac_nist [] = {
	{
		"L=20",
		10,
		10,
		"82f3b69a1bff4de15c33",
		"fcd6d98bef45ed6850806e96f255fa0c8114b72873abe8f43c10bea7c1df706f10458e6d4e1c9201f057b8492fa10fe4b541d0fc9d41ef839acff1bc76e3fdfebf2235b5bd0347a9a6303e83152f9f8db941b1b94a8a1ce5c273b55dc94d99a171377969234134e7dad1ab4c8e46d18df4dc016764cf95a11ac4b491a2646be1",
		"1ba0e66cf72efc349207"
	},
	{
		"L=28",
		50,
		14,
		"3714707839daf79122c782416351385e88a81d31c9f641d8dce538e90e63c95892a2ea9b1962ed0ba372f48e9474aa730ae2",
		"411843a21387846f3b9ed5fc545acadfa5b70386f62da4d9a27b041beea3aa1199367567b4d11a4fb4e8d46bc6c256ed62c505fd23f4645bd6b6cf45d1d96d9b86d6604157573ec5acf6c5414348ca83c81a736ca6faa6961cfac13993b08c502f816cf7a420d9184b51114675f30ee9ff3db69c264853d39dcd42c1dd31ef79",
		"33f17ac8a5c6b525db8b8644b6ab"
	},
	{
		"L=32",
		40,
		16,
		"6f35628d65813435534b5d67fbdb54cb33403d04e843103e6399f806cb5df95febbdd61236f33245",
		"752cff52e4b90768558e5369e75d97c69643509a5e5904e0a386cbe4d0970ef73f918f675945a9aefe26daea27587e8dc909dd56fd0468805f834039b345f855cfe19c44b55af241fff3ffcd8045cd5c288e6c4e284c3720570b58e4d47b8feeedc52fd1401f698a209fccfa3b4c0d9a797b046a2759f82a54c41ccd7b5f592b",
		"05d1243e6465ed9620c9aec1c351a186"
	},
	{
		"L=48",
		50,
		24,
		"f16ad73790ca39c7f9856c4483202e7f8e0c8283c7d50d6da79cc07d3dc7b76c2ef76100fa3ae2df8083b5a1c5579628f1c8",
		"9870007654ebc3d28f883bb832e0b31700f923d9c9b10168e0605971cfb920e848f1c64c5f240a2cf7f412ea7a73bbbfce432eff84fbb49e52cdcbf4c36679bd2d16e064e4311381adb528a0752c8e4443d4a12b6cfe7cd406b40e3f9e9e71f42e27764649db85d99913a4628bd5d5ae49f6a5e6e9810211e35d4ddac929b093",
		"79e24a203bf42074e72c8b4a0222aface3e8ce7b4004cec2"
	},
	{
		"L=64",
		100,
		32,
		"726374c4b8df517510db9159b730f93431e0cd468d4f3821eab0edb93abd0fba46ab4f1ef35d54fec3d85fa89ef72ff3d35f22cf5ab69e205c10afcdf4aaf11338dbb12073474fddb556e60b8ee52f91163ba314303ee0c910e64e87fbf302214edbe3f2",
		"ac939659dc5f668c9969c0530422e3417a462c8b665e8db25a883a625f7aa59b89c5ad0ece5712ca17442d1798c6dea25d82c5db260cb59c75ae650be56569c1bd2d612cc57e71315917f116bbfa65a0aeb8af7840ee83d3e7101c52cf652d2773531b7a6bdd690b846a741816c860819270522a5b0cdfa1d736c501c583d916",
		"bd3d2df6f9d284b421a43e5f9cb94bc4ff88a88243f1f0133bad0fb1791f6569"

	}

};
