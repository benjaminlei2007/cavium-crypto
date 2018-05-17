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
#include <stdint.h>
#include <stdlib.h>
#include <openssl/fips_random.h>
#include "cvmx.h"
#include "cvmx-rng.h"
#include <test-crypto-common.h>
#include <test-drbg-api.h>

#define personalisation_string_len 768
#define additional_input_len 654
#define entropy_input_reseed_len 768
#define additional_input_reseed_len 654
#define additional1_input_len 654
#define LINE_SIZE 6500

#define CVM_DRBG_RAND_LEN 64

#ifdef TEST_CPU_CYCLES
	extern uint32_t numcores;
	extern CVMX_SHARED uint64_t total_cpucycles;
	extern CVMX_SHARED uint64_t total_mbps;	
#endif
	
int Personalisation_string_len,Entropy_len,Nonce_len,Additional_input_len,
	Entropy_input_reseed_len,Additional_input_reseed_len,Additional1_input_len,ret_rand_len;

#define DUMP_BUFF(str_,buf_,len_) \
{ \
	int i; \
	printf("%s",(str_)); \
	for (i=0;i<(len_);i++){ \
	  printf( "%02x ",(buf_)[i]); \
	  if(i && ((i%8) == 7)) printf("\n"); \
   } \
}

static void str2hex(char* str, unsigned char* hex, int* len)
{
	unsigned char h[3];
	int i,j;

	/* remove newline */
	if (strlen(str))  {
		*len = strlen(str);
	}
	*len = ((*len)>>1);
	
	for (i=0,j=0;i<*len;i++) {
		h[0] = str[j++];
		h[1] = str[j++];
		hex[i] = (unsigned char)strtoul((const char *)h, NULL, 16);
	}
}

static void hex2str(char* str, uint8_t* hex, int len)
{
	int i,j;

	for (i=0,j=0;i<len;i++,j+=2)
		sprintf(&str[j],"%02x",hex[i]);
}


int test_drbg_kat() {
	uint8_t entropy_input[700];
	uint8_t nonce[16];
	uint8_t personalisation_string[personalisation_string_len];
	uint8_t additional_input[additional_input_len];
	uint8_t entropy_input_reseed[entropy_input_reseed_len];
	uint8_t additional_input_reseed[additional_input_reseed_len];
	uint8_t additional1_input[additional1_input_len];
	uint8_t ret_rand[400];
	unsigned int i, fail = 0;
	ctr_drbg_state_t *ds = NULL;

	int ret = 0;
	uint8_t res[CVM_DRBG_RAND_LEN];
	uint8_t res1[2*CVM_DRBG_RAND_LEN+1];
 ds = (ctr_drbg_state_t*)malloc(sizeof(ctr_drbg_state_t));
	memset (ds, 0x0, sizeof(ds));
	for (i = 0;i < sizeof ctr_drbg / sizeof (ctr_drbg[0]);i++) { 
			str2hex(ctr_drbg[i].entropy_input, entropy_input, &Entropy_len);
			str2hex(ctr_drbg[i].nonce, nonce, &Nonce_len);
			str2hex(ctr_drbg[i].pr_str, personalisation_string, &Personalisation_string_len);
			str2hex(ctr_drbg[i].add_input, additional_input, &Additional_input_len);
			str2hex(ctr_drbg[i].entropyinputreseed, entropy_input_reseed, &Entropy_input_reseed_len);
			str2hex(ctr_drbg[i].add_in_reseed, additional_input_reseed, &Additional_input_reseed_len);
			str2hex(ctr_drbg[i].add_input1, additional1_input, &Additional1_input_len);
			str2hex(ctr_drbg[i].ret_bits, ret_rand, &ret_rand_len);
			ret = ctr_drbg_df_instantiate(entropy_input, 
					Entropy_len,
					nonce, 
					16,
					personalisation_string, 
					Personalisation_string_len,
					ds);

			if (ret) {
				printf("\n instantiate:Exiting\n");
			}

			ret = ctr_drbg_df_generate(ds, 
					ret_rand_len, 
					additional_input, 
					Additional_input_len, 
					(uint8_t *)&res);
			if (ret) {
				printf("\n 1st generate :Exiting\n");
			}

			ret = ctr_drbg_df_reseed(entropy_input_reseed, 
					Entropy_input_reseed_len, 
					additional_input_reseed, 
					Additional_input_reseed_len, 
					ds);
			if (ret) {
				printf("return value is %d",ret);
				printf("\n Reseed :Exiting\n");
			}

			ret = ctr_drbg_df_generate(ds, 
					ret_rand_len,
					additional1_input, 
					Additional1_input_len, 
					(uint8_t *)&res);
			if (ret) {
				printf("\n 2nd generate :Exiting\n");
			}
			memset(&res1, 0, 2*CVM_DRBG_RAND_LEN+1);
			hex2str((char *)&res1, (unsigned char*)&res, CVM_DRBG_RAND_LEN);
			if (memcmp (res1,ctr_drbg[i].ret_bits,CVM_DRBG_RAND_LEN)) {
				printf ("DRBG Failed \n");
				fail++;
			}
		}
	if (fail)
		printf("***");
		if (cvmx_is_init_core()) {
			printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","DRBG",i,(i-fail),fail);
		}
	return 0;
}

int drbg()
{
	int i, ret = 0;
	uint8_t res[BUFF_SIZE*4];

	ctr_drbg_state_t *ds = NULL;
	if ((ds = (ctr_drbg_state_t*)malloc(sizeof(ctr_drbg_state_t))) == NULL)
	{
		perror ("malloc");
		return -1;
	}

	for (i = 0; i < TOTAL_TEST_VECTORS; i++)
	{
		/* Consider each test vector from Known Answers Test */
		ctr_drbg_KAT *drbg_tv = &drgb_test_vector[i];

		/* CTR_DRBG Instantiate */
		ret = ctr_drbg_df_instantiate(drbg_tv->entropy, 
					 drbg_tv->entropy_len,
					 drbg_tv->nonce,
					 drbg_tv->nonce_len,
					 drbg_tv->pstr,
					 drbg_tv->pstr_len,
					 ds);	
		if (ret) {
			printf("\n instantiate:Exiting\n");
		}
		/* CTR_DRBG Generate */
		ret = ctr_drbg_df_generate(ds, 
					 drbg_tv->random_len, 
					 drbg_tv->add_inp1, 
					 drbg_tv->add_len, 
					 (uint8_t *)res);
		if (ret) {
			printf("\n 1st generate :Exiting\n");
		}

		/* CTR_DRBG Reseed */
		ret = ctr_drbg_df_reseed(drbg_tv->ent_reseed, 
					 drbg_tv->entropy_len, 
					 drbg_tv->add_reseed, 
					 drbg_tv->add_len, 
					 ds);
		if (ret) {
			printf("return value is %d",ret);
			printf("\n Reseed :Exiting\n");
		}

		/* CTR_DRBG Generate */
		ret = ctr_drbg_df_generate(ds, 
					 drbg_tv->random_len,
					 drbg_tv->add_inp2, 
					 drbg_tv->add_len, 
					 (uint8_t *)res);
		if (ret) {
			printf("\n 2nd generate :Exiting\n");
		}

		/* Compare result with Known Answer */
		if(memcmp(res, drbg_tv->ReturnedRand, drbg_tv->random_len)) {
			printf ("DRBG test vector [%d] Mismatch\n", i);
			printf ("Expected: \n");
			hex_print (drbg_tv->ReturnedRand, drbg_tv->random_len);
			printf ("Actual: \n");
			hex_print (res, drbg_tv->random_len);
			ret = -1;
			goto End;
		}
		   
	}

{
	# define SIZE 2048
	/* Entropy */
	uint8_t entropy[SIZE] = "\xd6\x63\xd2\xcf\xcd\xdf\x40\xff\x61\x37\x7c\x38\x11\x26\x6d\x92\x7a\x5d\xfc\x7b\x73\xcf\x54\x9e\x67\x3e\x5a\x15\xf4\x05\x6a\xd1";
	 /* Entropy Reseed */
	uint32_t nonce_len = 16; /* Nonce Length */
	/* Nonce */
	uint8_t nonce[16] = "\x27\x28\xbe\x06\x79\x6e\x2a\x77\xc6\x0a\x40\x17\x52\xcd\x36\xe4";
	uint32_t pstr_len = 32; /* PersonalizationString Length */
	uint8_t pstr[SIZE] = "\xa0\x51\x72\x4a\xa3\x27\x6a\x14\x6b\x4b\x35\x10\x17\xee\xe7\x9c\x82\x57\x39\x8c\x61\x2f\xc1\x12\x9c\x0e\x74\xec\xef\x45\x5c\xd3";
	uint32_t add_len= 32; /* Additional Input Length */
	uint8_t add_inp1[SIZE]="\x62\x34\x9e\xfb\xac\x4a\x47\x47\xd0\xe9\x27\x27\xc6\x7a\x6b\xc7\xf8\x40\x4c\xf7\x46\x00\x2e\x7d\x3e\xef\xfb\x9a\x9b\xe0\xbb\xdc";

	uint32_t rand_bytes=16;
	uint32_t ent_len=32;  /* Entropy Len */

	/* Making Entropy and Personalized strings are constants */
	ent_len=32; pstr_len=32;
	for (add_len = START_ADD_SIZE; add_len <= MAX_ADD_SIZE; add_len*=2)
	{
	ret = ctr_drbg_df_instantiate(entropy,ent_len,
					 nonce, nonce_len, pstr, pstr_len, ds);	
		if (ret) {
			printf("\n instantiate:Exiting\n");
			ret = -1;
		}
	PRINT_HDR;
	START_CYCLE;
		ret = ctr_drbg_df_generate(ds, rand_bytes, add_inp1, 
				add_len, (uint8_t *)res);
	END_CYCLE("ctr_drbg_df_generate",add_len);
		if (ret) {
			printf("\n 1st generate :Exiting\n");
			ret = -1;
		}
	}

}
End:
	if (ret == -1 ) {
		printf("DRBG test Failed at Line:%d\n",__LINE__);
	} 
	else { 
		if (cvmx_is_init_core()) {
			printf ("Tested %-20s : Add Length from %d to %d : %s\n","DRBG",
						START_ADD_SIZE,MAX_ADD_SIZE,(ret==0)?"Passed":"Failed");
		}
	}
	
	return 0;
}
