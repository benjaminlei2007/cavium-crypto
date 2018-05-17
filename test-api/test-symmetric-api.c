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


#include "cvmx.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/rc4.h>
#include "cvmx-rng.h"
#include "test-crypto-common.h"
#include "test-symmetric-api.h"
#include <openssl/bio.h>

#ifdef TEST_CPU_CYCLES
	extern uint32_t numcores;
	extern CVMX_SHARED uint64_t total_cpucycles;
	extern CVMX_SHARED uint64_t total_mbps;		
#endif

#define DUMP_BUFF(str_,buf_,len_) \
{ \
	int i; \
	printf("%s",(str_)); \
	for (i=0;i<(len_);i++){ \
		printf( "%02x ",(buf_)[i]); \
		if(i && ((i%8) == 7)) printf("\n"); \
	} \
}

#define XOR(r,a,b,len) \
{ int i; \
	for (i=0; i<(len); i++) \
	(r)[i] = (a)[i] ^ (b)[i]; \
}
#define IS_ODD(x) \
({	uint8_t y; \
	y = (x) ^ ((x) >> 1); \
	y = y ^ (y >> 2); \
	y = y ^ (y >> 4); \
	(y&1); }) 

#define SET_ODD(x) \
{	if ((x) & 1) (x) &= ~1; \
	else (x) |= 1; }

typedef enum {AES_128 = 0, AES_192 = 1, AES_256 = 2} AesType;

static void str2hex(char* str, uint8_t* hex, int* len)
{
	uint8_t h[3];
	int i,j;

	/* remove newline */
	*len = strlen(str);
	*len = ((*len)>>1);

	for (i=0,j=0;i<*len;i++) {
		h[0] = str[j++];
		h[1] = str[j++];
		hex[i] = (uint8_t)strtoul((const char *)h, NULL, 16);
	}
}

int MonteCarloDesEcbDecrypt(uint8_t key[24], int mode, uint8_t C[8],int n,int* cnt)
{
	unsigned int i;
	int j,len,fail=0;
	uint8_t *k1, *k2, *k3;
	uint8_t p[8]; 
	uint8_t p_j_minus_1[8]; 
	uint8_t p_j_minus_2[8]; 
	uint8_t exp[20];
	des_key_schedule ks1, ks2, ks3;

	k1 = key;
	k2 = key+8;
	k3 = key+16;
	for (i=0; i<(sizeof des_ecb_monte_dec/sizeof des_ecb_monte_dec [0])/3; i++) {
		for (j=0; j<10000; j++) {
			 memcpy(p_j_minus_2,p_j_minus_1,8);
			 memcpy(p_j_minus_1,p,8);
	
	
			 DES_set_key_unchecked ((const_DES_cblock *) k1, &ks1);
			 DES_set_key_unchecked ((const_DES_cblock *) k2, &ks2);
			 DES_set_key_unchecked ((const_DES_cblock *) k3, &ks3);
			 DES_ecb3_encrypt ((const_DES_cblock *)C, (DES_cblock *)p, 
							   &ks1, &ks2, &ks3, DES_DECRYPT);
	
			 memcpy(C,p,8);
		}
	
		str2hex(des_ecb_monte_dec[n++].plain,exp,&len);
		if (memcmp (exp,p,len)) {
			printf("Monte Carlo DES ECB Decrypt failed\n");
			DUMP_BUFF("Expected\n",exp,len);
			DUMP_BUFF("Actual\n",p,len);
			fail++;
		} 
		  XOR(k1,k1,p,8);
	
		if ((mode == 2) || (mode == 3))
		{
			 XOR(k2,k2,p_j_minus_1,8);
		}
		else
		{
			 XOR(k2,k2,p,8);
		}
	
		if ((mode == 1) || (mode == 2))
		{
			 XOR(k3,k3,p,8);
		}
		else
		{
			 XOR(k3,k3,p_j_minus_2,8);
		}
	
		memcpy(C,p,8);
		(*cnt)++;
	}
	return fail;
}




int MonteCarloDesCbcDecrypt(uint8_t key[24], uint8_t cv[8], int mode, 
						  uint8_t C[8],int n, int * cnt )
{
	unsigned int i;
	int j,len,fail=0;
	uint8_t *k1, *k2, *k3;
	uint8_t p[8]; 
	uint8_t p_j_minus_1[8]; 
	uint8_t p_j_minus_2[8];
	uint8_t exp[20]; 
	des_key_schedule ks1, ks2, ks3;
	k1 = key;
	k2 = key+8;
	k3 = key+16;

	for (i=0; i<(sizeof des_cbc_monte_dec/ sizeof des_cbc_monte_dec [0])/3; i++) {
		for (j=0; j<10000; j++) {
			 memcpy(p_j_minus_2,p_j_minus_1,8);
			 memcpy(p_j_minus_1,p,8);
			 DES_set_key_unchecked ((const_DES_cblock *) k1, &ks1);
			 DES_set_key_unchecked ((const_DES_cblock *) k2, &ks2);
			 DES_set_key_unchecked ((const_DES_cblock *) k3, &ks3);
			 DES_ede3_cbc_encrypt (C, p, 8, &ks1, &ks2, &ks3,
								  (DES_cblock *) cv, DES_DECRYPT);
	
			 memcpy(cv,C,8);
			 memcpy(C,p,8);
	
		}
		memset (exp,0x00,20);
		str2hex(des_cbc_monte_dec[n++].plain,exp,&len);
		if (memcmp (exp,p,len)) {
			printf("Monte Carlo DES CBC Decrypt failed %d\n",n-1);
			DUMP_BUFF("Expected\n",exp,len);
			DUMP_BUFF("Actual\n",p,len);
			fail++;
		} 
		XOR(k1,k1,p,8);
	
		if ((mode == 2) || (mode == 3))
		{
			 XOR(k2,k2,p_j_minus_1,8);
		}
		else
		{
			 XOR(k2,k2,p,8);
		}
	
		if ((mode == 1) || (mode == 2))
		{
			 XOR(k3,k3,p,8);
		}
		else
		{
			 XOR(k3,k3,p_j_minus_2,8);
		}
		(*cnt)++;
	}
 return fail;
}

int MonteCarloDesCbcEncrypt(uint8_t key[24], uint8_t cv[8], int mode, 
						uint8_t p[8],int n, int * cnt)
{
	unsigned int i;
	int j,len,fail=0;
	uint8_t *k1, *k2, *k3;
	uint8_t C[8]; 
	uint8_t C_j_minus_1[8]; 
	uint8_t C_j_minus_2[8]; 
	uint8_t exp[20];
	des_key_schedule ks1, ks2, ks3;
	uint8_t cv_tmp[8];
	k1 = key;
	k2 = key+8;
	k3 = key+16;

	for (i=0; i<(sizeof des_cbc_monte_enc/sizeof des_cbc_monte_enc [0])/3 ; i++) {
		for (j=0; j<10000; j++) {
			memcpy(C_j_minus_2,C_j_minus_1,8);
			memcpy(C_j_minus_1,C,8);

			DES_set_key_unchecked ((const_DES_cblock *) k1, &ks1);
			DES_set_key_unchecked ((const_DES_cblock *) k2, &ks2);
			DES_set_key_unchecked ((const_DES_cblock *) k3, &ks3);
			memcpy (cv_tmp, cv, 8);

			DES_ede3_cbc_encrypt (p, C, 8, &ks1, &ks2, &ks3,(DES_cblock *) cv, 
								DES_ENCRYPT);

			if (j == 0)
				memcpy(p,cv_tmp,8);
			else
				memcpy(p,C_j_minus_1,8);
			memcpy(cv,C,8);
		}

		str2hex(des_cbc_monte_enc[n++].cipher,exp,&len);
	if (memcmp (exp,C,len)) {
		printf("Monte Carlo Des Cbc Encrypt failed\n");
		DUMP_BUFF("Expected\n",exp,len);
		DUMP_BUFF("Actual\n",C,len);
		fail++;
	} 
	XOR(k1,k1,C,8);

		if ((mode == 2) || (mode == 3)) {
			XOR(k2,k2,C_j_minus_1,8);
		}
		else {
			XOR(k2,k2,C,8);
		}

		if ((mode == 1) || (mode == 2)) {
			XOR(k3,k3,C,8);
		}
		else {
			XOR(k3,k3,C_j_minus_2,8);
		}

		memcpy(p,C_j_minus_1,8);
		memcpy(cv,C,8);
		(*cnt)++;
	 }
	 return fail;
}


int MonteCarloDesEcbEncrypt(uint8_t key[24], int mode, uint8_t p[8],int n,int * cnt)
{
	unsigned int i;
	int j,len,fail=0;
	uint8_t *k1, *k2, *k3;
	uint8_t C[8]; 
	uint8_t C_j_minus_1[8]; 
	uint8_t C_j_minus_2[8];
	uint8_t exp[20]; 
	des_key_schedule ks1, ks2, ks3;
	k1 = key;
	k2 = key+8;
	k3 = key+16;

	for (i=0; i<(sizeof des_ecb_monte_enc/ sizeof des_ecb_monte_enc [0])/3; i++) {
		for (j=0; j<10000; j++) {
			 memcpy(C_j_minus_2,C_j_minus_1,8);
			memcpy(C_j_minus_1,C,8);

			DES_set_key_unchecked ((const_DES_cblock *) k1, &ks1);
			DES_set_key_unchecked ((const_DES_cblock *) k2, &ks2);
			DES_set_key_unchecked ((const_DES_cblock *) k3, &ks3);
			DES_ecb3_encrypt ((const_DES_cblock *)p, (DES_cblock *)C, &ks1, 
									 &ks2, &ks3, DES_ENCRYPT);
				memcpy (p,C,8);
		}
		 

	str2hex(des_ecb_monte_enc[n++].cipher,exp,&len);
	if (memcmp (exp,C,len)) {
		printf("Monte Carlo Des Ecb Encrypt failed\n");
		DUMP_BUFF("Expected\n",exp,len);
		DUMP_BUFF("Actual\n",C,len);
		fail++;	
	}	
	 XOR(k1,k1,C,8);

	 if ((mode == 2) || (mode == 3)) {
		 XOR(k2,k2,C_j_minus_1,8);
	 }
	 else {
		 XOR(k2,k2,C,8);
	 }

	 if ((mode == 1) || (mode == 2)) {
		 XOR(k3,k3,C,8);
	 }
	 else {
		 XOR(k3,k3,C_j_minus_2,8);
	 }

	 memcpy(p,C,8);
	 (*cnt)++;
	}
	return fail;
}

int test_3des_cbc_kat()
{
	uint8_t iv[8];
	uint8_t key[24];
	uint8_t in_text[40];
	uint8_t out_text[40];
	int len;
	unsigned int i;
	int mode=0,fail=0,cnt=0;
	des_key_schedule ks1, ks2, ks3;
	uint8_t *k1, *k2, *k3;
	for (i=0;i<sizeof (des_cbc_enc)/sizeof (des_cbc_enc[0]);i++) { 
		memset (key, 0, sizeof (key));
		memset (iv, 0, sizeof (iv));
		memset (in_text, 0, sizeof (in_text));
		memset (out_text, 0, sizeof (out_text));
		str2hex(des_cbc_enc[i].key,key,&len);
		memmove(key+8,key,8);
		memmove(key+16,key,8);
		k1 = key;
		k2 = key+8;
		k3 = key+16;
	
		str2hex(des_cbc_enc[i].iv,iv,&len);
		str2hex(des_cbc_enc[i].plain,in_text,&len);
		DES_set_key_unchecked ((const_DES_cblock *) k1, &ks1);
		DES_set_key_unchecked ((const_DES_cblock *) k2, &ks2);
		DES_set_key_unchecked ((const_DES_cblock *) k3, &ks3);
		DES_ede3_cbc_encrypt (in_text, out_text, len, &ks1,
								&ks2, &ks3,(DES_cblock *) iv,
									 DES_ENCRYPT);
		str2hex(des_cbc_enc[i].cipher,in_text,&len);
		if (memcmp (in_text,out_text,len)) {
			printf("3des cbc failed\n");
			fail++;
		}
		cnt++;
	}
	for (i=0;i<sizeof (des_cbc_dec)/sizeof (des_cbc_dec[0]);i++) { 
		memset (key,0,sizeof (key));
		memset (iv,0,sizeof (iv));
		memset (in_text,0,sizeof (in_text));
		memset (out_text,0,sizeof (out_text));
		str2hex(des_cbc_dec[i].key,key,&len);
		memmove(key+8,key,8);
		memmove(key+16,key,8);
		k1 = key;
		k2 = key+8;
		k3 = key+16;
	
		str2hex(des_cbc_dec[i].iv,iv,&len);
		str2hex(des_cbc_dec[i].cipher,in_text,&len);
		DES_set_key_unchecked ((const_DES_cblock *) k1, &ks1);
		DES_set_key_unchecked ((const_DES_cblock *) k2, &ks2);
		DES_set_key_unchecked ((const_DES_cblock *) k3, &ks3);
		DES_ede3_cbc_encrypt (in_text, out_text, len, &ks1,
								&ks2, &ks3,(DES_cblock *) iv,
									 DES_DECRYPT);
		str2hex(des_cbc_dec[i].plain,in_text,&len);
		if (memcmp (in_text,out_text,len)) {
			printf("3des cbc failed\n");
			fail++;
		}
		cnt++;
	}
	// Monte carlo encrypt
	for (i=0;i<sizeof (des_cbc_monte_enc)/sizeof (des_cbc_monte_enc[0]);i=i+3) { 
		memset (key,0,sizeof (key));
		memset (iv,0,sizeof (iv));
		memset (in_text,0,sizeof (in_text));
		memset (out_text,0,sizeof (out_text));
		str2hex(des_cbc_monte_enc[i].key1,key,&len);
		str2hex(des_cbc_monte_enc[i].key2,key+8,&len);
		str2hex(des_cbc_monte_enc[i].key3,key+16,&len);
		k1 = key;
		k2 = key+8;
		k3 = key+16;
		if (!memcmp (des_ecb_monte_enc[i].monte,"Monte1",7)) {
			mode = 1;
		}
		if (!memcmp (des_ecb_monte_enc[i].monte,"Monte2",7)) {
			mode = 2;
		}
		if (!memcmp (des_ecb_monte_enc[i].monte,"Monte3",7)) {
			mode = 3;
		}
		str2hex(des_cbc_monte_enc[i].iv,iv,&len);
		str2hex(des_cbc_monte_enc[i].plain,in_text,&len);
		fail = MonteCarloDesCbcEncrypt (key,iv,mode, in_text,i,&cnt);
		}
	// Monte carlo Decrypt
	for (i=0;i<sizeof (des_cbc_monte_dec)/sizeof (des_cbc_monte_dec[0]);i=i+3) { 
		memset (key,0,sizeof (key));
		memset (iv,0,sizeof (iv));
		memset (in_text,0,sizeof (in_text));
		memset (out_text,0,sizeof (out_text));
		str2hex(des_cbc_monte_dec[i].key1,key,&len);
		str2hex(des_cbc_monte_dec[i].key2,key+8,&len);
		str2hex(des_cbc_monte_dec[i].key3,key+16,&len);
		k1 = key;
		k2 = key+8;
		k3 = key+16;
		if (!memcmp (des_ecb_monte_enc[i].monte,"Monte1",7)) {
			mode = 1;
		}
		if (!memcmp (des_ecb_monte_enc[i].monte,"Monte2",7)) {
			mode = 2;
		}
		if (!memcmp (des_ecb_monte_enc[i].monte,"Monte3",7)) {
			mode = 3;
		}
	
		str2hex(des_cbc_monte_dec[i].iv,iv,&len);
		str2hex(des_cbc_monte_dec[i].cipher,in_text,&len);
		fail =fail +MonteCarloDesCbcDecrypt (key,iv,mode, in_text,i,&cnt);
	}
	if (fail)
		printf("***");
	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d passed : %d failed : %d\n","3DES-CBC",cnt,(cnt-fail),fail);

	return 0;
}



int test_3des_ecb_kat()
{
	uint8_t key[24];
	uint8_t in_text[40];
	uint8_t out_text[40];
	int len;
	unsigned int i;
	int mode =0, j, fail=0, cnt=0;
	des_key_schedule ks1, ks2, ks3;
	uint8_t *k1, *k2, *k3;
	for (i=0;i<sizeof (des_ecb_enc)/sizeof (des_ecb_enc[0]);i++) { 
	// 3DES ENCRYPT
		memset (key, 0, sizeof (key));
		memset (in_text, 0, sizeof (in_text));
		memset (out_text, 0, sizeof (out_text));
		str2hex(des_ecb_enc[i].key,key,&len);
		memmove(key+8,key,8);
		memmove(key+16,key,8);
		k1 = key;
		k2 = key+8;
		k3 = key+16;
	
		str2hex(des_ecb_enc[i].plain,in_text,&len);
		DES_set_key_unchecked ((const_DES_cblock *) k1, &ks1);
		DES_set_key_unchecked ((const_DES_cblock *) k2, &ks2);
		DES_set_key_unchecked ((const_DES_cblock *) k3, &ks3);
		for (j = 0; j < len; j += 8) {
			DES_ecb3_encrypt ((const_DES_cblock *)&in_text[j],
							 (DES_cblock *)&out_text[j], &ks1,
								 &ks2, &ks3, DES_ENCRYPT);
	
		}
	
		str2hex(des_ecb_enc[i].cipher,in_text,&len);
		if (memcmp (in_text,out_text,len)) {
			printf("3des ecb failed\n");
			DUMP_BUFF("OUT TEXT\n",out_text,16);
			DUMP_BUFF("IN TEXT\n",in_text,16);
			fail++;
		}
		cnt++;
	
	}
	
	// 3DES DECRYPT
	for (i=0;i<sizeof (des_ecb_dec)/sizeof (des_ecb_dec[0]);i++) { 
		memset (key,0,sizeof (key));
		memset (in_text,0,sizeof (in_text));
		memset (out_text,0,sizeof (out_text));
		str2hex(des_ecb_dec[i].key,key,&len);
		memmove(key+8,key,8);
		memmove(key+16,key,8);
		k1 = key;
		k2 = key+8;
		k3 = key+16;
	
		str2hex(des_ecb_dec[i].cipher,in_text,&len);
		DES_set_key_unchecked ((const_DES_cblock *) k1, &ks1);
		DES_set_key_unchecked ((const_DES_cblock *) k2, &ks2);
		DES_set_key_unchecked ((const_DES_cblock *) k3, &ks3);
		for (j = 0; j < len; j += 8) {
			DES_ecb3_encrypt ((const_DES_cblock *)&in_text[j],
							 (DES_cblock *)&out_text[j], &ks1,
								 &ks2, &ks3, DES_DECRYPT);
	
		}
		str2hex(des_ecb_dec[i].plain,in_text,&len);
		if (memcmp (in_text,out_text,len)) {
			printf("3des cbc failed\n");
			fail++;
		}
	
		cnt++;
	}
	// Monte carlo Encrypt
	for (i=0;i<sizeof (des_ecb_monte_enc)/sizeof (des_ecb_monte_enc[0]);i=i+3) { 
		memset (key,0,sizeof (key));
		memset (in_text,0,sizeof (in_text));
		memset (out_text,0,sizeof (out_text));
		str2hex(des_ecb_monte_enc[i].key1,key,&len);
		str2hex(des_ecb_monte_enc[i].key2,key+8,&len);
		str2hex(des_ecb_monte_enc[i].key3,key+16,&len);
		k1 = key;
		k2 = key+8;
		k3 = key+16;
	
		if (!memcmp (des_ecb_monte_enc[i].monte,"Monte1",7)) {
			mode = 1;
		}
		if (!memcmp (des_ecb_monte_enc[i].monte,"Monte2",7)) {
			mode = 2;
		}
		if (!memcmp (des_ecb_monte_enc[i].monte,"Monte3",7)) {
			mode = 3;
		}
	
		str2hex(des_ecb_monte_enc[i].plain,in_text,&len);
		fail =fail +MonteCarloDesEcbEncrypt (key, mode, in_text,i,&cnt);
		}
	// Monte carlo Decrypt
	
	for (i=0;i<sizeof (des_ecb_monte_dec)/sizeof (des_ecb_monte_dec[0]);i=i+3) { 
		memset (key,0,sizeof (key));
		memset (in_text,0,sizeof (in_text));
		memset (out_text,0,sizeof (out_text));
		str2hex(des_ecb_monte_dec[i].key1,key,&len);
		str2hex(des_ecb_monte_dec[i].key2,key+8,&len);
		str2hex(des_ecb_monte_dec[i].key3,key+16,&len);
		k1 = key;
		k2 = key+8;
		k3 = key+16;
		if (!memcmp (des_ecb_monte_dec[i].monte,"Monte1",7)) {
			mode = 1;
		}
		if (!memcmp (des_ecb_monte_dec[i].monte,"Monte2",7)) {
			mode = 2;
		}
		if (!memcmp (des_ecb_monte_dec[i].monte,"Monte3",7)) {
			mode = 3;
		}
	
		str2hex(des_ecb_monte_dec[i].cipher,in_text,&len);
		fail =fail +MonteCarloDesEcbDecrypt (key, mode, in_text,i,&cnt);
	}

	if (fail)
		printf("***");
	if (cvmx_is_init_core()) {
		printf ("%-20s :Total Test vectors tested: %d passed : %d failed : %d\n","3DES-ECB",cnt,(cnt-fail),fail);
	}
	return 0;
}


 
int MonteCarloCbcDecrypt(uint8_t key[32], uint8_t iv[16], 
								 AesType mode, uint8_t ct[16],int n,int *cnt)
{
	AES_KEY akey;
	uint32_t val;
	int key_size = 0;
	unsigned int i;
	int j,len,fail = 0;
	uint8_t p[16];
	uint8_t p_minus_1[16];
	uint8_t exp [20];
	uint8_t tmp_iv[16];

	if (mode == 0)
		key_size = 128;
	if (mode == 1)
		key_size = 192;
	if (mode == 2)
		key_size = 256;


	for (i=0;i<(sizeof (aes_cbc_mct_dec)/sizeof (aes_cbc_mct_dec[0]))/3;i++) {
		for (j=0;j<1000;j++) {
			memcpy(p_minus_1,p,16); 
			val = AES_set_decrypt_key (key, key_size, &akey); 
			if (val)
				printf ("AES_set_decrypt_key Failed with error code %d\n",val);
			memcpy (tmp_iv, iv, 16);
			AES_cbc_encrypt (ct, p, 16, &akey, iv, AES_DECRYPT);

			if (j == 0) 
				memcpy(ct,tmp_iv,16);
			else 
				memcpy(ct,p_minus_1,16);
		}
	str2hex (aes_cbc_mct_dec[n++].plain,exp,&len);
	if (memcmp (exp,p,len)) {
		printf("Monte Carlo Cbc Decrypt failed\n");
		DUMP_BUFF ("Expected\n",exp,len);
		DUMP_BUFF ("Actual\n",p,len);
		fail++;
	}
		switch(mode)
		{
		case AES_128:
			XOR(key,key,p,16);
		break;
		case AES_192:
			XOR(key,key,p_minus_1+8,8);
			XOR(key+8,key+8,p,16);
		break;
		case AES_256:
			XOR(key,key,p_minus_1,16);
			XOR(key+16,key+16,p,16);
		break;
		}

		memcpy(iv,p,16);
		memcpy(ct,p_minus_1,16);
		(*cnt)++;
	}
	return fail;
}
	
int MonteCarloCbcEncrypt(uint8_t key[32], uint8_t iv[16], 
								 AesType mode, uint8_t p[16],int n,int *cnt)
{
	AES_KEY akey;
	uint32_t val;
	int key_size = 0;
	unsigned int i;
	int j,len, fail = 0;
	uint8_t exp [20];
	uint8_t ct[16];
	uint8_t ct_minus_1[16];
	unsigned char tmp_iv[16];

	if (mode == 0)
		key_size = 128;
	if (mode == 1)
		key_size = 192;
	if (mode == 2)
		key_size = 256;


	for (i=0;i<(sizeof (aes_cbc_mct_enc)/sizeof (aes_cbc_mct_enc[0]))/3;i++) {
		for (j=0;j<1000;j++) {
			memcpy(ct_minus_1,ct,16); 
			val = AES_set_encrypt_key (key, key_size, &akey); 
			if (val)
				printf ("AES_set_encrypt_key Failed with error code %d\n",val);
			memcpy (tmp_iv, iv, 16);
			AES_cbc_encrypt (p, ct, 16, &akey, iv, AES_ENCRYPT);
			if (j == 0)
				memcpy(p,tmp_iv,16);
			else 
				memcpy(p,ct_minus_1,16);
		
		 }
	str2hex (aes_cbc_mct_enc[n++].cipher,exp,&len);
	if (memcmp (exp,ct,len)) {
		printf("Monte Carlo Cbc Encrypt failed\n");
		DUMP_BUFF ("Expected\n",exp,len);
		DUMP_BUFF ("Actual\n",p,len);
		fail++;
	}

	switch(mode) {
	case AES_128:
		XOR(key,key,ct,16);
	break;
	case AES_192:
		XOR(key,key,ct_minus_1+8,8);
		XOR(key+8,key+8,ct,16);
	break;
	case AES_256:
		XOR(key,key,ct_minus_1,16);
		XOR(key+16,key+16,ct,16);
	break;
	}

	memcpy(iv,ct,16);
	memcpy(p,ct_minus_1,16);
	(*cnt)++;
	}
	return fail;
}
 int MonteCarloEcbDecrypt (uint8_t key[32], AesType mode,
								uint8_t ct[16],int n,int * cnt)
{
	unsigned int i;
	int j,len;
	uint8_t p[32];
	uint8_t p_minus_1[16];
	int val,fail = 0;
	uint8_t exp [20];
	int key_size = 0;
	AES_KEY akey;

	if (mode == 0)
		key_size = 128;
	if (mode == 1)
		key_size = 192;
	if (mode == 2)
		key_size = 256;

	for (i=0;i<(sizeof (aes_ecb_mct_dec)/sizeof (aes_ecb_mct_dec[0]))/3;i++) {
		 for (j=0;j<1000;j++) {
			 memcpy(p_minus_1,p,16); 
			 val = AES_set_decrypt_key(key, key_size, &akey); 
			 if (val)
				 printf ("AES_set_decrypt_key in MonteCarlo Failed with error code %d\n",val);
			 AES_ecb_encrypt (ct, p, &akey, AES_DECRYPT);
			 memcpy(ct,p,16);
		}

	str2hex (aes_ecb_mct_dec[n++].plain,exp,&len);
	if (memcmp (exp,p,len)) {
		printf("Monte Carlo Cbc Decrypt failed (LINE:%d)\n",__LINE__);
		DUMP_BUFF ("Expected\n",exp,len);
		DUMP_BUFF ("Actual\n",p,len);
		fail++;
	}
		
		 switch(mode) {
			 case AES_128:
				 XOR(key,key,p,16);
				 break;
			 case AES_192:
				 XOR(key,key,p_minus_1+8,8);
				 XOR(key+8,key+8,p,16);
				 break;
			 case AES_256:
				 XOR(key,key,p_minus_1,16);
				 XOR(key+16,key+16,p,16);
				 break;
		}
		 memcpy(ct,p,16);
		 (*cnt)++;
	}
	return fail;
}


int MonteCarloEcbEncrypt(uint8_t key[32], AesType mode,
								 uint8_t p[16],int n, int *cnt)
{

	AES_KEY akey;
	uint32_t val;
	int key_size = 0,fail =0;
	unsigned int i;
	int j,len;
	uint8_t exp [20];
	uint8_t ct[32];
	uint8_t ct_minus_1[16];

		if (mode == 0)
			key_size = 128;
		if (mode == 1)
			key_size = 192;
		if (mode == 2)
			key_size = 256;


	for (i=0;i<(sizeof (aes_ecb_mct_enc)/sizeof (aes_ecb_mct_enc[0]))/3;i++) {
		for (j=0;j<1000;j++) {
			memcpy(ct_minus_1,ct,16); 
			val = AES_set_encrypt_key (key, key_size, &akey); 
			if (val)
				printf ("AES_set_encrypt_key Failed with error code %d\n",val);
			AES_ecb_encrypt (p, ct, &akey, AES_ENCRYPT);
			memcpy(p,ct,16);
		 }
	str2hex (aes_ecb_mct_enc[n++].cipher,exp,&len);
	if (memcmp (exp,ct,len)) {
		printf("Monte Carlo Ebc Encrypt failed (LINE:%d)\n",__LINE__);
		DUMP_BUFF ("Expected\n",exp,len);
		DUMP_BUFF ("Actual\n",p,len);
		fail++;
	}
	switch(mode) {
	case AES_128:
		XOR(key,key,ct,16);
	break;
	case AES_192:
		XOR(key,key,ct_minus_1+8,8);
		XOR(key+8,key+8,ct,16);
	break;
	case AES_256:
		XOR(key,key,ct_minus_1,16);
		XOR(key+16,key+16,ct,16);
	break;
	}

	memcpy(p,ct,16);
	(*cnt)++;
	}
	return fail;
}



static void hex_print (uint8_t *buff, uint32_t len)
{
	uint32_t cnt = 0;
	for (cnt = 0; cnt < len; cnt++) 
		printf ("%02x", buff[cnt]);
	printf ("\n");
}
	uint32_t i;
	static unsigned int prev_inlen = 0;

int test_des_ncbc_kat () {
	if (cvmx_is_init_core())
		printf (" *** DES-NCBC Known Answer Test not available ***\n");
	return 0;
}

int test_des_ncbc ()
{	
	uint8_t encbuff[MAX_BUFF_SIZE];
	uint8_t decbuff[MAX_BUFF_SIZE];
	uint8_t inbuff[MAX_BUFF_SIZE];
	unsigned int inlen;
	uint8_t key[8] = {0xf2,0xe0,0xd5,0xc2,0xb5,0xa1,0x97,0x85};
	uint8_t iv[8]= {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
	uint8_t orig_iv[8] = {0};
	int ret = 0;
	des_key_schedule ks;
#ifndef TEST_CPU_CYCLES
	uint32_t cnt = 0;
#endif
	memset (inbuff, 0, sizeof (inbuff));	
	for (inlen=START_PACKET_SIZE; inlen<=MAX_BUFF_SIZE;){
		PRINT_HDR;
		if (inlen%16) { 
			printf ("Error..For AES to work inlen must be multiple to "
					"16 bytes\n");
			return -1;
		}
		for (i = prev_inlen; i < inlen; i++) {
			inbuff[i] = cvmx_rng_get_random8 (); 
		}

	memcpy (orig_iv, iv, 8);
	memset (encbuff, 0, sizeof (encbuff));
	memset (decbuff, 0, sizeof (decbuff));
	 
	ret = DES_set_key_checked ((const_DES_cblock *) key, &ks);
	if (ret != 0) {
		printf ("DES_set_key_checked Failed (Line %d)\n", __LINE__);
		ret = -1;
		goto End;
	}

	/* Single call DES_NCBC - Non Inplace */
	START_CYCLE;
	DES_ncbc_encrypt (inbuff, encbuff, inlen, 
					&ks, (DES_cblock *) iv, DES_ENCRYPT);
	END_CYCLE("DES_ncbc_encrypt");
	memcpy (iv, orig_iv, 8);
	START_CYCLE;
	DES_ncbc_encrypt (encbuff, decbuff, inlen, &ks,
					(DES_cblock *) iv, DES_DECRYPT);
	END_CYCLE("DES_ncbc_decrypt");

	if (memcmp (inbuff, decbuff, inlen)){
		printf ("DES NCBC Single Call non inplace API Failed "
				"(input size:%u)\n", inlen);
		hex_print (inbuff,inlen);
		hex_print (decbuff,inlen);
		ret = -1;
		goto End;
	}
	
#ifndef TEST_CPU_CYCLES
	/* Single call DES-NCBC Inplace */
	memset (decbuff, 0, sizeof (decbuff));
	memcpy (decbuff, inbuff, inlen);
	memcpy (iv, orig_iv, 8);
	DES_ncbc_encrypt (decbuff, decbuff, inlen, 
					&ks, (DES_cblock *) iv, DES_ENCRYPT);
	memcpy (iv, orig_iv, 8);
	DES_ncbc_encrypt (decbuff, decbuff, inlen, &ks,
					(DES_cblock *) iv, DES_DECRYPT);
	if (memcmp (inbuff, decbuff, inlen)){
		printf ("DES NCBC Single Call inplace API Failed "
				"(input size:%u)\n", inlen);
		ret = -1;
		goto End;
	}


	/* Multicall DES-NCBC NonInplace */
	memset (encbuff, 0, sizeof (encbuff));
	memset (decbuff, 0, sizeof (decbuff));
	memcpy (iv, orig_iv, 8);
	for (cnt = 0; cnt < inlen; cnt += DES_CHUNK_SIZE) {
		if ((inlen-cnt) < DES_CHUNK_SIZE)
			DES_ncbc_encrypt (&inbuff[cnt], &encbuff[cnt], (inlen-cnt), &ks,
							(DES_cblock *) iv, DES_ENCRYPT);
		else
			DES_ncbc_encrypt (&inbuff[cnt], &encbuff[cnt], DES_CHUNK_SIZE, &ks,
							(DES_cblock *) iv, DES_ENCRYPT);
	}
	memcpy (iv, orig_iv, 8);
	for (cnt = 0; cnt < inlen; cnt += DES_CHUNK_SIZE) {
		if ((inlen-cnt) < DES_CHUNK_SIZE)
			DES_ncbc_encrypt (&inbuff[cnt], &encbuff[cnt], (inlen-cnt), &ks,
							(DES_cblock *) iv, DES_DECRYPT);
		else
			DES_ncbc_encrypt (&encbuff[cnt], &decbuff[cnt], DES_CHUNK_SIZE, &ks,
							(DES_cblock *) iv, DES_DECRYPT);
	}
	if (memcmp (inbuff, decbuff, inlen)){
		printf ("DES NCBC multicall Noninplace API Failed "
				"(input size:%u)\n", inlen);
		ret = -1;
		goto End;
	}

	/* Multicall DES-NCBC Inplace */
	memset (decbuff, 0, sizeof (decbuff));
	memcpy (decbuff, inbuff, inlen);
	memcpy (iv, orig_iv, 8);
	for (cnt = 0; cnt < inlen; cnt += DES_CHUNK_SIZE) {
		if ((inlen-cnt) < DES_CHUNK_SIZE)
			DES_ncbc_encrypt (&decbuff[cnt], &decbuff[cnt], (inlen-cnt), &ks,
							(DES_cblock *) iv, DES_ENCRYPT);
		else
			DES_ncbc_encrypt (&decbuff[cnt], &decbuff[cnt], DES_CHUNK_SIZE, &ks,
							(DES_cblock *) iv, DES_ENCRYPT);
	}
	memcpy (iv, orig_iv, 8);
	for (cnt = 0; cnt < inlen; cnt += DES_CHUNK_SIZE) {
		if ((inlen-cnt) < DES_CHUNK_SIZE)
			DES_ncbc_encrypt (&decbuff[cnt], &decbuff[cnt], (inlen-cnt), &ks,
							(DES_cblock *) iv, DES_DECRYPT);
		else
			DES_ncbc_encrypt (&decbuff[cnt], &decbuff[cnt], DES_CHUNK_SIZE, &ks,
							(DES_cblock *) iv, DES_DECRYPT);
	}
	if (memcmp (inbuff, decbuff, inlen)){
		printf ("DES NCBC multicall inplace API Failed (input size:%u)\n", inlen);
		ret = -1;
		goto End;
	}
#endif
		prev_inlen = inlen;
	#ifdef TEST_CPU_CYCLES
		inlen+=inlen;
	#else	
		inlen+=INCR_STEPS;
	#endif
}
	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","DES-NCBC",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End: 
	return ret;
}


int test_3des_cbc ()
{	
	uint8_t encbuff[MAX_BUFF_SIZE] = {0};
	uint8_t decbuff[MAX_BUFF_SIZE] = {0};
	uint8_t inbuff[MAX_BUFF_SIZE];
	unsigned int inlen;
	uint8_t key1[8] = {0xf2,0xe0,0xd5,0xc2,0xb5,0xa1,0x97,0x85};
	uint8_t key2[8] = {0xf2,0xe0,0xd5,0xc2,0xb5,0xa1,0x97,0x85};
	uint8_t key3[8] = {0x31,0xe3,0xd0,0x51,0xb3,0xa4,0x97,0x83};
	uint8_t iv[8] = {0xab,0xcd,0xef,0xab,0xcd,0xef,0x01,0x23};
	uint8_t orig_iv[8];
	int ret = 0;
#ifndef TEST_CPU_CYCLES
	uint32_t cnt = 0;
#endif

	des_key_schedule ks1, ks2, ks3;
	memset (inbuff, 0, sizeof (inbuff));	
	for (inlen=START_PACKET_SIZE; inlen<=MAX_BUFF_SIZE;){
		PRINT_HDR;
		if (inlen%16) { 
			printf ("Error..For AES to work inlen must be multiple to "
					"16 bytes\n");
			return -1;
		}
		for (i = prev_inlen; i < inlen; i++) {
			inbuff[i] = cvmx_rng_get_random8 (); 
		}
	if ((ret = DES_set_key_checked ((const_DES_cblock *) key1, &ks1)) != 0) {
		printf ("3DES set key1 Failed %d\n", ret);
		ret = -1;
		goto End;
	}
	if ((ret = DES_set_key_checked ((const_DES_cblock *) key2, &ks2)) != 0) {
		printf ("3DES set key2 Failed %d\n", ret);
		ret = -1;
		goto End;
	}
	if ((ret = DES_set_key_checked ((const_DES_cblock *) key3, &ks3)) != 0) {
		printf ("3DES set key3 Failed %d\n", ret);
		ret = -1;
		goto End;
	}

	memcpy (orig_iv, iv, 8);
	/* 3DES single call NonInplace */
	START_CYCLE;
	DES_ede3_cbc_encrypt (inbuff, encbuff, inlen, &ks1, &ks2, &ks3,
						(DES_cblock *) iv, DES_ENCRYPT);
	END_CYCLE("DES_ede3_cbc_encrypt");
	memcpy (iv, orig_iv, 8);
	START_CYCLE;
	DES_ede3_cbc_encrypt (encbuff, decbuff, inlen, &ks1, &ks2, &ks3,
						(DES_cblock *) iv, DES_DECRYPT);
	END_CYCLE("DES_ede3_cbc_decrypt");
	if (memcmp (inbuff, decbuff, inlen)){
		printf ("3DES-CBC Single Call NonInplace API Failed "
				"(input size:%u)\n", inlen);
		ret = -1;
		goto End;
	}

#ifndef TEST_CPU_CYCLES
	/* 3DES single call Inplace */
	memset (decbuff, 0, sizeof (decbuff)); 
	memcpy (decbuff, inbuff, inlen);
	memcpy (iv, orig_iv, 8);
	DES_ede3_cbc_encrypt (decbuff, decbuff, inlen, &ks1, &ks2, &ks3,
						(DES_cblock *) iv, DES_ENCRYPT);
	memcpy (iv, orig_iv, 8);
	DES_ede3_cbc_encrypt (decbuff, decbuff, inlen, &ks1, &ks2, &ks3,
						(DES_cblock *) iv, DES_DECRYPT);
	if (memcmp (inbuff, decbuff, inlen)){
		printf ("3DES-CBC Single call Inplace API Failed "
				"(input size:%u)\n", inlen);
		ret = -1;
		goto End;
	}

	/* 3DES multicall NonInplace */
	memset (encbuff, 0, sizeof (encbuff));
	memset (decbuff, 0, sizeof (decbuff));
	memcpy (iv, orig_iv, 8);
	for (cnt = 0; cnt < inlen; cnt += DES_CHUNK_SIZE) {
		if ((inlen-cnt) < DES_CHUNK_SIZE) {
			DES_ede3_cbc_encrypt (&inbuff[cnt], &encbuff[cnt], (inlen-cnt), 
								&ks1, &ks2, &ks3,
								(DES_cblock *) iv, DES_ENCRYPT);
		} else {
			DES_ede3_cbc_encrypt (&inbuff[cnt], &encbuff[cnt], DES_CHUNK_SIZE, 
								&ks1, &ks2, &ks3,
								(DES_cblock *) iv, DES_ENCRYPT);
		}
	}
	memcpy (iv, orig_iv, 8);
	for (cnt = 0; cnt < inlen; cnt += DES_CHUNK_SIZE) {
		if ((inlen-cnt) < DES_CHUNK_SIZE) {
			DES_ede3_cbc_encrypt (&encbuff[cnt], &decbuff[cnt], (inlen-cnt), 
								&ks1, &ks2, &ks3,
								(DES_cblock *) iv, DES_DECRYPT);
		} else {
			DES_ede3_cbc_encrypt (&encbuff[cnt], &decbuff[cnt], DES_CHUNK_SIZE,
								&ks1, &ks2, &ks3,
								(DES_cblock *) iv, DES_DECRYPT);
		}
	}

	if (memcmp (inbuff, decbuff, inlen)){
		printf ("3DES-CBC Multicall NonInplace API Failed "
				"(input size:%u)\n", inlen);
	}

	/* 3DES multicall Inplace */
	memset (decbuff, 0, sizeof (decbuff));
	memcpy (iv, orig_iv, 8);
	memcpy (decbuff, inbuff, inlen);
	for (cnt = 0; cnt < inlen; cnt += DES_CHUNK_SIZE) {
		if ((inlen-cnt) < DES_CHUNK_SIZE) {
			DES_ede3_cbc_encrypt (&decbuff[cnt], &decbuff[cnt], (inlen-cnt), 
								&ks1, &ks2, &ks3,
								(DES_cblock *) iv, DES_ENCRYPT);
		} else {
			DES_ede3_cbc_encrypt (&decbuff[cnt], &decbuff[cnt], DES_CHUNK_SIZE, 
								&ks1, &ks2, &ks3,
								(DES_cblock *) iv, DES_ENCRYPT);
		}
	}
	memcpy (iv, orig_iv, 8);
	for (cnt = 0; cnt < inlen; cnt += DES_CHUNK_SIZE) {
		if ((inlen-cnt) < DES_CHUNK_SIZE) {
			DES_ede3_cbc_encrypt (&decbuff[cnt], &decbuff[cnt], (inlen-cnt), 
								&ks1, &ks2, &ks3,
								(DES_cblock *) iv, DES_DECRYPT);
		} else {
			DES_ede3_cbc_encrypt (&decbuff[cnt], &decbuff[cnt], DES_CHUNK_SIZE, 
								&ks1, &ks2, &ks3,
								(DES_cblock *) iv, DES_DECRYPT);
		}
	}
	if (memcmp (inbuff, decbuff, inlen)){
		printf ("3DES-CBC Multicall Inplace API Failed (input size:%u)\n", inlen);
		ret = -1;
		goto End;
	}
#endif
		prev_inlen = inlen;
	#ifdef TEST_CPU_CYCLES
		inlen+=inlen;
	#else	
		inlen+=INCR_STEPS;
	#endif
}
	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","3DES-CBC",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End :
	return ret;
}


int test_3des_ecb ()
{	
	uint8_t encbuff[MAX_BUFF_SIZE];
	uint8_t decbuff[MAX_BUFF_SIZE];
	uint8_t inbuff[MAX_BUFF_SIZE];
	unsigned int inlen;
	uint32_t cnt;
	int ret = 0;
	uint8_t key1[8] = {0xf2,0xe0,0xd5,0xc2,0xb5,0xa1,0x97,0x85};
	uint8_t key2[8] = {0x31,0xe3,0xd0,0x51,0xb3,0xa4,0x97,0x83};
	uint8_t key3[8] = {0xf2,0xe0,0xd5,0xc2,0xb5,0xa1,0x97,0x85};
#ifdef TEST_CPU_CYCLES
 uint8_t iv[8] = {0};
 uint8_t orig_iv[8] = {0};
#endif
	des_key_schedule ks1, ks2, ks3;
	memset (inbuff, 0, sizeof (inbuff));	
	for (inlen=START_PACKET_SIZE; inlen<=MAX_BUFF_SIZE;){
		PRINT_HDR;
		if (inlen%16) { 
			printf ("Error..For AES to work inlen must be multiple to "
					"16 bytes\n");
			return -1;
		}
		for (i = prev_inlen; i < inlen; i++) {
			inbuff[i] = cvmx_rng_get_random8 (); 
		}

	if ((ret = DES_set_key_checked ((const_DES_cblock *) key1, &ks1)) != 0) {
		printf ("3DES set key1 Failed %d\n", ret);
		ret = -1;
		goto End;
	}
	if ((ret = DES_set_key_checked ((const_DES_cblock *) key2, &ks2)) != 0) {
		printf ("3DES set key2 Failed %d\n", ret);
		ret = -1;
		goto End;
	}
	if ((ret = DES_set_key_checked ((const_DES_cblock *) key3, &ks3)) != 0) {
		printf ("3DES set key3 Failed %d\n", ret);
		ret = -1;
		goto End;
	}
	START_CYCLE;
	for (cnt = 0; cnt < inlen; cnt += 8){
		DES_ecb3_encrypt ((const_DES_cblock *) &inbuff[cnt],
						(DES_cblock *)&encbuff[cnt], 
						&ks1, &ks2, &ks3, DES_ENCRYPT);
	}
	END_CYCLE("DES_ecb3_encrypt");
	START_CYCLE;
	for (cnt = 0; cnt < inlen; cnt += 8){
		DES_ecb3_encrypt ((const_DES_cblock *) &encbuff[cnt],
						(DES_cblock *) &decbuff[cnt], &ks1, &ks2, &ks3, 
						DES_DECRYPT);
	}
	END_CYCLE("DES_ecb3_decrypt");
	if (memcmp (inbuff, decbuff, inlen)) {
		printf ("DES3 ECB Failed for input size : %u\n", inlen);
		ret = -1;
			goto End;
	}
		prev_inlen = inlen;
	#ifdef TEST_CPU_CYCLES
		inlen+=inlen;
	#else	
		inlen+=INCR_STEPS;
	#endif
}
	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","3DES-ECB",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}

int test_aes_cbc ()
{	
	uint8_t encbuff[MAX_BUFF_SIZE] = {0};
	uint8_t decbuff[MAX_BUFF_SIZE] = {0};
	uint8_t inbuff[MAX_BUFF_SIZE];
	unsigned int inlen;
#ifndef TEST_CPU_CYCLES
		uint32_t cnt;
#endif

	const unsigned char aes_key[][32] = {
	/* AES 128 bit key*/
		 {0x09,0x28,0x34,0x74,0x00,0x12,0xab,0x45,
		0x93,0x67,0x56,0x37,0xca,0xaf,0xff,0xbb},
	/* AES 192 bit key*/
		 {0x23,0x98,0x74,0xaa,0xbd,0xef,0xad,0x94,
		0x8b,0xcd,0xf7,0x36,0x4b,0xca,0xc7,0xbc,
		0x84,0xd8,0x47,0x46,0x69,0x47,0x00,0xcd},
	/* AES 256 bit key*/
		 {0x91,0x28,0x73,0x48,0x72,0x13,0x46,0x87,
		0x16,0xab,0xde,0x84,0x7b,0xc4,0x87,0xad,
		0x98,0x8d,0xdf,0xff,0xf7,0x38,0x46,0xbc,
		0xad,0xef,0x54,0x76,0x84,0x73,0x64,0x78}
	};
	uint8_t iv[] = {
		0x08,0x93,0x78,0x67,0x49,0x32,0x87,0x21,
		0x67,0xab,0xcd,0xef,0xaf,0xcd,0xef,0xff
	};
	uint8_t orig_iv[16] = {0};

	int keylen;
	unsigned int i = 0;
	AES_KEY akey;
	int ret = 0;
	memset (inbuff, 0, sizeof (inbuff));	
	for (inlen=START_PACKET_SIZE; inlen<=MAX_BUFF_SIZE;){
		PRINT_HDR;
		if (inlen%16) { 
			printf ("Error..For AES to work inlen must be multiple to "
					"16 bytes\n");
			return -1;
		}
		for (i = prev_inlen; i < inlen; i++) {
			inbuff[i] = cvmx_rng_get_random8 (); 
		}
	i=0;
	/* This loop tests AES key sizes 128, 192 and 256 */
	for (keylen = 128; keylen <= 256; keylen +=64){
		/* AES single call non-inplace */
		memcpy (orig_iv, iv, 16);
		AES_set_encrypt_key (aes_key[i], keylen, &akey);
		START_CYCLE;
		AES_cbc_encrypt (inbuff, encbuff, inlen, &akey, iv, AES_ENCRYPT);
		END_CYCLE_AES("AES_cbc_encrypt",keylen);
		memcpy (iv, orig_iv, 16);
		AES_set_decrypt_key (aes_key[i], keylen, &akey);	
		START_CYCLE;
		AES_cbc_encrypt (encbuff, decbuff, inlen, &akey, iv, AES_DECRYPT);
		END_CYCLE_AES("AES_cbc_decrypt",keylen);
		if (memcmp (inbuff, decbuff, inlen)) {
			printf ("AES%d-CBC Single Call NonInplace API Failed "
					"(input size : %u)\n", keylen, inlen);
			ret = -1;
			goto End;
		}

#ifndef TEST_CPU_CYCLES
		/* AES single call Inplace */
		memcpy (iv, orig_iv, 16);
		memcpy (decbuff, inbuff, inlen);
		AES_set_encrypt_key (aes_key[i], keylen, &akey);
		AES_cbc_encrypt (decbuff, decbuff, inlen, &akey, iv, AES_ENCRYPT);
		memcpy (iv, orig_iv, 16);
		AES_set_decrypt_key (aes_key[i], keylen, &akey);
		AES_cbc_encrypt (decbuff, decbuff, inlen, &akey, iv, AES_DECRYPT);
		if (memcmp (inbuff, decbuff, inlen)) {
			printf ("AES%d-CBC Single Call Inplace API Failed "
					"(input size : %u)\n", keylen, inlen);
			ret = -1;
			goto End;
		}

		/* AES Multicall NonInplace */
		memcpy (iv, orig_iv, 16);
		AES_set_encrypt_key (aes_key[i], keylen, &akey);
		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE)
		if ((inlen-cnt) < AES_CHUNK_SIZE) {
			AES_cbc_encrypt (&inbuff[cnt], &encbuff[cnt], (inlen-cnt), 
							 &akey, iv, AES_ENCRYPT);
		} else {
			AES_cbc_encrypt (&inbuff[cnt], &encbuff[cnt], AES_CHUNK_SIZE, 
							 &akey, iv, AES_ENCRYPT);
		}

		memcpy (iv, orig_iv, 16);
		AES_set_decrypt_key (aes_key[i], keylen, &akey);
		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE)
		if ((inlen-cnt) < AES_CHUNK_SIZE) {
			AES_cbc_encrypt (&inbuff[cnt], &encbuff[cnt], (inlen-cnt), 
							 &akey, iv, AES_DECRYPT);
		} else {
			AES_cbc_encrypt (&inbuff[cnt], &encbuff[cnt], AES_CHUNK_SIZE, 
							 &akey, iv, AES_DECRYPT);
		}

		if (memcmp (inbuff, decbuff, inlen)){
			printf ("AES%d-CBC Multicall NonInplace API Failed "
					"(input size : %u)\n", keylen, inlen);
			ret = -1;
			goto End;
		}

		/* AES Multicall Inplace */
		memcpy (iv, orig_iv, 16);
		memset (decbuff, 0, sizeof (decbuff));
		memcpy (decbuff, inbuff, inlen);
		AES_set_encrypt_key (aes_key[i], keylen, &akey);
		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE)
		if ((inlen-cnt) < AES_CHUNK_SIZE) {
			AES_cbc_encrypt (&decbuff[cnt], &decbuff[cnt], (inlen-cnt), 
							 &akey, iv, AES_ENCRYPT);
		} else {
			AES_cbc_encrypt (&decbuff[cnt], &decbuff[cnt], AES_CHUNK_SIZE, 
							 &akey, iv, AES_ENCRYPT);
		}

		memcpy (iv, orig_iv, 16);
		AES_set_decrypt_key (aes_key[i], keylen, &akey);
		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE)
		if ((inlen-cnt) < AES_CHUNK_SIZE) {
			AES_cbc_encrypt (&decbuff[cnt], &decbuff[cnt], (inlen-cnt), 
							 &akey, iv, AES_DECRYPT);
		} else {
			AES_cbc_encrypt (&decbuff[cnt], &decbuff[cnt], AES_CHUNK_SIZE, 
							 &akey, iv, AES_DECRYPT);
		}

		if (memcmp (inbuff, decbuff, inlen)){
			printf ("AES%d-CBC multicall Inplace API Failed "
					"(input size : %u)\n", keylen, inlen);
			ret = -1;
			goto End;
		}
#endif
		i++;
	}
		prev_inlen = inlen;
	#ifdef TEST_CPU_CYCLES
		inlen+=inlen;
	#else	
		inlen+=INCR_STEPS;
	#endif
}
	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","AES-CBC",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}
int test_aes_cbc_kat () {
	uint8_t iv[16];
	uint8_t key[32];
	uint8_t in_text[400];
	uint8_t out_text[400];
	int len, fail=0,cnt=0;
	unsigned int i;
	uint32_t val;
	AES_KEY akey;
	AesType aes_type = 0;
	for (i=0;i<sizeof(aes_cbc_enc)/sizeof (aes_cbc_enc[0]);i++) {
		memset (key, 0, sizeof (key));
		memset (iv, 0, sizeof (iv));
		memset (in_text, 0, sizeof (in_text));
		memset (out_text, 0, sizeof (out_text));
		str2hex(aes_cbc_enc[i].key,key,&len);
		val = AES_set_encrypt_key (key, aes_cbc_enc[i].key_size, &akey);
		if (val != 0){
			printf ("AES_set_encrypt_key Failed\n");
		}
			
		str2hex(aes_cbc_enc[i].iv,iv,&len);
		str2hex(aes_cbc_enc[i].plain,in_text,&len);
		AES_cbc_encrypt (in_text,out_text,len,&akey,iv,AES_ENCRYPT);
	
		str2hex(aes_cbc_enc[i].cipher,in_text,&len);
	
		if (memcmp (in_text,out_text, len)) {
			printf ("AES-CBC Failed for input size\n");
			printf("Expected %s\n",aes_cbc_enc[i].cipher);
			printf("actual %s\n",out_text);
			DUMP_BUFF("Plain\n",aes_cbc_enc[i].cipher,16);
			DUMP_BUFF("TEXT\n",out_text,len);
			fail++;
		}
		cnt++;
	}
	// Decrypt
	for (i=0;i<sizeof (aes_cbc_dec)/sizeof (aes_cbc_dec[0]);i++) {
		memset (key, 0, sizeof (key));
		memset (iv, 0, sizeof (iv));
		memset (in_text, 0, sizeof (in_text));
		memset (out_text, 0, sizeof (out_text));
		str2hex(aes_cbc_dec[i].key,key,&len);
		val = AES_set_decrypt_key (key,aes_cbc_dec[i].key_size , &akey);
		str2hex(aes_cbc_dec[i].iv,iv,&len);
		str2hex(aes_cbc_dec[i].cipher,in_text,&len);
		AES_cbc_encrypt (in_text, out_text, len, &akey,
											 iv, AES_DECRYPT);
		
	
		
		str2hex(aes_cbc_dec[i].plain,in_text,&len);
	
		if (memcmp (in_text,out_text, len)) {
			printf("AES CBC Decrypt failed\n");
			DUMP_BUFF("IN TEXT\n",in_text,16);
			DUMP_BUFF("OUT TEXT\n",out_text,16);
			fail++;
		}
		cnt++;
	}
	
	// Montecarlo Encrypt
	
	for (i=0;i<sizeof (aes_cbc_mct_enc)/sizeof (aes_cbc_mct_enc[0]);i=i+3) {
		memset (key, 0, sizeof (key));
		memset (iv, 0, sizeof (iv));
		memset (in_text, 0, sizeof (in_text));
		str2hex(aes_cbc_mct_enc [i].key,key,&len);
		str2hex(aes_cbc_mct_enc [i].iv,iv,&len);
		str2hex(aes_cbc_mct_enc [i].plain,in_text,&len);
		if ( aes_cbc_mct_enc [i].key_size == 128 ) {
		aes_type = AES_128;
		}
		else if (aes_cbc_mct_enc [i].key_size == 192 ) {
		aes_type = AES_192;
		}
		else if (aes_cbc_mct_enc [i].key_size == 256 ) {
		aes_type = AES_256;
		}
	
		fail =fail +MonteCarloCbcEncrypt(key,iv, aes_type, in_text,i,&cnt);
	}
	// Monte carlo Decrypt
	for (i=0;i<sizeof (aes_cbc_mct_dec)/sizeof (aes_cbc_mct_dec[0]);i=i+3) {
		memset (key, 0, sizeof (key));
		memset (iv, 0, sizeof (iv));
		memset (in_text, 0, sizeof (in_text));
		str2hex(aes_cbc_mct_dec [i].key,key,&len);
		str2hex(aes_cbc_mct_dec [i].iv,iv,&len);
		str2hex(aes_cbc_mct_dec [i].cipher,in_text,&len);
		if ( aes_cbc_mct_dec [i].key_size == 128 ) {
		aes_type = AES_128;
		}
		else if (aes_cbc_mct_dec [i].key_size == 192 ) {
		aes_type = AES_192;
		}
		else if (aes_cbc_mct_dec [i].key_size == 256 ) {
		aes_type = AES_256;
		}
	
		fail =fail +MonteCarloCbcDecrypt(key,iv, aes_type, in_text,i,&cnt);
	}
	if (fail)
		printf("***");
	
	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d passed : %d failed : %d\n","AES-CBC",cnt,(cnt-fail),fail);

	return 0;
}
int test_aes_ecb_kat () {
	uint8_t key[32];
	uint8_t in_text[400];
	uint8_t out_text[400];
	uint8_t exp_out_text[400];
	unsigned int i, j;
	int len, fail=0, cnt=0;
	uint32_t val;
	AES_KEY akey;
	AesType aes_type = 0;
	for (i=0;i < sizeof (aes_ecb_enc)/sizeof (aes_ecb_enc[0]);i++) {
		memset (key, 0, sizeof (key));
		memset (in_text, 0, sizeof (in_text));
		memset (out_text, 0, sizeof (out_text));
		str2hex(aes_ecb_enc[i].key,key,&len);
		val = AES_set_encrypt_key (key, aes_ecb_enc[i].key_size, &akey);		
		if (val != 0){
			printf ("AES_set_encrypt_key Failed\n");
		}
			
		str2hex(aes_ecb_enc[i].plain,in_text,&len);	
		for (j = 0; j < (unsigned int )len; j += 16) {
			AES_ecb_encrypt (&in_text[j], &out_text[j],
										&akey, AES_ENCRYPT);
					
		}	
		str2hex(aes_ecb_enc[i].cipher,in_text,&len);
		if (memcmp (in_text,out_text, len)) {
			printf ("AES-ECB Failed for input size\n");
			DUMP_BUFF("Plain\n",aes_ecb_enc[i].cipher,16);
			DUMP_BUFF("TEXT\n",out_text,len);
			fail++;
		}
		cnt++;
	}
	// Decrypt
	for (i=0;i < sizeof (aes_ecb_dec)/sizeof (aes_ecb_dec[0]);i++) {		
		memset (key, 0xcc, sizeof (key));
		memset (in_text, 0xcc, sizeof (in_text));
		memset (out_text, 0xcc, sizeof (out_text));
		memset (exp_out_text, 0xcc, sizeof (out_text));
		str2hex(aes_ecb_dec[i].key,key,&len);
		val = AES_set_decrypt_key (key, aes_ecb_dec[i].key_size, &akey);
		if (val != 0){
			printf ("AES_set_decrypt_key Failed\n");
		}
		str2hex(aes_ecb_dec[i].plain,exp_out_text,&len);
		str2hex(aes_ecb_dec[i].cipher,in_text,&len);		
		for (j = 0; j <(unsigned int ) len; j += 16) {
			AES_ecb_encrypt (&in_text[j], &out_text[j],
									&akey, AES_DECRYPT);
		}	
		if (memcmp (out_text,exp_out_text, len)) {
			printf("AES ECB Decrypt failed\n");
			DUMP_BUFF("Expected\n",in_text,16);
			DUMP_BUFF("Actual\n",out_text,len);
			fail++;
		}
		cnt++;
	}
	// Monte carlo Encrypt
	for (i=0;i < (sizeof (aes_ecb_mct_enc)/sizeof (aes_ecb_mct_enc[0]));i=i+3) {
		memset (key, 0, sizeof (key));
		memset (in_text, 0, sizeof (in_text));
		str2hex(aes_ecb_mct_enc [i].key,key,&len);
		str2hex(aes_ecb_mct_enc [i].plain,in_text,&len);
		if ( aes_ecb_mct_enc [i].key_size == 128 ) {
		aes_type = AES_128;
		}
		else if (aes_ecb_mct_enc [i].key_size == 192 ) {
		aes_type = AES_192;
		}
		else if (aes_ecb_mct_enc [i].key_size == 256 ) {
		aes_type = AES_256;
		}
	
		fail =fail +MonteCarloEcbEncrypt(key, aes_type, in_text,i,&cnt);
	}
	// Monte carlo Decrypt
	for (i=0;i < sizeof (aes_ecb_mct_dec)/sizeof (aes_ecb_mct_dec[0]);i=i+3) {
		memset (key, 0, sizeof (key));
		memset (in_text, 0, sizeof (in_text));
		str2hex(aes_ecb_mct_dec [i].key,key,&len);
		str2hex(aes_ecb_mct_dec [i].cipher,in_text,&len);
		if ( aes_ecb_mct_dec [i].key_size == 128 ) {
		aes_type = AES_128;
		}
		else if (aes_ecb_mct_dec [i].key_size == 192 ) {
		aes_type = AES_192;
		}
		else if (aes_ecb_mct_dec [i].key_size == 256 ) {
		aes_type = AES_256;
		}
	
		fail =fail +MonteCarloEcbDecrypt(key, aes_type, in_text,i,&cnt);
	
	}
	if (fail)
		printf("***");
	
	if (cvmx_is_init_core()) 
		printf ("%-20s :Total Test vectors tested: %d passed : %d failed : %d\n","AES-ECB",cnt,(cnt-fail),fail);
	return 0;
}


int test_aes_ecb ()
{	
	uint8_t encbuff[MAX_BUFF_SIZE];
	uint8_t decbuff[MAX_BUFF_SIZE];
	uint8_t inbuff[MAX_BUFF_SIZE];
	unsigned int inlen;
	const uint8_t aes_key[][32] = {
		/*AES 128 bit key*/
		{0x09,0x28,0x34,0x74,0x00,0x12,0xab,0x45,
		 0x93,0x67,0x56,0x37,0xca,0xaf,0xff,0xbb},
		/*AES 192 bit key*/
		{0x23,0x98,0x74,0xaa,0xbd,0xef,0xad,0x94,
		 0x8b,0xcd,0xf7,0x36,0x4b,0xca,0xc7,0xbc,
		 0x84,0xd8,0x47,0x46,0x69,0x47,0x00,0xcd},
		/*AES 256 bit key*/
		{0x91,0x28,0x73,0x48,0x72,0x13,0x46,0x87,
		 0x16,0xab,0xde,0x84,0x7b,0xc4,0x87,0xad,
		 0x98,0x8d,0xdf,0xff,0xf7,0x38,0x46,0xbc,
		 0xad,0xef,0x54,0x76,0x84,0x73,0x64,0x78}
	};
	int keylen = 0;
	AES_KEY akey_ecb;
	int ret = 0;
	uint32_t i;

	int cnt;
	memset (inbuff, 0, sizeof (inbuff));	
	for (inlen=START_PACKET_SIZE; inlen<=MAX_BUFF_SIZE;){
		if (inlen%16) { 
			printf ("Error..For AES to work inlen must be multiple to "
					"16 bytes\n");
			return -1;
		}
		for (i = prev_inlen; i < inlen; i++) {
			inbuff[i] = cvmx_rng_get_random8 (); 
		}
	cnt = 0;
	for (keylen = 128; keylen <= 256; keylen += 64){
	 ret = AES_set_encrypt_key (aes_key[cnt], keylen, &akey_ecb);
		if (ret != 0){
			printf ("AES_set_encrypt_key Failed\n");
			ret = -1;
			goto End;
		}
		for (i = 0; i < inlen; i += AES_CHUNK_SIZE)
			AES_ecb_encrypt (&inbuff[i], &encbuff[i], &akey_ecb, AES_ENCRYPT);
		
		ret = AES_set_decrypt_key (aes_key[cnt], keylen, &akey_ecb);
		if (ret != 0){
			printf ("AES_set_decrypt_key Failed\n");
			ret = -1;
		}
		for (i = 0; i < inlen; i += AES_CHUNK_SIZE)
			AES_ecb_encrypt (&encbuff[i], &decbuff[i], &akey_ecb, AES_DECRYPT);
		
		if (memcmp (inbuff, decbuff, inlen)) {
			printf ("AES%d-ECB Failed for input size:%u\n",keylen,inlen);
			ret = -1;
			goto End;
		}
		cnt++;
	}
	prev_inlen = inlen;
	#ifdef TEST_CPU_CYCLES
		inlen+=inlen;
	#else	
		inlen+=INCR_STEPS;
	#endif
}
	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","AES-ECB",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End :
	return ret;
}

int test_aes_ctr_kat () {
	uint8_t encbuff[MAX_BUFF_SIZE] = {0};
	unsigned int i, fail = 0;
	for (i = 0;i < sizeof aes_ctr_rfc/sizeof aes_ctr_rfc [0];i++) {
		cvm_crypto_aes_ctr_encrypt ((uint64_t *) aes_ctr_rfc [i].key, aes_ctr_rfc [i].key_len ,
										aes_ctr_rfc [i].iv, aes_ctr_rfc [i].nonce, (uint64_t *) aes_ctr_rfc [i].inbuff,
										aes_ctr_rfc [i].inbuff_size, (uint64_t*)encbuff);
		if (memcmp (encbuff,aes_ctr_rfc [i].exp_buff,aes_ctr_rfc [i].inbuff_size)) {
			printf("AES-CTR Known Answer Test failed for test case %d\n",i);
			DUMP_BUFF ("OUTPUT\n",encbuff,32);
			DUMP_BUFF ("Expect\n",aes_ctr_rfc[i].exp_buff,32);
			fail++;
		}
	}
	if (fail)
		printf("***");
	if (cvmx_is_init_core()) 
		printf ("%-20s :Total Test vectors tested: %d passed : %d failed : %d\n","AES-CTR",i,(i-fail),fail);
	return 0;
}
 


int test_aes_ctr ()
{	
	uint8_t encbuff[MAX_BUFF_SIZE] = {0};
	uint8_t decbuff[MAX_BUFF_SIZE] = {0};
	uint8_t inbuff[MAX_BUFF_SIZE];
	unsigned int inlen;
	uint8_t key[][32] = { 
		/* 128 bit key */
		{0xae,0x68,0x52,0xf8,0x12,0x10,0x67,0xcc,
		 0x4b,0xf7,0xa5,0x76,0x55,0x77,0xf3,0x9e},
		/* 192 bit key */
		{0x16,0xaf,0x5B,0x14,0x5f,0xc9,0xf5,0x79,
		 0xc1,0x75,0xf9,0x3e,0x3b,0xfb,0x0e,0xed,
		 0x86,0x3d,0x06,0xcc,0xfd,0xb7,0x85,0x15},
		/* 256 bit key */
		{0x77,0x6b,0xef,0xf2,0x85,0x1d,0xb0,0x6f,
		 0x4c,0x8a,0x05,0x42,0xc8,0x69,0x6f,0x6c,
		 0x6a,0x81,0xaf,0x1e,0xec,0x96,0xb4,0xd3,
		 0x7f,0xc1,0xd6,0x89,0xe6,0x0c,0xc1,0x04}
	};

	uint64_t iv[] = {0x0};
	uint32_t nonce = 0x00000030;
	int ret = 0;
	int keylen;
	unsigned int i = 0;
	#ifndef TEST_CPU_CYCLES
	uint32_t cnt;
	AES_KEY aeskey;
	AES_CTR_CTX state[1];
 	#else
 		uint64_t orig_iv[] = {0};
	#endif
	memset (inbuff, 0, sizeof (inbuff));	
	for (inlen=START_PACKET_SIZE; inlen<=MAX_BUFF_SIZE;){
		PRINT_HDR;
		if (inlen%16) { 
			printf ("Error..For AES to work inlen must be multiple to "
					"16 bytes\n");
			return -1;
		}
		for (i = prev_inlen; i < inlen; i++) {
			inbuff[i] = cvmx_rng_get_random8 (); 
		}
	i=0;
	for (keylen = 128; keylen <= 256; keylen += 64){
	/* AES CTR single call NonInplace */
		START_CYCLE;
		cvm_crypto_aes_ctr_encrypt ((uint64_t *) key[i], keylen, 
									iv[0], nonce, (uint64_t *) inbuff, 
									inlen, (uint64_t*)encbuff);
		END_CYCLE_AES("cvm_crypto_aes_ctr_encrypt",keylen);
		START_CYCLE;
		cvm_crypto_aes_ctr_decrypt ((uint64_t *)key[i], keylen, 
									iv[0], nonce, (uint64_t*)encbuff, 
									inlen, (uint64_t*)decbuff);
		END_CYCLE_AES("cvm_crypto_aes_ctr_decrypt",keylen);

		if (memcmp (inbuff, decbuff, inlen)) {
			printf ("cvm_crypto_aes_ctr Single Call NonInplace API "
					"(key:%d) Failed\n", 128);	
			ret = -1;
			goto End;
		}

#ifndef TEST_CPU_CYCLES
		/* AES CTR single call Inplace */
		memset (decbuff, 0, sizeof (decbuff));
		memcpy (decbuff, inbuff, inlen);
		cvm_crypto_aes_ctr_encrypt ((uint64_t *) key[i], keylen, 
									iv[0], nonce, (uint64_t *) decbuff, 
									inlen, (uint64_t *) decbuff);

		cvm_crypto_aes_ctr_decrypt ((uint64_t *)key[i], keylen, 
									iv[0], nonce, (uint64_t *) decbuff, 
									inlen, (uint64_t *) decbuff);

		if (memcmp (inbuff, decbuff, inlen)) {
			printf ("cvm_crypto_aes_ctr Single Call Inplace API "
					"(key:%d) Failed\n", 128);	
			ret = -1;
			goto End;
		}

		/* AES CTR multicall NonInplace */
		memset (encbuff, 0, sizeof (encbuff));
		memset (decbuff, 0, sizeof (decbuff));
		cvm_crypto_aes_ctr_encrypt_init (key[i], keylen, &aeskey, 
										 iv[0], nonce, state);

		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE){
			if ((inlen-cnt) <= AES_CHUNK_SIZE){
				cvm_crypto_aes_ctr_encrypt_final (&aeskey, &inbuff[cnt],
												(inlen-cnt), 
												&encbuff[cnt], state);
			} else {
				cvm_crypto_aes_ctr_encrypt_update (&aeskey, &inbuff[cnt],
												 AES_CHUNK_SIZE,
												 &encbuff[cnt], state);
			}
		}

		cvm_crypto_aes_ctr_decrypt_init (key[i], keylen, &aeskey, 
										 iv[0], nonce, state);
		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE){
			if ((inlen-cnt) <= AES_CHUNK_SIZE){
				cvm_crypto_aes_ctr_decrypt_final (&aeskey, &encbuff[cnt], 
												(inlen-cnt),
												&decbuff[cnt], state);
			} else {
				cvm_crypto_aes_ctr_decrypt_update (&aeskey, &encbuff[cnt], 
												AES_CHUNK_SIZE,
												&decbuff[cnt], state);
			}
		}
		if (memcmp (inbuff, decbuff, inlen)) {
			printf ("cvm_crypto_aes_ctr Multicall NonInplace API "
					"(key:%d) Failed\n", 128);	
			ret = -1;
			goto End;
		}

		/* AES CTR multicall Inplace */
		memset (decbuff, 0, sizeof (decbuff));
		memcpy (decbuff, inbuff, inlen);
		cvm_crypto_aes_ctr_encrypt_init (key[i], keylen, &aeskey, 
										 iv[0], nonce, state);

		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE){
			if ((inlen-cnt) <= AES_CHUNK_SIZE){
				cvm_crypto_aes_ctr_encrypt_final (&aeskey, &decbuff[cnt],
												(inlen-cnt), 
												&decbuff[cnt], state);
			} else {
				cvm_crypto_aes_ctr_encrypt_update (&aeskey, &decbuff[cnt],
												 AES_CHUNK_SIZE,
												 &decbuff[cnt], state);
			}
		}

		cvm_crypto_aes_ctr_decrypt_init (key[i], keylen, &aeskey, 
										 iv[0], nonce, state);
		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE){
			if ((inlen-cnt) <= AES_CHUNK_SIZE){
				cvm_crypto_aes_ctr_decrypt_final (&aeskey, &decbuff[cnt], 
												(inlen-cnt),
												&decbuff[cnt], state);
			} else {
				cvm_crypto_aes_ctr_decrypt_update (&aeskey, &encbuff[cnt], 
												AES_CHUNK_SIZE,
												&decbuff[cnt], state);
			}
		}
		if (memcmp (inbuff, decbuff, inlen)) {
			printf ("cvm_crypto_aes_ctr Multicall NonInplace API "
					"(key:%d) Failed\n", 128);	
			ret = -1;
			goto End;
		}
#endif
		i++;
	}
		prev_inlen = inlen;
	#ifdef TEST_CPU_CYCLES
		inlen+=inlen;
	#else	
		inlen+=INCR_STEPS;
	#endif
}
	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","AES-CTR",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End :
	return ret;
}

int test_aes_icm_kat () {	
	if (cvmx_is_init_core())	
		printf (" *** AES-ICM Known Answer Test not available ***\n");
	return 0;
}

int test_aes_icm ()
{	
	uint8_t encbuff[MAX_BUFF_SIZE] = {0};
	uint8_t decbuff[MAX_BUFF_SIZE] = {0};
	uint64_t iv[] = { 0x000000300000ULL,0x00000001ULL};
	uint8_t key[][32] = { 
		/* 128 bit key */
		{0xae,0x68,0x52,0xf8,0x12,0x10,0x67,0xcc,
		 0x4b,0xf7,0xa5,0x76,0x55,0x77,0xf3,0x9e},
		/* 192 bit key */
		{0x16,0xaf,0x5B,0x14,0x5f,0xc9,0xf5,0x79,
		 0xc1,0x75,0xf9,0x3e,0x3b,0xfb,0x0e,0xed,
		 0x86,0x3d,0x06,0xcc,0xfd,0xb7,0x85,0x15},
		/* 256 bit key */
		{0x77,0x6b,0xef,0xf2,0x85,0x1d,0xb0,0x6f,
		 0x4c,0x8a,0x05,0x42,0xc8,0x69,0x6f,0x6c,
		 0x6a,0x81,0xaf,0x1e,0xec,0x96,0xb4,0xd3,
		 0x7f,0xc1,0xd6,0x89,0xe6,0x0c,0xc1,0x04}
	};
	int keylen;
	unsigned int i = 0;
	uint8_t inbuff[MAX_BUFF_SIZE];
	unsigned int inlen;
	int ret = 0;
#ifndef TEST_CPU_CYCLES
	uint32_t cnt;
	AES_KEY aeskey;
	AES_ICM_CTX state[1];
#else
 uint64_t orig_iv[] = {0ULL, 0ULL};
#endif
	memset (inbuff, 0, sizeof (inbuff));	
	for (inlen=START_PACKET_SIZE; inlen<=MAX_BUFF_SIZE;){
		PRINT_HDR;
		if (inlen%16) { 
			printf ("Error..For AES to work inlen must be multiple to "
					"16 bytes\n");
			return -1;
		}
		for (i = prev_inlen; i < inlen; i++) {
			inbuff[i] = cvmx_rng_get_random8 (); 
		}
 
	i=0;
	for (keylen = 128; keylen <= 256; keylen += 64){
		/* AES ICM single call NonInplace */
		START_CYCLE;
		cvm_crypto_aes_icm_encrypt ((uint64_t *) key[i], keylen, iv,
									(uint64_t *) inbuff, inlen, 
									(uint64_t *)encbuff);
		END_CYCLE_AES("cvm_crypto_aes_icm_encrypt", keylen);
		START_CYCLE;
		cvm_crypto_aes_icm_decrypt ((uint64_t *) key[i], keylen, iv, 
									(uint64_t *) encbuff, inlen, 
									(uint64_t *) decbuff);
		END_CYCLE_AES("cvm_crypto_aes_icm_decrypt", keylen);
		if (memcmp (inbuff, decbuff, inlen)){
			printf ("AES%d-ICM Single Call NonInplace API Failed\n", keylen);
			ret = -1;
			goto End;
		}

#ifndef TEST_CPU_CYCLES
		/* AES ICM single call Inplace */
		memset (decbuff, 0, sizeof (decbuff));
		memcpy (decbuff, inbuff, inlen);
		cvm_crypto_aes_icm_encrypt ((uint64_t *) key[i], keylen, iv,
									(uint64_t *) decbuff, inlen, 
									(uint64_t *) decbuff);
		cvm_crypto_aes_icm_decrypt ((uint64_t *) key[i], keylen, iv, 
									(uint64_t *) decbuff, inlen, 
									(uint64_t *) decbuff);
		if (memcmp (inbuff, decbuff, inlen)){
			printf ("AES%d-ICM Single Call Inplace API Failed\n", keylen);
			ret = -1;
			goto End;
		}
		
		/* AES ICM multicall NonInplace */
		memset (encbuff, 0, sizeof (encbuff));
		memset (decbuff, 0, sizeof (decbuff));
		
		cvm_crypto_aes_icm_encrypt_init (key[i], keylen, &aeskey, iv, state);
		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE){
			if ((inlen-cnt) <= AES_CHUNK_SIZE) {
				cvm_crypto_aes_icm_encrypt_final (&aeskey, &inbuff[cnt], 
												(inlen-cnt),
												&encbuff[cnt], state);
			} else {
				cvm_crypto_aes_icm_encrypt_update (&aeskey, &inbuff[cnt], 
												 AES_CHUNK_SIZE,
												 &encbuff[cnt], state);
			}
		}

		cvm_crypto_aes_icm_decrypt_init (key[i], keylen, &aeskey, iv, state);
		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE){
			if ((inlen-cnt) <= AES_CHUNK_SIZE) {
				cvm_crypto_aes_icm_decrypt_final (&aeskey, &encbuff[cnt], 
												(inlen-cnt),
												&decbuff[cnt], state);
			} else {
				cvm_crypto_aes_icm_decrypt_update (&aeskey, &encbuff[cnt], 
												 AES_CHUNK_SIZE,
												 &decbuff[cnt], state);
			}
		}
		if (memcmp (inbuff, decbuff, inlen)){
			printf ("AES%d-ICM Multicall NonInplace API Failed\n",keylen);
			ret = -1;
			goto End;
		}

		/* AES ICM multicall Inplace */
		memset (decbuff, 0, sizeof (decbuff));
		memcpy (decbuff, inbuff, inlen);
		
		cvm_crypto_aes_icm_encrypt_init (key[i], keylen, &aeskey, iv, state);
		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE){
			if ((inlen-cnt) <= AES_CHUNK_SIZE) {
				cvm_crypto_aes_icm_encrypt_final (&aeskey, &decbuff[cnt], 
												(inlen-cnt),
												&decbuff[cnt], state);
			} else {
				cvm_crypto_aes_icm_encrypt_update (&aeskey, &decbuff[cnt], 
												 AES_CHUNK_SIZE,
												 &decbuff[cnt], state);
			}
		}

		cvm_crypto_aes_icm_decrypt_init (key[i], keylen, &aeskey, iv, state);
		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE){
			if ((inlen-cnt) <= AES_CHUNK_SIZE) {
				cvm_crypto_aes_icm_decrypt_final (&aeskey, &decbuff[cnt], 
												(inlen-cnt),
												&decbuff[cnt], state);
			} else {
				cvm_crypto_aes_icm_decrypt_update (&aeskey, &decbuff[cnt], 
												 AES_CHUNK_SIZE,
												 &decbuff[cnt], state);
			}
		}
		if (memcmp (inbuff, decbuff, inlen)){
			printf ("AES%d-ICM Multicall Inplace API Failed\n",keylen);
			ret = -1;
			goto End;
		}
#endif
		i++;
	}
		prev_inlen = inlen;
	#ifdef TEST_CPU_CYCLES
		inlen+=inlen;
	#else	
		inlen+=INCR_STEPS;
	#endif
}
	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","AES-ICM",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}

int test_aes_lrw_kat () {	
	if (cvmx_is_init_core())	
		printf (" *** AES-LRW Known Answer Test not available ***\n");
	return 0;
}

int test_aes_lrw ()
{	
	uint8_t encbuff[MAX_BUFF_SIZE] = {0};
	uint8_t decbuff[MAX_BUFF_SIZE] = {0};
	uint8_t key[][48] = {
		/* AES LRW key 256 bit*/
		{0xd8,0x2a,0x91,0x34,0xb2,0x6a,0x56,0x50,
		 0x30,0xfe,0x69,0xe2,0x37,0x7f,0x98,0x47,
		 0x4e,0xb5,0x5d,0x31,0x05,0x97,0x3a,0x3f,
		 0x5e,0x23,0xda,0xfb,0x5a,0x45,0xd6,0xc0},
		/* AES LRW key 320 bit*/
		{0x0f,0x6a,0xef,0xf8,0xd3,0xd2,0xbb,0x15,
		 0x25,0x83,0xf7,0x3c,0x1f,0x01,0x28,0x74,
		 0xca,0xc6,0xbc,0x35,0x4d,0x4a,0x65,0x54,
		 0x90,0xae,0x61,0xcf,0x7b,0xae,0xbd,0xcc,
		 0xad,0xe4,0x94,0xc5,0x4a,0x29,0xae,0x70},
		/* AES LRW key 384 bit*/
		{0xfb,0x76,0x15,0xb2,0x3d,0x80,0x89,0x1d,
		 0xd4,0x70,0x98,0x0b,0xc7,0x95,0x84,0xc8,
		 0xb2,0xfb,0x64,0xce,0x60,0x97,0x87,0x8d,
		 0x17,0xfc,0xe4,0x5a,0x49,0xe8,0x30,0xb7,
		 0x85,0xb1,0xca,0x1a,0x9e,0x19,0x95,0xda,
		 0x06,0xff,0xfc,0xb0,0x16,0x22,0x0f,0x6f}
	};
	uint8_t tweak[] = 
		{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		 0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00};

	int keylen;
	uint8_t inbuff[MAX_BUFF_SIZE];
	unsigned int inlen;
	int ret = 0;
	unsigned int i = 0;
#ifndef TEST_CPU_CYCLES
	lrw_aes_ctx_t lrw_ctx;
#else
 // These are added avoid compilation errors while measuring the cycles.
 uint8_t iv[8] = {0};
 uint8_t orig_iv[8] = {0};
#endif
memset (inbuff, 0, sizeof (inbuff));	
	for (inlen=START_PACKET_SIZE; inlen<=MAX_BUFF_SIZE;){
		PRINT_HDR;
		if (inlen%16) { 
			printf ("Error..For AES to work inlen must be multiple to "
					"16 bytes\n");
			return -1;
		}
		for (i = prev_inlen; i < inlen; i++) {
			inbuff[i] = cvmx_rng_get_random8 (); 
		}

	i=0;
	for (keylen = 256; keylen <= 384; keylen += 64){
		/* AES-LRW single call NonInplace */
		START_CYCLE;
		ret = LRW_AES_encrypt (key[i], keylen, inbuff, inlen, tweak, encbuff);
		END_CYCLE_AES("LRW_AES_encrypt",keylen);
		if (ret != LRW_AES_SUCCESS){
			printf ("LRW_AES_encrypt Failed (keylen:%d)\n", keylen);
			ret = -1;
			goto End;
		}
		START_CYCLE;
		ret = LRW_AES_decrypt (key[i], keylen, encbuff, inlen, tweak, decbuff);
		END_CYCLE_AES("LRW_AES_decrypt",keylen);
		if (ret != LRW_AES_SUCCESS){
			printf ("LRW AES_decrypt Failed (keylen:%d)\n", keylen);
			ret = -1;
			goto End;
		}
		if (memcmp (inbuff, decbuff, inlen)){
			printf ("AES%d-LRW Single Call NonInplace Failed\n", keylen);
			ret = -1;
			goto End;
		}

#ifndef TEST_CPU_CYCLES
		/* AES-LRW single call Inplace */
		memset (decbuff, 0, sizeof (decbuff));
		memcpy (decbuff, inbuff, inlen);
		ret = LRW_AES_encrypt (key[i], keylen, decbuff, inlen, tweak, decbuff);
		if (ret != LRW_AES_SUCCESS){
			printf ("LRW_AES_encrypt Failed (keylen:%d)\n", keylen);
			ret = -1;
			goto End;
		}
		ret = LRW_AES_decrypt (key[i], keylen, decbuff, inlen, tweak, decbuff);
		if (ret != LRW_AES_SUCCESS){
			printf ("LRW AES_decrypt Failed (keylen:%d)\n", keylen);
			ret = -1;
			goto End;
		}
		if (memcmp (inbuff, decbuff, inlen)){
			printf ("AES%d-LRW Single Call Inplace Failed\n", keylen);
			ret = -1;
			goto End;
		}

		/* AES-LRW multicall NonInplace */
		ret = LRW_AES_set_key (key[i], keylen, tweak, &lrw_ctx);
		if (ret != LRW_AES_SUCCESS){
			printf ("LRW_AES_set_key Failed (keylen : %d)\n", keylen);
			ret = -1;
			goto End;
		}
		ret = LRW_AES_ctx_encrypt (inbuff, inlen, encbuff, &lrw_ctx);
		if (ret != LRW_AES_SUCCESS){
			printf ("LRW_AES_ctx_encrypt Failed\n");
			ret = -1;
			goto End;
		}

		ret = LRW_AES_set_key (key[i], keylen, tweak, &lrw_ctx);
		if (ret != LRW_AES_SUCCESS){
			printf ("LRW_AES_set_key Failed (keylen : %d)\n", keylen);
			ret = -1;
			goto End;
		}
		ret = LRW_AES_ctx_decrypt (encbuff, inlen, decbuff, &lrw_ctx);
		if (ret != LRW_AES_SUCCESS){
			printf ("LRW_AES_ctx_encrypt Failed\n");
			ret = -1;
			goto End;
		}
		if (memcmp (inbuff, decbuff, inlen)){
			printf ("AES%d-LRW Multicall NonInplace Failed\n", keylen);
			ret = -1;
			goto End;
		}

		/* AES-LRW multicall Inplace */
		memset (decbuff, 0, sizeof (decbuff));
		memcpy (decbuff, inbuff, inlen);
		ret = LRW_AES_set_key (key[i], keylen, tweak, &lrw_ctx);
		if (ret != LRW_AES_SUCCESS){
			printf ("LRW_AES_set_key Failed (keylen : %d)\n", keylen);
			ret = -1;
			goto End;
		}
		ret = LRW_AES_ctx_encrypt (decbuff, inlen, decbuff, &lrw_ctx);
		if (ret != LRW_AES_SUCCESS){
			printf ("LRW_AES_ctx_encrypt Failed\n");
			ret = -1;
			goto End;
		}

		ret = LRW_AES_set_key (key[i], keylen, tweak, &lrw_ctx);
		if (ret != LRW_AES_SUCCESS){
			printf ("LRW_AES_set_key Failed (keylen : %d)\n", keylen);
			ret = -1;
			goto End;
		}
		ret = LRW_AES_ctx_decrypt (decbuff, inlen, decbuff, &lrw_ctx);
		if (ret != LRW_AES_SUCCESS){
			printf ("LRW_AES_ctx_encrypt Failed\n");
			ret = -1;
			goto End;
		}
		if (memcmp (inbuff, decbuff, inlen)){
			printf ("AES%d-LRW Multicall Inplace Failed\n", keylen);
			ret = -1;
			goto End;
		}
#endif
		i++;
	}
		prev_inlen = inlen;
	#ifdef TEST_CPU_CYCLES
		inlen+=inlen;
	#else	
		inlen+=INCR_STEPS;
	#endif
}
	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","AES-LRW",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}

int test_aes_ccm_kat ()
{
	unsigned int i;
	uint8_t cipher_text[50], Auth[16], enc_packet[MAX_BUFF_SIZE]; 
	int ret_block = 0;
	uint8_t plain_text[50], dec_packet[MAX_BUFF_SIZE], input_packet[MAX_BUFF_SIZE];
	int cnt = 0, fail = 0, ret = 0;
	uint8_t *pin;
	uint8_t *cin;

	/* single call */
	for (i = 0; i < sizeof(pkt)/sizeof(pkt[0]); i++) {
		AES_ccm_nist_t packet = pkt[i];
		
		pin =(packet.input+packet.alen);
		ret_block = AES_CCM_encrypt(packet.m, packet.l, (uint8_t *)packet.val, (uint8_t *)packet.key, packet.klen, pin, packet.plen,
							packet.input, packet.alen, cipher_text, Auth);
		if(ret_block!=0) {
			printf("AES CCM Encrypt Failed\n");	
			ret = -1;
			goto End;
		}
		
		memset(enc_packet,0,MAX_BUFF_SIZE);
		memcpy(enc_packet, packet.input, packet.alen);
		memcpy((enc_packet+packet.alen), cipher_text,packet.plen);
		memcpy((enc_packet+packet.alen+packet.plen), Auth, packet.m);
        
		if (memcmp(enc_packet, packet.output, (packet.alen+packet.plen+packet.m))) {
			printf("AES_CCM Failed during Encryption\n");
			ret = -1;
			goto End;
		}
			
		cin = cipher_text;
		ret_block = AES_CCM_decrypt(packet.m, packet.l, (uint8_t *)packet.val, (uint8_t *)packet.key , packet.klen, cin, packet.plen,
							packet.input, packet.alen, plain_text, Auth); 
		if(ret_block!=0) {
			printf("AES CCM Decrypt Failed\n");
			ret = -1;
			goto End;
		}
		
		memset(dec_packet, 0, MAX_BUFF_SIZE);
		memset(input_packet, 0, MAX_BUFF_SIZE);
		memcpy(dec_packet, packet.input, packet.alen);
		memcpy((dec_packet+packet.alen), plain_text,packet.plen);
		memcpy((input_packet), packet.input, (packet.alen+packet.plen));
		memcpy((dec_packet+packet.alen+packet.plen), Auth, packet.m);
		memcpy((input_packet+packet.alen+packet.plen), Auth, packet.m);

		if (memcmp(dec_packet, input_packet, (packet.alen+packet.plen+packet.m))){
			printf("AES_CCM Failed during Decryption\n");
			ret = -1;	
			fail++;
			goto End;
		}
		cnt++;
	}

	/* Multi call */
	for (i = 0; i < sizeof(pkt)/sizeof(pkt[0]); i++) {
		AES_ccm_nist_t packet = pkt[i];

		// Encrypt
		aes_ccm_ctx aes_ctx;
		ret_block = AES_CCM_setup_blocks(packet.m, packet.l, packet.input, 
						packet.alen, packet.plen, packet.val, &aes_ctx);
		if(ret_block) {
			printf("AES_CCM_SETUP_BLOCKS Failed.\n");
			ret = -1;
			goto End;
		}
    
		AES_CCM_set_key(packet.key, packet.klen);
		AES_CCM_init(&aes_ctx);

		pin =(packet.input+packet.alen);
		AES_CCM_ctx_encrypt(pin, packet.plen, packet.input,
                          packet.alen, cipher_text, Auth, &aes_ctx);
    
		memset(enc_packet,0,MAX_BUFF_SIZE);
		memcpy(enc_packet, packet.input, packet.alen);
		memcpy((enc_packet+packet.alen), cipher_text,packet.plen);
		memcpy((enc_packet+packet.alen+packet.plen), Auth, packet.m);

		if (memcmp(enc_packet, packet.output, (packet.alen+packet.plen+packet.m))) {
			printf("AES_CCM Failed during Encryption\n");	
			ret = -1;
			goto End;
		}
			
		// Decrypt
		ret_block = AES_CCM_setup_blocks(packet.m, packet.l, packet.input, packet.alen,
									 packet.plen, packet.val, &aes_ctx);
		if(ret_block) {
			printf("AES_CCM_SETUP_BLOCKS Failed.\n");
			ret = -1;
			goto End;
		}

		AES_CCM_set_key(packet.key, packet.klen);
		AES_CCM_init(&aes_ctx);

		cin = cipher_text;
		AES_CCM_ctx_decrypt(cin , packet.plen, packet.input, packet.alen,
                        plain_text, Auth, &aes_ctx);

		memset(dec_packet, 0, MAX_BUFF_SIZE);
		memset(input_packet, 0, MAX_BUFF_SIZE);
		memcpy(dec_packet, packet.input, packet.alen);
		memcpy((dec_packet+packet.alen), plain_text,packet.plen);
		memcpy((input_packet), packet.input, (packet.alen+packet.plen));
		memcpy((dec_packet+packet.alen+packet.plen), Auth, packet.m);
		memcpy((input_packet+packet.alen+packet.plen), Auth, packet.m);

		if (memcmp(dec_packet, input_packet, (packet.alen+packet.plen+packet.m))){
			printf("AES_CCM Failed during Decryption\n");
			fail++;
			ret = -1;
			goto End;
		}
		cnt++;
	} 
End:
	if (cvmx_is_init_core())
		printf("%-20s :Total Test vectors tested: %d passed : %d failed : %d\n","AES-CCM",cnt,(cnt-fail),fail);
	return ret;
}

int test_aes_ccm ()
{
	uint64_t key[][4] = {
							{0xc0c1c2c3c4c5c6c7ull,0xc8c9cacbcccdcecfull},
        					{0x146A163BBF10746Eull,0x7C1201546BA46DE7ull,0x69BE23F9D7CC2C80ull},
        					{0x9074B1AE4CA3342Full,0xE5BF6F14BCF2F279ull,0x04F0B15179D95A65ull,0x4F61E699692E6F71ull},
						};
	uint64_t val[2] = {0x00000003020100a0ull,0xa1a2a3a4a5000000ull}; 
	uint8_t ain[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
	uint32_t m = 8;// size of MAC
	uint8_t Auth[8];
	uint32_t alen = 8; //strlen of associated data	
	uint32_t l = 2;// N :Number of bytes to represent the plen(Noncelength = 15-l)
	uint32_t i,j=0;
	int ret = 0; 
	unsigned int inlen;	
	uint32_t keylen;		
	uint8_t pin[MAX_BUFF_SIZE], dec[MAX_BUFF_SIZE];	
	uint8_t c[MAX_BUFF_SIZE];		

#ifndef TEST_CPU_CYCLES
	aes_ccm_ctx aes_ctx;	
#else
 // These are added avoid compilation errors while measuring the cycles.
 	uint8_t iv[8] = {0};
 	uint8_t orig_iv[8] = {0};
#endif

	/* Single call */ 
	for (inlen=START_PACKET_SIZE; inlen<=MAX_BUFF_SIZE;) {		
		PRINT_HDR;
		for (i = prev_inlen; i < inlen; i++) {
			pin[i] = cvmx_rng_get_random8 (); 
		}
		j=0;
		for (keylen = 128; keylen <= 256; keylen += 64) {	
			// Encrypt			
			START_CYCLE;
			ret=AES_CCM_encrypt(m, l, (uint8_t *)val, (uint8_t *)key[j] , keylen, pin, inlen,
					ain, alen, c, Auth); 
			END_CYCLE_AES("AES_CCM_encrypt",keylen);
			if(ret!=0) {
				printf("AES CCM Encrypt Failed\n");
				ret = -1;
				goto End;
			}
			// Decrypt	
			START_CYCLE;
			ret=AES_CCM_decrypt(m, l, (uint8_t *)val, (uint8_t *)key[j] , keylen, c, inlen,
					 ain,alen, dec, Auth);	
			END_CYCLE_AES("AES_CCM_decrypt",keylen);
			if(ret!=0) {
				printf("AES CCM Decrypt Failed\n");
				ret = -1;
				goto End;
			}
			if (memcmp(pin, dec, inlen)) { 
				printf("AES CCM Failed \n");
				ret = -1;
				goto End;
			}
		#ifndef TEST_CPU_CYCLES
		/* Multi call */
		// Encrypt 
			ret = AES_CCM_setup_blocks(m, l, ain, alen, inlen, val, &aes_ctx);
			if(ret) {
				printf("AES_CCM_setup_blocks Failed.\n");	
				ret = -1;
				goto End;
			}
			AES_CCM_set_key(key[j], keylen);
			AES_CCM_init(&aes_ctx);
			for(i = 0; i < inlen ; i += 16) {
				if ((inlen - i) < 16)
					ret = AES_CCM_ctx_encrypt(&pin[i], (inlen-i), ain, (i==0)?alen:0, 
								&c[i], Auth, &aes_ctx); 
				else
					ret = AES_CCM_ctx_encrypt(&pin[i], 16, ain, (i==0)?alen:0, &c[i], 
								Auth, &aes_ctx); 
			}
			if(ret) {
				printf("AES CCM Encrypt Failed\n");
				ret = -1;
				goto End;
			}
		// Decrypt 
			ret = AES_CCM_setup_blocks(m, l, ain, alen, inlen, val, &aes_ctx);
			if(ret) {
				printf("AES_CCM_setup_blocks Failed.\n");
				ret = -1;
				goto End;
			}
			AES_CCM_set_key(key[j], keylen);
			AES_CCM_init(&aes_ctx);
			for(i = 0; i < inlen ; i += 16) {
				if ((inlen - i) < 16)
					ret = AES_CCM_ctx_decrypt(&c[i], (inlen-i), ain, 
							(i==0)?alen:0, &dec[i], Auth, &aes_ctx);
				else
					ret = AES_CCM_ctx_decrypt(&c[i], 16, ain, 
							(i==0)?alen:0, &dec[i], Auth, &aes_ctx);
			}
			if(ret) {
				printf("AES CCM Decrypt Failed\n");
				ret = -1;
				goto End;
			}
			if (memcmp(pin, dec, inlen)) { 
				printf("AES CCM Failed \n");
				ret = -1;	
				goto End;
			}
		#endif
			j++;
		}
		#ifdef TEST_CPU_CYCLES
			inlen+=inlen;
		#else	
			inlen+=INCR_STEPS;
		#endif
		prev_inlen=inlen;
	}
	if (cvmx_is_init_core()) 
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","AES-CCM",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
End:
	return ret;
}

int test_aes_gcm_kat () {
	uint8_t iv[128];
	uint8_t tag[16];
	uint8_t tag1[16];
	uint8_t key[32];
	uint8_t in_text[400];
	uint8_t out_text[400];
	uint8_t aad[400];
	int len, len_key,len_iv, len_aad;
	int aadlen, ptlen, ivlen, taglen;
	int keytype=0;
	int ret=0,fail=0,cnt=0, val = 0;

			 /* Keylen */
			 /* Variables set to '0' */
				 ptlen = keytype = ivlen = aadlen = taglen = 0;
	for (i = 0;i < sizeof (aes_gcm_dec)/sizeof (aes_gcm_dec[0]);i++) {
		ivlen = aes_gcm_dec [i].IVlen;
		ptlen = aes_gcm_dec [i].PTlen;
		aadlen = aes_gcm_dec [i].AADlen;
		taglen = aes_gcm_dec [i].Taglen;
		keytype = aes_gcm_dec [i].Keylen;

		str2hex (aes_gcm_dec [i].key,key,&len_key);
		str2hex (aes_gcm_dec [i].iv,iv,&len_iv);
		str2hex (aes_gcm_dec [i].aad,aad,&len_aad);
		str2hex (aes_gcm_dec [i].ct,in_text,&len);
		/* Validation */
		if (len_iv != ivlen/8)
		{
			printf ("IV length Mismatch\n");
			}
		if (len_key != keytype/8)
		{
			printf ("Key length Mismatch\n");
			ret = -1;
			goto End;
		}
		if (len != ptlen/8)
		{
			printf ("PT length Mismatch, %d = %d\n", ptlen, len);
			ret = -1;
			goto End;
		}
		if (len_aad != aadlen/8)
		{
			printf ("AAD length Mismatch, %d = %d\n", aadlen, len_aad);
			ret = -1;
			goto End;
		}
		/* End Validation */

		val = AES_GCM_decrypt (key, len_key*8, iv, len_iv, aad,
								len_aad, in_text, len,
								out_text, tag1);
		if (val != 0) {
			printf ("AES_GCM_decrypt failed at line : %d\n",__LINE__);
		}
		str2hex (aes_gcm_dec [i].pt,in_text,&len);
		if (memcmp (in_text,out_text,len)) {
			printf("AES-GCM nist verification failed\n");
		}
		str2hex (aes_gcm_dec [i].tag,tag,&len);
		if (memcmp (tag,tag1,len)) {
			printf("AES-GCM nist verification failed\n");
			DUMP_BUFF("Plain Text\n",out_text,len);
			DUMP_BUFF("Tag\n",tag1,len);
			fail++;
		}
		cnt++;
	}
	for (i = 0;i < sizeof (aes_gcm_enc)/sizeof (aes_gcm_enc[0]);i++) {
		ivlen = aes_gcm_enc [i].IVlen;
		ptlen = aes_gcm_enc [i].PTlen;
		aadlen = aes_gcm_enc [i].AADlen;
		taglen = aes_gcm_enc [i].Taglen;
		keytype = aes_gcm_enc [i].Keylen;

		str2hex (aes_gcm_enc [i].key,key,&len_key);
		str2hex (aes_gcm_enc [i].iv,iv,&len_iv);
		str2hex (aes_gcm_enc [i].aad,aad,&len_aad);
		str2hex (aes_gcm_enc [i].pt,in_text,&len);
		/* Validation */
		if (len_iv != ivlen/8)
		{
			printf ("IV length Mismatch\n");
			}
		if (len_key != keytype/8)
		{
			printf ("Key length Mismatch\n");
			ret = -1;
			goto End;
		}
		if (len != ptlen/8)
		{
			printf ("PT length Mismatch, %d = %d\n", ptlen, len);
			ret = -1;
			goto End;
		}
		if (len_aad != aadlen/8)
		{
			printf ("AAD length Mismatch, %d = %d\n", aadlen, len_aad);
			ret = -1;
			goto End;
		}
		/* End Validation */

		val = AES_GCM_encrypt (key, len_key*8, iv, len_iv, aad,
								len_aad, in_text, len,
								out_text, tag1);
		str2hex (aes_gcm_enc [i].ct,in_text,&len);
		if (memcmp (in_text,out_text,len)) {
			printf("AES-GCM nist verification failed\n");
			DUMP_BUFF("Plain Text\n",out_text,len);
			DUMP_BUFF("Tag\n",tag1,len);
		}
		str2hex (aes_gcm_enc [i].tag,tag,&len);
		if (memcmp (tag,tag1,len)) {
			printf("AES-GCM nist verification failed\n");
			DUMP_BUFF("Plain Text\n",out_text,len);
			DUMP_BUFF("Tag\n",tag1,len);
			fail++;
		}
		cnt++;
	}

	if (fail)
		printf("***");
	if (cvmx_is_init_core()) {
		printf ("%-20s :Total Test vectors tested: %d passed : %d failed : %d\n","AES-GCM NIST",cnt,(cnt-fail),fail);
	}
End: 
	return ret;
} 



int test_aes_gcm ()
{	
	uint8_t encbuff[MAX_BUFF_SIZE] = {0};
	uint8_t decbuff[MAX_BUFF_SIZE] = {0};
	uint8_t key[][32] = { 
		/* 128 bit key */
		{0xae,0x68,0x52,0xf8,0x12,0x10,0x67,0xcc,
		 0x4b,0xf7,0xa5,0x76,0x55,0x77,0xf3,0x9e},
		/* 192 bit key */
		{0x16,0xaf,0x5B,0x14,0x5f,0xc9,0xf5,0x79,
		 0xc1,0x75,0xf9,0x3e,0x3b,0xfb,0x0e,0xed,
		 0x86,0x3d,0x06,0xcc,0xfd,0xb7,0x85,0x15},
		/* 256 bit key */
		{0x77,0x6b,0xef,0xf2,0x85,0x1d,0xb0,0x6f,
		 0x4c,0x8a,0x05,0x42,0xc8,0x69,0x6f,0x6c,
		 0x6a,0x81,0xaf,0x1e,0xec,0x96,0xb4,0xd3,
		 0x7f,0xc1,0xd6,0x89,0xe6,0x0c,0xc1,0x04}
	};

	uint8_t iv[] = 
		"0xab,0x23,0x4c,0xa7,0x69,0x07,0x67,0xa4,0xc8,0xd9,0xa5,0xef";
	unsigned int keylen;
	uint8_t auth_string[] = "This string is used for authentication";
	uint8_t tag1[16] = {0},tag2[16] = {0};
	int ret = 0;
	uint8_t inbuff[MAX_BUFF_SIZE];
	unsigned int inlen;
	uint32_t i = 0;

#ifndef TEST_CPU_CYCLES
	aes_gcm_ctx_t actx;
	uint32_t cnt;
	uint8_t tag3[16] = {0}, tag4[16] = {0};
	uint8_t tag5[16] = {0},tag6[16] = {0}, tag7[16] = {0},tag8[16] = {0};
#else
 // It is added avoid compilation errors while measuring the cycles.
 uint8_t orig_iv[16] = {0};
#endif
memset (inbuff, 0, sizeof (inbuff));	
	for (inlen=START_PACKET_SIZE; inlen<=MAX_BUFF_SIZE;){
		PRINT_HDR;
		if (inlen%16) { 
			printf ("Error..For AES to work inlen must be multiple to "
					"16 bytes\n");
			return -1;
		}
		for (i = prev_inlen; i < inlen; i++) {
			inbuff[i] = cvmx_rng_get_random8 (); 
		}

	i=0;
	for (keylen = 128; keylen <= 256; keylen += 64){
		/* AES-GCM single call NonInplace */
		START_CYCLE;
		ret = AES_GCM_encrypt (key[i], keylen, iv, 12, auth_string,
							 sizeof (auth_string), inbuff, inlen, 
							 encbuff, tag1);
		END_CYCLE_AES("AES_GCM_encrypt", keylen);
		if (ret != AES_GCM_SUCCESS){
			printf ("AES_GCM_encrypt Failed (keylen:%u)\n",keylen);
			ret = -1;
			goto End;
		}
		START_CYCLE;
		ret = AES_GCM_decrypt (key[i], keylen, iv, 12, auth_string, 
							 sizeof (auth_string), encbuff, inlen, 
							 decbuff, tag2);
		END_CYCLE_AES("AES_GCM_decrypt", keylen);
		if (ret != AES_GCM_SUCCESS){
			printf ("AES_GCM_decrypt Failed (keylen:%u)\n",keylen);
			ret = -1;
			goto End;
		}
		if (memcmp (inbuff, decbuff, inlen)){
			printf ("AES%u-GCM Single Call NonInplace Failed\n", keylen);
			ret = -1;
			goto End;

		}
		if (memcmp (tag1 , tag2 , 16)){
			printf ("AES%u-GCM Single Call NonInplace Failed - "
					"Tag Mismatch\n", keylen);
			ret = -1;
			goto End;

		}

#ifndef TEST_CPU_CYCLES
		/* AES-GCM single call Inplace */
		memset (decbuff, 0, sizeof (decbuff));
		memcpy (decbuff, inbuff, inlen);
		ret = AES_GCM_encrypt (key[i], keylen, iv, 12, auth_string,
							 sizeof (auth_string), decbuff, inlen, 
							 decbuff, tag3);
		if (ret != AES_GCM_SUCCESS){
			printf ("AES_GCM_encrypt Failed (keylen:%u)\n",keylen);
			ret = -1;
			goto End;
		}
		ret = AES_GCM_decrypt (key[i], keylen, iv, 12, auth_string, 
							 sizeof (auth_string), decbuff, inlen, 
							 decbuff, tag4);
		if (ret != AES_GCM_SUCCESS){
			printf ("AES_GCM_decrypt Failed (keylen:%u)\n",keylen);
			ret = -1;
			goto End;
		}
		if (memcmp (inbuff, decbuff, inlen)){
			printf ("AES%u-GCM Single Call Inplace Failed\n", keylen);
			ret = -1;
			goto End;
		}
		if (memcmp (tag3 , tag4 , 16)){
			printf ("AES%u-GCM Multi Call NonInplace Failed - "
					"Tag mismatch\n", keylen);
			ret = -1;
			goto End;

		}

		/* AES-GCM multicall NonInplace */
		/* AES-GCM encrypt */
		ret = AES_GCM_init_key (key[i], keylen, &actx);
		if (ret != AES_GCM_SUCCESS){
			printf ("AES_GCM_init_key Failed\n");
			ret = -1;
			goto End;
		}
		ret = AES_GCM_set_iv (iv, sizeof (iv), &actx);
		if (ret != AES_GCM_SUCCESS){
			printf ("AES_GCM_set_iv Failed\n");
			ret = -1;
			goto End;
		}
		ret = AES_GCM_set_aad (auth_string, sizeof(auth_string), &actx);
		if (ret != AES_GCM_SUCCESS){
			printf ("AES_GCM_set_aad Failed\n");
			ret = -1;
			goto End;
		}
		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE) {
			if ((inlen - cnt) < 16) {
				ret = AES_GCM_ctx_encrypt (&inbuff[cnt], (inlen - cnt), 
										 &encbuff[cnt], &actx);
			} else {
				ret = AES_GCM_ctx_encrypt (&inbuff[cnt], AES_CHUNK_SIZE, 
										 &encbuff[cnt], &actx);
			}
		 
		if (ret != AES_GCM_SUCCESS){
				printf ("AES_GCM_ctx_encrypt Failed\n");
				ret = -1;
				goto End;
			}
		}
		ret = AES_GCM_ctx_final(inlen, sizeof(auth_string), tag5, &actx);
		/* AES-GCM decrypt */
		ret = AES_GCM_init_key (key[i], keylen, &actx);
		if (ret != AES_GCM_SUCCESS){
			printf ("AES_GCM_init_key Failed\n");
			ret = -1;
			goto End;
		}
		ret = AES_GCM_set_iv (iv, sizeof (iv), &actx);
		if (ret != AES_GCM_SUCCESS){
			printf ("AES_GCM_set_iv Failed\n");
			ret = -1;
			goto End;
		}
		ret = AES_GCM_set_aad (auth_string, sizeof (auth_string), &actx);
		if (ret != AES_GCM_SUCCESS){
			printf ("AES_GCM_set_aad Failed\n");
			ret = -1;
			goto End;
		}
		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE) {
			if ((inlen - cnt) < 16) {
				ret = AES_GCM_ctx_decrypt (&encbuff[cnt], (inlen - cnt), 
										 &decbuff[cnt], &actx);
			} else {
				ret = AES_GCM_ctx_decrypt (&encbuff[cnt], AES_CHUNK_SIZE, 
										 &decbuff[cnt], &actx);
			}
			if (ret != AES_GCM_SUCCESS){
				printf ("AES_GCM_ctx_decrypt Failed\n");
				ret = -1;
				goto End;
			}
		}
		ret = AES_GCM_ctx_final(inlen, sizeof(auth_string),tag6,&actx);
		if (memcmp (inbuff, decbuff, inlen)){
			printf ("AES%u-GCM Multicall NonInplace Failed\n", keylen);
			ret = -1;
			goto End;
		}
		if (memcmp (tag5 , tag6 , 16)){
			printf ("AES%u-GCM Multi Call NonInplace Failed - "
					"Tag mismatch\n", keylen);
			ret = -1;
			goto End;

		}

		/* AES-GCM multicall Inplace */
		/* AES-GCM encrypt */
		memset (decbuff, 0, sizeof (decbuff));
		memcpy (decbuff, inbuff, inlen);
		ret = AES_GCM_init_key (key[i], keylen, &actx);
		if (ret != AES_GCM_SUCCESS){
			printf ("AES_GCM_init_key Failed\n");
			ret = -1;
			goto End;
		}
		ret = AES_GCM_set_iv (iv, sizeof (iv), &actx);
		if (ret != AES_GCM_SUCCESS){
			printf ("AES_GCM_set_iv Failed\n");
			ret = -1;
			goto End;
		}
		ret = AES_GCM_set_aad (auth_string, sizeof (auth_string), &actx);
		if (ret != AES_GCM_SUCCESS){
			printf ("AES_GCM_set_aad Failed\n");
			ret = -1;
			goto End;
		}
		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE) {
			if ((inlen - cnt) < 16) {
				ret = AES_GCM_ctx_encrypt (&decbuff[cnt], (inlen - cnt), 
										 &decbuff[cnt], &actx);
			} else {
				ret = AES_GCM_ctx_encrypt (&decbuff[cnt], AES_CHUNK_SIZE, 
										 &decbuff[cnt], &actx);
			}
			if (ret != AES_GCM_SUCCESS){
				printf ("AES_GCM_ctx_encrypt Failed\n");
				ret = -1;
				goto End;
			}
		}
		ret = AES_GCM_ctx_final(inlen, sizeof(auth_string),tag7,&actx);

		/* AES-GCM decrypt */
		ret = AES_GCM_init_key (key[i], keylen, &actx);
		if (ret != AES_GCM_SUCCESS){
			printf ("AES_GCM_init_key Failed\n");
			ret = -1;
			goto End;
		}
		ret = AES_GCM_set_iv (iv, sizeof (iv), &actx);
		if (ret != AES_GCM_SUCCESS){
			printf ("AES_GCM_set_iv Failed\n");
			ret = -1;
			goto End;
		}
		ret = AES_GCM_set_aad (auth_string, sizeof (auth_string), &actx);
		if (ret != AES_GCM_SUCCESS){
			printf ("AES_GCM_set_aad Failed\n");
			ret = -1;
			goto End;
		}
		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE) {
			if ((inlen - cnt) < 16) {
				ret = AES_GCM_ctx_decrypt (&decbuff[cnt], (inlen - cnt), 
										 &decbuff[cnt], &actx);
			} else {
				ret = AES_GCM_ctx_decrypt (&decbuff[cnt], AES_CHUNK_SIZE, 
										 &decbuff[cnt], &actx);
			}
			if (ret != AES_GCM_SUCCESS){
				printf ("AES_GCM_ctx_decrypt Failed\n");
				ret = -1;
				goto End;
			}
		}
		ret = AES_GCM_ctx_final(inlen, sizeof(auth_string),tag8,&actx);
		if (memcmp (inbuff, decbuff, inlen)){
			printf ("AES%u-GCM Multicall Inplace Failed\n", keylen);
			ret = -1;
			goto End;
		}
		if (memcmp (tag7 , tag8 , 16)){
			printf ("AES%u-GCM Multicall NonInplace Failed - "
					"Tag mismatch\n", keylen);
			ret = -1;
			goto End;

		}
#endif
		i++;
	}
		prev_inlen = inlen;
	#ifdef TEST_CPU_CYCLES
		inlen+=inlen;
	#else	
		inlen+=INCR_STEPS;
	#endif
}
	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","AES-GCM",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}

int test_aes_xts_kat() {
	
	uint8_t key1[32];
	uint8_t key2[32];
	uint8_t in_text[400];
	uint8_t out_text[400];
	int len,cnt = 0,ret,fail = 0;
	uint32_t inlen = 48;
	unsigned int i;
	//Encrypt
	for (i = 0; i < sizeof(aes_xts_enc)/sizeof(aes_xts_enc[0]); i++) {
		memset (in_text, 0, sizeof(in_text));
		memset (out_text, 0, sizeof(out_text));
		memset (key1, 0, sizeof(key1));
		memset (key2, 0, sizeof(key2));
		str2hex (aes_xts_enc[i].key1, key1, &len);
		str2hex (aes_xts_enc[i].key2, key2, &len);
		str2hex (aes_xts_enc[i].plain, in_text, &len);
		ret=XTS_AES_encrypt((uint64_t *)key1, (uint64_t *)key2, aes_xts_enc[i].key_size, (uint64_t)aes_xts_enc[i].dseqnum, in_text, inlen, out_text);
		if(ret != XTS_AES_SUCCESS) {
			printf ("XTS_AES_encrypt Failed\n");
			ret = -1;
			goto End;
		}	
		
		str2hex (aes_xts_enc[i].cipher, in_text, &len);
		
		if ( memcmp(in_text, out_text, len)) {
			printf("AES-XTS Failed for input size\n");
			DUMP_BUFF("Plain\n",aes_xts_enc[i].cipher,16);
			DUMP_BUFF("TEXT\n", out_text, len);
			fail++;
		}
		cnt++;
	}
	//Decrypt 
	for(i=0; i<sizeof(aes_xts_dec)/sizeof(aes_xts_dec[0]); i++) {
		memset (in_text, 0, sizeof(in_text));
		memset (out_text, 0, sizeof(out_text));
		memset (key1, 0, sizeof(key1));
		memset (key2, 0, sizeof(key2));
		str2hex (aes_xts_dec[i].key1, key1, &len);
		str2hex (aes_xts_dec[i].key2, key2, &len);
		str2hex (aes_xts_dec[i].cipher, in_text, &len);
		ret=XTS_AES_decrypt((uint64_t *) key1, (uint64_t *) key2,aes_xts_dec[i].key_size, (uint64_t) aes_xts_dec[i].dseqnum, in_text, inlen, out_text);
	
		if(ret != XTS_AES_SUCCESS) {
			printf("XTS_AES_decrypt Failed\n");
			ret = -1;
			goto End;
		}
		str2hex (aes_xts_dec[i].plain, in_text, &len);

		if ( memcmp (in_text, out_text, len)) {
			printf ("AES-XTS Decrypt failed\n");
			DUMP_BUFF ("IN TEXT\n", in_text, len);
			DUMP_BUFF ("OUT TEXT\n", out_text, len);
			fail++;
		}
		cnt++;
	}
	if (fail)
		printf("***");
	
	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d passed : %d failed : %d\n","AES-XTS",cnt,(cnt-fail),fail);
	ret=0;
End:
	return ret;
}

int test_aes_xts ()
{	
	uint8_t encbuff[MAX_BUFF_SIZE] = {0};
	uint8_t decbuff[MAX_BUFF_SIZE] = {0};
	uint8_t key1[][32] = { 
		/* 128 bit key */
		{0xae,0x68,0x52,0xf8,0x12,0x10,0x67,0xcc,
		 0x4b,0xf7,0xa5,0x76,0x55,0x77,0xf3,0x9e},
		/* 256 bit key */
		{0x77,0x6b,0xef,0xf2,0x85,0x1d,0xb0,0x6f,
		 0x4c,0x8a,0x05,0x42,0xc8,0x69,0x6f,0x6c,
		 0x6a,0x81,0xaf,0x1e,0xec,0x96,0xb4,0xd3,
		 0x7f,0xc1,0xd6,0x89,0xe6,0x0c,0xc1,0x04}
	};

	uint8_t key2[][32] = {
		/* 128 bit key */
		{0x09,0x28,0x34,0x74,0x00,0x12,0xab,0x45,
		 0x93,0x67,0x56,0x37,0xca,0xaf,0xff,0xbb},
		/* 256 bit key */
		{0x91,0x28,0x73,0x48,0x72,0x13,0x46,0x87,
		 0x16,0xab,0xde,0x84,0x7b,0xc4,0x87,0xad,
		 0x98,0x8d,0xdf,0xff,0xf7,0x38,0x46,0xbc,
		 0xad,0xef,0x54,0x76,0x84,0x73,0x64,0x78}
	};

	uint64_t dseqnum = 0xffull;
	unsigned int keylen;
	uint8_t inbuff[MAX_BUFF_SIZE];
	unsigned int inlen,prev_inlen=0;
	unsigned int i = 0;
	int ret;
#ifndef TEST_CPU_CYCLES
	uint32_t cnt;
	aes_xts_ctx_t ctx[1];
#else
 uint8_t iv[8] = {0};
 uint8_t orig_iv[8] = {0};
#endif
memset (inbuff, 0, sizeof (inbuff));	
	for (inlen=START_PACKET_SIZE; inlen<=MAX_BUFF_SIZE;) {
		PRINT_HDR;
		if (inlen%16) { 
			printf ("Error..For AES to work inlen must be multiple to "
					"16 bytes\n");
			return -1;
		}
		for (i =prev_inlen; i < inlen; i++) {
			inbuff[i] = cvmx_rng_get_random8 (); 
		}
		
	i=0;
	for (keylen = 128; keylen <= 256; keylen += keylen) {	
		START_CYCLE;
		ret = XTS_AES_encrypt ((uint64_t *) key1[i], (uint64_t *) key2[i], 
								keylen, dseqnum, inbuff, inlen, encbuff);	
		END_CYCLE_AES("XTS_AES_encrypt",keylen);
		if (ret != XTS_AES_SUCCESS){
			printf ("XTS_AES_encrypt Failed\n");
			ret = -1;
			goto End;
		}
			
		START_CYCLE;
		ret = XTS_AES_decrypt ((uint64_t *) key1[i], (uint64_t *) key2[i], 
								keylen, dseqnum, encbuff, inlen, decbuff);	
		END_CYCLE_AES("XTS_AES_decrypt",keylen);
		if (ret != XTS_AES_SUCCESS){
			printf ("XTS_AES_decrypt Failed\n");
			ret = -1;
			goto End;
		}	
		if (memcmp (inbuff, decbuff, inlen)){
			printf ("AES%u-XTS Single Call Failed\n", keylen);
			ret = -1;
			goto End;
		}

#ifndef TEST_CPU_CYCLES
		/* AES-XTS multicall */
		/* AES-XTS encrypt code */
		ret = XTS_AES_ctx_init ((uint64_t *) key1[i], (uint64_t *) key2[i], 
								keylen, dseqnum, ctx);
		if (ret != XTS_AES_SUCCESS){
			printf ("XTS_AES_ctx_init Failed\n");
			ret = -1;
			goto End;
		}
		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE){
			if ((inlen - cnt) < AES_CHUNK_SIZE){
				ret = XTS_AES_ctx_encrypt (&inbuff[cnt], (inlen-cnt),
										 &encbuff[cnt], ctx);
			} else {
				ret = XTS_AES_ctx_encrypt (&inbuff[cnt], AES_CHUNK_SIZE,
										 &encbuff[cnt], ctx);
			}
			if (ret != XTS_AES_SUCCESS){
				printf ("XTS_AES_ctx_encrypt Failed %d\n", ret);
				ret = -1;
				goto End;
			}
		}
		
		/* AES-XTS decrypt code */
		ret = XTS_AES_ctx_init ((uint64_t *) key1[i], (uint64_t *) key2[i], 
								keylen, dseqnum, ctx);
		if (ret != XTS_AES_SUCCESS){
			printf ("XTS_AES_ctx_init Failed\n");
			ret = -1;
			goto End;
		}
		for (cnt = 0; cnt < inlen; cnt += AES_CHUNK_SIZE){
			if ((inlen - cnt) < AES_CHUNK_SIZE){
				ret = XTS_AES_ctx_decrypt (&encbuff[cnt], (inlen-cnt),
										 &decbuff[cnt], ctx);
			} else {
				ret = XTS_AES_ctx_decrypt (&encbuff[cnt], AES_CHUNK_SIZE,
										 &decbuff[cnt], ctx);
			}
			if (ret != XTS_AES_SUCCESS){
				printf ("XTS_AES_ctx_encrypt Failed\n");
				ret = -1;
				goto End;
			}
		}
		if (memcmp (inbuff, decbuff, inlen)) {
			printf ("AES%u-XTS Multicall Failed\n", keylen);
			ret = -1;
			goto End;
		}
#endif
		i++;
	}
		prev_inlen=inlen;
	#ifdef TEST_CPU_CYCLES
		inlen+=inlen;
	#else	
		inlen+=INCR_STEPS;
	#endif
}
	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","AES-XTS",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}

int test_aes_xcb_kat () {
	unsigned int i = 0,fail = 0;
	unsigned char tmpout [MAX_BUFF_SIZE];
	int retval = 0;
struct xcb_testcases 
{
	int id;
	unsigned char key[32];
	int key_len;
	unsigned char in[MAX_BUFF_SIZE];
	int text_len;
	unsigned char adata[MAX_BUFF_SIZE];
	int adata_len;
	unsigned char out[MAX_BUFF_SIZE];
};

	struct xcb_testcases *xtc = NULL;
	int j = 0;

#define MAX_TESTCASES 11

	if((xtc = malloc(MAX_TESTCASES * sizeof(*xtc))) == NULL)
	{
		printf("unable to allocate memory\n");
		return -1;
	}

	memset(xtc, 0, MAX_TESTCASES * sizeof(*xtc));
	/* Test cases are same as IEEE draft 10 test cases */
	{
	xtc[j++] = (struct xcb_testcases)
	{
		10,
		{
			0xa9, 0x55, 0xec, 0x89, 0xee, 0x6e, 0x0f, 0xf5,
			0xe5, 0x30, 0x34, 0xc5, 0x89, 0x1c, 0x4e, 0x97,
			0x68, 0x30, 0x31, 0x2a, 0x3a, 0x94, 0xb1, 0xe8,
			0x5e, 0x30, 0xeb, 0xc6, 0x34, 0x95, 0x97, 0xea,
		},
		32,
		{
			0x6e, 0xc7, 0xe1, 0x66, 0x5f, 0x80, 0x6d, 0xf4,
			0xbc, 0xbd, 0x4a, 0x4c, 0x10, 0xa0, 0x6b, 0xd8,
			0x7b, 0xfb, 0x06, 0xf4, 0x17, 0x8a, 0xe5, 0x18,
			0x70, 0x6a, 0x1d, 0x71, 0x5f, 0x44, 0x8b,
		},
		31,
		{
		},
		0,
		{
			0xfb, 0x9c, 0x5b, 0xfb, 0x11, 0xc5, 0x75, 0x28,
			0x47, 0x64, 0xaa, 0x81, 0xba, 0x18, 0x90, 0x6f,
			0x2d, 0x66, 0xf5, 0x3a, 0x52, 0x3a, 0xd4, 0xfc,
			0x2f, 0x23, 0x53, 0xa4, 0x8f, 0x0b, 0x6f,
		},
	};
	xtc[j++] = (struct xcb_testcases)
	{
		9,
		{
			0xc9, 0x9a, 0xb8, 0x97, 0xad, 0xdd, 0xcc, 0xca,
			0xb8, 0x4e, 0x0d, 0xf4, 0xea, 0xfc, 0x93, 0xa4,
			0xf7, 0x60, 0xf3, 0x92, 0x69, 0x64, 0x1c, 0x19,
			0xe5, 0x92, 0x9b, 0x71, 0x2d, 0xd3, 0xd0, 0x79,
		},
		32,
		{
			0xb1, 0x13, 0x50, 0x83, 0x81, 0x22, 0x96, 0x8d,
			0xbb, 0xf2, 0xaa, 0xe6, 0x9b, 0xfd, 0xf5, 0xdb,
			0x5b, 0xff, 0x16, 0x6f, 0xe7, 0x14, 0x03, 0x9b,
			0xd3,
		},
		25,
		{
			0xb7, 0xd6, 0xbb, 0x6d, 0x90, 0x35, 0x22, 0x08,
			0x02, 0x69, 0xb3, 0xa5, 0x75, 0x61, 0x5a, 0xf8,
			0xc7, 0x5a, 0x52, 0xa4, 0x82, 0x86, 0xe3, 0x46,
			0x15, 0xfc, 0x6c, 0x28, 0x9b, 0x09, 0x57,
		},
		31,
		{
			0x02, 0x15, 0x47, 0x5a, 0xec, 0xfc, 0xe0, 0x55,
			0x00, 0xc4, 0xcd, 0xc9, 0x06, 0x8c, 0xbb, 0x65,
			0xb6, 0x6b, 0x27, 0x0e, 0xff, 0xa2, 0xe3, 0x08,
			0x9d,
		},
	};
	xtc[j++] = (struct xcb_testcases)
	{
		8,
		{
			0x3b, 0xb9, 0x6b, 0xd5, 0x0b, 0x91, 0xa7, 0xd8,
			0x37, 0x84, 0x45, 0x24, 0x26, 0x2f, 0xef, 0x97,
			0xe0, 0x41, 0x2c, 0xbd, 0x64, 0xa3, 0x91, 0xc1,
			0xd3, 0x93, 0xc1, 0x33, 0x11, 0xf1, 0x9f, 0x86,
		},
		32,
		{
			0xf0, 0xae, 0x13, 0x92, 0x99, 0xc1, 0xaf, 0x3d,
			0xd0, 0xe5, 0xa0, 0x4b, 0xe3, 0x2c, 0xd3, 0xe3,
			0x93,
		},
		17,
		{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		16,
		{
			0x58, 0xe3, 0x6c, 0xeb, 0xc7, 0x41, 0x17, 0x28,
			0xc1, 0x5b, 0xe4, 0xaf, 0xad, 0x3d, 0xfd, 0x0f,
			0x18,
		},
	};
	xtc[j++] = (struct xcb_testcases)
	{
		7,
		{	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
			0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,},
		16,
		{	 0x08, 0x47, 0x1e, 0x46, 0x29, 0x45, 0xa7, 0x41,
			0x54, 0x0f, 0xaa, 0x16, 0xf0, 0x1e, 0x42, 0x1b,
			0x7f, 0xa4, 0x3e, 0x0d, 0x1f, 0x99, 0xf6, 0xa0,
			0x1f, 0x71, 0x26, 0xf9, 0x8a, 0x3f, 0xc9, 0x6a,
			0xd6, 0x8b, 0xf8, 0x6e, 0xa8, 0xd7, 0x2a, 0xab,
			0x5d, 0x98, 0x7d, 0x08, 0x54, 0xea, 0x72, 0xfe,
			0xa7, 0x64, 0x3c, 0x65, 0x84, 0x33, 0xdd, 0x5e,
			0x31, 0xb4, 0x06, 0x70, 0xc6, 0xd6, 0x9d, 0x1b,
			0x4c, 0xe3, 0xac, 0x9d, 0x9f, 0x5f, 0x73, 0xc6,
			0x91, 0x8a, 0xeb, 0x8d, 0x4c, 0x2d, 0xad, 0xbe,
			0x12, 0xe6, 0xd0, 0xc7, 0x2f, 0x4c, 0xa9, 0x1e,
			0x66, 0xc6, 0xbe, 0xbd, 0x32, 0xf0, 0x09, 0x48,
			0x65, 0x81, 0xda, 0x90, 0x18, 0xa7, 0x4b, 0x9c,
			0x7e, 0x28, 0x8f, 0xb1, 0x8f, 0xd6, 0x09, 0x00,
			0xa4, 0x44, 0x8f, 0xab, 0xea, 0xd7, 0x3d, 0x13,
			0xcb, 0x24, 0x83, 0xfb, 0xc8, 0xfb, 0xdf, 0xe9,
			0x30, 0xa1, 0x38, 0x90, 0x55, 0x5c, 0xaa, 0x88,
			0xf4, 0xac, 0xdd, 0x5a, 0x3e, 0x51, 0x59, 0xe5,
			0xa6, 0x46, 0x7e, 0xc7, 0xef, 0x05, 0x23, 0x95,
			0x30, 0x14, 0xe6, 0xde, 0x79, 0x6c, 0xce, 0x7d,
			0x4f, 0xcd, 0x14, 0xb0, 0x67, 0x7a, 0x2d, 0x8e,
			0x50, 0x9f, 0x55, 0xc8, 0x14, 0xed, 0x12, 0xcd,
			0x75, 0x5c, 0xd8, 0xac, 0xb7, 0xbb, 0x12, 0x66,
			0xb4, 0xd7, 0x25, 0xe2, 0x50, 0x55, 0xe4, 0xd3,
			0x60, 0xb7, 0xcd, 0x31, 0xab, 0xdd, 0x5f, 0x42,
			0x92, 0x7a, 0x4c, 0x11, 0x16, 0x30, 0x5f, 0xea,
			0x7e, 0xcb, 0xac, 0x5d, 0xc4, 0x7f, 0xf2, 0xf3,
			0x30, 0xef, 0x10, 0x8d, 0xc8, 0x93, 0xf7, 0xbe,
			0xcd, 0x6e, 0xea, 0xa3, 0x95, 0x74, 0xdb, 0x1e,
			0xe8, 0x42, 0xea, 0xab, 0x10, 0xf1, 0x7c, 0x29,
			0x93, 0x1f, 0x92, 0x52, 0xc1, 0x0c, 0x40, 0x2c,
			0xaa, 0x00, 0xe8, 0x77, 0x2d, 0x54, 0x11, 0x1a,
			0xba, 0x50, 0x6e, 0x4f, 0xef, 0x24, 0x7b, 0x58,
			0xcb, 0x6a, 0xa2, 0xfc, 0xbb, 0xc4, 0xef, 0x91,
			0xc4, 0x04, 0x5d, 0xde, 0x51, 0x32, 0xda, 0x81,
			0x12, 0x12, 0x7c, 0xa4, 0xb0, 0x0b, 0x9c, 0xa9,
			0xa4, 0x28, 0x29, 0xa4, 0xd3, 0x9a, 0xaf, 0x2b,
			0xc1, 0x27, 0xd9, 0xe6, 0x9e, 0x92, 0x4f, 0x01,
			0x69, 0x29, 0xf9, 0x5f, 0x54, 0x68, 0xbe, 0x6f,
			0xc7, 0x41, 0x58, 0xe7, 0x0d, 0xa7, 0x9c, 0x74,
			0x83, 0x54, 0xab, 0x11, 0x81, 0xee, 0xbd, 0x77,
			0x47, 0xf8, 0xfb, 0x44, 0x08, 0x72, 0xd4, 0xb4,
			0xfb, 0xa2, 0x11, 0xfb, 0x4c, 0x00, 0x9a, 0xf0,
			0xd4, 0x1a, 0xc8, 0x13, 0x44, 0x11, 0x20, 0xb9,
			0x62, 0xde, 0x53, 0x01, 0xdd, 0x54, 0x4e, 0x0c,
			0x0b, 0x1a, 0xd4, 0x3f, 0x82, 0x9f, 0x76, 0xa5,
			0x1b, 0x33, 0x1c, 0xd4, 0x26, 0x51, 0xb6, 0xa2,
			0x26, 0x28, 0x42, 0xb9, 0x0c, 0xd2, 0x93, 0x24,
			0x18, 0xd8, 0xb6, 0x70, 0x75, 0x2a, 0x99, 0x25,
			0xd2, 0xfb, 0x80, 0xfa, 0x25, 0x23, 0xb4, 0x22,
			0x21, 0x21, 0xd0, 0x09, 0x99, 0x7e, 0xf2, 0x22,
			0x3a, 0xca, 0x4b, 0x12, 0xe6, 0x28, 0x05, 0x0d,
			0xce, 0x8d, 0x0a, 0x6b, 0xdc, 0xd5, 0x47, 0x49,
			0xe0, 0xda, 0x58, 0xf3, 0xfc, 0xa5, 0x63, 0x91,
			0xb5, 0x60, 0x2b, 0x5b, 0xbb, 0x13, 0xd0, 0xf1,
			0x2b, 0x1c, 0xd3, 0x0b, 0x45, 0xb6, 0xa7, 0x62,
			0x32, 0xdc, 0x27, 0xab, 0x81, 0x97, 0x1f, 0xab,
			0xdc, 0xc7, 0x5a, 0xee, 0x7b, 0xb6, 0x8b, 0xf9,
			0x35, 0x95, 0x55, 0xe2, 0x04, 0x8c, 0xd4, 0x4b,
			0x8e, 0x7a, 0xdb, 0x89, 0x52, 0xe2, 0xf0, 0xfa,
			0x3b, 0xda, 0x38, 0xbc, 0xa6, 0x49, 0x72, 0x4a,
			0x5f, 0x1d, 0x0a, 0xac, 0x41, 0x31, 0x0d, 0x75,
			0x78, 0xa6, 0x17, 0x48, 0x88, 0x82, 0xab, 0x66,
			0x3f, 0x46, 0x26, 0x19, 0x11, 0xe4, 0xb8, 0x41,
			0x27, 0xf3, 0x70, 0x62, 0x3b, 0x9f, 0xf6, 0x2e,
		},
		520,
		{	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		16,
		{	0x28, 0xb0, 0xec, 0x43, 0x2f, 0x39, 0x7f, 0x1b,
			0x1a, 0xe9, 0x8e, 0x45, 0x86, 0xd2, 0x92, 0x66,
			0xae, 0x7e, 0x59, 0x78, 0x7c, 0x2d, 0x8e, 0x8b,
			0x3f, 0x3f, 0x1c, 0x10, 0xda, 0xfc, 0x7e, 0x63,
			0x13, 0x21, 0xec, 0x09, 0xe7, 0xa4, 0x7a, 0x04,
			0x92, 0xf1, 0xfb, 0x52, 0xff, 0x11, 0x23, 0xd4,
			0x96, 0xaf, 0xf0, 0xad, 0xbc, 0xb9, 0x32, 0x1c,
			0x9b, 0xd2, 0x91, 0x74, 0xc4, 0x78, 0x2b, 0x28,
			0xb1, 0x18, 0x92, 0x77, 0x72, 0x96, 0xd3, 0x0c,
			0xbc, 0xf0, 0x4f, 0x6e, 0x4f, 0x7a, 0xe6, 0x1a,
			0xc0, 0xa8, 0x6a, 0x06, 0x4c, 0xe9, 0xec, 0xe8,
			0x8b, 0x3a, 0x6d, 0x32, 0xd1, 0x79, 0xba, 0xca,
			0x91, 0x66, 0xcd, 0x15, 0xc5, 0xf1, 0x68, 0x7e,
			0x88, 0x9a, 0x1e, 0xe4, 0x0b, 0x32, 0x78, 0x3b,
			0x02, 0xdd, 0xfd, 0x50, 0x0b, 0x6c, 0xd4, 0x96,
			0xba, 0x1f, 0x5d, 0x7b, 0x6e, 0xd6, 0xfd, 0xee,
			0xfd, 0xc8, 0xc3, 0x6c, 0xa3, 0x81, 0x8b, 0x51,
			0x60, 0xb5, 0x58, 0x82, 0xc6, 0x16, 0x58, 0x03,
			0xdb, 0xbe, 0xe9, 0x5e, 0x12, 0xb5, 0xe2, 0xfd,
			0x4a, 0x0a, 0xfd, 0x5d, 0x84, 0x50, 0xd0, 0x98,
			0x3e, 0x30, 0xdb, 0x63, 0x18, 0x1f, 0x9a, 0x2a,
			0x3c, 0xc5, 0x16, 0xf2, 0x07, 0x59, 0x6e, 0xf5,
			0xee, 0x92, 0x7a, 0xfb, 0xf1, 0x41, 0xf0, 0xc5,
			0x5b, 0x0b, 0x08, 0x13, 0xe2, 0x99, 0x5b, 0x7c,
			0x4c, 0x13, 0xc0, 0x22, 0xe0, 0xba, 0x00, 0x42,
			0x27, 0x8b, 0x13, 0x32, 0x39, 0x1d, 0xb8, 0x9c,
			0x5d, 0xec, 0x68, 0x2f, 0xcd, 0xba, 0xdf, 0xba,
			0x6c, 0x01, 0x83, 0x25, 0x48, 0x47, 0x8f, 0x60,
			0x06, 0x21, 0x98, 0xa9, 0x5c, 0x85, 0xa3, 0xc8,
			0xf6, 0x33, 0x75, 0x3d, 0xc1, 0xe2, 0x9a, 0xc5,
			0x60, 0xf5, 0xf5, 0xf8, 0x1d, 0x9e, 0xaa, 0x24,
			0x00, 0x76, 0x65, 0x6b, 0x84, 0xe1, 0xd9, 0x20,
			0xb9, 0xd9, 0x68, 0xee, 0xb8, 0x4c, 0x74, 0x1a,
			0x22, 0x54, 0xe5, 0x11, 0x2c, 0x33, 0x92, 0xfb,
			0xd4, 0xf9, 0xb2, 0xdd, 0x30, 0x75, 0x2b, 0xf2,
			0x69, 0xef, 0x30, 0xa3, 0xca, 0x5c, 0x67, 0x35,
			0x6e, 0x4e, 0x53, 0xd9, 0xda, 0x6a, 0x1b, 0x99,
			0x55, 0x38, 0x1f, 0x85, 0x49, 0x1e, 0x52, 0xaa,
			0xdc, 0x38, 0xd8, 0x69, 0x61, 0xec, 0x53, 0x47,
			0xa7, 0x24, 0x04, 0xfc, 0x50, 0xd7, 0x33, 0x11,
			0xd8, 0x20, 0x00, 0x86, 0x98, 0x3e, 0x50, 0x35,
			0xff, 0x02, 0xb1, 0xf8, 0xf1, 0x44, 0xea, 0xef,
			0x31, 0x75, 0x12, 0x3a, 0xf4, 0x97, 0x0f, 0xc7,
			0x7e, 0x76, 0x91, 0xce, 0xe4, 0x50, 0x1d, 0x94,
			0x90, 0x69, 0xd6, 0x11, 0x6b, 0xf1, 0xb3, 0x01,
			0x2e, 0xac, 0x51, 0x07, 0x36, 0xc0, 0x9c, 0xfc,
			0x63, 0x6d, 0x01, 0x64, 0xf6, 0x9f, 0x52, 0x53,
			0xf4, 0xb4, 0x16, 0x2c, 0x5e, 0x55, 0x98, 0xcb,
			0x7b, 0x0f, 0x95, 0xff, 0xe4, 0xc0, 0x78, 0x97,
			0x1b, 0xe5, 0x49, 0x52, 0x0d, 0xec, 0x65, 0x5d,
			0xd6, 0x1d, 0x36, 0xcc, 0xa9, 0xd2, 0x6b, 0xaa,
			0x02, 0xb1, 0x8c, 0xed, 0x48, 0xfb, 0xee, 0xb4,
			0xb8, 0x42, 0xc0, 0x45, 0xc3, 0xc1, 0x18, 0x81,
			0xdc, 0x83, 0x76, 0xc5, 0xda, 0xfc, 0x82, 0xac,
			0xc6, 0xda, 0x45, 0x3a, 0xd3, 0xa1, 0x21, 0x39,
			0xab, 0x0f, 0x0f, 0x6d, 0xd7, 0xdf, 0x3b, 0x1e,
			0xe4, 0xaa, 0x71, 0x42, 0x8a, 0x19, 0xff, 0x97,
			0x31, 0x92, 0xeb, 0xd6, 0x0d, 0x6d, 0xe6, 0x98,
			0x84, 0xff, 0x99, 0xe9, 0x0d, 0xea, 0x4e, 0x5f,
			0xc0, 0xab, 0x0a, 0xa6, 0x0d, 0x96, 0x7d, 0x60,
			0x0b, 0xdd, 0x25, 0x9d, 0x5d, 0x63, 0xb3, 0xb9,
			0xd4, 0x85, 0x9e, 0xf7, 0x5d, 0x3d, 0xbd, 0xe2,
			0xd1, 0x4f, 0x17, 0x66, 0x07, 0xff, 0x3c, 0x1d,
			0xe5, 0xf6, 0x28, 0xc2, 0xfc, 0x65, 0x5f, 0x33,
			0x32, 0x29, 0xf7, 0x48, 0x12, 0x27, 0x98, 0xe3,
		},
	};
	xtc[j++] = (struct xcb_testcases)
	/* Test Case 6 */
	{
		 6,
		{	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x16, 0x16, 0xdd, 0xa6,
		},
		16,
		{	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		24,
		{	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		16,
		{	0x70, 0x13, 0xfd, 0xe3, 0xc3, 0x9f, 0xa1, 0xa4,
			0x3f, 0x5a, 0xb4, 0x34, 0x5a, 0xbf, 0xe5, 0xd9,
			0xcf, 0x80, 0x85, 0xf8, 0x7e, 0xb3, 0x11, 0x89,
		},
	};
	xtc[j++] = (struct xcb_testcases)
	{
		5,
		{	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x16, 0x16, 0xdd, 0xa6,
		},
		16,
		{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		},
		20,
		{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		16,
		{
			0x70, 0x13, 0xfd, 0xe3, 0xdb, 0x56, 0x19, 0xbf,
			0xa4, 0xed, 0x25, 0x6d, 0xb4, 0x44, 0x15, 0x68,
			0x7a, 0xa4, 0x50, 0x3f,
		},
	};
	xtc[j++] = (struct xcb_testcases)
	{
		4,
		{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xf3, 0x24, 0x6b, 0x19,
		},
		16,
		{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		16,
		{
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		16,
		{
			0x28, 0x2a, 0x71, 0x43, 0x39, 0xae, 0x66, 0x8c,
			0x3c, 0x20, 0x2a, 0xca, 0x9c, 0x71, 0xe0, 0x0b,
		},
	};
	xtc[j++] = (struct xcb_testcases)
	{
		3,
		{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x16, 0x16, 0xdd, 0xa6,
		},
		16,
		{
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 32 */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 64 */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 96 */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 128 */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 160 */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 192 */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 224 */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 256 */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 288 */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 320 */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 352 */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 384 */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 416 */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 448 */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 480 */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 512 */
		},
		512,
		{	
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		16,
		{
			0xbf, 0x2c, 0x04, 0x93, 0xbb, 0xb4, 0xbd, 0x55,
			0xcc, 0x11, 0xc0, 0x3d, 0xd9, 0x25, 0x1b, 0xe5,
			0x83, 0x79, 0x9f, 0x9d, 0xba, 0xcf, 0x23, 0x16,
			0x7a, 0x4c, 0x5e, 0xf0, 0x3e, 0x0d, 0xb9, 0x40,
			0x4e, 0x4e, 0xee, 0xb3, 0x5d, 0xdf, 0x15, 0x1d,
			0x23, 0x9e, 0x8b, 0x78, 0xc2, 0x64, 0x08, 0x24,
			0xce, 0x1f, 0x10, 0x6e, 0xab, 0x1c, 0x01, 0x9a,
			0xca, 0xd3, 0x98, 0x56, 0x31, 0xc7, 0x0c, 0x36,
			0x3f, 0x30, 0x15, 0xf5, 0xec, 0x41, 0xc8, 0x82,
			0x5e, 0xc4, 0xf4, 0x7f, 0x9e, 0xa0, 0x4d, 0x7e,
			0xdc, 0x17, 0x34, 0x1f, 0x5c, 0x41, 0x98, 0x9c,
			0x56, 0x3c, 0x6a, 0xc2, 0xac, 0x4e, 0xd8, 0xac,
			0x6b, 0xa4, 0x61, 0xfc, 0xaf, 0xb0, 0xb4, 0x1e,
			0x64, 0x4b, 0x00, 0x3c, 0xa3, 0xcf, 0x52, 0x60,
			0x73, 0xa1, 0xef, 0x97, 0x21, 0x7d, 0xf0, 0x3e,
			0x26, 0xbb, 0xd0, 0x22, 0xee, 0x27, 0x9f, 0x06,
			0x95, 0x3c, 0xa3, 0xcd, 0xfd, 0xb4, 0x3d, 0x49,
			0x20, 0xf3, 0x2e, 0xd6, 0x87, 0xd7, 0x81, 0x11,
			0x32, 0x84, 0xb1, 0x7d, 0x34, 0x10, 0x72, 0x58,
			0x1a, 0x3b, 0x38, 0xe7, 0x9f, 0x65, 0xd7, 0x54,
			0x9f, 0x80, 0x39, 0x00, 0x74, 0x5f, 0x37, 0x94,
			0xbf, 0x71, 0x75, 0xa8, 0xca, 0xeb, 0x62, 0xb7,
			0x96, 0x6f, 0xf7, 0xa2, 0xb7, 0x0f, 0xdf, 0x1f,
			0x12, 0x3f, 0x98, 0x26, 0x65, 0x2e, 0xda, 0x09,
			0x7e, 0x7f, 0x39, 0x2d, 0xf8, 0xd0, 0xa9, 0xc4,
			0xf4, 0x4b, 0xa4, 0x0e, 0x54, 0xb9, 0x71, 0xbe,
			0x31, 0x87, 0x6f, 0x1e, 0x43, 0xaa, 0x1f, 0x65,
			0xf5, 0xa6, 0x0e, 0xbf, 0x53, 0xf1, 0xea, 0x9b,
			0x8f, 0x9b, 0xc6, 0x37, 0x31, 0xfa, 0xbb, 0xb4,
			0xdf, 0xcb, 0xd2, 0xbc, 0xa9, 0x94, 0x70, 0x37,
			0x8f, 0x5a, 0x91, 0xc2, 0xf1, 0xbc, 0xb0, 0x80,
			0x10, 0xea, 0xfa, 0x3e, 0x32, 0xf3, 0xac, 0xe6,
			0xd3, 0xc9, 0xe9, 0x1d, 0x12, 0xd7, 0x9a, 0x78,
			0x3d, 0xb3, 0xf8, 0xdf, 0xec, 0xdd, 0xd8, 0x1a,
			0xda, 0xb8, 0x79, 0x03, 0x75, 0x28, 0x8c, 0x5d,
			0xf9, 0xee, 0xa4, 0xa6, 0x63, 0xb5, 0x45, 0x6a,
			0x02, 0xdc, 0x4f, 0xe4, 0x4c, 0xd9, 0x82, 0x1c,
			0x77, 0x3b, 0xdc, 0xfd, 0xf8, 0xc5, 0xe0, 0x68,
			0x65, 0x22, 0xab, 0x40, 0x98, 0x50, 0x01, 0x0f,
			0x34, 0xe9, 0x0a, 0x64, 0x2c, 0x0a, 0x96, 0xf2,
			0xbd, 0xa3, 0xe9, 0x75, 0x8b, 0xfd, 0xd5, 0x18,
			0x47, 0xa7, 0x15, 0xb0, 0xb8, 0xcf, 0x12, 0xc2,
			0x29, 0xf4, 0x39, 0x3d, 0xa6, 0xc8, 0x49, 0x72,
			0xf7, 0x3f, 0x2b, 0x2f, 0x72, 0xb7, 0x5d, 0x03,
			0x23, 0xe5, 0x9a, 0x48, 0xe3, 0xf2, 0x08, 0xe6,
			0x6d, 0xe7, 0x2f, 0x4d, 0x9a, 0x44, 0x04, 0x75,
			0x2a, 0xc7, 0x0f, 0x04, 0xe6, 0x47, 0x25, 0x27,
			0x1b, 0xd3, 0xff, 0xf2, 0x6c, 0xd7, 0xb4, 0x19,
			0x1d, 0x0d, 0xe3, 0xf7, 0x19, 0x63, 0xd7, 0x6e,
			0xf5, 0xda, 0x72, 0xbf, 0x7e, 0xf6, 0xd4, 0xdb,
			0xd7, 0x87, 0xce, 0xa1, 0x8a, 0x13, 0x6f, 0x01,
			0x2b, 0x2d, 0x8c, 0x8b, 0x50, 0x83, 0xdd, 0xcc,
			0xf8, 0xc2, 0x86, 0x41, 0xb6, 0x25, 0x60, 0x17,
			0x5f, 0x6d, 0x28, 0xea, 0xdd, 0xa5, 0xc9, 0xa1,
			0x5b, 0xf1, 0x53, 0xa5, 0xfd, 0x01, 0x16, 0xdf,
			0xd4, 0xf5, 0x62, 0x2a, 0x8f, 0x18, 0xd0, 0x7d,
			0x55, 0x93, 0x03, 0xe2, 0xe8, 0xdd, 0x10, 0x1c,
			0x17, 0x0f, 0xe8, 0x35, 0x88, 0xfb, 0xe2, 0x00,
			0x5e, 0x90, 0x07, 0x1b, 0xb0, 0x70, 0x64, 0xcd,
			0x36, 0x2e, 0x15, 0x32, 0x31, 0x1c, 0x06, 0x7e,
			0xf4, 0xa7, 0xa5, 0x00, 0xe3, 0x5e, 0x20, 0xc5,
			0x82, 0x05, 0x98, 0x18, 0xb3, 0x3e, 0xd0, 0x66,
			0x3f, 0x7a, 0xe0, 0xa0, 0xb2, 0xc8, 0x87, 0xef,
			0x72, 0x30, 0x91, 0x79, 0x9f, 0xaf, 0xfd, 0xbb,
		},
	};
	xtc[j++] = (struct xcb_testcases)
	{
		2,
		{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
		16,
		{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		48,
		{
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		16,
		{
			0x97, 0xc6, 0xb2, 0xb7, 0x19, 0xa9, 0x54, 0xe3,
			0x3b, 0xab, 0x39, 0x0a, 0xf2, 0x57, 0xeb, 0x4c,
			0x59, 0x93, 0xdd, 0x9a, 0x1a, 0x36, 0x61, 0xd5,
			0xb1, 0x52, 0xf8, 0xd6, 0x5f, 0x35, 0x37, 0xb9,
			0x54, 0x34, 0xff, 0xf3, 0x35, 0x2d, 0xfe, 0xb6,
			0x61, 0x5e, 0xc1, 0xb1, 0xc6, 0x6d, 0x81, 0x5d,
		},
	};
	xtc[j++] = (struct xcb_testcases)
	{
		1,
		{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		},
		32,
		{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		32,
		{
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		16,
		{
			0x0a, 0xa2, 0x7c, 0x16, 0x7b, 0x7a, 0x6f, 0x13,
			0x93, 0x23, 0x4c, 0xb1, 0x82, 0x8f, 0x73, 0x7c,
			0xe5, 0x3d, 0xa9, 0xf5, 0x05, 0x8e, 0xbd, 0x81,
			0xf4, 0x4b, 0xfb, 0x8a, 0xa6, 0x4a, 0xe6, 0xc1,
		},
	};
	xtc[j++] = (struct xcb_testcases)
	{
		0,
		{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
		16,
		{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		32,
		{
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		16,
		{
			0xf7, 0x27, 0xd7, 0x48, 0xb8, 0x6e, 0x3b, 0x36,
			0x2f, 0x20, 0x81, 0x0e, 0xed, 0xbe, 0x37, 0x8a,
			0x07, 0x76, 0x16, 0x31, 0xb9, 0x00, 0x94, 0x54,
			0xd5, 0x4d, 0x8d, 0x94, 0x9c, 0x35, 0x27, 0x19,
		},
	};
	}
		for (i=0 ; i < MAX_TESTCASES; i++)
	{
		AES_XCB_encrypt (xtc[i].in,xtc[i].text_len,xtc[i].key,xtc[i].key_len*8,
						 xtc[i].adata,xtc[i].adata_len,tmpout);
		if (memcmp (tmpout,xtc[i].out,xtc[i].text_len))
		{
			int j;
			printf ("#### ERROR ####:%s: XCB Test case id %d: Failed\n",
					__FUNCTION__,xtc[i].id);
			printf ("Expected : ");
			for (j=0; j<xtc[i].text_len; j++)
				printf("%02x",*(xtc[i].out+j));
			printf("\n");
			printf ("Got : ");
			for (j=0; j<xtc[i].text_len; j++)
				printf("%02x",*(tmpout+j));
			printf("\n");
			retval = -1;
		}
	}
	for (i=0; i<MAX_TESTCASES; i++)
	{
		AES_XCB_decrypt (xtc[i].out,xtc[i].text_len,xtc[i].key,xtc[i].key_len*8,
						 xtc[i].adata,xtc[i].adata_len,tmpout);
		if (memcmp (tmpout,xtc[i].in,xtc[i].text_len))
		{
			int j;
			printf ("#### ERROR ####:%s: XCB Test case id %d: Failed\n",
					__FUNCTION__,xtc[i].id);
			printf ("Expected : ");
			for (j=0; j<xtc[i].text_len; j++)
				printf("%02x",*(xtc[i].in+j));
			printf("\n");
			printf ("Got : ");
			for (j=0; j<xtc[i].text_len; j++)
				printf("%02x",*(tmpout+j));
			printf("\n");
			retval = -1;
		}
	}
	if (fail)
		printf("***");
	if (cvmx_is_init_core()) 
		printf ("%-20s :Total Test vectors tested: %d passed : %d failed : %d\n","AES-XCBC NIST",i,(i-fail),fail);

	if(xtc) free(xtc);
	return retval;


}
int test_aes_xcb ()
{	
	uint8_t inbuff[MAX_BUFF_SIZE];
	uint64_t z[2];
	uint8_t tmpout[MAX_BUFF_SIZE];
	int ret = 0;
	uint8_t key[][32] = { 
		/* 128 bit key */
		{0xae,0x68,0x52,0xf8,0x12,0x10,0x67,0xcc,
		 0x4b,0xf7,0xa5,0x76,0x55,0x77,0xf3,0x9e},
		/* 256 bit key */
		{0x77,0x6b,0xef,0xf2,0x85,0x1d,0xb0,0x6f,
		 0x4c,0x8a,0x05,0x42,0xc8,0x69,0x6f,0x6c,
		 0x6a,0x81,0xaf,0x1e,0xec,0x96,0xb4,0xd3,
		 0x7f,0xc1,0xd6,0x89,0xe6,0x0c,0xc1,0x04}
	};
#ifdef TEST_CPU_CYCLES
	uint8_t iv[8] = {0};
	uint8_t orig_iv[8] = {0};
#endif 
 unsigned int inlen;
	memset (inbuff, 0, sizeof (inbuff));	
	for (inlen=START_PACKET_SIZE; inlen<=MAX_BUFF_SIZE;){
		PRINT_HDR;
		if (inlen%16) { 
			printf ("Error..For AES to work inlen must be multiple to "
					"16 bytes\n");
			return -1;
		}
		for (i = 0; i < inlen; i++) {
			inbuff[i] = cvmx_rng_get_random8 (); 
		}

		z[0] = z[1] = 0;
	START_CYCLE;
	ret = AES_XCB_encrypt (inbuff,inlen,(uint8_t*)&(key[0]),128,(uint8_t*)z,16,tmpout);
	END_CYCLE_AES("AES_XCB_encrypt",128);
	START_CYCLE;
	ret = AES_XCB_decrypt (tmpout,inlen,(uint8_t*)&(key[0]),128,(uint8_t*)z,16,tmpout);
	END_CYCLE_AES("AES_XCB_decrypt",128);
	START_CYCLE;
	ret = AES_XCB_encrypt (inbuff,inlen,(uint8_t*)&(key[1]),256,(uint8_t*)z,16,tmpout);
	END_CYCLE_AES("AES_XCB_encrypt",256);
	START_CYCLE;
	ret = AES_XCB_decrypt (inbuff,inlen,(uint8_t*)&(key[1]),256,(uint8_t*)z,16,tmpout);
	END_CYCLE_AES("AES_XCB_decrypt",256);
//	prev_inlen = inlen;
	#ifdef TEST_CPU_CYCLES
		inlen+=inlen;
	#else	
		inlen+=INCR_STEPS;
	#endif
}	
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","AES-XCB",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
	return 0;
}

int test_rc4_kat () {
	if (cvmx_is_init_core())	
		printf (" *** RC4 Known Answer Test not available ***\n");
	return 0;
}
int test_rc4 ()
{	
	uint8_t encbuff[MAX_BUFF_SIZE];
	uint8_t decbuff[MAX_BUFF_SIZE];
	uint8_t inbuff[MAX_BUFF_SIZE];
	unsigned int inlen;
	int ret = 0;
	uint8_t key[16] =
		{0x01,0x84,0x31,0x93,0x79,0x14,0x87,0x03,
		 0x81,0x70,0x43,0x97,0x19,0x84,0x37,0x14};
	RC4_KEY rkey;
#ifdef TEST_CPU_CYCLES
 uint8_t iv[8] = {0};
 uint8_t orig_iv[8] = {0};
#endif
memset (inbuff, 0, sizeof (inbuff));	
	for (inlen=START_PACKET_SIZE; inlen<=MAX_BUFF_SIZE;){
		PRINT_HDR;
		if (inlen%16) { 
			printf ("Error..For AES to work inlen must be multiple to "
					"16 bytes\n");
return -1;
}
for (i = prev_inlen; i < inlen; i++) {
			inbuff[i] = cvmx_rng_get_random8 (); 
		}

	/* RC4 NonInplace */
	i=0;
	RC4_set_key (&rkey, 16, key);
	START_CYCLE;
	RC4 (&rkey, inlen, inbuff, encbuff);
	END_CYCLE("RC4 encrypt")
	RC4_set_key (&rkey, 16, key);
	START_CYCLE;
	RC4 (&rkey, inlen, encbuff, decbuff);
	END_CYCLE("RC4 decrypt")
	if (memcmp (inbuff, decbuff, inlen)){
		printf ("RC4 NonInlace API Failed for input size : %u\n", inlen);
		ret = -1;
		goto End;
	}

	/* RC4 Inplace */
	memset (decbuff, 0, sizeof (decbuff));
	memcpy (decbuff, inbuff, inlen);
	RC4_set_key (&rkey, 16, key);
	RC4 (&rkey, inlen, decbuff, decbuff);
	RC4_set_key (&rkey, 16, key);
	RC4 (&rkey, inlen, decbuff, decbuff);
	if (memcmp (inbuff, decbuff, inlen)){
		printf ("RC4 Inlace API Failed for input size : %u\n", inlen);
		ret = -1;
		goto End;
	}
		prev_inlen = inlen;
	#ifdef TEST_CPU_CYCLES
		inlen+=inlen;
	#else	
		inlen+=INCR_STEPS;
	#endif
}
	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","RC4",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End :
	return ret;
}

