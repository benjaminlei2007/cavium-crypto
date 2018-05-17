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
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "test-crypto-common.h"
#include <test-hash-api.h>

#ifdef TEST_CPU_CYCLES
	extern uint32_t numcores;
	extern CVMX_SHARED uint64_t total_cpucycles;
	extern CVMX_SHARED uint64_t total_mbps;		
#endif 

static void hex2str(char* str, uint8_t* hex, int len)
{
	int i,j;

	for (i=0,j=0;i<len;i++,j+=2)
		sprintf(&str[j],"%02x",hex[i]);
}


static void hex_print (uint8_t *buff, uint32_t len)
{
	uint32_t cnt = 0;
	for (cnt = 0; cnt < len; cnt++) 
		printf ("\\x%02x", buff[cnt]);
	printf ("\n");
}

#define DUMP_BUFF(str_,buf_,len_) \
{ \
	int i; \
	printf("%s",(str_)); \
	for (i=0;i<(len_);i++){ \
		printf( "%02x ",(buf_)[i]); \
		if(i && ((i%8) == 7)) printf("\n"); \
   } \
}


static void str2hex(char* str, uint8_t* hex, int* len)
{
	uint8_t h[3];
	int i,j;
  /* remove newline */
	*len = strlen(str);
	*len = ((*len)>>1);

	for (i=0,j=0;i<*len;i++)
	{
		h[0] = str[j++];
		h[1] = str[j++];
		hex[i] = (uint8_t)strtoul((const char* )h, NULL, 16);
	}
}



int test_sha1_kat () {
	char out_line[400];
	uint8_t in_text[400];
	uint8_t out_text[400];
	uint8_t exp_text[50];
	unsigned char msg[240];
	int j, len, md_len, fail = 0,cnt = 0;
	unsigned int i, k;

	for (k=0;k < sizeof(sha_nist)/sizeof (sha_nist[0]);k++) {
		if (!memcmp (sha_nist[k].hash ,"SHA1",sizeof ("SHA1"))) {
			str2hex(sha_nist[k].msg, in_text, &len);
			md_len = 20;
			memset (out_text,0, md_len);
			SHA1 (in_text, len, out_text);
			str2hex(sha_nist[k].digest,exp_text,&len);
			if (memcmp (exp_text,out_text,len)) {
				fail++;
				printf("SHA1 failed\n");
				DUMP_BUFF ("Exp Text\n",exp_text,len);
				DUMP_BUFF ("Out Text\n",out_text,len);
			}
			cnt++;
		}
	}
	for (k=0;k < sizeof(monte)/sizeof (monte[0]);k++) {
				if (!memcmp (monte [k].hash ,"SHA1",sizeof ("SHA1"))) {
		str2hex(monte [k].seed, in_text, &len);
		for (j=0; j<3; j++) {
			memcpy (msg, in_text, len);
			memcpy (msg+len, in_text, len);
			memcpy (msg+(2*len), in_text, len);
			for (i=0; i<1000; i++) {
				md_len=20;
				memset (out_text, 0xcc, md_len);
				SHA1 (msg, (3*len), out_text);
				memcpy (msg, msg+len, len);
				memcpy (msg+len, msg+(2*len), len);
				memcpy (msg+(2*len), out_text, len);
			}
				memcpy (in_text, out_text, len);
				hex2str (out_line+(j*len*2),out_text,len);
	
		}
		if (memcmp (out_line,monte[k].exp1,len) && memcmp (out_line+(len*2),monte[k].exp2,len)
									 && memcmp (out_line+(len*4),monte[k].exp3,len)) {
			fail++;
			printf("failed\n");
		}

	cnt++;
	}
}
	
	if (fail)
		printf("***");
	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","SHA1 ",cnt,(cnt-fail),fail);
	return 0;
}
int test_sha224_kat () {
	char out_line[400];
	uint8_t in_text[400];
	uint8_t out_text[400];
	uint8_t exp_text[500];
	unsigned char msg[240];
	int j, len, md_len =28 , fail = 0,cnt = 0;
	unsigned int i,k;

	for (k=0;k < sizeof(sha_nist)/sizeof (sha_nist[0]);k++) {

		if (!memcmp (sha_nist[k].hash ,"SHA224",sizeof ("SHA224"))) {
			str2hex(sha_nist[k].msg, in_text, &len);
			memset (out_text, 0xcc, md_len);
			SHA224 (in_text, len, out_text);
			str2hex(sha_nist[k].digest,exp_text,&len);
			if (memcmp (exp_text,out_text,len)) {
				fail++;
				printf("SHA224 failed\n");
				DUMP_BUFF ("Exp Text\n",exp_text,len);
				DUMP_BUFF ("Out Text\n",out_text,len);
			}
			cnt++;
	
		}
	}
	for (k=0;k < sizeof(monte)/sizeof (monte[0]);k++) {
		if (!memcmp (sha_nist[k].hash ,"SHA224",sizeof ("SHA224"))) {
		str2hex(monte [k].seed, in_text, &len);
		for (j=0; j<3; j++) {
			memcpy (msg, in_text, len);
			memcpy (msg+len, in_text, len);
			memcpy (msg+(2*len), in_text, len);
			for (i=0; i<1000; i++) {
				memset (out_text, 0xcc, md_len);
				SHA224 (msg, (3*len), out_text);
				memcpy (msg, msg+len, len);
				memcpy (msg+len, msg+(2*len), len);
				memcpy (msg+(2*len), out_text, len);
			}
				memcpy (in_text, out_text, len);
				hex2str (out_line+(j*len*2),out_text,len);
		}
		if (memcmp (out_line,monte[k].exp1,len) && memcmp (out_line+(len*2),monte[k].exp2,len)
									 && memcmp (out_line+(len*4),monte[k].exp3,len)) {
			fail++;
			printf("failed\n");
		}
		cnt++;
	}
	}
	if (fail)
		printf("***");
	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","SHA224 ",cnt,(cnt-fail),fail);
	return 0;
}
int test_sha256_kat () {
	char out_line[400];
	uint8_t in_text[400];
	uint8_t out_text[400];
	uint8_t exp_text[500];
	unsigned char msg[240];
	int j, len, md_len =32, fail = 0,cnt = 0;
	unsigned int i,k;

	for (k=0;k < sizeof(sha_nist)/sizeof (sha_nist[0]);k++) {

		if (!memcmp (sha_nist[k].hash ,"SHA256",sizeof ("SHA256"))) {
			str2hex(sha_nist[k].msg, in_text, &len);
			memset (out_text, 0xcc, md_len);
			SHA256 (in_text, len, out_text);
			str2hex(sha_nist[k].digest,exp_text,&len);
			if (memcmp (exp_text,out_text,len)) {
				fail++;
				printf("SHA256 failed\n");
				DUMP_BUFF ("Exp Text\n",exp_text,len);
				DUMP_BUFF ("Out Text\n",out_text,len);
			}
			cnt++;
	
		}
	}
	for (k=0;k < sizeof(monte)/sizeof (monte[0]);k++) {
		if (!memcmp (sha_nist[k].hash ,"SHA256",sizeof ("SHA256"))) {
		str2hex(monte [k].seed, in_text, &len);
		for (j=0; j<3; j++) {
			memcpy (msg, in_text, len);
			memcpy (msg+len, in_text, len);
			memcpy (msg+(2*len), in_text, len);
			for (i=0; i<1000; i++) {
				memset (out_text, 0xcc, md_len);
				SHA256 (msg, (3*len), out_text);
				memcpy (msg, msg+len, len);
				memcpy (msg+len, msg+(2*len), len);
				memcpy (msg+(2*len), out_text, len);
			}
				memcpy (in_text, out_text, len);
				hex2str (out_line+(j*len*2),out_text,len);
	
		}
		if (memcmp (out_line,monte[k].exp1,len) && memcmp (out_line+(len*2),monte[k].exp2,len)
									 && memcmp (out_line+(len*4),monte[k].exp3,len)) {
			fail++;
			printf("failed\n");
		}

cnt++;
	}
	}
	if (fail)
		printf("***");
	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","SHA256 ",cnt,(cnt-fail),fail);
	return 0;
}
int test_sha384_kat () {
	char out_line[400];
	uint8_t in_text[400];
	uint8_t out_text[400];
	uint8_t exp_text[500];
	unsigned char msg[240];
	int j, len, md_len = 48, fail = 0,cnt = 0;
	unsigned int i,k;

	for (k=0;k < sizeof(sha_nist)/sizeof (sha_nist[0]);k++) {

		if (!memcmp (sha_nist[k].hash ,"SHA384",sizeof ("SHA384"))) {
			str2hex(sha_nist[k].msg, in_text, &len);
			memset (out_text, 0xcc, md_len);
			SHA384 (in_text, len, out_text);
			str2hex(sha_nist[k].digest,exp_text,&len);
			if (memcmp (exp_text,out_text,len)) {
				fail++;
				printf("SHA384 failed\n");
				DUMP_BUFF ("Exp Text\n",exp_text,len);
				DUMP_BUFF ("Out Text\n",out_text,len);
			}
			cnt++;
	
		}
	}
	for (k=0;k < sizeof(monte)/sizeof (monte[0]);k++) {
		if (!memcmp (sha_nist[k].hash ,"SHA384",sizeof ("SHA384"))) {
		str2hex(monte [k].seed, in_text, &len);
		for (j=0; j<3; j++) {
			memcpy (msg, in_text, len);
			memcpy (msg+len, in_text, len);
			memcpy (msg+(2*len), in_text, len);
			for (i=0; i<1000; i++) {
				memset (out_text, 0xcc, md_len);
				SHA384 (msg, (3*len), out_text);
				memcpy (msg, msg+len, len);
				memcpy (msg+len, msg+(2*len), len);
				memcpy (msg+(2*len), out_text, len);
			}
				memcpy (in_text, out_text, len);
				hex2str (out_line+(j*len*2),out_text,len);
	
		}
		if (memcmp (out_line,monte[k].exp1,len) && memcmp (out_line+(len*2),monte[k].exp2,len)
									 && memcmp (out_line+(len*4),monte[k].exp3,len)) {
			fail++;
			printf("failed\n");
		}
		cnt++;

	}
	}
	if (fail)
		printf("***");
	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","SHA384 ",cnt,(cnt-fail),fail);
	return 0;
}
// finalizing it.
int test_sha512_kat () {
	char out_line[400];
	uint8_t in_text[400];
	uint8_t out_text[400];
	uint8_t exp_text[500];
	unsigned char msg[240];
	int j, len, md_len =64, fail = 0,cnt = 0;
	unsigned int i,k;

	for (k=0;k < sizeof(sha_nist)/sizeof (sha_nist[0]);k++) {

		if (!memcmp (sha_nist[k].hash ,"SHA512",sizeof ("SHA512"))) {
			str2hex(sha_nist[k].msg, in_text, &len);
			memset (out_text, 0xcc, md_len);
			SHA512 (in_text, len, out_text);
			str2hex(sha_nist[k].digest,exp_text,&len);
			if (memcmp (exp_text,out_text,len)) {
				fail++;
				printf("SHA512 failed\n");
				DUMP_BUFF ("Exp Text\n",exp_text,len);
				DUMP_BUFF ("Out Text\n",out_text,len);
			}
			cnt++;

		}
	}
	for (k=0;k < sizeof(monte)/sizeof (monte[0]);k++) {
		if (!memcmp (sha_nist[k].hash ,"SHA512",sizeof ("SHA512"))) {
		str2hex(monte [k].seed, in_text, &len);
		for (j=0; j<3; j++) {
			memcpy (msg, in_text, len);
			memcpy (msg+len, in_text, len);
			memcpy (msg+(2*len), in_text, len);
			for (i=0; i<1000; i++) {
				memset (out_text, 0xcc, md_len);
				SHA512 (msg, (3*len), out_text);
				memcpy (msg, msg+len, len);
				memcpy (msg+len, msg+(2*len), len);
				memcpy (msg+(2*len), out_text, len);
			}
				memcpy (in_text, out_text, len);
				hex2str (out_line+(j*len*2),out_text,len);
	
		}
		if (memcmp (out_line,monte[k].exp1,len) && memcmp (out_line+(len*2),monte[k].exp2,len)
									 && memcmp (out_line+(len*4),monte[k].exp3,len)) {
			fail++;
			printf("failed\n");
		}
		cnt++;

	}
	}
	if (fail)
		printf("***");
	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","SHA512",cnt,(cnt-fail),fail);
	return 0;

}
	


int test_hmac_kat () {
	char out_line[400];
	uint8_t key[128];
	uint8_t in_text[400];
	uint8_t out_text[400];
	int len, len_key,len_tag,fail=0,cnt=0;
	unsigned int i,mdlen;
for (i=0;i<sizeof (hmac_nist)/sizeof (hmac_nist[0]);i++) {
	memset(out_text,0xcc,64);
	memset(out_line,0,64);
	if (!memcmp(hmac_nist[i].evp,"L=20",sizeof ("L=20"))) {
		len_tag = hmac_nist[i].tlen;
		str2hex (hmac_nist[i].key,key,&len_key);
		str2hex(hmac_nist[i].msg,in_text,&len);

		HMAC (EVP_sha1 (), key, len_key, in_text,len,
									out_text, &mdlen);
		hex2str (out_line,out_text, len_tag);
		if (memcmp (out_line,hmac_nist[i].mac,len_tag)) {
			printf("EVP SHA1 nist verification failed\n");
			printf("Expected: %s\n",hmac_nist[i].mac);
			printf("Actual: %s\n",out_line);
			fail++;
			
		}
		cnt++;
}
	if (!memcmp(hmac_nist[i].evp,"L=28",sizeof ("L=28"))) {
		len_tag = hmac_nist[i].tlen;
		str2hex (hmac_nist[i].key,key,&len_key);
		str2hex(hmac_nist[i].msg,in_text,&len);
					  HMAC (EVP_sha224 (), key, len_key, in_text,len,
							out_text, &mdlen);
		hex2str (out_line,out_text, len_tag);
		if (memcmp (out_line,hmac_nist[i].mac,len_tag)) {
			printf("EVP SHA1 nist verification failed\n");
			printf("Expected: %s\n",hmac_nist[i].mac);
			printf("Actual: %s\n",out_line);
			fail++;	
		}
		cnt++;
	}
				   if (!memcmp(hmac_nist[i].evp,"L=32",sizeof ("L=32"))) {
		len_tag = hmac_nist[i].tlen;
		str2hex (hmac_nist[i].key,key,&len_key);
		str2hex(hmac_nist[i].msg,in_text,&len);
					   HMAC (EVP_sha256 (), key, len_key, in_text,len,
							 out_text, &mdlen);
		hex2str (out_line,out_text, len_tag);
		if (memcmp (out_line,hmac_nist[i].mac,len_tag)) {
			printf("EVP SHA1 nist verification failed\n");
			printf("Expected: %s\n",hmac_nist[i].mac);
			printf("Actual: %s\n",out_line);
			fail++;
		}
		cnt++;
	}

	 if (!memcmp(hmac_nist[i].evp,"L=48",sizeof ("L=48"))) {
		len_tag = hmac_nist[i].tlen;
		str2hex (hmac_nist[i].key,key,&len_key);
		str2hex(hmac_nist[i].msg,in_text,&len);
						HMAC (EVP_sha384 (), key, len_key, in_text,len,
							  out_text, &mdlen);
		hex2str (out_line,out_text, len_tag);
		if (memcmp (out_line,hmac_nist[i].mac,len_tag)) {
			printf("EVP SHA1 nist verification failed\n");
			printf("Expected: %s\n",hmac_nist[i].mac);
			printf("Actual: %s\n",out_line);
			fail++;
		}
		cnt++;
	}
	if (!memcmp(hmac_nist[i].evp,"L=64",sizeof ("L=64"))) {
		len_tag = hmac_nist[i].tlen;
		str2hex (hmac_nist[i].key,key,&len_key);
		str2hex(hmac_nist[i].msg,in_text,&len);
						HMAC (EVP_sha512 (), key, len_key, in_text,len,
							  out_text, &mdlen);
		hex2str (out_line,out_text, len_tag);
		if (memcmp (out_line,hmac_nist[i].mac,len_tag)) {
			printf("EVP SHA1 nist verification failed\n");
			printf("Expected: %s\n",hmac_nist[i].mac);
			printf("Actual: %s\n",out_line);
			fail++;
		}
		cnt++;
	}

	}
	if (fail)
		printf("***");
	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","HMAC",cnt,(cnt-fail),fail);
	return 0;

}

int test_md5_kat () {
	int fail = 0;
	unsigned int len,i;
	uint8_t hash_md[MD5_DIGEST_LENGTH];	
/* Test vectors are taken from RFC 1321 */
	const unsigned char msg[][100] = {"",
								"a","abc","message digest",
								"abcdefghijklmnopqrstuvwxyz","ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
								"12345678901234567890123456789012345678901234567890123456789012345678901234567890"};
	
	
	uint8_t expect[][MD5_DIGEST_LENGTH]= {
		{0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e},
		{0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61},
		{0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72},
		{0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0},
		{0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00, 0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b},
		{0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5, 0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41, 0x9d, 0x9f},
		{0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55, 0xac, 0x49, 0xda, 0x2e, 0x21, 0x07, 0xb6, 0x7a}};
	
	for (i=0;i<sizeof(msg)/sizeof(msg[0]);i++) {
		memset (hash_md,0,MD5_DIGEST_LENGTH);
		len = strlen ((const char *)msg[i]);
		MD5 (msg[i],len,hash_md);
		if (memcmp (hash_md,expect[i],MD5_DIGEST_LENGTH)) {
			printf("MD5 Failed at line :%d\n",__LINE__);
			DUMP_BUFF("output\n",hash_md,MD5_DIGEST_LENGTH);		
			DUMP_BUFF("exp\n",expect[i],MD5_DIGEST_LENGTH);
			fail++;
		}
	}
	if (fail)
		printf("***");
	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","MD5",i,(i-fail),fail);
	return 0;
}



int test_md5 ()
{
	uint32_t count = 0, i = 0;
	unsigned int inlen;
	uint8_t hash_md5[MD5_DIGEST_LENGTH];
	uint8_t buff[MAX_DATA_SIZE];
	int ret = 0;
	
#ifndef TEST_CPU_CYCLES
		MD5_CTX md5_ctx;
#endif

	/* These expected MD5 hash values are taken from OpenSSL crypto */
	uint8_t expected_md5_hash[][16] = {
		{0xe2,0xc8,0x65,0xdb,0x41,0x62,0xbe,0xd9,
		 0x63,0xbf,0xaa,0x9e,0xf6,0xac,0x18,0xf0},
		{0xf5,0xc8,0xe3,0xc3,0x1c,0x04,0x4b,0xae,
		 0x0e,0x65,0x56,0x95,0x60,0xb5,0x43,0x32},
		{0xb2,0xea,0x9f,0x7f,0xce,0xa8,0x31,0xa4,
		 0xa6,0x3b,0x21,0x3f,0x41,0xa8,0x85,0x5b}
	};

	/* Test input size 256, 512 and MAX_BUFF_SIZE bytes */
	for (inlen = START_DATA_SIZE; inlen <= MAX_DATA_SIZE; inlen+=inlen) {
		PRINT_HDR;
		memset (buff, 0, sizeof (buff));
		for (count = 0; count < inlen; count++)
			buff[count] = count;

		/* Single call MD5 */
		START_CYCLE;
		MD5 (buff, inlen, hash_md5);
		END_CYCLE("MD5");
		if (memcmp (hash_md5, expected_md5_hash[i], MD5_DIGEST_LENGTH))  {
			printf ("MD5 Single Call Failed for input size %d bytes\n", inlen);
			ret = -1;
			goto End;
		}

#ifndef TEST_CPU_CYCLES
		/* Multicall MD5 */
		MD5_Init (&md5_ctx);
		memset (hash_md5, 0, sizeof (hash_md5));
		for (count = 0; count < inlen; count += CHUNK_SIZE) {
			if ((inlen - count) <= CHUNK_SIZE)
				MD5_Update (&md5_ctx, &buff[count], (inlen - count));
			else
				MD5_Update (&md5_ctx, &buff[count], CHUNK_SIZE);
		}
		MD5_Final (hash_md5, &md5_ctx);
		if (memcmp (hash_md5, expected_md5_hash[i], MD5_DIGEST_LENGTH)) {
			printf ("MD5 Multicall Failed for input size %d bytes\n", inlen);
			ret = -1;
			goto End;
		}
#endif
		i++;
	}
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s : Packet Size from %d to %d : %s\n","MD5",
						START_DATA_SIZE,MAX_DATA_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}


int test_sha1 ()
{
	uint8_t hash_sha[SHA_DIGEST_LENGTH];
	uint32_t count = 0, i = 0;
	unsigned int inlen; 
	uint8_t buff[MAX_DATA_SIZE];
	int ret = 0;

#ifndef TEST_CPU_CYCLES
		SHA_CTX sha_ctx;
#endif

	/* These expected MD5 hash values are taken from OpenSSL crypto */
	char expected_hash[][20] = {
		{0x49,0x16,0xd6,0xbd,0xb7,0xf7,0x8e,0x68,
		  		0x03,0x69,0x8c,0xab,0x32,0xd1,0x58,0x6e,
		 0xa4,0x57,0xdf,0xc8},
		{0xdb,0xe6,0x49,0xda,0xba,0x34,0x0b,0xce,
		 0x7a,0x44,0xb8,0x09,0x01,0x6d,0x91,0x48,
		 0x39,0xb9,0x9f,0x10},
		{0x5b,0x00,0x66,0x9c,0x48,0x0d,0x5c,0xff,
		 0xbd,0xfa,0x8b,0xdb,0xa9,0x95,0x61,0x16,
		 0x0f,0x2d,0x1b,0x77}
	};

	/* Test input size 256, 512 and MAX_BUFF_SIZE bytes */
	for (inlen = START_DATA_SIZE; inlen <= MAX_DATA_SIZE; inlen+=inlen) {
		PRINT_HDR;
		memset (buff, 0, sizeof (buff));
		for (count = 0; count < inlen; count++)
			buff[count] = count;

		/* Single call SHA1 */ 
		START_CYCLE;
		SHA1 (buff, inlen, hash_sha);
		END_CYCLE("SHA1");
		if (memcmp (hash_sha, expected_hash[i], SHA_DIGEST_LENGTH))  {
			printf ("SHA1 single call Failed for input size %u bytes\n", inlen);
			ret = -1;
			goto End;
		}

#ifndef TEST_CPU_CYCLES
		/* Multicall SHA1 */
		SHA1_Init (&sha_ctx);
		memset (hash_sha, 0, sizeof (hash_sha));
		for (count = 0; count < inlen; count += CHUNK_SIZE) {
			if ((inlen - count) <= CHUNK_SIZE)
				SHA1_Update (&sha_ctx, &buff[count], (inlen - count));
			else
				SHA1_Update (&sha_ctx, &buff[count], CHUNK_SIZE);
		}
		SHA1_Final (hash_sha, &sha_ctx);
		if (memcmp (hash_sha, expected_hash[i], SHA_DIGEST_LENGTH))  {
			printf ("SHA1 Multicall Failed for input size %d bytes\n", inlen);
			ret = -1;
			goto End;
		}
#endif
		i++;	
	}
	if (cvmx_is_init_core()) {
	printf ("Tested %-20s : Packet Size from %d to %d : %s\n","SHA1",
						START_DATA_SIZE,MAX_DATA_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}


int test_sha224 ()
{
	uint8_t buff[MAX_DATA_SIZE];
	uint32_t count = 0, i = 0;
	unsigned int inlen;
	uint8_t hash_sha224[SHA224_DIGEST_LENGTH];
	int ret = 0;

#ifndef TEST_CPU_CYCLES
		SHA256_CTX ctx;
#endif

	/* These expected SHA224 hash values are taken from OpenSSL crypto */
	uint8_t expected_sha224_hash[][30] = {
		{0x88,0x70,0x2e,0x63,0x23,0x78,0x24,0xc4,
		  0xeb,0x0d,0x0f,0xcf,0xe4,0x14,0x69,0xa4,
		 0x62,0x49,0x3e,0x8b,0xeb,0x2a,0x75,0xbb,
		 0xe5,0x98,0x17,0x34},

		{0xb8,0x06,0x0c,0xcc,0x82,0xd4,0x0c,0x57,
		 0x61,0x56,0xf7,0xca,0x03,0x33,0xe4,0x38,
		 0x9e,0x41,0x0d,0xf0,0x27,0xd2,0xfb,0x8f,
		 0x76,0x4f,0xa6,0x03},

		{0x62,0x90,0x81,0x7f,0x60,0x01,0x43,0x2c,
		 0xd4,0x41,0x05,0x8d,0x2b,0xb8,0x2d,0x88,
		 0xb3,0xf3,0x24,0x25,0xad,0xe4,0xc9,0x3d,
		 0x56,0x20,0x78,0x38}
	};

	/* Test input size 256, 512 and MAX_BUFF_SIZE bytes */
	for (inlen = START_DATA_SIZE; inlen <= MAX_DATA_SIZE; inlen+=inlen) {
		PRINT_HDR;
		memset (buff, 0, sizeof (buff));
		for (count = 0; count < inlen; count++)
			buff[count] = count;

		/* Single call SHA224 */ 
		START_CYCLE;
		SHA224 (buff, inlen, hash_sha224);
		END_CYCLE("SHA224");
		if (memcmp (hash_sha224,expected_sha224_hash[i],SHA224_DIGEST_LENGTH)) {
			printf ("SHA224 Single Call Failed for input size %d "
					"bytes\n", inlen);
			ret = -1;
			goto End;
		}

#ifndef TEST_CPU_CYCLES
		/* Multicall Single call SHA224 */ 
		SHA224_Init (&ctx);
		memset (hash_sha224, 0, sizeof (hash_sha224));
		for (count = 0; count < inlen; count += CHUNK_SIZE) {
			if ((inlen - count) <= CHUNK_SIZE)
				SHA224_Update (&ctx, &buff[count], (inlen - count));
			else
				SHA224_Update (&ctx, &buff[count], CHUNK_SIZE);
		}
		SHA224_Final ((uint8_t *) hash_sha224, &ctx);
		if (memcmp (hash_sha224,expected_sha224_hash[i],SHA224_DIGEST_LENGTH)) {
			printf ("SHA224 Multicall Failed for input size %d bytes\n", inlen);
			ret = -1;
			goto End;
		}
#endif
		i++;			
	}
	if (cvmx_is_init_core()) {
	printf ("Tested %-20s : Packet Size from %d to %d : %s\n","SHA224",
						START_DATA_SIZE,MAX_DATA_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}


int test_sha256 ()
{
	uint8_t buff[MAX_DATA_SIZE];
	uint32_t count = 0, i = 0;
	unsigned int inlen;
	uint8_t hash_sha256[SHA256_DIGEST_LENGTH];
	int ret = 0;

#ifndef TEST_CPU_CYCLES
		SHA256_CTX ctx;
#endif

	/* These expected SHA256 hash values are taken from OpenSSL crypto */
	char expected_sha256_hash[][32] =  {
		{0x40,0xaf,0xf2,0xe9,0xd2,0xd8,0x92,0x2e,
		 0x47,0xaf,0xd4,0x64,0x8e,0x69,0x67,0x49,
		 0x71,0x58,0x78,0x5f,0xbd,0x1d,0xa8,0x70,
		 0xe7,0x11,0x02,0x66,0xbf,0x94,0x48,0x80},

		{0x11,0x00,0x09,0xdc,0xee,0x21,0x62,0x0b,
		 0x16,0x6f,0x3a,0xbf,0xec,0xb5,0xef,0xf7,
		 0xa8,0x73,0xbe,0x72,0x9d,0x1c,0x2d,0x53,
		 0x82,0x2e,0x7a,0xcc,0x5f,0x34,0xeb,0x9b},

		{0x78,0x5b,0x07,0x51,0xfc,0x2c,0x53,0xdc,
		 0x14,0xa4,0xce,0x3d,0x80,0x0e,0x69,0xef,
		 0x9c,0xe1,0x00,0x9e,0xb3,0x27,0xcc,0xf4,
		 0x58,0xaf,0xe0,0x9c,0x24,0x2c,0x26,0xc9}
	};

	/* Test input size 256, 512 and MAX_BUFF_SIZE bytes */
	for (inlen = START_DATA_SIZE; inlen <= MAX_DATA_SIZE; inlen+=inlen) {
		PRINT_HDR;
		memset (buff, 0, sizeof (buff));
		for (count = 0; count < inlen; count++)
			buff[count] = count;

		/* Single call SHA256 */
		START_CYCLE;
		SHA256 (buff, inlen, hash_sha256);
		END_CYCLE("SHA256");
		if (memcmp (hash_sha256,expected_sha256_hash[i],SHA256_DIGEST_LENGTH)) {
			printf ("SHA256 Single Call Failed for input size %d "
					"bytes\n", inlen);
			ret = -1;
			goto End;
		}

#ifndef TEST_CPU_CYCLES
		/* Multicall call SHA256 */
		SHA256_Init (&ctx);
		memset (hash_sha256, 0, sizeof (hash_sha256));
		for (count = 0; count < inlen; count += CHUNK_SIZE) {
			if ((inlen - count) <= CHUNK_SIZE)
				SHA256_Update (&ctx, &buff[count], (inlen - count));
			else
				SHA256_Update (&ctx, &buff[count], CHUNK_SIZE);
		}
		SHA256_Final ((uint8_t *) hash_sha256, &ctx);
		if (memcmp (hash_sha256,expected_sha256_hash[i],SHA256_DIGEST_LENGTH)) {
			printf ("SHA256 Multicall Failed for input size %d bytes\n", inlen);
			ret = -1;
			goto End;
		}
#endif
		i++;			
	}

	if (cvmx_is_init_core()) {
	printf ("Tested %-20s : Packet Size from %d to %d : %s\n","SHA256",
						START_DATA_SIZE,MAX_DATA_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}


int test_sha384 ()
{
	uint8_t buff[MAX_DATA_SIZE];
	uint32_t count = 0, i = 0;
	unsigned int inlen;
	uint8_t hash_sha384[SHA384_DIGEST_LENGTH];
	int ret = 0;

#ifndef TEST_CPU_CYCLES
		SHA512_CTX ctx;
#endif

	/* These expected SHA384 hash values are taken from OpenSSL crypto */
	char expected_sha384_hash[][48] =  {
		{0xff,0xda,0xeb,0xff,0x65,0xed,0x05,0xcf,
		 0x40,0x0f,0x02,0x21,0xc4,0xcc,0xfb,0x4b,
		 0x21,0x04,0xfb,0x6a,0x51,0xf8,0x7e,0x40,
		 0xbe,0x6c,0x43,0x09,0x38,0x6b,0xfd,0xec,
		 0x28,0x92,0xe9,0x17,0x9b,0x34,0x63,0x23,
		 0x31,0xa5,0x95,0x92,0x73,0x7d,0xb5,0xc5},

		{0x45,0x82,0xfc,0x82,0x43,0x0e,0x52,0x68,
		 0x86,0xa1,0x85,0x34,0x11,0xe6,0x06,0x45,
		 0xfe,0xf7,0xe8,0xea,0x0c,0x85,0x46,0xb7,
		 0xc9,0xba,0x0c,0x84,0x16,0xd9,0xa9,0x8f,
		 0xb5,0x2e,0xbd,0x0c,0x60,0x5f,0xbb,0x70,
		 0x74,0x9c,0x4e,0x3e,0x5d,0xa3,0xdb,0xac},

		{0x55,0xfd,0x17,0xee,0xb1,0x61,0x1f,0x91,
		 0x93,0xf6,0xac,0x60,0x02,0x38,0xce,0x63,
		 0xaa,0x29,0x8c,0x2e,0x33,0x2f,0x04,0x2b,
		 0x80,0xc8,0xf6,0x91,0xf8,0x00,0xe4,0xc7,
		 0x50,0x5a,0xf2,0x0c,0x1a,0x86,0xa3,0x1f,
		 0x08,0x50,0x45,0x87,0x39,0x5f,0x08,0x1f}
	};


	/* Test input size 256, 512 and MAX_BUFF_SIZE bytes */
	for (inlen = START_DATA_SIZE; inlen <= MAX_DATA_SIZE; inlen+=inlen) {
		PRINT_HDR;
		memset (buff, 0, sizeof (buff));
		for (count = 0; count < inlen; count++)
			buff[count] = count;

		/*Single call SHA384 */
		START_CYCLE;
		SHA384 (buff, inlen, hash_sha384);
		END_CYCLE("SHA384");
		if (memcmp (hash_sha384,expected_sha384_hash[i],SHA384_DIGEST_LENGTH)) {
			printf ("SHA384 Single Call Failed for input size %d "
					"bytes\n", inlen);
			ret = -1;
			goto End;
		}

#ifndef TEST_CPU_CYCLES
		/* Multicall SHA384 */
		SHA384_Init (&ctx);
		memset (hash_sha384, 0, sizeof (hash_sha384));
		for (count = 0; count < inlen; count += CHUNK_SIZE) {
			if ((inlen - count) <= CHUNK_SIZE)
				SHA384_Update (&ctx, &buff[count], (inlen - count));
			else
				SHA384_Update (&ctx, &buff[count], CHUNK_SIZE);
		}
		SHA384_Final ((uint8_t *) hash_sha384, &ctx);
		if (memcmp (hash_sha384,expected_sha384_hash[i],SHA384_DIGEST_LENGTH)) {
			printf ("SHA384 Multicall Failed for input size %d bytes\n", inlen);
			ret = -1;
			goto End;
		}
#endif
		i++;			
	}

	if (cvmx_is_init_core()) {
	printf ("Tested %-20s : Packet Size from %d to %d : %s\n","SHA384",
						START_DATA_SIZE,MAX_DATA_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;

}


int test_sha512 ()
{
	uint8_t buff[MAX_DATA_SIZE];
	uint32_t count = 0, i = 0;
	unsigned int inlen;
	uint8_t hash_sha512[SHA512_DIGEST_LENGTH];
	int ret = 0;

#ifndef TEST_CPU_CYCLES
		SHA512_CTX ctx;
#endif

	/* These expected SHA512 hash values are taken from OpenSSL crypto */
	char expected_sha512_hash[][64] =  {
		{0x1e,0x7b,0x80,0xbc,0x8e,0xdc,0x55,0x2c,
		 0x8f,0xee,0xb2,0x78,0x0e,0x11,0x14,0x77,
		 0xe5,0xbc,0x70,0x46,0x5f,0xac,0x1a,0x77,
		 0xb2,0x9b,0x35,0x98,0x0c,0x3f,0x0c,0xe4,
		 0xa0,0x36,0xa6,0xc9,0x46,0x20,0x36,0x82,
		 0x4b,0xd5,0x68,0x01,0xe6,0x2a,0xf7,0xe9,
		 0xfe,0xba,0x5c,0x22,0xed,0x8a,0x5a,0xf8,
		 0x77,0xbf,0x7d,0xe1,0x17,0xdc,0xac,0x6d},

		{0xed,0xb9,0xbe,0xd7,0x21,0xaa,0x6a,0x5f,
		 0x6f,0xbc,0x66,0x19,0xd3,0xa3,0xc2,0xbe,
		 0x3d,0x04,0x30,0x43,0xf0,0x5a,0x9a,0xeb,
		 0xc7,0xb1,0x19,0x7a,0x2a,0xa9,0xc4,0x9a,
		 0x57,0xd5,0xdd,0xd4,0x67,0x4c,0x17,0x85,
		 0x78,0x50,0x88,0xd9,0xf1,0xff,0x42,0xc7,
		 0x97,0xa0,0x2a,0xdc,0x9b,0x81,0x7a,0x13,
		 0x9a,0x50,0x97,0x0d,0xa6,0xc9,0x95,0x24},

		{0x37,0xf6,0x52,0xbe,0x86,0x7f,0x28,0xed,
		 0x03,0x32,0x69,0xcb,0xba,0x20,0x1a,0xf2,
		 0x11,0x2c,0x2b,0x3f,0xd3,0x34,0xa8,0x9f,
		 0xd2,0xf7,0x57,0x93,0x8d,0xde,0xe8,0x15,
		 0x78,0x7c,0xc6,0x1d,0x6e,0x24,0xa8,0xa3,
		 0x33,0x40,0xd0,0xf7,0xe8,0x6f,0xfc,0x05,
		 0x88,0x16,0xb8,0x85,0x30,0x76,0x6b,0xa6,
		 0xe2,0x31,0x62,0x0a,0x13,0x0b,0x56,0x6c}
	};


	/* Test input size 256, 512 and MAX_BUFF_SIZE bytes */
	for (inlen = START_DATA_SIZE; inlen <= MAX_DATA_SIZE; inlen+=inlen) {
		PRINT_HDR;
		memset (buff, 0, sizeof (buff));
		for (count = 0; count < inlen; count++)
			buff[count] = count;

		/* Single call SHA512 */
		START_CYCLE;
		SHA512 (buff, inlen, hash_sha512);
		END_CYCLE("SHA512");
		if (memcmp (hash_sha512,expected_sha512_hash[i],SHA512_DIGEST_LENGTH)) {
			printf ("SHA512 Single Call Failed for input size %d bytes\n", inlen);
			ret = -1;
			goto End;
		}

#ifndef TEST_CPU_CYCLES
		/* Multicall SHA512 */
		SHA512_Init (&ctx);
		memset (hash_sha512, 0, sizeof (hash_sha512));
		for (count = 0; count < inlen; count += CHUNK_SIZE) {
			if ((inlen - count) <= CHUNK_SIZE)
				SHA512_Update (&ctx, &buff[count], (inlen - count));
			else
				SHA512_Update (&ctx, &buff[count], CHUNK_SIZE);
		}
		SHA512_Final ((uint8_t *) hash_sha512, &ctx);
		if (memcmp (hash_sha512,expected_sha512_hash[i],SHA512_DIGEST_LENGTH)) {
			printf ("SHA512 Multicall Failed for input size %d bytes\n", inlen);
			ret = -1;
			goto End;
		}
#endif
		i++;			
	}
	if (cvmx_is_init_core()) {
	printf ("Tested %-20s : Packet Size from %d to %d : %s\n","SHA512",
						START_DATA_SIZE,MAX_DATA_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}


int test_hmac (const EVP_MD *evp, char * evp_hash)
{
	uint8_t hash_hmacmd[100];
	uint8_t buff[MAX_DATA_SIZE];
	uint32_t count = 0;
	unsigned int inlen;
	uint8_t key[] = {0x76,0x13,0xab,0x87,0x9b,0x4f,0x23,0xce};
	int ret = 0;
	uint32_t mdlen;
	static uint32_t i = 0;

#ifndef TEST_CPU_CYCLES
HMAC_CTX hmac_ctx;
#endif

	/* These expected hash values are taken from OpenSSL crypto */
	uint8_t expected_hmac_hash[][64] = {
		/* HMAC MD5 */
		{0x12,0xc6,0x5e,0x8d,0xdc,0x51,0xde,0xcc,
		 0x5c,0xbb,0x3a,0x30,0x97,0x6f,0x97,0x32},
		{0x36,0x18,0x20,0xc4,0x3a,0x84,0x27,0x82,
		 0x06,0x71,0x48,0x02,0x73,0x07,0x35,0x8d},
		{0xc4,0x2f,0x6f,0x32,0x15,0x9b,0x9e,0x9a,
		 0x46,0xe0,0x37,0x42,0x93,0x34,0xd8,0xa4},
	
		/* HMAC SHA1 */
		{0x35,0xed,0x52,0x45,0xa7,0xff,0xd5,0xa1,
		 0xca,0x97,0x2b,0xab,0xa9,0x44,0xb7,0x95,
		 0xe5,0x76,0xa5,0xf0},
		{0xa9,0x15,0x9c,0x30,0x98,0xa6,0x57,0x2c,
		 0x0d,0x16,0x8a,0x7d,0x5f,0xb4,0x0f,0x5b,
		 0x53,0xb4,0xd9,0x4b},
		{0x75,0x1c,0x4e,0x90,0xf3,0x61,0x88,0xba,
		  0x7f,0xde,0xa1,0xa4,0xba,0x0b,0xd8,0xe9,
		 0x10,0xbf,0x67,0x0e},
    
		/* HMAC SHA224 */
		{0x6f,0xc5,0x2d,0x5a,0x72,0x9a,0x51,0x1c,
		 0x97,0x2f,0x80,0xe6,0x28,0x35,0x5b,0x34,
		 0x26,0xb8,0x6e,0xcf,0x55,0x06,0x6f,0x61,
		 0x76,0x69,0x2d,0x5b},
		{0xd3,0xd8,0xe1,0x64,0xd3,0x5b,0x5e,0x42,
		 0x7f,0x4a,0xe1,0x4c,0x35,0xf5,0x47,0xc9,
		 0x57,0x9f,0x70,0xd8,0xe5,0xb2,0xaf,0xbc,
		 0xb2,0x86,0x25,0xde},
		{0xb9,0xc2,0xcb,0x3c,0x1b,0xb3,0x4a,0xf4,
		 0x60,0xc5,0xba,0xd1,0x1c,0x55,0xfa,0x6d,
		 0xce,0x01,0xfd,0x85,0xc2,0xb6,0x63,0x3b,
		 0x6a,0x9f,0x17,0xad},
	
		/* HMAC SHA256 */
		{0x13,0xc5,0xf0,0xcc,0xc0,0xd8,0x90,0x65,
		 0x56,0xc6,0xa1,0xbd,0xa1,0x0d,0xda,0x06,
		 0x5a,0x48,0x56,0x94,0x44,0x5a,0xbc,0x5b,
		 0x86,0x8a,0xa2,0x06,0x3f,0x9b,0xc2,0x0b},
		{0x22,0xa0,0xd8,0x7c,0xa2,0xaf,0xa0,0x03,
		 0x03,0x85,0x6e,0xf8,0x8b,0xc1,0xdd,0x01,
		 0x4b,0xdc,0x5e,0x19,0x70,0x93,0x2f,0xcb,
		 0x6d,0x7e,0x70,0x4a,0xf4,0xf7,0x7c,0xfc},
		{0x54,0x48,0x46,0xb2,0xd6,0xca,0xe6,0x2c,
		 0x20,0xc1,0xf1,0xfd,0xee,0xec,0x2f,0x7a,
		 0xc7,0x55,0x2e,0xc7,0x50,0x21,0xe3,0x2f,
		 0xcb,0x1a,0xba,0xd0,0xbf,0x46,0xae,0x4c},
	
		/* HMAC SHA384 */
		{0x24,0xfb,0x05,0x2d,0xd2,0x0b,0x65,0xfa,
		 0x49,0x9a,0x00,0x0c,0x02,0xb4,0x57,0x41,
		 0x5a,0x3a,0xf1,0xa8,0x02,0x14,0x6d,0xe6,
		 0x20,0xdc,0xd4,0x7e,0xf7,0xba,0xa6,0x74,
		 0x4f,0xdf,0xaf,0xd7,0xcb,0x94,0x60,0xf4,
		 0x91,0x5e,0x2d,0xac,0x11,0x66,0x61,0x90},
		{0xfa,0xb7,0xa6,0xe5,0x43,0xab,0x0b,0xef,
		 0x6c,0x27,0xf4,0xec,0x33,0xd6,0x2a,0x75,
		 0x85,0xca,0x0c,0xbe,0xc9,0x54,0x24,0x3b,
		 0xd4,0x94,0x1c,0xad,0x69,0xef,0xc3,0xa9,
		 0x89,0x20,0x46,0xa3,0x0f,0x33,0xd5,0xb2,
		 0x21,0xbb,0x7b,0x90,0x8d,0xe2,0xfe,0x7e},
		{0x8c,0x89,0x51,0x84,0x04,0x5c,0xc8,0xca,
		 0xc1,0xa8,0xef,0x12,0xd3,0x25,0xd2,0x5c,
		 0x25,0x55,0xc6,0x5c,0x06,0x27,0xb2,0xb9,
		 0x70,0x5f,0xeb,0x45,0xb9,0x7d,0x78,0x22,
		 0xd1,0x83,0xa9,0x06,0xf9,0x53,0x1d,0xb6,
		 0x55,0xc6,0x9e,0x84,0xc1,0x26,0x3d,0x1b},
	
		/* HMAC SHA512 */
		{0xdf,0xc6,0xe1,0x45,0x14,0x1f,0xbb,0x4f,
		 0xc9,0x0f,0xd8,0x4b,0xce,0x07,0x07,0x6a,
		 0x80,0x0a,0xc7,0x96,0xf4,0xcb,0x9e,0xac,
		 0x6e,0x23,0xc3,0x96,0x10,0xf8,0x45,0x28,
		 0xc2,0x98,0x99,0x63,0xdc,0xfd,0x6b,0xb7,
		 0xd0,0x0a,0x0c,0xb3,0x31,0xe1,0x75,0x9f,
		 0x97,0xed,0x77,0x85,0xc7,0xe4,0xfa,0xad,
		 0x59,0x09,0x74,0xea,0xb7,0x53,0xd3,0xf2},
		{0x67,0x4e,0x7c,0x18,0xc5,0xda,0x2f,0x2d,
		 0x7c,0x98,0x39,0x39,0x9d,0x23,0xa2,0xc6,
		 0x99,0xd8,0x7a,0xec,0x4d,0x1a,0x27,0x34,
		 0x78,0xcb,0xf3,0xf9,0xb2,0xe1,0x34,0xd9,
		 0xe9,0x0e,0xbd,0xa0,0x3c,0xbe,0x47,0x5c,
		 0x88,0x4a,0xec,0x7a,0xc4,0x37,0x7d,0x9f,
		 0x9b,0x6a,0x49,0x20,0x44,0x71,0x33,0xff,
		 0xb0,0xea,0x63,0x19,0x4e,0x60,0x7b,0x0b},
		{0x8a,0xde,0xd8,0xac,0x62,0x56,0xaf,0x36,
		 0x53,0xd8,0x8e,0x89,0xf0,0x93,0x67,0xdf,
		 0x95,0x62,0x67,0xb5,0x79,0xef,0xf8,0x84,
		 0xc1,0xbe,0x2d,0x52,0x45,0xbc,0xe0,0xbc,
		 0x2a,0xda,0xfc,0xab,0xf8,0xdf,0xee,0x4b,
		 0xb1,0xe4,0x4a,0x8d,0x9d,0x3a,0x61,0x77,
		 0x01,0xb3,0xbc,0xca,0x7a,0xe0,0x9b,0x7b,
		 0xd3,0x7e,0x16,0xbd,0x61,0x32,0x51,0x40},
	};
	

	/* Test input size 256, 512 and MAX_BUFF_SIZE bytes */
	for (inlen = START_DATA_SIZE; inlen <= MAX_DATA_SIZE; inlen+=inlen) {
		PRINT_HDR;
		for (count = 0; count < inlen; count++)
			buff[count] = count;

		/* HMAC single call */
		START_CYCLE;
		HMAC (evp, (const void *) key, sizeof (key), buff, inlen, hash_hmacmd,
			  (unsigned int *)&mdlen);
		END_CYCLE(evp_hash);
		if (memcmp (hash_hmacmd, expected_hmac_hash[i], mdlen))  {
			printf ("HMAC Single Call Failed for input size %d "
					"bytes\n", inlen);
			hex_print (hash_hmacmd, mdlen);
			ret = -1;
			goto End;
		}

#ifndef TEST_CPU_CYCLES
		/* HMAC Multicall */
		HMAC_CTX_init (&hmac_ctx);
		HMAC_Init (&hmac_ctx, key, sizeof (key), evp);
		for (count = 0; count < inlen; count += 8) {
			if ((inlen - count) <= 8)
				HMAC_Update (&hmac_ctx, &buff[count], (inlen - count));
			else
				HMAC_Update (&hmac_ctx, &buff[count], 8);
		}
		HMAC_Final (&hmac_ctx, hash_hmacmd, (unsigned int *)&mdlen);
		HMAC_cleanup (&hmac_ctx);

		if (memcmp (hash_hmacmd, expected_hmac_hash[i], mdlen))  {
			printf ("HMAC Multicall Failed for input size %d bytes\n", inlen);
			ret = -1;
			goto End;
		}
#endif
		i++;	
	}	
End:
	if (cvmx_is_init_core()) { 
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n",evp_hash, 
						START_DATA_SIZE,MAX_DATA_SIZE,(ret==0)?"Passed":"Failed"); 
	} 	
	return ret;	
}
int test_aes_gmac_kat () {	
	if (cvmx_is_init_core())	
		printf (" *** AES-GMAC Known Answer Test not available ***\n");
	return 0;
}

int test_aes_gmac ()
{
	uint8_t key[] = {
	  /* 128 bit key */
	  0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
	  0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
	};
	uint8_t iv[] = {
	  /* 12 byte iv */
	  0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
	  0xde, 0xca, 0xf8, 0x88
	};
	uint8_t auth_data[][32] = {
	  { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
		0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef
	  },
	  { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
		0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
		0xab, 0xad, 0xda, 0xd2, 0x42, 0x83, 0x1e, 0xc2,
		0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7
	  }
	};
	uint8_t expect_tag[][16] = {
	  { 0x54, 0xdf, 0x47, 0x4f, 0x4e, 0x71, 0xa9, 0xef,
		0x8a, 0x09, 0xbf, 0x30, 0xda, 0x7b, 0x1a, 0x92
	  },
	  { 0x1c, 0xbe, 0x39, 0x36, 0xe5, 0x53, 0xb0, 0x8f,
		0x25, 0xc0, 0x8d, 0x7b, 0x8d, 0xc3, 0x9f, 0xdb
	  }
	};
	uint8_t tag[16] = { 0 };
	int auth_len;
	uint8_t buff[MAX_BUFF_SIZE];
	uint32_t count = 0;
	unsigned int inlen;
	int i, ret;

	for (inlen = START_PACKET_SIZE; inlen <= MAX_BUFF_SIZE; inlen+=inlen) {
		PRINT_HDR;
		for (count = 0; count < inlen; count++)
			buff[count] = count;
	 START_CYCLE;
	 ret = AES_GMAC_tag(key, sizeof(key) * 8, iv, sizeof(iv),
						buff, inlen, tag);
	 END_CYCLE("AES_GMAC_tag");	
	}
  
	for (i = 0, auth_len = 16; auth_len <= 32; i++, auth_len += 16) {
	  ret = AES_GMAC_tag(key, sizeof(key) * 8, iv, sizeof(iv),
						 auth_data[i], auth_len, tag);
	  if (ret != AES_GMAC_SUCCESS) {
		printf ("AES_GMAC_tag Failed (auth len: %u) \n", auth_len);
		ret = -1;
		goto End;
	  }

	  if (memcmp(expect_tag[i], tag, sizeof(tag))) {
		printf("AES GCM Failed : Tag Mismatch for auth len %u\n", auth_len);
		ret = -1;
		goto End;
	  }
	}

	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s : Packet Size from %d to %d : %s\n","AES-GMAC",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}

int test_aes_cmac_kat () {
	uint8_t mac[16], keylen = 128;
	uint8_t datalen[] = {0, 16, 40, 64}; 
	int i,fail=0;
	const uint8_t tv_data[] = {
	   0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 
	   0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11,
	   0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d,
	   0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	   0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
	   0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46,
	   0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
	   0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	   0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f,
	   0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
	   0xe6, 0x6c, 0x37, 0x10
	};
	uint8_t expected_mac [] [16] = {
									{0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46},
									{0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c},
									{0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27},
									{0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe}
	};
	uint8_t key [16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	for (i=0;i<4;i++) {
		memset (mac,0,16);
		cvm_crypto_aes_cmac ((uint64_t *)key, keylen, (uint64_t *) tv_data, 
							 datalen[i], (uint64_t *)mac);
	if (memcmp (mac,expected_mac[i],16)) {
		printf ("AES-CMAC failed\n");
		DUMP_BUFF ("Expected:\n",expected_mac[i],16);
		DUMP_BUFF ("Actual\n",mac,16);
		fail++;
	}
	}
	if (fail)
		printf("***");
	
	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","AES-CMAC",i,(i-fail),fail);

	return 0;

}




int test_aes_cmac ()
{
	const uint8_t tv_data[] = {
	   0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 
	   0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11,
	   0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d,
	   0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	   0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
	   0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46,
	   0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
	   0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	   0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f,
	   0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
	   0xe6, 0x6c, 0x37, 0x10
	};

	uint64_t tv_key[][4] = {
	   /* 128 key */
	   {0x2b7e151628aed2a6ULL, 0xabf7158809cf4f3cULL, 0, 0},
	   /* 192 key */
	   {0x8e73b0f7da0e6452ULL, 0xc810f32b809079e5ULL,
		0x62f8ead2522c6b7bULL, 0},
	   /* 256 key */
	   {0x603deb1015ca71beULL, 0x2b73aef0857d7781ULL,
		0x1f352c073b6108d7ULL, 0x2d9810a30914dff4ULL}
	};

	uint64_t tv_mac[2];
	uint64_t exptected[][2] = {
		{0xbb1d6929e9593728ULL, 0x7fa37d129b756746ULL},
		{0x070a16b46b4d4144ULL, 0xf79bdd9dd04a287cULL},
		{0xdfa66747de9ae630ULL, 0x30ca32611497c827ULL},
		{0x51f0bebf7e3b9d92ULL, 0xfc49741779363cfeULL},
		{0xd17ddf46adaacde5ULL, 0x31cac483de7a9367ULL},
		{0x9e99a7bf31e71090ULL, 0x0662f65e617c5184ULL},
		{0x8a1de5be2eb31aadULL, 0x089a82e6ee908b0eULL},
		{0xa1d5df0eed790f79ULL, 0x4d77589659f39a11ULL},
		{0x028962f61b7bf89eULL, 0xfc6b551f4667d983ULL},
		{0x28a7023f452e8f82ULL, 0xbd4bf28d8c37c35cULL},
		{0xaaf3d8f1de5640c2ULL, 0x32f5b169b9c911e6ULL},
		{0xe1992190549f6ed5ULL, 0x696a2c056c315410ULL}
	};
	int ret = 0;
	int i = 0, j = 0;
	uint32_t keylen = 128;
	uint32_t datalen[] = {0, 16, 40, 64}; 
	uint8_t buff[MAX_BUFF_SIZE];
	uint32_t count = 0;
	unsigned int inlen;

#ifndef TEST_CPU_CYCLES	
	AES_CMAC_CTX ctx[1];
	AES_KEY k;
#endif

	/* AES CMAC single call */
	for (i = 0; i < 3; i++,keylen+=64) {
	  for (j = 0; j < 4; j++) {
		memset (tv_mac, 0, 16);
	   // START_CYCLE;
		cvm_crypto_aes_cmac (tv_key[i], keylen, (uint64_t *) tv_data, 
							 datalen[j], tv_mac);
	 //   END_CYCLE((unsigned int)datalen[j]);
		if (memcmp (tv_mac, exptected[i*4+j], 16))  { 
		  printf ("AES-CMAC Single Call Failed\n");
		  ret = -1;
		  goto End;
		}
	  }
	}

	for (inlen = START_PACKET_SIZE; inlen <= MAX_BUFF_SIZE; inlen+=inlen) {
		PRINT_HDR;
		for (count = 0; count < inlen; count++)
			buff[count] = count;
		keylen = 128;
for (i = 0; i < 3; i++,keylen+=64) {
		memset (tv_mac, 0, 16);
		START_CYCLE;
		ret = cvm_crypto_aes_cmac (tv_key[i], keylen, (uint64_t *) buff, inlen, tv_mac);
  //	  cvm_crypto_aes_cmac (tv_key[i], keylen, (uint64_t *) tv_data,
//						   datalen[j], tv_mac);
		END_CYCLE_AES("AES-CMAC",keylen);
	}
}
#ifndef TEST_CPU_CYCLES	
	memset (tv_mac, 0, 16);
	keylen = 128;

	/* AES CMAC multicall call */
	for (i = 0; i < 3; i++, keylen+=64) {
	  /* 0 bytes */
	  memset (tv_mac, 0, 16);
	  cvm_crypto_aes_cmac_init ((uint8_t *) tv_key[i], keylen, &k, ctx);
	  cvm_crypto_aes_cmac_final (&k, ctx, tv_mac);
	  if (memcmp (tv_mac, exptected[i*4], 16)) {
		printf ("AES-CMAC Multicall API Failed\n");
		ret = -1;
		goto End;
	  }
	  memset (tv_mac, 0, 16);
	  /* 16 bytes */
	  cvm_crypto_aes_cmac_init ((uint8_t *) tv_key[i], keylen, &k, ctx);
	  cvm_crypto_aes_cmac_update (&k, (uint8_t *) tv_data, 16, ctx);
	  cvm_crypto_aes_cmac_final (&k, ctx, tv_mac);
	  if (memcmp (tv_mac, exptected[(i*4)+1], 16)) {
		printf ("AES-CMAC Multicall API Failed\n");
		ret = -1;
		goto End;
	  }
	  memset (tv_mac, 0, 16);
	  /* 40 bytes */
	  cvm_crypto_aes_cmac_init ((uint8_t *) tv_key[i], keylen, &k, ctx);
	  cvm_crypto_aes_cmac_update (&k, (uint8_t *) tv_data, 16, ctx);
	  cvm_crypto_aes_cmac_update (&k, (uint8_t *) tv_data + 16, 24, ctx);
	  cvm_crypto_aes_cmac_final (&k, ctx, tv_mac);
	  if (memcmp (tv_mac, exptected[(i*4)+2], 16)) {
		printf ("AES-CMAC Multicall API Failed\n");
		ret = -1;
		goto End;
	  }
	  memset (tv_mac, 0, 16);
	  /* 64 bytes */
	  cvm_crypto_aes_cmac_init ((uint8_t *) tv_key[i], keylen, &k, ctx);
	  cvm_crypto_aes_cmac_update (&k, (uint8_t *) tv_data, 16, ctx);
	  cvm_crypto_aes_cmac_update (&k, (uint8_t *) tv_data + 16, 32, ctx);
	  cvm_crypto_aes_cmac_update (&k, (uint8_t *) tv_data + 48, 2, ctx);
	  cvm_crypto_aes_cmac_update (&k, (uint8_t *) tv_data + 50, 14, ctx);
	  cvm_crypto_aes_cmac_final (&k, ctx, tv_mac);
	  if (memcmp (tv_mac, exptected[(i*4)+3], 16)) {
		printf ("AES-CMAC Multicall API Failed\n");
		ret = -1;
		goto End;
	  }
	}
#endif
	
	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s : Packet Size from %d to %d : %s\n","AES-CMAC",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}

int test_aes_xcbc_mac_kat () {
	const uint8_t mac [16];
	int i, fail = 0;
	const int size_of_msg [] = {0,3,16,20,32,34};
	const uint8_t key [] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	const uint8_t msg [] [100] = {
								{},
								{0x00, 0x01, 0x02},
								{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
								0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
								{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
								0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
								0x10, 0x11, 0x12, 0x13},
								{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
								0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
								0x10, 0x11,	0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
								0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
								{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
								0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
								0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
								0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
								0x20, 0x21}};
	
	const uint8_t expect_mac [] [16] = {
								{0x75, 0xf0, 0x25, 0x1d, 0x52, 0x8a, 0xc0, 0x1c, 0x45, 0x73, 0xdf, 0xd5, 0x84, 0xd7, 0x9f, 0x29},
								{0x5b, 0x37, 0x65, 0x80, 0xae, 0x2f, 0x19, 0xaf, 0xe7, 0x21, 0x9c, 0xee, 0xf1, 0x72, 0x75, 0x6f},
								{0xd2, 0xa2, 0x46, 0xfa, 0x34, 0x9b, 0x68, 0xa7, 0x99, 0x98, 0xa4, 0x39, 0x4f, 0xf7, 0xa2, 0x63},
								{0x47, 0xf5, 0x1b, 0x45, 0x64, 0x96, 0x62, 0x15, 0xb8, 0x98, 0x5c, 0x63, 0x05, 0x5e, 0xd3, 0x08},
								{0xf5, 0x4f, 0x0e, 0xc8, 0xd2, 0xb9, 0xf3, 0xd3, 0x68, 0x07, 0x73, 0x4b, 0xd5, 0x28, 0x3f, 0xd4},
								{0xbe, 0xcb, 0xb3, 0xbc, 0xcd, 0xb5, 0x18, 0xa3, 0x06, 0x77, 0xd5, 0x48, 0x1f, 0xb6, 0xb4, 0xd8}};

	for(i=0;i<6;i++) {
		cvm_crypto_aes_xcbc_mac ((uint64_t *)key, 16,(uint64_t *) msg [i],size_of_msg [i] ,(uint64_t *) mac);
		if (memcmp (mac,expect_mac[i],16)) {
			printf("AES-XCBC failed at line %d\n",__LINE__);
			DUMP_BUFF ("MAC\n",mac,16);
			DUMP_BUFF ("MAC\n",expect_mac[i],16);
			fail++;
		}
	}
	if (fail)
		printf("***");

	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","AES-XCBC-MAC",i,(i-fail),fail);
	return 0;
}

int test_aes_xcbc_mac ()
{
	uint8_t buff[MAX_BUFF_SIZE];
	uint32_t count = 0;
	unsigned int inlen;
	/* Test Vectors */
	const uint8_t tv_data[] = {
		0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
		0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
		0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
		0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
		0x20,0x21
	};

	uint64_t tv_key[] = {
		0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL, 0, 0
	};
	uint64_t tv_mac[2];
	uint64_t exptected[] = {
		0xbecbb3bccdb518a3ULL, 0x0677d5481fb6b4d8ULL
	};
	int ret = 0;

#ifndef TEST_CPU_CYCLES	
	AES_XCBC_MAC_CTX ctx[1];
	AES_KEY k;
#endif   


	/* tested for all test vectors in RFC 3566 */
	/* AES XCBC single call */
	cvm_crypto_aes_xcbc_mac (tv_key, 16, (uint64_t *) tv_data, 34, tv_mac);
	if (memcmp (tv_mac, exptected, 16))  {
		printf ("AES-XCBC-MAC Single Call Failed\n");
		ret = -1;
		goto End;
	}
	for (inlen = START_PACKET_SIZE; inlen <= MAX_BUFF_SIZE; inlen+=inlen) {
		PRINT_HDR;
		for (count = 0; count < inlen; count++)
			buff[count] = count;
	START_CYCLE;
	cvm_crypto_aes_xcbc_mac (tv_key, 16, (uint64_t *) buff, inlen, tv_mac);
	END_CYCLE("AES-XCBC-MAC");
	}

#ifndef TEST_CPU_CYCLES	
	memset (tv_mac, 0, 16);

	/* AES XCBC multicall call */
	cvm_crypto_aes_xcbc_mac_init ((uint8_t *) tv_key, 16, &k, ctx);
	cvm_crypto_aes_xcbc_mac_update (&k, (uint8_t *) tv_data, 16, ctx);
	cvm_crypto_aes_xcbc_mac_update (&k, (uint8_t *) tv_data + 16, 16, ctx);
	cvm_crypto_aes_xcbc_mac_update (&k, (uint8_t *) tv_data + 32, 2, ctx);
	cvm_crypto_aes_xcbc_mac_final (&k, ctx, tv_mac);

	if (memcmp (tv_mac, exptected, 16)) {
		printf ("AES-XCBC-MAC Multicall API Failed\n");
		ret = -1;
	}
#endif
	
	if (cvmx_is_init_core()) 
	{
		printf ("Tested %-20s : Packet Size from %d to %d : %s\n","AES-XCBC-MAC",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
	ret = 0;
End:
	return ret;
}

int test_aes_xcbc_prf128_kat () {
	int i,fail = 0;
	uint8_t mac [20];
	uint8_t data [] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13};	
	uint8_t key [] [18] = {
							{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
							{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
							{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xed, 0xcb}};
	unsigned int key_size [] = {16,10,18};
	uint8_t expect_prf [] [20] ={ 
								{0x47, 0xf5, 0x1b, 0x45, 0x64, 0x96, 0x62, 0x15, 0xb8, 0x98, 0x5c, 0x63, 0x05, 0x5e, 0xd3, 0x08},
								{0x0f, 0xa0, 0x87, 0xaf, 0x7d, 0x86, 0x6e, 0x76, 0x53, 0x43, 0x4e, 0x60, 0x2f, 0xdd, 0xe8, 0x35},
								{0x8c, 0xd3, 0xc9, 0x3a, 0xe5, 0x98, 0xa9, 0x80, 0x30, 0x06, 0xff, 0xb6, 0x7c, 0x40, 0xe9, 0xe4}};
	
	for ( i = 0;i<3;i++) {
		cvm_crypto_aes_xcbc_prf128 ((uint64_t *)key[i],(key_size[i]*8), (uint64_t *)data,
										20,(uint64_t *) mac);
		if (memcmp (mac,expect_prf[i],16)) {
			printf("aes_xcbc_prf128_kat failed at line %d\n",__LINE__);
			DUMP_BUFF ("OUTPUT\n",mac,16);
			fail++;
		}
	}
	if (fail)
		printf("***");

	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","AES-XCBC-PRF128",i,(i-fail),fail);
	return 0;
}

int test_aes_xcbc_prf128 ()
{
	int ret = 0;
	uint64_t tv_mac[2];
	uint8_t buff[MAX_BUFF_SIZE];
	uint32_t count = 0;
	unsigned int inlen;
	uint64_t expected[] = {
		0x8cd3c93ae598a980ULL, 0x3006ffb67c40e9e4ULL
	};
#ifndef TEST_CPU_CYCLES
	AES_XCBC_MAC_CTX ctx[1];
	AES_KEY aeskey;
#endif  

	/* Test Vectors */
	const uint8_t tv_data[] = {
		0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
		0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
		0x10,0x11,0x12,0x13
	};
	uint64_t tv_key[] = {
		0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL, 0, 0
	};
	tv_key[2] = 0xedcb000000000000ULL;

	/* tested for all test vectors in RFC 4434 */
	/* Single call aes-xcbc-prf128 */
	cvm_crypto_aes_xcbc_prf128 (tv_key, 18*8, (uint64_t *)tv_data, 
								sizeof(tv_data), tv_mac);
	if (memcmp (tv_mac, expected, 16))  {
		printf ("AES-XCBC-PRF128 Single Call Failed\n");
		ret = -1;
		goto End;
	}
	for (inlen = START_PACKET_SIZE; inlen <= MAX_BUFF_SIZE; inlen+=inlen) {
		PRINT_HDR;
		for (count = 0; count < inlen; count++)
			buff[count] = count;
	START_CYCLE;
	ret = cvm_crypto_aes_xcbc_prf128 (tv_key, 18*8, (uint64_t *)buff, inlen, tv_mac);
	END_CYCLE("AES-XCBC-PRF128");
}
#ifndef TEST_CPU_CYCLES
	memset (tv_mac, 0, 16);
	
	/* Multicall aes-xcbc-prf128 */
	cvm_crypto_aes_xcbc_prf128_init ((uint8_t *) tv_key, 18 * 8, &aeskey, ctx);
	cvm_crypto_aes_xcbc_prf128_update (&aeskey, (uint8_t *)tv_data, 16, ctx);
	cvm_crypto_aes_xcbc_prf128_update (&aeskey, (uint8_t *)tv_data+16, 4, ctx);
	cvm_crypto_aes_xcbc_prf128_final (&aeskey, ctx, tv_mac);

	if (memcmp (tv_mac, expected, 16)) {
		printf ("AES-XCBC-PRF128 Multicall Failed\n");
		ret = -1;
	}
#endif
	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s : Packet Size from %d to %d : %s\n","AES-XCBC-PRF128",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}

int test_sha3_224 ()
{

	unsigned char buff[MAX_DATA_SIZE];
        uint32_t count = 0, i = 0;
        unsigned int inlen;
        uint8_t hash_sha3_224[100];

	int ret = 0;                                              

#ifndef TEST_CPU_CYCLES
		SHA3_CTX ctx;
#endif

	/* These expected SHA3-224 hash values are taken from OpenSSL crypto */
	char expected_sha3_224_hash[][30] =  {
		{0xbd,0x34,0xc1,0xfa,0xa0,0x3a,0x01,0xdb,
         0x5e,0x0c,0x3a,0x3d,0x5e,0x04,0x40,0xd6,
         0xe5,0xe3,0x61,0x06,0x0f,0x3d,0xc9,0xd1,
         0x49,0xa2,0x68,0x12},

		{0xfe,0x51,0xc5,0xd7,0x62,0x48,0xe1,0xe9,
         0xd3,0x01,0x29,0x6a,0xe8,0xab,0x94,0x69,
         0xd2,0x86,0x34,0xb4,0xad,0x3e,0x9e,0x78,
         0xc8,0xb0,0x9d,0x47},

		{0x5b,0x37,0xc0,0x9e,0x5b,0x5c,0xf2,0x1b,
         0x0d,0x80,0x97,0xe9,0x47,0x9f,0xe6,0x98,
         0x20,0x03,0xb6,0x17,0xd4,0x1a,0xb2,0x29,
         0x3d,0x77,0xbf,0x22}
	};


	/* Test input size 256, 512 and MAX_BUFF_SIZE bytes */
	for (inlen = START_DATA_SIZE; inlen <= MAX_DATA_SIZE; inlen += inlen) {
        PRINT_HDR;
        memset (buff, 0, sizeof (buff));
        for (count = 0; count < inlen; count++)
            buff[count] = count;

        /* Single call SHA3-224 */
        START_CYCLE;
        SHA3_224(buff, (unsigned long)inlen, hash_sha3_224);
        END_CYCLE("SHA3-224");
        if (memcmp (hash_sha3_224,expected_sha3_224_hash[i],SHA224_DIGEST_LENGTH)) {
			printf ("SHA3-224 Single Call Failed for input size %d bytes\n", inlen);
			ret = -1;
			goto End;
		}

#ifndef TEST_CPU_CYCLES
		/* Multicall SHA3-224 */
		SHA3_224_Init (&ctx);
		memset (hash_sha3_224, 0, sizeof (hash_sha3_224));
		for (count = 0; count < inlen; count += CHUNK_SIZE) {
			if ((inlen - count) <= CHUNK_SIZE)
				SHA3_224_Update (&ctx, &buff[count], (inlen - count));
			else
				SHA3_224_Update (&ctx, &buff[count], CHUNK_SIZE);
		}
		SHA3_224_Final ((uint8_t *) hash_sha3_224, &ctx);
		if (memcmp (hash_sha3_224,expected_sha3_224_hash[i],SHA224_DIGEST_LENGTH)) {
			printf ("SHA3-224 Multicall Failed for input size %d bytes\n", inlen);
			ret = -1;
			goto End;
		}
#endif
		i++;

	}
	if (cvmx_is_init_core()) {
	printf ("Tested %-20s : Packet Size from %d to %d : %s\n","SHA3-224",
						START_DATA_SIZE,MAX_DATA_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
        return ret;
}

int test_sha3_256 ()
{	
	uint8_t buff[MAX_DATA_SIZE];
        uint32_t count = 0, i = 0;
        unsigned int inlen;
        uint8_t hash_sha3_256[100];
        int ret = 0;

#ifndef TEST_CPU_CYCLES
		SHA3_CTX ctx;
#endif

	/* These expected SHA512 hash values are taken from OpenSSL crypto */
	char expected_sha3_256_hash[][32] =  {
		{0x9b,0x04,0xc0,0x91,0xda,0x96,0xb9,0x97,
         0xaf,0xb8,0xf2,0x58,0x5d,0x60,0x8a,0xeb,
         0xe9,0xc4,0xa9,0x04,0xf7,0xd5,0x2c,0x8f,
         0x28,0xc7,0xe4,0xd2,0xdd,0x9f,0xba,0x5f},

		{0xd4,0x72,0x8e,0xa5,0xe9,0xf3,0x81,0x9f,
         0x2b,0x47,0x60,0x15,0x1a,0x8f,0x80,0x2d,
         0xbe,0x9f,0x94,0x1f,0xd6,0xfb,0x59,0xb3,
         0x71,0x58,0x92,0x43,0x65,0x55,0x77,0x2a},

		{0xb6,0xc7,0x06,0x31,0xc6,0xff,0x93,0x2b,
         0x9f,0x38,0x0d,0x9c,0xde,0x87,0x50,0xeb,
         0x9b,0xea,0x39,0x38,0x17,0xa9,0xae,0xa4,
         0x10,0xc2,0x11,0x9e,0xb7,0xb9,0xb8,0x70}
	};


	/* Test input size 256, 512 and MAX_BUFF_SIZE bytes */
        for (inlen = START_DATA_SIZE; inlen <= MAX_DATA_SIZE; inlen += inlen) {
                PRINT_HDR;
                memset (buff, 0, sizeof (buff));
                for (count = 0; count < inlen; count++)
                        buff[count] = count;

                /* Single call SHA3_256 */
              START_CYCLE;
              SHA3_256(buff,  (unsigned long)inlen, hash_sha3_256);
              END_CYCLE("SHA3-256");
              if (memcmp (hash_sha3_256,expected_sha3_256_hash[i],SHA256_DIGEST_LENGTH)) {
                  printf ("SHA3-256 Single Call Failed for input size %d bytes\n", inlen);
                  ret = -1;
                  goto End;
              }

#ifndef TEST_CPU_CYCLES
              /* Multicall SHA3-256 */
              SHA3_256_Init (&ctx);
              memset (hash_sha3_256, 0, sizeof (hash_sha3_256));
              for (count = 0; count < inlen; count += CHUNK_SIZE) {
                  if ((inlen - count) <= CHUNK_SIZE)
                      SHA3_256_Update (&ctx, &buff[count], (inlen - count));
                  else
                      SHA3_256_Update (&ctx, &buff[count], CHUNK_SIZE);
              }
              SHA3_256_Final ((uint8_t *) hash_sha3_256, &ctx);
              if (memcmp (hash_sha3_256,expected_sha3_256_hash[i],SHA256_DIGEST_LENGTH)) {
                  printf ("SHA3-256 Multicall Failed for input size %d bytes\n", inlen);
                  ret = -1;
                  goto End;
              }
#endif
              i++;


        }
        if (cvmx_is_init_core()) {
            printf ("Tested %-20s : Packet Size from %d to %d : %s\n","SHA3-256",
                    START_DATA_SIZE,MAX_DATA_SIZE,(ret==0)?"Passed":"Failed");
        }
End:
   
        return ret;
}

int test_sha3_384 ()
{

        uint8_t buff[MAX_DATA_SIZE];
        uint32_t count = 0, i = 0;
        unsigned int inlen;
        uint8_t hash_sha3_384[100];
        int ret = 0;

#ifndef TEST_CPU_CYCLES
		SHA3_CTX ctx;
#endif


	/* These expected SHA384 hash values are taken from OpenSSL crypto */
	char expected_sha3_384_hash[][48] =  {
    {0xe8,0x34,0x03,0x1d,0x7b,0xab,0x82,0xac,
     0x00,0x90,0x51,0x87,0x33,0x55,0x95,0xe0,
     0x20,0xc5,0xbd,0x32,0x20,0x92,0x4f,0x4f,
     0x55,0x1d,0x74,0x85,0x93,0x1d,0x2c,0xb9,
     0xef,0xe9,0x0b,0x65,0x74,0xfc,0x46,0xb6,
     0x32,0x65,0x31,0x47,0x81,0xde,0x01,0x7a},

    {0xd5,0x3b,0x51,0x68,0x53,0xf5,0xac,0xb4,
     0xaa,0xfd,0xa5,0x9d,0x6f,0x74,0x0f,0x69,
     0x99,0xc9,0xe5,0x21,0x1c,0x51,0x03,0x9c,
     0x6d,0x64,0x5b,0xf9,0x83,0xd7,0xba,0x0b,
     0xdf,0x12,0x31,0xb5,0x50,0x90,0xb5,0x5e,
     0x35,0x99,0xee,0x7a,0xaa,0x62,0xd3,0xbf},

    {0xbf,0xdb,0x44,0xfc,0xb7,0x5b,0x4a,0x02,
     0xdb,0x04,0x87,0xb0,0xc6,0x07,0x63,0x02,
     0x83,0xae,0x79,0x2b,0xbe,0xf4,0x79,0x7b,
     0xd9,0x93,0x00,0x9a,0x2f,0xd1,0x5c,0xf2,
     0x42,0x5b,0x1a,0x9f,0x82,0xf2,0x5f,0x6c,
     0xdc,0x7c,0xac,0x15,0xbe,0x3d,0x57,0x2e}
	};


	/* Test input size 256, 512 and MAX_BUFF_SIZE bytes */
        for (inlen = START_DATA_SIZE; inlen <= MAX_DATA_SIZE; inlen += inlen) {
                PRINT_HDR;
                memset (buff, 0, sizeof (buff));
                for (count = 0; count < inlen; count++)
                        buff[count] = count;

            /* Single call SHA3-384 */
            START_CYCLE;
            SHA3_384(buff,  (unsigned long)inlen, hash_sha3_384);
            END_CYCLE("SHA3-384");
            if (memcmp (hash_sha3_384,expected_sha3_384_hash[i],SHA384_DIGEST_LENGTH)) {
                printf ("SHA3-384 Single Call Failed for input size %d bytes\n", inlen);
                ret = -1;
                goto End;
            }

#ifndef TEST_CPU_CYCLES
            /* Multicall SHA3-384 */
            SHA3_384_Init (&ctx);
            memset (hash_sha3_384, 0, sizeof (hash_sha3_384));
            for (count = 0; count < inlen; count += CHUNK_SIZE) {
                if ((inlen - count) <= CHUNK_SIZE)
                    SHA3_384_Update (&ctx, &buff[count], (inlen - count));
                else
                    SHA3_384_Update (&ctx, &buff[count], CHUNK_SIZE);
            }
            SHA3_384_Final ((uint8_t *) hash_sha3_384, &ctx);
            if (memcmp (hash_sha3_384,expected_sha3_384_hash[i],SHA384_DIGEST_LENGTH)) {
                printf ("SHA3-384 Multicall Failed for input size %d bytes\n", inlen);
                ret = -1;
                goto End;
            }
#endif
            i++;


        }
        if (cvmx_is_init_core()) {
            printf ("Tested %-20s : Packet Size from %d to %d : %s\n","SHA3-384",
                    START_DATA_SIZE,MAX_DATA_SIZE,(ret==0)?"Passed":"Failed");
        }
End:

        return ret;
}

int test_sha3_512 ()
{
        uint8_t buff[MAX_DATA_SIZE];
        uint32_t count = 0, i = 0;
        unsigned int inlen;
        uint8_t hash_sha3_512[100];
        int ret = 0;

#ifndef TEST_CPU_CYCLES
		SHA3_CTX ctx;
#endif


	/* These expected SHA512 hash values are taken from OpenSSL crypto */
	char expected_sha3_512_hash[][64] =  {
        {0x3a,0x84,0x3a,0xf1,0xf8,0x72,0x92,0x8f,
         0x0b,0xbb,0xb5,0x13,0x20,0x7a,0x1a,0x8e,
         0x14,0xe3,0xd9,0x11,0x26,0x9f,0xff,0x52,
         0x12,0x92,0xd0,0x7d,0xbd,0x5e,0x2e,0x52,
         0x0d,0x6c,0x26,0x34,0x29,0x28,0x01,0x18,
         0x4f,0xfa,0x54,0xfd,0x5f,0x1e,0x99,0x2c,
         0xcf,0xda,0xff,0x81,0x62,0xf5,0xc5,0xf6,
         0xd1,0xea,0x79,0xdb,0xca,0xe9,0x7e,0x1d},

        {0x58,0x4c,0xc7,0x02,0xc2,0x22,0x9a,0x0a,
         0xbc,0x78,0x9b,0xfa,0x64,0xb4,0x27,0x1f,
         0xb8,0xf0,0xbb,0x78,0x67,0x15,0x88,0xb9,
         0xef,0x1d,0x09,0x3e,0xa3,0xd4,0x72,0x58,
         0x4c,0x6d,0x43,0xb5,0x68,0x33,0x59,0x47,
         0x2f,0x44,0x1b,0x33,0x85,0x6f,0x68,0x28,
         0x59,0xf0,0xc3,0x95,0x4b,0x56,0x80,0x8f,
         0xd1,0xfb,0xa0,0xb5,0x9c,0x9d,0x19,0x54},

        {0xb0,0x52,0xfd,0x4a,0x09,0xf9,0x88,0xbb,
         0xe4,0x11,0x2d,0x9a,0x3e,0xca,0x8c,0xcc,
         0x51,0x7e,0x56,0xda,0x86,0x6c,0x16,0x09,
         0x50,0x4c,0x37,0x87,0x11,0x46,0xda,0x80,
         0x73,0x1b,0xb6,0x81,0x67,0x4a,0x20,0x00,
         0xa4,0x1b,0xcb,0x78,0x23,0x0b,0x3d,0x90,
         0x69,0xeb,0x42,0x82,0x02,0x93,0xce,0x23,
         0xcb,0xa2,0x94,0x55,0x0a,0x1d,0x4d,0x3b}
	};


	/* Test input size 256, 512 and MAX_BUFF_SIZE bytes */
        for (inlen = START_DATA_SIZE; inlen <= MAX_DATA_SIZE; inlen += inlen) {
                PRINT_HDR;
                memset (buff, 0, sizeof (buff));
                for (count = 0; count < inlen; count++)
                        buff[count] = count;

            /* Single call SHA3-512 */
            START_CYCLE;
            SHA3_512(buff, (unsigned long)inlen, hash_sha3_512);
            END_CYCLE("SHA3-512");
            if (memcmp (hash_sha3_512,expected_sha3_512_hash[i],SHA512_DIGEST_LENGTH)) {
                printf ("SHA3-512 Single Call Failed for input size %d bytes\n", inlen);
                ret = -1;
                goto End;
            }

#ifndef TEST_CPU_CYCLES
            /* Multicall SHA3-512 */
            SHA3_512_Init (&ctx);
            memset (hash_sha3_512, 0, sizeof (hash_sha3_512));
            for (count = 0; count < inlen; count += CHUNK_SIZE) {
                if ((inlen - count) <= CHUNK_SIZE)
                    SHA3_512_Update (&ctx, &buff[count], (inlen - count));
                else
                    SHA3_512_Update (&ctx, &buff[count], CHUNK_SIZE);
            }
            SHA3_512_Final ((uint8_t *) hash_sha3_512, &ctx);
            if (memcmp (hash_sha3_512,expected_sha3_512_hash[i],SHA512_DIGEST_LENGTH)) {
                printf ("SHA3-512 Multicall Failed for input size %d bytes\n", inlen);
                ret = -1;
                goto End;
            }
#endif
            i++;

        }
        if (cvmx_is_init_core()) {
            printf ("Tested %-20s : Packet Size from %d to %d : %s\n","SHA3-512",
                    START_DATA_SIZE,MAX_DATA_SIZE,(ret==0)?"Passed":"Failed");
        }
End:

        return ret;
}

#ifdef SHA3_SHAKE
int test_shake_128_hash ()
{
	   uint64_t result[64+21];
	   //char buff[256];
 	   //buff[0] = 0x13;
 	   int inlen = 1;
	   int ret = 0;

	  uint64_t result[64+21];
	  uint8_t buff[MAX_BUFF_SIZE];
          uint32_t count = 0;
          unsigned int inlen;
          int ret = 0;
	 for (inlen = 256; inlen <= MAX_BUFF_SIZE; inlen += inlen) {
                PRINT_HDR;
                memset (buff, 0, sizeof (buff));
                for (count = 0; count < inlen; count++)
                buff[count] = count;

		/* Single call Shake_128_Hash */
              START_CYCLE; 
//		shake_128_hash((char*)buff/*input*/, (int)inlen << 3 /*input_len_bits*/);
	//	shake_128_hash((char*)buff/*input*/, 5 /*input_len_bits*/);
		 END_CYCLE("Shake-128");
//	  }
		shake_extract(result);
                CVMX_MT_SHA3_STARTOP;
                shake_extract(result+21);
                CVMX_MT_SHA3_STARTOP;
                shake_extract(result+42);
                CVMX_MT_SHA3_STARTOP;
                shake_extract(result+63);
           assert(result[0]  == 0x2e0abfba83e6720bull);
 	   assert(result[63] == 0x3b8aec8ae3069cd9ull);
	printf ("Ran %-20s : Packet Size  %d bytes \n","Shake-128",inlen);
	return ret;
}
int test_shake_256_hash ()
{
          uint64_t result[64+21];
          uint8_t buff[MAX_BUFF_SIZE];
          uint32_t count = 0;
          unsigned int inlen;
          int ret = 0;
         for (inlen = 256; inlen <= MAX_BUFF_SIZE; inlen += inlen) {
                PRINT_HDR;
                memset (buff, 0, sizeof (buff));
                for (count = 0; count < inlen; count++)
                buff[count] = count;
                /* Single call Shake_256_Hash */
              START_CYCLE;
              //  shake_256_hash((char*)buff/*input*/, (int)inlen << 3 /*input_len_bits*/);
                 END_CYCLE("Shake-256");
	  }
		shake_extract(result);
                CVMX_MT_SHA3_STARTOP;
                shake_extract(result+17);
                CVMX_MT_SHA3_STARTOP;
                shake_extract(result+34);
                CVMX_MT_SHA3_STARTOP;
                shake_extract(result+51);
        printf ("Ran %-20s : Packet Size  %d bytes \n","Shake-256",inlen);
        return ret;
}
#endif
