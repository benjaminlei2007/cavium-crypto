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
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/dsa.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/dh.h>
#include "test-crypto-common.h"
#include <test-asymmetric-api.h>

#ifdef TEST_CPU_CYCLES
	extern uint32_t numcores;
	extern CVMX_SHARED uint64_t total_cpucycles;
	extern CVMX_SHARED uint64_t total_tps;		
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
DSA* DSA_genparam (int bits )
{
	int counter;
	unsigned long h;
	DSA *dsa = NULL;
	char seed[30] = "sdfonoidfwsdkfnwkenalajsfkjd";
	dsa = DSA_generate_parameters (bits, (uint8_t*)seed, strlen(seed), &counter, &h, NULL, NULL);
return dsa;
}
int test_dh_kat () {	
	if (cvmx_is_init_core())	
		printf ("*** DH Known Answer Test not available ***\n");
	return 0;
}

int  test_dsa_kat () {
	int bits = 0,msglen;
	unsigned char msg[2048];
	unsigned char msgdigest[20];
	unsigned int i;
	int ret, fail =0;
	DSA *dsa = NULL;
	DSA_SIG *dsa_sig= NULL;
	for (i=0;i< sizeof dsa_nist/sizeof (dsa_nist[0]);i++) {
		if (dsa_nist[i].mod_len == 1024 ) {
			bits = 1024;
			dsa = DSA_genparam (bits);
		}
		if (dsa_nist[i].mod_len == 2048) {
			bits = 2048;
			dsa = DSA_genparam (bits);
		}
		if (dsa_nist[i].mod_len == 3072 ) {
			bits = 3072;
			dsa = DSA_genparam (bits);
		}
		str2hex(dsa_nist[i].msg, msg, &msglen);
		ret = DSA_generate_key (dsa);
		if (ret != 1)
			 printf ("DSA_generate_key FAILED\n");

		if (memcmp (dsa_nist[i].hash,"SHA1",sizeof (dsa_nist[i].hash))==0) {
			SHA1 (msg, msglen, msgdigest);
			dsa_sig = DSA_do_sign (msgdigest, 20, dsa);
			if (dsa_sig == NULL)
			printf ("DSA_do_sign FAILED\n");
			ret = DSA_do_verify (msgdigest, 20, dsa_sig, dsa);
			if (ret == 0) {
				printf ("DSA verify failed\n");
				fail++;
			}
		}
		else if (memcmp (dsa_nist[i].hash,"SHA224",sizeof (dsa_nist[i].hash))==0) {
			SHA224 (msg, msglen, msgdigest);
			dsa_sig = DSA_do_sign (msgdigest, 28, dsa);
			if (dsa_sig == NULL)
			printf ("DSA_do_sign FAILED\n");
			ret = DSA_do_verify (msgdigest, 28, dsa_sig, dsa);
			if (ret == 0) {
				printf ("DSA verify failed\n");
				fail++;
			}
		}else if (memcmp (dsa_nist[i].hash,"SHA256",sizeof (dsa_nist[i].hash))==0) {
			SHA256 (msg, msglen, msgdigest);
			dsa_sig = DSA_do_sign (msgdigest, 32, dsa);
			if (dsa_sig == NULL)
			printf ("DSA_do_sign FAILED\n");
			ret = DSA_do_verify (msgdigest, 32, dsa_sig, dsa);
			if (ret == 0) {
				printf ("DSA verify failed\n");
				fail++;
			}
		}else if (memcmp (dsa_nist[i].hash,"SHA384",sizeof (dsa_nist[i].hash))==0) {
			SHA384 (msg, msglen, msgdigest);
			dsa_sig = DSA_do_sign (msgdigest, 48, dsa);
			if (dsa_sig == NULL)
			printf ("DSA_do_sign FAILED\n");
			ret = DSA_do_verify (msgdigest, 48, dsa_sig, dsa);
			if (ret == 0) {
				printf ("DSA verify failed\n");
				fail++;
			}
		}else if (memcmp (dsa_nist[i].hash,"SHA512",sizeof (dsa_nist[i].hash))==0) {
			SHA512 (msg, msglen, msgdigest);
			dsa_sig = DSA_do_sign (msgdigest, 64, dsa);
			if (dsa_sig == NULL)
			printf ("DSA_do_sign FAILED\n");
			ret = DSA_do_verify (msgdigest, 64, dsa_sig, dsa);
			if (ret == 0) {
				printf ("DSA verify failed\n");
				fail++;
			}
		}
	}
	if (fail)
		printf("***");
	 if (cvmx_is_init_core()) 
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","DSA",i,(i-fail),fail);

	return 0;
}


int test_rsa_kat () {
	RSA * rsa = NULL;
	unsigned int siglen = 0;
	unsigned char sha1_msgdigest[20] = {0};
	unsigned char sha224_msgdigest[28] = {0};
	unsigned char sha256_msgdigest[32] = {0};
	unsigned char sha384_msgdigest[48] = {0};
	unsigned char sha512_msgdigest[64] = {0};
	unsigned char sigret[10000]={0};
	uint8_t msg[4096];
	unsigned int i;
	int fail = 0;
  int msg_len = 0, bits = 0, ret;
	for (i = 0;i < sizeof (rsa_nist)/sizeof (rsa_nist[0]);i++) {
		if (rsa_nist[i].mod_len == 1024 ) {
			bits = 1024;
			siglen = 128;
			rsa = RSA_generate_key (bits, 3, NULL, NULL);
		}
		else if (rsa_nist[i].mod_len == 2048 ) {
			bits = 2048;
			siglen = 256;
			rsa = RSA_generate_key (bits, 3, NULL, NULL);
		}
		else if (rsa_nist[i].mod_len == 3072) {
			bits = 3072;
			siglen = 384;
			rsa = RSA_generate_key (bits, 3, NULL, NULL);
		}
		 str2hex (rsa_nist[i].msg, msg, &msg_len);
		if (memcmp (rsa_nist[i].hash,"SHA1",sizeof (rsa_nist[i].hash))==0) {
			SHA1 (msg, msg_len, sha1_msgdigest);
			ret = RSA_sign (NID_sha1, sha1_msgdigest, 20, sigret, &siglen, rsa);
			if (1 != ret) {
				printf ("RSA_sign failed\n");
			}
			SHA1 (msg, msg_len ,sha1_msgdigest);
			ret = RSA_verify (NID_sha1, sha1_msgdigest, 20, sigret, siglen, rsa);
			if (1 != ret) {
				printf ("RSA_verify failed (ret : %d)\n", ret);
				 fail++;
			}
		}
		else if (memcmp (rsa_nist[i].hash,"SHA224",sizeof (rsa_nist[i].hash))==0) {
			SHA224 (msg, msg_len, sha224_msgdigest); 
			ret = RSA_sign (NID_sha224, sha224_msgdigest, 28, sigret, &siglen, rsa);
			if (1 != ret) {
				 printf ("RSA_sign failed\n");
			}
			SHA224 (msg, msg_len ,sha224_msgdigest);
			ret = RSA_verify (NID_sha224, sha224_msgdigest, 28, sigret, siglen, rsa);
			if (1 != ret) {
				printf ("RSA_verify  failed (ret : %d)\n", ret);
				fail++;
			}
				   
		}
		else if (memcmp (rsa_nist[i].hash,"SHA256",sizeof (rsa_nist[i].hash))==0) {
			SHA256 (msg, msg_len, sha256_msgdigest); 
			ret = RSA_sign (NID_sha256, sha256_msgdigest, 32, sigret, &siglen, rsa);
			if (1 != ret) {
				 printf ("RSA_sign failed\n");
			}
			SHA256 (msg, msg_len ,sha256_msgdigest);
			ret = RSA_verify (NID_sha256, sha256_msgdigest, 32, sigret, siglen, rsa);
			if (1 != ret) {
				fail++;
				printf ("RSA_verify  failed (ret : %d)\n", ret);
			}
		}
		else if (memcmp (rsa_nist[i].hash,"SHA384",sizeof (rsa_nist[i].hash))==0) {
			SHA384 (msg, msg_len, sha384_msgdigest); 
			ret = RSA_sign (NID_sha384, sha384_msgdigest, 48, sigret, &siglen, rsa);
			if (1 != ret) {
				printf ("RSA_sign failed\n");
			}
			SHA384 (msg, msg_len ,sha384_msgdigest);
			ret = RSA_verify (NID_sha384, sha384_msgdigest, 48, sigret, siglen, rsa);
			if (1 != ret) {
				printf ("RSA_verify  failed (ret : %d)\n", ret);
				fail++;
			}
		}
		else if (memcmp (rsa_nist[i].hash,"SHA512",sizeof (rsa_nist[i].hash))==0) {
			SHA512 (msg, msg_len, sha512_msgdigest); 
			ret = RSA_sign (NID_sha512, sha512_msgdigest, 64, sigret, &siglen, rsa);
			if (1 != ret) {
				 printf ("RSA_sign failed\n");
			}
			SHA512 (msg, msg_len ,sha512_msgdigest);
			ret = RSA_verify (NID_sha512, sha512_msgdigest, 64, sigret, siglen, rsa);
			if (1 != ret) {
				printf ("RSA_verify  failed (ret : %d)\n", ret);
				fail++;
			}
		}
	}
	if (fail)
		printf("***");
	 if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","RSA",i,(i-fail),fail);

	return 0;
}




int test_rsa ()
{
	RSA *rsa = NULL;
	int modulus = 256, exponent = 3;
	uint8_t *sig = NULL;
	uint8_t m[] = "Hello";
	int ret = 0;
	uint8_t indata[] = "abcdefghijklmnopqrst";
	uint8_t temp[1024] = {0};
	int tlen;
	uint32_t siglen = 0;
	
/* This loop tests modules sizes 256, 512, 1024 and 2048*/
	for (modulus = 256; modulus <= 2048; modulus += modulus)  {
#ifdef TEST_CPU_CYCLES
		if (cvmx_is_init_core()) {
			printf ("\n\n####################################################\n");
			printf ("CPU Cycles for RSA modulus : %d and exponent : %d\n",
				 modulus, exponent);
			printf ("####################################################\n");
		}
#endif
		rsa = RSA_generate_key (modulus, exponent, NULL, NULL);
		if (rsa == NULL)  {
			printf ("\nRSA_generate_key Failed for modulus : %d\n", modulus);
			ret = -1;
			goto End;
		}
		sig = (unsigned char *) malloc (RSA_size (rsa));
		if (sig == NULL) {
			printf ("\nMalloc Failed Line : %d\n", __LINE__);
			ret = -1;
			goto End;
		}
		START_CYCLE;
		ret = RSA_sign (NID_sha1, (uint8_t*)m, sizeof(m), sig, 
						(unsigned int *)&siglen, rsa);
		END_CYCLE("RSA_sign");
		if (ret != 1)  {
			printf ("\nRSA_sign Failed for modulus : %d\n", modulus);
			ret = -1;
			goto End;
		}
	
		START_CYCLE;
		ret = RSA_verify (NID_sha1, (uint8_t*)m, sizeof (m), sig, 
						  (unsigned int)siglen, rsa);
		END_CYCLE("RSA_verify");
		if (ret != 1) {
			printf ("\nRSA_verify Failed for modulus : %d\n", modulus);
			ret = -1;
			goto End;
		}
	
		START_CYCLE;
		tlen = RSA_private_encrypt (sizeof(indata), indata, 
									sig, rsa, RSA_PKCS1_PADDING);
		END_CYCLE("RSA_private_encrypt");
		if (tlen < 0) {
			printf ("\nRSA_private_encrypt Failed for modulus:%d\n", modulus);
			ret = -1;
			goto End;
		}
	
		START_CYCLE;
		ret = RSA_public_decrypt (tlen, sig, temp, rsa, RSA_PKCS1_PADDING);
		END_CYCLE("RSA_public_decrypt");
		if (ret < 0) {
			printf ("\nRSA_public_decrypt Failed for modulus:%d\n", modulus);
			ret = -1;
			goto End;
		}
	
		if (memcmp (indata, temp, sizeof((const char *) indata)))  {
			printf ("\nRSA Private Encrypt/Public Decrypt Failed for "
					"modulus : %d\n", modulus);
			ret = -1;
			goto End;
		}
	
		START_CYCLE;
		tlen = RSA_public_encrypt (sizeof((const char *) indata), indata, sig,
								   rsa, RSA_PKCS1_PADDING);
		END_CYCLE("RSA_public_encrypt");
		if (tlen < 0) {
			printf ("\nRSA_public_encrypt Failed for modulus : %d\n", modulus);
			ret = -1;
			goto End;
		}
	
		memset (temp, 0, sizeof (temp));
	
		START_CYCLE;
		ret = RSA_private_decrypt (tlen, sig, temp, rsa, RSA_PKCS1_PADDING);
		END_CYCLE("RSA_private_decrypt");
		if (ret < 0) {
			printf ("\nRSA_private_decrypt Failed for modulus:%d\n", modulus);
			ret = -1;
			goto End;
		}
	
		if (memcmp (indata, temp, sizeof((const char *) indata)))  {
			printf ("\nRSA Public Encrypt/Private Decrypt Failed for "
					"modulus : %d\n", modulus);
			ret = -1;
			goto End;
		}
		ret = 0;
	
End:
		if (rsa)  RSA_free (rsa);
		if (sig)  free (sig);

		if (ret != 0) break;
	}

	if (cvmx_is_init_core()) {
	printf ("Tested %-15s : Modulus Length from %d To %d : %s\n","RSA",
						256,2048,(ret==0)?"Passed":"Failed");
	}
	return ret;
}


int test_dsa ()
{
	DSA *dsa = NULL;
	int counter_ret;
	uint8_t *dsamd = NULL;
	DSA_SIG *dsasig = NULL;
	unsigned long h_ret;
	uint8_t seed[] = "sdfonoidfwsdkfnwken";
	int primelen;
	uint32_t dsa_len;
	int ret = 0;

/* This will test prime lengths 256, 512, 1024 and 2048*/
	for (primelen = 256; primelen <= 1024; primelen += primelen)  {
#ifdef TEST_CPU_CYCLES	
	if (cvmx_is_init_core()) {
		printf ("\n\n####################################################\n");
		printf ("CPU Cycles for DSA primelen : %d\n", primelen);
		printf ("####################################################\n");
	}
#endif
		dsa = DSA_generate_parameters (primelen, seed, sizeof (seed), 
									   &counter_ret, &h_ret, NULL, NULL);
		if (dsa == NULL)  {
			printf ("\nDSA_generate_parameters Failed for primelen : %d\n", 
					 primelen);
			ret = -1;
			goto End;
		}
		START_CYCLE;
		ret = DSA_generate_key (dsa);
		END_CYCLE("DSA_generate_key");
		if (1 != ret)  {
			printf ("\nDSA_generate_key Failed for primelen : %d\n", primelen);
			ret = -1;
			goto End;
		}

		dsamd = malloc (DSA_size (dsa));
		if (dsamd == NULL)  {
			printf ("\nMalloc Failed Line %d\n", __LINE__);
			ret = -1;
			goto End;
		}

		START_CYCLE;
		ret = DSA_sign (0, seed, sizeof (seed), dsamd, 
						(unsigned int *)&dsa_len, dsa);
		END_CYCLE("DSA_sign");
		if (1 != ret)  {
			printf ("\nDSA_sign Failed for primelen : %d\n", primelen);
			ret = -1;
			goto End;
		}

		START_CYCLE;
		ret = DSA_verify (0, seed, sizeof (seed), dsamd, dsa_len, dsa);
		END_CYCLE("DSA_verify");
		if (1 != ret)  {
			printf ("\nDSA_verify Failed for primelen : %d\n", primelen);
			ret = -1;
			goto End;
		}
 
		START_CYCLE;
		dsasig = DSA_do_sign (seed, sizeof (seed), dsa);
		END_CYCLE("DSA_do_sign");
		if (dsasig == NULL)  {
			printf ("\nDSA_do_sign Failed for primelen : %d\n", primelen);
			ret = -1;
			goto End;
		}

		START_CYCLE;
		ret = DSA_do_verify (seed, sizeof (seed), dsasig, dsa);
		END_CYCLE("DSA_do_verify");
		if (1 != ret)  {
			printf ("\nDSA_do_verify Failed for primelen:%d\n", primelen);
			ret = -1;
			goto End;
		}

		ret = 0;
End :
		if (dsa)	  DSA_free (dsa);
		if (dsasig)   DSA_SIG_free (dsasig);
		if (dsamd)	free (dsamd);

		if (ret != 0)  break;
	}
	
	if (cvmx_is_init_core()) {
		printf ("Tested %-15s: Prime length From %d To %d : %s\n","DSA",
						256,2048,(ret==0)?"Passed":"Failed");
	}
	return ret;
}


int test_dh ()
{
	DH *adh = NULL, *bdh = NULL;
	uint8_t *abuf = NULL, *bbuf = NULL;
	int i, alen, blen, aout, bout;
	int primelen;
	int ret = -1;

	for (primelen = 256; primelen <= 1024; primelen+=primelen)  {
#ifdef TEST_CPU_CYCLES	
	if (cvmx_is_init_core()) {
		printf ("\n\n####################################################\n");
		printf ("CPU Cycles for DH primelen: %d and generator : %d\n",
				 primelen, DH_GENERATOR_5);
		printf ("####################################################\n");
	}
#endif

		adh = DH_generate_parameters (primelen, DH_GENERATOR_5, NULL, NULL);
		if (adh == NULL) {
			printf ("\nDH_generate_parameters Failed (primelen:%d)\n", primelen);
			ret = -1;
			goto Err;
		}

		if (!DH_check (adh, &i))
			goto Err;

		if (i & DH_CHECK_P_NOT_PRIME)
			printf ("p value is not prime\n");
		if (i & DH_CHECK_P_NOT_SAFE_PRIME)
			printf ("p value is not a safe prime\n");
		if (i & DH_UNABLE_TO_CHECK_GENERATOR)
			printf ("unable to check the generator value\n");
		if (i & DH_NOT_SUITABLE_GENERATOR)
			printf ("the g value is not a generator\n");

		bdh = DH_new ();
		if (bdh == NULL) {
			printf ("\nDH_new Failed\n");
			goto Err;
		}
		bdh->p = BN_dup (adh->p);
		bdh->g = BN_dup (adh->g);
		if ((bdh->p == NULL) || (bdh->g == NULL))  {
			printf ("\nBN_dup Failed\n");
			goto Err;
		}

		START_CYCLE;
		if (!DH_generate_key (adh))  {
			printf ("\nDH_generate_key Failed (primelen : %d)\n", primelen);
			goto Err;
		}
		END_CYCLE("DH_generate_key");
		if (!DH_generate_key (bdh))  {
			printf ("\nDH_generate_key Failed (primelen : %d)\n", primelen);
			goto Err;
		}

		alen = DH_size (adh);
		abuf = (uint8_t *) OPENSSL_malloc (alen);
		START_CYCLE;
		aout = DH_compute_key (abuf, bdh->pub_key, adh);
		END_CYCLE("DH_compute_key");
		
		blen = DH_size (bdh);
		bbuf = (uint8_t *) OPENSSL_malloc (blen);
		bout = DH_compute_key (bbuf, adh->pub_key, bdh);

		if ((aout < 4) || (bout != aout) || (memcmp (abuf, bbuf, aout) != 0)) {
			printf ("\nDH routines Failed (primelen:%d)\n", primelen);
			goto Err;
		}
		ret = 0;
Err :
		
		if (abuf)  OPENSSL_free (abuf);
		if (bbuf)  OPENSSL_free (bbuf);
		if (bdh)   DH_free (bdh);
		if (adh)   DH_free (adh);

		if (ret != 0) break;
	}

	if (cvmx_is_init_core()) {
		printf ("Tested %-15s: Prime length From %d To %d : %s\n","DH",
						256,2048,(ret==0)?"Passed":"Failed");
	}
	return ret;
}




