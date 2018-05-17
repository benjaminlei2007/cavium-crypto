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
#include "cvmx.h"
#include <openssl/camellia.h>
#include <test-camellia-api.h>

#ifdef TEST_CPU_CYCLES
	extern uint32_t numcores;
	extern CVMX_SHARED uint64_t total_cpucycles;
	extern CVMX_SHARED uint64_t total_mbps;		
#endif

int test_camellia_cbc_kat()
{
	unsigned int i = 0, fail = 0;  
	uint8_t encrypt[MAX_BUFF_SIZE];
	uint8_t decrypt[MAX_BUFF_SIZE];
	uint8_t origiv[CMLL_IV_LEN];
	CAMELLIA_KEY *cmll_key=NULL;
	uint8_t enciv[16], deciv[16];
	int ret = 0;
	int keylen[3]={ 16,24,32 };
	unsigned int j;

	if(!OCTEON_IS_OCTEON3())
	{ 
		if (cvmx_is_init_core())	
			printf ("Camellia APIs are supported only on CN7XXX OCTEON Models\n");
		return -2;
	}

	if((cmll_key=(CAMELLIA_KEY *)malloc(sizeof(CAMELLIA_KEY)))==NULL)
	{
		printf("unable to allocate memory for key\n");
	}
	
	memset(cmll_key,0,sizeof(CAMELLIA_KEY));
	memset(encrypt,0,sizeof(encrypt));
	memset(decrypt,0,sizeof(decrypt));


//CBC implememntation 
	for(i = 0; i < CMLL_IV_LEN; i++) origiv[i] = MASK8(i);

	for(i = 0; i < 3; i++) {
		memcpy(enciv, origiv, 16);
		memcpy(deciv, origiv, 16);
		Camellia_set_key(camellia_cbc_key[i], keylen[i] << 3, cmll_key);
	}

	for(j = 0; j < 3; j++) {
/* Encrypt */
		Camellia_cbc_encrypt(camellia_cbc_plain[j], encrypt,
					16, cmll_key, enciv, 1);
/* Decrypt */
		Camellia_cbc_encrypt(encrypt, decrypt, 16, cmll_key, deciv, 0);
		if(memcmp(camellia_cbc_plain[j], decrypt, 16))
		{
			printf("CAMELLIA-CBC FAILED!!\n");
			ret=-1;
				fail++;
			goto End;
		}
		memset(encrypt, 0, sizeof(encrypt));
		memset(decrypt, 0, sizeof(decrypt));
	}
	if(cmll_key) free(cmll_key);
	ret = 0;
End:
	if (fail)
		printf("***");
	if (cvmx_is_init_core())	
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","CAMELLIA-CBC",j,(j-fail),fail);
	return ret;


}

int test_camellia_cbc()
{
	unsigned int inlen= 0;
	uint8_t inbuff[16*1024];
	unsigned int i = 0;  
	uint8_t encrypt[MAX_BUFF_SIZE];
	uint8_t decrypt[MAX_BUFF_SIZE];
	uint8_t origiv[CMLL_IV_LEN];
	unsigned int k=0;  
	CAMELLIA_KEY *cmll_key=NULL;
	uint8_t enciv[16], deciv[16];
	int ret = 0;
	int keylen[3]={ 16,24,32 };
 
	for (k = 0; k < inlen; k++) {
	inbuff[k] = (k%10);
	}

	if(!OCTEON_IS_OCTEON3())
	{ 
		if (cvmx_is_init_core())	
			printf ("Camellia APIs are supported only on CN7XXX OCTEON Models\n");
		return -1;
	}

	if((cmll_key=(CAMELLIA_KEY *)malloc(sizeof(CAMELLIA_KEY)))==NULL)
	{
		printf("unable to allocate memory for key\n");
	}
	
	memset(cmll_key,0,sizeof(CAMELLIA_KEY));
	memset(encrypt,0,sizeof(encrypt));
	memset(decrypt,0,sizeof(decrypt));


//CBC implememntation 

	for(inlen = START_PACKET_SIZE ; inlen <= MAX_BUFF_SIZE;)
	{
		PRINT_HDR;
		for(i = 0; i < CMLL_IV_LEN; i++) origiv[i] = MASK8(i);
		for(i = 0; i < 3; i++) {
			memcpy(enciv, origiv, 16);
			memcpy(deciv, origiv, 16);
			Camellia_set_key(camellia_cbc_key[i], keylen[i] << 3, cmll_key);
	/* Encrypt */
			START_CYCLE_ENC;
			Camellia_cbc_encrypt(inbuff, encrypt,
						inlen, cmll_key, enciv, 1);
			END_CYCLE_AES("CAMELLIA-CBC-ENC",keylen[i]*8);
	/* Decrypt */
			START_CYCLE_DEC;
			Camellia_cbc_encrypt(encrypt, decrypt, inlen, cmll_key, deciv, 0);
			END_CYCLE_AES("CAMELLIA-CBC-DEC",keylen[i]*8);
			if(memcmp(inbuff, decrypt, inlen))
			{
				printf("CAMELLIA-CBC FAILED!!\n");
				ret=-1;
				goto End;
			}
			memset(encrypt, 0, sizeof(encrypt));
			memset(decrypt, 0, sizeof(decrypt));
		}
		#ifdef TEST_CPU_CYCLES
			inlen+=inlen;
		#else	
			inlen+=INCR_STEPS;
		#endif
	}
	if(cmll_key) free(cmll_key);
	ret = 0;
	if (cvmx_is_init_core())	
		printf ("Tested %-20s : Packet Size from %d to %d : %s\n","CAMELLIA-CBC",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
End:
	return ret;


}
int test_camellia_ctr_kat () {

//    uint8_t inbuff[16*1024];
	unsigned int i = 0, fail = 0;  
	uint8_t encrypt[MAX_BUFF_SIZE];
	uint8_t decrypt[MAX_BUFF_SIZE];
	CAMELLIA_KEY *cmll_key=NULL;
	uint8_t enciv[16], deciv[16];	
	int ret = 0;
	unsigned char ecount_buf[CAMELLIA_BLOCK_SIZE];
	unsigned int offset=0;


//#ifndef TEST_CPU_CYCLES
	static const int camellia_test_ctr_len[3] ={ 16, 32, 36 };
//#endif
 
	if(!OCTEON_IS_OCTEON3())
	{ 
		if (cvmx_is_init_core())	
			printf ("Camellia APIs are supported only on CN7XXX OCTEON Models\n");
		return -2;
	}

	if((cmll_key=(CAMELLIA_KEY *)malloc(sizeof(CAMELLIA_KEY)))==NULL)
	{
		printf("unable to allocate memory for key\n");
	}
	
	memset(cmll_key,0,sizeof(CAMELLIA_KEY));
	memset(encrypt,0,sizeof(encrypt));
	memset(decrypt,0,sizeof(decrypt));
/* CTR Implementation */

 	for(i = 0; i < 3; i++)
		{
			memcpy(enciv, camellia_test_ctr_nonce_counter[i], 16);
			memcpy(deciv, camellia_test_ctr_nonce_counter[i], 16);

	   		Camellia_set_key(camellia_test_ctr_key[i], 16*8, cmll_key);
			/* Encrypt */
			offset = 0;
			Camellia_ctr128_encrypt(camellia_test_ctr_pt[i], encrypt, camellia_test_ctr_len[i], cmll_key,
					 enciv, ecount_buf, &offset);
			if(memcmp(camellia_test_ctr_ct[i],encrypt,16)) 
			{
				printf("Encrypted test and expected cipher text are not matching: CAMELIA-CTR FAILED!!! \n\n");
		ret=-1;
				fail++;
		goto End;
			}

			/* Decrypt */
			offset=0;
			Camellia_ctr128_encrypt(encrypt, decrypt, camellia_test_ctr_len[i], cmll_key,
					deciv, ecount_buf, &offset);
			if(memcmp(camellia_test_ctr_pt[i], decrypt, camellia_test_ctr_len[i]))
			{
				printf("CAMELLIA-CTR FAILED!!\n");
				ret=-1;
				fail++;
				goto End;
		   }
		}
	

	if(cmll_key) free(cmll_key);
	ret = 0;
End:
	if (fail)
		printf("***");
	if (cvmx_is_init_core())	
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","CAMELLIA-CTR",i,(i-fail),fail);
	return ret;

}


int test_camellia_ctr () {
	unsigned int inlen= 0;
	uint8_t inbuff[MAX_BUFF_SIZE];
	unsigned int i = 0;  
	uint8_t encrypt[MAX_BUFF_SIZE];
	uint8_t decrypt[MAX_BUFF_SIZE];
	CAMELLIA_KEY *cmll_key=NULL;
	uint8_t enciv[16], deciv[16];
	int ret = 0;
	unsigned int k=0;  
	unsigned char ecount_buf[CAMELLIA_BLOCK_SIZE];
	unsigned int offset=0;

	for (k = 0; k < inlen; k++) {
	inbuff[k] = (k%10);
	}
 
	if(!OCTEON_IS_OCTEON3())
	{ 
		if (cvmx_is_init_core())	
			printf ("Camellia APIs are supported only on CN7XXX OCTEON Models\n");
		return -1;
	}

	if((cmll_key=(CAMELLIA_KEY *)malloc(sizeof(CAMELLIA_KEY)))==NULL)
	{
		printf("unable to allocate memory for key\n");
	}
	
	memset(cmll_key,0,sizeof(CAMELLIA_KEY));
	memset(encrypt,0,sizeof(encrypt));
	memset(decrypt,0,sizeof(decrypt));

/* CTR Implementation */

	for(inlen = START_PACKET_SIZE ; inlen <= MAX_BUFF_SIZE;)
	{
		PRINT_HDR;
	for(i = 0; i < 3; i++)
		{
			memcpy(enciv, camellia_test_ctr_nonce_counter[i], 16);
			memcpy(deciv, camellia_test_ctr_nonce_counter[i], 16);

	   		Camellia_set_key(camellia_test_ctr_key[i], 16*8, cmll_key);
			
			/* Encrypt */
			offset = 0;
		START_CYCLE_CTR;
			Camellia_ctr128_encrypt(inbuff, encrypt, inlen, cmll_key,
					 enciv, ecount_buf, &offset);
		END_CYCLE("CAMELLIA-CTR-ENC");
		   /* Decrypt */
			offset=0;
		START_CYCLE_CTR1;
			Camellia_ctr128_encrypt(encrypt, decrypt,inlen, cmll_key,
					deciv, ecount_buf, &offset);
		END_CYCLE("CAMELLIA-CTR-DEC");

			if(memcmp(inbuff, decrypt, inlen))
			{
				printf("CAMELLIA-CTR FAILED!!\n");
		ret=-1;
		goto End;
			}
		}	
		#ifdef TEST_CPU_CYCLES
			inlen+=inlen;
		#else
			inlen+=INCR_STEPS;
		#endif
	}

	if(cmll_key) free(cmll_key);
	ret = 0;
	if (cvmx_is_init_core())	
		printf ("Tested %-20s : Packet Size from %d to %d : %s\n","CAMELLIA-CTR",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
End:
	return ret;

}

int test_camellia_ecb_kat ( ) {
	unsigned int i = 0, j=0, k=0;  
	uint8_t encrypt[MAX_BUFF_SIZE];
	uint8_t decrypt[MAX_BUFF_SIZE];
	CAMELLIA_KEY *cmll_key=NULL;
	unsigned int len=16;
	int ret = 0, fail = 0;
	int keylen[3]={ 16,24,32 };

 
	if(!OCTEON_IS_OCTEON3())
	{ 
		if (cvmx_is_init_core())	
			printf ("Camellia APIs are supported only on CN7XXX OCTEON Models\n");
		return -2;
	}

	if((cmll_key=(CAMELLIA_KEY *)malloc(sizeof(CAMELLIA_KEY)))==NULL)
	{
		printf("unable to allocate memory for key\n");
	}
	memset(cmll_key,0,sizeof(CAMELLIA_KEY));
	memset(encrypt,0,sizeof(encrypt));
	memset(decrypt,0,sizeof(decrypt));

////ECB implememntation 


	for(i=0;i<3;i++) {
		for ( j=0; j<2; j++ ) {
			Camellia_set_key(camellia_test_ecb_key[i][j],keylen[i]*8,cmll_key);
			/*Encrypt */
			 k=0;
			do
			{
				Camellia_ecb_encrypt(&camellia_test_ecb_plain[j][k],&encrypt[k],cmll_key,1);
				k+=CMLL_BLOCK_LENGTH;
			} while( k < len);
			if(memcmp(camellia_test_ecb_cipher[i][j],encrypt,16)) 
			{
				printf("Encrypted test and expected cipher text are not matching: CAMELIA-ECB FAILED!!! \n\n");
				ret=-1;
				fail++;
				goto End;
			}
			/*Decrypt */
			k=0;
			do
			{ 
				Camellia_ecb_encrypt(&encrypt[k],&decrypt[k],cmll_key,0);
				k+=CMLL_BLOCK_LENGTH;
			} while(k<len);

			if(memcmp(decrypt,camellia_test_ecb_plain[j] ,16))
			{
				printf("CAMELIA-ECB test: FAILED!!!\n");
				ret=-1;
				fail++;
				goto End;
			}
		}
	}
	
	if(cmll_key) free(cmll_key);
	ret = 0;
End:
	if (fail)
		printf("***");
	if (cvmx_is_init_core())	
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","CAMELLIA-ECB",i,(i-fail),fail);
	return ret;
}


int test_camellia_ecb ( ) {
	
	unsigned int inlen= 0;
	uint8_t inbuff[MAX_BUFF_SIZE];
	unsigned int i = 0, j=0, k=0;  
	uint8_t encrypt[MAX_BUFF_SIZE];
	uint8_t decrypt[MAX_BUFF_SIZE];
	CAMELLIA_KEY *cmll_key=NULL;
	int ret = 0;
	int keylen[3]={ 16,24,32 };
	for (k = 0; k < inlen; k++) {
	inbuff[k] = (k%10);
	}

 
	if(!OCTEON_IS_OCTEON3())
	{ 
		if (cvmx_is_init_core())	
			printf ("Camellia APIs are supported only on CN7XXX OCTEON Models\n");
		return -1;
	}

	if((cmll_key=(CAMELLIA_KEY *)malloc(sizeof(CAMELLIA_KEY)))==NULL)
	{
		printf("unable to allocate memory for key\n");
	}
	memset(cmll_key,0,sizeof(CAMELLIA_KEY));
	memset(encrypt,0,sizeof(encrypt));
	memset(decrypt,0,sizeof(decrypt));

////ECB implememntation 

	for(inlen = START_PACKET_SIZE ; inlen <= MAX_BUFF_SIZE;)
	{
		for(i=0;i<3;i++) {
			for ( j=0; j<2; j++ ) {
				Camellia_set_key(camellia_test_ecb_key[i][j],keylen[i]*8,cmll_key);
				k=0;
				do
				{
					Camellia_ecb_encrypt(&inbuff[k],&encrypt[k],cmll_key,1);
					k+=CMLL_BLOCK_LENGTH;
	
				} while( k < inlen);
	/*Decrypt */
				k=0;
				do
				{ 
					Camellia_ecb_encrypt(&encrypt[k],&decrypt[k],cmll_key,0);
					k+=CMLL_BLOCK_LENGTH;
				} while(k<inlen);
				if(memcmp(inbuff,decrypt,inlen))
				{
					printf("CAMELIA-ECB test: FAILED!!!\n");
					ret=-1;
					goto End;
				}
	
			}
		}	
		#ifdef TEST_CPU_CYCLES
			inlen+=inlen;
		#else
			inlen+=INCR_STEPS;
		#endif
	}
	if(cmll_key) free(cmll_key);
	ret = 0;
	if (cvmx_is_init_core())	
		printf ("Tested %-20s : Packet Size from %d to %d : %s\n","CAMELLIA-ECB",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
End:
	return ret;
}

int camellia_kat()
{ 
	unsigned int ret=0;  
  
	if(!OCTEON_IS_OCTEON3())
	{ 	
		if (cvmx_is_init_core())	
			printf("Camellia APIs are supported only on CN7XXX OCTEON Models\n");
		return -2;
	}

	ret = test_camellia_cbc_kat ();
	CHECK_RESULT("CAMELLIA-CBC");

	ret = test_camellia_ctr_kat ();
	CHECK_RESULT("CAMELLIA-CTR");

	ret = test_camellia_ecb_kat ();
	CHECK_RESULT("CAMELLIA-ECB");

  return 0;
}


int camellia()
{ 
	unsigned int ret=0;  
  
	if(!OCTEON_IS_OCTEON3())
	{ 	
		if (cvmx_is_init_core())	
			printf("Camellia APIs are supported only on CN7XXX OCTEON Models\n");
		return -2;
	}

	ret = test_camellia_cbc ();
	CHECK_RESULT("CAMELLIA-CBC");

	ret = test_camellia_ctr ();
	CHECK_RESULT("CAMELLIA-CTR");

	ret = test_camellia_ecb ();
	CHECK_RESULT("CAMELLIA-ECB");

  return 0;
}
