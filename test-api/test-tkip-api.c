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
#include "openssl/tkip.h"
#include <test-tkip-api.h>


/* Funtion for print values */
void print_in_hex (uint8_t *val, int count)
{
	int i;
	for (i=0;i< count; i++)
		printf("%02x ", *(val+i));
	printf("\n");
	return;
}



int test_tkip()
{

	uint8_t plaintext[] = {
		0xaa,0xaa,0x03,0x00,0x00,0x00,0x08,0x00,0x45,0x00,0x00,0x54,0x00,0x00,0x40,0x00,
		0x40,0x01,0xa5,0x55,0xc0,0xa8,0x0a,0x02,0xc0,0xa8,0x0a,0x01,0x08,0x00,0x3a,0xb0,
		0x00,0x00,0x00,0x00,0xcd,0x4c,0x05,0x00,0x00,0x00,0x00,0x00,0x08,0x09,0x0a,0x0b,
		0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,
		0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,
		0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
		/*  MIC */  0x68,0x81,0xa3,0xf3,0xd6,0x48,0xd0,0x3c
	};


	uint8_t transmitter_mac[] = {0x02,0x03,0x04,0x05,0x06,0x07};
	size_t len = sizeof(plaintext);	
	uint8_t MPDU[TKIP_IV_LEN+len+TKIP_ICV_LEN];
	tkip_key enckey, deckey;
	int ret=0;
	uint8_t temporal_key[] = {
		0x12,0x34,0x56,0x78,0x90,0x12,0x34,0x56,0x78,0x90,0x12,0x34,0x56,0x78,0x90,0x12
	};


	
	memset(&enckey, 0, sizeof(enckey));
	enckey.IV32 = 0x00000000;
	enckey.IV16 = 0x0001;
	
	memcpy(enckey.tkey, temporal_key, 16);
	enckey.keyidx = 0;
	memcpy(MPDU+TKIP_IV_LEN, plaintext, len);	

	tkip_encrypt_data(&enckey, MPDU, len, transmitter_mac);
	


	memset(&deckey, 0, sizeof(deckey));
	deckey.IV32 = 0x00000000;
	deckey.IV16 = 0x0001;

	memcpy(deckey.tkey, temporal_key, 16);
	deckey.keyidx = 0;
	
	ret = tkip_decrypt_data(&deckey, MPDU, sizeof(MPDU), transmitter_mac);


	
	if(ret == -1)
		printf("\nTKIP Failed with Error : TKIP_DECRYPT_NO_EXT_IV \n");
	else if(ret == -2)
		printf("\nTKIP Failed with Error : TKIP_DECRYPT_INVALID_KEYIDX \n");
	else if(ret == -3)
		printf("\nTKIP Failed with Error : TKIP_DECRYPT_REPLAY \n");

	return 0;

}


int test_tkip_mixing()
{

	uint16_t P1K[NUM_VECTORS][5];
	uint32_t iv32[NUM_VECTORS] = {0,0,0x20DCFD43,0x20DCFD44,0xF0A410FC,0xF0A410FC,0x8B1573B7,0x8B1573B7};
	uint16_t iv16[NUM_VECTORS] = {0,1,0xFFFF,0x0,0x058C,0x058D,0x30F8,0x30f9};

	int loop = 0, fail = 0;


	while (loop<NUM_VECTORS)
	{
		tkip_gen_phase1_key (temporal_key[loop], transmitter_mac[loop], 
							 iv32[loop],P1K[loop]);
		tkip_gen_phase2_key (temporal_key[loop],P1K[loop], iv16[loop], rc4key[loop]);
		if (memcmp(rc4key[loop], expected_rc4key[loop], 16)) {
        	printf("\nRC4 Key Generation Failed.\n");
			fail++;
    	}

		loop++;
	}
	
	if (fail)
		printf("***");
	if (cvmx_is_init_core()) {
	printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","TKIP MIXING",loop,(loop-fail),fail);
	}
	return 0;
}

int test_tkip_michael()
{
	uint64_t key = 0x0;
	uint64_t mic_value;

	int i=0, fail = 0;
	uint32_t len = 0;
	char s[6][256] = {"","M","Mi","Mic","Mich","Michael"};

	while (i<6)
	{
		
		tkip_compute_michael_mic ((uint8_t*)&key,(uint8_t*)s[i], 
								  len,(uint8_t*)&mic_value);
		
		i++;
		len = strlen (s[i]);
		key = mic_value ;

	}
	
	if (fail)
		printf("***");
	if (cvmx_is_init_core()) {
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","TKIP MICHAEL",i,(i-fail),fail);
	}
	return 0;
}

int test_tkip_kat() 
{
	int ret=0;
#if defined(TEST_MICHAEL_MIC) || defined (TEST_ALL)
	ret = test_tkip_michael();
	CHECK_RET("MICHAEL");	
#endif
#if defined(TEST_KEY_MIXING) || defined (TEST_ALL)
	ret = test_tkip_mixing();
	CHECK_RET("MIXING");	
#endif
#if defined(TEST_TKIP) || defined (TEST_ALL)
	ret = test_tkip();
	CHECK_RET("TKIP");	
#endif

	return 0;
}


