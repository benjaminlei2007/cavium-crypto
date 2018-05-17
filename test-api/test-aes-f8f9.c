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
#include <openssl/f8-f9.h>
#include <openssl/aes.h>
#include "test-crypto-common.h"
#include "test-aes-f8f9.h"

#ifdef TEST_CPU_CYCLES
	extern uint32_t numcores;
	extern CVMX_SHARED uint64_t total_cpucycles;
	extern CVMX_SHARED uint64_t total_mbps;		
#endif 

int test_aes_f8f9_kat() {
	unsigned int i = 0,cnt1,cnt2; 
	uint8_t encrypt[MAX_BUFF_SIZE];
	uint8_t decrypt[MAX_BUFF_SIZE];
	uint32_t mac, len;
	int ret,fail = 0,cnt = 0;
 
	f8_ctx CTX;
	f9_ctx CTX1;
	CTX.uea_rev = EEA_REV_2;
	CTX1.uia_rev = EIA_REV_2;
     
	/*F8(AES) Test*/
	for (i = 0; i < sizeof(f8test)/sizeof(f8test[0]); i++) {
		F8TestVectors * f8testptr = &f8test[i];
		/*F8(AES) single-call Test*/
		memset (encrypt, 0, sizeof(encrypt));
		memset (decrypt, 0, sizeof(decrypt));
		ret = f8_eea2 (f8testptr->count, f8testptr->bearer, f8testptr->direction, 
		f8testptr->key, f8testptr->length, f8testptr->plaintext, encrypt);
		if(ret) {
			printf("f8_eea2 Failed\n");
			return ret;
		}
		if (memcmp (f8testptr->ciphertext, encrypt, f8testptr->length/8 + (!(!(f8testptr->length%8))))) {
			printf ("F8(AES) Test Vector # %d Single call Encrypt Failed\n", (i+1));
			return -1;
		}

		ret = f8_eea2 (f8testptr->count, f8testptr->bearer, f8testptr->direction, 
		f8testptr->key, f8testptr->length, encrypt, decrypt);
		if(ret) {
			printf("f8_eea2 Failed\n");
			return ret;
		}

		if (memcmp (f8testptr->plaintext, decrypt, f8testptr->length/8 + !(!(f8testptr->length%8)))) {
			 printf ("F8(AES) Test Vector # %d Single call Encrypt/Decrypt Failed\n", (i+1));
			 return -1;
		} 

		/*F8(AES) Multi-call Test*/
		memset (decrypt, 0, sizeof(decrypt));
		ret = f8_init(&CTX, f8testptr->count, f8testptr->bearer, 
				f8testptr->direction, f8testptr->key);
		if(ret) {
			printf("f8_init Failed\n");
			return ret;
		}

		len = f8testptr->length;
		for(cnt1=0; cnt1<(f8testptr->length)/8 ; cnt1+=16) {
			ret = f8_enc(&CTX,len >=128?128:len, f8testptr->plaintext + cnt1, encrypt + cnt1);
			if(ret) {
				printf("f8_enc Failed\n");
				return ret;
			}
			len = len>=128 ? len-128 : 0 ;
		}
		if (memcmp (f8testptr->ciphertext, encrypt, (f8testptr->length/8 + !(!(f8testptr->length%8))))) {
			printf ("F8(AES) Test Vector # %d Multi-call Encrypt Failed\n", (i+1));
			return -1;
		}

		ret = f8_init(&CTX, f8testptr->count, f8testptr->bearer, 
				f8testptr->direction, f8testptr->key);
		if(ret) {
			printf("f8_init Failed\n");
			return ret;
		}

		len = f8testptr->length;
		for(cnt1=0; cnt1<(f8testptr->length)/8; cnt1 += 16) {
			ret = f8_enc(&CTX,len >=128 ? 128:len, encrypt + cnt1, decrypt + cnt1);
			if(ret) {
				printf("f8_enc Failed\n");
				return ret;
			}
			len = len>=128 ? len-128 : 0 ;
		}

		if (memcmp (f8testptr->plaintext, decrypt, f8testptr->length/8 + !(!(f8testptr->length%8)))){
			 printf ("F8(AES) Test Vector # %d Multi-call Encrypt/Decrypt Failed\n", (i+1));
			 return -1;
		} 
		cnt++;
	}

	/*F9(AES) Test*/
	for (i = 0; i < sizeof(f9test)/sizeof(f9test[0]); i++) {
		F9TestVectors * f9testptr = &f9test[i];
		/*F9(AES) Single-callTest*/
		ret = f9_eia2 (f9testptr->count, f9testptr->bearer, f9testptr->direction, 
					f9testptr->key, f9testptr->length, f9testptr->message, &mac);
		if(ret) {
			printf("f9_eia2 Failed\n");
			return ret;
		}
		if (mac != f9testptr->expected_mac) {
			printf ("F9(AES) Test Vector # %d singlecall Failed\n", (i+1));
			return -1;
		} 

		 /*F9(AES) Multi-callTest*/
		ret = f9_init(&CTX1, f9testptr->count, f9testptr->bearer,
				f9testptr->direction, f9testptr->key);
		if(ret) {
			printf("f9_init Failed\n");
			return ret;
		}
		for(cnt2=0;cnt2 < (f9testptr->length)/8 ;cnt2++) {
			ret = f9_update(&CTX1, 8, f9testptr->message + cnt2);
			if(ret) {
				printf("f9_update Failed\n");
				return ret;
			}
		}

		if(f9testptr->length%8 != 0) {
			ret = f9_update(&CTX1,f9testptr->length%8, f9testptr->message +cnt2);
			if(ret) {
				printf("f9_update Failed\n");
				return ret;
			}
		}
		ret = f9_final(&CTX1, &mac);
		if(ret) {
			printf("f9_final Failed\n");
			return ret;
		}

		if (mac != f9testptr->expected_mac){
			printf ("F9(AES) Test Vector # %d multicall Failed\n", (i+1));
			ret = -1;
			goto End;
		} 
		cnt++;
	}

End:
	if (ret == -1 ) {
		printf("aes f8-f9 test Failed at Line:%d\n",__LINE__);
	} 
	else { 
	if (fail)
		printf("***");
		if (cvmx_is_init_core()) {
			printf ("%-20s :Total Test vectors tested:%d passed : %d failed : %d\n","AES-F8F9",cnt,(cnt-fail),fail);
		}
	}

	return 0;
}

int aes_f8f9 () {
	unsigned int inlen; 
	uint8_t encrypt[MAX_BUFF_SIZE];
	uint8_t decrypt[MAX_BUFF_SIZE];
	int ret=0;
	uint8_t plaintext[MAX_BUFF_SIZE];
	uint8_t key[16] = "\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48";
	uint32_t count = 0x38A6F056;
	uint8_t bearer= 0x1C;
	uint8_t direction = 0x0;
	uint32_t length, mac;
	/* 
	 * for performance tests perfomance taken for sizes ranging from 64
	 * bytes to 16 kB
	 */

	for (inlen = START_PACKET_SIZE; inlen <= MAX_BUFF_SIZE;)
	{	
		PRINT_HDR;	
		length = inlen*8;
		memset (encrypt, 0, sizeof(encrypt));
		START_CYCLE;
		f8_eea2 (count, bearer, direction, key, length, plaintext, encrypt);
		END_CYCLE("F8(AES) ENCRYPTION OF");
		START_CYCLE;
		f8_eea2 (count, bearer, direction, key, length, encrypt, decrypt);
		END_CYCLE("F8(AES) DECRYPTION OF");	
		#ifdef TEST_CPU_CYCLES
			inlen+=inlen;
		#else	
			inlen+=INCR_STEPS;
		#endif
	}
	
	for (inlen = START_PACKET_SIZE; inlen <= MAX_BUFF_SIZE;)
	{	
		PRINT_HDR;
		length = inlen*8;
		START_CYCLE;
		f9_eia2 (count, bearer, direction, key, length, plaintext, &mac);
		END_CYCLE("F9(AES) TEST OF");	
		#ifdef TEST_CPU_CYCLES
			inlen+=inlen;
		#else	
			inlen+=INCR_STEPS;
		#endif
	}
	if (cvmx_is_init_core()) {
	printf ("Tested %-20s : Packet Size from %d to %d : %s\n","AES-F8F9",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}	

	return 0;
}

