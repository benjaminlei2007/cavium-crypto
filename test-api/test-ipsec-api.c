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
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *	  software must display the following acknowledgment:
 *	  "This product includes software developed by the OpenSSL Project
 *	  for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *	  endorse or promote products derived from this software without
 *	  prior written permission. For written permission, please contact
 *	  openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *	  nor may "OpenSSL" appear in their names without prior written
 *	  permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *	  acknowledgment:
 *	  "This product includes software developed by the OpenSSL Project
 *	  for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *	  must display the following acknowledgement:
 *	  "This product includes cryptographic software written by
 *	 Eric Young (eay@cryptsoft.com)"
 *	  The word 'cryptographic' can be left out if the rouines from the library
 *	  being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *	  the apps directory (application code) you must include an acknowledgement:
 *	  "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
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
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/rc4.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/cryptlib.h>
#include "test-crypto-common.h"
#include <openssl/crypto_ipsec_api.h>
#include <test-ipsec-api.h>

#ifdef TEST_CPU_CYCLES
	extern uint32_t numcores;
	extern CVMX_SHARED uint64_t total_cpucycles;
	extern CVMX_SHARED uint64_t total_mbps;		
#endif 

int test_ipsec_aes_cbc (uint8_t *hash_key, 
						uint32_t hash_keylen,
						AesCbcEncFuncPtr ApiEncPtr,
						AesCbcDecFuncPtr ApiDecPtr,
						const char *api)
{
	uint16_t keylen;
	uint8_t pktbuff[MAX_OUT_PACKET_LENGTH];
	uint32_t pktlen;
	uint32_t cnt;
	int ret;
	int i = 0;
	uint8_t iv[16] = {0};
	uint8_t encbuff[MAX_OUT_PACKET_LENGTH]; 
	uint16_t outlen_enc = 0, outlen_dec = 0;
	uint8_t decbuff[MAX_OUT_PACKET_LENGTH];
//	uint8_t pkt_tmp[MAX_OUT_PACKET_LENGTH];
#ifdef TEST_CPU_CYCLES
    uint8_t apiname[100];
#else
    uint8_t pkt_tmp[MAX_OUT_PACKET_LENGTH];
#endif
	for (pktlen = START_PACKET_SIZE; pktlen <= MAX_BUFF_SIZE;
											  pktlen+=pktlen)  {

		if ((pktlen < 24) || (pktlen%16))  {
			printf ("Wrong Packet Length\n");
			return -1;
		}
		for (cnt = 0; cnt < pktlen; cnt++)  {
			pktbuff[cnt] = cnt;
		}   
		PRINT_HDR;
		memset (pktbuff, 0, sizeof(pktbuff));
	/* This loop tests 128, 192 and 256 bit keys */
		for (keylen = 16; keylen <= 32; keylen += 8)  {
			memcpy (iv, aes_iv, AES_CBC_IV_LEN);
			memset (encbuff, 0, sizeof(encbuff));
			memset (decbuff, 0, sizeof(decbuff));
	
			/* AES-CBC NonInplace */
	
			COPY_API(" Encrypt");
			START_CYCLE_AES_CBC;
			ret = ApiEncPtr (keylen, aes_key[i], hash_keylen,
							 hash_key, espheader, iv, pktbuff,
							 pktlen, encbuff, &outlen_enc);
			END_CYCLE_AES(apiname, keylen*8);
			CHECK_RETURN_VAL("AES-CBC Encrypt");
		
			memcpy (iv, aes_iv, AES_CBC_IV_LEN);
			COPY_API(" Decrypt");
			START_CYCLE_AES_CBC;
			ret = ApiDecPtr (keylen, aes_key[i], hash_keylen,
							 hash_key, iv, encbuff, outlen_enc,
							 decbuff, &outlen_dec, COMP_DIGEST);
			END_CYCLE_AES(apiname, keylen*8);
			CHECK_RETURN_VAL("AES-CBC Decrypt");
	
			if (memcmp((decbuff+ESP_HEADER_LEN+AES_CBC_IV_LEN), pktbuff, pktlen)) {
				printf ("AES-CBC NonInplace Failed\n");	
				ret = -1;
				goto End;
			}
			
#ifndef TEST_CPU_CYCLES
			/* AES-CBC Inplace */
			memset (decbuff, 0, sizeof (decbuff));
			memcpy (decbuff, pktbuff, pktlen);
			memcpy (iv, aes_iv, AES_CBC_IV_LEN);
			ret = ApiEncPtr (keylen, aes_key[i], hash_keylen,
							 hash_key, espheader, iv, decbuff, 
							 pktlen, NULL, &outlen_enc);
			CHECK_RETURN_VAL("AES-CBC Encrypt");
	
			memcpy (pkt_tmp, espheader, ESP_HEADER_LEN);  
			memcpy ((pkt_tmp+ESP_HEADER_LEN), aes_iv, AES_CBC_IV_LEN);
			memcpy ((pkt_tmp+ESP_HEADER_LEN+AES_CBC_IV_LEN), decbuff, 
					(pktlen+HMAC_LENGTH));  
			memcpy (iv, aes_iv, AES_CBC_IV_LEN);
			ret = ApiDecPtr (keylen, aes_key[i], hash_keylen,
							 hash_key, iv, pkt_tmp, 
							 (outlen_enc+ESP_HEADER_LEN+AES_CBC_IV_LEN),
							 NULL, &outlen_dec, COMP_DIGEST);
			CHECK_RETURN_VAL ("AES-CBC Decrypt");
	
			if (memcmp ((pkt_tmp+ESP_HEADER_LEN+AES_CBC_IV_LEN), pktbuff, pktlen)) {
				printf ("AES-CBC Inplace Failed\n");
				ret = -1;
				goto End;
			}
#endif
			i++;
		}
	}
	ret = 0;
	if (cvmx_is_init_core()) {
	printf ("Tested %-20s: Packet Size From %d to %d : %s\n",api,
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}


int test_ipsec_aes_ctr (uint8_t *hash_key, 
						uint32_t hash_keylen,
						AesCtrEncFuncPtr ApiEncPtr,
						AesCtrDecFuncPtr ApiDecPtr,
						const char *api)
{
	uint16_t keylen;
	uint8_t pktbuff[MAX_OUT_PACKET_LENGTH];
	uint32_t pktlen;
	uint32_t cnt;
	int ret;
	int i = 0;
	uint8_t iv[16] = {0};
	uint8_t encbuff[MAX_OUT_PACKET_LENGTH]; 
	uint16_t outlen_enc = 0, outlen_dec = 0;
	uint8_t decbuff[MAX_OUT_PACKET_LENGTH];
#ifdef TEST_CPU_CYCLES
	uint8_t apiname[100];
#else
	uint8_t pkt_tmp[MAX_OUT_PACKET_LENGTH];
#endif

	for (pktlen = START_PACKET_SIZE; pktlen <= MAX_BUFF_SIZE;
												  pktlen+=pktlen)  {
	
		if ((pktlen < 24) || (pktlen%16))  {
			printf ("Wrong Packet Length\n");
			return -1;
		}
		for (cnt = 0; cnt < pktlen; cnt++)  {
			pktbuff[cnt] = cnt;
		} 
		PRINT_HDR;
		memset (pktbuff, 0, sizeof(pktbuff));
		/* This loop tests 128, 192 and 256 bit keys */
		for (keylen = 16; keylen <= 32; keylen += 8)  {
			memcpy (iv, aesctr_iv, AES_CTR_IV_LEN);
			memset (encbuff, 0, sizeof(encbuff));
			memset (decbuff, 0, sizeof(decbuff));
			
			/* AES-CTR NonInplace */
			COPY_API(" Encrypt");
			START_CYCLE_AES_CTR;
			ret = ApiEncPtr ((uint64_t *)aesctr_key[i], keylen, nonce, 
							 hash_keylen, hash_key, espheader, iv, pktbuff, 
							 pktlen, encbuff, &outlen_enc);
			END_CYCLE_AES(apiname, keylen*8);
			CHECK_RETURN_VAL ("AES-CTR Encrypt");
	
			memcpy (iv, aesctr_iv, AES_CTR_IV_LEN);
			COPY_API(" Decrypt");
			START_CYCLE_AES_CTR;
			ret = ApiDecPtr ((uint64_t *)aesctr_key[i], keylen, nonce, 
							 hash_keylen, hash_key, iv, encbuff, outlen_enc,
							 decbuff, &outlen_dec, COMP_DIGEST);
			END_CYCLE_AES(apiname, keylen*8);
			CHECK_RETURN_VAL("AES-CTR Decrypt");
	
			if (memcmp((decbuff+ESP_HEADER_LEN+AES_CTR_IV_LEN), pktbuff, pktlen)) {
				printf ("AES-CTR NonInplace Failed\n");
				ret = -1;
				goto End;
			}
	
#ifndef TEST_CPU_CYCLES
			/* AES-CTR Inplace */
			memset (decbuff, 0, sizeof (decbuff));
			memcpy (decbuff, pktbuff, pktlen);
			memcpy (iv, aesctr_iv, AES_CTR_IV_LEN);
			ret = ApiEncPtr ((uint64_t *)aesctr_key[i], keylen, nonce, 
							 hash_keylen, hash_key, espheader, iv, decbuff, 
							 pktlen, NULL, &outlen_enc);
			CHECK_RETURN_VAL("AES-CTR Encrypt");
	
			memcpy (pkt_tmp, espheader, ESP_HEADER_LEN);
			memcpy ((pkt_tmp+ESP_HEADER_LEN), aesctr_iv, AES_CTR_IV_LEN);
			memcpy ((pkt_tmp+ESP_HEADER_LEN+AES_CTR_IV_LEN), decbuff, 
					 (pktlen + HMAC_LENGTH)); 
	
			ret = ApiDecPtr ((uint64_t *)aesctr_key[i], keylen, nonce,
							 hash_keylen, hash_key, iv, pkt_tmp, 
							 (outlen_enc+ESP_HEADER_LEN+AES_CTR_IV_LEN),
							 NULL, &outlen_dec, COMP_DIGEST);
			CHECK_RETURN_VAL("AES-CTR Decrypt");
	
			if (memcmp((pkt_tmp+ESP_HEADER_LEN+AES_CTR_IV_LEN), pktbuff, pktlen))  {
				printf ("AES-CTR Inplace Encrypt/Decrypt Failed\n");
				ret = -1;
				goto End;
			}
#endif
			i++;
		}
	}
	ret = 0;
	if (cvmx_is_init_core()) {
	printf ("Tested %-20s: Packet Size From %d to %d : %s\n",api,
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}


int test_ipsec_3des (uint8_t *hash_key, 
					 uint32_t hash_keylen,
					 DesEncFuncPtr ApiEncPtr,
					 DesDecFuncPtr ApiDecPtr,
					 const char *api)
{
	int ret;
	uint8_t pktbuff[MAX_OUT_PACKET_LENGTH];
	uint32_t pktlen;
	uint32_t cnt;
	uint8_t iv[16] = {0};
	uint8_t encbuff[MAX_OUT_PACKET_LENGTH]; 
	uint16_t outlen_enc = 0, outlen_dec = 0;
	uint8_t decbuff[MAX_OUT_PACKET_LENGTH] = {0};
#ifdef TEST_CPU_CYCLES
	uint8_t apiname[100];
#else
	uint8_t pkt_tmp[MAX_OUT_PACKET_LENGTH] = {0};
#endif

	for (pktlen = START_PACKET_SIZE; pktlen <= MAX_BUFF_SIZE;
												  pktlen+=pktlen)  {
		if ((pktlen < 24) || (pktlen%16))  {
			printf ("Wrong Packet Length\n");
			return -1;
		}
		for (cnt = 0; cnt < pktlen; cnt++)  {
			pktbuff[cnt] = cnt;
		} 
		PRINT_HDR;
		memset (pktbuff, 0, sizeof(pktbuff));
		memcpy (iv, des_iv, DES_IV_LEN);
		/* DES-CBC NonInplace */
		COPY_API(" Encrypt");
		START_CYCLE_3DES;
		ret = ApiEncPtr (des_key, hash_keylen, hash_key, espheader, iv, 
						 pktbuff, pktlen, encbuff, &outlen_enc);
		END_CYCLE(apiname);
		CHECK_RETURN_VAL("DES-CBC Encrypt");
	
		memcpy (iv, des_iv, DES_IV_LEN);
		COPY_API(" Decrypt");
		START_CYCLE_3DES;
		ret = ApiDecPtr (des_key, hash_keylen, hash_key, iv, encbuff, outlen_enc,
						 decbuff, &outlen_dec, COMP_DIGEST);
		END_CYCLE(apiname);
		CHECK_RETURN_VAL("DES-CBC Decrypt");
	
		if (memcmp (decbuff+ESP_HEADER_LEN+DES_IV_LEN, pktbuff, pktlen))  {
			printf ("DES-CBC NonInplace Failed\n");	
			ret = -1;
			goto End;
		}
	
	#ifndef TEST_CPU_CYCLES
		/* DES-CBC Inplace */
		memset (decbuff, 0, sizeof (decbuff));
		memcpy (decbuff, pktbuff, pktlen);
		memcpy (iv, des_iv, DES_IV_LEN);
	
		ret = ApiEncPtr (des_key, hash_keylen, hash_key, espheader, iv, 
						 decbuff, pktlen, NULL, &outlen_enc);
		CHECK_RETURN_VAL("DES-CBC Encrypt");
	
		memcpy (pkt_tmp, espheader, ESP_HEADER_LEN);  
		memcpy ((pkt_tmp+ESP_HEADER_LEN), des_iv, DES_IV_LEN);
		memcpy ((pkt_tmp+ESP_HEADER_LEN+DES_IV_LEN), decbuff, (pktlen+HMAC_LENGTH));
		memcpy (iv, des_iv, DES_IV_LEN);
	
		ret = ApiDecPtr (des_key, hash_keylen, hash_key, iv, pkt_tmp, 
						 (outlen_enc+ESP_HEADER_LEN+DES_IV_LEN),
						 NULL, &outlen_dec, COMP_DIGEST);
		CHECK_RETURN_VAL("DES-CBC Decrypt");
	
		if (memcmp ((pkt_tmp+ESP_HEADER_LEN+DES_IV_LEN), pktbuff, pktlen))  {
			printf ("DES-CBC Inplace Failed\n");
			ret = -1;
			goto End;
		}
	#endif
	}
	ret = 0;
	if (cvmx_is_init_core()) {
	printf ("Tested %-20s: Packet Size From %d to %d : %s\n",api,
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}


int test_ipsec_NullEnc (uint8_t *hash_key,
						uint32_t hash_keylen,
						EncNULLFuncPtr ApiEncPtr,
						DecNULLFuncPtr ApiDecPtr,
						const char *api)
{
	int ret;
	uint8_t pktbuff[MAX_OUT_PACKET_LENGTH];
	uint32_t pktlen;
	uint32_t cnt;
	uint8_t encbuff[MAX_OUT_PACKET_LENGTH]; 
	uint16_t outlen_enc = 0, outlen_dec = 0;
	uint8_t decbuff[MAX_OUT_PACKET_LENGTH] = {0};
#ifdef TEST_CPU_CYCLES
	uint8_t apiname[100];
#else
	uint8_t pkt_tmp[MAX_OUT_PACKET_LENGTH] = {0};
#endif
	for (pktlen = START_PACKET_SIZE; pktlen <= MAX_BUFF_SIZE;
												  pktlen+=pktlen)  {
		if ((pktlen < 24) || (pktlen%16))  {
			printf ("Wrong Packet Length\n");
			return -1;
		}
		PRINT_HDR;
		for (cnt = 0; cnt < pktlen; cnt++)  {
			pktbuff[cnt] = cnt;
		} 
		memset (pktbuff, 0, sizeof(pktbuff));
		/* NULL NonInplace */
		COPY_API(" Encrypt");
		START_CYCLE
		ret = ApiEncPtr (hash_keylen, hash_key, espheader, pktbuff, 
						 pktlen, encbuff, &outlen_enc);
		END_CYCLE(apiname);
		CHECK_RETURN_VAL("NULL Encryption");
	
		COPY_API(" Decrypt");
		START_CYCLE;
		ret = ApiDecPtr (hash_keylen, hash_key, encbuff, outlen_enc, 
						 decbuff, &outlen_dec, COMP_DIGEST);
		END_CYCLE(apiname);
		CHECK_RETURN_VAL("NULL Decryption");
	
		if (memcmp (pktbuff, (decbuff+ESP_HEADER_LEN), pktlen))  {
			printf ("NULL Encrypt/Decrypt NonInplace Failed\n");
			ret = -1;
			goto End;
		}
	
#ifndef TEST_CPU_CYCLES
		/* NULL Inplace */
		memset (decbuff, 0, sizeof (decbuff));
		memcpy (decbuff, pktbuff, pktlen);
		ret = ApiEncPtr (hash_keylen, hash_key, espheader, decbuff, 
						   pktlen, NULL, &outlen_enc);
		CHECK_RETURN_VAL("NULL Encryption");
		memcpy (pkt_tmp, espheader, ESP_HEADER_LEN);
		memcpy (pkt_tmp+ESP_HEADER_LEN, decbuff, (pktlen+HMAC_LENGTH));
	
		ret = ApiDecPtr (hash_keylen, hash_key, pkt_tmp, 
						 (outlen_enc+ESP_HEADER_LEN), NULL, &outlen_dec, 
						 COMP_DIGEST);
		CHECK_RETURN_VAL("NULL Decryption");
	
		if (memcmp (pktbuff, (pkt_tmp+ESP_HEADER_LEN), pktlen))  {
			printf ("NULL Encrypt/Decrypt Inplace Failed\n");
			ret = -1;
			goto End;
		}
#endif
	}
	ret = 0;
	if (cvmx_is_init_core()) {
	printf ("Tested %-20s: Packet Size From %d to %d : %s\n",api,
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End :
	return ret;
}


int test_ipsec_AH (uint8_t *hash_key,
				   uint32_t hash_keylen,
				   OutbAHFuncPtr OutBPtr,
				   InbAHFuncPtr InBPtr,
				   const char *api,
				   uint8_t icvlen)
{
	uint8_t encbuff[MAX_OUT_PACKET_LENGTH] = {0};
	uint8_t pktbuff[MAX_OUT_PACKET_LENGTH];
	uint32_t pktlen;
	uint32_t cnt;
	uint8_t decbuff[MAX_OUT_PACKET_LENGTH] = {0};
	uint16_t outlen_enc = 0, outlen_dec = 0;
	int ret;
#ifdef TEST_CPU_CYCLES
	uint8_t apiname[100];
#endif
	for (pktlen = START_PACKET_SIZE; pktlen <= MAX_BUFF_SIZE;
												  pktlen+=pktlen)  {
		if ((pktlen < 24) || (pktlen%16))  {
			printf ("Wrong Packet Length\n");
			return -1;
		}
		for (cnt = 0; cnt < pktlen; cnt++)  {
			pktbuff[cnt] = cnt;
		} 
		PRINT_HDR;
		memset (pktbuff, 0, sizeof(pktbuff));
		/* AH NonInplace */
		COPY_API(" Outbound");
		START_CYCLE;
		ret =  OutBPtr (hash_keylen, hash_key, ah_header, pktbuff, pktlen,
						encbuff, &outlen_enc);
		END_CYCLE(apiname);
		CHECK_RETURN_VAL("AH IPSec Outbound");
	
		COPY_API(" Inbound");
		START_CYCLE;
		ret = InBPtr (hash_keylen, hash_key, encbuff, outlen_enc, decbuff, 
					  &outlen_dec, COMP_DIGEST);
		END_CYCLE(apiname);
	
		if (memcmp (pktbuff, decbuff, IP_HEADER_LEN) || 
			memcmp ((pktbuff+IP_HEADER_LEN), (decbuff+IP_HEADER_LEN), 
					 (pktlen-IP_HEADER_LEN)))  {
			printf ("AH Outbound/Inbound NonInplace IPSec Failed\n");
			ret = -1;
			return ret;
		}
	
	#ifndef TEST_CPU_CYCLES
		/* AH Inplace */
		memset (decbuff, 0, sizeof (decbuff));
		memcpy (decbuff, pktbuff, pktlen);
		ret = OutBPtr (hash_keylen, hash_key, ah_header, decbuff, pktlen, 
					   NULL, &outlen_enc);
		CHECK_RETURN_VAL("AH IPSec Outbound");
	
		ret = InBPtr (hash_keylen, hash_key, decbuff, outlen_enc, NULL, 
					  &outlen_dec, COMP_DIGEST);
		CHECK_RETURN_VAL("AH IPSec Inbound");
	
		if (memcmp (pktbuff, decbuff, IP_HEADER_LEN) || 
			memcmp ((pktbuff+IP_HEADER_LEN), (decbuff+IP_HEADER_LEN), 
					 (pktlen-IP_HEADER_LEN)))  {
			printf ("AH Outbound/Inbound NonInplace IPSec Failed\n");
			ret = -1;
			return ret;
		}
	#endif
	}
	ret = 0;
	if (cvmx_is_init_core()) {
	printf ("Tested %-20s: Packet Size From %d to %d : %s\n",api,
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}

