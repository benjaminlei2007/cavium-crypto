
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
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/cryptlib.h>
#include <openssl/crypto_ipsec_api.h>
#include "test-crypto-common.h"
#include "test-crypto-api.h"
#include "ec/ec_lcl.h"

uint8_t pktbuff[MAX_OUT_PACKET_LENGTH];
uint8_t hash_key[MAX_OUT_PACKET_LENGTH];
uint8_t inbuff[MAX_BUFF_SIZE];
uint32_t hash_keylen = HASH_KEY_LEN;
unsigned int prev_inlen = 0;
uint32_t pktlen = 0;
uint32_t cnt;
uint32_t i;
int ret;

#ifdef TEST_CPU_CYCLES
	uint32_t numcores;	
	CVMX_SHARED uint64_t total_cpucycles;
	CVMX_SHARED uint64_t total_mbps;		
	CVMX_SHARED uint64_t total_tps;		
#endif 

void show_help()
{
	if(cvmx_is_init_core()) 
	{ 
		printf("\n\n To test golden test vectors for all ciphers.\n");
		printf("\tIn SEUM: # ./test-crypto-api-seum \n");
		printf("\tIn SE: # bootoct 0 numcores=<number_of_cores> endbootargs test-crypto-api \n\t\tor \n");
		printf("\tIn SEUM: # ./test-crypto-api-seum -kat\n");
		printf("\tIn SE: # bootoct 0 numcores=<number_of_cores> endbootargs test-crypto-api -kat\n");
		printf(" To test buffer walkthrough for all ciphers.\n");
		printf("\tIn SEUM: # ./test-crypto-api-seum -buffer-walk\n");
		printf("\tIn SE: # bootoct 0 numcores=<number_of_cores> endbootargs test-crypto-api -buffer-walk\n\n\n");
		printf(" To test golden test vectors for group of ciphers\n");
		printf("\tIn SEUM: # ./test-crypto-api-seum <group-name>\n");
		printf("\tIn SE: # bootoct 0 numcores=<number_of_cores> endbootargs test-crypto-api <group-name> \n\t\tor \n");
		printf("\tIn SEUM: # ./test-crypto-api-seum <group-name> -kat\n");
		printf("\tIn SE: # bootoct 0 numcores=<number_of_cores> endbootargs test-crypto-api <group-name> -kat\n");
		printf(" To test buffer walkthrough for group of ciphers\n");
		printf("\tIn SEUM: # ./test-crypto-api <group-name> -buffer-walk\n");
		printf("\tIn SE: # bootoct 0 numcores=<number_of_cores> endbootargs test-crypto-api <group-name> -buffer-walk\n");
		printf(BOLD_PRINT"\n The following are <group-name> for crypto api's \n ");
		printf("\tasymmetric \t\tTo test all asymmetric api\n");
		printf("\tsymmetric \t\tTo test all symmetric api\n");
		printf("\thash \t\t\tTo test all hash api\n");
		printf("\tipsec \t\t\tTo test all ipsec api\n");
		printf("\ttkip \t\t\tTo test all tkip api\n");
		printf("\tf8-f9 \t\t\tTo test all F8-F9 api\n");
		printf("\tdhgroup \t\tTo test dhgroup api (dhgroup19 dhgroup20 dhgroup24)\n");
		printf("\tdrbg \t\t\tTo test drbg api\n");
		printf("\tfecc \t\t\tTo test all ECC api (ECDSA,ECDH, ECEG and EC-POINT)\n\n"NORMAL_PRINT);
		printf(" To test golden test vectors for a particular cipher\n");
		printf("\tIn SEUM: # ./test-crypto-api-seum <cipher-name>\n");
		printf("\tIn SE: # bootoct 0 numcores=<number_of_cores> endbootargs test-crypto-api <cipher-name>\n\t\tor \n");
		printf("\tIn SEUM: # ./test-crypto-api-seum <cipher-name> -kat\n");
		printf("\tIn SE: # bootoct 0 numcores=<number_of_cores> endbootargs test-crypto-api <cipher-name> -kat\n");
		printf(" To test buffer walkthrough for a particular cipher\n");
		printf("\tIn SEUM: # ./test-crypto-api-seum <cipher-name> -buffer-walk\n");
		printf("\tIn SE: # bootoct 0 numcores=<number_of_cores> endbootargs test-crypto-api <cipher-name> -buffer-walk\n\n");
		printf(" For list of individual ciphers execute\n");
		printf("\tIn SEUM: # ./test-crypto-api-seum -cipher-list \n");
		printf("\tIn SE: # bootoct 0 numcores=<number_of_cores> endbootargs test-crypto-api -cipher-list\n");
	}
}

void cipher_list () {	
	if(cvmx_is_init_core()) { 
		printf("\n\n To test golden test vectors for a particular cipher\n");
		printf("\tIn SEUM: # ./test-crypto-api-seum <cipher-name>\n");
		printf("\tIn SE: # bootoct 0 numcores=<number_of_cores> endbootargs test-crypto-api <cipher-name>\n\t\tor\n");
		printf("\tIn SEUM: # ./test-crypto-api-seum <cipher-name> -kat\n");
		printf("\tIn SE: # bootoct 0 numcores=<number_of_cores> endbootargs test-crypto-api <cipher-name> -kat\n");
		printf(" To test buffer walkthrough for a particular cipher\n");
		printf("\tIn SEUM: # ./test-crypto-api-seum <cipher-name> -buffer-walk\n");
		printf("\tIn SE: # bootoct 0 numcores=<number_of_cores> endbootargs test-crypto-api <cipher-name> -buffer-walk\n");
		printf(BOLD_PRINT"\n\n The following are <cipher-name> for crypto api's\n ");
		printf("\tmd5 \t\t\tTo test md5 hash api\n");
		printf("\tsha1 \t\t\tTo test sha1 hash api\n");
		printf("\tsha224 \t\t\tTo test sha224 hash api\n");
		printf("\tsha256 \t\t\tTo test sha256 hash api\n");
		printf("\tsha384 \t\t\tTo test sha384 hash api\n");
		printf("\tsha512 \t\t\tTo test sha512 hash api\n");	
		printf("\tsha3_224 \t\t\tTo test sha3_224 hash api\n");
		printf("\tsha3_256 \t\t\tTo test sha3_256 hash api\n");
		printf("\tsha3_384 \t\t\tTo test sha3_384 hash api\n");
		printf("\tsha3_512 \t\t\tTo test sha3_512 hash api\n");
		printf("\thmac \t\t\tTo test hamc hash api\n");
		printf("\taes-xcbc-mac \t\tTo test aes-xcbc-mac api\n ");
		printf("\taes-xcbc-prf128 \tTo test aes-xcbc-prf128 api\n");
		printf("\taes-gmac \t\tTo test aes gmac hash api\n");
		printf("\taes-cmac \t\tTo test aes-cmac ash api\n");
		printf("\tdes-ncbc \t\tTo test all symmetric des-ncbc api\n");
		printf("\t3des-cbc \t\tTo test all symmetric 3des cbc api\n");
		printf("\t3des-ecb \t\tTo test all symmetric 3des ecb api\n");
		printf("\taes-cbc \t\tTo test all symmetric aes cbc api\n");
		printf("\taes-ecb \t\tTo test all symmetric aes ecb api\n");
		printf("\taes-ctr \t\tTo test all symmetric aes ctr api\n");
		printf("\taes-icm \t\tTo test all symmetric aes icm api\n");
		printf("\taes-gcm \t\tTo test all symmetric aes gcm api\n");
		printf("\taes-xts \t\tTo test all symmetric aes xts api\n");
		printf("\taes-xcb \t\tTo test all symmetric aes xcb api\n");
		printf("\taes-ccm \t\tTo test all symmetric aes ccm api\n");	
		printf("\tmode-xts \t\tTo test all symmetric mode xts api\n");	
		printf("\tmode-cts \t\tTo test all symmetric mode cts api\n");	
		printf("\tmode-cfb \t\tTo test all symmetric mode cfb api\n");
		printf("\tmode-cbc \t\tTo test all symmetric mode cbc api\n");
		printf("\tmode-gcm \t\tTo test all symmetric mode gcm api\n");
		printf("\tmode-ccm \t\tTo test all symmetric mode ccm api\n");
		printf("\taes-ccm-rfc \t\tTo test all symmetric aes ccm api with rfc test vectors\n");
		printf("\taes-xcbc \t\tTo test all symmetric aes xcbc api \n ");
		printf("\taes-lrw \t\tTo test all symmetric aes lrw api\n");
		printf("\trc4 \t\t\tTo test all symmetric rc4 api\n");
		printf("\trsa \t\t\tTo test all rsa api\n");
		printf("\tdsa \t\t\tTo test all dsa api \n");
		printf("\tdh \t\t\tTo test dh api \n");
		printf("\tpoint-add \t\tTo test point addition api \n");
		printf("\tpoint-mul \t\tTo test point multiply api \n");
		printf("\tpoint-dbl \t\tTo test point double api \n");
		printf("\tipsec-aes-cbc \t\tTo test all ipsec aes-cbc api\n");
		printf("\tipsec-aes-ctr \t\tTo test all ipsec aes ctr api\n");
		printf("\tipsec-3des \t\tTo test all ipsec 3des api\n");
		printf("\tipsec-ah \t\tTo test all ipseci AH api(md5,sha1,sha224,sha256,sha384,sha512 and hmac)\n");
		printf("\tipsec-nullenc \t\tTo test all ipsec null encryption\n");
		printf("\tmichael \t\tTo test michael test\n");
		printf("\tmixing \t\t\tTo test mixing test case\n");
		printf("\ttkip \t\t\tTo test tkip\n");
		printf("\tecdsa \t\t\tTo test ecdsa api \n");
		printf("\tecdh \t\t\tTo test ecdh api \n");
		printf("\teceg \t\t\tTo test eceg api \n");
		printf("\tcamellia-cbc \t\tTo test camellia cbc api \n");
		printf("\tcamellia-ecb \t\tTo test camellia ecb api\n");
		printf("\tcamellia-ctr \t\tTo test camellia ctr api\n");
		printf("\tzuc-encrypt \t\tTo test zuc encrypt api\n");
		printf("\tzuc-mac \t\tTo test zuc mac api\n"NORMAL_PRINT);
	}
}

int check_list() {
	#ifdef OCTEON_OPENSSL_NO_DYNAMIC_MEMORY 
		if (cvmx_user_app_init() < 0) { 
			printf ("User Application Initialization Failed\n"); 
			return -1; 
		} 
	#endif
	
	#if (OCTEON_SDK_VERSION_NUMBER > 106000217ull) 
		if (cvm_crypto_model_check()) { 
			printf("This model is Not supported \n"); 
			return -1; 
		} 
	#endif
		return 0;
}
int test_dhgroup () {	
	if (cvmx_is_init_core())	
		printf ("*** DHGROUP Buffer Walk Through not available ***\n");
	return -2;
}

int test_dhgroup_kat (const char *api) {
	PRT_HDR ("DHGROUPS");
	ret = dhgroup19_kat ();
	CHECK_RESULT ("DHGROUP19");
	
	ret = dhgroup20_kat ();
	CHECK_RESULT ("DHGROUP20");
		
	ret = dhgroup24_kat ();
	CHECK_RESULT ("DHGROUP24");
	return 0;
}
void test_all () {
	
	int ret;
			
	PRT_HDR ("IPSEC");
	ret = test_ipsec_kat (); 
	CHECK_RET ("IPSEC");

	PRT_HDR ("HASH");
	ret = hash_kat ();	
	CHECK_RET ("HASH");

	PRT_HDR ("SYMMETRIC");
	ret = symmetric_kat ();
	CHECK_RET ("SYMMETRIC");

	PRT_HDR ("ASYMMETRIC");
	ret = asymmetric_kat ();
	CHECK_RET ("ASYMMETRIC");

	PRT_HDR ("DHGROUPS");
	ret = dhgroup19_kat (); CHECK_RESULT ("DHGROUP19");
	ret = dhgroup20_kat (); CHECK_RESULT ("DHGROUP20");	
	ret = dhgroup24_kat (); CHECK_RESULT ("DHGROUP24");
	CHECK_RET ("DHGROUPS");

	PRT_HDR ("DRBG");
	ret = test_drbg_kat ();
	CHECK_RET ("DRBG");

	PRT_HDR ("AES-F8F9");
	ret = test_aes_f8f9_kat ();
	CHECK_RET ("AES-F8F9");

	PRT_HDR ("SNOW3G");
	ret = test_snow3g_kat ();
	CHECK_RET ("SNOW3G");

	PRT_HDR ("KASUMI");
	ret = test_kasumi_kat ();
	CHECK_RET ("KASUMI");

	PRT_HDR ("TKIP");
	ret = test_tkip_kat ();
	CHECK_RET ("TKIP");

	PRT_HDR ("ECDSA");
	ret = test_ecdsa_kat ();
	CHECK_RET ("ECDSA");

	PRT_HDR ("ECDH");
	ret = test_ecdh_kat ();
	CHECK_RET ("ECDH");

	PRT_HDR ("ECEG");
	ret = test_eceg_kat ();
	CHECK_RET ("ECEG");		
}

void test_all_buffer () {
		
	int ret;
    
	cvmx_cav_fecc();

	PRT_HDR ("IPSEC");
	ret =ipsec ();
	CHECK_RET ("IPSec");

	PRT_HDR ("HASH");
	ret = hash ();
	CHECK_RET ("HASH");

	PRT_HDR ("SYMMETRIC");
	ret = symmetric ();
	CHECK_RET ("SYMMETRIC");

	PRT_HDR ("ASYMMETRIC");
	ret = asymmetric ();
	CHECK_RET ("ASYMMETRIC");

	PRT_HDR ("DRBG");
	ret = drbg ();
	CHECK_RET ("DRBG");

	PRT_HDR ("DHGROUP");
	ret = test_dhgroup ();
	CHECK_RET ("DHGROUP");
	
	PRT_HDR ("AES-F8F9");
	ret = aes_f8f9 ();
	CHECK_RET ("AES-F8F9");

	PRT_HDR ("SNOW3G");
	ret = snow3g ();
	CHECK_RET ("SNOW3G");

	PRT_HDR ("KASUMI");
	ret = kasumi ();
	CHECK_RET ("KASUMI");

	PRT_HDR ("TKIP");
	ret = test_tkip_buff ();
	CHECK_RET ("TKIP");

	PRT_HDR ("ECDSA");
	ret = test_ecdsa ();
	CHECK_RET ("ECDSA");

	PRT_HDR ("ECDH");
	ret = test_ecdh ();
	CHECK_RET ("ECDH");

	PRT_HDR ("ECEG");
	ret = test_eceg ();
	CHECK_RET ("ECEG");
}


int test_ipsec_kat () {
	if (cvmx_is_init_core())	
		printf ("*** IPSec known answer test not available ***\n");
	return -2;
}

int test_tkip_buff () {	
	if (cvmx_is_init_core())	
		printf ("*** TKIP Buffer walk through not available ***\n");
	return -2;
	
}

int test_ipsec (const char *api) {
	if (memcmp (api,"ipsec",sizeof("ipsec"))==0) { 
		PRT_HDR ("IPSEC");
		ret=ipsec ();
		CHECK_RET("IPSEC");
	
	}
	else if (memcmp (api,"ipsec-aes-cbc",sizeof ("ipsec-aes-cbc"))==0) {
		PRT_HDR ("IPSEC-AES-CBC");
		ret=ipsec_aes_cbc ();
		CHECK_RET("IPSEC-AES-CBC");
	
	}
	else if (memcmp (api,"ipsec-aes-ctr",sizeof ("ipsec-aes-ctr"))==0) {
		PRT_HDR ("IPSEC-AES-CTR");
		ret=ipsec_aes_ctr ();
		CHECK_RET("IPSEC-AES-CTR");
	
	}
	else if (memcmp (api,"ipsec-3des",sizeof ("ipsec-3des"))==0) {
		PRT_HDR ("IPSEC-3DES");
		ret=ipsec_3des ();
		CHECK_RET("IPSEC-3DES");
	
	}
	else if (memcmp (api,"ipsec-ah",sizeof ("ipsec-ah"))==0) {
		PRT_HDR ("IPSEC-AH");
		ret=ipsec_ah ();
		CHECK_RET("IPSEC-AH");
	
	}
	else if (memcmp (api,"ipsec-nullenc",sizeof ("ipsec-nullenc"))==0) {
		PRT_HDR ("IPSEC-NULL ENC");
		ret=ipsec_nullenc ();
		CHECK_RET("IPSEC-NULLENC");
	
	}
	return 0;
}

int test_all_tkip (const char *api) {

	if (memcmp (api,"tkip",sizeof("tkip"))==0) {
	PRT_HDR ("TKIP");
	ret=test_tkip_kat ();
	CHECK_RET("TKIP");
	}
	
	else if (memcmp (api,"michael",sizeof ("michael"))==0) {
	PRT_HDR ("MICHAEL");
	ret=test_tkip_michael ();
//	printf ("Result of MICHAEL : %s\n",  (ret==0)?"Passed":"Failed");
	CHECK_RET("MICHAEL");
	
	}
	else if (memcmp (api,"mixing",sizeof ("mixing"))==0) {
	PRT_HDR ("MIXING");
	ret=test_tkip_mixing ();
//	printf ("Result of MIXING : %s\n",  (ret==0)?"Passed":"Failed");
	CHECK_RET("MIXING");
	
	}

	return 0;
}

int test_symmetric_api (const char *api) {	
	cvmx_rng_enable ();

	if (memcmp (api,"des-ncbc",sizeof ("des-ncbc"))==0) {
		PRT_HDR ("DES-NCBC");
		ret=test_des_ncbc ();
		CHECK_RET("DES-NCBC");
	
	}
	else if (memcmp (api,"3des-cbc",sizeof ("3des-cbc"))==0) {
		PRT_HDR ("3DES-CBC");
		ret=test_3des_cbc ();
		CHECK_RET("3DES-CBC");
	
	}
	else if (memcmp (api,"3des-ecb",sizeof ("3des-ecb"))==0) {
		PRT_HDR ("3DES-ECB");
		ret=test_3des_ecb ();
		CHECK_RET("3DES-ECB");
	
	}
	else if (memcmp (api,"aes-cbc",sizeof ("aes-cbc"))==0) {
		PRT_HDR ("AES-CBC");
		ret=test_aes_cbc ();
		CHECK_RET("AES-CBC");
	
	}	
	else if (memcmp (api,"aes-ecb",sizeof ("aes-ecb"))==0) {
		PRT_HDR ("AES-ECB");
		ret=test_aes_ecb ();
		CHECK_RET("AES-ECB");
	
	}
	else if (memcmp (api,"aes-ctr",sizeof ("aes-ctr"))==0) {
		PRT_HDR ("AES-CTR");
		ret=test_aes_ctr ();
		CHECK_RET("AES-CTR");
	
	}
	else if (memcmp (api,"aes-icm",sizeof ("aes-icm"))==0) {
		PRT_HDR ("AES-ICM");
		ret=test_aes_icm ();
		CHECK_RET("AES-ICM");
	
	}
	else if (memcmp (api,"aes-lrw",sizeof ("aes-lrw"))==0) {
		PRT_HDR ("AES-LRW");
		ret=test_aes_lrw ();
		CHECK_RET("AES-LRW");
	
	}
	else if (memcmp (api,"aes-gcm",sizeof ("aes-gcm"))==0) {
		PRT_HDR ("AES-GCM");
		ret=test_aes_gcm ();
		CHECK_RET("AES-GCM");
	
	}
	else if (memcmp (api,"aes-xts",sizeof ("aes-xts"))==0) {
		PRT_HDR ("AES-XTS");
		ret=test_aes_xts ();
		CHECK_RET("AES-XTS");
	
	}
	else if (memcmp (api,"aes-xcb",sizeof ("aes-xcb"))==0) {
		PRT_HDR ("AES-XCB");
		ret=test_aes_xcb ();
		CHECK_RET("AES-XCB");

	}
	else if (memcmp (api,"rc4",sizeof ("rc4"))==0) {
		PRT_HDR ("RC4");
		ret=test_rc4 ();
		CHECK_RET("RC4");
	}
	else if (memcmp (api,"aes-ccm",sizeof ("aes-ccm"))==0) {
		PRT_HDR ("AES-CCM");
		ret=test_aes_ccm ();
		CHECK_RET("AES-CCM");
	}
	else if (memcmp (api,"symmetric",sizeof ("symmetric"))==0) {
		PRT_HDR ("SYMMETRIC");
		ret=symmetric ();
		CHECK_RET("SYMMETRIC");
	}
	 else if (memcmp (api,"mode-xts",sizeof ("mode-xts"))==0) {
        PRT_HDR ("MODE-XTS");
        ret=test_mode_xts ();
        CHECK_RET("MODE-XTS");
    }
    else if (memcmp (api,"mode-cts",sizeof ("mode-cts"))==0) {
        PRT_HDR ("MODE-CTS");
        ret=test_mode_cts ();
        CHECK_RET("MODE-CTS");
    }
    else if (memcmp (api,"mode-cfb",sizeof ("mode-cfb"))==0) {
        PRT_HDR ("MODE-CFB");
        ret=test_mode_cfb ();
        CHECK_RET("MODE-CFB");
    }
    else if (memcmp (api,"mode-cbc",sizeof ("mode-cbc"))==0) {
        PRT_HDR ("MODE-CBC");
        ret=test_mode_cbc ();
        CHECK_RET("MODE-CBC");
    }
    else if (memcmp (api,"mode-gcm",sizeof ("mode-gcm"))==0) {
        PRT_HDR ("MODE-GCM");
        ret=test_mode_gcm ();
        CHECK_RET("MODE-GCM");
    }
    else if (memcmp (api,"mode-ccm",sizeof ("mode-ccm"))==0) {
        PRT_HDR ("MODE-CCM");
        ret=test_mode_ccm ();
        CHECK_RET("MODE-CCM");
    }
	return 0;
}

int test_hash_kat (const char * api) {
	if (memcmp (api,"hash",sizeof ("hash"))==0) {
		PRT_HDR ("HASH");
		ret = hash_kat();
		CHECK_RET("HASH");	
	}
	else if (memcmp (api,"md5",sizeof ("md5"))==0) {
		PRT_HDR ("MD5");
		ret = test_md5_kat ();
		CHECK_RET("MD5");
	}
	else if (memcmp (api,"sha1",sizeof ("sha1"))==0) {
		PRT_HDR ("SHA1");
		ret = test_sha1_kat ();
		CHECK_RET("SHA1");
	
	}
	else if (memcmp (api,"sha224",sizeof ("sha224"))==0) {
		PRT_HDR ("SHA224");
		ret = test_sha224_kat ();
		CHECK_RET("SHA224");
	
	}
	else if (memcmp (api,"sha256",sizeof ("sha256"))==0) {
		PRT_HDR ("SHA256");
		ret = test_sha256_kat ();
		CHECK_RET("SHA256");
	
	}
	else if (memcmp (api,"sha384",sizeof ("sha384"))==0) {
		PRT_HDR ("SHA384");
		ret = test_sha384_kat ();
		CHECK_RET("SHA384");
	
	}
	else if (memcmp (api,"sha512",sizeof ("sha512"))==0) { 
		PRT_HDR ("SHA512");
		ret = test_sha512_kat ();
		CHECK_RET("SHA512");
	
	}
	else if (memcmp (api,"hmac",sizeof ("hmac"))==0) {
		PRT_HDR ("HMAC");
		ret = test_hmac_kat ();	
		CHECK_RET("HMAC");
	}
	else if (memcmp (api,"aes-gmac",sizeof ("aes-gmac"))==0) {
		PRT_HDR ("AES-GMAC");
		ret = test_aes_gmac_kat ();
		CHECK_RET("AES-GMAC");
	
	}
	else if (memcmp (api,"aes-xcbc-mac",sizeof ("aes-xcbc-mac"))==0) {
		PRT_HDR ("AES-XCBC-MAC");
		ret = test_aes_xcbc_mac_kat ();
		CHECK_RET("AES-XCBC-MAC");

	}
	else if (memcmp (api,"aes-xcbc-prf128",sizeof ("aes-xcbc-prf128"))==0) {
		PRT_HDR ("AES-XCBC-PRF128");
		ret = test_aes_xcbc_prf128_kat ();
		CHECK_RET("AES-XCBC-PRF128");

	}
	else if (memcmp (api,"aes-cmac",sizeof ("aes-cmac"))==0) {
		PRT_HDR ("AES-CMAC");
		ret = test_aes_cmac_kat ();
		CHECK_RET("AES-CMAC");

	}
	
	return 0;

}

int test_hash (const char * api) {
	const EVP_MD *evp[] = {
		EVP_md5(),
		EVP_sha1(),
		EVP_sha224(),
		EVP_sha256(),
		EVP_sha384(),
		EVP_sha512()
	};
	char *evp_hash[] = {
		"EVP_MD5",
		"EVP_SHA1",
		"EVP_SHA224",
		"EVP_SHA256",
		"EVP_SHA384",
		"EVP_SHA512"
	};
	int i;   
	if (memcmp (api,"hash",sizeof ("hash"))==0) {
		PRT_HDR ("HASH");
		ret=hash();
		CHECK_RET("HASH");
	
	}
	else if (memcmp (api,"md5",sizeof ("md5"))==0) {
		PRT_HDR ("MD5");
		ret=test_md5 ();
		CHECK_RET("MD5");
	
	}
	else if (memcmp (api,"sha1",sizeof ("sha1"))==0) {
		PRT_HDR ("SHA1");
		ret=test_sha1 ();
		CHECK_RET("SHA1");
	
	}
	else if (memcmp (api,"sha224",sizeof ("sha224"))==0) {
		PRT_HDR ("SHA224");
		ret=test_sha224 ();
		CHECK_RET("SHA224");
	
	}
	else if (memcmp (api,"sha256",sizeof ("sha256"))==0) {
		PRT_HDR ("SHA256");
		ret=test_sha256 ();
		CHECK_RET("SHA256");
	
	}
	else if (memcmp (api,"sha384",sizeof ("sha384"))==0) {
		PRT_HDR ("SHA384");
		ret=test_sha384 ();
		CHECK_RET("SHA384");
	
	}
	else if (memcmp (api,"sha512",sizeof ("sha512"))==0) { 
		PRT_HDR ("SHA512");
		ret=test_sha512 ();
		CHECK_RET("SHA512");
	
	}
	else if (memcmp (api,"hmac",sizeof ("hmac"))==0) {
		PRT_HDR ("HMAC");
		for (i = 0; i < 6; i++)  {
			PRT_HDR (evp_hash[i]);
			#ifdef TEST_CPU_CYCLES
				if (cvmx_is_init_core()) 
					printf ("\n\n######### HMAC (%s) CPU CYCLES #########\n", evp_hash[i]);
			#endif
			ret = test_hmac (evp[i], evp_hash[i]);
			CHECK_RET(evp_hash[i]);
		}	
		CHECK_RET("HMAC");
	}
	else if (memcmp (api,"aes-gmac",sizeof ("aes-gmac"))==0) {
		PRT_HDR ("AES-GMAC");
		ret=test_aes_gmac ();
		CHECK_RET("AES-GMAC");
	
	}
	else if (memcmp (api,"aes-xcbc-mac",sizeof ("aes-xcbc-mac"))==0) {
		PRT_HDR ("AES-XCBC-MAC");
		ret=test_aes_xcbc_mac ();
		CHECK_RET("AES-XCBC-MAC");

	}
	else if (memcmp (api,"aes-xcbc-prf128",sizeof ("aes-xcbc-prf128"))==0) {
		PRT_HDR ("AES-XCBC-PRF128");
		ret=test_aes_xcbc_prf128 ();
		CHECK_RET("AES-XCBC-PRF128");

	}
	else if (memcmp (api,"aes-cmac",sizeof ("aes-cmac"))==0) {
		PRT_HDR ("AES-CMAC");
		ret=test_aes_cmac ();
		CHECK_RET("AES-CMAC");

	}
	else if (memcmp (api,"sha3_224",sizeof ("sha3_224"))==0) {
                PRT_HDR ("SHA3_224");
                ret=test_sha3_224 ();
                CHECK_RET("SHA3_224");
	}
	else if (memcmp (api,"sha3_256",sizeof ("sha3_256"))==0) {
                PRT_HDR ("SHA3_256");
                ret=test_sha3_256 ();
                CHECK_RET("SHA3_256");
	}
	else if (memcmp (api,"sha3_384",sizeof ("sha3_384"))==0) {
                PRT_HDR ("SHA3_384");
                ret=test_sha3_384 ();
                CHECK_RET("SHA3_384");
	}
	else if (memcmp (api,"sha3_512",sizeof ("sha3_512"))==0) {
                PRT_HDR ("SHA3_512");
                ret=test_sha3_512 ();
                CHECK_RET("SHA3_512");
	}

#ifdef SHA3_SHAKE
	else if (memcmp (api,"shake_128",sizeof ("shake_128"))==0) {
                PRT_HDR ("SHAKE_128");
                ret=test_shake_128_hash ();
                CHECK_RET("SHAKE_128");
	}
	else if (memcmp (api,"shake_256",sizeof ("shake_256"))==0) {
                PRT_HDR ("SHAKE_256");
                ret=test_shake_256_hash ();
                CHECK_RET("SHAKE_256");
	}
#endif
	
	return 0;

}
int test_asymmetric_kat (const char *api ) {
	if (memcmp (api,"asymmetric",sizeof ("asymmetric"))==0) {
		PRT_HDR ("ASYMMETRIC");
		ret=asymmetric_kat ();
		CHECK_RET("ASYMMETRIC");
	
	}
	else if (memcmp (api,"rsa", sizeof ("rsa"))==0) {
		PRT_HDR ("RSA");
		ret=test_rsa_kat ();
		CHECK_RET("RSA");
	
	}
	else if (memcmp (api,"dsa",sizeof ("dsa"))==0) {
		PRT_HDR ("DSA");
		ret=test_dsa_kat ();
		CHECK_RET("DSA");
	
	}
	else if (memcmp (api,"dh",sizeof ("dh"))==0) {
		PRT_HDR ("DH");
		ret=test_dh_kat ();
		CHECK_RET("DH");
	
	}
	return 0;
}



int test_asymmetric (const char *api ) {
	if (memcmp (api,"asymmetric",sizeof ("asymmetric"))==0) {
		PRT_HDR ("ASYMMETRIC");
		ret=asymmetric ();
		CHECK_RET("ASYMMETRIC");
	
	}
	else if (memcmp (api,"rsa", sizeof ("rsa"))==0) {
		PRT_HDR ("RSA");
		ret=test_rsa ();
		CHECK_RET("RSA");
	
	}
	else if (memcmp (api,"dsa",sizeof ("dsa"))==0) {
		PRT_HDR ("DSA");
		ret=test_dsa ();
		CHECK_RET("DSA");
	
	}
	else if (memcmp (api,"dh",sizeof ("dh"))==0) {
		PRT_HDR ("DH");
		ret=test_dh ();
		CHECK_RET("DH");
	
	}
	return 0;
}

int test_fECC_kat (const char *api) {
	if (memcmp (api,"fecc",sizeof ("fecc"))==0) {
		PRT_HDR ("FECC");
		PRT_HDR ("ECDH");
		ret = test_ecdh_kat ();
		CHECK_RET("ECDH");
	
		PRT_HDR ("ECDSA");
		ret=test_ecdsa_kat ();
		CHECK_RET("ECDSA");

		PRT_HDR ("ECEG");
		ret=test_eceg_kat ();
		CHECK_RET("ECEG");

		PRT_HDR ("EC-POINT");
		ret=test_ec_point_kat ();
		CHECK_RET("EC-POINT");
	}
	if (memcmp (api,"ecdh",sizeof ("ecdh"))==0) {
		PRT_HDR ("ECDH");
		ret=test_ecdh_kat ();
		CHECK_RET("ECDH");
	}
	else if (memcmp (api,"ecdsa", sizeof ("ecdsa"))==0) {
		PRT_HDR ("ECDSA");
		ret=test_ecdsa_kat ();
		CHECK_RET("ECDSA");
	}
	else if (memcmp (api,"eceg", sizeof ("eceg"))==0) {
		PRT_HDR ("ECEG");
		ret=test_eceg_kat ();
		CHECK_RET("ECEG");
	}
	else if (memcmp (api,"ec-point", sizeof ("ec-point"))==0) {
		PRT_HDR ("EC-POINT");
		ret=test_ec_point_kat ();
		CHECK_RET("EC-POINT");
	}
	else if (memcmp (api,"point-add", sizeof ("point-add"))==0) {
		PRT_HDR ("EC-POINT");
		ret=test_point_addition_kat ();
		CHECK_RET("EC-POINT");
	}
	else if (memcmp (api,"point-mul", sizeof ("point-mul"))==0) {
		PRT_HDR ("EC-POINT");
		ret=test_point_multiply_kat ();
		CHECK_RET("EC-POINT");
	}
	else if (memcmp (api,"point-dbl", sizeof ("point-dbl"))==0) {
		PRT_HDR ("EC-POINT");
		ret=test_point_double_kat ();
		CHECK_RET("EC-POINT");
	}
	return 0;
}



int test_fECC (const char *api) {
	
    cvmx_cav_fecc();
	
	if (memcmp (api,"fecc",sizeof ("fecc"))==0) {
		PRT_HDR ("FECC");
		ret = test_ecdh (); CHECK_RESULT ("ECDH");	
		ret = test_ecdsa (); CHECK_RESULT ("ECDSA");
		ret = test_eceg (); CHECK_RESULT ("ECEG");
		PRT_HDR ("EC-POINT");	
		if (cvmx_is_init_core()) {
			printf ("*** EC-POINT buffer walk through not available ***\n");
			printf ("########### End of EC-POINT Test ############\n");
		}
	}
	if (memcmp (api,"ecdh",sizeof ("ecdh"))==0) {
		PRT_HDR ("ECDH");
		ret=test_ecdh ();
		CHECK_RET("ECDH");
	}
	else if (memcmp (api,"ecdsa", sizeof ("ecdsa"))==0) {
		PRT_HDR ("ECDSA");
		ret=test_ecdsa ();
		CHECK_RET("ECDSA");
	}
	else if (memcmp (api,"eceg", sizeof ("eceg"))==0) {
		PRT_HDR ("ECEG");
		ret=test_eceg ();
		CHECK_RET("ECEG");
	}
	else if (memcmp (api,"ec-point", sizeof ("ec-point"))==0) {
		PRT_HDR ("EC-POINT");	
		if (cvmx_is_init_core()) {
			printf ("*** EC-POINT buffer walk through not available ***\n");
			printf ("########### End of EC-POINT Test ############\n");
		}
	}
	else if (memcmp (api,"point-add", sizeof ("point-add"))==0) {
		PRT_HDR ("EC-POINT");	
		if (cvmx_is_init_core()) {
			printf ("*** POINT ADDITION buffer walk through not available ***\n");
			printf ("########### End of POINT-ADD Test ############\n");
		}
	}
	else if (memcmp (api,"point-mul", sizeof ("point-mul"))==0) {
		PRT_HDR ("POINT-MUL");	
		if (cvmx_is_init_core()) {
			printf ("*** POINT MULTIPLY buffer walk through not available ***\n");
			printf ("########### End of POINT-MUL Test ############\n");
		}
	}
	else if (memcmp (api,"point-dbl", sizeof ("point-dbl"))==0) {
		PRT_HDR ("POINT-DBL");	
		if (cvmx_is_init_core()) {
			printf ("*** POINT DOUBLE buffer walk through not available ***\n");
			printf ("########### End of POINT-DBL Test ############\n");
		}
	}
	return 0;
}

int test_camellia_kat (const char *api) {
	if (memcmp (api,"camellia",sizeof ("camellia"))==0) {
		PRT_HDR ("CAMELLIA");
		ret=camellia_kat ();
		CHECK_RET("CAMELLIA");
	
	}
	else if (memcmp (api,"camellia-cbc", sizeof ("camellia-cbc"))==0) {
		PRT_HDR ("CAMELLIA-CBC");
		ret=test_camellia_cbc_kat ();
		CHECK_RET("CAMELLIA-CBC");
	
	}
	else if (memcmp (api,"camellia-ctr",sizeof ("camellia-ctr"))==0) {
		PRT_HDR ("CAMELLIA-CTR");
		ret=test_camellia_ctr_kat ();
		CHECK_RET("CAMELLIA-CTR");
	
	}
	else if (memcmp (api,"camellia-ecb", sizeof ("camellia-ecb"))==0){
		PRT_HDR ("CAMELLIA-ECB");
		ret=test_camellia_ecb_kat ();
		CHECK_RET("CAMELLIA-ECB");
	
	}
	return 0;
}


int test_camellia (const char *api) {
	if (memcmp (api,"camellia",sizeof ("camellia"))==0) {
		PRT_HDR ("CAMELLIA");
		ret=camellia ();
		CHECK_RET("CAMELLIA");
	
	}
	else if (memcmp (api,"camellia-cbc", sizeof ("camellia-cbc"))==0) {
		PRT_HDR ("CAMELLIA-CBC");
		ret=test_camellia_cbc ();
		CHECK_RET("CAMELLIA-CBC");
	
	}
	else if (memcmp (api,"camellia-ctr",sizeof ("camellia-ctr"))==0) {
		PRT_HDR ("CAMELLIA-CTR");
		ret=test_camellia_ctr ();
		CHECK_RET("CAMELLIA-CTR");
	
	}
	else if (memcmp (api,"camellia-ecb", sizeof ("camellia-ecb"))==0){
		PRT_HDR ("CAMELLIA-ECB");
		ret=test_camellia_ecb ();
		CHECK_RET("CAMELLIA-ECB");
	
	}
	return 0;
}

int test_zuc (const char *api) {
	if (memcmp (api,"zuc",sizeof ("zuc"))==0) {
		PRT_HDR ("ZUC");
		ret=test_zuc_api ();
		CHECK_RET("ZUC");
	
	}
	else if (memcmp (api,"zuc-mac", sizeof ("zuc-mac"))==0) {
		PRT_HDR ("ZUC-MAC");
		ret=test_zuc_mac ();
//printf ("Result of ZUC-MAC : %s\n", (ret==0)?"Passed":"Failed");
		CHECK_RET("ZUC-MAC");
	}
	else if (memcmp (api,"zuc-encrypt",sizeof ("zuc-encrypt"))==0) {
		PRT_HDR ("ZUC-ENCRYPT");
		ret=test_zuc_encrypt ();
//printf ("Result of ZUC-ENCRYPT : %s\n", (ret==0)?"Passed":"Failed");
		CHECK_RET("ZUC-ENCRYPT");
	}
	return 0;
}

int test_zuc_kat (const char *api) {
	if (memcmp (api,"zuc",sizeof ("zuc"))==0) {
		PRT_HDR ("ZUC");
		ret=test_zuc_api_kat ();
		CHECK_RET("ZUC");
	
	}
	else if (memcmp (api,"zuc-mac", sizeof ("zuc-mac"))==0) {
		PRT_HDR ("ZUC-MAC");
		ret=test_zuc_mac_kat ();
		CHECK_RET("ZUC-MAC");
	}
	else if (memcmp (api,"zuc-encrypt",sizeof ("zuc-encrypt"))==0) {
		PRT_HDR ("ZUC-ENCRYPT");
		ret=test_zuc_encrypt_kat ();
		CHECK_RET("ZUC-ENCRYPT");
	}
	return 0;
}

int hash_kat() {
	
	int ret; 	

	ret = test_md5_kat (); CHECK_RESULT ("MD5");
	ret = test_sha1_kat ();	CHECK_RESULT ("SHA1");	
	ret = test_sha224_kat (); CHECK_RESULT ("SHA224");
	ret = test_sha256_kat (); CHECK_RESULT ("SHA256");	
	ret = test_sha384_kat (); CHECK_RESULT ("SHA384");	
	ret = test_sha512_kat (); CHECK_RESULT ("SHA512");	
	ret = test_hmac_kat (); CHECK_RESULT ("HMAC");	
	ret = test_aes_xcbc_mac_kat (); CHECK_RESULT ("AES-XCBC-MAC");	
	ret = test_aes_xcbc_prf128_kat (); CHECK_RESULT ("AES-XCBC-PRF128");	
	ret = test_aes_gmac_kat (); CHECK_RESULT ("AES-GMAC");
	ret = test_zuc_mac_kat (); CHECK_RESULT ("ZUC-MAC");	
	ret = test_aes_cmac_kat (); CHECK_RESULT ("AES-CMAC");	
	return ret;
}



int hash()
{
	int ret;
	int i;
   const EVP_MD *evp[] = {
		EVP_md5(),
		EVP_sha1(),
		EVP_sha224(),
		EVP_sha256(),
		EVP_sha384(),
		EVP_sha512()
	};
	char *evp_hash[] = {
		"EVP_MD5",
		"EVP_SHA1",
		"EVP_SHA224",
		"EVP_SHA256",
		"EVP_SHA384",
		"EVP_SHA512"
	};
    

	ret = test_md5 ();CHECK_RESULT ("MD5");
	ret = test_sha1 ();CHECK_RESULT ("SHA1");
	ret = test_sha224 ();CHECK_RESULT ("SHA224");
	ret = test_sha256 ();CHECK_RESULT ("SHA256");
	ret = test_sha384 ();CHECK_RESULT ("SHA384");
	ret = test_sha512 ();CHECK_RESULT ("SHA512");
    ret = test_sha3_224 ();CHECK_RESULT ("SHA3_224");
    ret = test_sha3_256 ();CHECK_RESULT ("SHA3_256");
    ret = test_sha3_384 ();CHECK_RESULT ("SHA3_384");
    ret = test_sha3_512 ();CHECK_RESULT ("SHA3_512");
	
	for (i = 0; i < 6; i++)  {
		#ifdef TEST_CPU_CYCLES	
			if (cvmx_is_init_core())
				printf ("\n\n######### HMAC (%s) CPU CYCLES #########\n", evp_hash[i]);
		#endif
		ret=test_hmac (evp[i],evp_hash[i]);
		CHECK_RESULT (evp_hash[i]);
	}	
	
	ret = test_aes_xcbc_mac ();CHECK_RESULT ("AES-XCBC-MAC");
	ret = test_aes_xcbc_prf128 ();CHECK_RESULT ("AES-XCBC-PRF128");
	ret = test_aes_gmac ();CHECK_RESULT ("AES-GMAC");
	ret = test_zuc_mac ();CHECK_RESULT ("ZUC-MAC");
	ret = test_aes_cmac ();CHECK_RESULT("AES-CMAC");

	return ret;
}

int ipsec_aes_cbc (const char * api) {
	check_list();
	   
		hash_keylen=64;
		for (i = 0; i < 6; i++)  {
			ret = test_ipsec_aes_cbc (hash_key, hash_keylen,
										  AesCbcEncArr[i], AesCbcDecArr[i],
										  AesCbcApiNames[i]);
			CHECK_RESULT(AesCbcApiNames[i]);
   		}

		hash_keylen=16;
		ret = test_ipsec_aes_cbc (hash_key, hash_keylen,
										 AesCbcEncArr[i], AesCbcDecArr[i],
										  AesCbcApiNames[i]);
		CHECK_RESULT(AesCbcApiNames[i]);
	
/* 
#ifndef TEST_CPU_CYCLES
	printf ("\nThe following Crypto IPSec APIs tested  from packet size %d to %d with an increment of %d\n",
	START_PACKET_SIZE,MAX_BUFF_SIZE,INCR_STEPS); 
	for (i = 0; i < 7; i++)  {
		printf ("%s\n", AesCbcApiNames[i]);
	} 
#endif
*/
	return 0;
}

int ipsec()
{
	uint32_t cnt;
	uint8_t hash_key[MAX_OUT_PACKET_LENGTH];
	int ret;
	uint32_t hash_keylen = HASH_KEY_LEN;
	int i;
	
		hash_keylen=64;
		if (hash_keylen > MAX_OUT_PACKET_LENGTH)  {
			printf ("Wrong Hash Key size\n");
			return ret;
		}
		memset (hash_key, 0, sizeof(hash_key));

		for (cnt = 0; cnt < HASH_KEY_LEN; cnt++) {
			hash_key[cnt] = cnt;
		}
		for (i = 0; i < 6; i++)  {
			ret = test_ipsec_aes_cbc (hash_key, hash_keylen, 
									  AesCbcEncArr[i], AesCbcDecArr[i],
									  AesCbcApiNames[i]); 
			CHECK_RESULT(AesCbcApiNames[i]);

			ret = test_ipsec_3des (hash_key, hash_keylen,
								   DesEncArr[i], DesDecArr[i], DesApiNames[i]);
			CHECK_RESULT(DesApiNames[i]);
			ret = test_ipsec_aes_ctr (hash_key,hash_keylen, AesCtrEncArr[i], 
									  AesCtrDecArr[i], AesCtrApiNames[i]);
			CHECK_RESULT(AesCtrApiNames[i]);
		}
		hash_keylen=16; /* rfc 3566 talk about 16 byte key length only. 
				This implementation aupport AES-XCBC with 16 byte key only. */
		ret = test_ipsec_aes_cbc (hash_key,hash_keylen,AesCbcEncArr[i], AesCbcDecArr[i],
									  AesCbcApiNames[i]); 
		CHECK_RESULT(AesCbcApiNames[i]);

		ret = test_ipsec_3des (hash_key, hash_keylen,DesEncArr[i], DesDecArr[i], DesApiNames[i]);
		CHECK_RESULT(DesApiNames[i]);


		ret = test_ipsec_aes_ctr (hash_key,hash_keylen, AesCtrEncArr[i], 
										  AesCtrDecArr[i], AesCtrApiNames[i]);
		CHECK_RESULT(AesCtrApiNames[i]);

		ret = test_ipsec_NullEnc (hash_key, hash_keylen,NULL_aes_xcbc_encrypt, NULL_aes_xcbc_decrypt,
								  "NULL-AES-XCBC");
		CHECK_RESULT("NULL-AES-XCBC");
		
		hash_keylen=128; 
		ret = test_ipsec_NullEnc (hash_key, hash_keylen,NULL_md5_encrypt, NULL_md5_decrypt,
								  "NULL-MD5");
		CHECK_RESULT("NULL-MD5");

		ret = test_ipsec_NullEnc (hash_key, hash_keylen,NULL_sha1_encrypt, NULL_sha1_decrypt,
								  "NULL-SHA1");
		CHECK_RESULT("NULL-SHA1");

		ret = test_ipsec_NullEnc (hash_key, hash_keylen,NULL_sha224_encrypt, NULL_sha224_decrypt,
								  "NULL-SHA224");
		CHECK_RESULT("NULL-SHA224");

		ret = test_ipsec_NullEnc (hash_key, hash_keylen,NULL_sha256_encrypt, NULL_sha256_decrypt,
								  "NULL-SHA256");
		CHECK_RESULT("NULL-SHA256");

		ret = test_ipsec_NullEnc (hash_key, hash_keylen,NULL_sha384_encrypt, NULL_sha384_decrypt,
								  "NULL-SHA384");
		CHECK_RESULT("NULL-SHA384");

		ret = test_ipsec_NullEnc (hash_key, hash_keylen,NULL_sha512_encrypt, NULL_sha512_decrypt,
								  "NULL-SHA512");
		CHECK_RESULT("NULL-SHA512");

		ret = test_ipsec_AH (hash_key, hash_keylen,AH_outbound_sha1, AH_inbound_sha1, 
							 "AH SHA1",12);
		CHECK_RESULT("AH SHA1");

		ret = test_ipsec_AH (hash_key, hash_keylen,AH_outbound_sha256, AH_inbound_sha256, 
							 "AH SHA256",16);
		CHECK_RESULT("AH SHA256");

		ret = test_ipsec_AH (hash_key, hash_keylen,AH_outbound_sha384, AH_inbound_sha384, 
							 "AH SHA384",24);
		CHECK_RESULT("AH SHA384");

		ret = test_ipsec_AH (hash_key, hash_keylen,AH_outbound_sha512, AH_inbound_sha512, 
							 "AH SHA512",32);
		CHECK_RESULT("AH SHA512");

		ret = test_ipsec_AH (hash_key, hash_keylen,AH_outbound_md5, AH_inbound_md5, 
							 "AH MD5",12);
		CHECK_RESULT("AH MD5");
		hash_keylen=16; 
		ret = test_ipsec_AH (hash_key, hash_keylen,AH_outbound_aes_xcbc, AH_inbound_aes_xcbc, 
							 "AH AES-XCBC",12);
		CHECK_RESULT("AH AES-XCBC");
	
	return 0;
}

int symmetric_kat () {
	
	int ret;
	
	ret = test_des_ncbc_kat (); CHECK_RESULT ("DES-NCBC");	
	ret = test_3des_cbc_kat (); CHECK_RESULT ("3DES-CBC");		
	ret = test_3des_ecb_kat (); CHECK_RESULT ("3DES-ECB");
	ret = test_aes_cbc_kat (); CHECK_RESULT ("AES-CBC");	
	ret = test_aes_ecb_kat (); CHECK_RESULT ("AES-ECB");	
	ret = test_aes_ctr_kat (); CHECK_RESULT ("AES-CTR");	
	ret = test_aes_icm_kat (); CHECK_RESULT ("AES-ICM");	
	ret = test_aes_lrw_kat (); CHECK_RESULT ("AES-LRW");	
	ret = test_aes_ccm_kat (); CHECK_RESULT ("AES-CCM");	
	ret = test_zuc_encrypt_kat (); CHECK_RESULT ("ZUC-ENC");	
	ret = test_camellia_cbc_kat (); CHECK_RESULT ("CAMELLIA-CBC");		
	ret = test_camellia_ecb_kat (); CHECK_RESULT ("CAMELLIA-ECB");	
	ret = test_camellia_ctr_kat (); CHECK_RESULT ("CAMELLIA-CTR");	
	ret = test_aes_gcm_kat (); CHECK_RESULT ("AES-GCM");	
	ret = test_aes_xts_kat (); CHECK_RESULT ("AES-XTS");	
	ret = test_rc4_kat (); CHECK_RESULT ("RC4");	
	ret = test_aes_xcb_kat (); CHECK_RESULT ("AES-XCB");	
	ret = test_mode_cts_kat (); CHECK_RESULT ("MODE-CTS");
	ret = test_mode_gcm_kat (); CHECK_RESULT ("MODE-GCM");		
	ret = test_mode_cbc_kat (); CHECK_RESULT ("MODE-CBC");		
	ret = test_mode_xts_kat (); CHECK_RESULT ("MODE-XTS");	
	ret = test_mode_ccm_kat (); CHECK_RESULT ("MODE-CCM");	

	return ret;
}



int symmetric ()
{
	int ret;
	
	cvmx_rng_enable ();
	
	ret = test_des_ncbc (); CHECK_RESULT ("DES-NCBC");
	ret = test_3des_cbc (); CHECK_RESULT ("3DES-CBC");
	ret = test_3des_ecb (); CHECK_RESULT ("3DES-ECB");
	ret = test_aes_cbc (); CHECK_RESULT ("AES-CBC");
	ret = test_aes_ecb (); CHECK_RESULT ("AES-ECB");
	ret = test_aes_ctr (); CHECK_RESULT ("AES-CTR");
	ret = test_aes_icm (); CHECK_RESULT ("AES-ICM");
	ret = test_aes_lrw (); CHECK_RESULT ("AES-LRW");
	ret = test_aes_ccm (); CHECK_RESULT ("AES-CCM");
	ret = test_zuc_encrypt (); CHECK_RESULT ("ZUC-ENC");
	ret = test_camellia_cbc (); CHECK_RESULT ("CAMELLIA-CBC");
	ret = test_camellia_ecb (); CHECK_RESULT ("CAMELLIA-ECB");
	ret = test_camellia_ctr (); CHECK_RESULT ("CAMELLIA-CTR");
	ret = test_aes_gcm (); CHECK_RESULT ("AES-GCM");
	ret = test_aes_xts (); CHECK_RESULT ("AES-XTS");
	ret = test_rc4 (); CHECK_RESULT ("RC4");
	ret = test_aes_xcb (); CHECK_RESULT ("AES-XCB");
	ret = test_mode_xts (); CHECK_RESULT ("MODE-XTS");	
	ret = test_mode_cts (); CHECK_RESULT ("MODE-CTS");
	ret = test_mode_cfb (); CHECK_RESULT ("MODE-CFB");
	ret = test_mode_cbc (); CHECK_RESULT ("MODE-CBC");
	ret = test_mode_gcm (); CHECK_RESULT ("MODE-GCM");
	ret = test_mode_ccm (); CHECK_RESULT ("MODE-CCM");
	return ret;
}

int asymmetric()
{
	int ret;

	ret = test_rsa (); CHECK_RESULT ("RSA");	
	ret = test_dsa (); CHECK_RESULT ("DSA");
	ret = test_dh (); CHECK_RESULT ("DH");

	return ret;
}

int asymmetric_kat()
{
	int ret;

	ret = test_rsa_kat (); CHECK_RESULT ("RSA");
	ret = test_dsa_kat (); CHECK_RESULT ("DSA");
	ret = test_dh_kat (); CHECK_RESULT ("DH");

	return ret;
}


int ipsec_3des () {
	check_list();
		for (cnt = 0; cnt < HASH_KEY_LEN; cnt++) {
			hash_key[cnt] = cnt;
		}

	   
		for (i = 0; i < 6; i++)  {
			ret = test_ipsec_3des ( hash_key, hash_keylen,
								DesEncArr[i], DesDecArr[i], DesApiNames[i]);
			CHECK_RESULT(DesApiNames[i]);
   		}

		hash_keylen=16;
		ret = test_ipsec_3des ( hash_key, hash_keylen,
								DesEncArr[i], DesDecArr[i], DesApiNames[i]);
		CHECK_RESULT(DesApiNames[i]);
	
  
	return 0;
}
int ipsec_nullenc () {
	check_list();

		for (cnt = 0; cnt < HASH_KEY_LEN; cnt++) {
			hash_key[cnt] = cnt;
		}
		hash_keylen=16; 
		ret = test_ipsec_NullEnc ( hash_key, hash_keylen,
								  NULL_aes_xcbc_encrypt, NULL_aes_xcbc_decrypt,
								  "NULL-AES-XCBC");
		CHECK_RESULT("NULL-AES-XCBC");

		hash_keylen=128; 
		ret = test_ipsec_NullEnc ( hash_key, hash_keylen,
								  NULL_md5_encrypt, NULL_md5_decrypt,
								  "NULL-MD5");
		CHECK_RESULT("NULL-MD5");

		ret = test_ipsec_NullEnc ( hash_key, hash_keylen,
								  NULL_sha1_encrypt, NULL_sha1_decrypt,
								  "NULL-SHA1");
		CHECK_RESULT("NULL-SHA1");

		ret = test_ipsec_NullEnc ( hash_key, hash_keylen,
								  NULL_sha224_encrypt, NULL_sha224_decrypt,
								  "NULL-SHA224");
		CHECK_RESULT("NULL-SHA224");

		ret = test_ipsec_NullEnc ( hash_key, hash_keylen,
								  NULL_sha256_encrypt, NULL_sha256_decrypt,
								  "NULL-SHA256");
		CHECK_RESULT("NULL-SHA256");

		ret = test_ipsec_NullEnc ( hash_key, hash_keylen,
								  NULL_sha384_encrypt, NULL_sha384_decrypt,
								  "NULL-SHA384");
		CHECK_RESULT("NULL-SHA384");

		ret = test_ipsec_NullEnc ( hash_key, hash_keylen,
								  NULL_sha512_encrypt, NULL_sha512_decrypt,
								  "NULL-SHA512");
		CHECK_RESULT("NULL-SHA512");
	
 
	return 0;
}

int ipsec_aes_ctr () {
	check_list();

		for (cnt = 0; cnt < HASH_KEY_LEN; cnt++) {
			hash_key[cnt] = cnt;
		}
		
		for (i = 0; i < 6; i++)  {
			ret = test_ipsec_aes_ctr ( hash_key, 
									  hash_keylen, AesCtrEncArr[i], 
									  AesCtrDecArr[i], AesCtrApiNames[i]);
			CHECK_RESULT(AesCtrApiNames[i]);
		}
		hash_keylen=16; 
 		ret = test_ipsec_aes_ctr ( hash_key, 
										  hash_keylen, AesCtrEncArr[i], 
										  AesCtrDecArr[i], AesCtrApiNames[i]);
			CHECK_RESULT(AesCtrApiNames[i]);
	
	return 0;
}
int ipsec_ah () {
	check_list();
		for (cnt = 0; cnt < HASH_KEY_LEN; cnt++) {
			hash_key[cnt] = cnt;
		}
 

		ret = test_ipsec_AH ( hash_key, hash_keylen,
							 AH_outbound_sha1, AH_inbound_sha1, 
							 "AH SHA1",12);
		CHECK_RESULT("AH SHA1");

		ret = test_ipsec_AH ( hash_key, hash_keylen,
							 AH_outbound_sha256, AH_inbound_sha256, 
							 "AH SHA256",16);
		CHECK_RESULT("AH SHA256");

		ret = test_ipsec_AH ( hash_key, hash_keylen,
							 AH_outbound_sha384, AH_inbound_sha384, 
							 "AH SHA384",24);
		CHECK_RESULT("AH SHA384");

		ret = test_ipsec_AH ( hash_key, hash_keylen,
							 AH_outbound_sha512, AH_inbound_sha512, 
							 "AH SHA512",32);
		CHECK_RESULT("AH SHA512");

		ret = test_ipsec_AH ( hash_key, hash_keylen,
							 AH_outbound_md5, AH_inbound_md5, 
							 "AH MD5",12);
		CHECK_RESULT("AH MD5");
		hash_keylen=16; 
		ret = test_ipsec_AH ( hash_key, hash_keylen,
							 AH_outbound_aes_xcbc, AH_inbound_aes_xcbc, 
							 "AH AES-XCBC",12);
		CHECK_RESULT("AH AES-XCBC");
	
	return 0;
}
int test_symmetric_api_kat (const char *api) {
	if (memcmp (api,"des-ncbc",sizeof ("des-ncbc"))==0) {
		PRT_HDR ("DES-NCBC");
		ret=test_des_ncbc_kat ();
		CHECK_RET("DES-NCBC");
	
	}
	else if (memcmp (api,"3des-cbc",sizeof ("3des-cbc"))==0) {
		PRT_HDR ("3DES-CBC");
		ret=test_3des_cbc_kat ();
		CHECK_RET("3DES-CBC");
	
	}
	else if (memcmp (api,"3des-ecb",sizeof ("3des-ecb"))==0) {
		PRT_HDR ("3DES-ECB");
		ret=test_3des_ecb_kat ();
		CHECK_RET("3DES-ECB");
	
	}
	else if (memcmp (api,"aes-cbc",sizeof ("aes-cbc"))==0) {
		PRT_HDR ("AES-CBC");
		ret=test_aes_cbc_kat ();
		CHECK_RET("AES-CBC");
	
	}
	else if (memcmp (api,"aes-ecb",sizeof ("aes-ecb"))==0) {
		PRT_HDR ("AES-ECB");
		ret=test_aes_ecb_kat ();
		CHECK_RET("AES-ECB");
	
	}

	else if (memcmp (api,"aes-ctr",sizeof ("aes-ctr"))==0) {
		PRT_HDR ("AES-CTR");
		ret=test_aes_ctr_kat ();
		CHECK_RET("AES-CTR");
	
	}
	else if (memcmp (api,"aes-icm",sizeof ("aes-icm"))==0) {
		PRT_HDR ("AES-ICM");
		ret=test_aes_icm_kat ();
		CHECK_RET("AES-ICM");
	
	}
	else if (memcmp (api,"aes-lrw",sizeof ("aes-lrw"))==0) {
		PRT_HDR ("AES-LRW");
		ret=test_aes_lrw_kat ();
		CHECK_RET("AES-LRW");
	
	}
	else if (memcmp (api,"aes-gcm",sizeof ("aes-gcm"))==0) {
		PRT_HDR ("AES-GCM");
		ret=test_aes_gcm_kat ();
		CHECK_RET("AES-GCM");
	
	}
	else if (memcmp (api,"aes-xts",sizeof ("aes-xts"))==0) {	
		PRT_HDR ("AES-XTS");	
		ret=test_aes_xts_kat ();	
		CHECK_RET("AES-XTS");	
	}
	else if (memcmp (api,"aes-xcb",sizeof ("aes-xcb"))==0) {
		PRT_HDR ("AES-XCB");
		ret=test_aes_xcb_kat ();
		CHECK_RET("AES-XCB");

	}
	else if (memcmp (api,"rc4",sizeof ("rc4"))==0) {
		PRT_HDR ("RC4");
		ret=test_rc4_kat ();
		CHECK_RET("RC4");
	}
	else if (memcmp (api,"aes-ccm",sizeof ("aes-ccm"))==0) {
		PRT_HDR ("AES-CCM");
		ret=test_aes_ccm_kat ();
		CHECK_RET("AES-CCM");
	}
	else if (memcmp (api,"symmetric",sizeof ("symmetric"))==0) {
		PRT_HDR ("SYMMETRIC");
		ret=symmetric_kat ();
		CHECK_RET("SYMMETRIC");
	}
	else if (memcmp (api,"mode-gcm",sizeof ("mode-gcm"))==0) {
        PRT_HDR ("MODE_GCM");
        ret=test_mode_gcm_kat ();
        CHECK_RET("MODE_GCM");
    }
    else if (memcmp (api,"mode-cts",sizeof ("mode-cts"))==0) {
        PRT_HDR ("MODE_CTS");
        ret=test_mode_cts_kat ();
        CHECK_RET("MODE_CTS");
    }	
    else if (memcmp (api,"mode-cbc",sizeof ("mode-cbc"))==0) {
        PRT_HDR ("MODE_CBC");
        ret=test_mode_cbc_kat ();
        CHECK_RET("MODE_CBC");
    }
    else if (memcmp (api,"mode-xts",sizeof ("mode-xts"))==0) {
        PRT_HDR ("MODE_XTS");
        ret=test_mode_xts_kat ();
        CHECK_RET("MODE_XTS");
    }	
    else if (memcmp (api,"mode-ccm",sizeof ("mode-ccm"))==0) {
        PRT_HDR ("MODE_CCM");
        ret=test_mode_ccm_kat ();
        CHECK_RET("MODE_CCM");
    }

	return ret;
}




int test_kat (char **v) {
	
	int ret;

	if (IPSEC) {
		ret = test_ipsec_kat (v[1]);
		CHECK_RET ("IPSEC");
		exit (0);
	}
	if (HASH) {
		ret = test_hash_kat (v[1]);
		CHECK_RET ("HASH KAT");
		exit (0);
	}
	if (SYMMETRIC) {
		ret = test_symmetric_api_kat (v[1]);
		CHECK_RET ("SYMMETRIC KAT");
		exit (0);
	}
	if (ASYMMETRIC) {
		ret = test_asymmetric_kat (v[1]);
		CHECK_RET ("ASYMMERIC KAT");
		exit (0);
	}
	if (CAMELLIA) {
		if(!OCTEON_IS_OCTEON3() && (cvmx_is_init_core())) {
			printf("Camellia APIs are supported only on CN7XXX OCTEON Models\n");
			printf("############ End of CAMELLIA test ############\n\n");
			return -1;
		}
		ret = test_camellia_kat (v[1]);
		exit (0);
	}
	if (ZUC) {
	    if(!OCTEON_IS_OCTEON3() && (cvmx_is_init_core())) {
			printf("ZUC APIs are supported only on CN7XXX OCTEON Models\n");
			printf("############ End of ZUC test ############\n\n");
			return -1;
		}
		ret = test_zuc_kat (v[1]);
		exit (0);
	}

	if (fECC) {
		ret = test_fECC_kat (v[1]);
		CHECK_RET("FECC");
		exit (0);
	}
	if (memcmp (v[1],"drbg",sizeof ("drbg"))==0) {
		ret = test_drbg_kat ();
		CHECK_RET("DRBG");
		exit (0);
	}

	if (DHGROUP) {
		ret = test_dhgroup_kat (v[1]);
		CHECK_RET("DHGROUP");
		exit (0);
	}
	
	if (TKIP) {
		ret = test_all_tkip (v[1]);
		exit (0);
	}
	if (F8_F9) {
		ret = test_f8f9_kat (v[1]);
		CHECK_RET ("F8-F9");
		exit (0);
	}
	if (memcmp (v[1],"ec-point",sizeof ("ec-point"))==0) {
		ret = test_ec_point_kat ();
		CHECK_RET("EC-POINT");
		exit (0);
	}

	return 0;
}
int test_f8f9_kat (const char * api ) {
	if (memcmp (api,"f8-f9",sizeof ("f8-f9"))==0) {
		PRT_HDR("AES-F8F9");
		ret = test_aes_f8f9_kat ();
		CHECK_RET("AES-F8F9");

		PRT_HDR("KASUMI");
		ret = test_kasumi_kat ();
		CHECK_RET("KASUMI");

		PRT_HDR("SNOW3G");
		ret = test_snow3g_kat ();
		CHECK_RET("SNOW3G");
	}
	if (memcmp (api,"snow3g",sizeof ("snow3g"))==0) {
		PRT_HDR("SNOW3G");
		ret = test_snow3g_kat ();
		CHECK_RET("SNOW3G");
		exit (0);
	}
	if (memcmp (api,"aes-f8f9",sizeof ("aes-f8f9"))==0) {
		PRT_HDR("AES-F8F9");
		ret = test_aes_f8f9_kat ();
		CHECK_RET("AES-F8F9");
		exit (0);
	}
	if (memcmp (api,"kasumi",sizeof ("kasumi"))==0) {
		PRT_HDR("KASUMI");
		ret = test_kasumi_kat ();
		CHECK_RET("KASUMI");
		exit (0);
	}

	return 0;
}
int test_f8f9 (const char * api ) {
	if (memcmp (api,"f8-f9",sizeof ("f8-f9"))==0) {
		PRT_HDR("AES-F8F9");
		ret = aes_f8f9 ();
		CHECK_RET("AES-F8F9");

		PRT_HDR("KASUMI");
		ret = kasumi ();
		CHECK_RET("KASUMI");

		PRT_HDR("SNOW3G");
		ret = snow3g ();
		CHECK_RET("SNOW3G");
	}
	if (memcmp (api,"aes-f8f9",sizeof ("aes-f8f9"))==0) {
		PRT_HDR("AES-F8F9");
		ret = aes_f8f9 ();
		CHECK_RET("AES-F8F9");
		exit (0);
	}

	if (memcmp (api,"kasumi",sizeof ("kasumi"))==0) {
		PRT_HDR("KASUMI");
		ret = kasumi ();
		CHECK_RET("KASUMI");
		exit (0);
	}
	if (memcmp (api,"snow3g",sizeof ("snow3g"))==0) {
		PRT_HDR("SNOW3G");
		ret = snow3g ();
		CHECK_RET("SNOW3G");
		exit (0);
	}
	return 0;
}
 
int test_buffer_walk_through (char **v) {
	if (HASH) {
		ret = test_hash (v[1]);
	} 

	if (IPSEC) {
		ret = test_ipsec (v[1]);
	}

	if (SYMMETRIC) {
		ret = test_symmetric_api (v[1]);
	}
	if (ASYMMETRIC) {
		ret = test_asymmetric (v[1]);
	}
	
	if (CAMELLIA) {
		if(!OCTEON_IS_OCTEON3() && (cvmx_is_init_core())) {
			printf("Camellia APIs are supported only on CN7XXX OCTEON Models\n");
			printf("############ End of CAMELLIA test ############\n\n");
			return -1;
		}
		ret = test_camellia (v[1]);
	}
	if (ZUC) {
	    if(!OCTEON_IS_OCTEON3() && (cvmx_is_init_core())) {
			printf("ZUC APIs are supported only on CN7XXX OCTEON Models\n");
			printf("############ End of ZUC test ############\n\n");
			return -1;
    	}
		ret = test_zuc (v[1]);
	}
	if (fECC) {
		ret = test_fECC (v[1]);
		CHECK_RET ("FECC");
	}
	if (TKIP) {
		ret = test_tkip_buff ();
		CHECK_RET ("TKIP");
	}
	if (F8_F9) {
		ret = test_f8f9 (v[1]);
		CHECK_RET ("F8-F9");
	}

	if ((memcmp (v[1],"dhgroup",sizeof ("dhgroup"))==0) && (cvmx_is_init_core())) {
		printf ("*** DHGROUP buffer walk through not available ***\n");
		printf ("########### End of DHGROUP Test ############\n");
	}

	if (memcmp (v[1],"drbg",sizeof ("drbg"))==0) {
		ret = drbg ();
		CHECK_RET("DRBG");
	}
	return 0;
}

int main(int c,char **v)
{		
	#ifdef TEST_CPU_CYCLES
		cvmx_coremask_t core_mask1;
    	core_mask1 = cvmx_sysinfo_get()->core_mask;
    	numcores = cvmx_coremask_get_core_count(&core_mask1);	
	#endif 

	#ifdef OCTEON_OPENSSL_NO_DYNAMIC_MEMORY
		if (cvmx_user_app_init() < 0) {
			printf ("User Application Initialization Failed\n");
			return -1;
		}
	#endif

	#if (OCTEON_SDK_VERSION_NUMBER > 106000217ull)
		if (cvm_crypto_model_check()) {
			printf("This model is Not supported \n");
			return -1;
		}
	#endif
	
	#ifdef TEST_CPU_CYCLES
		if ((c==2) && (memcmp (v[1],"-buffer-walk",sizeof ("-buffer-walk"))==0)) {
			PRINT_CORE0 ("############### Test Results of Buffer Walk Through Test  ##############\n");
			test_all_buffer ();
			goto End;
		}
		else if ((c == 3 ) && (memcmp(v[2],"-buffer-walk",sizeof ("-buffer-walk"))==0) && (CHECK_ALL)) { 
			PRINT_CORE0 ("############### Test Results of Buffer Walk Through Test  ##############\n");
			test_buffer_walk_through (v);
			goto End;
		}
	#else
		if((c==1 || memcmp (v[1],"all",sizeof ("all"))==0)) {
			test_all ();
			exit (0);
		}
		if (memcmp (v[1],"--help",sizeof ("--help"))==0 || memcmp (v[1],"-h",sizeof ("-h"))==0 ) {
			show_help ();
			exit (0);
		}
		if ((c == 2 ) && (memcmp(v[1],"-cipher-list",sizeof ("-cipher-list"))==0) ) { 
			cipher_list ();
			exit (0);
		}
		if((c==2) && (memcmp (v[1],"-kat",sizeof ("-kat"))==0)) {
			PRINT_CORE0 ("############### Test Results of Known Answer Test  ##############\n");
			test_all ();
			exit (0);
		}
		if ((c==2) && (memcmp (v[1],"-buffer-walk",sizeof ("-buffer-walk"))==0)) {
			PRINT_CORE0 ("############### Test Results of Buffer Walk Through Test  ##############\n");
			test_all_buffer ();
			exit (0);
		}
		if (((c == 3) && (memcmp(v[2],"-kat",sizeof ("-kat"))==0) && (CHECK_ALL)) || ((c == 2) && (CHECK_ALL)))  { 
			PRINT_CORE0 ("############### Test Results of Known Answer Test  ##############\n");
			test_kat (v);	
			exit (0);
		}
		if ((c == 3 ) && (memcmp(v[2],"-buffer-walk",sizeof ("-buffer-walk"))==0) && (CHECK_ALL)) { 
			PRINT_CORE0 ("############### Test Results of Buffer Walk Through Test  ##############\n");
			test_buffer_walk_through (v);	
			exit (0);
		}
	#endif

	if (cvmx_is_init_core()) { 
		#ifdef TEST_CPU_CYCLES
			printf("\t *** IMPROPER INPUT *** \n");
			printf("\t To measure performance numbers use -buffer-walk option \n");
			printf("\t For more information please refer README.txt\n");
		#else
			printf("\t *** IMPROPER INPUT *** \n");
			printf("\tFor help: \n");
			printf("\t\tIn SEUM: # ./test-crypto-api-seum --help \n");
			printf("\t\tIn SE: # bootoct 0 numcores=<number_of_cores> endbootargs test-crypto-api --help \n");
			printf("\tFor more information please refer README.txt\n");
		#endif
		exit(0);
	}

	#ifdef TEST_CPU_CYCLES
		End:
			if (cvmx_is_init_core()) 
				printf ("\n!!Please note that Mbps numbers shown are for core clock frquency 1000 Mhz!!\n");
	#endif
	return 0;
}
