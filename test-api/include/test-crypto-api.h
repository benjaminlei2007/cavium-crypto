
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

#define MAX_OUT_PACKET_LENGTH (MAX_BUFF_SIZE+200)
#define HASH_KEY_LEN          64


#define TEST_ALL snow3g();hash();dhgroup19();dhgroup20();dhgroup24();asymmetric();drbg(); \
		ipsec();kasumi();tkip();symmetric();aes_f8f9();camellia();test_zuc_api();test_ecdsa(); \
		test_ecdh();test_eceg();exit (0);




#define BOLD_PRINT   "\033[1m\033[30m"      /* Bold  */
#define NORMAL_PRINT  "\033[0m"

#if 0
#defidne CALL(fun) \
	if((c==2) && (memcmp(v[1],fun,sizeof(fun))==0)) \
	{
#endif

#define PRINT_CORE0(str) \
	if(cvmx_is_init_core()) { \
		printf(str); \
	}

#define CHECK_RET(str) \
	if (cvmx_is_init_core()) { \
		if(ret == -2) { \
    		printf ("######### End of %s test #########\n\n",str); \
		} \
		else if(ret!= 0) { \
			printf ("%s test Failed (Line:%d)\n",str,__LINE__); \
			exit (0); \
		} \
		else { \
			printf ("\n %s API tested successfully\n",str); \
    		printf ("######### End of %s test #########\n\n",str); \
		} \
	} 
	 
#ifndef TEST_CPU_CYCLES
	#define PRT_HDR(str) \
		if (cvmx_is_init_core())  \
			printf ("\n############### Test Results of %s API's ##############\n\n",str);
#else
	#define PRT_HDR(str) 
#endif

#define CHECK_RESULT(str) \
		if ((strstr (str,"ZUC")) || (strstr (str,"CAMELLIA"))){ \
		} \
		else if (ret) { \
            printf ("Result of %-15s : %s\n", str, "Failed"); \
        }

#define HASH ((memcmp (v[1],"hash",sizeof ("hash")) == 0) || (memcmp (v[1],"md5",sizeof ("md5")) == 0) || (memcmp (v[1],"sha1",sizeof ("sha1")) == 0) || (memcmp (v[1],"sha224",sizeof ("sha224")) == 0) || (memcmp (v[1],"sha256",sizeof ("sha256")) == 0) || (memcmp (v[1],"sha512",sizeof ("sha512")) == 0) || (memcmp (v[1],"sha384",sizeof ("sha384")) == 0) || (memcmp (v[1],"aes-xcb",sizeof ("aes-xcb")) == 0)  || (memcmp (v[1],"aes-xcbc",sizeof ("aes-xcbc")) == 0) || (memcmp (v[1],"aes-xcbc-mac",sizeof ("aes-xcbc-mac")) == 0) || (memcmp (v[1],"aes-xcbc-prf128",sizeof ("aes-xcbc-prf128")) == 0) || (memcmp (v[1],"hmac",sizeof ("hmac")) == 0) || (memcmp (v[1],"aes-cmac",sizeof ("aes-cmac")) == 0) || (memcmp (v[1],"aes-gmac",sizeof ("aes-gmac")) == 0) || (memcmp (v[1],"sha3_224",sizeof ("sha3_224")) == 0) || (memcmp (v[1],"sha3_256",sizeof ("sha3_256")) == 0) || (memcmp (v[1],"sha3_384",sizeof ("sha3_384")) == 0) || (memcmp (v[1],"sha3_512",sizeof ("sha3_512")) == 0) || (memcmp (v[1],"shake_128",sizeof ("shake_128")) == 0) || (memcmp (v[1],"shake_256",sizeof ("shake_256")) == 0))

#define HASH1 

#define IPSEC ((memcmp (v[1],"ipsec",sizeof ("ipsec"))==0) || (memcmp (v[1],"ipsec-aes-cbc",sizeof ("ipsec-aes-cbc"))==0) || (memcmp (v[1],"ipsec-aes-ctr",sizeof ("ipsec-aes-ctr"))==0) || (memcmp (v[1],"ipsec-3des",sizeof ("ipsec-3des"))==0) || (memcmp (v[1],"ipsec-ah",sizeof ("ipsec-ah"))==0) || (memcmp (v[1],"ipsec-nullenc",sizeof ("ipsec-nullenc"))==0))


#define SYMMETRIC ((memcmp (v[1],"symmetric",sizeof ("symmetric"))==0) || (memcmp (v[1],"des-ncbc",sizeof ("des-ncbc"))==0) || (memcmp (v[1],"3des-cbc",sizeof ("3des-cbc"))==0) || (memcmp (v[1],"3des-ecb",sizeof ("3des-ecb"))==0) || (memcmp (v[1],"aes-cbc",sizeof ("aes-cbc"))==0) || (memcmp (v[1],"aes-ecb",sizeof ("aes-ecb"))==0) || (memcmp (v[1],"aes-ctr",sizeof ("aes-ctr"))==0) || (memcmp (v[1],"aes-icm",sizeof ("aes-icm"))==0) || (memcmp (v[1],"aes-lrw",sizeof ("aes-lrw"))==0) || (memcmp (v[1],"aes-gcm",sizeof ("aes-gcm"))==0) || (memcmp (v[1],"aes-xcb",sizeof ("aes-xcb"))==0) || (memcmp (v[1],"aes-xts",sizeof ("aes-xts"))==0) || (memcmp (v[1],"rc4",sizeof ("rc4"))==0) || (memcmp (v[1],"aes-ccm-rfc",sizeof ("aes-ccm-rfc"))==0)  || (memcmp (v[1],"aes-ccm",sizeof ("aes-ccm"))==0) || (memcmp (v[1],"aes-xbc",sizeof ("aes-xbc"))==0) || (memcmp (v[1],"mode-xts",sizeof("mode-xts"))==0) || (memcmp (v[1],"mode-cts",sizeof("mode-cts"))==0) || (memcmp(v[1],"mode-cfb",sizeof("mode-cfb"))==0) || (memcmp(v[1],"mode-cbc",sizeof("mode-cbc"))==0) || (memcmp (v[1],"mode-gcm",sizeof("mode-gcm"))==0) || (memcmp (v[1],"mode-ccm",sizeof("mode-ccm"))==0))




#define ASYMMETRIC ((memcmp (v[1],"asymmetric",sizeof ("asymmetric"))==0) || (memcmp (v[1],"rsa",sizeof ("rsa"))==0) || (memcmp (v[1],"dsa",sizeof ("dsa"))==0) || (memcmp (v[1],"dh",sizeof ("dh"))==0))


#define F8_F9 ((memcmp (v[1],"f8-f9",sizeof ("f8-f9"))==0) || (memcmp (v[1],"kasumi",sizeof ("kasumi"))==0) || (memcmp (v[1],"snow3g",sizeof ("snow3g"))==0) || (memcmp (v[1],"aes-f8f9",sizeof ("aes-f8f9"))==0))

#define CAMELLIA ((memcmp (v[1],"camellia",sizeof ("camellia"))==0) || (memcmp (v[1],"camellia-cbc",sizeof ("camellia-cbc"))==0) || (memcmp (v[1],"camellia-ctr",sizeof ("camellia-ctr"))==0) || (memcmp (v[1],"camellia-ecb",sizeof ("camellia-ecb"))==0))



#define ZUC ((memcmp (v[1],"zuc",sizeof ("zuc"))==0) || (memcmp (v[1],"zuc-mac",sizeof ("zuc-mac"))==0) || (memcmp (v[1],"zuc-encrypt",sizeof ("zuc-encrypt"))==0))



#define TKIP ((memcmp (v[1],"tkip",sizeof ("tkip"))==0) || (memcmp (v[1],"michael",sizeof ("michael"))==0) || (memcmp (v[1],"mixing",sizeof ("mixing"))==0))

#define DHGROUP ((memcmp (v[1],"dhgroup",sizeof ("dhgroup"))==0)  || (memcmp (v[1],"dhgroup19",sizeof ("dhgroup19"))==0) || (memcmp (v[1],"dhgroup20",sizeof ("dhgroup20"))==0) || (memcmp (v[1],"dhgroup24",sizeof ("dhgroup24"))==0) )


#define fECC ((memcmp (v[1],"fecc",sizeof ("fecc"))==0) || (memcmp (v[1],"ecdh",sizeof ("ecdh"))==0)  || (memcmp (v[1],"ecdsa",sizeof ("ecdsa"))==0)  || (memcmp (v[1],"eceg",sizeof ("eceg"))==0)|| (memcmp (v[1],"point-add",sizeof ("point-add"))==0)|| (memcmp (v[1],"point-mul",sizeof ("point-mul"))==0)|| (memcmp (v[1],"point-dbl",sizeof ("point-dbl"))==0)|| (memcmp (v[1],"ec-point",sizeof ("ec-point"))==0))

#define CHECK_ALL (F8_F9 || fECC || DHGROUP || TKIP || ZUC || CAMELLIA || ASYMMETRIC || SYMMETRIC || IPSEC || HASH || (memcmp (v[1],"drbg",sizeof ("drbg"))==0))

/* IPSec API function pointers */
typedef int (*AesCbcEncFuncPtr) (uint16_t, uint8_t *,  uint16_t, uint8_t *, 
								 uint8_t *, uint8_t *, uint8_t *, uint16_t, 
								 uint8_t *, uint16_t *);
typedef int (*AesCbcDecFuncPtr) (uint16_t, uint8_t *, uint16_t, uint8_t *, 
								 uint8_t *, uint8_t *, uint16_t, uint8_t *, 
								 uint16_t *, uint8_t);
typedef int (*AesCtrEncFuncPtr) (uint64_t *, uint32_t, uint32_t, uint16_t, 
								 uint8_t *, uint8_t *, uint8_t *, uint8_t *,
								 uint16_t, uint8_t *, uint16_t *);
typedef int (*AesCtrDecFuncPtr) (uint64_t *, uint32_t, uint32_t, uint16_t, 
								 uint8_t *, uint8_t *,  uint8_t *, uint16_t,
								 uint8_t *, uint16_t *, uint8_t);
typedef int (*DesEncFuncPtr) (uint8_t *, uint16_t, uint8_t *, uint8_t *, 
							  uint8_t *, uint8_t *, uint16_t, uint8_t *, 
							  uint16_t *);
typedef int (*DesDecFuncPtr) (uint8_t *, uint16_t , uint8_t *, uint8_t *,
							  uint8_t *, uint16_t ,uint8_t *, uint16_t *,
							  uint8_t);
typedef int (*EncNULLFuncPtr) (uint16_t, uint8_t *, uint8_t *, uint8_t *,
							   uint16_t, uint8_t *, uint16_t *);
typedef int (*DecNULLFuncPtr) (uint16_t, uint8_t *, uint8_t *, uint16_t,
							   uint8_t *, uint16_t *, uint8_t);
typedef int (*OutbAHFuncPtr) (uint16_t, uint8_t *,  uint8_t *, uint8_t *, 
							  uint16_t , uint8_t *, uint16_t *);
typedef int (*InbAHFuncPtr) (uint16_t, uint8_t *,  uint8_t *, uint16_t , 
							 uint8_t *, uint16_t *,int);

 
	/* Arry of IPSec APIs */
	const char *AesCbcApiNames[] = {
		"AES-CBC-MD5",
		"AES-CBC-SHA1",
		"AES-CBC-SHA224",
		"AES-CBC-SHA256",
		"AES-CBC-SHA384",
		"AES-CBC-SHA512",
		"AES-CBC-AES-XCBC"
	};
	const char *DesApiNames[] = {
		"DES-EDE3-MD5",	
		"DES-EDE3-SHA1",	
		"DES-EDE3-SHA224",	
		"DES-EDE3-SHA256",	
		"DES-EDE3-SHA384",	
		"DES-EDE3-SHA512",
		"DES-EDE3-AES-XCBC"
	};
	const char *AesCtrApiNames[] = {
		"AES-CTR-MD5",
		"AES-CTR-SHA1",
		"AES-CTR-SHA224",
		"AES-CTR-SHA256",
		"AES-CTR-SHA384",
		"AES-CTR-SHA512",
		"AES-CTR-AES-XCBC"
	};
	AesCbcEncFuncPtr AesCbcEncArr[] = {
		AES_cbc_md5_encrypt,
		AES_cbc_sha1_encrypt,
		AES_cbc_sha224_encrypt,
		AES_cbc_sha256_encrypt,
		AES_cbc_sha384_encrypt,
		AES_cbc_sha512_encrypt,
		AES_cbc_aes_xcbc_encrypt
	};
	AesCbcDecFuncPtr AesCbcDecArr[] = {
		AES_cbc_md5_decrypt,
		AES_cbc_sha1_decrypt,
		AES_cbc_sha224_decrypt,
		AES_cbc_sha256_decrypt,
		AES_cbc_sha384_decrypt,
		AES_cbc_sha512_decrypt,
		AES_cbc_aes_xcbc_decrypt
	};
	DesEncFuncPtr DesEncArr[] = {
		DES_ede3_cbc_md5_encrypt, 
		DES_ede3_cbc_sha1_encrypt, 
		DES_ede3_cbc_sha224_encrypt, 
		DES_ede3_cbc_sha256_encrypt, 
		DES_ede3_cbc_sha384_encrypt, 
		DES_ede3_cbc_sha512_encrypt, 
		DES_ede3_cbc_aes_xcbc_encrypt
	};
	DesDecFuncPtr DesDecArr[] = {
		DES_ede3_cbc_md5_decrypt, 
		DES_ede3_cbc_sha1_decrypt, 
		DES_ede3_cbc_sha224_decrypt, 
		DES_ede3_cbc_sha256_decrypt, 
		DES_ede3_cbc_sha384_decrypt, 
		DES_ede3_cbc_sha512_decrypt, 
		DES_ede3_cbc_aes_xcbc_decrypt
	};
	AesCtrEncFuncPtr AesCtrEncArr[] = {
		AES_ctr_md5_encrypt,
		AES_ctr_sha1_encrypt,
		AES_ctr_sha224_encrypt,
		AES_ctr_sha256_encrypt,
		AES_ctr_sha384_encrypt,
		AES_ctr_sha512_encrypt,
		AES_ctr_aes_xcbc_encrypt
	};
	AesCtrDecFuncPtr AesCtrDecArr[] = {
		AES_ctr_md5_decrypt,
		AES_ctr_sha1_decrypt,
		AES_ctr_sha224_decrypt,
		AES_ctr_sha256_decrypt,
		AES_ctr_sha384_decrypt,
		AES_ctr_sha512_decrypt,
		AES_ctr_aes_xcbc_decrypt
	};



/*
 * Test Hash/MAC Function Declarations 
 */
	int hash();
	int test_md5();
	int test_sha1();
	int test_sha224();
	int test_sha256();
	int test_sha384();
	int test_sha512();
	int test_hmac();
	int test_aes_cmac();
	int test_aes_xcbc_mac();
	int test_aes_xcbc_prf128();
	int test_aes_xcb();
	int test_aes_gmac();
	int hash_kat();
	int test_md5_kat();
	int test_sha1_kat();
	int test_sha224_kat();
	int test_sha256_kat();
	int test_sha384_kat();
	int test_sha512_kat();
	int test_hmac_kat();
	int test_aes_gmac_kat();
	int test_aes_xcbc_mac_kat();
	int test_aes_xcbc_prf128_kat(); 
	int test_aes_cmac_kat();
	int test_sha3_224();
	int test_sha3_256();
	int test_sha3_384();
	int test_sha3_512();
	int test_shake_128_hash();
	int test_shake_256_hash();





	
/* 
 * Test Symmetric Function Declarations
 */
	int symmetric();
	int symmetric_kat();
	int test_des_ncbc();
	int test_3des_cbc();
	int test_3des_ecb();
	int test_aes_cbc();
	int test_aes_ecb();
	int test_aes_ctr();
	int test_aes_icm();
	int test_aes_lrw();
	int test_aes_gcm();
	int test_aes_xts();
	int test_rc4();
	int test_aes_ccm();
	int aes_ccm_rfc_tests();
	int camellia_kat ();
	int test_camellia_cbc();
	int test_camellia_cbc_kat();
	int test_camellia_ctr();
	int test_camellia_ctr_kat();
	int test_camellia_ecb();
	int test_camellia_ecb_kat();
	int test_camellia_kat();
	int test_tkip_michael();
	int test_tkip_buff();
	int test_tkip_mixing();
	int test_3des_cbc_kat(); 
	int test_3des_ecb_kat();
	int test_aes_cbc_kat();
	int test_aes_ecb_kat();
	int test_aes_ctr_kat();
	int test_aes_gcm_kat();
	int test_aes_xcb_kat();
	int test_des_ncbc_kat(); 
	int test_aes_icm_kat();
	int test_aes_lrw_kat();
	int test_aes_xts_kat();
	int test_rc4_kat();
	int test_aes_ccm_kat();
	int test_mode_xts ();
    int test_mode_cts ();
    int test_mode_cfb ();
    int test_mode_cbc ();
    int test_mode_gcm ();
    int test_mode_ccm ();
    int test_mode_gcm_kat ();
    int test_mode_cts_kat ();	
    int test_mode_cbc_kat ();
    int test_mode_xts_kat ();
    int test_mode_ccm_kat ();

/*
 * Test Asymmetric Function Declarations
 */
	int asymmetric();
	int asymmetric_kat();
	int test_rsa();
	int test_rsa_kat();
	int test_dsa();
	int test_dsa_kat();
	int test_dh();
	int test_dh_kat();
	
/*
 * Test IPSec Function Declarations
 */
	int test_ipsec_aes_cbc();
	int test_ipsec_3des();
	int test_ipsec_NullEnc();
	int test_ipsec_aes_ctr();
	int test_ipsec_AH();
	int ipsec_aes_cbc();
	int ipsec_aes_ctr();
	int ipsec_3des();
	int ipsec_ah();
	int ipsec();
	int test_ipsec_kat();
	int ipsec_nullenc();
	
/* 
 * Test ZUC Function Declarations
 */
	int zuc();
	int test_zuc_api();
	int test_zuc_api_kat();
	int test_zuc_mac();
	int test_zuc_mac_kat();
	int test_zuc_encrypt();
	int test_zuc_encrypt_kat();
	
/*
 * DHGroup Function Declarations
 */
	
	int dhgroup19_kat();
	int dhgroup20_kat();
	int dhgroup24_kat();
	int drbg();
	int test_drbg_kat();
	int tkip();
	int test_tkip();
	int test_tkip_kat();
	int camellia();

/*
 * F8-F9 Function Declarations
 */
	int aes_f8f9();
	int test_aes_f8f9_kat();
	int test_f8f9_kat();
	int kasumi();
	int test_kasumi_kat();
	int snow3g();
	int test_snow3g_kat();

/*
 * Test fECC Function Declarations
 */
	int test_fECC_kat ();
	int test_fECC ();
	int test_ecdsa ();
	int test_ecdh ();
	int test_eceg ();	
	int test_ec_point ();	
	int test_ec_point ();
	int test_point_addition ();
	int test_point_double ();
	int test_point_multiply ();	
	int test_ecdh_kat();
	int test_ecdsa_kat();
	int test_eceg_kat();
	int test_ec_point_kat();
	int test_point_addition_kat();
	int test_point_multiply_kat();
	int test_point_double_kat();

