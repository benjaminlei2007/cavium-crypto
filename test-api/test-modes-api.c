#include<stdio.h>
#include <openssl/crypto.h>
#include <openssl/modes_lcl.h>
#include <string.h>
#include "openssl/aes.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include "cvmx-rng.h"
#include "test-modes-api.h"
#include "test-crypto-common.h"

#define DUMP_BUFF(str_,buf_,len_) \
{ \
	int i; \
	printf("%s",(str_)); \
	for (i=0;i<(len_);i++){ \
		printf( "%02x ",(buf_)[i]); \
		if(i && ((i%8) == 7)) printf("\n"); \
	} \
}

#ifdef TEST_CPU_CYCLES
	extern uint32_t numcores;
	extern CVMX_SHARED uint64_t total_cpucycles;
	extern CVMX_SHARED uint64_t total_mbps;		
#endif

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

int test_mode_cbc_kat () {
	uint8_t iv[16];
	uint8_t key[32];
	uint8_t in_text[400];
	uint8_t out_text[400];
	int len, fail=0,cnt=0;
	unsigned int i;
	uint32_t val;
	AES_KEY akey;

	for (i=0;i<sizeof(mode_cbc_enc)/sizeof (mode_cbc_enc[0]);i++) {
		memset (key, 0, sizeof (key));
		memset (iv, 0, sizeof (iv));
		memset (in_text, 0, sizeof (in_text));
		memset (out_text, 0, sizeof (out_text));
		str2hex(mode_cbc_enc[i].key,key,&len);	
		str2hex(mode_cbc_enc[i].iv,iv,&len);
		str2hex(mode_cbc_enc[i].plain,in_text,&len);

		val = AES_set_encrypt_key (key, mode_cbc_enc[i].key_size, &akey);	
		if (val != 0){
			printf ("AES_set_encrypt_key Failed\n");
		}	
		
		CRYPTO_cbc128_encrypt (in_text, out_text, len, &akey, iv,(block128_f) AES_encrypt);
		
		str2hex(mode_cbc_enc[i].cipher,in_text,&len);
		if (memcmp (in_text,out_text, len)) {
			printf ("CRPTO_cbc128_encrypt Failed for input size\n");
			printf("Expected %s\n",mode_cbc_enc[i].cipher);
			printf("actual %s\n",out_text);
			DUMP_BUFF("Plain\n",mode_cbc_enc[i].cipher,16);
			DUMP_BUFF("TEXT\n",out_text,len);
			fail++;
		}
		cnt++;
	}
	// Decrypt
	for (i=0;i<sizeof (mode_cbc_dec)/sizeof (mode_cbc_dec[0]);i++) {
		memset (key, 0, sizeof (key));
		memset (iv, 0, sizeof (iv));
		memset (in_text, 0, sizeof (in_text));
		memset (out_text, 0, sizeof (out_text));
		str2hex(mode_cbc_dec[i].key,key,&len);	
		str2hex(mode_cbc_dec[i].iv,iv,&len);
		str2hex(mode_cbc_dec[i].cipher,in_text,&len);

		val = AES_set_decrypt_key (key,mode_cbc_dec[i].key_size , &akey);	
		if (val != 0){
			printf ("AES_set_decrypt_key Failed\n");
		}

		CRYPTO_cbc128_decrypt (in_text, out_text, len, &akey, iv, (block128_f) AES_decrypt);
		
		str2hex(mode_cbc_dec[i].plain,in_text,&len);	
		if (memcmp (in_text,out_text, len)) {	
			printf ("CRPTO_cbc128_decrypt Failed for input size\n");
			DUMP_BUFF("IN TEXT\n",in_text,16);
			DUMP_BUFF("OUT TEXT\n",out_text,16);
			fail++;
		}
		cnt++;
	}

	if (fail)
		printf("***");
	
	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d passed : %d failed : %d\n","MODE-CBC",cnt,(cnt-fail),fail);

	return 0;
}

int test_mode_cbc ()
{	
	uint8_t encbuff[MAX_BUFF_SIZE] = {0};
	uint8_t decbuff[MAX_BUFF_SIZE] = {0};
	uint8_t inbuff[MAX_BUFF_SIZE];

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
	uint8_t test_iv[] = {
		0x08,0x93,0x78,0x67,0x49,0x32,0x87,0x21,
		0x67,0xab,0xcd,0xef,0xaf,0xcd,0xef,0xff
	};
	uint8_t iv[16];
	int keylen;
	int j;	
	unsigned int inlen,prev_inlen = 0,i;
	int ret = 0;
	AES_KEY akey;
	
	memset (inbuff, 0, sizeof (inbuff));	
	for (inlen = START_PACKET_SIZE; inlen <= MAX_BUFF_SIZE; inlen+=inlen){
		for (i = prev_inlen; i < inlen; i++) {
			inbuff[i] = cvmx_rng_get_random8 (); 
		}
		j=0;
		for (keylen = 128; keylen <= 256; keylen +=64){	

			//Encrypt
			AES_set_encrypt_key (aes_key[j], keylen, &akey);
			memcpy (iv, test_iv, 16);
			CRYPTO_cbc128_encrypt (inbuff, encbuff, inlen, &akey, iv,(block128_f) AES_encrypt);
		
			//Decrypt
			AES_set_decrypt_key (aes_key[j], keylen, &akey);			
			memcpy (iv, test_iv, 16);
			CRYPTO_cbc128_decrypt (encbuff, decbuff, inlen, &akey, iv, (block128_f) AES_decrypt);
		
			if (memcmp (inbuff, decbuff, inlen)) {
				DUMP_BUFF ("plain_text\n", inbuff, (signed)inlen);
				DUMP_BUFF ("decrypt_text", decbuff, (signed)inlen);
				printf ("Crypto_cbc128 failed\n");
				ret = -1;
				goto End;
			}
			j++;
		}
		prev_inlen = inlen;
	}
	ret = 0;	
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","MODE-CBC",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}

int test_mode_gcm ()
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

	uint8_t iv[] = "0xab,0x23,0x4c,0xa7,0x69,0x07,0x67,0xa4,0xc8,0xd9,0xa5,0xef";
	unsigned int keylen;
	uint8_t ain[] = "This string is used for authentication";
	uint8_t tag1[16] = {0},tag2[16] = {0};
	uint8_t inbuff[MAX_BUFF_SIZE];
	unsigned int inlen,prev_inlen = 0;
	uint32_t i = 0;
	int j = 0;
	int ret = 0;
		
	AES_KEY key1;
  	GCM128_CONTEXT ctx; 
	
	for (inlen = START_PACKET_SIZE; inlen <= MAX_BUFF_SIZE; inlen+=inlen) {
		for (i = prev_inlen; i < inlen; i++) {
			inbuff[i] = cvmx_rng_get_random8 (); 
		}
		j=0;
		for (keylen = 128; keylen <= 256; keylen += 64) {	
				
			AES_set_encrypt_key (key[j], sizeof(key)*8, &key1); 
			CRYPTO_gcm128_init (&ctx, &key1, (block128_f)AES_encrypt);   
			
			//Encrypt
			CRYPTO_gcm128_setiv (&ctx, iv, sizeof(iv));	
			CRYPTO_gcm128_aad (&ctx, ain, sizeof(ain));
			CRYPTO_gcm128_encrypt (&ctx, inbuff, encbuff, sizeof(inbuff));			
			CRYPTO_gcm128_tag (&ctx, tag1, 16);	
	
			//Decrypt				
			CRYPTO_gcm128_setiv (&ctx, iv, sizeof(iv));	
			CRYPTO_gcm128_aad (&ctx, ain, sizeof(ain));	  	
			CRYPTO_gcm128_decrypt (&ctx, encbuff, decbuff, sizeof(encbuff));	   		
			CRYPTO_gcm128_tag (&ctx, tag2, 16);	
		
			if (memcmp (decbuff, inbuff, sizeof(inbuff))) {
				DUMP_BUFF ("inbuff\n", inbuff, (signed)inlen);	
				DUMP_BUFF ("decbuff\n", decbuff, (signed)inlen);
				printf("CRYPTO_gcm128_decrypt failed\n");
				ret = -1;
				goto End;	
			}	
	
			if (memcmp (tag2, tag1,sizeof(tag1))) {
				DUMP_BUFF("tag1\n", tag1, 16);	
				DUMP_BUFF("tag2\n", tag2, 16);
				printf("tag mismatch\n");	
				ret = -1;
				goto End;	
			}
			j++;
		}	
		prev_inlen = inlen;
	}	
	ret = 0;	
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","MODE-GCM",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}

int test_mode_gcm_kat ()
{			
	uint8_t inbuff[400];
	uint8_t	ain[400]; 
	uint8_t	encbuff[400];
	uint8_t iv[128];
	uint8_t tag[16]; 
	uint8_t tag1[16] = {0};	
	uint8_t tag2[16] = {0};
	uint8_t enc_buff[400];						
	uint8_t dec_buff[400];						
	uint8_t key[32];
	unsigned int i;	
	int ctlen;
	int aadlen, ptlen, ivlen, taglen, keylen;	
	int ret = 0,fail = 0,cnt = 0;
	AES_KEY key1;
  	GCM128_CONTEXT ctx; 
		
	for (i = 0;i < sizeof (mode_gcm_vector)/sizeof (mode_gcm_vector[0]);i++) {			
		str2hex (mode_gcm_vector [i].key, key, &keylen);
		str2hex (mode_gcm_vector [i].plain, inbuff, &ptlen);
		str2hex (mode_gcm_vector [i].ain, ain, &aadlen);	
		str2hex (mode_gcm_vector [i].iv, iv, &ivlen);
		str2hex (mode_gcm_vector [i].cin, encbuff, &ctlen);	
		str2hex (mode_gcm_vector [i].tag, tag, &taglen);
  			
		memset(tag1, 0, 16);	
		memset(tag2, 0, 16);
	
		//Encrypt		
		AES_set_encrypt_key (key, keylen*8, &key1); 
		CRYPTO_gcm128_init (&ctx, &key1, (block128_f)AES_encrypt);   		
		CRYPTO_gcm128_setiv (&ctx, iv, ivlen);	
		CRYPTO_gcm128_aad (&ctx, ain, aadlen);	 
  		CRYPTO_gcm128_encrypt (&ctx, inbuff, enc_buff, ptlen);	
  		CRYPTO_gcm128_tag (&ctx, tag1, 16);	
		
		if (memcmp (enc_buff, encbuff, ctlen)) {
			printf("CRYPTO_gcm128_encrypt failed\n");	
			ret = -1;
			goto End;
		}	
		
		if (memcmp(tag1, tag, taglen)) {
			DUMP_BUFF ("tag1\n", tag1, 16);	
			DUMP_BUFF ("tag\n", tag, 16);
			printf("tag1 mismatch\n");
			ret = -1;
			goto End;	
			fail++;
		}
						
		//Decrypt			
		AES_set_encrypt_key (key, keylen*8, &key1); 
		CRYPTO_gcm128_init (&ctx, &key1, (block128_f)AES_encrypt);   
		CRYPTO_gcm128_setiv (&ctx, iv, ivlen);	
		CRYPTO_gcm128_aad (&ctx, ain, aadlen);	  
  		CRYPTO_gcm128_decrypt (&ctx, enc_buff, dec_buff, ctlen);	   	
  		CRYPTO_gcm128_tag (&ctx, tag2, 16);	
	
		if(memcmp (dec_buff, inbuff, ptlen)) {	
			DUMP_BUFF ("inbuff\n", inbuff, ptlen);	
			DUMP_BUFF ("decbuff\n", dec_buff, ptlen);
			printf("CRYPTO_gcm128_decrypt failed\n");	
			ret = -1;
			goto End;	
		}	
	
		if (memcmp (tag2, tag, taglen)) {	
			DUMP_BUFF ("tag2\n", tag2, 16);	
			DUMP_BUFF ("tag\n", tag, 16);
			printf("tag2 mismatch\n");	
			ret = -1;
			goto End;	
			fail++;
		}	
		cnt++;
	}	
	if (fail)
		printf("***");
	if (cvmx_is_init_core()) {
		printf ("%-20s :Total Test vectors tested: %d passed : %d failed : %d\n","MODE-GCM",cnt,(cnt-fail),fail);
	}
End:
	return ret;
}

int test_mode_cfb ()
{	
	unsigned char key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
	unsigned char decrypttext[MAX_BUFF_SIZE] = {0};
	unsigned char ciphertext[MAX_BUFF_SIZE] = {0};
	unsigned char iv[16];
	unsigned char test_iv[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	int n = 8,*num;	
	unsigned int inlen,prev_inlen=0,i;
	unsigned char input[MAX_BUFF_SIZE];
	int ret;		
	num = &n;
	
	for (inlen = START_PACKET_SIZE; inlen <= MAX_BUFF_SIZE; inlen+=inlen) {
		for (i = prev_inlen; i < inlen; i++) {
			input[i] = cvmx_rng_get_random8 (); 
		}
		
		memcpy (iv, test_iv, sizeof(test_iv));
		CRYPTO_cfb128_encrypt (input, ciphertext, inlen, key, iv, num, AES_ENCRYPT, (block128_f)AES_encrypt);
			
		memcpy (iv, test_iv, sizeof(test_iv));	
		CRYPTO_cfb128_encrypt (ciphertext, decrypttext, inlen, key, iv, num, AES_DECRYPT, (block128_f)AES_encrypt);		
	
		if (memcmp (input, decrypttext, inlen)) {	
			DUMP_BUFF ("plaintext\n", input, (signed)inlen); 
			DUMP_BUFF ("decrypttext\n",decrypttext, (signed)inlen);
			printf("Crypto_cfb128 failed!!\n");	
			ret = -1;
			goto End;
		}	
		prev_inlen = inlen;
	}	
	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","MODE-CFB",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}

int test_mode_xts_kat() {
	
	uint8_t key1[32];
	uint8_t key2[32];	
	uint8_t iv[128];
	uint8_t in_text[400];
	uint8_t out_text[400];
	int len, cnt = 0, ret, fail = 0, plen, ivlen;
	unsigned int i;
	XTS128_CONTEXT ctx;
	AES_KEY k1,k2;
	
	//Encrypt
	for (i = 0; i < sizeof(mode_xts_enc)/sizeof(mode_xts_enc[0]); i++) {
		memset (in_text, 0, sizeof(in_text));
		memset (out_text, 0, sizeof(out_text));
		memset (key1, 0, sizeof(key1));
		memset (key2, 0, sizeof(key2));
		memset (iv, 0, sizeof (iv));
		str2hex (mode_xts_enc[i].key1, key1, &len);
		str2hex (mode_xts_enc[i].key2, key2, &len);
		str2hex (mode_xts_enc[i].plain, in_text, &plen);	
		str2hex (mode_xts_enc[i].iv, iv, &ivlen);
	
		AES_set_encrypt_key (key1, mode_xts_enc[i].key_size, &k1);	
		AES_set_encrypt_key (key2, mode_xts_enc[i].key_size, &k2);
		ctx.key1 = &k1;	
		ctx.key2 = &k2;
		ctx.block1 = (block128_f)AES_encrypt;	
		ctx.block2 = (block128_f)AES_encrypt;
		
		ret = CRYPTO_xts128_encrypt (&ctx, iv, in_text, out_text, plen, AES_ENCRYPT);			
		if (ret != 0){
			printf ("CRYPTO_xts_encrypt Failed\n");
			ret = -1;
			goto End;
		}
		
		str2hex (mode_xts_enc[i].cipher, in_text, &len);
		if ( memcmp(in_text, out_text, len)) {
			printf("CRYPTO_xts128_encrypt Failed for input size\n");
			DUMP_BUFF("Plain\n",mode_xts_enc[i].cipher,16);
			DUMP_BUFF("TEXT\n", out_text, len);
			fail++;
		}
		cnt++;
	}

	//Decrypt 
	for(i=0; i<sizeof(mode_xts_dec)/sizeof(mode_xts_dec[0]); i++) {
		memset (in_text, 0, sizeof(in_text));
		memset (out_text, 0, sizeof(out_text));
		memset (key1, 0, sizeof(key1));
		memset (key2, 0, sizeof(key2));
		str2hex (mode_xts_dec[i].key1, key1, &len);
		str2hex (mode_xts_dec[i].key2, key2, &len);
		str2hex (mode_xts_enc[i].cipher, in_text, &plen);	
		str2hex (mode_xts_enc[i].iv, iv, &ivlen);
	
		AES_set_encrypt_key (key1, mode_xts_dec[i].key_size, &k1);	
		AES_set_encrypt_key (key2, mode_xts_dec[i].key_size, &k2);
		ctx.key1 = &k1;	
		ctx.key2 = &k2;
		ctx.block1 = (block128_f)AES_decrypt;	
		ctx.block2 = (block128_f)AES_encrypt;
		ret = CRYPTO_xts128_encrypt(&ctx, iv, in_text, out_text, plen, AES_DECRYPT);					
		if (ret != 0){
			printf ("CRYPTO_xts_decrypt Failed\n");
			ret = -1;
			goto End;
		}

		str2hex (mode_xts_dec[i].plain, in_text, &len);
		if ( memcmp (in_text, out_text, len)) {
			printf ("CRYPTO_xts128_decrypt failed\n");
			DUMP_BUFF ("IN TEXT\n", in_text, len);
			DUMP_BUFF ("OUT TEXT\n", out_text, len);
			fail++;
		}
		cnt++;
	}
	if (fail)
		printf("***");
	
	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d passed : %d failed : %d\n","MODE-XTS",cnt,(cnt-fail),fail);
	ret=0;
End:
	return ret;
}
int test_mode_xts ()
{	
	uint8_t encbuff[MAX_BUFF_SIZE] = {0};
	uint8_t decbuff[MAX_BUFF_SIZE] = {0};
	uint8_t iv[]={0xf2,0xb8,0x67,0x93,0xb2,0x9e,0x73,0x0e,0x4a,0x62,0x7b,0x6e,0xe1,0x61,0x70,0x6c};
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
	uint32_t keylen;	
	uint8_t inbuff[MAX_BUFF_SIZE] = {0};
	int ret;	
	unsigned int inlen,prev_inlen=0,i;
	int j;
		
	for (inlen = START_PACKET_SIZE; inlen <= MAX_BUFF_SIZE; inlen+=inlen) {
		for (i = prev_inlen; i < inlen; i++) {
			inbuff[i] = cvmx_rng_get_random8 (); 
		}
		j=0;
		for (keylen = 128; keylen <= 256; keylen += keylen) {			
			XTS128_CONTEXT ctx;
			AES_KEY k1,k2;

			//Encrypt
			AES_set_encrypt_key (key1[j], keylen, &k1);	
			AES_set_encrypt_key (key2[j], keylen, &k2);
			ctx.key1 = &k1;	
			ctx.key2 = &k2;
			ctx.block1 = (block128_f)AES_encrypt;	
			ctx.block2 = (block128_f)AES_encrypt;
			ret = CRYPTO_xts128_encrypt (&ctx, iv, inbuff, encbuff, inlen, AES_ENCRYPT);			
			
			if (ret != 0){
				printf ("CRYPTO_xts_encrypt Failed\n");
				ret = -1;
				goto End;
			}

			//Decrypt		
			AES_set_encrypt_key (key1[j], keylen, &k1);	
			AES_set_encrypt_key (key2[j], keylen, &k2);
			ctx.key1 = &k1;	
			ctx.key2 = &k2;
			ctx.block1 = (block128_f)AES_decrypt;	
			ctx.block2 = (block128_f)AES_encrypt;
			ret = CRYPTO_xts128_encrypt(&ctx, iv, encbuff, decbuff, inlen, AES_DECRYPT);			

			if (ret != 0){
				printf ("CRYPTO_xts_decrypt Failed\n");
				ret = -1;
				goto End;
			}
			
			if (memcmp (inbuff, decbuff, inlen)){
				DUMP_BUFF("Plain Text\n", inbuff, (signed)inlen);
				DUMP_BUFF("decrypt Text\n", decbuff, (signed)inlen);
				printf ("CRYPTO xts Failed\n");
				ret = -1;
				goto End;
			}
			j++;
		}	
		prev_inlen = inlen;
	}	
	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","MODE-XTS",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}

int test_mode_cts_kat ()
{		
	unsigned char key[16] = "chicken teriyaki";
	unsigned int keylen = 128;		
	uint8_t decrypttext[1024] = {0};
	uint8_t ciphertext[1024] = {0};
	unsigned char test_iv[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};	
	unsigned char iv[16];
	uint8_t input[1024] = {0};
	int inlen;
	unsigned int i;	
	int cnt = 0,ret,fail = 0;
	
	AES_KEY encks, decks;
	
	for(i = 0;i < sizeof(mode_cts_vector)/sizeof(mode_cts_vector[0]); i++) {
			
		str2hex (mode_cts_vector[i].inbuff, input, &inlen);
		
		AES_set_encrypt_key (key, keylen, &encks);
		AES_set_decrypt_key (key, keylen, &decks);
	
		/* test block-based encryption */	
		memcpy(iv, test_iv, sizeof(test_iv));
		CRYPTO_cts128_encrypt_block (input, ciphertext, inlen, &encks, iv, (block128_f)AES_encrypt);
	
		/* test block-based decryption */	
		memcpy(iv, test_iv, sizeof(test_iv));	
		CRYPTO_cts128_decrypt_block (ciphertext, decrypttext, inlen, &decks, iv, (block128_f)AES_decrypt);	
		
		if (memcmp (input, decrypttext, inlen)) {	
			DUMP_BUFF ("decrypttext\n", decrypttext, (signed)inlen);		
			DUMP_BUFF ("input\n", input, (signed)inlen);
			printf("CRYPTO_cts128_block failed\n"); 	
			fail++;
			ret = -1;
			goto End;
		}
		
		/* test streamed encryption */	
		memcpy (iv, test_iv, sizeof(test_iv));	
		CRYPTO_cts128_encrypt (input, ciphertext, inlen, &encks, iv, (cbc128_f)AES_cbc_encrypt);	
		
		/* test streamed decryption */	
		memcpy(iv, test_iv, sizeof(test_iv));
		CRYPTO_cts128_decrypt (ciphertext, decrypttext, inlen, &decks, iv, (cbc128_f)AES_cbc_encrypt);	

		if (memcmp(decrypttext, input, inlen)) {	
			DUMP_BUFF ("decrypttext\n", decrypttext, inlen);	
			DUMP_BUFF ("input\n", input, inlen);
			printf("CRYPTO_cts128 failed\n");
			fail++;
			ret = -1;
			goto End;
		}
				
		/* test block-based encryption */
		memcpy (iv, test_iv, sizeof(test_iv));
		CRYPTO_nistcts128_encrypt_block (input, ciphertext, inlen, &encks, iv, (block128_f)AES_encrypt);	
		
		/* test block-based decryption */
		memcpy (iv, test_iv, sizeof(test_iv));
		CRYPTO_nistcts128_decrypt_block (ciphertext, decrypttext, inlen, &decks, iv, (block128_f)AES_decrypt);	
		
		if (memcmp (decrypttext, input, inlen)) {	
			DUMP_BUFF("decrypttext\n", decrypttext, inlen);	
			DUMP_BUFF("input\n", input, inlen);
			printf("CRYPTO_cts128 failed\n");
			fail++;
			ret = -1;
			goto End;
		}
		
		/* test streamed encryption */
		memcpy (iv, test_iv, sizeof(test_iv));
		CRYPTO_nistcts128_encrypt (input, ciphertext, inlen, &encks, iv, (cbc128_f)AES_cbc_encrypt);	
		
		/* test streamed decryption */
		memcpy(iv, test_iv, sizeof(test_iv));
		CRYPTO_nistcts128_decrypt (ciphertext, decrypttext, inlen, &decks, iv, (cbc128_f)AES_cbc_encrypt);	
		if (memcmp (decrypttext, input, inlen)) {	
			DUMP_BUFF ("decrypttext\n", decrypttext, inlen);	
			DUMP_BUFF ("input\n", input, inlen);
			printf("CRYPTO_cts128 failed\n");
			fail++;
			ret = -1;
			goto End;
		}
		cnt++;
	}
	ret = 0;	
	if (fail)
		printf("***");
	if (cvmx_is_init_core()) {
		printf ("%-20s :Total Test vectors tested: %d passed : %d failed : %d\n","MODE-CTS",cnt,(cnt-fail),fail);
	}
End: 
	return ret;
}

int test_mode_cts ()
{		
	unsigned char key[16] = "chicken teriyaki";
	unsigned int keylen = 128;		
	uint8_t decrypttext[MAX_BUFF_SIZE] = {0};
	uint8_t ciphertext[MAX_BUFF_SIZE] = {0};
	unsigned char test_iv[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};	
	unsigned char iv[16];
	uint8_t input[MAX_BUFF_SIZE] = {0};
	unsigned int inlen,prev_inlen=0,i;
	int ret = 0;	
	AES_KEY encks, decks;
	
	AES_set_encrypt_key(key,keylen,&encks);
	AES_set_decrypt_key(key,keylen,&decks);
		
	for (inlen = START_PACKET_SIZE; inlen <= MAX_BUFF_SIZE; inlen+=inlen) {
		for (i = prev_inlen; i < inlen; i++) {
			input[i] = cvmx_rng_get_random8 (); 
		}
	
		/* test block-based encryption */	
		memcpy(iv,test_iv,sizeof(test_iv));
		CRYPTO_cts128_encrypt_block(input,ciphertext,inlen,&encks,iv,(block128_f)AES_encrypt);
	
		/* test block-based decryption */	
		memcpy(iv,test_iv,sizeof(test_iv));	
		CRYPTO_cts128_decrypt_block(ciphertext,decrypttext,inlen,&decks,iv,(block128_f)AES_decrypt);	
		
		if (memcmp (input, decrypttext, inlen)) {	
			DUMP_BUFF ("decrypttext\n", decrypttext, (signed)inlen);		
			DUMP_BUFF ("input\n", input, (signed)inlen);
			printf("CRYPTO_cts128_block failed\n"); 	
			ret = -1;
			goto End;
		}
		
		/* test streamed encryption */	
		memcpy(iv,test_iv,sizeof(test_iv));	
		CRYPTO_cts128_encrypt(input,ciphertext,inlen,&encks,iv,(cbc128_f)AES_cbc_encrypt);	
		
		/* test streamed decryption */	
		memcpy(iv,test_iv,sizeof(test_iv));
		CRYPTO_cts128_decrypt(ciphertext,decrypttext,inlen,&decks,iv,(cbc128_f)AES_cbc_encrypt);	

		if (memcmp(decrypttext,input,inlen)) {		
			DUMP_BUFF ("decrypttext\n", decrypttext, (signed)inlen);	
			DUMP_BUFF ("input\n", input, (signed)inlen);	
			printf("CRYPTO_cts128 failed\n"); 
			ret = -1;
			goto End;
		}
		prev_inlen = inlen;
	}	
	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","MODE-CTS",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End:
	return ret;
}

int test_mode_ccm_kat ()
{
	unsigned int i;
	uint8_t cipher_text[50], enc_packet[MAX_BUFF_SIZE]; 
	uint8_t plain_text[50], dec_packet[MAX_BUFF_SIZE], input_packet[MAX_BUFF_SIZE];
	int cnt = 0, fail = 0, ret = 0;
	uint8_t *pin;
	uint8_t *cin;	
	uint8_t auth[16];	
	CCM128_CONTEXT ctx;	
	AES_KEY key1;
	
	for (i = 0; i < sizeof(mode_ccm_vector)/sizeof(mode_ccm_vector[0]); i++) {
		mode_ccm_nist_t packet = mode_ccm_vector[i];
				
		//Encrypt	
		pin = (packet.input+packet.alen);
		AES_set_encrypt_key ((uint8_t *)packet.key, packet.klen, &key1);
		CRYPTO_ccm128_init (&ctx, packet.m, packet.l, &key1, (block128_f)AES_encrypt);				
		CRYPTO_ccm128_setiv (&ctx, (unsigned char *)packet.nonce, sizeof(packet.nonce), packet.plen);		
		CRYPTO_ccm128_aad (&ctx, packet.input, packet.alen);		
		ret = CRYPTO_ccm128_encrypt (&ctx, pin, cipher_text, packet.plen);		
		CRYPTO_ccm128_tag (&ctx, auth, sizeof(auth));	
		
		if(ret!=0) {
			printf("CRYPTO_ccm128 encrypt Failed\n");
			ret=-1;	
			goto End;
		}

		memset(enc_packet,0,MAX_BUFF_SIZE);
		memcpy(enc_packet, packet.input, packet.alen);
		memcpy((enc_packet+packet.alen), cipher_text,packet.plen);
		memcpy((enc_packet+packet.alen+packet.plen), auth, packet.m);
        
		if (memcmp(enc_packet, packet.output, (packet.alen+packet.plen+packet.m))) {
			printf("CRYPTO_ccm128 Failed during Encryption\n");	
			ret = -1;
			goto End;
		}
			
		//Decrypt
		cin = cipher_text;
		CRYPTO_ccm128_init (&ctx, packet.m, packet.l, &key1, (block128_f)AES_encrypt);			
		CRYPTO_ccm128_setiv (&ctx, (unsigned char *)packet.nonce, sizeof(packet.nonce), packet.plen);	
		CRYPTO_ccm128_aad (&ctx, packet.input, packet.alen);	
		ret = CRYPTO_ccm128_decrypt (&ctx, cin, plain_text, packet.plen);			
		CRYPTO_ccm128_tag (&ctx, auth, sizeof(auth));	

		if(ret!=0) {
			printf("CRYPTO_ccm128 decrypt Failed\n");
			ret=-1;	
			goto End;
		}

		memset(dec_packet, 0, MAX_BUFF_SIZE);
		memset(input_packet, 0, MAX_BUFF_SIZE);
		memcpy(dec_packet, packet.input, packet.alen);
		memcpy((dec_packet+packet.alen), plain_text,packet.plen);
		memcpy((input_packet), packet.input, (packet.alen+packet.plen));
		memcpy((dec_packet+packet.alen+packet.plen), auth, packet.m);
		memcpy((input_packet+packet.alen+packet.plen), auth, packet.m);

		if (memcmp(dec_packet, input_packet, (packet.alen+packet.plen+packet.m))){
			printf("CRYPTO_ccm128 Failed during Decryption\n");
			ret = -1;	
			fail++;
			goto End;
		}
		cnt++;
	}
End:
	if (cvmx_is_init_core())
		printf("%-20s :Total Test vectors tested: %d passed : %d failed : %d\n","MODE-CCM",cnt,(cnt-fail),fail);
	return ret;
}

int test_mode_ccm ()
{			
	uint32_t m = 8; 
	uint32_t l = 2;
	uint32_t alen = 8; 
	uint64_t nonce[2] = {0x00000003020100a0ull,0xa1a2a3a4a5000000ull};
	uint64_t key[][4] = {
							{0xc0c1c2c3c4c5c6c7ull,0xc8c9cacbcccdcecfull},
        					{0x146A163BBF10746Eull,0x7C1201546BA46DE7ull,0x69BE23F9D7CC2C80ull},
        					{0x9074B1AE4CA3342Full,0xE5BF6F14BCF2F279ull,0x04F0B15179D95A65ull,0x4F61E699692E6F71ull},
						};
	uint8_t ain[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};	
	uint8_t pin[MAX_BUFF_SIZE], dec[MAX_BUFF_SIZE];	
	uint8_t auth1[16] = {0},auth2[16] = {0};	
	uint8_t cin[MAX_BUFF_SIZE]; 	
	uint32_t keylen = 128;	
	unsigned int inlen;	
	unsigned int prev_inlen=0;	
	unsigned int i = 0;		
	int ret = 0,j;

	for (inlen = START_PACKET_SIZE; inlen <= MAX_BUFF_SIZE; inlen+=inlen) {		
		for (i = prev_inlen; i < inlen; i++) {
			pin[i] = cvmx_rng_get_random8 (); 
		}
		j=0;
		for (keylen = 128; keylen <= 256; keylen += 64) {	
			CCM128_CONTEXT ctx;	
			AES_KEY key1;
			
			//Encrypt	
			AES_set_encrypt_key ((uint8_t *)key[j], keylen, &key1);
			CRYPTO_ccm128_init (&ctx, m, l, &key1, (block128_f)AES_encrypt);				
			CRYPTO_ccm128_setiv (&ctx, (unsigned char *)nonce, sizeof(nonce), inlen);		
			CRYPTO_ccm128_aad (&ctx, ain, alen);		
			ret = CRYPTO_ccm128_encrypt (&ctx, pin, cin, inlen);		
			CRYPTO_ccm128_tag (&ctx, auth1, sizeof(auth1));	

			if(ret!=0) {
				printf("CRYPTO_ccm128 Encrypt Failed\n");
				ret=-1;	
				goto End;
			}
	
			//Decrypt	
			AES_set_encrypt_key ((uint8_t *)key[j], keylen, &key1);
			CRYPTO_ccm128_init (&ctx, m, l, &key1, (block128_f)AES_encrypt);			
			CRYPTO_ccm128_setiv (&ctx, (unsigned char *)nonce, sizeof(nonce), inlen);	
			CRYPTO_ccm128_aad (&ctx, ain, alen);	
			ret = CRYPTO_ccm128_decrypt (&ctx, cin, dec, inlen);			
			CRYPTO_ccm128_tag (&ctx, auth2, sizeof(auth2));	

			if(ret!=0) {
				printf("CRYPTO_ccm128 decrypt Failed\n");
				ret=-1;	
				goto End;
			}

			if (memcmp(pin, dec, inlen)) {	
				DUMP_BUFF("Plain Text\n", pin, (signed)inlen);
				DUMP_BUFF("Decrypt Text\n", dec, (signed)inlen);
				printf("CRYPTO_ccm_128 Failed \n");
				ret = -1;
				goto End;
			}
				
			if (memcmp (auth1, auth2,sizeof(auth1))) {
				DUMP_BUFF("auth1\n", auth1, 16);	
				DUMP_BUFF("auth2\n", auth2, 16);
				printf("auth mismatch\n");	
				ret = -1;
				goto End;	
			}
			j++;
		}	
	}
	if (cvmx_is_init_core()) 
		printf ("Tested %-20s: Packet Size From %d to %d : %s\n","MODE-CCM",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
End:
	return ret;
}

