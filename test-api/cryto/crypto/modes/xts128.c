/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
 *
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
 */

#include <openssl/crypto.h>
#include <openssl/modes_lcl.h>
#include <string.h>

#ifdef OCTEON_OPENSSL 
#include "cvmx.h"
#include "cvmx-key.h"
#include "openssl/aes.h"
#endif 

#ifndef MODES_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif
#include <assert.h>

int CRYPTO_xts128_encrypt(const XTS128_CONTEXT *ctx, const unsigned char iv[16],
	const unsigned char *inp, unsigned char *out,
	size_t len, int enc)
{
#ifdef OCTEON_OPENSSL 
	
  	uint64_t *ivec;
	uint64_t *input;
  	uint64_t *output;
	uint64_t x[2];
  	uint64_t oldtweak[2];
  	uint64_t rx[2];
  	int32_t j;
  	uint64_t all80  = 0x8080808080808080ull;
  	uint64_t all7f  = ~all80;
  	uint64_t lenby8, i=0;
	uint64_t upperbits, lsb, cout;
	AES_KEY *k2;
	AES_KEY *k1;
	union { u64 u[2]; u32 d[4]; u8 c[16]; } tweak, ctxtweak;
	ivec = (uint64_t *) iv;	
	
	if(len<16) {
		return -1;
	}

	if (!enc && (len%16)) len-=16;
   	
	k2=(AES_KEY *)ctx->key2;
	k1=(AES_KEY *)ctx->key1;
 	
	//Initialisation of key2
	switch (k2->cvm_keylen) {
		case 256:
			CVMX_MT_AES_KEY (k2->cvmkey[3], 3);
		case 192:
			CVMX_MT_AES_KEY (k2->cvmkey[2], 2);
		case 128:	
  			CVMX_MT_AES_KEY (k2->cvmkey[1], 1);	
			CVMX_MT_AES_KEY (k2->cvmkey[0], 0);
	}
	CVMX_MT_AES_KEYLENGTH (k2->cvm_keylen / 64 - 1);
		
	//block output encryption of IV
	CVMX_MT_AES_ENC0(ivec[0]);
  	CVMX_MT_AES_ENC1(ivec[1]);
  	CVMX_MF_AES_RESULT(tweak.u[0],0);
  	CVMX_MF_AES_RESULT(tweak.u[1],1);
	
 	//Initialisation of key1	
	switch (k1->cvm_keylen) {
		case 256:
			CVMX_MT_AES_KEY (k1->cvmkey[3], 3);
		case 192:
			CVMX_MT_AES_KEY (k1->cvmkey[2], 2);
		case 128:	
  			CVMX_MT_AES_KEY (k1->cvmkey[1], 1);	
			CVMX_MT_AES_KEY (k1->cvmkey[0], 0);
	}
	CVMX_MT_AES_KEYLENGTH (k1->cvm_keylen / 64 - 1);

	lenby8 = len /16 * 2;
  	lenby8 -= 2;
		
	CVMX_PREFETCH0 (inp);

	input = (uint64_t*)inp;
  	output = (uint64_t*)out;
  	ctxtweak = tweak;
	
	if(len>=48) {
		x[0] = input[0] ^ ctxtweak.u[0];
    	x[1] = input[1] ^ ctxtweak.u[1];
		
	if(AES_ENCRYPT == enc) {
		CVMX_MT_AES_ENC0(x[0]);
    	CVMX_MT_AES_ENC1(x[1]);
	}
	else {
    	CVMX_MT_AES_DEC0(x[0]);
    	CVMX_MT_AES_DEC1(x[1]);
	}
	
	oldtweak[0] = ctxtweak.u[0];
    oldtweak[1] = ctxtweak.u[1];
		
	upperbits = ctxtweak.u[0] & all80;
    ctxtweak.u[0] &= all7f;
    lsb = upperbits & 0xffull;
    ctxtweak.u[0] = (ctxtweak.u[0]<<1) + (upperbits>>15);

    upperbits = ctxtweak.u[1] & all80;
    ctxtweak.u[1] &= all7f;
    cout = upperbits & 0xffull;
    upperbits = (lsb<<56) | (upperbits>>8);
    ctxtweak.u[1] = (ctxtweak.u[1]<<1) + (upperbits>>7);

    ctxtweak.u[0] ^= (cout?0x87ull<<56:0);
    
    input += 2;
    x[0] = input[0] ^ ctxtweak.u[0];
    x[1] = input[1] ^ ctxtweak.u[1];

    CVMX_MF_AES_RESULT(rx[0],0);
    CVMX_MF_AES_RESULT(rx[1],1);

    for( i = 2; i < lenby8; i += 2 ) {
      	if(AES_ENCRYPT == enc) {
			CVMX_MT_AES_ENC0(x[0]);
      		CVMX_MT_AES_ENC1(x[1]);
		}
		else {
			CVMX_MT_AES_DEC0(x[0]);
      		CVMX_MT_AES_DEC1(x[1]);
		}

      	CVMX_PREFETCH0(input+16);

      	output[0] = rx[0] ^ oldtweak[0];
      	output[1] = rx[1] ^ oldtweak[1];
      	output += 2;
      
      	oldtweak[0] = ctxtweak.u[0];
      	oldtweak[1] = ctxtweak.u[1];

      	upperbits = ctxtweak.u[0] & all80;
      	ctxtweak.u[0] &= all7f;
      	lsb = upperbits & 0xffull;
      	ctxtweak.u[0] = (ctxtweak.u[0]<<1) + (upperbits>>15);

      	upperbits = ctxtweak.u[1] & all80;
      	ctxtweak.u[1] &= all7f;
      	cout = upperbits & 0xffull;
      	upperbits = (lsb<<56) | (upperbits>>8);
      	ctxtweak.u[1] = (ctxtweak.u[1]<<1) + (upperbits>>7);

      	ctxtweak.u[0] ^= (cout?0x87ull<<56:0);

      	input += 2;
      	x[0] = input[0] ^ ctxtweak.u[0];
      	x[1] = input[1] ^ ctxtweak.u[1];

      	CVMX_MF_AES_RESULT(rx[0],0);
      	CVMX_MF_AES_RESULT(rx[1],1);
    }
	
	if(AES_ENCRYPT == enc) {
    	CVMX_MT_AES_ENC0(x[0]);
    	CVMX_MT_AES_ENC1(x[1]);
	}
	else {
		CVMX_MT_AES_DEC0(x[0]);
    	CVMX_MT_AES_DEC1(x[1]);
	}

    output[0] = rx[0] ^ oldtweak[0];
    output[1] = rx[1] ^ oldtweak[1];
    output += 2;

    oldtweak[0] = ctxtweak.u[0];
    oldtweak[1] = ctxtweak.u[1];

    upperbits = ctxtweak.u[0] & all80;
    ctxtweak.u[0] &= all7f;
    lsb = upperbits & 0xffull;
    ctxtweak.u[0] = (ctxtweak.u[0]<<1) + (upperbits>>15);

    upperbits = ctxtweak.u[1] & all80;
    ctxtweak.u[1] &= all7f;
    cout = upperbits & 0xffull;
    upperbits = (lsb<<56) | (upperbits>>8);
    ctxtweak.u[1] = (ctxtweak.u[1]<<1) + (upperbits>>7);

    ctxtweak.u[0] ^= (cout?0x87ull<<56:0);
    
    i+=2;
	
	if(AES_ENCRYPT == enc) {
    	i<<=3;
	}
	
    CVMX_MF_AES_RESULT(rx[0],0);
    CVMX_MF_AES_RESULT(rx[1],1);

    output[0] = rx[0] ^ oldtweak[0];
    output[1] = rx[1] ^ oldtweak[1];

  	} else if(len>=32 ){
		
		x[0] = input[0] ^ ctxtweak.u[0];
    	x[1] = input[1] ^ ctxtweak.u[1];
    
    	if(AES_ENCRYPT == enc) {
			CVMX_MT_AES_ENC0(x[0]);
    		CVMX_MT_AES_ENC1(x[1]);
		}
		else {
			CVMX_MT_AES_DEC0(x[0]);
    		CVMX_MT_AES_DEC1(x[1]);
		}

    	oldtweak[0] = ctxtweak.u[0];
    	oldtweak[1] = ctxtweak.u[1];

    	upperbits = ctxtweak.u[0] & all80;
    	ctxtweak.u[0] &= all7f;
    	lsb = upperbits & 0xffull;
    	ctxtweak.u[0] = (ctxtweak.u[0]<<1) + (upperbits>>15);

    	upperbits = ctxtweak.u[1] & all80;
    	ctxtweak.u[1] &= all7f;
    	cout = upperbits & 0xffull;
    	upperbits = (lsb<<56) | (upperbits>>8);
    	ctxtweak.u[1] = (ctxtweak.u[1]<<1) + (upperbits>>7);

    	ctxtweak.u[0] ^= (cout?0x87ull<<56:0);
    
    	input += 2;
    	x[0] = input[0] ^ ctxtweak.u[0];
    	x[1] = input[1] ^ ctxtweak.u[1];

    	CVMX_MF_AES_RESULT(rx[0],0);
    	CVMX_MF_AES_RESULT(rx[1],1);
	
    	if(AES_ENCRYPT == enc) {
			CVMX_MT_AES_ENC0(x[0]);
    		CVMX_MT_AES_ENC1(x[1]);
		}
		else {
			CVMX_MT_AES_DEC0(x[0]);
    		CVMX_MT_AES_DEC1(x[1]);
		}

    	output[0] = rx[0] ^ oldtweak[0];
    	output[1] = rx[1] ^ oldtweak[1];
    	output += 2;

    	oldtweak[0] = ctxtweak.u[0];
    	oldtweak[1] = ctxtweak.u[1];

    	upperbits = ctxtweak.u[0] & all80;
    	ctxtweak.u[0] &= all7f;
    	lsb = upperbits & 0xffull;
    	ctxtweak.u[0] = (ctxtweak.u[0]<<1) + (upperbits>>15);

    	upperbits = ctxtweak.u[1] & all80;
    	ctxtweak.u[1] &= all7f;
    	cout = upperbits & 0xffull;
    	upperbits = (lsb<<56) | (upperbits>>8);
    	ctxtweak.u[1] = (ctxtweak.u[1]<<1) + (upperbits>>7);

    	ctxtweak.u[0] ^= (cout?0x87ull<<56:0);
    
    	i=32;
    	CVMX_MF_AES_RESULT(rx[0],0);
    	CVMX_MF_AES_RESULT(rx[1],1);

    	output[0] = rx[0] ^ oldtweak[0];
    	output[1] = rx[1] ^ oldtweak[1];

  	} else if(len>=16) {
    	
		x[0] = input[0] ^ ctxtweak.u[0];
    	x[1] = input[1] ^ ctxtweak.u[1];
    	
    	if(AES_ENCRYPT == enc) {
			CVMX_MT_AES_ENC0(x[0]);
    		CVMX_MT_AES_ENC1(x[1]);
		}
		else {
			CVMX_MT_AES_DEC0(x[0]);
    		CVMX_MT_AES_DEC1(x[1]);
		}

    	oldtweak[0] = ctxtweak.u[0];
    	oldtweak[1] = ctxtweak.u[1];

    	upperbits = ctxtweak.u[0] & all80;
    	ctxtweak.u[0] &= all7f;
    	lsb = upperbits & 0xffull;
    	ctxtweak.u[0] = (ctxtweak.u[0]<<1) + (upperbits>>15);

    	upperbits = ctxtweak.u[1] & all80;
    	ctxtweak.u[1] &= all7f;
    	cout = upperbits & 0xffull;
    	upperbits = (lsb<<56) | (upperbits>>8);
    	ctxtweak.u[1] = (ctxtweak.u[1]<<1) + (upperbits>>7);

    	ctxtweak.u[0] ^= (cout?0x87ull<<56:0);
    	
    	if(AES_ENCRYPT == enc) {
			i = 16;
		}
		else {
			i = 2;
		}

    	CVMX_MF_AES_RESULT(rx[0],0);
    	CVMX_MF_AES_RESULT(rx[1],1);

    	output[0] = rx[0] ^ oldtweak[0];
    	output[1] = rx[1] ^ oldtweak[1];
  	}
  
  /* end = cvmx_get_cycle(); */
  /* printf("cycles = %ld\n",end-start); */

	
    if(AES_ENCRYPT == enc) {
		if(cvmx_unlikely(len%16)) {
  			uint8_t x[16];
    		uint64_t *CT;
    		uint64_t *X;
  
    		for(j=0;(i+j)<len;j++) {
      			x[j] = inp[i+j] ;
      			out[i+j] = out[i+j-16];
    		}

    		for(;j<16;j++) {
      			x[j] = out[i+j-16];
    		}
  
    		X = (uint64_t*)x;
    		X[0] = X[0] ^ tweak.u[0];
    		X[1] = X[1] ^ tweak.u[1];
    		CVMX_MT_AES_ENC0(X[0]);
    		CVMX_MT_AES_ENC1(X[1]);
    		CVMX_MF_AES_RESULT(X[0],0);
    		CVMX_MF_AES_RESULT(X[1],1);

    		CT = (uint64_t*)&out[i-16];

    		CT[0] = X[0] ^ tweak.u[0];
    		CT[1] = X[1] ^ tweak.u[1];
  		}
	}
	else {
		if(cvmx_unlikely(len%16)) {
    	uint8_t y[16];
    	uint64_t *Y = (uint64_t*)y;
    	uint8_t *T=(uint8_t*)oldtweak;
    
    	x[0] = input[0] ^ tweak.u[0];
    	x[1] = input[1] ^ tweak.u[1];

    	CVMX_MT_AES_DEC0(x[0]);
    	CVMX_MT_AES_DEC1(x[1]);

    	CVMX_MF_AES_RESULT(x[0],0);
    	CVMX_MF_AES_RESULT(x[1],1);

    	output[0] = x[0] ^ tweak.u[0];
    	output[1] = x[1] ^ tweak.u[1];

    	i <<= 3;
    	for(j=0;(i+j)<len;j++) {
      		out[i+j] = out[i+j-16];
      		y[j] = inp[i+j] ^ T[j];
    	}

    	for(;j<16;j++) {
      		y[j] = inp[i+j-16] ^ T[j] ;
    	}

    	CVMX_MT_AES_DEC0(Y[0]);
    	CVMX_MT_AES_DEC1(Y[1]);
    	CVMX_MF_AES_RESULT(Y[0],0);
    	CVMX_MF_AES_RESULT(Y[1],1);

    	output = (uint64_t*)&out[i-16];
    	output[0] = Y[0] ^ oldtweak[0];
    	output[1] = Y[1] ^ oldtweak[1];
  		}
	} 
#else
	const union { long one; char little; } is_endian = {1};
	union { u64 u[2]; u32 d[4]; u8 c[16]; } tweak, scratch;
	unsigned int i;

	if (len<16) return -1;

	memcpy(tweak.c, iv, 16);

	(*ctx->block2)(tweak.c,tweak.c,ctx->key2);

	if (!enc && (len%16)) len-=16;

	while (len>=16) {
#if defined(STRICT_ALIGNMENT)
		memcpy(scratch.c,inp,16);
		scratch.u[0] ^= tweak.u[0];
		scratch.u[1] ^= tweak.u[1];
#else
		scratch.u[0] = ((u64*)inp)[0]^tweak.u[0];
		scratch.u[1] = ((u64*)inp)[1]^tweak.u[1];
#endif
		(*ctx->block1)(scratch.c,scratch.c,ctx->key1);
#if defined(STRICT_ALIGNMENT)
		scratch.u[0] ^= tweak.u[0];
		scratch.u[1] ^= tweak.u[1];
		memcpy(out,scratch.c,16);
#else
		((u64*)out)[0] = scratch.u[0]^=tweak.u[0];
		((u64*)out)[1] = scratch.u[1]^=tweak.u[1];
#endif
		inp += 16;
		out += 16;
		len -= 16;

		if (len==0)	return 0;

		if (is_endian.little) {
			unsigned int carry,res;
			
			res = 0x87&(((int)tweak.d[3])>>31);
			carry = (unsigned int)(tweak.u[0]>>63);
			tweak.u[0] = (tweak.u[0]<<1)^res;
			tweak.u[1] = (tweak.u[1]<<1)|carry;
		}
		else {
			size_t c;

			for (c=0,i=0;i<16;++i) {
				/*+ substitutes for |, because c is 1 bit */ 
				c += ((size_t)tweak.c[i])<<1;
				tweak.c[i] = (u8)c;
				c = c>>8;
			}
			tweak.c[0] ^= (u8)(0x87&(0-c));
		}
	}
	if (enc) {
		for (i=0;i<len;++i) {
			u8 c = inp[i];
			out[i] = scratch.c[i];
			scratch.c[i] = c;
		}
		scratch.u[0] ^= tweak.u[0];
		scratch.u[1] ^= tweak.u[1];
		(*ctx->block1)(scratch.c,scratch.c,ctx->key1);
		scratch.u[0] ^= tweak.u[0];
		scratch.u[1] ^= tweak.u[1];
		memcpy(out-16,scratch.c,16);
	}
	else {
		union { u64 u[2]; u8 c[16]; } tweak1;

		if (is_endian.little) {
			unsigned int carry,res;

			res = 0x87&(((int)tweak.d[3])>>31);
			carry = (unsigned int)(tweak.u[0]>>63);
			tweak1.u[0] = (tweak.u[0]<<1)^res;
			tweak1.u[1] = (tweak.u[1]<<1)|carry;
		}
		else {
			size_t c;

			for (c=0,i=0;i<16;++i) {
				/*+ substitutes for |, because c is 1 bit */ 
				c += ((size_t)tweak.c[i])<<1;
				tweak1.c[i] = (u8)c;
				c = c>>8;
			}
			tweak1.c[0] ^= (u8)(0x87&(0-c));
		}
#if defined(STRICT_ALIGNMENT)
		memcpy(scratch.c,inp,16);
		scratch.u[0] ^= tweak1.u[0];
		scratch.u[1] ^= tweak1.u[1];
#else
		scratch.u[0] = ((u64*)inp)[0]^tweak1.u[0];
		scratch.u[1] = ((u64*)inp)[1]^tweak1.u[1];
#endif
		(*ctx->block1)(scratch.c,scratch.c,ctx->key1);
		scratch.u[0] ^= tweak1.u[0];
		scratch.u[1] ^= tweak1.u[1];

		for (i=0;i<len;++i) {
			u8 c = inp[16+i];
			out[16+i] = scratch.c[i];
			scratch.c[i] = c;
		}
		scratch.u[0] ^= tweak.u[0];
		scratch.u[1] ^= tweak.u[1];
		(*ctx->block1)(scratch.c,scratch.c,ctx->key1);
#if defined(STRICT_ALIGNMENT)
		scratch.u[0] ^= tweak.u[0];
		scratch.u[1] ^= tweak.u[1];
		memcpy (out,scratch.c,16);
#else
		((u64*)out)[0] = scratch.u[0]^tweak.u[0];
		((u64*)out)[1] = scratch.u[1]^tweak.u[1];
#endif
	}
#endif
	return 0;
}
