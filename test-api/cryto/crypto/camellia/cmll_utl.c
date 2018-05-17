/* crypto/camellia/cmll_utl.c -*- mode:C; c-file-style: "eay" -*- */
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
 *
 */
 
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/camellia.h>
#include "openssl/cmll_locl.h"
#include "cvmx.h"

#ifdef OCTEON_OPENSSL
const int KSFT1[26] = {
   0,64,0,64,15,79,15,79,30,94,45,109,45,124,60,124,77,13,
   94,30,94,30,111,47,111,47
};
const int KIDX1[26] = {
   0,0,4,4,0,0,4,4,4,4,0,0,4,0,4,4,0,0,0,0,4,4,0,0,4,4
};
const int KSFT2[34] = {
   0,64,0,64,15,79,15,79,30,94,30,94,45,109,45,109,60,124,
   60,124,60,124,77,13,77,13,94,30,94,30,111,47,111,47
};
const int KIDX2[34] = {
   0,0,12,12,8,8,4,4,8,8,12,12,0,0,4,4,0,0,8,8,12,12,
   0,0,4,4,8,8,4,4,0,0,12,12
};

const uint64_t CMLL_SIGMA[6] = {
   0xa09e667f3bcc908b,
   0xb67ae8584caa73b2,
   0xc6ef372fe94f82be,
   0x54ff53a5f1d36f1c,
   0x10e527fade682d1d,
   0xb05688c2b3e6c1fd
};


static inline uint64_t RotateBlock(const uint32_t *x,const int n)
{
	uint32_t res0,res1;
	int r;

	r=(n&31);

	if(r)
	{
      		res0=x[((n>>5)+0)&3]<<r^x[((n>>5)+1)&3]>>(32-r);
		res1=x[((n>>5)+1)&3]<<r^x[((n>>5)+2)&3]>>(32-r);
	}
	else
	{
		res0=x[((n>>5)+0)&3];
		res1=x[((n>>5)+1)&3];
	}

	return ((((uint64_t)res0)<<32)|res1);
}
#endif /* OCTEON_OPENSSL */

int Camellia_set_key(const unsigned char *userKey, const int bits,
	CAMELLIA_KEY *key)
	{
#ifdef OCTEON_OPENSSL
	int i, keylen;

	if(!userKey || !key)
		return -1;

	if(bits!=128 && bits!=192 && bits!=256)
		return -2;

	key->cvm_key_len = bits;

	keylen = bits / 64;
	memset(&(key->cvmkey[0]), 0, 4 * sizeof(uint64_t));
	memset(&(key->round_keys[0]),0,34*sizeof(uint64_t));
	memcpy(&(key->cvmkey[0]), userKey,bits>>3);
	keylen=bits;

#ifdef CMLL_DEBUG
	{
	int z;
	printf("%s:\n",__func__);
	printf("keylen %d\n",key->cvm_key_len);
	for(z=0;z<(bits>>3);z++)
		printf("%02x%c",userKey[z],(z+1)%16?' ':'\n');
	printf("\n");
	}
#endif

	if(OCTEON_IS_OCTEON3())
	{
		uint64_t t[8];
		uint32_t u[16];

		memset(t,0,8*sizeof(uint64_t));
		memset(u,0,16*sizeof(uint32_t));
		
		if(keylen==128)
		{
			t[0] = key->cvmkey[0];
			t[1] = key->cvmkey[1];
			t[2] = 0;
			t[3] = 0;
		}
		else if(keylen==192)
		{
			t[0] = key->cvmkey[0];
			t[1] = key->cvmkey[1];
			t[2] = key->cvmkey[2];
			t[3] = t[2] ^ 0xFFFFFFFFFFFFFFFFull;
		}
		else
		{
			assert(keylen==256);
			t[0] = key->cvmkey[0];
			t[1] = key->cvmkey[1];
			t[2] = key->cvmkey[2];
			t[3] = key->cvmkey[3];
		}
		
		CVMX_MT_CAMELLIA_RESINP(t[0] ^ t[2], 0);
		CVMX_MT_CAMELLIA_RESINP(t[1] ^ t[3], 1);
		
		CVMX_MT_CAMELLIA_ROUND(CMLL_SIGMA[0]);
		CVMX_MT_CAMELLIA_ROUND(CMLL_SIGMA[1]);
		
		CVMX_MF_CAMELLIA_RESINP(t[4], 0);
		CVMX_MF_CAMELLIA_RESINP(t[5], 1);
		t[4] ^= t[0];
		t[5] ^= t[1];
		CVMX_MT_CAMELLIA_RESINP(t[4], 0);
		CVMX_MT_CAMELLIA_RESINP(t[5], 1);
		
		CVMX_MT_CAMELLIA_ROUND(CMLL_SIGMA[2]);
		CVMX_MT_CAMELLIA_ROUND(CMLL_SIGMA[3]);
		
		CVMX_MF_CAMELLIA_RESINP(t[4], 0);
		CVMX_MF_CAMELLIA_RESINP(t[5], 1);
		
		u[0] = (uint32_t)(t[0] >> 32);
		u[1] = (uint32_t)(t[0] >>  0);
		u[2] = (uint32_t)(t[1] >> 32);
		u[3] = (uint32_t)(t[1] >>  0);
		u[4] = (uint32_t)(t[4] >> 32);
		u[5] = (uint32_t)(t[4] >>  0);
		u[6] = (uint32_t)(t[5] >> 32);
		u[7] = (uint32_t)(t[5] >>  0);
		
		if(keylen==128)
		{
			for(i=0;i<26;i+=2)
			{
				key->round_keys[i+0]=RotateBlock((u+KIDX1[i+0]),KSFT1[i+0]);
				key->round_keys[i+1]=RotateBlock((u+KIDX1[i+1]),KSFT1[i+1]);
			}
		}
		else
		{
			CVMX_MT_CAMELLIA_RESINP(t[4] ^ t[2], 0);
			CVMX_MT_CAMELLIA_RESINP(t[5] ^ t[3], 1);
			
			CVMX_MT_CAMELLIA_ROUND(CMLL_SIGMA[4]);
			CVMX_MT_CAMELLIA_ROUND(CMLL_SIGMA[5]);
			
			CVMX_MF_CAMELLIA_RESINP(t[6], 0);
			CVMX_MF_CAMELLIA_RESINP(t[7], 1);
			
			u[ 8] = (uint32_t)(t[2] >> 32);
			u[ 9] = (uint32_t)(t[2] >>  0);
			u[10] = (uint32_t)(t[3] >> 32);
			u[11] = (uint32_t)(t[3] >>  0);
			u[12] = (uint32_t)(t[6] >> 32);
			u[13] = (uint32_t)(t[6] >>  0);
			u[14] = (uint32_t)(t[7] >> 32);
			u[15] = (uint32_t)(t[7] >>  0);
			
			for(i=0;i<34;i+=2)
			{
			   key->round_keys[i+0]=RotateBlock((u+KIDX2[i+0]),KSFT2[i+0]);
			   key->round_keys[i+1]=RotateBlock((u+KIDX2[i+1]),KSFT2[i+1]);
			}
		}
	}
	else
	{
		printf("Camellia Algorithm is supported only on CN7XXX chips.\n");
	}

	return 0;
#endif /* OCTEON_OPENSSL */

#ifdef OPENSSL_FIPS
	fips_cipher_abort(Camellia);
#endif
	return private_Camellia_set_key(userKey, bits, key);
	}
