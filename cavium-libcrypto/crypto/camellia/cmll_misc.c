/* crypto/camellia/camellia_misc.c -*- mode:C; c-file-style: "eay" -*- */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
#include "cmll_locl.h"
#include "cvmx.h"

const char CAMELLIA_version[]="CAMELLIA" OPENSSL_VERSION_PTEXT;

int private_Camellia_set_key(const unsigned char *userKey, const int bits,
	CAMELLIA_KEY *key)
	{
	if(!userKey || !key)
		return -1;
	if(bits != 128 && bits != 192 && bits != 256)
		return -2;
	key->grand_rounds = Camellia_Ekeygen(bits , userKey, key->u.rd_key);
	return 0;
	}

void Camellia_encrypt(const unsigned char *in, unsigned char *out,
	const CAMELLIA_KEY *key)
	{
#ifndef OCTEON_OPENSSL
	Camellia_EncryptBlock_Rounds(key->grand_rounds, in , key->u.rd_key , out);
#else
	uint64_t *inp, *outp;
	const uint64_t *rd_keys=&(key->round_keys[0]);

	inp  = (uint64_t *)in;
	outp = (uint64_t *)out;

#ifdef CMLL_DEBUG
	{
        int z;
	printf("%s:\n",__func__);
	printf("keylen %d\n",key->cvm_key_len);
        for(z=0;z<4;z++)
		printf("key[%d]: 0x%016llx\n",z,(uint64_t)key->cvmkey[z]);
	printf("input buffer:\n");
	for(z=0;z<16;z++)
		printf("%02x%c",in[z],(z+1)%16?' ':'\n');
	printf("\n");
	}
#endif
	if(OCTEON_IS_OCTEON3())
	{
		CVMX_MT_CAMELLIA_RESINP(inp[0] ^ *rd_keys++, 0); // 0
		CVMX_MT_CAMELLIA_RESINP(inp[1] ^ *rd_keys++, 1); // 1
		
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 2
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 3
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 4
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 5
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 6
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 7
		
		CVMX_MT_CAMELLIA_FL   (*rd_keys++); // 8
		CVMX_MT_CAMELLIA_FLINV(*rd_keys++); // 9
		
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 10
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 11
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 12
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 13
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 14
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 15
		
		CVMX_MT_CAMELLIA_FL   (*rd_keys++); // 16
		CVMX_MT_CAMELLIA_FLINV(*rd_keys++); // 17
		
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 18
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 19
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 20
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 21
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 22
		CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 23
		

		if(key->cvm_key_len!=128)
		{
			CVMX_MT_CAMELLIA_FL   (*rd_keys++); // 24
			CVMX_MT_CAMELLIA_FLINV(*rd_keys++); // 25
			
			CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 26
			CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 27
			CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 28
			CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 29
			CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 30
			CVMX_MT_CAMELLIA_ROUND(*rd_keys++); // 31
		}

		
		CVMX_MF_CAMELLIA_RESINP(outp[0], 1);
		CVMX_MF_CAMELLIA_RESINP(outp[1], 0);
		outp[0] ^= *rd_keys++;          // 24 or 32
		outp[1] ^= *rd_keys;            // 25 or 33
	}
	else
	{
		printf("Camellia Algorithm is supported only on CN7XXX chips.\n");
	}

#endif
	}

void Camellia_decrypt(const unsigned char *in, unsigned char *out,
	const CAMELLIA_KEY *key)
	{
#ifndef OCTEON_OPENSSL
	Camellia_DecryptBlock_Rounds(key->grand_rounds, in , key->u.rd_key , out);
#else
	uint64_t *inp, *outp;
	const uint64_t *roundkeyptr=&(key->round_keys[0]);
	const uint64_t *rd_keys;

	inp  = (uint64_t *)in;
	outp = (uint64_t *)out;

	if(OCTEON_IS_OCTEON3())
	{
		if(key->cvm_key_len==128)
		{
			rd_keys=roundkeyptr+23;
			CVMX_MT_CAMELLIA_RESINP(inp[0]^rd_keys[1],0);
			CVMX_MT_CAMELLIA_RESINP(inp[1]^rd_keys[2],1);
		}
		else
		{
			rd_keys=roundkeyptr+31;
			CVMX_MT_CAMELLIA_RESINP(inp[0] ^ rd_keys[1], 0); // 32
			CVMX_MT_CAMELLIA_RESINP(inp[1] ^ rd_keys[2], 1); // 33
			
			CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 31
			CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 30
			CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 29
			CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 28
			CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 27
			CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 26
			
			CVMX_MT_CAMELLIA_FL   (*rd_keys--); // 25
			CVMX_MT_CAMELLIA_FLINV(*rd_keys--); // 24
		}


#ifdef CMLL_DEBUG
		{
        	int z;
		printf("%s:\n",__func__);
		printf("keylen %d\n",key->cvm_key_len);
        	for(z=0;z<4;z++)
			printf("key[%d]: 0x%016llx\n",z,(uint64_t)key->cvmkey[z]);
		printf("input buffer:\n");
        	for(z=0;z<16;z++)
			printf("%02x%c",in[z],(z+1)%16?' ':'\n');
		printf("\n");
		}
#endif


		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 23
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 22
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 21
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 20
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 19
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 18
		
		CVMX_MT_CAMELLIA_FL   (*rd_keys--); // 17
		CVMX_MT_CAMELLIA_FLINV(*rd_keys--); // 16
		
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 15
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 14
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 13
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 12
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 11
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 10
		
		CVMX_MT_CAMELLIA_FL   (*rd_keys--); // 9
		CVMX_MT_CAMELLIA_FLINV(*rd_keys--); // 8
		
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 7
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 6
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 5
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 4
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 3
		CVMX_MT_CAMELLIA_ROUND(*rd_keys--); // 2
		
		CVMX_MF_CAMELLIA_RESINP(outp[1], 0);
		CVMX_MF_CAMELLIA_RESINP(outp[0], 1);
		outp[1] ^= *rd_keys--;       // 1
		outp[0] ^= *rd_keys;         // 0
	}
	else
	{
		printf("Camellia Algorithm is supported only on CN7XXX chips.\n");
	}
#endif
	}
