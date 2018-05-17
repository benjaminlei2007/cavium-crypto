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
#include "test-crypto-common.h"
#include <test-zuc-api.h> 

#ifdef TEST_CPU_CYCLES
	extern uint32_t numcores;
	extern CVMX_SHARED uint64_t total_cpucycles;
	extern CVMX_SHARED uint64_t total_mbps;		
#endif

int test_zuc_encrypt_kat ()
{
	unsigned char output[MAX_BUFFER_SIZE];
	int i, fail = 0 ;
	int testsize=0;

	if (!OCTEON_IS_OCTEON3()) {
		if (cvmx_is_init_core())	
			printf ("ZUC Algorithm is supported only on 7XXX chips.\n");
		return -2;
	}
	testsize = sizeof(zuc_enc) / sizeof(zuc_enc[0]);
	for(i = 0; i < testsize; i++)
	{
	ZUC_init();

	(void)ZUC_encrypt(zuc_enc[i].input, zuc_enc[i].length, output,
			zuc_enc[i].key, zuc_enc[i].count, zuc_enc[i].bearer,
				zuc_enc[i].direction);

	ZUC_finish();

	if(memcmp(output, zuc_enc[i].output, zuc_enc[i].length/8))
	{
		printf("ZUC_encrypt(): test %d FAILED\n",(i+1));
		hex_dump("output", output, zuc_enc[i].length/8);
		hex_dump("expected-output",zuc_enc[i].output,zuc_enc[i].length/8);
		ret=-1;
		fail++;
		goto End;
	}
	memset(output,0,sizeof(output));
	}
	ret = 0;
End :
	if (fail)
		printf("***");
	
	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","ZUC-ENCRYPT",i,(i-fail),fail);
	return ret;

}

int test_zuc_encrypt()
{
	unsigned char output[MAX_BUFFER_SIZE];
	unsigned char outbuff[MAX_BUFFER_SIZE];
	int i = 1;
	unsigned int k;
	if (!OCTEON_IS_OCTEON3()) {
		if (cvmx_is_init_core())	
			printf("ZUC Algorithm is supported only on 7XXX chips.\n");
		return -1;
	}
	for(inlen =START_PACKET_SIZE; inlen <= MAX_BUFF_SIZE;) {
		PRINT_HDR;
		for (k = 0; k < inlen; k++) {
		inbuff[k] = (k%8);
 		}
		ZUC_init();
		START_CYCLE_ITR;
		ret = ZUC_encrypt(inbuff, ((inlen*8)+1), output,
					zuc_enc[i].key, zuc_enc[i].count, zuc_enc[i].bearer,
							zuc_enc[i].direction);
		END_CYCLE_ITR("ZUC-ENC");
		ZUC_finish();
		ZUC_init();

		(void)ZUC_encrypt(output,((inlen*8)+1), outbuff,
					zuc_enc[i].key, zuc_enc[i].count, zuc_enc[i].bearer,
							zuc_enc[i].direction);

		ZUC_finish();
		if(memcmp(inbuff,outbuff, inlen))
		{
			printf("ZUC_encrypt(): test %d FAILED\n",(i+1));
			hex_dump("input", inbuff, inlen);
			hex_dump("output",outbuff, inlen);
			ret=-1;
			goto End;
		}	
		#ifdef TEST_CPU_CYCLES
			inlen+=inlen;
		#else	
			inlen+=INCR_STEPS;
		#endif
	}


	ret = 0;
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s : Packet Size from %d to %d : %s\n","ZUC-ENCRYPT",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
End :
	return ret;

}
int test_zuc_mac_kat ()
{
	unsigned char output[MAX_BUFFER_SIZE];
	int keystreamlen=2;
	int i, fail = 0;
	int testsize=0;
/*
#ifdef TEST_CPU_CYCLES
	unsigned int k;
#endif
*/
	if (!OCTEON_IS_OCTEON3()) {
		if (cvmx_is_init_core())	
			printf ("ZUC Algorithm is supported only on 7XXX chips.\n");
		return -1;
	}

	testsize = sizeof(zuc_mac) / sizeof(zuc_mac[0]);
	for(i = 0; i < testsize; i++)
	{
	ZUC_init();

	(void)ZUC_mac(zuc_mac[i].input, zuc_mac[i].length, output,
				 zuc_mac[i].key, zuc_mac[i].count, zuc_mac[i].bearer,
					 zuc_mac[i].direction);

	ZUC_finish();

	if(memcmp(output, zuc_mac[i].mac, 4 * sizeof(unsigned char)))
	{
	printf("ZUC_mac(): test %d FAILED at line %d\n",(i+1),__LINE__);
	hex_dump("expected",zuc_mac[i].mac,4);
	hex_dump("output",output,4);
	ret=-1;
	goto End;
	}

	memset(output,0,sizeof(output));
	}
	
	testsize = sizeof(zuc_vector) / sizeof(zuc_vector[0]);
	
	for(i = 0; i < testsize; i++)
	{
		ZUC(zuc_vector[i].key, zuc_vector[i].iv, 
				(uint32_t *)output, keystreamlen);
		if(memcmp(zuc_vector[i].output,output,keystreamlen*4))
		{
			printf("ZUC: test %d FAILED\n", (i+1));
			fail++;
		}
	}

	ret=0;
End :
	if (fail)
		printf("***");

	if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested: %d  passed : %d  failed : %d\n","ZUC-MAC",i,(i-fail),fail);
	return ret;


}

int test_zuc_mac()
{
	unsigned char output[MAX_BUFFER_SIZE];
	int i;
	unsigned int k;
	unsigned int inlen;
	if (!OCTEON_IS_OCTEON3()) {
		if (cvmx_is_init_core())	
			printf ("ZUC Algorithm is supported only on 7XXX chips.\n");
		return -2;
	}
	i=0;
	for(inlen = START_PACKET_SIZE; inlen <= MAX_BUFF_SIZE;) {
		PRINT_HDR;
		for (k = 0; k < inlen; k++) {
			inbuff[k] = (k%8);
		}
		START_CYCLE_ITR;
		ZUC_init();
		ret = ZUC_mac(inbuff, (inlen*8), output,
		zuc_mac[i].key, zuc_mac[i].count, zuc_mac[i].bearer,
		zuc_mac[i].direction);
		 ZUC_finish();
		END_CYCLE_ITR("ZUC-MAC");
		memset(output,0,sizeof(output));	
		#ifdef TEST_CPU_CYCLES
			inlen+=inlen;
		#else	
			inlen+=INCR_STEPS;
		#endif
	}
	ret=0;
	if (cvmx_is_init_core()) {
	printf ("Tested %-20s : Packet Size from %d to %d : %s\n","ZUC-MAC",
						START_PACKET_SIZE,MAX_BUFF_SIZE,(ret==0)?"Passed":"Failed");
	}
	return ret;

}

int test_zuc_api_kat()
{
	if (!OCTEON_IS_OCTEON3()) {
		if (cvmx_is_init_core())
			printf("ZUC Algorithm is supported only on 7XXX chips.\n");
		return -2;
	}
	
	ret=test_zuc_encrypt_kat();
	CHECK_RES("zuc-encrypt");

	ret=test_zuc_mac_kat();
	CHECK_RES("zuc-mac");
	
	return 0;
}

int test_zuc_api()
{
	
	if (!OCTEON_IS_OCTEON3()) {
		if (cvmx_is_init_core())
			printf("ZUC Algorithm is supported only on 7XXX chips.\n");
		return -2;
	}
	
	ret=test_zuc_encrypt();
	CHECK_RES("zuc-encrypt");

	ret=test_zuc_mac();
	CHECK_RES("zuc-mac");
	
	return 0;
}
