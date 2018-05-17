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
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <ec/ec_lcl.h>
#include "test-crypto-common.h"
#include "test-ecdh-api.h"

#ifdef TEST_CPU_CYCLES
	extern uint32_t numcores;
	extern CVMX_SHARED uint64_t total_cpucycles;
	extern CVMX_SHARED uint64_t total_tps;		
#endif

/* Known Answer Test for ECDH */
int test_ecdh_kat ()
{
	unsigned char   *abuf=NULL,*bbuf=NULL;
	int nid,i,alen,blen,aout,bout,ret1,ret2;
	int ret = 0,fail = 0;
	BIGNUM *x=NULL, *y=NULL, *expected=NULL;
	EC_KEY *a,*b;
	EC_POINT *point2 =NULL,*point1=NULL;
	const EC_GROUP  *group;

	for (i=0;i<NUM_CURVES;i++)
	{
		nid = curves[i].nid;
		a = EC_KEY_new_by_curve_name(nid);
		b = EC_KEY_new_by_curve_name(nid);
		if (a == NULL || b == NULL) 
		{
			printf("EC_KEY allocation failed.\n");
			goto err;
		}
		
		ret1= BN_hex2bn(&x, ecdh_test_vectors[i].priv_key_a);
		ret2= BN_hex2bn(&y, ecdh_test_vectors[i].priv_key_b);
		
		ret1=EC_KEY_set_private_key(a, x);
		ret2=EC_KEY_set_private_key(b, y);

		if (!ret1 || !ret2) 
		{
			printf("EC_KEY generation failed. at line %d\n",__LINE__);
			goto err;
		}
		group = EC_KEY_get0_group(a);
		ret1 = BN_hex2bn(&x,ecdh_test_vectors[i].pub_key_a_x);
		ret2 = BN_hex2bn(&y,ecdh_test_vectors[i].pub_key_a_y);
		if (!ret1 || !ret2) 
		{
			printf("EC_KEY generation failed.\n");
			goto err;
		}
		point1 = EC_POINT_new(group);
		if (point1 == NULL)
			goto err;
		if (!EC_POINT_set_affine_coordinates_GFp(group, point1, x, y, NULL))
		{
			printf("EC_KEY generation failed.\n");
			goto err;
		}

		ret1 = BN_hex2bn(&x,ecdh_test_vectors[i].pub_key_b_x);
		ret2 = BN_hex2bn(&y,ecdh_test_vectors[i].pub_key_b_y);
		if (!ret1 || !ret2) 
		{
			printf("EC_KEY generation failed.\n");
			goto err;
		}
		point2 = EC_POINT_new(group);
		if (point2 == NULL)
			goto err;
		if (!EC_POINT_set_affine_coordinates_GFp(group, point2, x, y, NULL))
		{
			printf("EC_KEY generation failed.\n");
			goto err;
		}
		ret1= EC_KEY_set_public_key(a ,point1);
		ret2= EC_KEY_set_public_key(b ,point2);
		if (!ret1 || !ret2) 
		{
			printf("EC_KEY generation failed. at line %d\n",__LINE__);
			goto err;
		}

		alen = blen = (EC_GROUP_get_degree(group) + 7)/8;
		abuf=(unsigned char *)OPENSSL_malloc(alen);
		bbuf=(unsigned char *)OPENSSL_malloc(blen);
		aout=ECDH_compute_key(abuf, alen, EC_KEY_get0_public_key(b), a, NULL);
		bout=ECDH_compute_key(bbuf, blen, EC_KEY_get0_public_key(a) , b, NULL);
		x= BN_bin2bn(abuf, alen, NULL);
		y= BN_bin2bn(bbuf, blen, NULL);
		
		if (!x || !y) 
		{
			printf("Binary to big number convertion failed.\n");
			goto err;
		}
		ret1= BN_hex2bn(&expected,ecdh_test_vectors[i].shared_key);
		if (!ret1) 
		{
			printf("Hex to big number convertion failed.\n");
			goto err;
		}
		if ((aout < 4) || (bout != aout) || (BN_cmp(expected,x) != 0) || (BN_cmp(expected,y) != 0))
		{
			printf("ECDH failed\n\n");
			ret = -1;
			fail++;
			goto err;
		}
	err:
		if (abuf != NULL) OPENSSL_free(abuf);
		if (bbuf != NULL) OPENSSL_free(bbuf);
		if (a) EC_KEY_free(a);
		if (b) EC_KEY_free(b);

		if (ret != 0) break;
	}
	if (fail)
		printf("***");
	
	if (cvmx_is_init_core()) 
		printf ("%-20s :Total Test vectors tested:  %d passed : %d failed : %d\n","ECDH",i,(i-fail),fail);
	return ret;
}

int test_ecdh ()
{
	EC_KEY *a,*b;
	const EC_GROUP  *group;
	unsigned char   *abuf=NULL,*bbuf=NULL;
	int nid,i,alen,blen,aout,bout;
	int ret = 0;

	for (i=0;i<NUM_CURVES;i++)
	{
		nid = curves[i].nid;	
		PRINT_HDR;
		a = EC_KEY_new_by_curve_name(nid);
		b = EC_KEY_new_by_curve_name(nid);
		group = EC_KEY_get0_group(a);
		alen = blen = (EC_GROUP_get_degree(group) + 7)/8;
		if (a == NULL || b == NULL) 
		{
			printf("EC_KEY allocation failed.\n");
			goto err;
		}
		START_CYCLE;
		if (!EC_KEY_generate_key(a)) {
			printf("EC_KEY generation failed.\n");
			goto err;
		}
		END_CYCLE("ECDH generate key");
		if (!EC_KEY_generate_key(b)) {
			printf("EC_KEY generation failed.\n");
			goto err;
		}

		abuf=(unsigned char *)OPENSSL_malloc(alen);
		bbuf=(unsigned char *)OPENSSL_malloc(blen);
		START_CYCLE;
		aout=ECDH_compute_key(abuf, alen, EC_KEY_get0_public_key(b), a, NULL);
		END_CYCLE("ECDH compute key");
		bout=ECDH_compute_key(bbuf, blen, EC_KEY_get0_public_key(a) , b, NULL);
		if ((aout < 4) || (bout != aout) || (memcmp(abuf,bbuf,aout) != 0))
		{
			printf("ECDH failed\n\n");
			ret = -1;
			goto err;
		}
	err:
		if (abuf != NULL) OPENSSL_free(abuf);
		if (bbuf != NULL) OPENSSL_free(bbuf);
		if (a) EC_KEY_free(a);
		if (b) EC_KEY_free(b);

		if (ret != 0) break;
		
	}
	if (cvmx_is_init_core()) {	
	printf ("Tested %-20s: Prime Curves P-192 P-224 P-256 P-384 P-521 : %s\n",
												"ECDH",(ret==0)?"Passed":"Failed");
	}

	return ret;
}
