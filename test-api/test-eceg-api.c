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
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <eceg/eceg.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <ec/ec_lcl.h>
#include "test-crypto-common.h"
#include "test-eceg-api.h"

#ifdef TEST_CPU_CYCLES
	extern uint32_t numcores;
	extern CVMX_SHARED uint64_t total_cpucycles;
	extern CVMX_SHARED uint64_t total_tps;		
#endif 

int test_eceg()
{
	EC_KEY *eckey = NULL;
	unsigned char *digest = NULL;
	unsigned char *signature = NULL;
	ECEG_SIG *ECEG_sig = NULL; 
	unsigned int  sig_len,digest_len=0;
	int nid, i, ret =  0;

	for (i=0;i<NUM_CURVES;i++)
	{	
		nid = curv[i].nid;	
		PRINT_HDR;
		if (nid == NID_X9_62_prime256v1)
		digest_len=32;
		else if (nid == NID_secp384r1)
		digest_len=48;
		else if (nid == NID_secp521r1)
		digest_len=64;
		
		
		/* create new key (== EC_KEY) */
		if (!(eckey = EC_KEY_new_by_curve_name(nid)))
		{
			printf("EC_KEY allocation failed.\n");
			return -1;
		}
		/* create key */
		if (!EC_KEY_generate_key(eckey))
		{
			printf("EC_KEY generation failed.\n");
			ret = -1;
			goto err;
		}

		if ((digest = OPENSSL_malloc(digest_len)) == NULL)
		{
			printf( "Unable to allocate memory.\n");
			ret = -1;
			goto err;
		}
	
		if (!RAND_pseudo_bytes(digest, digest_len))
		{
			printf( "Unable to get random data.\n");
			ret = -1;
			goto err;
		}
		/* create signature */
		sig_len = ECEG_size(eckey);
		if ((signature = OPENSSL_malloc(sig_len)) == NULL)
			goto err;
			START_CYCLE;
					 ret = ECEG_sign(0, digest, digest_len, signature, &sig_len, eckey);
			END_CYCLE("ECEG sign");
		if (!ret)
		{
			printf("ECEG_sign failed.\n");
			ret = -1;
			goto err;
		}
		/* verify signature */
			START_CYCLE;
		ret = ECEG_verify(0, digest, digest_len, signature, sig_len, eckey);
			END_CYCLE("ECEG verify");
		if (ret != 1)
		{
			printf("ECEG_verify failed\n");
			ret = -1;
			goto err;
		}
			START_CYCLE;
		ECEG_sig = ECEG_do_sign 	( digest, digest_len, eckey);
			END_CYCLE("ECEG do sign");

		if (ECEG_sig == NULL ) {
			printf("ECEG_do_sign failed\n");
			ret = -1;
		}
			START_CYCLE;
		ret = ECEG_do_verify ( digest, digest_len, ECEG_sig, eckey);
			END_CYCLE("ECEG do verify");
		if (ret != 1)
        {
            printf("ECEG_do_verify failed\n");
			ret = -1;
            goto err;
        }
		/* cleanup */
	err:
		if (signature)
			OPENSSL_free(signature);
		if (digest)
			OPENSSL_free(digest);
		if (eckey)
			EC_KEY_free(eckey);
		if (ECEG_sig)
			ECEG_SIG_free (ECEG_sig);

		signature = NULL;
		eckey = NULL;
		if (ret == -1)
		{
		printf("ECEG test failed with prime curve %s\n",curv[i].curvename);
		break;
		}
		ret=0;
	}

	if (cvmx_is_init_core()) 
		printf ("Tested %-20s: Prime Curves P-256 P-384 P-521 : %s\n","ECEG",(ret==0)?"Passed":"Failed");
	
	return ret;
}

int test_eceg_kat () {	
	if (cvmx_is_init_core())	
		printf (" *** ECEG Known Answer Test not available ***\n");
	return -2;
}


