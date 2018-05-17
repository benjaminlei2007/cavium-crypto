/* ====================================================================
 * Copyright (c) 1998-2008 The OpenSSL Project.  All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in
 *	 the documentation and/or other materials provided with the
 *	 distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *	 software must display the following acknowledgment:
 *	 "This product includes software developed by the OpenSSL Project
 *	 for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *	 endorse or promote products derived from this software without
 *	 prior written permission. For written permission, please contact
 *	 openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *	 nor may "OpenSSL" appear in their names without prior written
 *	 permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *	 acknowledgment:
 *	 "This product includes software developed by the OpenSSL Project
 *	 for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
 *	 notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *	 must display the following acknowledgement:
 *	 "This product includes cryptographic software written by
 *	  Eric Young (eay@cryptsoft.com)"
 *	 The word 'cryptographic' can be left out if the rouines from the library
 *	 being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *	 the apps directory (application code) you must include an acknowledgement:
 *	 "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
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
#include <openssl/bn.h>
#include <ec/ec_lcl.h>
#include <openssl/obj_mac.h>
#include <ecdsa/ecs_locl.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "test-crypto-common.h"
#include "test-ecdsa-api.h"

#ifdef TEST_CPU_CYCLES
	extern uint32_t numcores;
	extern CVMX_SHARED uint64_t total_cpucycles;
	extern CVMX_SHARED uint64_t total_tps;		
#endif

int test_ecdsa_kat ()
{
	 int rv = 0;
	 EC_KEY *eckey = NULL;
	 EC_GROUP *ecgroup = NULL;
	 ECDSA_DATA *ecdsa = NULL;
	 ECDSA_SIG *ecdsa_sig = NULL;
	 EC_POINT *P = NULL, *G = NULL;
	 BIGNUM *p = NULL, *a = NULL, *b = NULL, *order = NULL,
				*x = NULL, *y = NULL, *r = NULL, *s = NULL, *kinv = NULL;
	 BN_CTX *ctx = NULL;
	int i,fail =0;
	const char msg[] = "abc";
	unsigned int siglen = 0, digestlen = 0;
	unsigned char *sign = NULL, digest[128];
	int _r = 0, _s = 0;
#ifdef OCTEON_OPENSSL_NO_DYNAMIC_MEMORY
	if (cvmx_user_app_init() < 0)
	{
		printf ("User application initialization failed\n");
		return -1;
	}
#endif
	for (i = 0; i < (int)ARRAY_ELEMENTS(rfc); i++) {
		memset(digest, 0, sizeof(digest));
		switch (rfc[i].curve_len) {
		case 256:
			SHA256((const unsigned char *)msg, strlen(msg), digest);
			digestlen = 32;
			break;
		case 384:
			SHA384((const unsigned char *)msg, strlen(msg), digest);
			digestlen = 48;
			break;
		case 521:
			SHA512((const unsigned char *)msg, strlen(msg), digest);
			digestlen = 64;
			break;
		default:
			ERR("Invalid curve size given: %d\n", rfc[i].curve_len);
			rv = -1;
			goto end_nist_test;
		}
	
	
		ctx = BN_CTX_new();
	
		if (!(p = BN_new()) || !(a = BN_new()) || !(b = BN_new()) ||
			!(x = BN_new()) || !(y = BN_new()) || !(kinv = BN_new()) ||
			!(order = BN_new())) {
			ERR("BN_new failed");
			rv = -1;
			goto end_nist_test;
		}
	
		if (!(eckey = EC_KEY_new_by_curve_name(rfc[i].nid))) {
			ERR("EC_KEY_new_by_curve_name failed");
			rv = -1;
			goto end_nist_test;
		}
	
		if (!(ecdsa = ecdsa_check(eckey))) {
			ERR("ecdsa_check failed");
			rv = -1;
			goto end_nist_test;
		}
	
	
		if (!BN_hex2bn(&eckey->priv_key, rfc[i].w)) {
			ERR("BN_hex2bn failed");
			rv = -1;
			goto end_nist_test;
		}
		ecgroup = (EC_GROUP *)EC_KEY_get0_group(eckey);
		if (ecgroup == NULL) {
			ERR("EC_KEY_get0_group failed");
			rv = -1;
			goto end_nist_test;
		}
	
		if (!BN_hex2bn(&p, rfc[i].p) || !BN_hex2bn(&a, rfc[i].a) ||
			!BN_hex2bn(&b, rfc[i].b)) {
			ERR("[%d] BN_hex2bn failed", __LINE__);
			rv = -1;
			goto end_nist_test;
		}
	
		if (!EC_GROUP_set_curve_GFp(ecgroup, p, a, b, ctx)) {
			ERR("EC_GROUP_set_curve_GFp failed");
			rv = -1;
			goto end_nist_test;
		}
	
		if (!(P = EC_POINT_new(ecgroup)) || !(G = EC_POINT_new(ecgroup))) {
			ERR("EC_POINT_new failed");
			rv = -1;
			goto end_nist_test;
		}
	
		if (!BN_hex2bn(&x, rfc[i].Gx) || !BN_hex2bn(&y, rfc[i].Gy) ||
			!BN_hex2bn(&order, rfc[i].order)) {
			ERR("[%d] BN_hex2bn failed", __LINE__);
			rv = -1;
			goto end_nist_test;
		}
	
		if (!EC_POINT_set_affine_coordinates_GFp(ecgroup, G, x, y, ctx)) {
			ERR("EC_POINT_set_affine_coordinates_GFp failed");
			rv = -1;
			goto end_nist_test;
		}
		if (!EC_GROUP_set_generator(ecgroup, G, order, BN_value_one())) {
			ERR("EC_GROUP_set_generator failed");
			rv = -1;
			goto end_nist_test;
		}
	
		if (!(r = BN_new()) || !(s = BN_new())) {
			ERR("[%d] BN_new failed", __LINE__);
			rv = -1;
			goto end_nist_test;
		}
	
		if (!BN_hex2bn(&kinv, rfc[i].kinv) || !BN_hex2bn(&r, rfc[i].r)) {
			ERR("[%d] BN_hex2bn failed", __LINE__);
			rv = -1;
			goto end_nist_test;
		}
	
		siglen = ECDSA_size(eckey);
		if (!(sign = OPENSSL_malloc(siglen))) {
			ERR("OPENSSL_malloc failed");
			rv = -1;
			goto end_nist_test;
		}
	
		 /* Generate the signature */
		if (!(ecdsa_sig = ECDSA_do_sign_ex (digest, digestlen, kinv, r, eckey))) {

			ERR("ecdsa_do_sign failed");
			rv = -1;
			goto end_nist_test;
		}
	
		if (!BN_hex2bn(&s, rfc[i].s)) {
			ERR("[%d] BN_hex2bn failed", __LINE__);
			rv = -1;
			goto end_nist_test;
		}
	
		 /* Compare the (r, s) pair. (r, s) is actually the signature
		  * of the msg 'abc'.
		  */
		if ((_r = BN_cmp(ecdsa_sig->r, r)) || (_s = BN_cmp(ecdsa_sig->s, s))) {
			ERR("[%d] comparison failed r %d s %d", __LINE__, _r, _s);
			fail++;
			if (_r) {
					dump("ecdsa r", (unsigned char *)ecdsa_sig->r->d,
							  ecdsa_sig->r->top * sizeof(BN_ULONG));
					dump("r", (unsigned char *)r->d, r->top * sizeof(BN_ULONG));
			}
			if (_s) {
					dump("ecdsa s", (unsigned char *)ecdsa_sig->s->d,
							  ecdsa_sig->s->top * sizeof(BN_ULONG));
					dump("s", (unsigned char *)s->d, s->top * sizeof(BN_ULONG));
			}
			rv = -1;
			goto end_nist_test;
		}
	
		if (!BN_hex2bn(&x, rfc[i].gwx) || !BN_hex2bn(&y, rfc[i].gwy)) {
			ERR("[%d] BN_hex2bn failed", __LINE__);
			rv = -1;
			goto end_nist_test;
		}
	
		if (!EC_POINT_set_affine_coordinates_GFp(ecgroup, P, x, y, ctx)) {
			ERR("EC_POINT_set_affine_coordinates_GFp failed");
			rv = -1;
			goto end_nist_test;
		}
	
		 if (!EC_KEY_set_public_key(eckey, P)) {
			  ERR("EC_KEY_set_public_key failed");
			  rv = -1;
			  goto end_nist_test;
		 }
	
		if (!(rv = ECDSA_do_verify ( digest, digestlen, ecdsa_sig, eckey))) {

			  ERR("ecdsa_do_verify failed");
			  rv = -1;
			  goto end_nist_test;
		 }
	
		 rv = 0;
	
	end_nist_test:
		 if (p) BN_free(p);
		 if (a) BN_free(a);
		 if (b) BN_free(b);
		 if (x) BN_free(x);
		 if (y) BN_free(y);
		 if (r) BN_free(r);
		 if (s) BN_free(s);
		 if (order)  BN_free(order);
	
		 if (P) EC_POINT_free(P);
		 if (G) EC_POINT_free(G);
	
		 if (ctx) BN_CTX_free(ctx);
	
		 if (ecdsa_sig) ECDSA_SIG_free(ecdsa_sig);
		 if (eckey)  EC_KEY_free(eckey);

	}
	if (fail)
		printf("***");
	if (cvmx_is_init_core()) {
		printf ("%-20s :Total Test vectors tested:  %d passed : %d failed : %d\n","ECDSA",i,(i-fail),fail);
	}
	 return rv;
}


int test_ecdsa ()
{
	 int rv = 0, i;
	
	EC_KEY *eckey = NULL;
	EC_GROUP *ecgroup = NULL;
	ECDSA_SIG * ecdsa_sig = NULL, * new = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *kinv = NULL,*rp = NULL; 
	unsigned char *sign = NULL;
	unsigned int siglen = 0;
	#ifdef TEST_CPU_CYCLES
		int nid;
	#endif 
#ifdef OCTEON_OPENSSL_NO_DYNAMIC_MEMORY
	if (cvmx_user_app_init() < 0)
	{
		printf ("User application initialization failed\n");
		return -1;
	}
#endif
	for (i = 0; i < (int)ARRAY_ELEMENTS(ecdsa_param); i++) {
		#ifdef TEST_CPU_CYCLES
			nid = ecdsa_param[i].nid;
		#endif
		PRINT_HDR;
		if (!(eckey = EC_KEY_new())) {
				ERR("EC_KEY_new failed");
				rv = -1;
				goto end_ecdsa_speed;
		}

		if (!(ecgroup = EC_GROUP_new_by_curve_name(ecdsa_param[i].nid))) {
				ERR("EC_GROUP_new_by_curve_name failed");
				rv = -1;
				goto end_ecdsa_speed;
		}

		if (!EC_KEY_set_group(eckey, ecgroup)) {
				ERR("EC_KEY_set_group failed");
				rv = -1;
				goto end_ecdsa_speed;
		}

		if (!EC_KEY_generate_key(eckey)) {
				ERR("EC_KEY_generate_key failed");
				rv = -1;
				goto end_ecdsa_speed;
		}
		rv = ECDSA_sign_setup (eckey, ctx, &kinv, &rp);
		if (!rv) {
			ERR("ECDSA_sign_setup");
			rv = -1;
			goto end_ecdsa_speed;
		}
		siglen = ECDSA_size(eckey);
		if (!(sign = OPENSSL_malloc(siglen))) {
				ERR("OPENSSL_malloc failed");
				rv = -1;
				goto end_ecdsa_speed;
		}

		START_CYCLE;
		rv = ECDSA_sign(0, ecdsa_param[i].h, ecdsa_param[i].hlen,
									 sign, &siglen, eckey);
		END_CYCLE("ECDSA_sign");
		if (!rv) {
				ERR("ECDSA_sign failed");
				rv = -1;
				goto end_ecdsa_speed;
		}

		START_CYCLE;
		rv = ECDSA_verify(0, ecdsa_param[i].h, ecdsa_param[i].hlen, sign,
								 siglen, eckey);
		END_CYCLE("ECDSA_verify");
		if (!rv) {
				ERR("ECDSA_verify failed");
				rv = -1;
				goto end_ecdsa_speed;
		}

		START_CYCLE;
		ecdsa_sig = ECDSA_do_sign(ecdsa_param[i].h, ecdsa_param[i].hlen, eckey);
		END_CYCLE("ECDSA_do_sign");
		if (ecdsa_sig == NULL ) {
				ERR("ECDSA_sign failed");
				rv = -1;
				goto end_ecdsa_speed;
		}

		START_CYCLE;
		rv = ECDSA_do_verify(ecdsa_param[i].h, ecdsa_param[i].hlen, ecdsa_sig, eckey);
		END_CYCLE("ECDSA_do_verify");
		if (!rv) {
				ERR("ECDSA_verify failed");
				rv = -1;
				goto end_ecdsa_speed;
		}
		if (!(new = ECDSA_do_sign_ex (ecdsa_param[i].h, ecdsa_param[i].hlen, kinv, rp, eckey))) {
			ERR("ecdsa_do_sign failed");
			rv = -1;
			goto end_ecdsa_speed;
		}
		rv = ECDSA_do_verify(ecdsa_param[i].h, ecdsa_param[i].hlen, new, eckey);
		if (!rv) {
			ERR("ECDSA_verify failed");
			rv = -1;
			goto end_ecdsa_speed;
		}
		rv = 0;
end_ecdsa_speed:
		if (sign) OPENSSL_free(sign);
		if (eckey) EC_KEY_free(eckey);
		if (ecdsa_sig) ECDSA_SIG_free(ecdsa_sig);

		if (rv) break;
	}
	if (cvmx_is_init_core()) {
		printf ("Tested %-20s: Prime Curves P-256 P-384 P-521 : %s\n","ECDSA",(rv==0)?"Passed":"Failed");
	}	
	return rv;
}
