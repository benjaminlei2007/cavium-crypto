/* crypto/eceg/ecg_ossl.c */
/* ====================================================================
 * Copyright (c) 1998-2004 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* Copyright (c) 2003-2005 Cavium Networks (support@cavium.com) All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:

 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 *
 * 3. Cavium Networks name may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * This Software, including technical data, may be subject to U.S. export control laws,
 * including the U.S. Export Administration Act and its associated regulations,
 and may be
 * subject to export or import regulations in other countries. You warrant that
 You will comply
 * strictly in all respects with all such regulations and acknowledge that you have the responsibility
 * to obtain licenses to export, re-export or import the Software.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND
 WITH ALL FAULTS
 * AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES, EITHER EXPRESS,
 IMPLIED, STATUTORY,
 * OR OTHERWISE, WITH RESPECT TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY
 * REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM
 * SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT,
 * FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS,
 QUIET ENJOYMENT,
 * QUIET POSSESSION OR CORRESPONDENCE TO DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE
 * OF THE SOFTWARE LIES WITH YOU.
 */


#include "ecg_locl.h"
#include <openssl/err.h>
#include <openssl/obj_mac.h>

static ECEG_SIG *eceg_do_sign(const unsigned char *dgst, int dlen, 
		const BIGNUM *, const BIGNUM *, EC_KEY *eckey);
static int eceg_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, 
		BIGNUM **rp);
static int eceg_do_verify(const unsigned char *dgst, int dgst_len, 
		const ECEG_SIG *sig, EC_KEY *eckey);

static ECEG_METHOD openssl_eceg_meth = {
	"OpenSSL ECEG method",
	eceg_do_sign,
	eceg_sign_setup,
	eceg_do_verify,
#if 0
	NULL, /* init     */
	NULL, /* finish   */
#endif
	0,    /* flags    */
	NULL  /* app_data */
};

const ECEG_METHOD *ECEG_OpenSSL(void)
{
	return &openssl_eceg_meth;
}

static int eceg_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
		BIGNUM **rp)
{
	BN_CTX   *ctx = NULL;
	BIGNUM	 *k = NULL, *r = NULL, *order = NULL, *X = NULL;
	EC_POINT *tmp_point=NULL;
	const EC_GROUP *group;
	int 	 ret = 0;

	if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL)
	{
		ECEGerr(ECEG_F_ECEG_SIGN_SETUP, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (ctx_in == NULL) 
	{
		if ((ctx = BN_CTX_new()) == NULL)
		{
			ECEGerr(ECEG_F_ECEG_SIGN_SETUP,ERR_R_MALLOC_FAILURE);
			return 0;
		}
	}
	else
		ctx = ctx_in;

	k     = BN_new();	/* this value is later returned in *kp */
	r     = BN_new();	/* this value is later returned in *rp    */
	order = BN_new();
	X     = BN_new();
	if (!k || !r || !order || !X)
	{
		ECEGerr(ECEG_F_ECEG_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if ((tmp_point = EC_POINT_new(group)) == NULL)
	{
		ECEGerr(ECEG_F_ECEG_SIGN_SETUP, ERR_R_MALLOC_FAILURE);	
		goto err;
	}
	if (!EC_GROUP_get_order(group, order, ctx))
	{
		ECEGerr(ECEG_F_ECEG_SIGN_SETUP, ERR_R_MALLOC_FAILURE);	
		goto err;
	}

	do
	{
		do
			if (!BN_rand_range(k, order))
			{
				ECEGerr(ECEG_F_ECEG_SIGN_SETUP,
				 ECEG_R_RANDOM_NUMBER_GENERATION_FAILED);
				goto err;
			}
		while (BN_is_zero(k));

		/* compute r the x-coordinate of generator * k */
		if (!EC_POINT_mul(group, tmp_point, k, NULL, NULL, ctx))
		{
			ECEGerr(ECEG_F_ECEG_SIGN_SETUP, ERR_R_EC_LIB);
			goto err;
		}
		if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
		{
			if (!EC_POINT_get_affine_coordinates_GFp(group,
				tmp_point, X, NULL, ctx))
			{
				ECEGerr(ECEG_F_ECEG_SIGN_SETUP,ERR_R_EC_LIB);
				goto err;
			}
		}
		else /* NID_X9_62_characteristic_two_field */
		{
			if (!EC_POINT_get_affine_coordinates_GF2m(group,
				tmp_point, X, NULL, ctx))
			{
				ECEGerr(ECEG_F_ECEG_SIGN_SETUP,ERR_R_EC_LIB);
				goto err;
			}
		}
		if (!BN_nnmod(r, X, order, ctx))
		{
			ECEGerr(ECEG_F_ECEG_SIGN_SETUP, ERR_R_BN_LIB);
			goto err;
		}
	}
	while (BN_is_zero(r));

	/* compute the inverse of k */
	if (!BN_mod_inverse(k, k, order, ctx))
	{
		ECEGerr(ECEG_F_ECEG_SIGN_SETUP, ERR_R_BN_LIB);
		goto err;	
	}

	/* clear old values if necessary */
	if (*rp != NULL)
		BN_clear_free(*rp);
	if (*kinvp != NULL) 
		BN_clear_free(*kinvp);
	/* save the pre-computed values  */
	*rp    = r;
	*kinvp = k;
	ret = 1;
err:
	if (!ret)
	{
		if (k != NULL) BN_clear_free(k);
		if (r != NULL) BN_clear_free(r);
	}
	if (ctx_in == NULL) 
		BN_CTX_free(ctx);
	if (order != NULL)
		BN_free(order);
	if (tmp_point != NULL) 
		EC_POINT_free(tmp_point);
	if (X)
		BN_clear_free(X);
	return(ret);
}


static ECEG_SIG *eceg_do_sign(const unsigned char *dgst, int dgst_len, 
		const BIGNUM *in_kinv, const BIGNUM *in_r, EC_KEY *eckey)
{
	int     ok = 0;
	BIGNUM *kinv=NULL, *s, *m=NULL,*tmp=NULL,*order=NULL;
	const BIGNUM *ckinv;
	BN_CTX     *ctx = NULL;
	const EC_GROUP   *group;
	ECEG_SIG  *ret;
	ECEG_DATA *eceg;
	const BIGNUM *priv_key;

	eceg    = eceg_check(eckey);
	group    = EC_KEY_get0_group(eckey);
	priv_key = EC_KEY_get0_private_key(eckey);

	if (group == NULL || priv_key == NULL || eceg == NULL)
	{
		ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	ret = ECEG_SIG_new();
	if (!ret)
	{
		ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	s = ret->s;

	if ((ctx = BN_CTX_new()) == NULL || (order = BN_new()) == NULL ||
		(tmp = BN_new()) == NULL || (m = BN_new()) == NULL)
	{
		ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!EC_GROUP_get_order(group, order, ctx))
	{
		ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_EC_LIB);
		goto err;
	}
	if (dgst_len > BN_num_bytes(order))
	{
		ECEGerr(ECEG_F_ECEG_DO_SIGN,
			ECEG_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
		goto err;
	}

	if (!BN_bin2bn(dgst, dgst_len, m))
	{
		ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_BN_LIB);
		goto err;
	}
	do
	{
		if (in_kinv == NULL || in_r == NULL)
		{
			if (!ECEG_sign_setup(eckey, ctx, &kinv, &ret->r))
			{
				ECEGerr(ECEG_F_ECEG_DO_SIGN,ERR_R_ECEG_LIB);
				goto err;
			}
			ckinv = kinv;
		}
		else
		{
			ckinv  = in_kinv;
			if (BN_copy(ret->r, in_r) == NULL)
			{
				ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_MALLOC_FAILURE);
				goto err;
			}
		}
		
		if (!BN_mod_mul(tmp, priv_key, ret->r, order, ctx))
		{
			ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		if (!BN_mod_add_quick(s, tmp, m, order))
		{
			ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		if (!BN_mod_mul(s, s, ckinv, order, ctx))
		{
			ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		if (BN_is_zero(s))
		{
			/* if kinv and r have been supplied by the caller
			 * don't to generate new kinv and r values */
			if (in_kinv != NULL && in_r != NULL)
			{
				ECEGerr(ECEG_F_ECEG_DO_SIGN, ECEG_R_NEED_NEW_SETUP_VALUES);
				goto err;
			}
		}
		else
			/* s != 0 => we have a valid signature */
			break;
	}
	while (1);

	ok = 1;
err:
	if (!ok)
	{
		ECEG_SIG_free(ret);
		ret = NULL;
	}
	if (ctx)
		BN_CTX_free(ctx);
	if (m)
		BN_clear_free(m);
	if (tmp)
		BN_clear_free(tmp);
	if (order)
		BN_free(order);
	if (kinv)
		BN_clear_free(kinv);
	return ret;
}

static int eceg_do_verify(const unsigned char *dgst, int dgst_len,
		const ECEG_SIG *sig, EC_KEY *eckey)
{
	int ret = -1;
	BN_CTX   *ctx;
	BIGNUM   *order, *u1, *u2, *m, *X, *s_inv;
	EC_POINT *point = NULL;
	const EC_GROUP *group;
	const EC_POINT *pub_key;

	/* check input values */
	if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL ||
	    (pub_key = EC_KEY_get0_public_key(eckey)) == NULL || sig == NULL)
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ECEG_R_MISSING_PARAMETERS);
		return -1;
	}

	ctx = BN_CTX_new();
	if (!ctx)
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_MALLOC_FAILURE);
		return -1;
	}
	BN_CTX_start(ctx);
	order = BN_CTX_get(ctx);	
	u1    = BN_CTX_get(ctx);
	u2    = BN_CTX_get(ctx);
	m     = BN_CTX_get(ctx);
	X     = BN_CTX_get(ctx);
	s_inv = BN_CTX_get(ctx);
	if (!X)
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	
	if (!EC_GROUP_get_order(group, order, ctx))
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_EC_LIB);
		goto err;
	}

	if (BN_is_zero(sig->r)          || BN_is_negative(sig->r) || 
	    BN_ucmp(sig->r, order) >= 0 || BN_is_zero(sig->s)  ||
	    BN_is_negative(sig->s)      || BN_ucmp(sig->s, order) >= 0)
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ECEG_R_BAD_SIGNATURE);
		ret = 0;	/* signature is invalid */
		goto err;
	}
	/* calculate tmp1 = inv(S) mod order */
	if (!BN_mod_inverse(s_inv, sig->s, order, ctx))
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	/* digest -> m */
	if (!BN_bin2bn(dgst, dgst_len, m))
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	/* u1 = m * s_inv mod order */
	if (!BN_mod_mul(u1, m, s_inv, order, ctx))
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	/* u2 = sig->r * s_inv mod q */
	if (!BN_mod_mul(u2, sig->r, s_inv, order, ctx))
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}

	if ((point = EC_POINT_new(group)) == NULL)
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!EC_POINT_mul(group, point, u1, pub_key, u2, ctx))
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_EC_LIB);
		goto err;
	}
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
	{
		if (!EC_POINT_get_affine_coordinates_GFp(group,
			point, X, NULL, ctx))
		{
			ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_EC_LIB);
			goto err;
		}
	}
	else /* NID_X9_62_characteristic_two_field */
	{
		if (!EC_POINT_get_affine_coordinates_GF2m(group,
			point, X, NULL, ctx))
		{
			ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_EC_LIB);
			goto err;
		}
	}
	
	if (!BN_nnmod(u1, X, order, ctx))
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	/*  if the signature is correct u1 is equal to sig->r */
	ret = (BN_ucmp(u1, sig->r) == 0);
err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	if (point)
		EC_POINT_free(point);
	return ret;

}

/* KT-IV signature */
#if 0
static int eceg_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kp,
		BIGNUM **rp)
{
	BN_CTX   *ctx = NULL;
	BIGNUM	 *k = NULL, *r = NULL, *order = NULL, *X = NULL;
	EC_POINT *tmp_point=NULL;
	const EC_GROUP *group;
	int 	 ret = 0;

	if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL)
	{
		ECEGerr(ECEG_F_ECEG_SIGN_SETUP, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (ctx_in == NULL) 
	{
		if ((ctx = BN_CTX_new()) == NULL)
		{
			ECEGerr(ECEG_F_ECEG_SIGN_SETUP,ERR_R_MALLOC_FAILURE);
			return 0;
		}
	}
	else
		ctx = ctx_in;

	k     = BN_new();	/* this value is later returned in *kp */
	r     = BN_new();	/* this value is later returned in *rp    */
	order = BN_new();
	X     = BN_new();
	if (!k || !r || !order || !X)
	{
		ECEGerr(ECEG_F_ECEG_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if ((tmp_point = EC_POINT_new(group)) == NULL)
	{
		ECEGerr(ECEG_F_ECEG_SIGN_SETUP, ERR_R_MALLOC_FAILURE);	
		goto err;
	}
	if (!EC_GROUP_get_order(group, order, ctx))
	{
		ECEGerr(ECEG_F_ECEG_SIGN_SETUP, ERR_R_MALLOC_FAILURE);	
		goto err;
	}

	do
	{
		do
			if (!BN_rand_range(k, order))
			{
				ECEGerr(ECEG_F_ECEG_SIGN_SETUP,
				 ECEG_R_RANDOM_NUMBER_GENERATION_FAILED);
				goto err;
			}
		while (BN_is_zero(k));

		/* compute r the x-coordinate of generator * k */
		if (!EC_POINT_mul(group, tmp_point, k, NULL, NULL, ctx))
		{
			ECEGerr(ECEG_F_ECEG_SIGN_SETUP, ERR_R_EC_LIB);
			goto err;
		}
		if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
		{
			if (!EC_POINT_get_affine_coordinates_GFp(group,
				tmp_point, X, NULL, ctx))
			{
				ECEGerr(ECEG_F_ECEG_SIGN_SETUP,ERR_R_EC_LIB);
				goto err;
			}
		}
		else /* NID_X9_62_characteristic_two_field */
		{
			if (!EC_POINT_get_affine_coordinates_GF2m(group,
				tmp_point, X, NULL, ctx))
			{
				ECEGerr(ECEG_F_ECEG_SIGN_SETUP,ERR_R_EC_LIB);
				goto err;
			}
		}
		if (!BN_nnmod(r, X, order, ctx))
		{
			ECEGerr(ECEG_F_ECEG_SIGN_SETUP, ERR_R_BN_LIB);
			goto err;
		}
	}
	while (BN_is_zero(r));

	/* clear old values if necessary */
	if (*rp != NULL)
		BN_clear_free(*rp);
	if (*kp != NULL) 
		BN_clear_free(*kp);
	/* save the pre-computed values  */
	*rp    = r;
	*kp = k;
	ret = 1;
err:
	if (!ret)
	{
		if (k != NULL) BN_clear_free(k);
		if (r != NULL) BN_clear_free(r);
	}
	if (ctx_in == NULL) 
		BN_CTX_free(ctx);
	if (order != NULL)
		BN_free(order);
	if (tmp_point != NULL) 
		EC_POINT_free(tmp_point);
	if (X)
		BN_clear_free(X);
	return(ret);
}


static ECEG_SIG *eceg_do_sign(const unsigned char *dgst, int dgst_len, 
		const BIGNUM *in_k, const BIGNUM *in_r, EC_KEY *eckey)
{
	int     ok = 0;
	BIGNUM *k=NULL, *s, *m=NULL,*tmp=NULL,*order=NULL;
	const BIGNUM *ck;
	BN_CTX     *ctx = NULL;
	const EC_GROUP   *group;
	ECEG_SIG  *ret;
	ECEG_DATA *eceg;
	const BIGNUM *priv_key;

	eceg    = eceg_check(eckey);
	group    = EC_KEY_get0_group(eckey);
	priv_key = EC_KEY_get0_private_key(eckey);

	if (group == NULL || priv_key == NULL || eceg == NULL)
	{
		ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	ret = ECEG_SIG_new();
	if (!ret)
	{
		ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	s = ret->s;

	if ((ctx = BN_CTX_new()) == NULL || (order = BN_new()) == NULL ||
		(tmp = BN_new()) == NULL || (m = BN_new()) == NULL)
	{
		ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!EC_GROUP_get_order(group, order, ctx))
	{
		ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_EC_LIB);
		goto err;
	}
	if (dgst_len > BN_num_bytes(order))
	{
		ECEGerr(ECEG_F_ECEG_DO_SIGN,
			ECEG_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
		goto err;
	}

	if (!BN_bin2bn(dgst, dgst_len, m))
	{
		ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_BN_LIB);
		goto err;
	}
	do
	{
		if (in_k == NULL || in_r == NULL)
		{
			if (!ECEG_sign_setup(eckey, ctx, &k, &ret->r))
			{
				ECEGerr(ECEG_F_ECEG_DO_SIGN,ERR_R_ECEG_LIB);
				goto err;
			}
			ck = k;
		}
		else
		{
			ck  = in_k;
			if (BN_copy(ret->r, in_r) == NULL)
			{
				ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_MALLOC_FAILURE);
				goto err;
			}
		}
		
		if (!BN_mod_mul(tmp, priv_key, ret->r, order, ctx))
		{
			ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		if (!BN_mod_add_quick(s, tmp, m, order))
		{
			ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
	}
	while (BN_is_zero(s));
	if (!BN_mod_inverse(s, s, order, ctx))
	{
		ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_BN_LIB);
		goto err;
	}
	if (!BN_mod_mul(s, s, ck, order, ctx))
	{
		ECEGerr(ECEG_F_ECEG_DO_SIGN, ERR_R_BN_LIB);
		goto err;
	}

	ok = 1;
err:
	if (!ok)
	{
		ECEG_SIG_free(ret);
		ret = NULL;
	}
	if (ctx)
		BN_CTX_free(ctx);
	if (m)
		BN_clear_free(m);
	if (tmp)
		BN_clear_free(tmp);
	if (order)
		BN_free(order);
	if (k)
		BN_clear_free(k);
	return ret;

}

static int eceg_do_verify(const unsigned char *dgst, int dgst_len,
		const ECEG_SIG *sig, EC_KEY *eckey)
{
	int ret = -1;
	BN_CTX   *ctx;
	BIGNUM   *order, *u1, *u2, *m, *X;
	EC_POINT *point = NULL;
	const EC_GROUP *group;
	const EC_POINT *pub_key;

	/* check input values */
	if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL ||
	    (pub_key = EC_KEY_get0_public_key(eckey)) == NULL || sig == NULL)
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ECEG_R_MISSING_PARAMETERS);
		return -1;
	}

	ctx = BN_CTX_new();
	if (!ctx)
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_MALLOC_FAILURE);
		return -1;
	}
	BN_CTX_start(ctx);
	order = BN_CTX_get(ctx);	
	u1    = BN_CTX_get(ctx);
	u2    = BN_CTX_get(ctx);
	m     = BN_CTX_get(ctx);
	X     = BN_CTX_get(ctx);
	if (!X)
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	
	if (!EC_GROUP_get_order(group, order, ctx))
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_EC_LIB);
		goto err;
	}

	if (BN_is_zero(sig->r)          || BN_is_negative(sig->r) || 
	    BN_ucmp(sig->r, order) >= 0 || BN_is_zero(sig->s)  ||
	    BN_is_negative(sig->s)      || BN_ucmp(sig->s, order) >= 0)
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ECEG_R_BAD_SIGNATURE);
		ret = 0;	/* signature is invalid */
		goto err;
	}
	/* digest -> m */
	if (!BN_bin2bn(dgst, dgst_len, m))
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	/* u1 = m * sig->s mod order */
	if (!BN_mod_mul(u1, m, sig->s, order, ctx))
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	/* u2 = sig->r * sig->s mod q */
	if (!BN_mod_mul(u2, sig->r, sig->s, order, ctx))
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}

	if ((point = EC_POINT_new(group)) == NULL)
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!EC_POINT_mul(group, point, u1, pub_key, u2, ctx))
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_EC_LIB);
		goto err;
	}
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
	{
		if (!EC_POINT_get_affine_coordinates_GFp(group,
			point, X, NULL, ctx))
		{
			ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_EC_LIB);
			goto err;
		}
	}
	else /* NID_X9_62_characteristic_two_field */
	{
		if (!EC_POINT_get_affine_coordinates_GF2m(group,
			point, X, NULL, ctx))
		{
			ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_EC_LIB);
			goto err;
		}
	}
	
	if (!BN_nnmod(u1, X, order, ctx))
	{
		ECEGerr(ECEG_F_ECEG_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	/*  if the signature is correct u1 is equal to sig->r */
	ret = (BN_ucmp(u1, sig->r) == 0);
err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	if (point)
		EC_POINT_free(point);
	return ret;

}
#endif
