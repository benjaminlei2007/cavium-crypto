/* crypto/ec/ecp_hmg.c */
/*
 * Written by Nils Larsch for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2003 The OpenSSL Project.  All rights reserved.
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
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * Portions of this software developed by SUN MICROSYSTEMS, INC.,
 * and contributed to the OpenSSL project.
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


#include <openssl/err.h>

#include "ec_lcl.h"
#include "cvmx.h"
#include "ec_longAddition.h"

//#include <openssl/crypto.h>
//
// these are needed for the fn pointer assignments
//
void fecc_MulP256o3Asm(uint64_t *, uint64_t *,uint64_t *);
void fecc_MulP256AsmB17731(uint64_t *, uint64_t *,uint64_t *);
void fecc_SubP256Asm(uint64_t *, uint64_t *,uint64_t *);
void fecc_SubP256AsmB17731(uint64_t *, uint64_t *,uint64_t *);

void fecc_MulP384o3Asm(uint64_t *, uint64_t *,uint64_t *);
void fecc_SubP384Asm(uint64_t *, uint64_t *,uint64_t *);
void fecc_ConstMulP384Asm(uint64_t *, uint64_t *,uint64_t);
void fecc_MulP384AsmB17731(uint64_t *, uint64_t *,uint64_t *);
void fecc_SubP384AsmB17731(uint64_t *, uint64_t *,uint64_t *);
void fecc_ConstMulP384AsmB17731(uint64_t *, uint64_t *,uint64_t);

void fecc_MulP521o3Asm(uint64_t *, uint64_t *,uint64_t *);
void fecc_SubP521Asm(uint64_t *, uint64_t *,uint64_t *);
void fecc_ConstMulP521Asm(uint64_t *, uint64_t *,uint64_t);
void fecc_MulP521AsmB17731(uint64_t *, uint64_t *,uint64_t *);
void fecc_SubP521AsmB17731(uint64_t *, uint64_t *,uint64_t *);
void fecc_ConstMulP521AsmB17731(uint64_t *, uint64_t *,uint64_t);
//
// function to determine O2 or O3
//

const EC_METHOD *EC_GFp_fecc_method(void)
	{
	static const EC_METHOD ret = {
        0,
		NID_X9_62_prime_field,
		ec_GFp_simple_group_init,
		ec_GFp_simple_group_finish,
		ec_GFp_simple_group_clear_finish,
		ec_GFp_nist_group_copy,
		ec_GFp_simple_group_set_curve,
		ec_GFp_simple_group_get_curve,
		ec_GFp_simple_group_get_degree,
		ec_GFp_simple_group_check_discriminant,
		ec_GFp_simple_point_init,
		ec_GFp_simple_point_finish,
		ec_GFp_simple_point_clear_finish,
		ec_GFp_simple_point_copy,
		ec_GFp_simple_point_set_to_infinity,
		ec_GFp_fecc_set_Homogeneous_coordinates_GFp, 
		ec_GFp_fecc_get_Homogeneous_coordinates_GFp,
		ec_GFp_fecc_point_set_affine_coordinates,
		ec_GFp_hw_point_get_affine_coordinates,
		ec_GFp_simple_set_compressed_coordinates,
		ec_GFp_simple_point2oct,
		ec_GFp_simple_oct2point,
		ec_GFp_hw_add,
		ec_GFp_hw_dbl,
		NULL,
		ec_GFp_simple_is_at_infinity,
		ec_GFp_fecc_is_on_curve,
		NULL,
		NULL,
		NULL,
		ec_GFp_fecc_window_mul,
		0 /* precompute_mult */,
		0 /* have_precompute_mult */,	
		ec_GFp_simple_field_mul,
		ec_GFp_simple_field_sqr,
		0 /* field_div */,
		0 /* field_encode */,
		0 /* field_decode */,
		0 /* field_set_to_one */ };

	return &ret;
	}
EC_POINT **precompute = NULL;			
EC_POINT **precompute_generator = NULL;			


typedef struct cav_precomp_st {
	const EC_GROUP *group;
	EC_POINT **points;
	int references;
} CAV_PRECOMP;

static void *cav_precomp_dup(void *);
static void cav_precomp_free(void *);
static void cav_precomp_clear_free(void *);

static CAV_PRECOMP *cav_precomp_new(const EC_GROUP *group)
	{
	CAV_PRECOMP *ret = NULL;

	if (!group)
		return NULL;

	ret = (CAV_PRECOMP *)OPENSSL_malloc(sizeof(CAV_PRECOMP));
	if (!ret)
		{
		ECerr(EC_F_EC_PRE_COMP_NEW, ERR_R_MALLOC_FAILURE);
		return ret;
		}
	ret->group = group;
	ret->points = NULL;
	ret->references = 1;
	return ret;
	}


static void *cav_precomp_dup(void *src_)
	{
	CAV_PRECOMP *src = src_;

	/* no need to actually copy, these objects never change! */

	CRYPTO_add(&src->references, 1, CRYPTO_LOCK_EC_PRE_COMP);

	return src_;
	}
static void cav_precomp_free(void *pre_)
	{
	int i;
	CAV_PRECOMP *pre = pre_;

	if (!pre)
		return;

	i = CRYPTO_add(&pre->references, -1, CRYPTO_LOCK_EC_PRE_COMP);
	if (i > 0)
		return;

	if (pre->points)
		{
		EC_POINT **p;

		for (p = pre->points; *p != NULL; p++)
			EC_POINT_free(*p);
		OPENSSL_free(pre->points);
		}
	OPENSSL_free(pre);
	}

static void cav_precomp_clear_free(void *pre_)
	{
	int i;
	CAV_PRECOMP *pre = pre_;

	if (!pre)
		return;

	i = CRYPTO_add(&pre->references, -1, CRYPTO_LOCK_EC_PRE_COMP);
	if (i > 0)
		return;

	if (pre->points)
		{
		EC_POINT **p;

		for (p = pre->points; *p != NULL; p++)
			EC_POINT_clear_free(*p);
		OPENSSL_cleanse(pre->points, sizeof pre->points);
		OPENSSL_free(pre->points);
		}
	OPENSSL_cleanse(pre, sizeof pre);
	OPENSSL_free(pre);
	}


int ec_GFp_fecc_set_Homogeneous_coordinates_GFp(const EC_GROUP *group, EC_POINT *point,
	const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *ctx)
	{
	BN_CTX *new_ctx = NULL;
	int ret = 0;
		
	if (ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
		}

	if (x != NULL)
		{
		if (!BN_nnmod(&point->X, x, &group->field, ctx)) goto err;
		}
	
	if (y != NULL)
		{
		if (!BN_nnmod(&point->Y, y, &group->field, ctx)) goto err;
		}
	
	if (z != NULL)
		{
		int Z_is_one;
		
		if (!BN_nnmod(&point->Z, z, &group->field, ctx)) goto err;
		Z_is_one = BN_is_one(&point->Z);
		point->Z_is_one = Z_is_one;
		}

	ret = 1;
	
 err:
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	return ret;
	}

int ec_GFp_fecc_get_Homogeneous_coordinates_GFp(const EC_GROUP *group, const EC_POINT *point,
	BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *ctx)
	{
	BN_CTX *new_ctx = NULL;
	int ret = 0;
	
	if (x != NULL)
		{
		if (!BN_copy(x, &point->X)) goto err;
		}
	if (y != NULL)
		{
		if (!BN_copy(y, &point->Y)) goto err;
		}
	if (z != NULL)
		{
		if (!BN_copy(z, &point->Z)) goto err;
		}
	
	ret = 1;

 err:
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	return ret;
	}

int ec_GFp_fecc_point_set_affine_coordinates(const EC_GROUP *group, EC_POINT *point,
	const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx)
	{
	if (x == NULL || y == NULL)
		{
		/* unlike for projective coordinates, we do not tolerate this */
		ECerr(EC_F_EC_GFP_FECC_POINT_SET_AFFINE_COORDINATES, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}

	return EC_POINT_set_Jprojective_coordinates_GFp(group, point, x, y, BN_value_one(), ctx);
	}

//
// m values for P384
//
#define m0P384 0x00000000ffffffffull
#define m1P384 0xffffffff00000000ull
#define m2P384 0xfffffffffffffffeull
#define m3P384 0xffffffffffffffffull
#define m4P384 0xffffffffffffffffull
#define m5P384 0xffffffffffffffffull

int ec_GFp_hw_point_get_affine_coordinates_p384(const EC_GROUP *group, const EC_POINT *point,
	BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
	{
	void (*mulP384)(uint64_t *, uint64_t *, uint64_t *);
	void (*subP384)(uint64_t *, uint64_t *, uint64_t *);
	const BIGNUM *Z_;
	int ret = 0;
	uint64_t u[6]={0,0,0,0,0,0},v[6];
	uint64_t x1[6]={1,0,0,0,0,0},x2[6]={0,0,0,0,0,0},X[6]={0,0,0,0,0,0},Y[6]={0,0,0,0,0,0},Z_inv[6];
	uint64_t ci;
	
	int i;

	if (EC_POINT_is_at_infinity(group, point))
		{
		ECerr(EC_F_EC_GFP_FECC_POINT_GET_AFFINE_COORDINATES, EC_R_POINT_AT_INFINITY);
		return 0;
		}

	if(OCTEON_IS_OCTEON3())
	    {  
		mulP384 = fecc_MulP384o3Asm;
		subP384 = fecc_SubP384Asm;
	    }	
	else
	    {   
		mulP384 = fecc_MulP384AsmB17731;
		subP384 = fecc_SubP384AsmB17731;
	    }
	/* transform  (X, Y, Z)  into  (x, y) := (X/Z, Y/Z) */

	Z_ = &point->Z;
	
	if (BN_is_one(Z_))
		{
		if (x != NULL)
			{
			if (!BN_copy(x, &point->X)) goto err;
			}
		if (y != NULL)
			{
			if (!BN_copy(y, &point->Y)) goto err;
			}
		}
	else
		{
		for (i=0;i<(point->X).top;i++)
			X[i] = (point->X).d[i];
		for (i=0;i<(point->Y).top;i++)
			Y[i] = (point->Y).d[i];
		for(i=0;i<Z_->top;i++)
			u[i] = Z_->d[i]; 

		v[0] = m0P384;
		v[1] = m1P384;
		v[2] = m2P384;
		v[3] = m3P384;
		v[4] = m4P384;
		v[5] = m5P384;

		while(!(!u[5] && !u[4] && !u[3] && !u[2] && !u[1] && u[0] == 1) 
			&& !(!v[5] && !v[4] && !v[3] && !v[2] && !v[1] && v[0] == 1))
		{	
			
//			uint64_t junk;
            while(!(u[0]&1)) 
			{
			/* u = u/2*/
				u[0] = u[1]<< 63 |u[0] >> 1;	
				u[1] = u[2]<< 63 |u[1] >> 1;	
				u[2] = u[3]<< 63 |u[2] >> 1;	
				u[3] = u[4]<< 63 |u[3] >> 1;	
				u[4] = u[5]<< 63 |u[4] >> 1;	
				u[5] = u[5] >> 1;	
			/* x is even */
				if (!(x1[0]&1))
				{
			/* X1 = X1 /2 */	
					x1[0] = x1[1]<< 63 |x1[0] >> 1;	
					x1[1] = x1[2]<< 63 |x1[1] >> 1;	
					x1[2] = x1[3]<< 63 |x1[2] >> 1;	
					x1[3] = x1[4]<< 63 |x1[3] >> 1;	
					x1[4] = x1[5]<< 63 |x1[4] >> 1;	
					x1[5] = x1[5]>> 1;
				}
			/* x1 = (x1+p)/2 */
				else 
				{
					ci=0;
					ADDCS(ci,x1[0],m0P384,x1[0]);
					ADDCS(ci,x1[1],m1P384,x1[1]);
					ADDCS(ci,x1[2],m2P384,x1[2]);
					ADDCS(ci,x1[3],m3P384,x1[3]);
					ADDCS(ci,x1[4],m4P384,x1[4]);
					ADDCS(ci,x1[5],m5P384,x1[5]);
					x1[0] = x1[1]<< 63 |x1[0] >> 1;	
					x1[1] = x1[2]<< 63 |x1[1] >> 1;	
					x1[2] = x1[3]<< 63 |x1[2] >> 1;	
					x1[3] = x1[4]<< 63 |x1[3] >> 1;	
					x1[4] = x1[5]<< 63 |x1[4] >> 1;	
					x1[5] = x1[5]>> 1 |ci << 63;
				}
			}
			while(!(v[0]&1)) // count trailing zeros, do 1 shift ?
			{
			/* v = v/2*/
				v[0] = v[1]<< 63 |v[0] >> 1;	
				v[1] = v[2]<< 63 |v[1] >> 1;	
				v[2] = v[3]<< 63 |v[2] >> 1;	
				v[3] = v[4]<< 63 |v[3] >> 1;	
				v[4] = v[5]<< 63 |v[4] >> 1;	
				v[5] = v[5]>> 1;
			/* x2 is even */
				if (!(x2[0]&1))
				{
				/* X2 = X2 /2 */	
					x2[0] = x2[1]<< 63 |x2[0] >> 1;	
					x2[1] = x2[2]<< 63 |x2[1] >> 1;	
					x2[2] = x2[3]<< 63 |x2[2] >> 1;	
					x2[3] = x2[4]<< 63 |x2[3] >> 1;	
					x2[4] = x2[5]<< 63 |x2[4] >> 1;	
					x2[5] = x2[5]>> 1;
				}
			/* x2 = (x2+p)/2 */
				else 
				{
					ci=0;
					ADDCS(ci,x2[0],m0P384,x2[0]);
					ADDCS(ci,x2[1],m1P384,x2[1]);
					ADDCS(ci,x2[2],m2P384,x2[2]);
					ADDCS(ci,x2[3],m3P384,x2[3]);
					ADDCS(ci,x2[4],m4P384,x2[4]);
					ADDCS(ci,x2[5],m5P384,x2[5]);
					x2[0] = x2[1]<< 63 |x2[0] >> 1;	
					x2[1] = x2[2]<< 63 |x2[1] >> 1;	
					x2[2] = x2[3]<< 63 |x2[2] >> 1;	
					x2[3] = x2[4]<< 63 |x2[3] >> 1;	
					x2[4] = x2[5]<< 63 |x2[4] >> 1;	
					x2[5] = x2[5]>> 1 |ci << 63;
				}
			}

			/* if u >= v; u=u-v x1=x1-x2*/
			ci=0;

			SUBCS_M(ci,u[0],v[0]);
			SUBCS_M(ci,u[1],v[1]);
			SUBCS_M(ci,u[2],v[2]);
			SUBCS_M(ci,u[3],v[3]);
			SUBCS_M(ci,u[4],v[4]);
			SUBCS_M(ci,u[5],v[5]);
            /*
			SUBCS(ci,junk,u[0],v[0]);
			SUBCS(ci,junk,u[1],v[1]);
			SUBCS(ci,junk,u[2],v[2]);
			SUBCS(ci,junk,u[3],v[3]);
			SUBCS(ci,junk,u[4],v[4]);
			SUBCS(ci,junk,u[5],v[5]);
			*/
            if (!ci)
			{
				subP384(u,u,v);
				subP384(x1,x1,x2);
			}
			/*else v=v-u x2=x2-x1 */
			else 
			{
				subP384(v,v,u);
				subP384(x2,x2,x1);
			}

		}
		/* u=1 return x1modp else x2modp */
		if(!u[5] && !u[4] && !u[3] && !u[2] && !u[1] && u[0] == 1)
		{
			uint64_t t0,t1,t2;
			t0 = x1[0];
			t1 = x1[1];
			t2 = x1[2];
			Z_inv[0] = t0;
			Z_inv[1] = t1;
			Z_inv[2] = t2;
			t0 = x1[3];
			t1 = x1[4];
			t2 = x1[5];
			Z_inv[3] = t0;
			Z_inv[4] = t1;
			Z_inv[5] = t2;
		}
		else 
		{
			uint64_t t0,t1,t2;
			t0 = x2[0];
			t1 = x2[1];
			t2 = x2[2];
			Z_inv[0] = t0;
			Z_inv[1] = t1;
			Z_inv[2] = t2;
			t0 = x2[3];
			t1 = x2[4];
			t2 = x2[5];
			Z_inv[3] = t0;
			Z_inv[4] = t1;
			Z_inv[5] = t2;
		}	

		if (x != NULL)
		{
			mulP384(X,X,Z_inv);
			if(bn_wexpand(x,6)==NULL) goto err;
			x->top = 6; 
			for (i=0;i<6;i++)		// a few cycles repeating the above inlining
				x->d[i] = X[i];
			bn_fix_top(x);

		}
		if (y != NULL)
		{
			mulP384(Y,Y,Z_inv);
			if(bn_wexpand(y,6)==NULL) goto err;
			y->top = 6; 
			for (i=0;i<6;i++)
				y->d[i] = Y[i];
			bn_fix_top(y);


		}
		} // end of else (BN_is_one)

	ret = 1;

 err:
	return ret;
	}
//
// m values for p256
//
#define m0P256 0XFFFFFFFFFFFFFFFFull
#define m1P256 0X00000000FFFFFFFFull
#define m2P256 0X0000000000000000ull
#define m3P256 0XFFFFFFFF00000001ull

int ec_GFp_hw_point_get_affine_coordinates_p256(const EC_GROUP *group, const EC_POINT *point,
	BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
	{
	void (*mulP256)(uint64_t *, uint64_t *, uint64_t *);
	void (*subP256)(uint64_t *, uint64_t *, uint64_t *);
	const BIGNUM *Z_;
	int ret = 0;
	uint64_t u[4]={0,0,0,0},v[4]={0,0,0,0};
	uint64_t x1[4]={1,0,0,0},x2[4]={0,0,0,0},X[4]={0,0,0,0},Y[4]={0,0,0,0},Z_inv[4]={0,0,0,0};
	uint64_t ci;
	
	int i;

	if (EC_POINT_is_at_infinity(group, point))
		{
		ECerr(EC_F_EC_GFP_FECC_POINT_GET_AFFINE_COORDINATES, EC_R_POINT_AT_INFINITY);
		return 0;
		}

	if(OCTEON_IS_OCTEON3())
	    {
		mulP256 = fecc_MulP256o3Asm;
		subP256 = fecc_SubP256Asm;
	    }
	else 
	    {
		mulP256 = fecc_MulP256AsmB17731;
		subP256 = fecc_SubP256AsmB17731;
	    }

	/* transform  (X, Y, Z)  into  (x, y) := (X/Z, Y/Z) */

	Z_ = &point->Z;
	
	if (BN_is_one(Z_))
		{
			if (x != NULL)
				{
				if (!BN_copy(x, &point->X)) goto err;
				}
			if (y != NULL)
				{
				if (!BN_copy(y, &point->Y)) goto err;
				}
		}
	else
		{
		for (i=0;i<(point->X).top;i++)
			X[i] = (point->X).d[i];
		for (i=0;i<(point->Y).top;i++)
			Y[i] = (point->Y).d[i];
		for(i=0;i<Z_->top;i++)
			u[i] = Z_->d[i]; 

		v[0] = m0P256;
		v[1] = m1P256;
		v[2] = m2P256;
		v[3] = m3P256;

		while(!(!u[3] && !u[2] && !u[1] && u[0] == 1) 
			&& !(!v[3] && !v[2] && !v[1] && v[0] == 1))
		{	
			while(!(u[0]&1)) 
			{
		/* u = u/2*/
			u[0] = u[1]<< 63 |u[0] >> 1;	
			u[1] = u[2]<< 63 |u[1] >> 1;	
			u[2] = u[3]<< 63 |u[2] >> 1;	
			u[3] = u[3] >> 1;	
		/* x is even */
			if (!(x1[0]&1))
			{
		/* X1 = X1 /2 */	
				x1[0] = x1[1]<< 63 |x1[0] >> 1;	
				x1[1] = x1[2]<< 63 |x1[1] >> 1;	
				x1[2] = x1[3]<< 63 |x1[2] >> 1;	
				x1[3] = x1[3]>> 1;
			}
		/* x1 = (x1+p)/2 */
			else 
			{
				ci = 0;
	   			ADDCS(ci,x1[0],x1[0],m0P256);
   				ADDCS(ci,x1[1],x1[1],m1P256);
   				ADDCS(ci,x1[2],x1[2],m2P256);
   				ADDCS(ci,x1[3],x1[3],m3P256);
				x1[0] = x1[1]<< 63 |x1[0] >> 1;	
				x1[1] = x1[2]<< 63 |x1[1] >> 1;	
				x1[2] = x1[3]<< 63 |x1[2] >> 1;	
				x1[3] = x1[3]>> 1 |ci << 63;
			}
			}
			while(!(v[0]&1)) 
			{
		/* v = v/2*/
			v[0] = v[1]<< 63 |v[0] >> 1;	
			v[1] = v[2]<< 63 |v[1] >> 1;	
			v[2] = v[3]<< 63 |v[2] >> 1;	
			v[3] = v[3]>> 1;
		/* x2 is even */
			if (!(x2[0]&1))
			{
		/* X2 = X2 /2 */	
				x2[0] = x2[1]<< 63 |x2[0] >> 1;	
				x2[1] = x2[2]<< 63 |x2[1] >> 1;	
				x2[2] = x2[3]<< 63 |x2[2] >> 1;	
				x2[3] = x2[3]>> 1;
			}
		/* x2 = (x2+p)/2 */
			else 
			{
				ci = 0;
	   			ADDCS(ci,x2[0],x2[0],m0P256);
   				ADDCS(ci,x2[1],x2[1],m1P256);
   				ADDCS(ci,x2[2],x2[2],m2P256);
   				ADDCS(ci,x2[3],x2[3],m3P256);
				x2[0] = x2[1]<< 63 |x2[0] >> 1;	
				x2[1] = x2[2]<< 63 |x2[1] >> 1;	
				x2[2] = x2[3]<< 63 |x2[2] >> 1;	
				x2[3] = x2[3]>> 1 |ci << 63;
			}
			}
			/* if u >= v; u=u-v x1=x1-x2*/
			ci = 0;
			{

			SUBCS_M(ci,u[0],v[0]);
			SUBCS_M(ci,u[1],v[1]);
			SUBCS_M(ci,u[2],v[2]);
			SUBCS_M(ci,u[3],v[3]);
			/*uint64_t junk;
			SUBCS(ci,junk,u[0],v[0]);
			SUBCS(ci,junk,u[1],v[1]);
			SUBCS(ci,junk,u[2],v[2]);
			SUBCS(ci,junk,u[3],v[3]);
			*/
            }
			if (!ci)
			{
				subP256(u,u,v);
				subP256(x1,x1,x2);
			}
			/*else v=v-u x2=x2-x1 */
			else 
			{
				subP256(v,v,u);
				subP256(x2,x2,x1);
			}

		}
		/* u=1 return x1modp else x2modp */
		if(!u[3] && !u[2] && !u[1] && u[0] == 1)
		{
			for (i=0;i<4;i++)
				Z_inv[i] = x1[i];
		}
		else 
		{
			for (i=0;i<4;i++)
				Z_inv[i] = x2[i];
		}	

		if (x != NULL)
		{
			mulP256(X,X,Z_inv);
			if(bn_wexpand(x,4)==NULL) goto err;
			x->top = 4; 
			for (i=0;i<4;i++)
				x->d[i] = X[i];
			bn_fix_top(x);

		}
		if (y != NULL)
		{
			mulP256(Y,Y,Z_inv);
			if(bn_wexpand(y,4)==NULL) goto err;
			y->top = 4; 
			for (i=0;i<4;i++)
				y->d[i] = Y[i];
			bn_fix_top(y);


		}
		}

	ret = 1;

 err:
	return ret;
	}


//
// m values for P521
//
#define m0P521 0xffffffffffffffffull
#define m1P521 0xffffffffffffffffull
#define m2P521 0xffffffffffffffffull
#define m3P521 0xffffffffffffffffull
#define m4P521 0xffffffffffffffffull
#define m5P521 0xffffffffffffffffull
#define m6P521 0xffffffffffffffffull
#define m7P521 0xffffffffffffffffull
#define m8P521 0x00000000000001ffull

int ec_GFp_hw_point_get_affine_coordinates(const EC_GROUP *group, const EC_POINT *point,
	BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
	{
	void (*mulP521)(uint64_t *, uint64_t *, uint64_t *);
	void (*subP521)(uint64_t *, uint64_t *, uint64_t *);
	const BIGNUM *Z_;
	int ret = 0;
	/* P521 only  */
	uint64_t u[9]={0,0,0,0,0,0,0,0,0},v[9];
	uint64_t x1[9]={1,0,0,0,0,0,0,0,0},x2[9]={0,0,0,0,0,0,0,0,0},X[9]={0,0,0,0,0,0,0,0,0},Y[9]={0,0,0,0,0,0,0,0,0},Z_inv[9]={0,0,0,0,0,0,0,0,0};
	uint64_t ci;
	int i;
    uint64_t *pt;
	
    if (group->curve_name == NID_X9_62_prime256v1)
		return ec_GFp_hw_point_get_affine_coordinates_p256(group, point,x,y,ctx);
	else if (group->curve_name == NID_secp384r1)
		return ec_GFp_hw_point_get_affine_coordinates_p384(group, point,x,y,ctx);
	else if (group->curve_name == NID_secp521r1)
		{/*execute this routine */}
	else return ec_GFp_fecc_point_get_affine_coordinates(group, point, x, y, ctx);

	if (EC_POINT_is_at_infinity(group, point))
		{
		ECerr(EC_F_EC_GFP_FECC_POINT_GET_AFFINE_COORDINATES, EC_R_POINT_AT_INFINITY);
		return 0;
		}

//
// this is now P521 only
//
	/* transform  (X, Y, Z)  into  (x, y) := (X/Z, Y/Z) */

	if(OCTEON_IS_OCTEON3())
	    {
		mulP521 = fecc_MulP521o3Asm;
		subP521 = fecc_SubP521Asm;
	    }
	else 
	    {
		mulP521 = fecc_MulP521AsmB17731;
		subP521 = fecc_SubP521AsmB17731;
	    }
	
	Z_ = &point->Z;
	
	if (BN_is_one(Z_))
		{
			if (x != NULL)
				{
				if (!BN_copy(x, &point->X)) goto err;
				}
			if (y != NULL)
				{
				if (!BN_copy(y, &point->Y)) goto err;
				}
		}
	else
		{
		for (i=0;i<(point->X).top;i++)
			X[i] = (point->X).d[i];
		for (i=0;i<(point->Y).top;i++)
			Y[i] = (point->Y).d[i];
		for(i=0;i<Z_->top;i++)
			u[i] = Z_->d[i]; 

		v[0] = m0P521;
		v[1] = m1P521;
		v[2] = m2P521;
		v[3] = m3P521;
		v[4] = m4P521;
		v[5] = m5P521;
		v[6] = m6P521;
		v[7] = m7P521;
		v[8] = m8P521;

		while(!(!u[8] &&!u[7] &&!u[6] &&!u[5] && !u[4] && !u[3] && !u[2] && !u[1] && u[0] == 1) 
			&& !(!v[8] &&!v[7] &&!v[6] &&!v[5] && !v[4] && !v[3] && !v[2] && !v[1] && v[0] == 1))
		{	
			
		//	uint64_t junk;


            while(!(u[0]&1)) 
			{
		/* u = u/2*/
			u[0] = u[1]<< 63 |u[0] >> 1;	
			u[1] = u[2]<< 63 |u[1] >> 1;	
			u[2] = u[3]<< 63 |u[2] >> 1;	
			u[3] = u[4]<< 63 |u[3] >> 1;	
			u[4] = u[5]<< 63 |u[4] >> 1;	
			u[5] = u[6]<< 63 |u[5] >> 1;	
			u[6] = u[7]<< 63 |u[6] >> 1;	
			u[7] = u[8]<< 63 |u[7] >> 1;	
			u[8] = u[8]>> 1;
		/* x is even */
			if (!(x1[0]&1))
			{
		/* X1 = X1 /2 */	
				x1[0] = x1[1]<< 63 |x1[0] >> 1;	
				x1[1] = x1[2]<< 63 |x1[1] >> 1;	
				x1[2] = x1[3]<< 63 |x1[2] >> 1;	
				x1[3] = x1[4]<< 63 |x1[3] >> 1;	
				x1[4] = x1[5]<< 63 |x1[4] >> 1;	
				x1[5] = x1[6]<< 63 |x1[5] >> 1;	
				x1[6] = x1[7]<< 63 |x1[6] >> 1;	
				x1[7] = x1[8]<< 63 |x1[7] >> 1;	
				x1[8] = x1[8]>> 1;
			}
		/* x1 = (x1+p)/2 */
			else 
			{
				ci = 0;
				ADDCS(ci,x1[0],m0P521,x1[0]);
				ADDCS(ci,x1[1],m1P521,x1[1]);
				ADDCS(ci,x1[2],m2P521,x1[2]);
				ADDCS(ci,x1[3],m3P521,x1[3]);
				ADDCS(ci,x1[4],m4P521,x1[4]);
				ADDCS(ci,x1[5],m5P521,x1[5]);
				ADDCS(ci,x1[6],m6P521,x1[6]);
				ADDCS(ci,x1[7],m7P521,x1[7]);
				ADDCS(ci,x1[8],m8P521,x1[8]);
				x1[0] = x1[1]<< 63 |x1[0] >> 1;	
				x1[1] = x1[2]<< 63 |x1[1] >> 1;	
				x1[2] = x1[3]<< 63 |x1[2] >> 1;	
				x1[3] = x1[4]<< 63 |x1[3] >> 1;	
				x1[4] = x1[5]<< 63 |x1[4] >> 1;	
				x1[5] = x1[6]<< 63 |x1[5] >> 1;	
				x1[6] = x1[7]<< 63 |x1[6] >> 1;	
				x1[7] = x1[8]<< 63 |x1[7] >> 1;	
				x1[8] = x1[8]>> 1 |ci << 63;
			}
			}
			while(!(v[0]&1)) 
			{
		/* v = v/2*/
			v[0] = v[1]<< 63 |v[0] >> 1;	
			v[1] = v[2]<< 63 |v[1] >> 1;	
			v[2] = v[3]<< 63 |v[2] >> 1;	
			v[3] = v[4]<< 63 |v[3] >> 1;	
			v[4] = v[5]<< 63 |v[4] >> 1;	
			v[5] = v[6]<< 63 |v[5] >> 1;	
			v[6] = v[7]<< 63 |v[6] >> 1;	
			v[7] = v[8]<< 63 |v[7] >> 1;	
			v[8] = v[8]>> 1;
		/* x2 is even */
			if (!(x2[0]&1))
			{
		/* X2 = X2 /2 */	
				x2[0] = x2[1]<< 63 |x2[0] >> 1;	
				x2[1] = x2[2]<< 63 |x2[1] >> 1;	
				x2[2] = x2[3]<< 63 |x2[2] >> 1;	
				x2[3] = x2[4]<< 63 |x2[3] >> 1;	
				x2[4] = x2[5]<< 63 |x2[4] >> 1;	
				x2[5] = x2[6]<< 63 |x2[5] >> 1;	
				x2[6] = x2[7]<< 63 |x2[6] >> 1;	
				x2[7] = x2[8]<< 63 |x2[7] >> 1;	
				x2[8] = x2[8]>> 1;
			}
		/* x2 = (x2+p)/2 */
			else 
			{
				ci = 0;
				ADDCS(ci,x2[0],m0P521,x2[0]);
				ADDCS(ci,x2[1],m1P521,x2[1]);
				ADDCS(ci,x2[2],m2P521,x2[2]);
				ADDCS(ci,x2[3],m3P521,x2[3]);
				ADDCS(ci,x2[4],m4P521,x2[4]);
				ADDCS(ci,x2[5],m5P521,x2[5]);
				ADDCS(ci,x2[6],m6P521,x2[6]);
				ADDCS(ci,x2[7],m7P521,x2[7]);
				ADDCS(ci,x2[8],m8P521,x2[8]);
				x2[0] = x2[1]<< 63 |x2[0] >> 1;	
				x2[1] = x2[2]<< 63 |x2[1] >> 1;	
				x2[2] = x2[3]<< 63 |x2[2] >> 1;	
				x2[3] = x2[4]<< 63 |x2[3] >> 1;	
				x2[4] = x2[5]<< 63 |x2[4] >> 1;	
				x2[5] = x2[6]<< 63 |x2[5] >> 1;	
				x2[6] = x2[7]<< 63 |x2[6] >> 1;	
				x2[7] = x2[8]<< 63 |x2[7] >> 1;	
				x2[8] = x2[8]>> 1 |ci << 63;
			}
			}
			/* if u >= v; u=u-v x1=x1-x2*/
			ci = 0;
	        SUBCS_M(ci,u[0],v[0]);
            SUBCS_M(ci,u[1],v[1]);
            SUBCS_M(ci,u[2],v[2]);
            SUBCS_M(ci,u[3],v[3]);
            SUBCS_M(ci,u[4],v[4]);
            SUBCS_M(ci,u[5],v[5]);
            SUBCS_M(ci,u[6],v[6]);
            SUBCS_M(ci,u[7],v[7]);
            SUBCS_M(ci,u[8],v[8]);

            /*
			SUBCS(ci,junk,u[0],v[0]);
			SUBCS(ci,junk,u[1],v[1]);
			SUBCS(ci,junk,u[2],v[2]);
			SUBCS(ci,junk,u[3],v[3]);
			SUBCS(ci,junk,u[4],v[4]);
			SUBCS(ci,junk,u[5],v[5]);
			SUBCS(ci,junk,u[6],v[6]);
			SUBCS(ci,junk,u[7],v[7]);
			SUBCS(ci,junk,u[8],v[8]);
			*/
            if (!ci)
			{
				subP521(u,u,v);
				subP521(x1,x1,x2);
			}
			/*else v=v-u x2=x2-x1 */
			else 
			{
				subP521(v,v,u);
				subP521(x2,x2,x1);
			}

		}
		/* u=1 return x1modp else x2modp */

		pt = x2;
		if(!u[8] &&!u[7] &&!u[6] &&!u[5] && !u[4] && !u[3] && !u[2] && !u[1] && u[0] == 1)
		{
			pt = x1;
		}
{
	uint64_t t0,t1,t2;

		t0 = pt[0];
		t1 = pt[1];
		t2 = pt[2];
		Z_inv[0] = t0;
		Z_inv[1] = t1;
		Z_inv[2] = t2;
		t0 = pt[3];
		t1 = pt[4];
		t2 = pt[5];
		Z_inv[3] = t0;
		Z_inv[4] = t1;
		Z_inv[5] = t2;
		t0 = pt[6];
		t1 = pt[7];
		t2 = pt[8];
		Z_inv[6] = t0;
		Z_inv[7] = t1;
		Z_inv[8] = t2;
}
		if (x != NULL)
		{
			mulP521(X,Z_inv,X);
			if(bn_wexpand(x,9)==NULL) goto err;
			x->top = 9; 
			//
			// Cycles will be saved by doing the same as in the
			// previous stores.  Otherwise the compiler lines up 
			// loads and stores, so there is a 18 cycle stall.
			// The same is true for the next also.
				x->d[0] = X[0];
				x->d[1] = X[1];
				x->d[2] = X[2];
				x->d[3] = X[3];
				x->d[4] = X[4];
				x->d[5] = X[5];
				x->d[6] = X[6];
				x->d[7] = X[7];
				x->d[8] = X[8];
			bn_fix_top(x);

		}
		if (y != NULL)
		{
			mulP521(Y,Z_inv,Y);
			if(bn_wexpand(y,9)==NULL) goto err;
			y->top = 9; 
				y->d[0] = Y[0];
				y->d[1] = Y[1];
				y->d[2] = Y[2];
				y->d[3] = Y[3];
				y->d[4] = Y[4];
				y->d[5] = Y[5];
				y->d[6] = Y[6];
				y->d[7] = Y[7];
				y->d[8] = Y[8];
			bn_fix_top(y);

		}
		}

	ret = 1;

 err:
	return ret;
	}

int ec_GFp_fecc_point_get_affine_coordinates(const EC_GROUP *group, const EC_POINT *point,
	BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
	{
	BN_CTX *new_ctx = NULL;
	BIGNUM *Z_1;
	const BIGNUM *Z_;
	int ret = 0;

	if (EC_POINT_is_at_infinity(group, point))
		{
		ECerr(EC_F_EC_GFP_FECC_POINT_GET_AFFINE_COORDINATES, EC_R_POINT_AT_INFINITY);
		return 0;
		}
	if(ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();	
		if(ctx == NULL)
			return 0;
		}

	BN_CTX_start(ctx);
//	Z = BN_CTX_get(ctx);
	Z_1 = BN_CTX_get(ctx);

	/* transform  (X, Y, Z)  into  (x, y) := (X/Z, Y/Z) */

	Z_ = &point->Z;
	
	if (BN_is_one(Z_))
		{
			if (x != NULL)
				{
				if (!BN_copy(x, &point->X)) goto err;
				}
			if (y != NULL)
				{
				if (!BN_copy(y, &point->Y)) goto err;
				}
		}
	else
		{
		if (!BN_mod_inverse(Z_1, Z_, &group->field, ctx))
			{
			ECerr(EC_F_EC_GFP_FECC_POINT_GET_AFFINE_COORDINATES, ERR_R_BN_LIB);
			goto err;
			}

		if (x != NULL)
			if (!group->meth->field_mul(group, x, &point->X, Z_1, ctx)) goto err;

		if (y != NULL)
			if (!group->meth->field_mul(group, y, &point->Y, Z_1, ctx)) goto err;
		}

	ret = 1;

 err:
	BN_CTX_end(ctx);
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	return ret;
	}

int ec_GFp_hw_dbl_p521(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a)
	{
	void (*mulP521)(uint64_t *, uint64_t *, uint64_t *);
	void (*subP521)(uint64_t *, uint64_t *, uint64_t *);
	void (*constMulP521)(uint64_t *, uint64_t *, uint64_t);
	int ret = 0;
	uint64_t X[9],Y[9],Z[9],res1[10],res2[10],res3[18],res4[18];
	uint64_t W[9],S[9],B[9],H[9],S_new[9];
	int i;


	if(OCTEON_IS_OCTEON3())
	    {
		mulP521 = fecc_MulP521o3Asm;
		subP521 = fecc_SubP521Asm;
		constMulP521 = fecc_ConstMulP521Asm;
	    }
	else 
	    {
		mulP521 = fecc_MulP521AsmB17731;
		subP521 = fecc_SubP521AsmB17731;
		constMulP521 = fecc_ConstMulP521AsmB17731;
	    }
	
	X[0]=Y[0]=Z[0]=0;
	X[1]=Y[1]=Z[1]=0;
	X[2]=Y[2]=Z[2]=0;
	X[3]=Y[3]=Z[3]=0;
	X[4]=Y[4]=Z[4]=0;
	X[5]=Y[5]=Z[5]=0;
	X[6]=Y[6]=Z[6]=0;
	X[7]=Y[7]=Z[7]=0;
	X[8]=Y[8]=Z[8]=0;
	for (i=0;i<(a->Z).top;i++)
		Z[i] = (a->Z).d[i]; //avoid DWB
	for (i=0;i<(a->X).top;i++)
		X[i] = (a->X).d[i];
	for (i=0;i<(a->Y).top;i++)
		Y[i] = (a->Y).d[i];
	if (!Z[0] && !Z[1] && !Z[2] && !Z[3] && !Z[4] && !Z[5] && !Z[6] && !Z[7] && !Z[8])
		{
		BN_zero(&r->Z);
		r->Z_is_one = 0;
		return 1;
		}

	// I don't understand how this worked with the a_is_minus3 clause?
	//
	// if (group->a_is_minus3)
	// {
	
{
	uint64_t ci;
	ci = 0;
	ADDCS(ci,res1[0],X[0],Z[0]);
	ADDCS(ci,res1[1],X[1],Z[1]);
	ADDCS(ci,res1[2],X[2],Z[2]);
	ADDCS(ci,res1[3],X[3],Z[3]);
	ADDCS(ci,res1[4],X[4],Z[4]);
	ADDCS(ci,res1[5],X[5],Z[5]);
	ADDCS(ci,res1[6],X[6],Z[6]);
	ADDCS(ci,res1[7],X[7],Z[7]);
	ADDCS(ci,res1[8],X[8],Z[8]);

	if(res1[8] > m8P521)		// result of subtract cant be negative if true
	{
		ci = 0;
		SUBCS(ci,res1[0],res1[0],m0P521);
		SUBCS(ci,res1[1],res1[1],m1P521);
		SUBCS(ci,res1[2],res1[2],m2P521);
		SUBCS(ci,res1[3],res1[3],m3P521);
		SUBCS(ci,res1[4],res1[4],m4P521);
		SUBCS(ci,res1[5],res1[5],m5P521);
		SUBCS(ci,res1[6],res1[6],m6P521);
		SUBCS(ci,res1[7],res1[7],m7P521);
		SUBCS(ci,res1[8],res1[8],m8P521);
	}
}
	subP521(res2,X,Z);
	/* res3 = res1 * res2 mod p */
	// caviumMulP521o3Asm(res3,res2,res1);
	mulP521(res3,res2,res1);

	constMulP521(W,res3,3);

	// } // a_is_minus3	
	/* n1 = a*Z^2 + 3*X^2 */

	/* X_r */
	/* S = Z*Y
	   res4 = X*Y */
	mulP521(S,Y,Z);
	mulP521(res4,Y,X);
	mulP521(B,S,res4);

	constMulP521(res3,B,8);
	mulP521(res4,W,W);
	subP521(H,res4,res3);
	mulP521(res3,S,H);
	constMulP521(res3,res3,2);

	if(bn_wexpand(&r->X,9)==NULL) goto err;

	(&r->X)->top = 9; 
{
uint64_t t0,t1,t2,t3,t4;
	t0 = res3[0];
	t1 = res3[1];
	t2 = res3[2];
	t3 = res3[3];
	t4 = res3[4];
	(&r->X)->d[0] = t0;
	(&r->X)->d[1] = t1;
	(&r->X)->d[2] = t2;
	(&r->X)->d[3] = t3;
	(&r->X)->d[4] = t4;
	t0 = res3[5];
	t1 = res3[6];
	t2 = res3[7];
	t3 = res3[8];
	(&r->X)->d[5] = t0;
	(&r->X)->d[6] = t1;
	(&r->X)->d[7] = t2;
	(&r->X)->d[8] = t3;
}
	bn_fix_top(&r->X);


	/* Y_r */
	/* W*(4*B - H) */
	/* 4*B */
	constMulP521(res3,B,4);
	/* 4*B - H */
	subP521(res3,res3,H);
	/* W(4B-H) */
	mulP521(res3,res3,W);
	mulP521(S_new,S,S);
	
	/* 8*S^2  */
	constMulP521(S_new,S_new,8);
	/* res4 = Y^2 */
	mulP521(res4,Y,Y);
	mulP521(res4,res4,S_new);
	/* res3 = res3 - res4 */	
	subP521(res3,res3,res4);

	if(bn_wexpand(&r->Y,9)==NULL) goto err;

	(&r->Y)->top = 9; 
{
uint64_t t0,t1,t2;
	t0 = res3[0];
	t1 = res3[1];
	t2 = res3[2];
	(&r->Y)->d[0] = t0;
	(&r->Y)->d[1] = t1;
	(&r->Y)->d[2] = t2;
	t0 = res3[3];
	t1 = res3[4];
	t2 = res3[5];
	(&r->Y)->d[3] = t0;
	(&r->Y)->d[4] = t1;
	(&r->Y)->d[5] = t2;
	t0 = res3[6];
	t1 = res3[7];
	t2 = res3[8];
	(&r->Y)->d[6] = t0;
	(&r->Y)->d[7] = t1;
	(&r->Y)->d[8] = t2;
}
	bn_fix_top(&r->Y);

	/* Z_r */
	mulP521(res3,S,S_new);

	if(bn_wexpand(&r->Z,9)==NULL) goto err;

{
uint64_t t0,t1,t2,t3,t4;
	t0 = res3[0];
	t1 = res3[1];
	t2 = res3[2];
	t3 = res3[3];
	t4 = res3[4];
	(&r->Z)->d[0] = t0;
	(&r->Z)->d[1] = t1;
	(&r->Z)->d[2] = t2;
	(&r->Z)->d[3] = t3;
	(&r->Z)->d[4] = t4;
	t0 = res3[5];
	t1 = res3[6];
	t2 = res3[7];
	t3 = res3[8];
	(&r->Z)->d[5] = t0;
	(&r->Z)->d[6] = t1;
	(&r->Z)->d[7] = t2;
	(&r->Z)->d[8] = t3;
}
	(&r->Z)->top = 9; 
	bn_fix_top(&r->Z);

	r->Z_is_one = 0;

	ret = 1;

 err:
	return ret;
	}

int ec_GFp_hw_add_p521(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b)	
	{
	void (*mulP521)(uint64_t *, uint64_t *, uint64_t *);
	void (*subP521)(uint64_t *, uint64_t *, uint64_t *);
	void (*constMulP521)(uint64_t *, uint64_t *, uint64_t);
	int ret = 0;
     	uint64_t pdt1[18],pdt2[18],res1[10];
	uint64_t X1[9],X2[9],Y1[9],Y2[9],Z1[9],Z2[9];
	uint64_t U[9],V[9],U2[9],V2[9],W[9],A[9],V_2[9],V_3[9];
	int i;

	
	if(OCTEON_IS_OCTEON3())
	    {
		mulP521 = fecc_MulP521o3Asm;
		subP521 = fecc_SubP521Asm;
		constMulP521 = fecc_ConstMulP521Asm;
	    }
	else 
	    {
		mulP521 = fecc_MulP521AsmB17731;
		subP521 = fecc_SubP521AsmB17731;
		constMulP521 = fecc_ConstMulP521AsmB17731;
	    }
	
	X1[0]=X2[0]=Y1[0]=Y2[0]=Z1[0]=Z2[0]=0;
	X1[1]=X2[1]=Y1[1]=Y2[1]=Z1[1]=Z2[1]=0;
	X1[2]=X2[2]=Y1[2]=Y2[2]=Z1[2]=Z2[2]=0;
	X1[3]=X2[3]=Y1[3]=Y2[3]=Z1[3]=Z2[3]=0;
	X1[4]=X2[4]=Y1[4]=Y2[4]=Z1[4]=Z2[4]=0;
	X1[5]=X2[5]=Y1[5]=Y2[5]=Z1[5]=Z2[5]=0;
	X1[6]=X2[6]=Y1[6]=Y2[6]=Z1[6]=Z2[6]=0;
	X1[7]=X2[7]=Y1[7]=Y2[7]=Z1[7]=Z2[7]=0;
	X1[8]=X2[8]=Y1[8]=Y2[8]=Z1[8]=Z2[8]=0;
	for (i=0;i<(a->X).top;i++)
		X1[i] = (a->X).d[i];
	for (i=0;i<(a->Y).top;i++)
		Y1[i] = (a->Y).d[i];
	for (i=0;i<(a->Z).top;i++)
		Z1[i] = (a->Z).d[i];

	if (!Z1[0] && !Z1[1] && !Z1[2] && !Z1[3] && !Z1[4] && !Z1[5] && !Z1[6] && !Z1[7] && !Z1[8])
		return EC_POINT_copy(r, b);

	for (i=0;i<(b->X).top;i++)
		X2[i] = (b->X).d[i];
	for (i=0;i<(b->Y).top;i++)
		Y2[i] = (b->Y).d[i];
	for (i=0;i<(b->Z).top;i++)
		Z2[i] = (b->Z).d[i];

	if (!Z2[0] && !Z2[1] && !Z2[2] && !Z2[3] && !Z2[4] && !Z2[5] && !Z2[6] && !Z2[7] && !Z2[8])
		return EC_POINT_copy(r, a);

	/* n1, n2 */
	/*U1= Y2*Z1*/
	mulP521(pdt1,Z1,Y2);
	mulP521(pdt2,Z1,X2);

	/* n3, n4 */
	if (b->Z_is_one)
		{
		for (i=0;i<9;i++)
		{
			U2[i] = Y1[i];
			V2[i] = X1[i];
		}
		}
	else 
		{
		/* U2 = Y1*Z2 */
		/* V2 = X1*Z2 */
		mulP521(U2,Z2,Y1);
		mulP521(V2,Z2,X1);
		}

	/* n5, n6 */
	subP521(U,pdt1,U2);
	subP521(V,pdt2,V2);

 	if (!V[0] && !V[1] && !V[2] && !V[3] && !V[4] && !V[5] && !V[6] && !V[7] && !V[8])
		{
		if (!U[0] && !U[1] && !U[2] && !U[3] && !U[4] && !U[5] && !U[6] && !U[7] && !U[8])		
			{
			/* a is the same point as b */
			ret = ec_GFp_hw_dbl_p521(group, r, a);
			goto end;
			}
		else
			{
			/* a is the inverse of b */
			BN_zero(&r->Z);
			r->Z_is_one = 0;
			ret = 1;
			goto end;
			}
		}
	/* n7 */
	/* W = Z1*Z2 */
	/* W = Z1*Z2 */
	mulP521(W,Z2,Z1);
	/* V^3 */
	mulP521(V_2,V,V);
	mulP521(V_3,V_2,V);
	/* V^3*W */
	mulP521(pdt2,V_3,W);

	if(bn_wexpand(&r->Z,9)==NULL) goto end;

	(&r->Z)->top = 9; 
{
uint64_t t0,t1,t2,t3,t4;
	t0 = pdt2[0];
	t1 = pdt2[1];
	t2 = pdt2[2];
	t3 = pdt2[3];
	t4 = pdt2[4];
	(&r->Z)->d[0] = t0;
	(&r->Z)->d[1] = t1;
	(&r->Z)->d[2] = t2;
	(&r->Z)->d[3] = t3;
	(&r->Z)->d[4] = t4;
	t0 = pdt2[5];
	t1 = pdt2[6];
	t2 = pdt2[7];
	t3 = pdt2[8];
	(&r->Z)->d[5] = t0;
	(&r->Z)->d[6] = t1;
	(&r->Z)->d[7] = t2;
	(&r->Z)->d[8] = t3;
}
	bn_fix_top(&r->Z);
	/* Z_r */
	r->Z_is_one = 0;

	/* U^2 */
	mulP521(pdt1,U,U);
	mulP521(pdt1,W,pdt1);
	/* U^2*W - V^3 */
	subP521(res1,pdt1,V_3);
	/* pdt1 = V^2*V2 */
	mulP521(pdt1,V_2,V2);
	constMulP521(pdt2,pdt1,2);
	/* U^2*W - V^3 - 2*V^2*V2 */
	subP521(A,res1,pdt2);
	/* V*A */
	mulP521(pdt2,A,V);

	if(bn_wexpand(&r->X,9)==NULL) goto end;
	(&r->X)->top = 9; 
{
uint64_t t0,t1,t2,t3,t4;
	t0 = pdt2[0];
	t1 = pdt2[1];
	t2 = pdt2[2];
	t3 = pdt2[3];
	t4 = pdt2[4];
	(&r->X)->d[0] = t0;
	(&r->X)->d[1] = t1;
	(&r->X)->d[2] = t2;
	(&r->X)->d[3] = t3;
	(&r->X)->d[4] = t4;
	t0 = pdt2[5];
	t1 = pdt2[6];
	t2 = pdt2[7];
	t3 = pdt2[8];
	(&r->X)->d[5] = t0;
	(&r->X)->d[6] = t1;
	(&r->X)->d[7] = t2;
	(&r->X)->d[8] = t3;
}
	bn_fix_top(&r->X);
	/* X_r */
	/* V^2*V2 - A */
	subP521(res1,pdt1,A);
	/* U(V^2*V2 - A) */
	mulP521(pdt1,res1,U);

	/* V^3*U2 */
	mulP521(pdt2,U2,V_3);
	/* U*(V^2*V2 - A) - V^3*U2 */
	subP521(res1,pdt1,pdt2);

	if(bn_wexpand(&r->Y,9)==NULL) goto end; 
	(&r->Y)->top = 9;
{
uint64_t t0,t1,t2,t3,t4;
	t0 = res1[0];
	t1 = res1[1];
	t2 = res1[2];
	t3 = res1[3];
	t4 = res1[4];
	(&r->Y)->d[0] = t0;
	(&r->Y)->d[1] = t1;
	(&r->Y)->d[2] = t2;
	(&r->Y)->d[3] = t3;
	(&r->Y)->d[4] = t4;
	t0 = res1[5];
	t1 = res1[6];
	t2 = res1[7];
	t3 = res1[8];
	(&r->Y)->d[5] = t0;
	(&r->Y)->d[6] = t1;
	(&r->Y)->d[7] = t2;
	(&r->Y)->d[8] = t3;
}
	bn_fix_top(&r->Y);
	/* Y_r */
	ret = 1;
end:
	return ret;
	
	}


#define cm0P256 0x0000000000000001ull
#define cm1P256 0xffffffff00000000ull
#define cm2P256 0xffffffffffffffffull
#define cm3P256 0x00000000fffffffeull

int ec_GFp_hw_dbl_p256(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a)
	{

	void (*mulP256)(uint64_t *, uint64_t *, uint64_t *);
	int ret = 0;
	uint64_t X[4],Y[4],Z[4],res1[5],res2[5],res3[12],res4[12];
	uint64_t W[4],S[4],B[4],H[4],S_new[4];
	int i;
	uint64_t ci,bi,Zero = 0;

	// CVMX_PREFETCH0(((a->X).d[0])); this causes an unhandled tlb exception... why?
	// otherwise, warning: prefetches cost an issue slot so if they miss often enough
	// or are too close to be effective they will slow the program down!  This seems 
	// to have reasonable locality otherwise note that the dst of mulP256 is
	// prefetched.
	//

	X[0] = 0;
	Z[0] = 0;
	X[1] = 0;
	Z[1] = 0;
	X[2] = 0;
	Z[2] = 0;
	X[3] = 0;
	Z[3] = 0;

	for (i=0;i<(a->X).top;i++)
		X[i] = (a->X).d[i];
	
	for (i=0;i<(a->Z).top;i++) {
		Z[i] = (a->Z).d[i]; //avoid DWB
	}

	if (!Z[0] && !Z[1] && !Z[2] && !Z[3])
		{
		BN_zero(&r->Z); //TODO:
		r->Z_is_one = 0;
		return 1;
		}

	if(OCTEON_IS_OCTEON3())
	  mulP256 = fecc_MulP256o3Asm;
	else 
	  mulP256 = fecc_MulP256AsmB17731;

	ci = 0;
	ADDCS(ci,res1[0],X[0],Z[0]);
	ADDCS(ci,res1[1],X[1],Z[1]);
	ADDCS(ci,res1[2],X[2],Z[2]);
	ADDCS(ci,res1[3],X[3],Z[3]);

	if (ci || (res1[3] > m3P256))
	{
		ci = 0;
		ADDCS(ci,res1[0],cm0P256,res1[0]);
		ADDCS(ci,res1[1],cm1P256,res1[1]);
		ADDCS(ci,res1[2],cm2P256,res1[2]);
		ADDCS(ci,res1[3],cm3P256,res1[3]);

	}
	bi = 0;
	SUBCS(bi,res2[0],X[0],Z[0]);
	SUBCS(bi,res2[1],X[1],Z[1]);
	SUBCS(bi,res2[2],X[2],Z[2]);
	SUBCS(bi,res2[3],X[3],Z[3]);
	if (bi)
	{
		ci=0;
		ADDCS(ci,res2[0],m0P256,res2[0]);
		ADDCS(ci,res2[1],m1P256,res2[1]);
		ADDCS(ci,res2[2],Zero,res2[2]);
		ADDCS(ci,res2[3],m3P256,res2[3]);
	}

	Y[0] = 0;
	Y[1] = 0;
	Y[2] = 0;
	Y[3] = 0;
	
	/* res3 = res1 * res2 mod p */
	mulP256(res3,res1,res2);
	{
    register uint64_t u0,u1,u2,u3,u4;
    register uint64_t v0,v1,v2,v3,v4;
	for (i=0;i<(a->Y).top;i++)	// do this while waiting for u3,u4
		Y[i] = (a->Y).d[i];

	/*W = 3*res3 */
	v4 = res3[3] >> 63;	 
	v3 = res3[3] << 1 | res3[2] >> 63;
	v2 = res3[2] << 1 | res3[1] >> 63;
	v1 = res3[1] << 1 | res3[0] >> 63;
	v0 = res3[0] << 1;
	ci = 0;
	ADDCS(ci,u0,v0,res3[0]);
	ADDCS(ci,u1,v1,res3[1]);
	ADDCS(ci,u2,v2,res3[2]);
	ADDCS(ci,u3,v3,res3[3]);
	ADDCS(ci,u4,v4,0);

	if(u4 || (u3 >= m3P256)) 
	{
                while (1)
                {
                        bi = 0;
                        ADDCS(bi,v0,u0,cm0P256);
                        ADDCS(bi,v1,u1,cm1P256);
                        ADDCS(bi,v2,u2,cm2P256);
                        ADDCS(bi,v3,u3,cm3P256);
                        ADDCS(bi,v4,u4,~0ull);
                        if (!bi)
                        {
                                W[0] = u0;
                                W[1] = u1;
                                W[2] = u2;
                                W[3] = u3;
                                break;
                        }
                        bi = 0;
                        ADDCS(bi,u0,v0,cm0P256);
                        ADDCS(bi,u1,v1,cm1P256);
                        ADDCS(bi,u2,v2,cm2P256);
                        ADDCS(bi,u3,v3,cm3P256);
                        ADDCS(bi,u4,v4,~0ull);
                        if (!bi)
                        {
                                W[0] = v0;
                                W[1] = v1;
                                W[2] = v2;
                                W[3] = v3;
                                break;
                        }
                }

	}
	else 
	{
                W[0] = u0;
                W[1] = u1;
                W[2] = u2;
                W[3] = u3;
	}
	}

	/* n1 = a*Z^2 + 3*X^2 */

	/* X_r */
  	/* S = Z*Y
	   res4 = X*Y */
	mulP256(S,Z,Y);
	mulP256(res4,X,Y);
	/* res3 = res4*S */
	/* B = res3 mod p */
	mulP256(B,res4,S);
	/* n0 res3= 8*B */
{
register uint64_t u0,u1,u2,u3,u4;
register uint64_t v0,v1,v2,v3,v4;
	u0 = B[0] << 3;
	u1 = B[1] << 3 | B[0] >> 61;
	u2 = B[2] << 3 | B[1] >> 61;
	u3 = B[3] << 3 | B[2] >> 61;
	u4 = B[3] >> 61;	
	
	if(u4 || (u3 >= m3P256)) 
	{
                while (1)
                {
                        bi = 0;
                        ADDCS(bi,v0,u0,cm0P256);
                        ADDCS(bi,v1,u1,cm1P256);
                        ADDCS(bi,v2,u2,cm2P256);
                        ADDCS(bi,v3,u3,cm3P256);
                        ADDCS(bi,v4,u4,~0ull);
                        if (!bi)
                        {
                                res3[0] = u0;
                                res3[1] = u1;
                                res3[2] = u2;
                                res3[3] = u3;
                                break;
                        }
                        bi = 0;
                        ADDCS(bi,u0,v0,cm0P256);
                        ADDCS(bi,u1,v1,cm1P256);
                        ADDCS(bi,u2,v2,cm2P256);
                        ADDCS(bi,u3,v3,cm3P256);
                        ADDCS(bi,u4,v4,~0ull);
                        if (!bi)
                        {
                                res3[0] = v0;
                                res3[1] = v1;
                                res3[2] = v2;
                                res3[3] = v3;
                                break;
                        }
                }

	}
	else 
	{
                res3[0] = u0;
                res3[1] = u1;
                res3[2] = u2;
                res3[3] = u3;
	}
}
	/* res4 = W^2 */
	mulP256(res4,W,W);
{
	bi = 0;
	SUBCS(bi,H[0],res4[0],res3[0]);
	SUBCS(bi,H[1],res4[1],res3[1]);
	SUBCS(bi,H[2],res4[2],res3[2]);
	SUBCS(bi,H[3],res4[3],res3[3]);
	if (bi)
	{
		ci=0;
		ADDCS(ci,H[0],m0P256,H[0]);
		ADDCS(ci,H[1],m1P256,H[1]);
		ADDCS(ci,H[2],Zero,H[2]);
		ADDCS(ci,H[3],m3P256,H[3]);
	}
}
	/* res3 = H*S mod p */
	mulP256(res3,H,S);

{
register uint64_t u0,u1,u2,u3,u4;
register uint64_t v0,v1,v2,v3,v4;
register uint64_t t0,t1,t2,t3;

	/* 2*H*S */
	v4 = res3[3] >> 63;	 
	v3 = res3[3] << 1 | res3[2] >> 63;
	v2 = res3[2] << 1 | res3[1] >> 63;
	v1 = res3[1] << 1 | res3[0] >> 63;
	v0 = res3[0] << 1;

	if(v4 || (v3 >= m3P256))
	{
		ci = 0;
		ADDCS(ci,v0,cm0P256,v0);
		ADDCS(ci,v1,cm1P256,v1);
		ADDCS(ci,v2,cm2P256,v2);
		ADDCS(ci,v3,cm3P256,v3);

	}

	u0 = B[0] << 2;
	u1 = B[1] << 2 | B[0] >> 62;
	u2 = B[2] << 2 | B[1] >> 62;
	u3 = B[3] << 2 | B[2] >> 62;
	u4 = B[3] >> 62;	

	if(bn_wexpand(&r->X,4)==NULL) goto err;  // the call allocs r->X

	(&r->X)->top = 4; 
	(&r->X)->d[0] = v0;
	(&r->X)->d[1] = v1;
	(&r->X)->d[2] = v2;
	(&r->X)->d[3] = v3;
	bn_fix_top(&r->X);

	if(u4 || (u3 >= m3P256))
	{
                while (1)
                {
                        bi = 0;
                        ADDCS(bi,v0,u0,cm0P256);
                        ADDCS(bi,v1,u1,cm1P256);
                        ADDCS(bi,v2,u2,cm2P256);
                        ADDCS(bi,v3,u3,cm3P256);
                        ADDCS(bi,v4,u4,~0ull);
                        if (!bi)
                        {
                                t0 = u0;
                                t1 = u1;
                                t2 = u2;
                                t3 = u3;
                                break;
                        }
                        bi = 0;
                        ADDCS(bi,u0,v0,cm0P256);
                        ADDCS(bi,u1,v1,cm1P256);
                        ADDCS(bi,u2,v2,cm2P256);
                        ADDCS(bi,u3,v3,cm3P256);
                        ADDCS(bi,u4,v4,~0ull);
                        if (!bi)
                        {
                                t0 = v0;
                                t1 = v1;
                                t2 = v2;
                                t3 = v3;
                                break;
                        }
                }
	}
	else
	{
                t0 = u0;
                t1 = u1;
                t2 = u2;
                t3 = u3;
	}
	bi = 0;
	SUBCS(bi,res3[0],t0,H[0]);
	SUBCS(bi,res3[1],t1,H[1]);
	SUBCS(bi,res3[2],t2,H[2]);
	SUBCS(bi,res3[3],t3,H[3]);
	if (bi)
	{
		ci = 0;
		ADDCS(ci,res3[0],res3[0],m0P256);  
		ADDCS(ci,res3[1],res3[1],m1P256);
		ADDCS(ci,res3[2],res3[2],m2P256);
		ADDCS(ci,res3[3],res3[3],m3P256);
	}
}
	/* W(4B-H) */
	/* res3 = res4 mod p */
	mulP256(res3,W,res3);
	/* S_new = S^2 */
	mulP256(S_new,S,S);
	
{
register uint64_t u0,u1,u2,u3,u4;
register uint64_t v0,v1,v2,v3,v4;

	u0 = S_new[0] << 3;
	u1 = S_new[1] << 3 | S_new[0] >> 61;
	u2 = S_new[2] << 3 | S_new[1] >> 61;
	u3 = S_new[3] << 3 | S_new[2] >> 61;
	u4 = S_new[3] >> 61;	

	if(u4 || (u3 >= m3P256))
	{
                while (1)
                {
                        bi = 0;
                        ADDCS(bi,v0,u0,cm0P256);
                        ADDCS(bi,v1,u1,cm1P256);
                        ADDCS(bi,v2,u2,cm2P256);
                        ADDCS(bi,v3,u3,cm3P256);
                        ADDCS(bi,v4,u4,~0ull);
                        if (!bi)
                        {
                                S_new[0] = u0;
                                S_new[1] = u1;
                                S_new[2] = u2;
                                S_new[3] = u3;
                                break;
                        }
                        bi = 0;
                        ADDCS(bi,u0,v0,cm0P256);
                        ADDCS(bi,u1,v1,cm1P256);
                        ADDCS(bi,u2,v2,cm2P256);
                        ADDCS(bi,u3,v3,cm3P256);
                        ADDCS(bi,u4,v4,~0ull);
                        if (!bi)
                        {
                                S_new[0] = v0;
                                S_new[1] = v1;
                                S_new[2] = v2;
                                S_new[3] = v3;
                                break;
                        }
                }
	}
	else
	{
		S_new[0] = u0;	// more efficient to leave this in the else
		S_new[1] = u1;	// than try and absorb the if clause
		S_new[2] = u2;
		S_new[3] = u3;
	}
}
	/* res4 = Y^2 */
	mulP256(res4,Y,Y);
	
	/* Y2*S2 */
	mulP256(res4,S_new,res4);
{
register uint64_t u0,u1,u2,u3;

	/* res3 = res3 - res4 */	
	bi = 0;
	SUBCS(bi,u0,res3[0],res4[0]);
	SUBCS(bi,u1,res3[1],res4[1]);
	SUBCS(bi,u2,res3[2],res4[2]);
	SUBCS(bi,u3,res3[3],res4[3]);
	if (bi)
	{
		ci = 0;
		ADDCS(ci,u0,u0,m0P256);  
		ADDCS(ci,u1,u1,m1P256);
		ADDCS(ci,u2,u2,m2P256);
		ADDCS(ci,u3,u3,m3P256);
	}

	if(bn_wexpand(&r->Y,4)==NULL) goto err;
	(&r->Y)->top = 4; 
	(&r->Y)->d[0] = u0;
	(&r->Y)->d[1] = u1;
	(&r->Y)->d[2] = u2;
	(&r->Y)->d[3] = u3;
	bn_fix_top(&r->Y);
}

	mulP256(res3,S_new,S);
	

	/* Z_r */
	if(bn_wexpand(&r->Z,4)==NULL) goto err;

	(&r->Z)->top = 4; 
{
	uint64_t t0,t1,t2,t3;

	t0 = res3[0];
	t1 = res3[1];
	t2 = res3[2];
	t3 = res3[3];
	(&r->Z)->d[0] = t0;
	(&r->Z)->d[1] = t1;
	(&r->Z)->d[2] = t2;
	(&r->Z)->d[3] = t3;
}
	bn_fix_top(&r->Z);
	/* Y_r */

	r->Z_is_one = 0;

	ret = 1;

err:
	return ret;
	}

int ec_GFp_hw_add_p256(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b)	
	{
	void (*mulP256)(uint64_t *, uint64_t *, uint64_t *);
	int ret = 0;
     	uint64_t pdt1[8],pdt2[8],res1[7];
	uint64_t X1[4],X2[4],Y1[4],Y2[4],Z1[4],Z2[4];
	uint64_t U[4],V[4],U2[4],V2[4],W[4],A[4],V_2[4],V_3[4];
	uint64_t ci,bi;
    int i;

	Z1[0] = 0;
	Z1[1] = 0;
	Z1[2] = 0;
	Z1[3] = 0;
	for (i=0;i<(a->Z).top;i++)
		Z1[i] = (a->Z).d[i];

	if (!Z1[0] && !Z1[1] && !Z1[2] && !Z1[3])
		return EC_POINT_copy(r, b);

	Z2[0] = 0;
	Z2[1] = 0;
	Z2[2] = 0;
	Z2[3] = 0;
	for (i=0;i<(b->Z).top;i++)
		Z2[i] = (b->Z).d[i];

	if (!Z2[0] && !Z2[1] && !Z2[2] && !Z2[3])
		return EC_POINT_copy(r, a);


	if(OCTEON_IS_OCTEON3())
	  mulP256 = fecc_MulP256o3Asm;
	else 
	  mulP256 = fecc_MulP256AsmB17731;

	Y2[0] = 0;
	Y2[1] = 0;
	Y2[2] = 0;
	Y2[3] = 0;
	for (i=0;i<(b->Y).top;i++)
		Y2[i] = (b->Y).d[i];
	/* n1, n2 */
		{
		/*U1= Y2*Z1*/
		/*V1= X2*Z1*/
		mulP256(pdt1,Y2,Z1);
	X2[0] = 0;
	X2[1] = 0;
	X2[2] = 0;
	X2[3] = 0;
	for (i=0;i<(b->X).top;i++)
		X2[i] = (b->X).d[i];
		mulP256(pdt2,X2,Z1);
		}

	/* n3, n4 */
	if (b->Z_is_one)
		{
		V2[0] = 0;
		V2[1] = 0;
		V2[2] = 0;
		V2[3] = 0;
		for (i=0;i<(a->X).top;i++)
			V2[i] = (a->X).d[i];
		U2[0] = 0;
		U2[1] = 0;
		U2[2] = 0;
		U2[3] = 0;
		for (i=0;i<(a->Y).top;i++)
			U2[i] = (a->Y).d[i];
		}
	else 
		{
		X1[0] = 0;
		Y1[1] = 0;
		Y1[2] = 0;
		Y1[3] = 0;
		for (i=0;i<(a->Y).top;i++)
			Y1[i] = (a->Y).d[i];
		/* U2 = Y1*Z2 */
		/* V2 = X1*Z2 */
		mulP256(U2,Y1,Z2);
		X1[0] = 0;
		X1[1] = 0;
		X1[2] = 0;
		X1[3] = 0;
		for (i=0;i<(a->X).top;i++)
			X1[i] = (a->X).d[i];
		mulP256(V2,X1,Z2);
		}
{
register uint64_t u0,u1,u2,u3,u4;
register uint64_t v0,v1,v2,v3,v4;
	bi = 0;
	SUBCS(bi,u0,pdt1[0],U2[0]);
	SUBCS(bi,u1,pdt1[1],U2[1]);
	SUBCS(bi,u2,pdt1[2],U2[2]);
	SUBCS(bi,u3,pdt1[3],U2[3]);
	if (bi)
	{
		ci=0;
		ADDCS(ci,u0,u0,m0P256);
		ADDCS(ci,u1,u1,m1P256);
		ADDCS(ci,u2,u2,m2P256);
		ADDCS(ci,u3,u3,m3P256);
	}

	bi = 0;
	SUBCS(bi,v0,pdt2[0],V2[0]);
	SUBCS(bi,v1,pdt2[1],V2[1]);
	SUBCS(bi,v2,pdt2[2],V2[2]);
	SUBCS(bi,v3,pdt2[3],V2[3]);
	if (bi)
	{
		ci=0;
		ADDCS(ci,v0,v0,m0P256);
		ADDCS(ci,v1,v1,m1P256);
		ADDCS(ci,v2,v2,m2P256);
		ADDCS(ci,v3,v3,m3P256);
	}

	U[0] = u0;
	v4 = v0 | v1;  // this only helps a little bit, but
	U[1] = u1;
	u4 = u0 | u1;  // attempt to get efficient dispatch.
	U[2] = u2;
	v4 = v4 | v2;
	U[3] = u3;
	u4 = u4 | u2;
	V[0] = v0;
	v4 = v4 | v3;
	V[1] = v1;
	u4 = u4 | u3;
	V[2] = v2;
	V[3] = v3;


	if (!v4)
		{
		if (!u4)
			{
			/* a is the same point as b */
			ret = ec_GFp_hw_dbl_p256(group,r,a);
			goto end;
			}
		else
			{
			/* a is the inverse of b */
			BN_zero(&r->Z);
			r->Z_is_one = 0;
			ret = 1;
			goto end;
			}
		}
}
	/* n7 */
	/* W = Z1*Z2 */
	mulP256(W,Z1,Z2);
	/* V^2 */
	mulP256(V_2,V,V);
	/* V^3 */
	mulP256(V_3,V_2,V);
	/* V^3*W */
	mulP256(pdt2,V_3,W);
	if(bn_wexpand(&r->Z,4)==NULL) goto end;
	(&r->Z)->top = 4; 
	(&r->Z)->d[0] = pdt2[0];
	(&r->Z)->d[1] = pdt2[1];
	(&r->Z)->d[2] = pdt2[2];
	(&r->Z)->d[3] = pdt2[3];
	bn_fix_top(&r->Z);
	/* Z_r */
	r->Z_is_one = 0;

	/* U^2 */
	mulP256(pdt1,U,U);
	/* U^2*W */
	mulP256(pdt1,pdt1,W);

	bi = 0;
	SUBCS(bi,res1[0],pdt1[0],V_3[0]);
	SUBCS(bi,res1[1],pdt1[1],V_3[1]);
	SUBCS(bi,res1[2],pdt1[2],V_3[2]);
	SUBCS(bi,res1[3],pdt1[3],V_3[3]);
	if (bi)
	{
		ci=0;
		ADDCS(ci,res1[0],res1[0],m0P256);
		ADDCS(ci,res1[1],res1[1],m1P256);
		ADDCS(ci,res1[2],res1[2],m2P256);
		ADDCS(ci,res1[3],res1[3],m3P256);
	}

	//if (!BN_mod_sub_quick(n0, n0, n2, p)) goto end;
	/* pdt1 = V^2*V2 */
	mulP256(pdt1,V2,V_2);

{
register uint64_t u0,u1,u2,u3,u4;
register uint64_t v0,v1,v2,v3,v4;
	/* 2*V^2*V2 */
	u0 = pdt1[0] << 1;
	u1 = pdt1[1] << 1 | pdt1[0] >> 63;
	u2 = pdt1[2] << 1 | pdt1[1] >> 63;
	u3 = pdt1[3] << 1 | pdt1[2] >> 63;
	u4 = pdt1[3] >> 63;	

	if(u4 || (u3 >= m3P256))
	{
                while (1)
                {
                        bi = 0;
                        ADDCS(bi,v0,u0,cm0P256);
                        ADDCS(bi,v1,u1,cm1P256);
                        ADDCS(bi,v2,u2,cm2P256);
                        ADDCS(bi,v3,u3,cm3P256);
                        ADDCS(bi,v4,u4,~0ull);
                        if (!bi)
                        {
                                A[0] = u0;
                                A[1] = u1;
                                A[2] = u2;
                                A[3] = u3;
                                break;
                        }
                        bi = 0;
                        ADDCS(bi,u0,v0,cm0P256);
                        ADDCS(bi,u1,v1,cm1P256);
                        ADDCS(bi,u2,v2,cm2P256);
                        ADDCS(bi,u3,v3,cm3P256);
                        ADDCS(bi,u4,v4,~0ull);
                        if (!bi)
                        {
                                A[0] = v0;
                                A[1] = v1;
                                A[2] = v2;
                                A[3] = v3;
                                break;
                        }
                }
	}
	else
	{
		A[0] = u0;
		A[1] = u1;
		A[2] = u2;
		A[3] = u3;
	}
	bi = 0;
	SUBCS(bi,A[0],res1[0],A[0]);
	SUBCS(bi,A[1],res1[1],A[1]);
	SUBCS(bi,A[2],res1[2],A[2]);
	SUBCS(bi,A[3],res1[3],A[3]);
	if (bi)
	{
		ci=0;
		ADDCS(ci,A[0],A[0],m0P256);
		ADDCS(ci,A[1],A[1],m1P256);
		ADDCS(ci,A[2],A[2],m2P256);
		ADDCS(ci,A[3],A[3],m3P256);
	}
}
	/* V*A */
	mulP256(pdt2,V,A);
	if(bn_wexpand(&r->X,4)==NULL) goto end;
	(&r->X)->top = 4; 
	(&r->X)->d[0] = pdt2[0];
	(&r->X)->d[1] = pdt2[1];
	(&r->X)->d[2] = pdt2[2];
	(&r->X)->d[3] = pdt2[3];
	bn_fix_top(&r->X);
	/* X_r */

	/* V^2*V2 - A */
	bi = 0;
	SUBCS(bi,res1[0],pdt1[0],A[0]);
	SUBCS(bi,res1[1],pdt1[1],A[1]);
	SUBCS(bi,res1[2],pdt1[2],A[2]);
	SUBCS(bi,res1[3],pdt1[3],A[3]);
	if (bi)
	{
		ci=0;
		ADDCS(ci,res1[0],res1[0],m0P256);
		ADDCS(ci,res1[1],res1[1],m1P256);
		ADDCS(ci,res1[2],res1[2],m2P256);
		ADDCS(ci,res1[3],res1[3],m3P256);
	}
	//if (!BN_mod_sub_quick(n7, n7, n0, p)) goto end;
	/* U(V^2*V2 - A) */
	mulP256(pdt1,U,res1);
	/* V^3*U2 */
	mulP256(pdt2,V_3,U2);
{
register uint64_t u0,u1,u2,u3;
	/* U*(V^2*V2 - A) - V^3*U2 */
	bi = 0;
	SUBCS(bi,u0,pdt1[0],pdt2[0]);
	SUBCS(bi,u1,pdt1[1],pdt2[1]);
	SUBCS(bi,u2,pdt1[2],pdt2[2]);
	SUBCS(bi,u3,pdt1[3],pdt2[3]);
	if (bi)
	{
		ci=0;
		ADDCS(ci,u0,u0,m0P256);
		ADDCS(ci,u1,u1,m1P256);
		ADDCS(ci,u2,u2,m2P256);
		ADDCS(ci,u3,u3,m3P256);
	}

	if(bn_wexpand(&r->Y,4)==NULL) goto end;

	(&r->Y)->top = 4; 
	(&r->Y)->d[0] = u0;
	(&r->Y)->d[1] = u1;
	(&r->Y)->d[2] = u2;
	(&r->Y)->d[3] = u3;
	bn_fix_top(&r->Y);
}
	/* Y_r */
	ret = 1;
end:
	return ret;
	
	}

int ec_GFp_hw_dbl_p384(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a)
	{
	void (*mulP384)(uint64_t *, uint64_t *, uint64_t *);
	void (*subP384)(uint64_t *, uint64_t *, uint64_t *);
	void (*constMulP384)(uint64_t *, uint64_t *, uint64_t);
	int ret = 0;
	uint64_t X[6],Y[6],Z[6],res1[7],res2[7],res3[12],res4[13];
	uint64_t W[6],S[6],B[6],H[6],S_new[6];
	int i;

	// p = &group->field;
	for (i=0;i<6;i++)
		X[i]=Y[i]=Z[i]=0;
	for (i=0;i<(a->Z).top;i++)
		Z[i] = (a->Z).d[i]; 
	if (!Z[0] && !Z[1] && !Z[2] && !Z[3] && !Z[4] && !Z[5])
		{
		BN_zero(&r->Z);
		r->Z_is_one = 0;
		return 1;
		}

	if(OCTEON_IS_OCTEON3())
	    {
		mulP384 = fecc_MulP384o3Asm;
		subP384 = fecc_SubP384Asm;
		constMulP384 = fecc_ConstMulP384Asm;
	    }
	else 
	    {
		mulP384 = fecc_MulP384AsmB17731;
		subP384 = fecc_SubP384AsmB17731;
		constMulP384 = fecc_ConstMulP384AsmB17731;
	    }

	for (i=0;i<(a->X).top;i++)
		X[i] = (a->X).d[i];


	/*res1 =  X + Z  */
	for (i=0;i<(a->Y).top;i++)  
		Y[i] = (a->Y).d[i];

{
	uint64_t ci;
	ci = 0;
	ADDCS(ci,res1[0],X[0],Z[0]);
	ADDCS(ci,res1[1],X[1],Z[1]);
	ADDCS(ci,res1[2],X[2],Z[2]);
	ADDCS(ci,res1[3],X[3],Z[3]);
	ADDCS(ci,res1[4],X[4],Z[4]);
	ADDCS(ci,res1[5],X[5],Z[5]);

	if(ci || (res1[5] >= m5P384))
	{
		ci = 0;
		SUBCS(ci,res1[0],res1[0],m0P384);
		SUBCS(ci,res1[1],res1[1],m1P384);
		SUBCS(ci,res1[2],res1[2],m2P384);
		SUBCS(ci,res1[3],res1[3],m3P384);
		SUBCS(ci,res1[4],res1[4],m4P384);
		SUBCS(ci,res1[5],res1[5],m5P384);
	}
}
	subP384(res2,X,Z);
	/* res3 = res1 * res2 mod p */
	mulP384(res3,res1,res2);
	/*W = 3*res3 */
	constMulP384(W,res3,3);
	/* n1 = a*Z^2 + 3*X^2 */

	/* X_r */
  	/* S = Z*Y
	   res4 = X*Y */

	mulP384(S,Z,Y);
	mulP384(res4,X,Y);
	/* res3 = res4*S */
	mulP384(B,res4,S);

	mulP384(H,W,W);    
	/* n0 res3= 8*B */
	constMulP384(res3,B,8);

	subP384(H,H,res3);

	mulP384(res3,H,S);


	/* 2*H*S */
	constMulP384(res3,res3,2);

	if(bn_wexpand(&r->X,6)==NULL) goto err;
	(&r->X)->top = 6; 
{
#if 0
	(&r->X)->d[0] = res3[0];
	(&r->X)->d[1] = res3[1];
	(&r->X)->d[2] = res3[2];
	(&r->X)->d[3] = res3[3];
	(&r->X)->d[4] = res3[4];
	(&r->X)->d[5] = res3[5];
#else
	uint64_t t0,t1,t2;
	t0 = res3[0];
	t1 = res3[1];
	t2 = res3[2];
	(&r->X)->d[0] = t0;
	(&r->X)->d[1] = t1;
	(&r->X)->d[2] = t2;
	t0 = res3[3];
	t1 = res3[4];
	t2 = res3[5];
	(&r->X)->d[3] = t0;
	(&r->X)->d[4] = t1;
	(&r->X)->d[5] = t2;
#endif
}
	bn_fix_top(&r->X);

	/* Y_r */
	/* W*(4*B - H) */
	/* 4*B */
	constMulP384(res3,B,4);
	/* 4*B - H */
	subP384(res3,res3,H);
	/* W(4B-H) */
	mulP384(res3,W,res3);
	/* S_new = S^2 */
	mulP384(S_new,S,S);
	
	/* 8*S^2  */
	constMulP384(S_new,S_new,8);

	/* res4 = Y^2 */
	mulP384(res4,Y,Y);
	
	/* Y2*S2 */
	mulP384(res4,S_new,res4);
	/* res3 = res3 - res4 */	
	subP384(res3,res3,res4);

	if(bn_wexpand(&r->Y,6)==NULL) goto err;
	(&r->Y)->top = 6; 
{
	uint64_t t0,t1,t2;
	t0 = res3[0];
	t1 = res3[1];
	t2 = res3[2];
	(&r->Y)->d[0] = t0;
	(&r->Y)->d[1] = t1;
	(&r->Y)->d[2] = t2;
	t0 = res3[3];
	t1 = res3[4];
	t2 = res3[5];
	(&r->Y)->d[3] = t0;
	(&r->Y)->d[4] = t1;
	(&r->Y)->d[5] = t2;
}
	bn_fix_top(&r->Y);

	/* Y^2*S^2 * S */
	mulP384(res3,S_new,S);
	

	/* Z_r */
	if(bn_wexpand(&r->Z,6)==NULL) goto err;
	(&r->Z)->top = 6; 
{
	uint64_t t0,t1,t2;
	t0 = res3[0];
	t1 = res3[1];
	t2 = res3[2];
	(&r->Z)->d[0] = t0;
	(&r->Z)->d[1] = t1;
	(&r->Z)->d[2] = t2;
	t0 = res3[3];
	t1 = res3[4];
	t2 = res3[5];
	(&r->Z)->d[3] = t0;
	(&r->Z)->d[4] = t1;
	(&r->Z)->d[5] = t2;
}
	bn_fix_top(&r->Z);
	/* Y_r */

	r->Z_is_one = 0;

	ret = 1;

 err:
	return ret;
	}

int ec_GFp_hw_add_p384(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b)
	{
	void (*mulP384)(uint64_t *, uint64_t *, uint64_t *);
	void (*subP384)(uint64_t *, uint64_t *, uint64_t *);
	void (*constMulP384)(uint64_t *, uint64_t *, uint64_t);
	int ret = 0;
     	uint64_t pdt1[12],pdt2[12],res1[7];
	uint64_t X1[6],X2[6],Y1[6],Y2[6],Z1[6],Z2[6];
	uint64_t U[6],V[6],U2[6],V2[6],W[6],A[6],V_2[6],V_3[6];
	int i;

	// could look at optimizing this expression, but not much to get
	for (i=0;i<6;i++)
		X1[i]=X2[i]=Y1[i]=Y2[i]=Z1[i]=Z2[i]=0;

	for (i=0;i<(a->X).top;i++)
		X1[i] = (a->X).d[i];
	for (i=0;i<(a->Y).top;i++)
		Y1[i] = (a->Y).d[i];
	for (i=0;i<(a->Z).top;i++)
		Z1[i] = (a->Z).d[i];
	if (a == b)
		return ec_GFp_hw_dbl_p384(group, r, a);
	if (!Z1[0] && !Z1[1] && !Z1[2] && !Z1[3] && !Z1[4] && !Z1[5])
		return EC_POINT_copy(r, b);
	for (i=0;i<(b->X).top;i++)
		X2[i] = (b->X).d[i];
	for (i=0;i<(b->Y).top;i++)
		Y2[i] = (b->Y).d[i];
	for (i=0;i<(b->Z).top;i++)
		Z2[i] = (b->Z).d[i];
	if (!Z2[0] && !Z2[1] && !Z2[2] && !Z2[3] && !Z2[4] && !Z2[5])
		return EC_POINT_copy(r, a);
	// p = &group->field;

	if(OCTEON_IS_OCTEON3())
	    {
		mulP384 = fecc_MulP384o3Asm;
		subP384 = fecc_SubP384Asm;
		constMulP384 = fecc_ConstMulP384Asm;
	    }
	else 
	    {
		mulP384 = fecc_MulP384AsmB17731;
		subP384 = fecc_SubP384AsmB17731;
		constMulP384 = fecc_ConstMulP384AsmB17731;
	    }

	/* n1, n2 */
	/*if (a->Z_is_one)
		{
		//if (!BN_copy(n1, &b->Y)) goto end;
		//if (!BN_copy(n2, &b->X)) goto end;
		}	
	else */
		{
		/*U1= Y2*Z1*/
		mulP384(pdt1,Y2,Z1);
		/*V1= X2*Z1*/
		mulP384(pdt2,X2,Z1);
		}

	/* n3, n4 */
	if (b->Z_is_one)
		{
			for (i=0;i<6;i++)
			{
				// NB you could eliminate the copy by reusing X1,Y1.  The compiler is
				// not smart enough to realize this
				U2[i] = Y1[i];
				V2[i] = X1[i];
			}
		}
	else 
		{
		/* U2 = Y1*Z2 */
		/* V2 = X1*Z2 */
		mulP384(U2,Y1,Z2);
		mulP384(V2,X1,Z2);
		}

	/* n5, n6 */

	subP384(U,pdt1,U2);
	subP384(V,pdt2,V2);

	if (!V[0] && !V[1] && !V[2] && !V[3] && !V[4] && !V[5] )		
		{
		if (!U[0] && !U[1] && !U[2] && !U[3] && !U[4] && !U[5])		
			{
			/* a is the same point as b */
			ret = ec_GFp_hw_dbl_p384(group, r, a);
			goto err;
			}
		else
			{
			/* a is the inverse of b */
			BN_zero(&r->Z);
			r->Z_is_one = 0;
			ret = 1;
			goto err;
			}
		}
	/* n7 */
	/* W = Z1*Z2 */
	mulP384(W,Z1,Z2);
	/* V^2 */
	mulP384(V_2,V,V);
	
	/* V^3 */
	mulP384(V_3,V_2,V);
	/* V^3*W */
	mulP384(pdt2,V_3,W);

	if(bn_wexpand(&r->Z,6)==NULL) goto err;
	(&r->Z)->top = 6;
	(&r->Z)->d[0] = pdt2[0];
	(&r->Z)->d[1] = pdt2[1];
	(&r->Z)->d[2] = pdt2[2];
	(&r->Z)->d[3] = pdt2[3];
	(&r->Z)->d[4] = pdt2[4];
	(&r->Z)->d[5] = pdt2[5];
	bn_fix_top(&r->Z);
	/* Z_r */
	r->Z_is_one = 0;

	/* U^2 */
	mulP384(pdt1,U,U);
	/* U^2*W */
	mulP384(pdt1,pdt1,W);
	/* U^2*W - V^3 */
	subP384(res1,pdt1,V_3);
	/* pdt1 = V^2*V2 */
	mulP384(pdt1,V2,V_2);
	/* 2*V^2*V2 */
	constMulP384(pdt2,pdt1,2);
	/* U^2*W - V^3 - 2*V^2*V2 */
	subP384(A,res1,pdt2);
	/* V*A */
	mulP384(pdt2,V,A);

	if(bn_wexpand(&r->X,6)==NULL) goto err;
	(&r->X)->top = 6;
	(&r->X)->d[0] = pdt2[0];
	(&r->X)->d[1] = pdt2[1];
	(&r->X)->d[2] = pdt2[2];
	(&r->X)->d[3] = pdt2[3];
	(&r->X)->d[4] = pdt2[4];
	(&r->X)->d[5] = pdt2[5];
	bn_fix_top(&r->X);
	/* X_r */
	/* V^2*V2 - A */
	subP384(res1,pdt1,A);
	/* U(V^2*V2 - A) */
	mulP384(pdt1,U,res1);
	/* V^3*U2 */
	mulP384(pdt2,V_3,U2);

	/* U*(V^2*V2 - A) - V^3*U2 */
	subP384(res1,pdt1,pdt2);
	if(bn_wexpand(&r->Y,6)==NULL) goto err;
	(&r->Y)->top = 6; 
	(&r->Y)->d[0] = res1[0];
	(&r->Y)->d[1] = res1[1];
	(&r->Y)->d[2] = res1[2];
	(&r->Y)->d[3] = res1[3];
	(&r->Y)->d[4] = res1[4];
	(&r->Y)->d[5] = res1[5];
	bn_fix_top(&r->Y);
	/* Y_r */

	
	ret = 1;
 err:
	return ret;
	
	}

int ec_GFp_hw_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx)
	{

	if (group->curve_name == NID_X9_62_prime256v1)
	{
		return ec_GFp_hw_add_p256(group, r, a, b);
	}
	else if (group->curve_name == NID_secp521r1)
	{
		return ec_GFp_hw_add_p521(group, r, a, b);
	}
	else if (group->curve_name == NID_secp384r1)
	{
		return ec_GFp_hw_add_p384(group, r, a, b);
	}
	else return ec_GFp_fecc_add(group, r, a, b, ctx);
	
	}

int ec_GFp_hw_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, BN_CTX *ctx)
	{

	if (group->curve_name == NID_X9_62_prime256v1)
	{
		return ec_GFp_hw_dbl_p256(group,r,a);
	}
	else if (group->curve_name == NID_secp521r1)
	{
		return ec_GFp_hw_dbl_p521(group, r, a);
	}
	else if (group->curve_name == NID_secp384r1)
	{
		return ec_GFp_hw_dbl_p384(group, r, a);
	}
	else return ec_GFp_fecc_dbl(group, r, a, ctx);
	}

int ec_GFp_fecc_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx)
	{
	int (*field_mul)(const EC_GROUP *, BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
	int (*field_sqr)(const EC_GROUP *, BIGNUM *, const BIGNUM *, BN_CTX *);
	const BIGNUM *p;
	BN_CTX *new_ctx = NULL;
	BIGNUM *n0, *n1, *n2, *n3, *n4, *n5, *n6, *n7, *n8;
	int ret = 0;

	if (a == b)
		return EC_POINT_dbl(group, r, a, ctx);
	if (EC_POINT_is_at_infinity(group, a))
		return EC_POINT_copy(r, b);
	if (EC_POINT_is_at_infinity(group, b))
		return EC_POINT_copy(r, a);

	field_mul = group->meth->field_mul;
	field_sqr = group->meth->field_sqr;
	p = &group->field;

	if (ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
		}

	BN_CTX_start(ctx);
	n0 = BN_CTX_get(ctx);
	n1 = BN_CTX_get(ctx);
	n2 = BN_CTX_get(ctx);
	n3 = BN_CTX_get(ctx);
	n4 = BN_CTX_get(ctx);
	n5 = BN_CTX_get(ctx);
	n6 = BN_CTX_get(ctx);
	n7 = BN_CTX_get(ctx);
	n8 = BN_CTX_get(ctx);
	if (n8 == NULL) goto end;

	/* n1, n2 */
	if (a->Z_is_one)
		{
		if (!BN_copy(n1, &b->Y)) goto end;
		if (!BN_copy(n2, &b->X)) goto end;
		}	
	else
		{
		if (!field_mul(group, n1, &b->Y, &a->Z, ctx)) goto end;
		if (!field_mul(group, n2, &b->X, &a->Z, ctx)) goto end;
		}

	/* n3, n4 */
	if (b->Z_is_one)
		{
		if (!BN_copy(n3, &a->Y)) goto end;
		if (!BN_copy(n4, &a->X)) goto end;
		}
	else
		{
		if (!field_mul(group, n3, &a->Y, &b->Z, ctx)) goto end;
		if (!field_mul(group, n4, &a->X, &b->Z, ctx)) goto end;
		}

	/* n5, n6 */
	if (!BN_mod_sub_quick(n5, n1, n3, p)) goto end;
	if (!BN_mod_sub_quick(n6, n2, n4, p)) goto end;

	if (BN_is_zero(n6))
		{
		if (BN_is_zero(n5))
			{
			/* a is the same point as b */
			BN_CTX_end(ctx);
			ret = EC_POINT_dbl(group, r, a, ctx);
			ctx = NULL;
			goto end;
			}
		else
			{
			/* a is the inverse of b */
			BN_zero(&r->Z);
			r->Z_is_one = 0;
			ret = 1;
			goto end;
			}
		}

	/* n7 */
	if (!field_mul(group, n7, &a->Z, &b->Z, ctx)) goto end;
	if (!field_sqr(group, n1, n6, ctx)) goto end;
	if (!field_mul(group, n2, n1, n6, ctx)) goto end;
	if (!field_mul(group, &r->Z, n2, n7, ctx)) goto end;
	/* Z_r */
	r->Z_is_one = 0;

	if (!field_sqr(group, n0, n5, ctx)) goto end;
	if (!field_mul(group, n0, n0, n7, ctx)) goto end;
	if (!field_mul(group, n7, n1, n4, ctx)) goto end;
	if (!BN_mod_lshift1_quick(n8, n7, p)) goto end;
	if (!BN_mod_sub_quick(n0, n0, n2, p)) goto end;
	if (!BN_mod_sub_quick(n0, n0, n8, p)) goto end;
	if (!field_mul(group, &r->X, n6, n0, ctx)) goto end;
	/* X_r */

	if (!BN_mod_sub_quick(n7, n7, n0, p)) goto end;
	if (!field_mul(group, n7, n5, n7, ctx)) goto end;
	if (!field_mul(group, n8, n2, n3, ctx)) goto end;
	if (!BN_mod_sub_quick(&r->Y, n7, n8, p)) goto end;
	/* Y_r */

	
	ret = 1;

 end:
	if (ctx) /* otherwise we already called BN_CTX_end */
		BN_CTX_end(ctx);
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	return ret;
	
	}

int ec_GFp_fecc_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, BN_CTX *ctx)
	{
	int (*field_mul)(const EC_GROUP *, BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
	int (*field_sqr)(const EC_GROUP *, BIGNUM *, const BIGNUM *, BN_CTX *);
	const BIGNUM *p;
	BN_CTX *new_ctx = NULL;
	BIGNUM *n0, *n1, *n2, *n3, *n4, *n5;
	int ret = 0;

	if (EC_POINT_is_at_infinity(group, a))
		{
		BN_zero(&r->Z);
		r->Z_is_one = 0;
		return 1;
		}

	field_mul = group->meth->field_mul;
	field_sqr = group->meth->field_sqr;
	p = &group->field;
	
	if (ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
		}

	BN_CTX_start(ctx);
	n0 = BN_CTX_get(ctx);
	n1 = BN_CTX_get(ctx);
	n2 = BN_CTX_get(ctx);
	n3 = BN_CTX_get(ctx);
	n4 = BN_CTX_get(ctx);
	n5 = BN_CTX_get(ctx);
	if (n5 == NULL) goto err;

	if (a->Z_is_one)
		{
		if (!field_sqr(group, n0, &a->X, ctx)) goto err;
		if (!BN_mod_lshift1_quick(n1, n0, p)) goto err;
		if (!BN_mod_add_quick(n0, n0, n1, p)) goto err;
		if (!BN_mod_add_quick(n1, n0, &group->a, p)) goto err;
		}
	else if (group->a_is_minus3)
		{
		if (!BN_mod_add_quick(n0, &a->X, &a->Z, p)) goto err;
		if (!BN_mod_sub_quick(n1, &a->X, &a->Z, p)) goto err;
		if (!field_mul(group, n0, n0, n1, ctx)) goto err;
		if (!BN_mod_lshift1_quick(n1, n0, p)) goto err;
		if (!BN_mod_add_quick(n1, n1, n0, p)) goto err;
		}
	else	
		{
		if (!field_sqr(group, n0, &a->Z, ctx)) goto err;
		if (!field_mul(group, n0, &group->a, n0, ctx)) goto err;
		if (!field_sqr(group, n1, &a->X, ctx)) goto err;
		if (!BN_mod_lshift1_quick(n2, n1, p)) goto err;
		if (!BN_mod_add_quick(n1, n1, n2, p)) goto err;
		if (!BN_mod_add_quick(n1, n0, n1, p)) goto err;
		}
	/* n1 = a*Z^2 + 3*X^2 */

	/* X_r */
	if (!field_mul(group, n2, &a->Y, &a->Z, ctx)) goto err;
	if (!field_mul(group, n0, &a->X, &a->Y, ctx)) goto err;
	if (!field_mul(group, n3, n0, n2, ctx)) goto err;
	if (!BN_mod_lshift_quick(n0, n3, 3, p)) goto err;
	if (!field_sqr(group, n4, n1, ctx)) goto err;
	if (!BN_mod_sub_quick(n4, n4, n0, p)) goto err;
	if (!field_mul(group, n0, n4, n2, ctx)) goto err;
	if (!BN_mod_lshift1_quick(&r->X, n0, p)) goto err;

	/* Y_r */
	if (!field_sqr(group, n0, &a->Y, ctx)) goto err;
	if (!field_sqr(group, n5, n2, ctx)) goto err;
	if (!field_mul(group, n0, n0, n5, ctx)) goto err;
	if (!BN_mod_lshift_quick(n0, n0, 3, p)) goto err;
	if (!BN_mod_lshift_quick(n3, n3, 2, p)) goto err;
	if (!BN_mod_sub_quick(n4, n3, n4, p)) goto err;
	if (!field_mul(group, n1, n1, n4, ctx)) goto err;
	if (!BN_mod_sub_quick(&r->Y, n1, n0, p)) goto err;

	/* Z_r */
	if (!field_mul(group, n1, n5, n2, ctx)) goto err;
	if (!BN_mod_lshift_quick(&r->Z, n1, 3, p)) goto err;
	r->Z_is_one = 0;

	ret = 1;

 err:
	BN_CTX_end(ctx);
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	return ret;
	}


int ec_GFp_fecc_is_on_curve(const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx)
	{
	int (*field_mul)(const EC_GROUP *, BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
	int (*field_sqr)(const EC_GROUP *, BIGNUM *, const BIGNUM *, BN_CTX *);
	const BIGNUM *p;
	BN_CTX *new_ctx = NULL;
	BIGNUM *rh, *lh, *tmp, *Z2, *Z3;
	int ret = -1;

	if (EC_POINT_is_at_infinity(group, point))
		return 1;
	
	field_mul = group->meth->field_mul;
	field_sqr = group->meth->field_sqr;
	p = &group->field;

	if (ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return -1;
		}

	BN_CTX_start(ctx);
	rh = BN_CTX_get(ctx);
	lh = BN_CTX_get(ctx);
	tmp = BN_CTX_get(ctx);
	Z2 = BN_CTX_get(ctx);
	Z3 = BN_CTX_get(ctx);
	if (Z3 == NULL) goto err;

	/* We have a curve defined by a Weierstrass equation
	 *      y^2 = x^3 + a*x + b.
	 * The point to consider is given in Homogeneous projective coordinates
	 * where  (X, Y, Z)  represents  (x, y) = (X/Z, Y/Z).
	 * Substituting this and multiplying by  Z^3  transforms the above equation into
	 *      Y^2*Z = X^3 + a*X*Z^2 + b*Z^3.
	 * To test this, we add up the right-hand side in 'rh'.
	 */

	/* rh := X^2 */
	if (!field_sqr(group, rh, &point->X,ctx)) goto err;

	if (!point->Z_is_one)
		{
		if (!field_sqr(group, Z2, &point->Z,ctx)) goto err;
		if (!field_mul(group, Z3, Z2, &point->Z,ctx)) goto err;

		/* rh := (rh + a*Z^2)*X */
		if (group->a_is_minus3)
			{
			if (!BN_mod_lshift1_quick(tmp, Z2, p)) goto err;
			if (!BN_mod_add_quick(tmp, tmp, Z2, p)) goto err;
			if (!BN_mod_sub_quick(rh, rh, tmp, p)) goto err;
			if (!field_mul(group, rh, rh, &point->X,ctx)) goto err;
			}
		else
			{
			if (!field_mul(group, tmp, Z2, &group->a,ctx)) goto err;
			if (!BN_mod_add_quick(rh, rh, tmp, p)) goto err;
			if (!field_mul(group, rh, rh, &point->X,ctx)) goto err;
			}

		/* rh := rh + b*Z^3 */
		if (!field_mul(group, tmp, &group->b, Z3,ctx)) goto err;
		if (!BN_mod_add_quick(rh, rh, tmp, p)) goto err;
		/* 'lh' := Y^2*Z */
		if (!field_sqr(group, tmp, &point->Y,ctx)) goto err;
		if (!field_mul(group, lh, tmp, &point->Z,ctx)) goto err;
		}
	else
		{
		/* point->Z_is_one */

		/* rh := (rh + a)*X */
		if (!BN_mod_add_quick(rh, rh, &group->a, p)) goto err;
		if (!field_mul(group, rh, rh, &point->X,ctx)) goto err;
		/* rh := rh + b */
		if (!BN_mod_add_quick(rh, rh, &group->b, p)) goto err;
		/* 'lh' := Y^2 */
		if (!field_sqr(group, lh, &point->Y,ctx)) goto err;
		}

	ret = (0 == BN_ucmp(lh, rh));

 err:
	BN_CTX_end(ctx);
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	return ret;
	}


int ec_GFp_fecc_precompute(const EC_GROUP *group, const EC_POINT *a, BN_CTX *ctx)
	{
	EC_POINT **points;
	uint16_t w=0, i;
	CAV_PRECOMP *precomp;
	BIGNUM *order;
	
	order = BN_new();
	EC_EX_DATA_free_data((EC_EXTRA_DATA **)&group->extra_data, cav_precomp_dup, cav_precomp_free, cav_precomp_clear_free);

	if ((precomp = cav_precomp_new(group)) == NULL)
		return 0;
	if(a == NULL)
		return 0;
	if (group->curve_name == NID_X9_62_prime256v1)
		w = 64;
	else if (group->curve_name == NID_secp384r1)
		w = 96;
	else if (group->curve_name == NID_secp521r1)
		w = 132;
	if (!EC_GROUP_get_order(group, order, ctx)) goto err;		
	w = 2*BN_num_bytes(order);
	/* There is a chance that we may need more pre-computed values than 2 * BN_num_bytes(order)
	* i.e when BN_num_bytes(scalar) > BN_num_bytes(order) */
	w = 2*w;
	precompute = OPENSSL_malloc(sizeof (EC_POINT*)*(w+1));
	points = precompute;	
	points[w] = NULL;
	for (i = 0; i < w; i++)
		{
		if ((points[i] = EC_POINT_new(group)) == NULL)
			{
			ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_MALLOC_FAILURE);
			goto err;
			}
		}


	//EC_POINT_set_to_infinity(group, *points++);
	EC_POINT_copy(*points++,a);
		
	for(i=1;i<w;i++,points++)
		{
		EC_POINT_dbl(group, *points, *(points - 1), ctx);
		EC_POINT_dbl(group, *points, *(points), ctx);
		EC_POINT_dbl(group, *points, *(points), ctx);
		EC_POINT_dbl(group, *points, *(points), ctx);
		}
	precomp->group = group;
	precomp->points = precompute;
	if (!EC_EX_DATA_set_data((EC_EXTRA_DATA **)&group->extra_data, precomp, cav_precomp_dup, cav_precomp_free, cav_precomp_clear_free))
		goto err;
	precomp = NULL;
err:
	BN_free(order);
	return 0;

	}
int ec_GFp_fecc_window_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
	size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *ctx)
	{
	BN_CTX *new_ctx = NULL;
	BIGNUM *tmp = NULL;
	EC_POINT *p = NULL,*q =NULL,*s = NULL;
	EC_POINT **precompute1 = NULL,**pre;
	const EC_POINT *generator = NULL;
	const CAV_PRECOMP *precomp = NULL;
	uint8_t num1=0,num2=0,val;
	uint8_t *var=NULL,*exp=NULL,window=4,w;
	int ret = 0,i=0,j=0,bytes,top=0;
	

	w = 1<<window;
	if (group->meth != r->meth)
		{
		ECerr(EC_F_EC_GFP_FECC_MUL, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}

	if ((scalar == NULL) && (num == 0))
		{
		return EC_POINT_set_to_infinity(group, r);
		}

	if (ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			goto err;
		}

	tmp = BN_new();
	p = EC_POINT_new(group);
	q = EC_POINT_new(group);
	s = EC_POINT_new(group);
	EC_POINT_set_to_infinity(group, q);

	//Algorithm 14.109
	if (scalar != NULL)
		{
		generator = EC_GROUP_get0_generator(group);
		if (generator == NULL)
			{
			ECerr(EC_F_EC_GFP_FECC_MUL, EC_R_UNDEFINED_GENERATOR);
			goto err;
			}
		precomp = EC_EX_DATA_get_data(group->extra_data, cav_precomp_dup, cav_precomp_free, cav_precomp_clear_free);
		if(precomp == NULL)
		{
			ec_GFp_fecc_precompute(group,generator,ctx);
			precomp = EC_EX_DATA_get_data(group->extra_data, cav_precomp_dup, cav_precomp_free, cav_precomp_clear_free);
			precompute_generator = precomp->points;
		}
		EC_POINT_set_to_infinity(group, p);

		bytes = BN_num_bytes(scalar);
		exp=var = OPENSSL_malloc(bytes);
		BN_bn2bin(scalar, exp);
		
		EC_POINT_set_to_infinity(group, q);
		for(j=w-1;j>=1;j--)
			{
			var = exp;
			for(i=bytes-1;i>=0;i--)
				{
					num1 = *var & 0xF0;
					num1 = num1 >> 4;
					num2 = *var & 0x0F;
					if (num1 == j)
					{
						EC_POINT_add(group, p, p, precompute_generator[2*i+1], ctx);
					}
					if (num2 == j)
					{
						EC_POINT_add(group, p, p, precompute_generator[2*i], ctx);
					}
					var = var+1;
				}
				EC_POINT_add(group, q, q, p, ctx);
			}
		OPENSSL_free(exp);
		}	
		
	//HAC Algorithm:14.83 Modified K ary

	if(points[0]!=NULL && scalars[0] != NULL)
	{
		uint8_t u[16]={0,1,1,3,1,5,3,7,1,9,5,11,3,13,7,15};
		uint8_t h[16]={0,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0};
		int b=w/2;
		w = b+1;

		EC_POINT_copy(p, points[0]);
		precompute1 = OPENSSL_malloc(sizeof (EC_POINT*)*(w+1));
		pre = precompute1;
		pre[w] = NULL;
		for (i = 0; i < w; i++)
		{
			if ((pre[i] = EC_POINT_new(group)) == NULL)
			{
				ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_MALLOC_FAILURE);
				goto err;
			}
		}
		/*Step 1.1 */	
		EC_POINT_dbl(group, p, points[0], ctx);
		EC_POINT_set_to_infinity(group, pre[0]);
		EC_POINT_copy(pre[1], points[0]);
		/*Step 1.2 */	
		for(i=1;i<b;i++)
		{
			EC_POINT_add(group, pre[i+1], pre[i], p, ctx);
		}
		BN_copy(tmp,scalars[0]);
		/*Step 2 */
		EC_POINT_set_to_infinity(group, s);
		/*Step 3 */
		top = tmp->top-1;
		while(top>=0)
		{
			for (i=0;i<16;i++)
			{
				val = (tmp->d[top])>>60;
				/* A^(2^(k-h))*/
				for (j=0;j<(window-h[val]);j++)
					EC_POINT_dbl(group, s, s, ctx);
				EC_POINT_add(group, s, s, precompute1[(u[val]+1)/2], ctx);
				for (j=0;j<h[val];j++)
					EC_POINT_dbl(group, s, s, ctx);
				tmp->d[top] = tmp->d[top] << 4;
			}	
			top--;
		}
		if(precompute1)
		{
			for (pre = precompute1; *pre != NULL; pre++)
				EC_POINT_free(*pre);	
			OPENSSL_free(precompute1);
		}
	}

	/* 14.82 K-ary */
#if 0
	if(points[0]!=NULL && scalars[0] != NULL)
	{
		EC_POINT_copy(p, points[0]);
		precompute1 = OPENSSL_malloc(sizeof (EC_POINT*)*(w+1));
		pre = precompute1;
		pre[w] = NULL;
		for (i = 0; i < w; i++)
		{
			if ((pre[i] = EC_POINT_new(group)) == NULL)
			{
				ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_MALLOC_FAILURE);
				goto err;
			}
		}
	
		EC_POINT_set_to_infinity(group, *pre++);
		
		for(i=1;i<w;i++,pre++)
			EC_POINT_add(group, *pre, p, *(pre - 1), ctx);
		BN_copy(tmp,scalars[0]);
		EC_POINT_set_to_infinity(group, p);

		top = tmp->top-1;
		while(top>=0)
		{
			for (i=0;i<16;i++)
			{
				val = (tmp->d[top])>>60;
				EC_POINT_add(group, s, p, precompute1[val], ctx);
				EC_POINT_dbl(group, p, s, ctx);
				EC_POINT_dbl(group, p, p, ctx);
				EC_POINT_dbl(group, p, p, ctx);
				EC_POINT_dbl(group, p, p, ctx);
				tmp->d[top] = tmp->d[top] << 4;
			}	
			top--;
		}
		if(precompute1)
		{
			for (pre = precompute1; *pre != NULL; pre++)
				EC_POINT_free(*pre);	
			OPENSSL_free(precompute1);
		}

	}
#endif
		
	EC_POINT_add(group, q, q, s, ctx);
	EC_POINT_copy(r,q);	
	ret = 1;	

 err:
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	EC_POINT_free(q);
	EC_POINT_free(p);
	EC_POINT_free(s);
	BN_free(tmp);
	return ret;
	
	}
