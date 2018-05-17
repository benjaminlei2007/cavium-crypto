/* crypto/eceg/ecg_lib.c */
/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
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


#include <string.h>
#include "ecg_locl.h"
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/err.h>
#include <openssl/bn.h>

static const ECEG_METHOD *default_ECEG_method = NULL;

static void *eceg_data_new(void);
static void *eceg_data_dup(void *);
static void  eceg_data_free(void *);

const ECEG_METHOD *ECEG_get_default_method(void)
{
	if(!default_ECEG_method) 
		default_ECEG_method = ECEG_OpenSSL();
	return default_ECEG_method;
}

static ECEG_DATA *ECEG_DATA_new_method(ENGINE *engine)
{
	ECEG_DATA *ret;

	ret=(ECEG_DATA *)OPENSSL_malloc(sizeof(ECEG_DATA));
	if (ret == NULL)
	{
		ECEGerr(ECEG_F_ECEG_DATA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
		return(NULL);
	}

	ret->init = NULL;

	ret->meth = ECEG_get_default_method();
	ret->engine = engine;
#ifndef OPENSSL_NO_ENGINE
	if (!ret->engine)
		ret->engine = ENGINE_get_default_ECEG();
	if (ret->engine)
	{
		ret->meth = ENGINE_get_ECEG(ret->engine);
		if (!ret->meth)
		{
			ECEGerr(ECEG_F_ECEG_DATA_NEW_METHOD, ERR_R_ENGINE_LIB);
			ENGINE_finish(ret->engine);
			OPENSSL_free(ret);
			return NULL;
		}
	}
#endif

	ret->flags = ret->meth->flags;
	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_ECEG, ret, &ret->ex_data);
#if 0
	if ((ret->meth->init != NULL) && !ret->meth->init(ret))
	{
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_ECEG, ret, &ret->ex_data);
		OPENSSL_free(ret);
		ret=NULL;
	}
#endif	
	return(ret);
}

static void *eceg_data_new(void)
{
	return (void *)ECEG_DATA_new_method(NULL);
}

static void *eceg_data_dup(void *data)
{
	ECEG_DATA *r = (ECEG_DATA *)data;

	/* XXX: dummy operation */
	if (r == NULL)
		return NULL;

	return eceg_data_new();
}

static void eceg_data_free(void *data)
{
	ECEG_DATA *r = (ECEG_DATA *)data;

#ifndef OPENSSL_NO_ENGINE
	if (r->engine)
		ENGINE_finish(r->engine);
#endif
	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_ECEG, r, &r->ex_data);

	OPENSSL_cleanse((void *)r, sizeof(ECEG_DATA));

	OPENSSL_free(r);
}

ECEG_DATA *eceg_check(EC_KEY *key)
{
	ECEG_DATA *eceg_data;
 
	void *data = EC_KEY_get_key_method_data(key, eceg_data_dup,
					eceg_data_free, eceg_data_free);
	if (data == NULL)
	{
		eceg_data = (ECEG_DATA *)eceg_data_new();
		if (eceg_data == NULL)
			return NULL;
		EC_KEY_insert_key_method_data(key, (void *)eceg_data,
			eceg_data_dup, eceg_data_free, eceg_data_free);
	}
	else
		eceg_data = (ECEG_DATA *)data;
	

	return eceg_data;
}

int ECEG_size(const EC_KEY *r)
{
	int ret,i;
	ASN1_INTEGER bs;
	BIGNUM	*order=NULL;
	unsigned char buf[4];
	const EC_GROUP *group;

	if (r == NULL)
		return 0;
	group = EC_KEY_get0_group(r);
	if (group == NULL)
		return 0;

	if ((order = BN_new()) == NULL) return 0;
	if (!EC_GROUP_get_order(group,order,NULL))
	{
		BN_clear_free(order);
		return 0;
	} 
	i=BN_num_bits(order);
	bs.length=(i+7)/8;
	bs.data=buf;
	bs.type=V_ASN1_INTEGER;
	/* If the top bit is set the asn1 encoding is 1 larger. */
	buf[0]=0xff;	

	i=i2d_ASN1_INTEGER(&bs,NULL);
	i+=i; /* r and s */
	ret=ASN1_object_size(1,i,V_ASN1_SEQUENCE);
	BN_clear_free(order);
	return(ret);
}

