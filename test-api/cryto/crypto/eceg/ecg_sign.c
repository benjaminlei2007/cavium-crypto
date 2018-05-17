/* crypto/eceg/ecg_sign.c */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
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

ECEG_SIG *ECEG_do_sign(const unsigned char *dgst, int dlen, EC_KEY *eckey)
{
	return ECEG_do_sign_ex(dgst, dlen, NULL, NULL, eckey);
}

ECEG_SIG *ECEG_do_sign_ex(const unsigned char *dgst, int dlen,
	const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *eckey)
{
	ECEG_DATA *eceg = eceg_check(eckey);
	if (eceg == NULL)
		return NULL;
	return eceg->meth->eceg_do_sign(dgst, dlen, kinv, rp, eckey);
}

int ECEG_sign(int type, const unsigned char *dgst, int dlen, unsigned char 
		*sig, unsigned int *siglen, EC_KEY *eckey)
{
	return ECEG_sign_ex(type, dgst, dlen, sig, siglen, NULL, NULL, eckey);
}

int ECEG_sign_ex(int type, const unsigned char *dgst, int dlen, unsigned char 
	*sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, 
	EC_KEY *eckey)
{
	ECEG_SIG *s;
	s = ECEG_do_sign_ex(dgst, dlen, kinv, r, eckey);
	if (s == NULL)
	{
		*siglen=0;
		return 0;
	}
	*siglen = i2d_ECEG_SIG(s, &sig);
	ECEG_SIG_free(s);
	return 1;
}
int ECEG_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, 
		BIGNUM **rp)
{
	ECEG_DATA *eceg = eceg_check(eckey);
	if (eceg == NULL)
		return 0;
	return eceg->meth->eceg_sign_setup(eckey, ctx_in, kinvp, rp); 
}
/* KT-IV */
#if 0
ECEG_SIG *ECEG_do_sign_ex(const unsigned char *dgst, int dlen,
	const BIGNUM *k, const BIGNUM *rp, EC_KEY *eckey)
{
	ECEG_DATA *eceg = eceg_check(eckey);
	if (eceg == NULL)
		return NULL;
	return eceg->meth->eceg_do_sign(dgst, dlen, k, rp, eckey);
}
int ECEG_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kp, 
		BIGNUM **rp)
{
	ECEG_DATA *eceg = eceg_check(eckey);
	if (eceg == NULL)
		return 0;
	return eceg->meth->eceg_sign_setup(eckey, ctx_in, kp, rp); 
}
#endif
