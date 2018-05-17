/* crypto/eceg/eceg.h */
/* ====================================================================
 * Copyright (c) 2000-2005 The OpenSSL Project.  All rights reserved.
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
 *    licensing@OpenSSL.org.
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


#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_ECEG
#error ECEG is disabled.
#endif

#include <openssl/ec.h>
#ifndef OPENSSL_NO_DEPRECATED
#include <openssl/bn.h>
#endif


typedef struct ECEG_SIG_st
	{
	BIGNUM *r;
	BIGNUM *s;
	} ECEG_SIG;

/** Allocates and initialize a ECEG_SIG structure
 *  \return pointer to a ECEG_SIG structure or NULL if an error occurred
 */

/** ECEG_SIG *ECEG_SIG_new(void)
 * allocates and initialize a ECEG_SIG structure
 * \return pointer to a ECEG_SIG structure or NULL if an error occurred
 */
ECEG_SIG *ECEG_SIG_new(void);

/** ECEG_SIG_free
 * frees a ECEG_SIG structure
 * \param a pointer to the ECEG_SIG structure
 */
void	  ECEG_SIG_free(ECEG_SIG *a);

/** i2d_ECEG_SIG
 * DER encode content of ECEG_SIG object (note: this function modifies *pp
 * (*pp += length of the DER encoded signature)).
 * \param a  pointer to the ECEG_SIG object
 * \param pp pointer to a unsigned char pointer for the output or NULL
 * \return the length of the DER encoded ECEG_SIG object or 0 
 */
int	  i2d_ECEG_SIG(const ECEG_SIG *a, unsigned char **pp);

/** d2i_ECEG_SIG
 * decodes a DER encoded ECEG signature (note: this function changes *pp
 * (*pp += len)). 
 * \param v pointer to ECEG_SIG pointer (may be NULL)
 * \param pp buffer with the DER encoded signature
 * \param len bufferlength
 * \return pointer to the decoded ECEG_SIG structure (or NULL)
 */
ECEG_SIG *d2i_ECEG_SIG(ECEG_SIG **v, const unsigned char **pp, long len);

/** ECEG_do_sign
 * computes the ECEG signature of the given hash value using
 * the supplied private key and returns the created signature.
 * \param dgst pointer to the hash value
 * \param dgst_len length of the hash value
 * \param eckey pointer to the EC_KEY object containing a private EC key
 * \return pointer to a ECEG_SIG structure or NULL
 */
ECEG_SIG *ECEG_do_sign(const unsigned char *dgst,int dgst_len,EC_KEY *eckey);


/** ECEG_do_sign_ex
 * computes ECEG signature of a given hash value using the supplied
 * private key (note: sig must point to ECEG_size(eckey) bytes of memory).
 * \param dgst pointer to the hash value to sign
 * \param dgstlen length of the hash value
 * \param k optional pointer to a pre-computed inverse k
 * \param rp optional pointer to the pre-computed rp value (see 
 *        ECEG_sign_setup
 * \param eckey pointer to the EC_KEY object containing a private EC key
 * \return pointer to a ECEG_SIG structure or NULL
 */

ECEG_SIG *ECEG_do_sign_ex(const unsigned char *dgst, int dgstlen, 
		const BIGNUM *k, const BIGNUM *rp, EC_KEY *eckey);

/** ECEG_do_verify
 * verifies that the supplied signature is a valid ECEG
 * signature of the supplied hash value using the supplied public key.
 * \param dgst pointer to the hash value
 * \param dgst_len length of the hash value
 * \param sig  pointer to the ECEG_SIG structure
 * \param eckey pointer to the EC_KEY object containing a public EC key
 * \return 1 if the signature is valid, 0 if the signature is invalid and -1 on error
 */
int	  ECEG_do_verify(const unsigned char *dgst, int dgst_len,
		const ECEG_SIG *sig, EC_KEY* eckey);


/** ECEG_sign_ex
 * computes ECEG signature of a given hash value using the supplied
 * private key (note: sig must point to ECEG_size(eckey) bytes of memory).
 * \param type this parameter is ignored
 * \param dgst pointer to the hash value to sign
 * \param dgstlen length of the hash value
 * \param sig buffer to hold the DER encoded signature
 * \param siglen pointer to the length of the returned signature
 * \param kinv optional pointer to a pre-computed inverse k
 * \param rp optional pointer to the pre-computed rp value (see 
 *        ECEG_sign_setup
 * \param eckey pointer to the EC_KEY object containing a private EC key
 * \return 1 on success and 0 otherwise
 */

int	  ECEG_sign_ex(int type, const unsigned char *dgst, int dgstlen, 
		unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv,
		const BIGNUM *rp, EC_KEY *eckey);

const ECEG_METHOD *ECEG_OpenSSL(void);

/** Returns the maximum length of the DER encoded signature
 *  \param  eckey  EC_KEY object
 *  \return numbers of bytes required for the DER encoded signature
 */
int	  ECEG_size(const EC_KEY *eckey);

/** ECEG_sign_setup
 * precompute parts of the signing operation. 
 * \param eckey pointer to the EC_KEY object containing a private EC key
 * \param ctx  pointer to a BN_CTX object (may be NULL)
 * \param kinv pointer to a BIGNUM pointer for the inverse of k
 * \param rp   pointer to a BIGNUM pointer for x coordinate of k * generator
 * \return 1 on success and 0 otherwise
 */
int 	  ECEG_sign_setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv, 
		BIGNUM **rp);

/** Computes ECEG signature of a given hash value using the supplied
 *  private key (note: sig must point to ECEG_size(eckey) bytes of memory).
 *  \param  type     this parameter is ignored
 *  \param  dgst     pointer to the hash value to sign
 *  \param  dgstlen  length of the hash value
 *  \param  sig      memory for the DER encoded created signature
 *  \param  siglen   pointer to the length of the returned signature
 *  \param  eckey    EC_KEY object containing a private EC key
 *  \return 1 on success and 0 otherwise
 */
int	  ECEG_sign(int type, const unsigned char *dgst, int dgstlen, 
		unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);

/** Verifies that the given signature is valid ECEG signature
 *  of the supplied hash value using the specified public key.
 *  \param  type     this parameter is ignored
 *  \param  dgst     pointer to the hash value 
 *  \param  dgstlen  length of the hash value
 *  \param  sig      pointer to the DER encoded signature
 *  \param  siglen   length of the DER encoded signature
 *  \param  eckey    EC_KEY object containing a public EC key
 *  \return 1 if the signature is valid, 0 if the signature is invalid
 *          and -1 on error
 */
int 	  ECEG_verify(int type, const unsigned char *dgst, int dgstlen, 
		const unsigned char *sig, int siglen, EC_KEY *eckey);

void ERR_load_ECEG_strings(void);

/* Error codes for the ECEG functions. */

/* Function codes. */
#define ECEG_F_ECEG_DATA_NEW_METHOD			 100
#define ECEG_F_ECEG_DO_SIGN				 101
#define ECEG_F_ECEG_DO_VERIFY				 102
#define ECEG_F_ECEG_SIGN_SETUP				 103

/* Reason codes. */
#define ECEG_R_BAD_SIGNATURE				 100
#define ECEG_R_DATA_TOO_LARGE_FOR_KEY_SIZE		 101
#define ECEG_R_ERR_EC_LIB				 102
#define ECEG_R_MISSING_PARAMETERS			 103
#define ECEG_R_NEED_NEW_SETUP_VALUES			 106
#define ECEG_R_RANDOM_NUMBER_GENERATION_FAILED		 104
#define ECEG_R_SIGNATURE_MALLOC_FAILED			 105


