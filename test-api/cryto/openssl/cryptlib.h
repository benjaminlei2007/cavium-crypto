/* crypto/cryptlib.h */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
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

#ifndef HEADER_CRYPTLIB_H
#define HEADER_CRYPTLIB_H

#include <stdlib.h>
#include <string.h>

#include "e_os.h"

#ifdef OPENSSL_USE_APPLINK
#define BIO_FLAGS_UPLINK 0x8000
#include "ms/uplink.h"
#endif

#include <openssl/crypto.h>
#include <openssl/buffer.h> 
#include <openssl/bio.h> 
#include <openssl/err.h>
#include <openssl/opensslconf.h>

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef OCTEON_OPENSSL
#include <openssl/rsa.h>
#define ROUNDUP8(val) (((val) + 7)&0xfffffff8)
#define MINIMUM(a,b) ( (a<b)? a :b)
#define MAXIMUM(a,b) ( (a>b)? a :b)

/**
 * Modular Exponentiation <br> 
 * ME = b ^ e mod m
 * <h3>NOTE</h3>
 * <ol>
 * <li> There must be at least one bit set in the most-significant word of the modulus.
 * <li> The modulus must be odd.
 * <li> The exponent and base lengths must be less than to the modulus length.
 * <li> modulus length from 9 to 256 bytes is supported.
 * </ol>
 *
 * Prerequisites to use this function:
 * Parameters(mod,exponent,base) should be padded with 64 bytes of data. Also 
 * the parameters should be reversed taken 8 bytes at a time before 
 * passing to this function.

 * @param  product  [out] pointer to result of modular exponent operation.
 * @param  base     [in]  pointer to base value used in modular exponent operation.
 * @param  exponent [in]  pointer to exponent value used for modular
                          exponent operation.
 * @param  mod      [in]  pointer to modulus value used in modular exponent
 *                        operation.
 * @param  len      [in]  length  of product buffer in bytes.(len = (mlen/192)+1)
 * @param  elen     [in]  length  of exponent buffer in bytes
 * @param  mlen     [in]  length  of modulus buffer in bytes
 * @param  blen     [in]  length  of base buffer in bytes
 *
 * @return 0 on success .
 * @return  Failure: Non-zero (@ref cerr for Error codes)
 */
  int cvm_ModExp (uint64_t * product, uint64_t * base, uint64_t * exponent,
    uint64_t * mod, int len, int elen, int mlen, int blen);
  int cvm_ModExpCrt (uint64_t * product, uint64_t * base,
    cvm_rsa_key_t * rkey, int nonwalign);
  int _cvm_ModExpCrt (uint64_t * product, uint64_t * base,
    cvm_rsa_key_t * rkey, int nonwalign, int convert);
  int cav_mod_exp (BIGNUM * res, const BIGNUM * base, const BIGNUM * exp,
    const BIGNUM * mod, BN_CTX * ctx);
  int crypto_mult (uint64_t montmul, uint64_t arg);
  int crypto_init (void);
#endif


#ifndef OPENSSL_SYS_VMS
#define X509_CERT_AREA		OPENSSLDIR
#define X509_CERT_DIR		OPENSSLDIR "/certs"
#define X509_CERT_FILE		OPENSSLDIR "/cert.pem"
#define X509_PRIVATE_DIR	OPENSSLDIR "/private"
#else
#define X509_CERT_AREA		"SSLROOT:[000000]"
#define X509_CERT_DIR		"SSLCERTS:"
#define X509_CERT_FILE		"SSLCERTS:cert.pem"
#define X509_PRIVATE_DIR        "SSLPRIVATE:"
#endif

#define X509_CERT_DIR_EVP        "SSL_CERT_DIR"
#define X509_CERT_FILE_EVP       "SSL_CERT_FILE"

/* size of string representations */
#define DECIMAL_SIZE(type)	((sizeof(type)*8+2)/3+1)
#define HEX_SIZE(type)		(sizeof(type)*2)

void OPENSSL_cpuid_setup(void);
extern unsigned int OPENSSL_ia32cap_P[];
void OPENSSL_showfatal(const char *fmta,...);
void *OPENSSL_stderr(void);
extern int OPENSSL_NONPIC_relocated;

#ifdef  __cplusplus
}
#endif

#endif
