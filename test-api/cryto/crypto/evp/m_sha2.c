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



#ifndef OPENSSL_NO_SHA
#include <stdio.h>
#include "cryptlib.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

/* SHA224 */
static int init_sha224 (EVP_MD_CTX *ctx)
{
   return SHA224_Init ((SHA256_CTX *)ctx->md_data);
}

static int update_sha224 (EVP_MD_CTX *ctx, const void *data, unsigned long count)
{
   return SHA224_Update ((SHA256_CTX *)ctx->md_data, data, count);
}

static int final_sha224 (EVP_MD_CTX *ctx, unsigned char *md)
{
   return SHA224_Final (md, (SHA256_CTX *)ctx->md_data);
}

static const EVP_MD sha224_md =
{
   NID_sha224,
   NID_sha224WithRSAEncryption,
   SHA224_DIGEST_LENGTH,
   0,
   init_sha224,
   update_sha224,
   final_sha224,
   NULL,
   NULL,
   EVP_PKEY_RSA_method,
   SHA224_CBLOCK,
   sizeof (EVP_MD *) + sizeof (SHA256_CTX), 
   NULL 
};

const EVP_MD *EVP_sha224(void)
{
   return (&sha224_md);
}

/* SHA256 */
static int init_sha256 (EVP_MD_CTX *ctx)
{
   return SHA256_Init ((SHA256_CTX *)ctx->md_data);
}

static int update_sha256 (EVP_MD_CTX *ctx, const void *data, unsigned long count)
{
   return SHA256_Update ((SHA256_CTX *)ctx->md_data, data, count);
}

static int final_sha256 (EVP_MD_CTX *ctx, unsigned char *md)
{
   return SHA256_Final (md, (SHA256_CTX *)ctx->md_data);
}

static const EVP_MD sha256_md =
{
   NID_sha256,
   NID_sha256WithRSAEncryption,
   SHA256_DIGEST_LENGTH,
   0,
   init_sha256,
   update_sha256,
   final_sha256,
   NULL,
   NULL,
   EVP_PKEY_RSA_method,
   SHA256_CBLOCK,
   sizeof (EVP_MD *) + sizeof (SHA256_CTX), 
   NULL 
};

const EVP_MD *EVP_sha256(void)
{
   return (&sha256_md);
}

/* SHA384 */
static int init_sha384 (EVP_MD_CTX *ctx)
{
   return SHA384_Init ((SHA512_CTX *)ctx->md_data);
}

static int update_sha384 (EVP_MD_CTX *ctx, const void *data, unsigned long count)
{
   return SHA384_Update ((SHA512_CTX *)ctx->md_data, data, count);
}

static int final_sha384 (EVP_MD_CTX *ctx, unsigned char *md)
{
   return SHA384_Final (md, (SHA512_CTX *)ctx->md_data);
}

static const EVP_MD sha384_md =
{
   NID_sha384,
   NID_sha384WithRSAEncryption,
   SHA384_DIGEST_LENGTH,
   0,
   init_sha384,
   update_sha384,
   final_sha384,
   NULL,
   NULL,
   EVP_PKEY_RSA_method,
   SHA384_CBLOCK,
   sizeof (EVP_MD *) + sizeof (SHA512_CTX), 
   NULL 
};

const EVP_MD *EVP_sha384(void)
{
   return (&sha384_md);
}

/* SHA512 */
static int init_sha512 (EVP_MD_CTX *ctx)
{
   return SHA512_Init ((SHA512_CTX *)ctx->md_data);
}

static int update_sha512 (EVP_MD_CTX *ctx, const void *data, unsigned long count)
{
   return SHA512_Update ((SHA512_CTX *)ctx->md_data, data, count);
}

static int final_sha512 (EVP_MD_CTX *ctx, unsigned char *md)
{
   return SHA512_Final (md, (SHA512_CTX *)ctx->md_data);
}

static const EVP_MD sha512_md =
{
   NID_sha512,
   NID_sha512WithRSAEncryption,
   SHA512_DIGEST_LENGTH,
   0,
   init_sha512,
   update_sha512,
   final_sha512,
   NULL,
   NULL,
   EVP_PKEY_RSA_method,
   SHA512_CBLOCK,
   sizeof (EVP_MD *) + sizeof (SHA512_CTX),
   NULL 
};

const EVP_MD *EVP_sha512(void)
{
   return (&sha512_md);
}
#endif
