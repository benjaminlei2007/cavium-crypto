/* e_octeon_err.c */
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



/* NOTE: this file was auto generated by the mkerr.pl script: any changes
 * made to it will be overwritten when the script next updates this file,
 * only reason strings will be preserved.
 */

#include <stdio.h>
#include <openssl/err.h>
#include "e_octeon_err.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

#define ERR_FUNC(func) ERR_PACK(0,func,0)
#define ERR_REASON(reason) ERR_PACK(0,0,reason)

static ERR_STRING_DATA OCTEON_str_functs[]=
	{
{ERR_FUNC(OCTEON_F_OCTEON_AES_DO_CIPHER),	"OCTEON_AES_DO_CIPHER"},
{ERR_FUNC(OCTEON_F_OCTEON_DES_DO_CIPHER),	"OCTEON_DES_DO_CIPHER"},
{ERR_FUNC(OCTEON_F_OCTEON_DES_EDE3_DO_CIPHER),	"OCTEON_DES_EDE3_DO_CIPHER"},
{ERR_FUNC(OCTEON_F_OCTEON_INIT),	"OCTEON_INIT"},
{ERR_FUNC(OCTEON_F_OCT_ENG_BN_MOD_EXP),	"OCT_ENG_BN_MOD_EXP"},
{ERR_FUNC(OCTEON_F_OCT_ENG_DH_MOD_EXP),	"OCT_ENG_DH_MOD_EXP"},
{ERR_FUNC(OCTEON_F_OCT_ENG_DSA_BN_MOD_EXP),	"OCT_ENG_DSA_BN_MOD_EXP"},
{ERR_FUNC(OCTEON_F_OCT_ENG_DSA_MOD_EXP),	"OCT_ENG_DSA_MOD_EXP"},
{ERR_FUNC(OCTEON_F_OCT_ENG_RSA_MOD_EXP),	"OCT_ENG_RSA_MOD_EXP"},
{0,NULL}
	};

static ERR_STRING_DATA OCTEON_str_reasons[]=
	{
{ERR_REASON(OCTEON_R_AES_INIT_NOT_DONE)  ,"aes init not done"},
{ERR_REASON(OCTEON_R_CVM_INIT_FAILURE)   ,"cvm init failure"},
{ERR_REASON(OCTEON_R_DES_EDE3_ENCRYPT_FAILURE),"des ede3 encrypt failure"},
{ERR_REASON(OCTEON_R_DES_EDE3_INIT_NOT_DONE),"des ede3 init not done"},
{ERR_REASON(OCTEON_R_DES_ENCRYPT_FAILURE),"des encrypt failure"},
{ERR_REASON(OCTEON_R_DES_INIT_NOT_DONE)  ,"des init not done"},
{ERR_REASON(OCTEON_R_MOD_EXP_CRT_FAILURE),"mod exp crt failure"},
{ERR_REASON(OCTEON_R_MOD_EXP_FAILURE)    ,"mod exp failure"},
{ERR_REASON(OCTEON_R_OCT_CRYPTO_MODULE_INIT_FAILURE),"oct crypto module init failure"},
{0,NULL}
	};

#endif

#ifdef OCTEON_LIB_NAME
static ERR_STRING_DATA OCTEON_lib_name[]=
        {
{0	,OCTEON_LIB_NAME},
{0,NULL}
	};
#endif


static int OCTEON_lib_error_code=0;
static int OCTEON_error_init=1;

static void ERR_load_OCTEON_strings(void)
	{
	if (OCTEON_lib_error_code == 0)
		OCTEON_lib_error_code=ERR_get_next_error_library();

	if (OCTEON_error_init)
		{
		OCTEON_error_init=0;
#ifndef OPENSSL_NO_ERR
		ERR_load_strings(OCTEON_lib_error_code,OCTEON_str_functs);
		ERR_load_strings(OCTEON_lib_error_code,OCTEON_str_reasons);
#endif

#ifdef OCTEON_LIB_NAME
		OCTEON_lib_name->error = ERR_PACK(OCTEON_lib_error_code,0,0);
		ERR_load_strings(0,OCTEON_lib_name);
#endif
		}
	}

static void ERR_unload_OCTEON_strings(void)
	{
	if (OCTEON_error_init == 0)
		{
#ifndef OPENSSL_NO_ERR
		ERR_unload_strings(OCTEON_lib_error_code,OCTEON_str_functs);
		ERR_unload_strings(OCTEON_lib_error_code,OCTEON_str_reasons);
#endif

#ifdef OCTEON_LIB_NAME
		ERR_unload_strings(0,OCTEON_lib_name);
#endif
		OCTEON_error_init=1;
		}
	}

static void ERR_OCTEON_error(int function, int reason, char *file, int line)
	{
	if (OCTEON_lib_error_code == 0)
		OCTEON_lib_error_code=ERR_get_next_error_library();
	ERR_PUT_error(OCTEON_lib_error_code,function,reason,file,line);
	}
