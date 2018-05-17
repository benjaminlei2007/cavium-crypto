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

#define UEA_REV_1	1	/* uses Kasumi */
#define UIA_REV_1	1	/* uses Kasumi */

typedef struct 
{
   uint64_t start;
   union{
     uint64_t ksb;
     uint8_t  k[8];
   }x;
   uint64_t blkcnt;
   int pos;
   uint64_t key0;
   uint64_t key1;
}uea1_ctx;

typedef struct 
{
   uint64_t a;
   uint64_t b;
  union{
   uint64_t dat;
   uint8_t d[8];
  }x;
   int rem_len;
   uint64_t key0;
   uint64_t key1;
   uint8_t direction;
}uia1_ctx;

/** 
 * initializes UEA1 context  
 *
 * @param ctx		pointer to UEA1 context 
 *
 * @param count		count ,
 * @param bearer	bearer and
 * @param direction	direction are used to generate start param
 *  			
 * @param key		16 byte key used to encrypt
 *  			
 * @return  0 on SUCCESS
 *          NON-ZERO on FAILURE 
 *
 */
int uea1_init(uea1_ctx *ctx, uint32_t count, uint8_t bearer, uint8_t direction, uint8_t *key);

/** 
 * Encrypts using UEA1  
 *
 * @param ctx	    pointer to uea1 ctx
 *  			
 * @param length	Message length in bits
 *  
 * @param input 	pointer to input
 *  
 * @param output	result pointer
 *  
 * @return  0 on SUCCESS
 *          NON-ZERO on FAILURE 
 *
 */
int uea1_enc(uea1_ctx *ctx, int length, uint8_t *input, uint8_t *output);

/** 
 * Initializes  UIA1 ctx  
 *
 * @param ctx	        pointer UIA1 ctx
 *  
 * @param count		count ,
 * @param fresh	        fresh and
 * @param direction	direction are used to generate start param
 *  			
 * @param key		16 byte key used to encrypt
 *  			
 * @return  0 on SUCCESS
 *          NON-ZERO on FAILURE 
 *
 */
int uia1_init(uia1_ctx *ctx, uint32_t count, uint32_t fresh, uint8_t direction, uint8_t *key);

/** 
 * update  UIA1 ctx with data  
 *
 * @param ctx	        pointer to uia1 ctx
 *  			
 * @param length	Message length
 *  
 * @param input 	pointer to input
 *  
 * @return  0 on SUCCESS
 *          NON-ZERO on FAILURE 
 *
 */
int uia1_update(uia1_ctx *ctx, int length, uint8_t *input);
/** 
 * Auth using UIA1  
 *
 * @param ctx	        pointer to uia1 ctx
 *  			
 * @param mac	        4 bytes result pointer
 *  
 * @return  0 on SUCCESS
 *          NON-ZERO on FAILURE 
 *
 */
int uia1_final(uia1_ctx *ctx, uint32_t *mac);
