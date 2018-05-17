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



#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "cvmx.h"
#include "cvmx-asm.h"
#include "openssl/aes.h"

int
AES_CCM_setup_blocks(uint8_t m, uint8_t l,uint8_t *ain, uint64_t alen, uint64_t plen, uint64_t *nonce_val, aes_ccm_ctx * aes_ctx)
{
   memset (aes_ctx, 0, sizeof (aes_ccm_ctx));
   aes_ctx->mac_length = m;
   aes_ctx->nonce.val[0] = nonce_val[0];	
   aes_ctx->nonce.val[1] = nonce_val[1];	
   aes_ctx->b0_flags.val = 0;
   aes_ctx->b0_flags.s.adata = (alen ? 1 : 0);
   aes_ctx->b0_flags.s.m = (m - 2)/2;
   aes_ctx->b0_flags.s.l = (l - 1);
   /* A0  = [Flags, Nonce, Counter] */
   aes_ctx->a0_flags.val = 0;
   aes_ctx->a0_flags.s.l = (l - 1);

   /* Make b0, a0 */
   aes_ctx->a0high = (((uint64_t)(aes_ctx->a0_flags.val)) << 56);
   aes_ctx->a0low = 0;
   if ( l < 8) {
      int i;
      for (i = 0; i < 7; i++)
         aes_ctx->a0high |= (((uint64_t)aes_ctx->nonce.byte[i]) << (48 - 8*i));
      for (i = 7; i < 15-l; i++)
         aes_ctx->a0low |= (((uint64_t)aes_ctx->nonce.byte[i]) << (56 - (i - 7)*8));
   } else { /* l == 8 */
      aes_ctx->a0high |= aes_ctx->nonce.val[0];
   }
   aes_ctx->b0high = (((uint64_t)aes_ctx->b0_flags.val) << 56);
   aes_ctx->b0low = 0;
   if ( l < 8) {
      int i;
      for (i = 0; i < 7; i++) 
         aes_ctx->b0high |= (((uint64_t)aes_ctx->nonce.byte[i]) << (48 - 8*i));
      for (i = 7; i < 15-l; i++) 
         aes_ctx->b0low |= (((uint64_t)aes_ctx->nonce.byte[i]) << (56 - (i - 7)*8));
   } else { /* l == 8 */
      aes_ctx->b0high |= aes_ctx->nonce.val[0];
   }
   aes_ctx->b0low |= plen;
   aes_ctx->no_alen=(alen?0:1);

   #define MIN(a, b) (a < b ? (a) : (b))
   /* Make first authentication block */
   if (cvmx_likely(alen < 256*255)) { 
      /* Length (1, (2^16 - 2^8)) Encode value = 0x0001 ... 0xFEFF */
      int i;
      aes_ctx->block64_t.val[0] = 0;
      aes_ctx->block64_t.val[1] = 0;
      aes_ctx->block64_t.s.two_octets = alen;
      aes_ctx->offset = MIN(alen,14);
      for (i = 0; i < aes_ctx->offset; i++)
         aes_ctx->block64_t.s.adata[i] = ain[i];
   } else if(cvmx_likely( (alen >= 0xFF00) && (alen < 0x100000000ULL))){
     /*Length Encode value 0xFF , 0xFE and the four bytes encoding length of adata */
      int i;
      aes_ctx->block64_t.val[0] = 0;
      aes_ctx->block64_t.val[1] = 0;
      aes_ctx->block64_t.s1.two_octets[0] = 0xff;	
      aes_ctx->block64_t.s1.two_octets[1] = 0xfe;	
      *(uint32_t *)(aes_ctx->block64_t.s1.four_octets) = (uint32_t)alen;	
      aes_ctx->offset = 10;
      for (i = 0; i < aes_ctx->offset; i++)
         aes_ctx->block64_t.s1.adata[i] = ain[i];
   } else if(cvmx_likely( (alen >= 0x100000000ULL))){
     /*Length Encode value 0xFF , 0xFF and the eight bytes encoding length of adata */
      int i;
      aes_ctx->block64_t.val[0] = 0;
      aes_ctx->block64_t.val[1] = 0;
      aes_ctx->block64_t.s2.two_octets[0] = 0xff;	
      aes_ctx->block64_t.s2.two_octets[1] = 0xff;	
      *(uint64_t *)(aes_ctx->block64_t.s2.eight_octets) = alen;	
      aes_ctx->offset = 6;
      for (i = 0; i < aes_ctx->offset; i++)
         aes_ctx->block64_t.s2.adata[i] = ain[i];
   } else {
      printf("Invalid Length for the Authentication data\n");
      return AES_CCM_INVALID_AUTH_DATA;	
   }	
 return 0;
}

int AES_CCM_set_key(uint64_t *K, uint32_t klen)
{
    CVMX_MT_AES_KEY(K[0],0);
    CVMX_MT_AES_KEY(K[1],1);
    switch(klen)
    {
       case 128: 
                CVMX_MT_AES_KEY(0,2);
                CVMX_MT_AES_KEY(0,3);
                break;
       case 192:
                CVMX_MT_AES_KEY(K[2],2);
                CVMX_MT_AES_KEY(0,3);
                break;
       case 256:                
                CVMX_MT_AES_KEY(K[2],2);
                CVMX_MT_AES_KEY(K[3],3);
                break;
       default :
               printf("Invalid Key length\n"); 
               return -1;          
    }
                    
    CVMX_MT_AES_KEYLENGTH(klen/64 - 1);
    return 0; 	
}

int AES_CCM_set_iv(uint64_t iv1, uint64_t iv2)
{
    CVMX_MT_AES_IV(iv1,0);
    CVMX_MT_AES_IV(iv2,1);
    return 0;	
}

int AES_CCM_init(aes_ccm_ctx *aes_ctx)
{
   uint64_t s0, s1;
   AES_CCM_set_iv(0,0);
   CVMX_MT_AES_ENC_CBC0(aes_ctx->b0high);
   CVMX_MT_AES_ENC_CBC1(aes_ctx->b0low);
   CVMX_MF_AES_RESULT(s0, 0);
   CVMX_MF_AES_RESULT(s1, 1);
   if(!aes_ctx->no_alen){
   	CVMX_MT_AES_ENC_CBC0(aes_ctx->block64_t.val[0]);
   	CVMX_MT_AES_ENC_CBC1(aes_ctx->block64_t.val[1]);
   	CVMX_MF_AES_RESULT(aes_ctx->r0, 0);
   	CVMX_MF_AES_RESULT(aes_ctx->r1, 1);
   }
   else{ /*If there is no Associated data */
	   aes_ctx->r0=s0;
	   aes_ctx->r1=s1;
   }
   CVMX_MT_AES_ENC0(aes_ctx->a0high);
   CVMX_MT_AES_ENC1(aes_ctx->a0low);
   CVMX_MF_AES_RESULT(aes_ctx->s0, 0);
   CVMX_MF_AES_RESULT(aes_ctx->s1, 1);
   return 0;	
}

int
AES_CCM_ctx_encrypt(uint8_t *pin, uint64_t plen,
                uint8_t *ain, uint64_t alen,
                uint8_t *cout, uint8_t *aout, aes_ccm_ctx * aes_ctx)
{
   uint64_t *aptr, *pptr, *cptr;
   int loop = 0;
   uint64_t data0, data1, r0, r1;

	 AES_CCM_set_iv(aes_ctx->r0, aes_ctx->r1);
   if (cvmx_unlikely(!plen)) {
        loop = 1;
   }
   if (cvmx_unlikely(!alen)) {
      aptr = (uint64_t *)pin;
      alen = plen;
      pptr = (uint64_t *)pin;
      cptr = (uint64_t *)cout;
            loop = 1;
      goto no_auth_data;
   }

   aptr = (uint64_t *)ain;
   pptr = (uint64_t *)pin;
   cptr = (uint64_t *)cout;

/*We need to offset alen and aptr by the size of adata written in the first authentication block in AES_CCM_setup_blocks()*/
   alen -= (uint64_t)aes_ctx->offset;
   aptr = (uint64_t *)((uint8_t *)aptr + aes_ctx->offset);

no_auth_data:
   do {
      uint64_t data0, data1;
      while (alen > 16) {
         data0 = aptr[0];
         data1 = aptr[1];
         CVMX_PREFETCH(aptr, 64);
         aptr+=2;

         CVMX_MF_AES_RESULT(aes_ctx->r0, 0);
         CVMX_MF_AES_RESULT(aes_ctx->r1, 1);

         CVMX_MT_AES_ENC_CBC0(data0);
         CVMX_MT_AES_ENC_CBC1(data1);

         alen -= 16;
      }

      /* alen is < 16 */
      if (alen) {
         data0 = 0;
         data1 = 0;
         if (alen > 8) {
            data0 = aptr[0];
            aptr++;
            alen -= 8;
            memcpy(&data1, aptr, alen);
         } else {
            memcpy(&data0, aptr, alen);
         }
         CVMX_MF_AES_RESULT(aes_ctx->r0, 0);
         CVMX_MF_AES_RESULT(aes_ctx->r1, 1);

         CVMX_MT_AES_ENC_CBC0(data0);
         CVMX_MT_AES_ENC_CBC1(data1);
      }
      //CVMX_PREFETCH0(pptr);

      CVMX_MF_AES_RESULT(aes_ctx->r0, 0);
      CVMX_MF_AES_RESULT(aes_ctx->r1, 1);

      aptr = (uint64_t *)pin;
      alen = plen;
      loop++;
   } while(loop < 2);

   /* Encryption (CTR mode) */
   data0 = pptr[0];
   data1 = pptr[1];
   pptr+=2;
   aes_ctx->a0low++;

   if (cvmx_unlikely(!plen)) {
      goto no_encrypt_data;
   }
   CVMX_MT_AES_ENC0(aes_ctx->a0high);
   CVMX_MT_AES_ENC1(aes_ctx->a0low);

   while (plen > 16) {
      aes_ctx->a0low++;
      if (cvmx_unlikely(aes_ctx->a0low == 0)) {
         aes_ctx->a0low--;
         aes_ctx->a0high++;
      }

      CVMX_MF_AES_RESULT(r0, 0);
      CVMX_MF_AES_RESULT(r1, 1);

      CVMX_MT_AES_ENC0(aes_ctx->a0high);
      CVMX_MT_AES_ENC1(aes_ctx->a0low);

      r0 ^= data0;
      r1 ^= data1;
      plen -= 16;

      cptr[0] = r0;
      cptr[1] = r1;
      data0 = pptr[0];
      data1 = pptr[1];
      pptr+=2; 
      cptr+=2;
   }

   if (plen) {
      pptr -= 2;
      data0 = 0;
      data1 = 0;
      if (plen > 8) {
         data0 = pptr[0];
         pptr++;
         memcpy(&data1, pptr, plen - 8);
      } else {
         memcpy(&data0, pptr, plen);
      }
      CVMX_MF_AES_RESULT(r0, 0);
      CVMX_MF_AES_RESULT(r1, 1);
      r0 ^= data0;
      r1 ^= data1;
      if (plen > 8) {
         cptr[0] = r0;
         cptr++;
         memcpy(cptr, &r1, plen - 8);
      } else {
         memcpy(cptr, &r0, plen);
      }
   }
no_encrypt_data:
   r0 = (aes_ctx->r0) ^ (aes_ctx->s0);
   r1 = (aes_ctx->r1) ^ (aes_ctx->s1);
	if (aes_ctx->mac_length > 8) {
		*(uint64_t *)aout = r0;
		memcpy(aout + 8, &r1, aes_ctx->mac_length - 8);
	} else {
		memcpy(aout, &r0, aes_ctx->mac_length);
	}
		return AES_CCM_ENCRYPT_SUCCESS;
}


int
AES_CCM_ctx_decrypt(uint8_t *cin, uint64_t clen,
                uint8_t *ain, uint64_t alen,
                uint8_t *pout, uint8_t *adata, aes_ccm_ctx *aes_ctx)
{
   uint64_t *aptr, *pptr, *cptr;
   int loop = 0;
   uint64_t data0, data1, r0, r1, orig_clen;
	 orig_clen = clen; 
   pptr = (uint64_t *)pout;
   cptr = (uint64_t *)cin;


   /* Encryption (CTR mode) */

   data0 = cptr[0];
   data1 = cptr[1];
   cptr+=2;
   aes_ctx->a0low++;

   if (cvmx_unlikely(!clen)) {
				loop =1;
        goto no_decrypt_data; 
   }
   CVMX_MT_AES_ENC0(aes_ctx->a0high);
   CVMX_MT_AES_ENC1(aes_ctx->a0low);

   while (clen > 16) {
      aes_ctx->a0low++;
      if (cvmx_unlikely(aes_ctx->a0low == 0)) {
         aes_ctx->a0low--;
         aes_ctx->a0high++;
      }

      CVMX_MF_AES_RESULT(r0, 0);
      CVMX_MF_AES_RESULT(r1, 1);

      CVMX_MT_AES_ENC0(aes_ctx->a0high);
      CVMX_MT_AES_ENC1(aes_ctx->a0low);

      r0 ^= data0;
      r1 ^= data1;
      clen -= 16;

      pptr[0] = r0;
      pptr[1] = r1;
      data0 = cptr[0];
      data1 = cptr[1];
      cptr+=2; 
      pptr+=2;
   }

   if (clen) {
      cptr -= 2;
      data0 = 0;
      data1 = 0;
      if (clen > 8) {
         data0 = cptr[0];
         cptr++;
         memcpy(&data1, cptr, clen - 8);
      } else {
         memcpy(&data0, cptr, clen);
      }
      CVMX_MF_AES_RESULT(r0, 0);
      CVMX_MF_AES_RESULT(r1, 1);
      r0 ^= data0;
      r1 ^= data1;
      if (clen > 8) {
         pptr[0] = r0;
         pptr++;
         memcpy(pptr, &r1, clen - 8);
      } else {
         memcpy(pptr, &r0, clen);
      }
   }

   /* Authentication Work */
no_decrypt_data: 
   clen = orig_clen;
	 AES_CCM_set_iv(aes_ctx->r0, aes_ctx->r1);
   if (cvmx_unlikely(!alen)) {
      aptr = (uint64_t *)pout;  /* Now, it contains plain data */
      alen = clen;
      loop = 1;
      goto no_auth_data;
   }

   aptr = (uint64_t *)ain;
   pptr = (uint64_t *)pout;

/*We need to offset alen and aptr by the size of adata written in the first authentication block in AES_CCM_setup_blocks()*/
   alen -= (uint64_t)aes_ctx->offset;
   aptr = (uint64_t *)((uint8_t *)aptr + aes_ctx->offset);

no_auth_data:
   do {
      uint64_t data0, data1;
      while (alen > 16) {
         data0 = aptr[0];
         data1 = aptr[1];
         CVMX_PREFETCH(aptr, 64);
         aptr+=2;

         CVMX_MF_AES_RESULT(aes_ctx->r0, 0);
         CVMX_MF_AES_RESULT(aes_ctx->r1, 1);

         CVMX_MT_AES_ENC_CBC0(data0);
         CVMX_MT_AES_ENC_CBC1(data1);

         alen -= 16;
      }

      /* alen is <= 16 */
      if (alen) {
         data0 = 0;
         data1 = 0;
         if (alen > 8) {
            data0 = aptr[0];
            aptr++;
            alen -= 8;
            memcpy(&data1, aptr, alen);
         } else {
            memcpy(&data0, aptr, alen);
         }
         CVMX_MF_AES_RESULT(aes_ctx->r0, 0);
         CVMX_MF_AES_RESULT(aes_ctx->r1, 1);

         CVMX_MT_AES_ENC_CBC0(data0);
         CVMX_MT_AES_ENC_CBC1(data1);
      }
      //CVMX_PREFETCH0(cptr);

      CVMX_MF_AES_RESULT(aes_ctx->r0, 0);
      CVMX_MF_AES_RESULT(aes_ctx->r1, 1);

      aptr = (uint64_t *)pout;
      alen = clen;
      loop++;
   } while(loop < 2);

	r0 = aes_ctx->s0 ^ aes_ctx->r0;
	r1 = aes_ctx->s1 ^ aes_ctx->r1;
	if (aes_ctx->mac_length > 8) {
		if (r0 != *(uint64_t *)adata) {
			return AES_CCM_AUTH_CHECK_FAILED;
		}
		if (memcmp(&r1, (adata + 8), (aes_ctx->mac_length - 8)))
			return AES_CCM_AUTH_CHECK_FAILED;
		return AES_CCM_DECRYPT_SUCCESS;
	}
	if (memcmp(&r0, adata, aes_ctx->mac_length))
			return AES_CCM_AUTH_CHECK_FAILED;
	
	return AES_CCM_DECRYPT_SUCCESS;
}


int AES_CCM_encrypt (uint8_t m, uint8_t l, uint8_t *nonce, uint8_t * key, uint32_t keylen, uint8_t * pin, uint64_t plen, uint8_t * ain,
    uint64_t alen, uint8_t * out, uint8_t * auth)
{
	aes_ccm_ctx aes_ctx;
	int ret_block = 0;
	ret_block = AES_CCM_setup_blocks(m, l, ain, alen, plen,	(uint64_t *)nonce, &aes_ctx);	
    if(ret_block) {
			printf("AES_CCM_SETUP_BLOCKS FAILED:\n");
	return ret_block;
	}
 	AES_CCM_set_key((uint64_t *)key, keylen);
 	AES_CCM_init(&aes_ctx);

	AES_CCM_ctx_encrypt(pin, plen, ain,  alen, out, auth, &aes_ctx);
	return AES_CCM_ENCRYPT_SUCCESS;
}

int AES_CCM_decrypt (uint8_t m, uint8_t l, uint8_t* nonce, uint8_t * key, uint32_t keylen, uint8_t * cin, uint64_t plen, uint8_t * ain,
    uint64_t alen, uint8_t * out, uint8_t * auth)
{
	aes_ccm_ctx aes_ctx;
	int ret_block = 0;
	ret_block = AES_CCM_setup_blocks(m, l, ain, alen, plen,	(uint64_t *)nonce, &aes_ctx);	
  if(ret_block) {
			printf("AES_CCM_SETUP_BLOCKS FAILED:\n");
			return ret_block;
	}
 	AES_CCM_set_key((uint64_t *)key, keylen);
 	AES_CCM_init(&aes_ctx);

	ret_block = AES_CCM_ctx_decrypt(cin, plen, ain,  alen, out, auth, &aes_ctx);
  if(ret_block) {
		printf(" AES_CCM_decrypt failed :\n");
		return ret_block;
	}
	return AES_CCM_DECRYPT_SUCCESS;
}
