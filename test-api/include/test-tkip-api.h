
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
#define TEST_ALL

int test_tkip_michael();
int  test_tkip_mixing();
int test_tkip();

#define NUM_VECTORS 8


/* Note that these test vectors are those given in IEEE 802.11 document
 * dated 12th june 2007
 */

	uint8_t temporal_key[NUM_VECTORS][16] = {
		{0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf},
		{0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf},
		{0x63,0x89,0x3b,0x25,0x08,0x40,0xb8,0xae,0x0b,0xd0,0xfa,0x7e,0x61,0xd2,0x78,0x3e},
		{0x63,0x89,0x3B,0x25,0x08,0x40,0xB8,0xAE,0x0B,0xD0,0xFA,0x7E,0x61,0xD2,0x78,0x3E},
		{0x98,0x3A,0x16,0xEF,0x4F,0xAC,0xB3,0x51,0xAA,0x9E,0xCC,0x27,0x1D,0x73,0x09,0xE2},
		{0x98,0x3A,0x16,0xEF,0x4F,0xAC,0xB3,0x51,0xAA,0x9E,0xCC,0x27,0x1D,0x73,0x09,0xE2},
		{0xC8,0xAD,0xC1,0x6A,0x8B,0x4D,0xDA,0x3B,0x4D,0xD5,0xB6,0x54,0x38,0x35,0x9B,0x05},
		{0xC8,0xAD,0xC1,0x6A,0x8B,0x4D,0xDA,0x3B,0x4D,0xD5,0xB6,0x54,0x38,0x35,0x9B,0x05}
	}; 
	uint8_t transmitter_mac[NUM_VECTORS][6] = {
		{0x10,0x22,0x33,0x44,0x55,0x66},
		{0x10,0x22,0x33,0x44,0x55,0x66},
		{0x64,0xf2,0xea,0xed,0xdc,0x25},
		{0x64,0xf2,0xEA,0xed,0xdc,0x25},
		{0x50,0x9c,0x4b,0x17,0x27,0xd9},
		{0x50,0x9c,0x4b,0x17,0x27,0xd9},
		{0x94,0x5E,0x24,0x4E,0x4D,0x6E},
		{0x94,0x5E,0x24,0x4E,0x4D,0x6E}
	};
	uint8_t rc4key [NUM_VECTORS][16];
	uint8_t expected_rc4key [NUM_VECTORS][16] = {
		{0x00,0x20,0x00,0x33,0xEA,0x8D,0x2F,0x60,0xCA,0x6D,0x13,0x74,0x23,0x4A,0x66,0x0B},
		{0x00,0x20,0x01,0x90,0xFF,0xDC,0x31,0x43,0x89,0xA9,0xD9,0xD0,0x74,0xFD,0x20,0xAA},
		{0xFF,0x7F,0xFF,0x93,0x81,0x0F,0xC6,0xE5,0x8F,0x5D,0xD3,0x26,0x25,0x15,0x44,0xCE},
		{0x00,0x20,0x00,0x49,0x8C,0xA4,0x71,0xFC,0xFB,0xFA,0xA1,0x6E,0x36,0x10,0xF0,0x05},
		{0x05,0x25,0x8C,0xF4,0xD8,0x51,0x52,0xF4,0xD9,0xAF,0x1A,0x64,0xF1,0xD0,0x70,0x21},
		{0x05,0x25, 0x8D, 0x09, 0xF8, 0x15,0x43,0xB7,0x6A,0x59,0x6F,0xC2,0xC6,0x73,0x8B,0x30},
		{0x30,0x30,0xF8,0x65,0x0D,0xA0,0x73,0xEA,0x61,0x4E,0xA8,0xF4,0x74,0xEE,0x03,0x19},
		{0x30,0x30,0xF9,0x31,0x55,0xCE,0x29,0x34,0x37,0xCC,0x76,0x71,0x27,0x16,0xAB,0x8F}
	};

#define CHECK_RET(str) \
			if (ret != 0 ) \
			printf ("Result of %-15s : %s\n", str, "Fail"); \

