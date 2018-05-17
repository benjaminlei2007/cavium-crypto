
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


enum {
FECC_POINT_ADDITION=1,
FECC_POINT_DOUBLE,
FECC_POINT_MULTIPLY
};

#define ROUNDUP8(val) (((val) + 7)&0xfffffff8)


#define FECC_PRIME_CURVE_192           0
#define FECC_PRIME_CURVE_224           1
#define FECC_PRIME_CURVE_256           2
#define FECC_PRIME_CURVE_384           3
#define FECC_PRIME_CURVE_521           4


#define FECC_PRIME_CURVE_MAX_LEN       256
#define FECC_PRIME_CURVE_192_LEN       24
#define FECC_PRIME_CURVE_224_LEN       28
#define FECC_PRIME_CURVE_256_LEN       32
#define FECC_PRIME_CURVE_384_LEN       48
#define FECC_PRIME_CURVE_521_LEN       66

void strtohex(char *str, unsigned char *hex, uint16_t *len)
{
  uint8_t h[3];
  int i,j;

  /* remove newline */
  *len = strlen((const char *)str);
  *len = ((*len)>>1);

  for(i=0, j=0; i<*len; i++) {
    h[0] = str[j++];
    h[1] = str[j++];
    hex[i] = (char) strtoul((const char *)h, NULL, 16);
  }
}

struct point_add {
	unsigned int prim; //prime
	 char *x1; //X1 co-ordinate
	 char *y1; //Y1 co-ordinate
	 char *x2; //X2 co-ordinate
	 char *y2; //Y2 co-ordinate
	 char *exp; // expected output generated from OpenSSL
};

struct point_dbl {
	unsigned int prim; // prime
	char *x1; // X1 co-ordinate
	char *y1; // Y1 co-ordinate
	char *exp; // expected output generated from OpenSSL
};

struct point_mul {
	unsigned int prim; //prime
	char *x1; // X1 co-ordinate
	char *y1; // Y1 co-ordinate
	char *k; // scalar
	char *exp; // expected output generated from OpenSSL
};


const struct point_dbl dbl [] = {
	{
	192,
	"d458e7d127ae671b0c330266d246769353a012073e97acf8",
	"325930500d851f336bddc050cf7fb11b5673a1645086df3b",
	"30C5BC6B8C7DA25354B373DC14DD8A0EBA42D25A3F6E69620DDE14BC4249A721C407AEDBF011E2DDBBCB2968C9D889CF"
	},
	{
	224,
	"b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
	"bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
	"706A46DC76DCB76798E60E6D89474788D16DC18032D268FD1A704FA6000000001C2B76A7BC25E7702A704FA986892849FCA629487ACF3709D2E4E8BB00000000"
	},
	{
	256,
	"de2444bebc8d36e682edd27e0f271508617519b3221a8fa0b77cab3989da97c9",
	"c093ae7ff36e5380fc01a5aad1e66659702de80f53cec576b6350b243042a256",
	"7669E6901606EE3BA1A8EEF1E0024C33DF6C22F3B17481B82A860FFCDB6127B0FA878162187A54F6C39F6EE0072F33DE389EF3EECD03023DE10CA2C1DB61D0C7"
	},
	{
	384,
	"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f92385dda82768ada415ebab4167459da98e62b1332d1e73cb0e",
	"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45",
	"2A2111B1E0AA8B2FC5A1975516BC4D58017FF96B25E1BDFF3C229D5FAC3BACC319DCBEC29F9478F42DEE597B4641504CFA2E3D9DC84DB8954CE8085EF28D7184FDDFD1344B4D4797343AF9B5F9D837520B450F726443E4114BD4E5BDB2F65DDD"
	},
	{
	521,
	"00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
	"011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
	"433C219024277E7E682FCB288148C282747403279B1CCC06352C6E5505D769BE97B3B204DA6EF55507AA104A3A35C5AF41CF2FA364D60FD967F43E3933BA6D783D00000000000000F4BB8CC7F86DB26700A7F3ECEEEED3F0B5C6B5107C4DA97740AB21A29906C42DBBB3E377DE9F251F6B93937FA99A3248F4EAFCBE95EDC0F4F71BE356D661F41B02000000000000"
	},
};
const struct point_mul mul [] = {
	{
	192,
	"d458e7d127ae671b0c330266d246769353a012073e97acf8",
	"325930500d851f336bddc050cf7fb11b5673a1645086df3b",
	"a1",
	"6D71EBE874F65ABE09FBE5D1E1C13933AD5D16E95212600083EE12804FD169AEBD3D02B4ABF0A7BF974E46D5B7CF49B8"
	},
	{
	224,
	"B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
	"BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
	"01",
	"B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D2100000000BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E3400000000"
	},
	{
	256,
	"71ae5dc38ef5ff89563b411bed56a87b249d3968400867d7f5f2026dfd4fe3b6",
	"924add1c339ea881a0f3e98deb7a301769b1cc1f0c7362383bc86b2834368cc7",
	"a3",
	"50D701D687247E728312968A8A66FA2AE7A67ACE6804A070DAF11B644283F3AED35FF5ACE024ED6DD699BCA354D0509DB5FC3DE12A45B0AC018164E620F17A1F"
	},
	{
	384,
	"281d1debe960d8fcf3316f5c93f15595e346115d969a773f35145b4b2c604f976cf2e3351a9434de2f45423be75dbd72",
	"8bfcca7a15dc461a9b896c91023fb3c4338e6227da723cd77e00781e0beeb51f484a379bdd6edb07799c46b2fbe70802",
	"a3",
	"082B849AAB5B5891CC71682D7937B92D7155E8DE40492A132274A7FC0A1EE2D9D2090494AD3CD40EB84A7C05679D52AAC5B287EE79BA59BC819B177E91875309A5C874188A21DDF538981AD6602BE77CA1DEF7B9928FB0EB3B22329AD6FA1CAA"

	},
	{
	521,
	"00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
	"011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
	"01",
	"C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66000000000000011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650000000000000"
	}
};

const struct point_add arr [] = {
	{
	192,
	"d458e7d127ae671b0c330266d246769353a012073e97acf8",
	"325930500d851f336bddc050cf7fb11b5673a1645086df3b",
	"f22c4395213e9ebe67ddecdd87fdbd01be16fb059b9753a4",
	"264424096af2b3597796db48f8dfb41fa9cecc97691a9c79",
	"48E1E4096B9B8E5CA9D0F1F077B8ABF58E843894DE4D0290408FA77C797CD7DBFB16AA48A3648D3D63C94117D7B6AA4B"
	},
	{
	224,
	"b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
	"bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
	"236f26d9e84c2f7d776b107bd478ee0a6d2bcfcaa2162afae8d2fd15",
	"e53cc0a7904ce6c3746f6a97471297a0b7d5cdf8d536ae25bb0fda70",
	"50CF20A89E167CF5A5AADB86DDD0289BE3100A72B74976B132C2E1A100000000768C0D0346C25DEE83CB0130CCB935F132E37975EA743492F9283C3B"
	},
	{
	256,
	"de2444bebc8d36e682edd27e0f271508617519b3221a8fa0b77cab3989da97c9",
	"c093ae7ff36e5380fc01a5aad1e66659702de80f53cec576b6350b243042a256",
	"55a8b00f8da1d44e62f6b3b25316212e39540dc861c89575bb8cf92e35e0986b",
	"5421c3209c2d6c704835d82ac4c3dd90f61a8a52598b9e7ab656e9d8c8b24316",
	"72B13DD4354B6B81745195E98CC5BA6970349191AC476BD4553CF35A545A067E8D585CBB2E1327D75241A8A122D7620DC33B13315AA5C9D46D013011744AC264"
	},
	{
	384,
	"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f92385dda82768ada415ebab4167459da98e62b1332d1e73cb0e",
	"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45",
	"aacc05202e7fda6fc73d82f0a66220527da8117ee8f8330ead7d20ee6f255f582d8bd38c5a7f2b40bcdb68ba13d81051",
	"84009a263fefba7c2c57cffa5db3634d286131afc0fca8d25afa22a7b5dce0d9470da89233cee178592f49b6fecb5092",
	"12DC5CE7ACDFC5844D939F40B4DF012E68F865B89C3213BA97090A247A2FC009075CF471CD2E85C489979B65EE0B5EED167312E58FE0C0AFA248F2854E3CDDCB557F983B3189B67F21EEE01341E7E9FE67F6EE81B36988EFA406945C8804A4B0"
	},
	{
	521,
	"00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
	"011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
	"00433C219024277E7E682FCB288148C282747403279B1CCC06352C6E5505D769BE97B3B204DA6EF55507AA104A3A35C5AF41CF2FA364D60FD967F43E3933BA6D783D",
	"00F4BB8CC7F86DB26700A7F3ECEEEED3F0B5C6B5107C4DA97740AB21A29906C42DBBB3E377DE9F251F6B93937FA99A3248F4EAFCBE95EDC0F4F71BE356D661F41B02",
	"01A73D352443DE29195DD91D6A64B5959479B52A6E5B123D9AB9E5AD7A112D7A8DD1AD3F164A3A4832051DA6BD16B59FE21BAEB490862C32EA05A5919D2EDE37AD7D000000000000013E9B03B97DFA62DDD9979F86C6CAB814F2F1557FA82A9D0317D2F8AB1FA355CEEC2E2DD4CF8DC575B02D5ACED1DEC3C70CF105C9BC93A590425F588CA1EE86C0E5000000000000"
	}
};

  unsigned char const_prime_192[24] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };
  unsigned char const_prime_224[28+4] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
    };
  unsigned char const_prime_256[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };
  unsigned char const_prime_384[48] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
    };
  unsigned char const_prime_521[66+6] = {
    0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00};


  const char *const_p192_a = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC";
  const char *const_p192_b = "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1";
  /* actual test vector has 28B ONLY but our implementation is 8B aligned so considering 32bytes */
  const char *const_p224_a = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE";
  const char *const_p224_b = "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4";
  const char *const_p256_a = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC";
  const char *const_p256_b = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
  const char *const_p384_a = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC";
  const char *const_p384_b = "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF";
  /* actual test vector has 68B ONLY but our implementation is 8B aligned so considering 72bytes */
  const char *const_p521_a = "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC";
  const char *const_p521_b = "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00";


