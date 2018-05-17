
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


#define ERR(fmt, args...)     printf("ERROR: " fmt "\n", ##args)

#ifdef TEST_CPU_CYCLES
	static uint64_t start_cycle = 0;
	static uint64_t end_cycle = 0;
	static uint64_t cpucycles, tps;
	static int iter;
	unsigned int core;
	cvmx_sysinfo_t *sysinfo;
#endif 

#ifdef TEST_CPU_CYCLES
	#define START_CYCLE  \
		start_cycle = end_cycle = 0;  \
 		sysinfo = cvmx_sysinfo_get();\
		start_cycle = cvmx_clock_get_count (CVMX_CLOCK_CORE); \
		for (iter = 0; iter < MAX_ITERATIONS; iter++) {  
		
	#define END_CYCLE(str)  \
		} \
		end_cycle = cvmx_clock_get_count (CVMX_CLOCK_CORE); \
	 	cpucycles = (long)(end_cycle - start_cycle)/MAX_ITERATIONS; \
		tps = cpufreq * 1000000 / cpucycles; \
 		for (core = 0; core < CVMX_MAX_CORES; core++) {\
			if (cvmx_coremask_is_core_set(&sysinfo->core_mask, core) && core == cvmx_get_core_num()){ \
				total_cpucycles+=cpucycles;\
				total_tps +=tps;\
			}\
			cvmx_coremask_barrier_sync(&sysinfo->core_mask);\
		}\
		cvmx_coremask_barrier_sync(&sysinfo->core_mask);\
		if(cvmx_is_init_core()){\
 			printf ("API :%-20s total tps :%-10lu average values per core    cpucycles :%lu tps :%lu\n", str, total_tps, (total_cpucycles/numcores), (total_tps/numcores));\
			total_cpucycles = 0;\
			total_tps = 0;\
		}
#else
	#define START_CYCLE
	#define END_CYCLE(str)
#endif

#ifdef TEST_CPU_CYCLES
	char *curve_name;
	#define PRINT_HDR \
		if (cvmx_is_init_core()) { \
			if (nid == NID_X9_62_prime256v1)\
				curve_name = "NID_X9_62_prime256v1";\
			else if (nid == NID_secp384r1)\
				curve_name = "NID_secp384r1";\
			else if (nid == NID_secp521r1)\
				curve_name = "NID_secp521r1";\
			printf ("\n\n#############################################################\n"); \
        	printf ("           Prime Curve %s \n",curve_name); \
        	printf ("#############################################################\n"); \
		}
#else
    #define PRINT_HDR
#endif

void dump(const char *msg, unsigned char *buf, unsigned int len)
{
	 unsigned int i;

	 if (!buf || !len) return;

	 printf("%s(%u):\n", msg, len);
	 for (i = 0; i < len; i++) {
		  printf("%02x%c", buf[i], (i + 1) % 8 ? ' ' : '\n');
	 }

	 if (i % 8) printf("\n");
}


/**
 * Equation followed here for elliptical curve is
 *
 * y^2 = x^3 + a.x + b
 *
 * q = order of the elliptical curve.
 * P = prime modulus
 * g = generator; g = (gx, gy)
 *
 * w = static private key
 * g^w = static public key; g^w = (gwx, gwy)
 * k = random integer (0, q) and ephemeral private key
 *
 * ephemeral public key g^k = (gkx, gky)
 *
 * k * kinv = 1 mod q
 *
 */

struct ecdsa_rfc4754_vectors {
	int nid;
	char *name;
	int curve_len;
	const char  *p,
				*a,
				*b,
				*Gx,
				*Gy,
				*order,
				*w,
				*k,
				*kinv,
				*r,
				*s,
				*gwx,
				*gwy;
};

#define ARRAY_ELEMENTS(a) (sizeof(a)/sizeof(a[0]))

/**
 * Contents taken from 
 * http://www.ietf.org/rfc/rfc4754.txt
 */
static const struct ecdsa_rfc4754_vectors rfc[] = {
	 { /* P-256 */
		//NID_X9_62_prime256v1,
		NID_secp256k1,
		"X9.62/SECG curve over a 256 bit prime field",
		256,
		"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", /* p */
		"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", /* a */
		"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", /* b */
		"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", /* Gx */
		"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", /* Gy */
		"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", /* order */
		"DC51D3866A15BACDE33D96F992FCA99DA7E6EF0934E7097559C27F1614C88A7F", /* w */
		"9E56F509196784D963D1C0A401510EE7ADA3DCC5DEE04B154BF61AF1D5A6DECE", /* k */
		"AFA278945AF74B1E295008E03A8984E2E1C69D9BBBC74AF14E3AC4E421ABFA61", /* kinv */
		"CB28E0999B9C7715FD0A80D8E47A77079716CBBF917DD72E97566EA1C066957C", /* r */
		"86FA3BB4E26CAD5BF90B7F81899256CE7594BB1EA0C89212748BFF3B3D5B0315", /* s */
		"2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E970", /* gwx */
		"6FC98BD7E50211A4A27102FA3549DF79EBCB4BF246B80945CDDFE7D509BBFD7D" /* gwy */
	 },
	 {	/* P-384 */
		NID_secp384r1,
		"NIST/SECG curve over a 384 bit prime field",
		384,
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", /* p */
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", /* a */
		"B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", /* b */
		"AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", /* gx */
		"3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", /* gy */
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", /* order akaq */
		"0BEB646634BA87735D77AE4809A0EBEA865535DE4C1E1DCB692E84708E81A5AF62E528C38B2A81B35309668D73524D9F", /* w */
		"B4B74E44D71A13D568003D7489908D564C7761E229C58CBFA18950096EB7463B854D7FA992F934D927376285E63414FA", /* k */
		"EB12876BF6191A291AA5780A3887C3BFE7A5C7E321CCA674886B1228D9BB3D52918EF19FE5CE67E980BEDC1E613D39C0", /* kinv */
		"FB017B914E29149432D8BAC29A514640B46F53DDAB2C69948084E2930F1C8F7E08E07C9C63F2D21A07DCB56A6AF56EB3", /* r */
		"B263A1305E057F984D38726A1B46874109F417BCA112674C528262A40A629AF1CBB9F516CE0FA7D2FF630863A00E8B9F", /* s */
		"96281BF8DD5E0525CA049C048D345D3082968D10FEDF5C5ACA0C64E6465A97EA5CE10C9DFEC21797415710721F437922", /* gwx */
			"447688BA94708EB6E2E4D59F6AB6D7EDFF9301D249FE49C33096655F5D502FAD3D383B91C5E7EDAA2B714CC99D5743CA" /* gwy */
	 },
	 {	/* P-521 */
		NID_secp521r1,
		"NIST/SECG curve over a 521 bit prime field",
		521,
		"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", /* p */
		"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", /* a */
		"0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", /* b */
		"00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", /* Gx */
		"011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", /* Gy */
		"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", /* order */
		"0065FDA3409451DCAB0A0EAD45495112A3D813C17BFD34BDF8C1209D7DF5849120597779060A7FF9D704ADF78B570FFAD6F062E95C7E0C5D5481C5B153B48B375FA1", /* w */
		"00C1C2B305419F5A41344D7E4359933D734096F556197A9B244342B8B62F46F9373778F9DE6B6497B1EF825FF24F42F9B4A4BD7382CFC3378A540B1B7F0C1B956C2F", /* k */
		"00E90EF3CE52F8D1E5A4EEBD0905F4252400B0AE73B49E3323BCE258A55F507D7C45F3A2DE3A3EA2E51D934346D71593A80C8C62FE229DDF5D2B64B7AF4A08370D32", /* kinv */
		"0154FD3836AF92D0DCA57DD5341D3053988534FDE8318FC6AAAAB68E2E6F4339B19F2F281A7E0B22C269D93CF8794A9278880ED7DBB8D9362CAEACEE544320552251", /* r */
		"017705A7030290D1CEB605A9A1BB03FF9CDD521E87A696EC926C8C10C8362DF4975367101F67D1CF9BCCBF2F3D239534FA509E70AAC851AE01AAC68D62F866472660", /* s */
		"0151518F1AF0F563517EDD5485190DF95A4BF57B5CBA4CF2A9A3F6474725A35F7AFE0A6DDEB8BEDBCD6A197E592D40188901CECD650699C9B5E456AEA5ADD19052A8", /* gwx */
		"006F3B142EA1BFFF7E2837AD44C9E4FF6D2D34C73184BBAD90026DD5E6E85317D9DF45CAD7803C6C20035B2F3FF63AFF4E1BA64D1C077577DA3F4286C58F0AEAE643" /* gwy */
	 }
};

 struct curve_params {
		int nid, curve_len;
		unsigned char h[128]; /* digest */
		unsigned int hlen;	 /* digestlen */
	} ecdsa_param[] = {
		{
				NID_X9_62_prime256v1,
				256,
				{
					0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
					0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
					0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
					0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
				},
				32
		},
		{
				NID_secp384r1,
				384,
				{
					0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 
					0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07, 
					0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 
					0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 
					0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 
					0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7, 
				},
				48
		},
		{
				NID_secp521r1,
				521,
				{
					 0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 
					 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31, 
					 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 
					 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 
					 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 
					 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 
					 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 
					 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f 
				},
				64
		  }
	};

