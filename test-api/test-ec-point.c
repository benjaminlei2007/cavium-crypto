
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


/*
 * test_crypto_fecc.c
 */

#include <ctype.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <test-ec-point.h>

int test_point_multiply_kat () {
	uint8_t *scalar=NULL;
	uint8_t *sw_scalar=NULL;
	uint16_t scalar_length=0;

	uint8_t *prime = NULL;
	uint16_t prime_length=0;
	int byte_count=0, fail = 0;
	unsigned int i=0;
	uint32_t ret_val=0;
	unsigned char * input = NULL;
	uint16_t len= 0;
	uint8_t *out = NULL;

	EC_POINT *P = NULL;
	EC_POINT *Q = NULL;
	EC_POINT *R = NULL;
	EC_GROUP *group = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *p   = NULL, *a  = NULL, *b = NULL;
	BIGNUM *px  = NULL, *py = NULL;
	BIGNUM *e = NULL,*k = NULL;

for (i=0;i < sizeof(mul)/sizeof(mul[0]);i++) {

	scalar = calloc(FECC_PRIME_CURVE_MAX_LEN, sizeof(uint8_t));
	if(scalar == NULL) {
		printf("Unable to allocate memory for scalar\n");
	}

	sw_scalar = calloc(FECC_PRIME_CURVE_MAX_LEN, sizeof(uint8_t));
	if(sw_scalar == NULL) {
		printf("Unable to allocate memory for sw_scalar\n");
	}

	prime = calloc(FECC_PRIME_CURVE_MAX_LEN, sizeof(uint8_t));
	if(prime == NULL) {
		printf("Unable to allocate memory for prime\n");
	}

	input = calloc(FECC_PRIME_CURVE_MAX_LEN, sizeof(char));
	if(input == NULL) {
		printf("Unable to allocate memory for read_line\n");
	}
	out = calloc(2*FECC_PRIME_CURVE_MAX_LEN, sizeof(uint8_t));
	if(out == NULL) {
		printf("Unable to allocate memory for out\n");
	}

		if(mul[i].prim == 192) {
			prime_length = FECC_PRIME_CURVE_192_LEN;
			memcpy(prime, const_prime_192, prime_length);
		} else if(mul[i].prim == 224) {
			prime_length = FECC_PRIME_CURVE_224_LEN;
			memcpy(prime, const_prime_224, prime_length);
		} else if(mul[i].prim == 256) {
			prime_length = FECC_PRIME_CURVE_256_LEN;
			memcpy(prime, const_prime_256, prime_length);
		} else if(mul[i].prim == 384) {
			prime_length = FECC_PRIME_CURVE_384_LEN;
			memcpy(prime, const_prime_384, prime_length);
		} else if(mul[i].prim == 521) {
			prime_length = FECC_PRIME_CURVE_521_LEN;
			memcpy(prime, const_prime_521, prime_length);
		} 


	/* allocate memory for big numbers */
	p	 = BN_new();
	px  = BN_new();
	py  = BN_new();
	a   = BN_new();
	b   = BN_new();
	ctx = BN_CTX_new();

  /* set curve constants */
	if(prime_length == FECC_PRIME_CURVE_192_LEN) {
		if(!BN_hex2bn(&a, const_p192_a)) goto End;
		if(!BN_hex2bn(&b, const_p192_b)) goto End;
	} else if(prime_length == FECC_PRIME_CURVE_224_LEN) {
		if(!BN_hex2bn(&a, const_p224_a)) goto End;
		if(!BN_hex2bn(&b, const_p224_b)) goto End;
	} else if(prime_length == FECC_PRIME_CURVE_256_LEN) {
		if(!BN_hex2bn(&a, const_p256_a)) goto End;
		if(!BN_hex2bn(&b, const_p256_b)) goto End;
	} else if(prime_length == FECC_PRIME_CURVE_384_LEN) {
		if(!BN_hex2bn(&a, const_p384_a)) goto End;
		if(!BN_hex2bn(&b, const_p384_b)) goto End;
	} else if(prime_length == FECC_PRIME_CURVE_521_LEN) {
		if(!BN_hex2bn(&a, const_p521_a)) goto End;
		if(!BN_hex2bn(&b, const_p521_b)) goto End;
	} 
 
	/* prime --> bn_prime */
	p = BN_bin2bn(prime, prime_length, p); 

	/* create group of type montgomery */
	group = EC_GROUP_new(EC_GFp_fecc_method());
	if(!group) goto End;

	/* set group to the prime curve with constants a, b */
	if(!EC_GROUP_set_curve_GFp(group, p, a, b, ctx)) goto End;

	/* allocate memory for input point P,Q and output R */
	P = EC_POINT_new(group);
	Q = EC_POINT_new(group);
	R = EC_POINT_new(group);
	if (!P||!Q||!R) goto End;
	/* convert inputx to bn_px */
	strtohex(mul[i].x1, input, &len);
	px = BN_bin2bn(input, prime_length, px);
	/* convert inputy to bn_py */
	strtohex(mul[i].y1, input, &len);
	py = BN_bin2bn(input, prime_length, py);
	/* set P <-- (px, py) */
	if(!EC_POINT_set_affine_coordinates_GFp(group, P, px, py, ctx)) 
		goto End;

		memset(input, 0, FECC_PRIME_CURVE_MAX_LEN);
		strtohex(mul[i].k, input, &len);
		scalar_length = len;
		len = ROUNDUP8(scalar_length);
		memcpy(sw_scalar, input, len);
		/* convert scalar to bn_scalar */
		k = BN_bin2bn(sw_scalar, scalar_length, k);
		/* do point multiplication */
		if(!EC_POINT_mul(group, R, NULL, P, k, ctx))
			goto End;

	/* capture result (px, py) <--- R */
	EC_POINT_get_affine_coordinates_GFp(group, R, px, py, ctx);

	/* convert bn_px to p3 */

	byte_count = BN_bn2bin(px, out);
	if (byte_count < prime_length) {
		 memmove(out+prime_length-byte_count, out,byte_count);
		 memset(out,0,prime_length-byte_count);
	}
	/* convert bn_py to p3 */
	byte_count = BN_bn2bin(py, out+ROUNDUP8(prime_length));
	if (byte_count < prime_length) {
		 memmove(out+ROUNDUP8(prime_length)+prime_length-byte_count, out+ROUNDUP8(prime_length),byte_count);
		 memset(out+ROUNDUP8(prime_length),0,prime_length-byte_count);
	}
	e= BN_bin2bn(out,2*ROUNDUP8(prime_length),e);
	if(memcmp(mul[i].exp, BN_bn2hex (e), 2*ROUNDUP8(prime_length))) {
		printf("FECC compare FAILED for prime P-%d\n",mul[i].prim);
		printf("Expect :%s\n",mul[i].exp);
		printf("Actual :%s\n",BN_bn2hex (e));
		fail++;
	}

End:
	/* free allocated memory */
	if(p) BN_free(p);
	if(px)BN_free(px);
	if(py)BN_free(py);
	if(a) BN_free(a);
	if(b) BN_free(b);
	if(prime) free(prime);
	if(input) free(input);
	if(scalar) free(scalar);
	if(sw_scalar) free(sw_scalar);
	if(out) free(out);
	if(ctx) BN_CTX_free(ctx);
	if(group) EC_GROUP_free(group);
	if(P) EC_POINT_free(P);
	if(R) EC_POINT_free(R);
}
	if (fail)
		printf("***");
	 if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested:  %d passed : %d failed : %d\n","POINT-MULTIPLY",i,(i-fail),fail);
	return ret_val;
}


int test_point_double_kat () {

	uint8_t *prime = NULL;
	uint16_t prime_length=0;
	int byte_count=0, fail = 0;
	uint32_t ret_val=0;
	unsigned int i=0;
	unsigned char * input = NULL;
	uint16_t len= 0;
	uint8_t *out = NULL;

	EC_POINT *P = NULL;
	EC_POINT *Q = NULL;
	EC_POINT *R = NULL;
	EC_GROUP *group = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *p = NULL, *a= NULL, *b = NULL;
	BIGNUM *px= NULL, *py = NULL;
	BIGNUM *e = NULL;

for (i=0;i < sizeof(dbl)/sizeof(dbl[0]);i++) {

	prime = calloc(FECC_PRIME_CURVE_MAX_LEN, sizeof(uint8_t));
	if(prime == NULL) {
		printf("Unable to allocate memory for prime\n");
	}

	input = calloc(FECC_PRIME_CURVE_MAX_LEN, sizeof(char));
	if(input == NULL) {
		printf("Unable to allocate memory for read_line\n");
	}
	out = calloc(2*FECC_PRIME_CURVE_MAX_LEN, sizeof(uint8_t));
	if(out == NULL) {
		printf("Unable to allocate memory for out\n");
	}

		if(dbl[i].prim == 192) {
			prime_length = FECC_PRIME_CURVE_192_LEN;
			memcpy(prime, const_prime_192, prime_length);
		} else if(dbl[i].prim == 224) {
			prime_length = FECC_PRIME_CURVE_224_LEN;
			memcpy(prime, const_prime_224, prime_length);
		} else if(dbl[i].prim == 256) {
			prime_length = FECC_PRIME_CURVE_256_LEN;
			memcpy(prime, const_prime_256, prime_length);
		} else if(dbl[i].prim == 384) {
			prime_length = FECC_PRIME_CURVE_384_LEN;
			memcpy(prime, const_prime_384, prime_length);
		} else if(dbl[i].prim == 521) {
			prime_length = FECC_PRIME_CURVE_521_LEN;
			memcpy(prime, const_prime_521, prime_length);
		} 

	/* allocate memory for big numbers */
	p = BN_new();
	px= BN_new();
	py= BN_new();
	a = BN_new();
	b = BN_new();
	ctx = BN_CTX_new();

	/* set curve constants */
	if(prime_length == FECC_PRIME_CURVE_192_LEN) {
		if(!BN_hex2bn(&a, const_p192_a)) goto End;
		if(!BN_hex2bn(&b, const_p192_b)) goto End;
	} else if(prime_length == FECC_PRIME_CURVE_224_LEN) {
		if(!BN_hex2bn(&a, const_p224_a)) goto End;
		if(!BN_hex2bn(&b, const_p224_b)) goto End;
	} else if(prime_length == FECC_PRIME_CURVE_256_LEN) {
		if(!BN_hex2bn(&a, const_p256_a)) goto End;
		if(!BN_hex2bn(&b, const_p256_b)) goto End;
	} else if(prime_length == FECC_PRIME_CURVE_384_LEN) {
		if(!BN_hex2bn(&a, const_p384_a)) goto End;
		if(!BN_hex2bn(&b, const_p384_b)) goto End;
	} else if(prime_length == FECC_PRIME_CURVE_521_LEN) {
		if(!BN_hex2bn(&a, const_p521_a)) goto End;
		if(!BN_hex2bn(&b, const_p521_b)) goto End;
	} 
 
	/* prime --> bn_prime */
	p = BN_bin2bn(prime, prime_length, p); 

	/* create group of type montgomery */
	group = EC_GROUP_new(EC_GFp_fecc_method());
	if(!group) goto End;

	/* set group to the prime curve with constants a, b */
	if(!EC_GROUP_set_curve_GFp(group, p, a, b, ctx)) goto End;

	/* allocate memory for input point P,Q and output R */
	P = EC_POINT_new(group);
	Q = EC_POINT_new(group);
	R = EC_POINT_new(group);
	if (!P||!Q||!R) goto End;

	/* convert inputx to bn_px */
	strtohex(dbl[i].x1, input, &len);
	px = BN_bin2bn(input, prime_length, px);
	/* convert inputy to bn_py */
	strtohex(dbl[i].y1, input, &len);
	py = BN_bin2bn(input, prime_length, py);
	/* set P <-- (px, py) */
	if(!EC_POINT_set_affine_coordinates_GFp(group, P, px, py, ctx)) 
		goto End;

		/* do point double */
		if(!EC_POINT_dbl(group, R, P, ctx))
			goto End;


	/* capture result (px, py) <--- R */
	EC_POINT_get_affine_coordinates_GFp(group, R, px, py, ctx);

	/* convert bn_px to p3 */

	byte_count = BN_bn2bin(px, out);
	if (byte_count < prime_length) {
		 memmove(out+prime_length-byte_count, out,byte_count);
		 memset(out,0,prime_length-byte_count);
	}
	/* convert bn_py to p3 */
	byte_count = BN_bn2bin(py, out+ROUNDUP8(prime_length));
	if (byte_count < prime_length) {
		memmove(out+ROUNDUP8(prime_length)+prime_length-byte_count, out+ROUNDUP8(prime_length),byte_count);
		memset(out+ROUNDUP8(prime_length),0,prime_length-byte_count);
	}
	e= BN_bin2bn(out,2*ROUNDUP8(prime_length),e);
	if(memcmp(dbl[i].exp, BN_bn2hex (e), 2*ROUNDUP8(prime_length))) {
		printf("FECC compare FAILED for prime P-%d\n",dbl[i].prim);
		printf("Expect :%s\n",dbl[i].exp);
		printf("Actual :%s\n",BN_bn2hex (e));
		fail++;
	}

End:
	/* free allocated memory */
	if(p) BN_free(p);
	if(px)BN_free(px);
	if(py)BN_free(py);
	if(a) BN_free(a);
	if(b) BN_free(b);
	if(prime) free(prime);
	if(input) free(input);
	if(out) free(out);
	if(ctx) BN_CTX_free(ctx);
	if(group) EC_GROUP_free(group);
	if(P) EC_POINT_free(P);
	if(R) EC_POINT_free(R);
}
	if (fail)
		printf("***");
	 if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested:  %d passed : %d failed : %d\n","POINT-DOUBLE",i,(i-fail),fail);
	return ret_val;
}


int test_point_addition_kat () {
	uint8_t *prime = NULL;
	uint16_t prime_length=0;
	int byte_count=0, fail = 0;
	unsigned int i=0;
	uint32_t ret_val=0;
	unsigned char * input = NULL;
	uint16_t len= 0;
	uint8_t *out = NULL;

	EC_POINT *P = NULL;
	EC_POINT *Q = NULL;
	EC_POINT *R = NULL;
	EC_GROUP *group = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *p = NULL, *a= NULL, *b = NULL;
	BIGNUM *px= NULL, *py = NULL, *qx = NULL, *qy = NULL;
	BIGNUM *k = NULL,*e = NULL;

	for (i=0;i < sizeof(arr)/sizeof(arr[0]);i++) {

		prime = calloc(FECC_PRIME_CURVE_MAX_LEN, sizeof(uint8_t));
		if(prime == NULL) {
			printf("Unable to allocate memory for prime\n");
		}
	
		input = calloc(FECC_PRIME_CURVE_MAX_LEN, sizeof(char));
		if(input == NULL) {
			printf("Unable to allocate memory for read_line\n");
		}
		out = calloc(2*FECC_PRIME_CURVE_MAX_LEN, sizeof(uint8_t));
		if(out == NULL) {
			printf("Unable to allocate memory for out\n");
		}
	
			if(arr[i].prim == 192) {
				prime_length = FECC_PRIME_CURVE_192_LEN;
				memcpy(prime, const_prime_192, prime_length);
			} else if(arr[i].prim == 224) {
				prime_length = FECC_PRIME_CURVE_224_LEN;
				memcpy(prime, const_prime_224, prime_length);
			} else if(arr[i].prim == 256) {
				prime_length = FECC_PRIME_CURVE_256_LEN;
				memcpy(prime, const_prime_256, prime_length);
			} else if(arr[i].prim == 384) {
				prime_length = FECC_PRIME_CURVE_384_LEN;
				memcpy(prime, const_prime_384, prime_length);
			} else if(arr[i].prim == 521) {
				prime_length = FECC_PRIME_CURVE_521_LEN;
				memcpy(prime, const_prime_521, prime_length);
			} 
	
		/* allocate memory for big numbers */
		p = BN_new();
		px= BN_new();
		py= BN_new();
		qx= BN_new();
		qy= BN_new();
		a = BN_new();
		b = BN_new();
		k = BN_new();
		ctx = BN_CTX_new();
	
		/* set curve constants */
		if(prime_length == FECC_PRIME_CURVE_192_LEN) {
			if(!BN_hex2bn(&a, const_p192_a)) goto End;
			if(!BN_hex2bn(&b, const_p192_b)) goto End;
		} else if(prime_length == FECC_PRIME_CURVE_224_LEN) {
			if(!BN_hex2bn(&a, const_p224_a)) goto End;
			if(!BN_hex2bn(&b, const_p224_b)) goto End;
		} else if(prime_length == FECC_PRIME_CURVE_256_LEN) {
			if(!BN_hex2bn(&a, const_p256_a)) goto End;
			if(!BN_hex2bn(&b, const_p256_b)) goto End;
		} else if(prime_length == FECC_PRIME_CURVE_384_LEN) {
			if(!BN_hex2bn(&a, const_p384_a)) goto End;
			if(!BN_hex2bn(&b, const_p384_b)) goto End;
		} else if(prime_length == FECC_PRIME_CURVE_521_LEN) {
			if(!BN_hex2bn(&a, const_p521_a)) goto End;
			if(!BN_hex2bn(&b, const_p521_b)) goto End;
		} 
	 
		/* prime --> bn_prime */
		p = BN_bin2bn(prime, prime_length, p); 
	
		/* create group of type montgomery */
		group = EC_GROUP_new(EC_GFp_mont_method());
		if(!group){
		printf("Failed at %d\n",__LINE__);
		 goto End;
		}
		/* set group to the prime curve with constants a, b */
		if(!EC_GROUP_set_curve_GFp(group, p, a, b, ctx)) {
		printf("Failed at %d\n",__LINE__);
		 goto End;
		}
		/* allocate memory for input point P,Q and output R */
		P = EC_POINT_new(group);
		Q = EC_POINT_new(group);
		R = EC_POINT_new(group);
		if (!P||!Q||!R) goto End;
	
		/* convert inputx to bn_px */
		strtohex(arr[i].x1, input, &len);
		px = BN_bin2bn(input, prime_length, px);
		/* convert inputy to bn_py */
		strtohex(arr[i].y1, input, &len);
		py = BN_bin2bn(input, prime_length, py);
		/* set P <-- (px, py) */
		if(!EC_POINT_set_affine_coordinates_GFp(group, P, px, py, ctx)) { 
		printf("Failed at %d\n",__LINE__);
			goto End;
	}
	
	/* convert qx to bn_qx */
		strtohex(arr[i].x2, input,&len );
		qx = BN_bin2bn(input, prime_length, qx);
	/* convert qy to bn_qy */
		strtohex(arr[i].y2, input, &len);
		qy = BN_bin2bn(input, prime_length, qy);
	/* set Q <-- (qx, qy) */
		if(!EC_POINT_set_affine_coordinates_GFp(group, Q, qx, qy, ctx)) {
			printf("Failed at %d\n",__LINE__);
			goto End;
		}
			/* do point addition */
			if(!EC_POINT_add(group, R, P, Q, ctx))
				goto End;
	
	
		/* capture result (px, py) <--- R */
		EC_POINT_get_affine_coordinates_GFp(group, R, px, py, ctx);
	
		/* convert bn_px to p3 */
	
		byte_count = BN_bn2bin(px, out);
		if (byte_count < prime_length) {
			 memmove(out+prime_length-byte_count, out,byte_count);
			 memset(out,0,prime_length-byte_count);
		}
		/* convert bn_py to p3 */
		byte_count = BN_bn2bin(py, out+ROUNDUP8(prime_length));
		if (byte_count < prime_length) {
			 memmove(out+ROUNDUP8(prime_length)+prime_length-byte_count, out+ROUNDUP8(prime_length),byte_count);
			 memset(out+ROUNDUP8(prime_length),0,prime_length-byte_count);
		}
		e= BN_bin2bn(out,2*ROUNDUP8(prime_length),e);
		if(memcmp(arr[i].exp, BN_bn2hex (e), 2*ROUNDUP8(prime_length))) {
			printf("FECC comparison FAILED:\n");
			printf("Expect :%s\n",arr[i].exp);
			printf("Actual :%s\n",BN_bn2hex (e));
			fail++;
		}
	
	End:
		/* free allocated memory */
		if(p) BN_free(p);
		if(px)BN_free(px);
		if(py)BN_free(py);
		if(qx)BN_free(qx);
		if(qy)BN_free(qy);
		if(a) BN_free(a);
		if(b) BN_free(b);
		if(k) BN_free(k);
		if(prime) free(prime);
		if(input) free(input);
		if(out) free(out);
		if(ctx) BN_CTX_free(ctx);
		if(group) EC_GROUP_free(group);
		if(P) EC_POINT_free(P);
		if(R) EC_POINT_free(R);
	}
	if (fail)
		printf("***");
	 if (cvmx_is_init_core())
		printf ("%-20s :Total Test vectors tested:  %d passed : %d failed : %d\n","POINT-ADDITION",i,(i-fail),fail);
	return ret_val;
}

int test_ec_point_kat ()
{
	int val=0;
	val = test_point_addition_kat ();
			if (val) {
				 printf("FECC point addition FAIlED \n");
			}
	val = test_point_double_kat ();
			if (val) {
				 printf("FECC point double FAIlED \n");
			}
	val = test_point_multiply_kat ();
			if (val) {
				 printf("FECC point multiply FAIlED \n");
			}


	return 0;
}

