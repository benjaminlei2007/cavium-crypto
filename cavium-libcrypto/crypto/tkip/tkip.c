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
#include <stdint.h>
#include <cvmx.h>
#include <cvmx-asm.h>
#include <cvmx-swap.h>
#include <openssl/rc4.h>
#include <openssl/tkip.h>

#ifdef DEBUG_TKIP
void print_in_hex (uint8_t *val, int count)
{
	int i;
	for (i=0;i< count; i++)
		printf("%02x ", *(val+i));
	printf("\n");
	return;
}
#endif

/* Macros for extraction/creation of byte/double byte values */
#define Lo8(v16) ((uint8_t)( (v16) & 0x00FF))
#define Hi8(v16) ((uint8_t)((v16) >> 8))
#define Lo16(v32) ((uint16_t)( (v32) & 0xFFFF))
#define Hi16(v32) ((uint16_t)(((v32) >>16)))
#define Mk16(hi,lo) ((lo) | (((uint16_t)(hi)) << 8))



/* S-box lookup: 16 bits --> 16 bits */
#define _S_(v16) (Sbox[0][Lo8(v16)] ^ Sbox[1][Hi8(v16)])

/* fixed algorithm "parameters" */
#define PHASE1_LOOP_CNT 8 

/* 2-byte by 2-byte subset of the full AES S-box table */
const uint16_t Sbox[2][256]= /* Sbox for hash */
{ {
	0xC6A5,0xF884,0xEE99,0xF68D,0xFF0D,0xD6BD,0xDEB1,0x9154,
	0x6050,0x0203,0xCEA9,0x567D,0xE719,0xB562,0x4DE6,0xEC9A,
	0x8F45,0x1F9D,0x8940,0xFA87,0xEF15,0xB2EB,0x8EC9,0xFB0B,
	0x41EC,0xB367,0x5FFD,0x45EA,0x23BF,0x53F7,0xE496,0x9B5B,
	0x75C2,0xE11C,0x3DAE,0x4C6A,0x6C5A,0x7E41,0xF502,0x834F,
	0x685C,0x51F4,0xD134,0xF908,0xE293,0xAB73,0x6253,0x2A3F,
	0x080C,0x9552,0x4665,0x9D5E,0x3028,0x37A1,0x0A0F,0x2FB5,
	0x0E09,0x2436,0x1B9B,0xDF3D,0xCD26,0x4E69,0x7FCD,0xEA9F,
	0x121B,0x1D9E,0x5874,0x342E,0x362D,0xDCB2,0xB4EE,0x5BFB,
	0xA4F6,0x764D,0xB761,0x7DCE,0x527B,0xDD3E,0x5E71,0x1397,
	0xA6F5,0xB968,0x0000,0xC12C,0x4060,0xE31F,0x79C8,0xB6ED,
	0xD4BE,0x8D46,0x67D9,0x724B,0x94DE,0x98D4,0xB0E8,0x854A,
	0xBB6B,0xC52A,0x4FE5,0xED16,0x86C5,0x9AD7,0x6655,0x1194,
	0x8ACF,0xE910,0x0406,0xFE81,0xA0F0,0x7844,0x25BA,0x4BE3,
	0xA2F3,0x5DFE,0x80C0,0x058A,0x3FAD,0x21BC,0x7048,0xF104,
	0x63DF,0x77C1,0xAF75,0x4263,0x2030,0xE51A,0xFD0E,0xBF6D,
	0x814C,0x1814,0x2635,0xC32F,0xBEE1,0x35A2,0x88CC,0x2E39,
	0x9357,0x55F2,0xFC82,0x7A47,0xC8AC,0xBAE7,0x322B,0xE695,
	0xC0A0,0x1998,0x9ED1,0xA37F,0x4466,0x547E,0x3BAB,0x0B83,
	0x8CCA,0xC729,0x6BD3,0x283C,0xA779,0xBCE2,0x161D,0xAD76,
	0xDB3B,0x6456,0x744E,0x141E,0x92DB,0x0C0A,0x486C,0xB8E4,
	0x9F5D,0xBD6E,0x43EF,0xC4A6,0x39A8,0x31A4,0xD337,0xF28B,
	0xD532,0x8B43,0x6E59,0xDAB7,0x018C,0xB164,0x9CD2,0x49E0,
	0xD8B4,0xACFA,0xF307,0xCF25,0xCAAF,0xF48E,0x47E9,0x1018,
	0x6FD5,0xF088,0x4A6F,0x5C72,0x3824,0x57F1,0x73C7,0x9751,
	0xCB23,0xA17C,0xE89C,0x3E21,0x96DD,0x61DC,0x0D86,0x0F85,
	0xE090,0x7C42,0x71C4,0xCCAA,0x90D8,0x0605,0xF701,0x1C12,
	0xC2A3,0x6A5F,0xAEF9,0x69D0,0x1791,0x9958,0x3A27,0x27B9,
	0xD938,0xEB13,0x2BB3,0x2233,0xD2BB,0xA970,0x0789,0x33A7,
	0x2DB6,0x3C22,0x1592,0xC920,0x8749,0xAAFF,0x5078,0xA57A,
	0x038F,0x59F8,0x0980,0x1A17,0x65DA,0xD731,0x84C6,0xD0B8,
	0x82C3,0x29B0,0x5A77,0x1E11,0x7BCB,0xA8FC,0x6DD6,0x2C3A,
},
{
	0xA5C6,0x84F8,0x99EE,0x8DF6,0x0DFF,0xBDD6,0xB1DE,0x5491,
	0x5060,0x0302,0xA9CE,0x7D56,0x19E7,0x62B5,0xE64D,0x9AEC,
	0x458F,0x9D1F,0x4089,0x87FA,0x15EF,0xEBB2,0xC98E,0x0BFB,
	0xEC41,0x67B3,0xFD5F,0xEA45,0xBF23,0xF753,0x96E4,0x5B9B,
	0xC275,0x1CE1,0xAE3D,0x6A4C,0x5A6C,0x417E,0x02F5,0x4F83,
	0x5C68,0xF451,0x34D1,0x08F9,0x93E2,0x73AB,0x5362,0x3F2A,
	0x0C08,0x5295,0x6546,0x5E9D,0x2830,0xA137,0x0F0A,0xB52F,
	0x090E,0x3624,0x9B1B,0x3DDF,0x26CD,0x694E,0xCD7F,0x9FEA,
	0x1B12,0x9E1D,0x7458,0x2E34,0x2D36,0xB2DC,0xEEB4,0xFB5B,
	0xF6A4,0x4D76,0x61B7,0xCE7D,0x7B52,0x3EDD,0x715E,0x9713,
	0xF5A6,0x68B9,0x0000,0x2CC1,0x6040,0x1FE3,0xC879,0xEDB6,
	0xBED4,0x468D,0xD967,0x4B72,0xDE94,0xD498,0xE8B0,0x4A85,
	0x6BBB,0x2AC5,0xE54F,0x16ED,0xC586,0xD79A,0x5566,0x9411,
	0xCF8A,0x10E9,0x0604,0x81FE,0xF0A0,0x4478,0xBA25,0xE34B,
	0xF3A2,0xFE5D,0xC080,0x8A05,0xAD3F,0xBC21,0x4870,0x04F1,
	0xDF63,0xC177,0x75AF,0x6342,0x3020,0x1AE5,0x0EFD,0x6DBF,
	0x4C81,0x1418,0x3526,0x2FC3,0xE1BE,0xA235,0xCC88,0x392E,
	0x5793,0xF255,0x82FC,0x477A,0xACC8,0xE7BA,0x2B32,0x95E6,
	0xA0C0,0x9819,0xD19E,0x7FA3,0x6644,0x7E54,0xAB3B,0x830B,
	0xCA8C,0x29C7,0xD36B,0x3C28,0x79A7,0xE2BC,0x1D16,0x76AD,
	0x3BDB,0x5664,0x4E74,0x1E14,0xDB92,0x0A0C,0x6C48,0xE4B8,
	0x5D9F,0x6EBD,0xEF43,0xA6C4,0xA839,0xA431,0x37D3,0x8BF2,
	0x32D5,0x438B,0x596E,0xB7DA,0x8C01,0x64B1,0xD29C,0xE049,
	0xB4D8,0xFAAC,0x07F3,0x25CF,0xAFCA,0x8EF4,0xE947,0x1810,
	0xD56F,0x88F0,0x6F4A,0x725C,0x2438,0xF157,0xC773,0x5197,
	0x23CB,0x7CA1,0x9CE8,0x213E,0xDD96,0xDC61,0x860D,0x850F,
	0x90E0,0x427C,0xC471,0xAACC,0xD890,0x0506,0x01F7,0x121C,
	0xA3C2,0x5F6A,0xF9AE,0xD069,0x9117,0x5899,0x273A,0xB927,
	0x38D9,0x13EB,0xB32B,0x3322,0xBBD2,0x70A9,0x8907,0xA733,
	0xB62D,0x223C,0x9215,0x20C9,0x4987,0xFFAA,0x7850,0x7AA5,
	0x8F03,0xF859,0x8009,0x171A,0xDA65,0x31D7,0xC684,0xB8D0,
	0xC382,0xB029,0x775A,0x111E,0xCB7B,0xFCA8,0xD66D,0x3A2C,
	}
};


/**
 * Function to generate Phase1 Key.
 *
 * @param TA		Transmitter MAC address pointer (6 octets).
 * @param TK 		Temporal Key pointer (128 bits).
 * @param IV32		Upper 32 bits (4 MSB) of IV.
 * @param P1K		Output pointer that stores the 80 bit Phase1 Key.
 *
 * @return 		Return 80 bit phase1 key in P1K.
 *
 */

void tkip_gen_phase1_key (const uint8_t *TK, const uint8_t *TA, const uint32_t IV32, uint16_t *P1K)
{
	int i;

	/* Step 1 */


	P1K [0] = (uint16_t)(IV32 & 0xFFFF);
	P1K [1] = (uint16_t)(IV32>>16);
	P1K [2] = Mk16 (TA [1], TA [0]);
	P1K [3] = Mk16 (TA [3], TA [2]);
	P1K [4] = Mk16 (TA [5], TA [4]);

	/* Step 2 */

	for (i=0; i < PHASE1_LOOP_CNT ;i++)
	{
	#define TK16(N) Mk16(TK[(N)+1],TK[(N)])
		int j = 2*(i&1);
		P1K[0] += _S_(P1K[4] ^ TK16(j+0));
		P1K[1] += _S_(P1K[0] ^ TK16(j+4));
		P1K[2] += _S_(P1K[1] ^ TK16(j+8));
		P1K[3] += _S_(P1K[2] ^ TK16(j+12));
		P1K[4] += _S_(P1K[3] ^ TK16(j+0));
		P1K[4] += i;

	}

	return;
}


/**
 * Function to generate Phase2 Key.
 *
 * @param TK 		Temporal Key pointer (128 bits).
 * @param P1K		Pointer to Phase 1 Output Key (10 octets).
 * @param IV6		Lower 16 bits (2 LSB) of IV.
 * @param RC4KEY	Output pointer that returns 128 bit RC4 key.
 *
 * @return 		Return 128 bit phase2 key in RC4KEY.
 *
 */

void tkip_gen_phase2_key (const uint8_t *TK, const uint16_t *P1K, const uint16_t IV16, uint8_t *RC4KEY)
{
	int i;
	uint16_t PPK[6];


	PPK [0] = P1K [0];
	PPK [1] = P1K [1];
	PPK [2] = P1K [2];
	PPK [3] = P1K [3];
	PPK [4] = P1K [4];
	PPK [5] = P1K [4] + IV16;

	PPK[0] += _S_ ( PPK [5] ^ TK16 (0));
	PPK[1] += _S_ ( PPK [0] ^ TK16 (2));
	PPK[2] += _S_ ( PPK [1] ^ TK16 (4));
	PPK[3] += _S_ ( PPK [2] ^ TK16 (6));
	PPK[4] += _S_ ( PPK [3] ^ TK16 (8));
	PPK[5] += _S_ ( PPK [4] ^ TK16 (10));

#define RotR1(v16) ((((v16) >> 1)) ^ (((v16)) << 15))

	PPK[0] += RotR1(PPK [5] ^ TK16 (12));
	PPK[1] += RotR1(PPK [0] ^ TK16 (14));
	PPK[2] += RotR1(PPK [1]);
	PPK[3] += RotR1(PPK [2]);
	PPK[4] += RotR1(PPK [3]);
	PPK[5] += RotR1(PPK [4]);

	RC4KEY[0] = Hi8(IV16); /* RC4KEY[0..2] is the TKIP IV */
	RC4KEY[1] =(Hi8(IV16) | 0x20) & 0x7F; 
	RC4KEY[2] = Lo8(IV16);
	RC4KEY[3] = Lo8((PPK[5] ^ TK16(0)) >> 1);

	for (i=0; i<6; i++)
	{
		int j = 4 + 2*i;
		RC4KEY[j++] = Lo8(PPK[i]);
		RC4KEY[j] = Hi8(PPK[i]);
	}

	return ;
}

/* Michael Related Functions */

#define michael_b(l, r) \
do { \
	r ^= (l << 17) | (l >> 15); \
	l += r; \
	r ^= ((l & 0xff00ff00) >> 8) | ((l & 0x00ff00ff) << 8); \
	l += r; \
	r ^= (l << 3) | (l >> 29); \
	l += r; \
	r ^= (l >> 2) | (l << 30); \
	l += r; \
} while (0)

/** 
 * Function to compute Michael Message Integrity Code.
 * 
 * @param key		64 bit key pointer.
 * @param data		data for which Michael MIC is to be generated.
 * @param data_len 	The length of data.
 * @param michael_mic	Output pointer in which 64 bit MIC will be stored.
 * 			LSB of michael_mic is M0 as defined by IEEE802.11i standard
 * 			MSB of micahel_mic is M7 as defined by IEEE802.11i standard
 *
 *@return 		Return 64 bit MIC value in michael_mic.
 *
 */

void tkip_compute_michael_mic (const uint8_t *key, const uint8_t *data, uint32_t data_len, uint8_t *michael_mic)
{
	uint32_t l, r;
	uint32_t i, endian;
	uint32_t nwords = data_len/4;
	uint8_t data_left = data_len % 4;

        CVMX_ES32(l, *((uint32_t *)key));	/* K0	*/  
        CVMX_ES32(r, *((uint32_t *) (key+4)));	/* K1 	*/

	for (i=0; i<nwords; i++)
	{
		CVMX_ES32(endian, *((uint32_t *) (data+i*4)));
		l ^= endian;
		michael_b (l,r);
	}

	i = nwords *4 + data_left;

	if ( data_left == 0)
	{
		l ^= 0x5a;
		michael_b (l,r);
	}
	else if ( data_left == 1)
	{
		l ^= (0x5a << 8) | *(data + i -1);
		michael_b (l,r);
	}
	else if (data_left == 2)
	{
		l ^= (0x5a<<16) | (*(data + i -1) << 8) | *(data + i -2);
		michael_b (l,r);
	}
	else if (data_left == 3)
	{
		l ^= (0x5a<<24) | (*(data + i -1) << 16) | (*(data + i -2) << 8)
			 | *(data + i - 3);
		michael_b (l,r);
	}

	/* We dont XOR for the last block since last block is zero by design */
	michael_b (l,r);
	
	CVMX_ES32(*((uint32_t *) michael_mic), l);

	CVMX_ES32(*((uint32_t *) (michael_mic+4)), r);

#ifdef DEBUG_TKIP
	printf("The Value of michael_mic : ");
	print_in_hex(michael_mic,TKIP_MIC_LEN);
#endif

	return;
}

/**
 * Add TKIP IV and Ext. IV at @pos. @iv0, @iv1, and @iv2 are the first octets
 * of the IV. Returns pointer to the octet following IVs (i.e., beginning of
 * the packet payload).

 * @param pos		Pointer to the beginning of the buffer containing payload, headroom of 8 octets for IV & Ext. IV and taildroom of 4 octets for ICV.
 * @param key		Pointer to Tkip_key that contain IV.
 * @param RC4KEY	Pointer to 128 bit Phase2 key(i.e.,RC4 encryption key). 		
 *
 * @return 		Pointer to the beginning of packet payload.
 *
 */


uint8_t* tkip_add_iv(uint8_t *pos, tkip_key *key, uint8_t *RC4KEY)
{
	*pos++ = *(RC4KEY+0);
	*pos++ = *(RC4KEY+1);
	*pos++ = *(RC4KEY+2);
	*pos++ = ((key->keyidx) << 6) | (1 << 5); // Ext IV /;
	*pos++ = key->IV32 & 0xff;
	*pos++ = (key->IV32 >> 8) & 0xff;
	*pos++ = (key->IV32 >> 16) & 0xff;
	*pos++ = (key->IV32>> 24) & 0xff;
	return pos;
}


/**
 * Function to calculate CRC32 value for given data.
 *
 * @param data 		Pointer to data buffer.
 * @param data_len	The length of data.
 *
 * @return 		Return 32 bit CRC value for given data.
 *
 */

uint32_t tkip_crc32(uint8_t *data, int data_len)
{
    uint64_t crc = 0xFFFFFFFF;
    int size;
    uint64_t t1, t2, t3, t4;
    uint64_t * buffer;

    if (data == NULL) {
        crc = 0xFFFFFFFF;
        return 0;
    }

#define POLY 0x2083b8ed

    CVMX_MT_CRC_POLYNOMIAL_REFLECT(POLY);
    CVMX_ES32(t1, crc);
    CVMX_MT_CRC_IV_REFLECT(t1);

    size = data_len;
    buffer = (uint64_t *) data;

    while (size > 127) {
        CVMX_LOADUNA_INT64(t1, buffer++, 0);
        CVMX_LOADUNA_INT64(t2, buffer++, 0);
        CVMX_LOADUNA_INT64(t3, buffer++, 0);
        CVMX_LOADUNA_INT64(t4, buffer++, 0);
        CVMX_MT_CRC_DWORD_REFLECT(t1);
        CVMX_MT_CRC_DWORD_REFLECT(t2);
        CVMX_MT_CRC_DWORD_REFLECT(t3);
        CVMX_MT_CRC_DWORD_REFLECT(t4);
        CVMX_LOADUNA_INT64(t1, buffer++, 0);
        CVMX_LOADUNA_INT64(t2, buffer++, 0);
        CVMX_LOADUNA_INT64(t3, buffer++, 0);
        CVMX_LOADUNA_INT64(t4, buffer++, 0);
        CVMX_MT_CRC_DWORD_REFLECT(t1);
        CVMX_MT_CRC_DWORD_REFLECT(t2);
        CVMX_MT_CRC_DWORD_REFLECT(t3);
        CVMX_MT_CRC_DWORD_REFLECT(t4);
        CVMX_LOADUNA_INT64(t1, buffer++, 0);
        CVMX_LOADUNA_INT64(t2, buffer++, 0);
        CVMX_LOADUNA_INT64(t3, buffer++, 0);
        CVMX_LOADUNA_INT64(t4, buffer++, 0);
        CVMX_MT_CRC_DWORD_REFLECT(t1);
        CVMX_MT_CRC_DWORD_REFLECT(t2);
        CVMX_MT_CRC_DWORD_REFLECT(t3);
        CVMX_MT_CRC_DWORD_REFLECT(t4);
        CVMX_LOADUNA_INT64(t1, buffer++, 0);
        CVMX_LOADUNA_INT64(t2, buffer++, 0);
        CVMX_LOADUNA_INT64(t3, buffer++, 0);
        CVMX_LOADUNA_INT64(t4, buffer++, 0);
        CVMX_MT_CRC_DWORD_REFLECT(t1);
        CVMX_MT_CRC_DWORD_REFLECT(t2);
        CVMX_PREFETCH(buffer,128);
        CVMX_MT_CRC_DWORD_REFLECT(t3);
        CVMX_MT_CRC_DWORD_REFLECT(t4);
        size -= 128;
    }

    while (size > 15) {
        CVMX_LOADUNA_INT64(t1, buffer++, 0);
        CVMX_LOADUNA_INT64(t2, buffer++, 0);
        CVMX_MT_CRC_DWORD_REFLECT(t1);
        CVMX_MT_CRC_DWORD_REFLECT(t2);
        size -= 16;
    }

    data = (unsigned char *)buffer;

    while (size > 3) {
        CVMX_LOADUNA_INT32(t1, data, 0);
        CVMX_MT_CRC_WORD_REFLECT(t1);
        size -= 4;
        data += 4;
    }

    if (size > 1) {
        CVMX_LOADUNA_UINT16(t1, data, 0);
        CVMX_MT_CRC_HALF_REFLECT(t1);
        data += 2;
    }

    if (size & 1) {
        CVMX_MT_CRC_BYTE_REFLECT(*data);
    }

    CVMX_MF_CRC_IV_REFLECT(crc);

    crc = crc & 0xFFFFFFFF;

    crc =  crc ^ 0xFFFFFFFF;

    return crc; 
}

/**
 * Perform TKIP encryption using given key.
 *
 * @param rc4key	Pointer to 128 bit Phase2 key(i.e.,RC4 decryption key). 
 * @param klen 		The length of RC4 devryption key. 
 * @param data		data buffer includes payload, including tailroom for 4-byte ICV, but not include IV.
 * @param data_len	The length of data buffer, but not include ICV
 *
 * @return 		Encrypted payload and ICV in data.
 *
 */

void tkip_encrypt(uint8_t *rc4key, size_t klen, uint8_t *data, size_t data_len)
{
	uint32_t *icv;
	RC4_KEY Rc4Key;

	icv = (uint32_t *)(data + data_len);
	*icv = tkip_crc32(data, data_len);


	RC4_set_key(&Rc4Key, klen, (unsigned char *) rc4key );

	RC4(&Rc4Key, (data_len + TKIP_ICV_LEN), (unsigned char *) data, (unsigned char *) data);

	return;	
}

/**
 * Perform TKIP decryption using given key.
 *
 * @param rc4key	Pointer to 128 bit Phase2 key(i.e.,RC4 decryption key). 
 * @param klen 		The length of RC4 devryption key. 
 * @param data		data buffer includes encrypted payload, including 4-byte ICV, but not IV.
 * @param data_len	The length of data buffer, but not include ICV
 *
 * @return 		1 on success and -1 on failure.
 * @return 		On success return decryped data and ICV in data.
 * @return  		Failure: -1 (ICV mismatch).
 *
 */

int tkip_decrypt(uint8_t *rc4key, size_t klen, uint8_t *data, size_t data_len)
{

	uint32_t crc;
	RC4_KEY Rc4Key;

	RC4_set_key(&Rc4Key, klen, (unsigned char* )rc4key );

	RC4(&Rc4Key, data_len + TKIP_ICV_LEN, (unsigned char *) data, (unsigned char *) data);

	crc = tkip_crc32(data, data_len);
	
	if (memcmp(&crc, (data + data_len), TKIP_ICV_LEN) != 0)
		/* ICV mismatch */
		return -1;

	return 0;
}

/**
 * Encrypt packet payload with TKIP using key.
 *
 * @param key		Pointer to tkip_key key use for encryption.
 * @param pos		Pointer to the beginning of the buffer containing payload, headroom of 8 octets for IV & Ext. IV and taildroom of 4 octets for ICV.
 * @param payload_len	The length of payload, not including extra headroom and tailroom.
 * @param ta		Transmitters MAC Address pointer (6 octets).	
 *
 * @return 		Return Encrypted data and ICV in pos.
 *
 */

void tkip_encrypt_data(tkip_key *key, uint8_t *pos, size_t payload_len, uint8_t *ta)
{
	uint8_t rc4key[16];

	/* Calculate per-packet key */
	if (key->IV16 == 0 || !key->initialized) {
		/* IV16 wrapped around - perform TKIP phase 1 */
		tkip_gen_phase1_key(key->tkey, ta, key->IV32, key->p1k);
#ifdef DEBUG_TKIP
		printf("TKIP encrypt: TA : ");
		print_in_hex(ta, 6);
		printf("TKIP encrypt: TK : ");
		print_in_hex(key->tkey, 16);
		printf("TKIP encrypt: P1K : ");
		print_in_hex((uint8_t *) key->p1k,10);
#endif

		key->initialized = 1;
	}

	tkip_gen_phase2_key(key->tkey, key->p1k, key->IV16, rc4key);

#ifdef DEBUG_TKIP
	printf("TKIP encrypt: Phase2 rc4key : ");
	print_in_hex(rc4key, 16);
#endif
	pos = tkip_add_iv(pos, key, rc4key);
	
	tkip_encrypt(rc4key, 16, pos, payload_len);
	
	return;

}


/**
 * Decrypt packet payload with TKIP using key.
 *
 * @param key		Pointer to tkip_key key use for decryption.
 * @param payload	Pointer to the beginning of the buffer containing IEEE 802.11 header payload,
 *			including IV, Ext. IV, real data, Michael MIC, ICV.
 * @param payload_len	The length of payload, including IV, Ext. IV, MIC, ICV.
 * @param ta		Transmitters MAC Address pointer (6 octets).	 		
 *
 * @return 		1 on success and error code on failure.
 *
 */

int tkip_decrypt_data(tkip_key *key, uint8_t *payload, size_t payload_len, uint8_t *ta)
{
	uint32_t IV32;
	uint16_t IV16;
	uint8_t rc4key[16], keyid, *pos = payload;
	int ret;
	
	if (payload_len < 12)
		return -1;

	IV16 = (pos[0] << 8) | pos[2];
	keyid = pos[3];
	IV32 = pos[4] | (pos[5] << 8) | (pos[6] << 16) | (pos[7] << 24);
	pos += 8;

#ifdef DEBUG_TKIP
	printf("TKIP decrypt: data(len = %d) :", payload_len);
	print_in_hex(payload, payload_len);
	printf("TKIP decrypt: IV16 = %04x IV32 = %08x\n", IV16, IV32);
	printf("keyid = %02x \n", keyid);
	printf("key->idx = %d \n", key->keyidx);
#endif
	if (!(keyid & (1 << 5)))
		return TKIP_DECRYPT_NO_EXT_IV;

	if ((keyid >> 6) != key->keyidx)
		return TKIP_DECRYPT_INVALID_KEYIDX;

	if (key->initialized && (IV32 < key->IV32 || (IV32 == key->IV32 && IV16 <= key->IV16)))
	 {
#ifdef DEBUG_TKIP
		printf("TKIP replay detected \n ( IV (%04x,%02x) <= prev. IV (%04x,%02x)\n",IV32, IV16, key->IV32, key->IV16);
#endif  
		return TKIP_DECRYPT_REPLAY;
	}


	if (!key->initialized || key->IV32 != IV32) 
	{
		key->initialized = 1;
		/* IV16 wrapped around - perform TKIP phase 1 */
		tkip_gen_phase1_key(key->tkey, ta, IV32, key->p1k);

#ifdef DEBUG_TKIP
		printf("TKIP decrypt: TA : ");
		print_in_hex(ta, 6);
		printf("TKIP decrypt: TK : ");
		print_in_hex(key->tkey, 16);
		printf("TKIP decrypt: P1K : ");
		print_in_hex((uint8_t *) key->p1k,10);
#endif
	}

	tkip_gen_phase2_key(key->tkey, key->p1k, IV16, rc4key);

#ifdef DEBUG_TKIP
	printf("TKIP decrypt: Phase2 rc4key : ");
	print_in_hex(rc4key, 16);
#endif

	ret = tkip_decrypt(rc4key, 16, pos, payload_len - 12);


	if (ret == TKIP_DECRYPT_OK) {

		key->IV32 = IV32;
		key->IV16 = IV16;
	}

	return ret;
}


