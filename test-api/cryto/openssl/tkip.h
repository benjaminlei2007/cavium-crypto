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

#define TKIP_IV_LEN 8
#define TKIP_ICV_LEN 4
#define TKIP_MIC_LEN 8


enum {  /* Return Codes */

	TKIP_DECRYPT_OK = 0,
	TKIP_DECRYPT_NO_EXT_IV = -1,
	TKIP_DECRYPT_INVALID_KEYIDX = -2,
	TKIP_DECRYPT_REPLAY = -3,
};


typedef struct tkip_key {

	
	uint32_t IV32;
	uint16_t IV16;
	uint16_t p1k[5];
	int initialized;

	
	int keyidx:8; /* TKIP key index */
	
	uint8_t tkey[16]; /* Temporal key (TK) */

}tkip_key;


/**
 * Add TKIP IV and Ext. IV at \@pos, \@iv0, \@iv1, and \@iv2 are the first octets
 * of the IV. Returns pointer to the octet following IVs (i.e., beginning of
 * the packet payload).

 * @param pos		Pointer to the beginning of the buffer containing payload, headroom of 8 octets for IV & Ext. IV and taildroom of 4 octets for ICV.
@verbatim
       ----------------------------------------------------------
pos -->|  IV & Ext. IV  |       payload                |   ICV  |
       ----------------------------------------------------------	
@endverbatim						
 * @param key		Pointer to Tkip_key that contain IV.
 * @param RC4KEY	Pointer to 128 bit Phase2 key(i.e.,RC4 encryption key). 		
 *
 * @return 		Pointer to the beginning of packet payload.
 *
 */

uint8_t* tkip_add_iv(uint8_t *pos, tkip_key *key, uint8_t *RC4KEY);


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

void tkip_compute_michael_mic (const uint8_t *key, const uint8_t *data, uint32_t data_len, uint8_t *michael_mic);

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

void tkip_gen_phase1_key (const uint8_t *TK, const uint8_t *TA, const uint32_t IV32, uint16_t *P1K);

/**
 * Function to generate Phase2 Key.
 *
 * @param TK 		Temporal Key pointer (128 bits).
 * @param P1K		Pointer to Phase 1 Output Key (10 octets).
 * @param IV16		Lower 16 bits (2 LSB) of IV.
 * @param RC4KEY	Output pointer that returns 128 bit RC4 key.
 *
 * @return 		Return 128 bit phase2 key in RC4KEY.
 *
 */

void tkip_gen_phase2_key (const uint8_t *TK, const uint16_t *P1K, uint16_t IV16, uint8_t *RC4KEY);

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

void tkip_encrypt_data (tkip_key *key, uint8_t *pos, size_t payload_len, uint8_t *ta);

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

int tkip_decrypt_data(tkip_key *key, uint8_t *payload, size_t payload_len, uint8_t *ta);

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

void tkip_encrypt(uint8_t *rc4key, size_t klen, uint8_t *data, size_t data_len);

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

int tkip_decrypt(uint8_t *rc4key, size_t klen, uint8_t *data, size_t data_len);

/**
 * Function to calculate CRC32 value for given data.
 *
 * @param data 		Pointer to data buffer.
 * @param data_len	The length of data.
 *
 * @return 		Return 32 bit CRC value for given data.
 *
 */

uint32_t tkip_crc32(uint8_t *data, int data_len);

