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



/**
 * @file
 *
 * Interface to generate FIPS compliant (ANSI X9.31 A2.4) 
 * Random number.
 */
#ifndef __FIPS_RAND_H__
#define __FIPS_RAND_H__

/**
 *
@page fips_algo_sec FIPS Random Number Generation Algorithm (Based on Ansi X 9.31 A2.4)
 The algorithm for generation of FIPS complaint Random Number
 is as described in Ansi X9.31 A2.4.
 The algorithm inputs are:
         - DT =  Date-Time Vector
         - V = Seed
         - K = Key data
         - Encryption Type = AES128, AES192, AES256, 3DES.  
 
 The implementation can take all of the above as inputs from
 the user in the form of a context or can instantiate itself 
 if none of the inputs are provided.
 When none of the inputs are provided, the implementation
 does the following:
         - Obtain DT from Octeon H/W RNG
         - Obtain V from Octeon H/W RNG
         - Obtain K from Octeon H/W RNG
         - Assumes Encryption Algorithm to be AES256.

 Implementation generates the Random Number in the following
 manner for Block size (16 bytes for AES, 8 bytes for 3DES):

	<ol>
         <li>  Encrypt DT with K.
         <li>  Store the result in Intermediate.
         <li>  Encrypt V with K.
         <li>  XOR the result obtained in step 3 with Intermediate.
         <li>  Store the Output in Result (Random Number).
         <li>  Encrypt Intermediate with K.
         <li>  XOR the result obtained in step 6 with Result (Random Number).
         <li>  Get the new value of V.
         <li>  Increment DT.
	</ol>

Steps 1 to 9 are repeated till the desired length of Random number
is generated.

Note!!! If context information is provided, the values obtained in 
        step 8 and step 9 are stored in the context for the next
        invocation.
 */

/**
 *
@page fips_crng_sec Random Number Generation Self Test (CRNG)
 Each call to a RNG produces blocks of 16 bytes (by default).
 If TDES Algo is selected, the block would be 8 bytes.
 The first 16 byte block generated after initialization is not used, 
 but is saved for comparison with the next 16 byte block.
 Each subsequent generation of a 16 byte block is compared 
 with the previously generated block. 
 The test shall fail if any two compared 16 byte blocks are equal,
 and it will return OCT_RAND_CRNG_FAILURE.

 CRNG_TEST is disabled by default, if it is required
 the line number 44 in crypto/rand/fips_rand.c should be
 uncommented.

 Upon CRNG_FAILURE, all Crypto APIs which internally use Random Number
 retry for random number, and if a crng callback is registered the
 callback is called.

 There is a mode in which a failure can be simulated, and the frequency
 can be specified at the line number 46 in crypto/rand/fips_rand.c.
 This mode is disabled by default, Uncommenting the line 46 in the file
 specifying the frequency, would simulate the errors.
 */

/**
 * Encryption algo to be used for generating
 * FIPS complaint (ANSI X9.31 A2.4) RNG
 */
typedef enum {
   OCT_FIPSRAND_3DES      = 1,         /**< 3DES Encryption algo  */
   OCT_FIPSRAND_AES128    = 2,         /**< AES 128bit Encryption algo  */ 
   OCT_FIPSRAND_AES192    = 3,         /**< AES 192bit Encryption algo  */
   OCT_FIPSRAND_AES256    = 4          /**< AES 256bit Encryption algo  */
} oct_fipsrand_algo_t;

/**
 * Octeon FIPS Random Context
 */
typedef struct {
   uint64_t K[4];                    /**< Encryption Key to be used
                                       *    - For 3DES, 192bit key 
                                       *          (K[0],K[1],K[2])
                                       *    - For AES128, 128bit key 
                                       *          (K[0],K[1])
                                       *    - For AES192, 192bit key 
                                       *          (K[0],K[1],K[2])
                                       *    - For AES256, 256bit key 
                                       *          (K[0],K[1],K[2],K[3]) 
                                       */
   uint64_t DT[2];                   /**< Date-Time Vector
                                             - For 3DES, 64 bit in DT[0]
                                             - For AES128, AES192, AES256
                                                   128 bit in DT[0], DT[1]
                                     */
   uint64_t V[2];                   /**< V(Seed) Vector
                                             - For 3DES, 64 bit in DT[0]
                                             - For AES128, AES192, AES256
                                                   128 bit in DT[0], DT[1]
                                     */
   uint64_t init_sig;              /**< Context signature for internal use */
   oct_fipsrand_algo_t algo;       /**< Encryption Algorithm to be used */
} oct_fipsrand_ctx_t;

/**
 * Signature for the Context
 */
#define OCT_FIPS_RAND_SIG 0xDEAFDEEDABCDDEADull
#define OCT_RAND_CRNG_FAILURE 1

/**
 * Generate a random number using Octeon H/W RNG unit.
 *
 * @param rand      Random data is stored in this buffer.
 * @param len       Byte Length of the random number to be
 *                  generated
 * @return 0        Success
 *
*/
int oct_rand_generate(uint8_t *rand, uint64_t len);

/**
 * Initialize a FIPS Random Context 
 *
 * @param algo      Encryption Algorithm to be used.
 *                  For supported algos, @see oct_fipsrand_algo_t.
 * @param K         Encryption Key data. 
 *                  Should be 
 *                            - 128bits for AES128,
 *                            - 192bits for AES192,
 *                            - 256bits for AES256,
 *                            - 192bits for 3DES.
 * @param DT        Date-Time Vector to be used.
 *                  Should be 
 *                         - 128bits for AES128,AES192,AES256.
 *                         - 64bits for 3DES.
 *                  This value gets incremented for the same context
 *                  for every block of data processed. 
 *                  @see @ref fips_algo_sec
 * @param V         V (seed) to be used.         
 *                  Should be
 *                         - 128bits for AES128,AES192,AES256.
 *                         -  64bits for 3DES.
 * @param ctx       Pointer to context data.
 *                  Context is initialized with all these values.
 *                  
 * @return 0        Success
 *
*/
int oct_fipsrand_init(oct_fipsrand_algo_t algo, uint8_t *K,
                      uint8_t *DT, uint8_t *V,
                      oct_fipsrand_ctx_t *ctx);

/**
 * Generate a random number using FIPS complaint RNG.
 *    For Algorithm, @see @ref fips_algo_sec
 *
 * @param rand      Random data is stored in this buffer.
 * @param len       Byte Length of the random number to be
 *                  generated
 * @param ctx       Pointer to context data passed in oct_fipsrand_init
 *                  This can be NULL.
 *                  If it is NULL, the parameters are obtained randomly
 *                  from Octeon H/W Rng.  @see @ref fips_algo_sec
 * @return 0        Success
 *         -1       Failure         
 *         OCT_RAND_CRNG_FAILURE CRNG Failure if CRNG_TEST is defined (@see @ref fips_crng_sec)
 *
*/
int oct_fipsrand_generate(uint8_t *rand, uint64_t len, void *ctx);
 
/**
 * Generate a random number (This is deprecated) 
 *     Use oct_rand_generate() instead.
 */
static inline int N3Random(int len, uint8_t *output) 
{
   oct_rand_generate(output, ((uint64_t)len & 0xFFFFFFFFull));
   return len;
}


/**
 * DRBG specific
 */

#define ERR_DF_PARAMS -1
#define ERR_GENERATE_PARAMS -3
#define ERR_UPDATE_PARAMS -4

#define MAX_LEN   256

typedef union {
  uint8_t u8[16];
  uint64_t u64[2];
} blk16_t;

typedef struct {
  blk16_t v;
  #define vl v.u64[1]
  #define vh v.u64[0]
  uint64_t k[4];
  int reseed_counter;  /* unused */
} ctr_drbg_state_t;

/**
 * Creates a seed from entropy input in combination with nonce and personalization string.
 * also creates the internal state of DRBG mechanism 
 *
 * @param entropy   entropy input.
 * @param entlen    length of entropy.
 * @param nonce     nonce.
 * @param nlen      length of nonce.
 * @param pers_str  personalization string.
 * @param perslen   length of personalization string.
 * @param s         state of drbg mechanism.
 * @return 0        Success
 *         -4       Failure (ERR_UPDATE_PARAMS)        
 *
*/
int ctr_drbg_df_instantiate(uint8_t *entropy, int entlen,
                            uint8_t *nonce, int nlen,
                            uint8_t *pers_str, int perslen,
                            ctr_drbg_state_t *s);

/**
 * Generate pseudo-random bits using current internal state.
 * generates new internal state for the next request.
 *
 * @param s                 state of drbg mechanism.
 * @param rand_bytes_req    number of random bytes requested.
 * @param addl_inp          additional input.
 * @param addl_inp_len      length of additional input.
 * @param rand              generated pseudo random bits.
 * @return 0                Success
 *         -1               Failure         
 *
*/
int ctr_drbg_df_generate(ctr_drbg_state_t *s,
                         int rand_bytes_req,
                         uint8_t *addl_inp, int addl_inp_len,
                         uint8_t *rand);

/**
 * creates a new seed and new internal state with entropy and additional input.
 *
 * @param ent           entropy input.
 * @param entlen        length of entropy.
 * @param addl_inp      additional input.
 * @param addlinplen    additional input length.
 * @param s             state of drbg mechanism.
 * @return 0            Success
 *
*/
int ctr_drbg_df_reseed(uint8_t *ent, int entlen,
                       uint8_t *addl_inp, int addlinplen,
                       ctr_drbg_state_t *s);

#endif // __OCT_RANDOM__
