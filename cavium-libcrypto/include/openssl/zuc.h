#include "cvmx.h"

#define ZUC_KEY_LEN			(16)
#define ZUC_IV_LEN			(16)

#define BITS_TO_DOUBLEWORD(x)		(((x) + 63) >> 6)

#define MAKELFSR(k0, c0, iv0, k1, c1, iv1)				\
   (((uint64_t)(k0 ) << 55) |						\
    ((uint64_t)(c0 ) << 40) |						\
    ((uint64_t)(iv0) << 32) |						\
    ((uint64_t)(k1 ) << 23) |						\
    ((uint64_t)(c1 ) <<  8) |						\
    ((uint64_t)(iv1) <<  0))

/**
 * ZUC_init
 *
 * Initializes the ZUC related data structures
 *
 * @return void
 */
void ZUC_init(void);

/**
 * ZUC_finish
 *
 * Completes the ZUC processing
 *
 * @return void
 */
void ZUC_finish(void);

/**
 * ZUC
 *
 * Generates the key stream of size 32 bits 'len' times.
 *
 * @param key	    pointer to the key argument
 * @param iv        pointer to the initialization vector
 * @param ks        pointer the keystream buffer (output pointer)
 * @param len       the number of 32bit keystreams to be generated
 *
 * @return  0 on Success else a failure.
 */
int ZUC(unsigned char *key,unsigned char *iv,uint32_t *ks, int len);

/**
 * ZUC_encrypt
 *
 * Encrypts/Decrypts the data.
 *
 * @param in        pointer to the input buffer
 * @param len       length of the input 'in' in *bits*
 * @param out       pointer to the output buffer
 * @param key       pointer to the key
 * @param count     count value
 * @param bearer    bearer value
 * @param direction direction value
 *
 * @return 0 on Success else a failure
 */
int ZUC_encrypt(const unsigned char *in,unsigned int len,unsigned char *out,
    unsigned char *key,unsigned int count,unsigned int bearer,
    unsigned int direction);

/**
 * ZUC_mac
 *
 * Calculates the Message Authentication Code.
 *
 * @param in        pointer to the input buffer
 * @param len       length of the input 'in' in *bits*
 * @param mac       pointer to the output mac buffer
 * @param ikey      pointer to the key
 * @param count     count value
 * @param bearer    bearer value
 * @param direction direction value
 *
 * @return 0 on Success else a failure
 */
int ZUC_mac(const unsigned char *in,unsigned int len,unsigned char *mac,
    unsigned char *ikey,unsigned int count,unsigned int bearer,
    unsigned int direction);

