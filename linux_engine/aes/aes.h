#ifndef OCT_HEADER_AES_H
#define OCT_HEADER_AES_H

#include "cvmx.h"
#include "cvmx-asm.h"
#include "cryptolinux.h"
#define AES_CHUNK_SIZE 16

struct aes_key {
    uint64_t cvmkey[4];
    int cvm_keylen;
    int rounds;
};
typedef struct aes_key OCT_AES_KEY;


 int Oct_AES_cbc_encrypt(uint64_t *inp64, uint64_t *outp64, size_t inl, uint64_t *key,
 		int key_len, uint64_t *iv, int enc);

void Oct_AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
             const OCT_AES_KEY *key, const int enc);
#endif
