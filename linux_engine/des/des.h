#ifndef HEADER_DES_H
#define HEADER_DES_H

#include "cvmx.h"
#include "cvmx-asm.h"

int Oct_DES_ede3_cbc_encrypt(uint64_t *inp64, uint64_t *outp64, size_t inl, uint64_t *key1,
		uint64_t *key2, uint64_t *key3, uint64_t *iv, int enc);

#endif
