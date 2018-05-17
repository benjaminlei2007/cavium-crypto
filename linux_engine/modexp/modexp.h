#include <openssl/e_os2.h>
#include "cvmx.h"
#include "cvmx-asm.h"

int oct_mod_exp(BIGNUM *r, BIGNUM *a, BIGNUM *p, BIGNUM *m, BN_CTX *ctx);

int oct_mod_exp_crt(BIGNUM *res, BIGNUM *base, RSA *rsa);
