#include "cvmx.h"
#include "cvmx-asm.h"
#include "cryptolinux.h"


int Oct_MD5_Update(oct_md5_ctx_data *digest_data, uint64_t *data, size_t count);
int Oct_MD5_Final(oct_md5_ctx_data *digest_data, unsigned char *md);
