#include "cvmx.h"
#include "cryptolinux.h"


int Oct_SHA1_Update(oct_sha_ctx_data *digest_data, uint64_t *data, size_t count);
int Oct_SHA1_Final(oct_sha_ctx_data *digest_data, unsigned char *md);

int Oct_SHA256_Update(oct_sha256_ctx_data *digest_data, uint64_t *data, size_t count);
int Oct_SHA256_Final(oct_sha256_ctx_data *digest_data, unsigned char *md);

int Oct_SHA512_Update(oct_sha512_ctx_data *digest_data, uint64_t *data, size_t count);
int Oct_SHA512_Final(oct_sha512_ctx_data *digest_data, unsigned char *md);
