#include "aes.h"
#define AES_ENCRYPT 1
#define AES_DECRYPT 0


void Oct_AES_encrypt(const unsigned char *in, unsigned char *out,
         const OCT_AES_KEY *key)
{
	uint64_t *in64,*out64;
	assert(in && out && key);
	CVMX_MT_AES_KEY (key->cvmkey[0], 0);
	CVMX_MT_AES_KEY (key->cvmkey[1], 1);
	CVMX_MT_AES_KEY (key->cvmkey[2], 2);
	CVMX_MT_AES_KEY (key->cvmkey[3], 3);
	CVMX_MT_AES_KEYLENGTH (key->cvm_keylen/64 - 1);
	in64 = (uint64_t*)in;
	out64 = (uint64_t*)out;   
	CVMX_MT_AES_ENC0(in64[0]);
	CVMX_MT_AES_ENC1(in64[1]);
	CVMX_MF_AES_RESULT(out64[0],0);
	CVMX_MF_AES_RESULT(out64[1],1);
}

void Oct_AES_decrypt(const unsigned char *in, unsigned char *out,
         const OCT_AES_KEY *key)
{
	uint64_t *in64,*out64;
	assert(in && out && key);
	CVMX_MT_AES_KEY (key->cvmkey[0], 0);
	CVMX_MT_AES_KEY (key->cvmkey[1], 1);
	CVMX_MT_AES_KEY (key->cvmkey[2], 2);
	CVMX_MT_AES_KEY (key->cvmkey[3], 3); 
	CVMX_MT_AES_KEYLENGTH (key->cvm_keylen/64 - 1);
	in64 = (uint64_t*)in;
	out64 = (uint64_t*)out;
	CVMX_MT_AES_DEC0(in64[0]);
	CVMX_MT_AES_DEC1(in64[1]);
	CVMX_MF_AES_RESULT(out64[0],0);
	CVMX_MF_AES_RESULT(out64[1],1);
}


void Oct_AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
             const OCT_AES_KEY *key, const int enc)
{
	assert(in && out && key);
    assert((AES_ENCRYPT == enc)||(AES_DECRYPT == enc));

    if (AES_ENCRYPT == enc)
        Oct_AES_encrypt(in, out, key);
    else
        Oct_AES_decrypt(in, out, key);
}

