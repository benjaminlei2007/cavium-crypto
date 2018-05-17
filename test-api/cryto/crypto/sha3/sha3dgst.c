#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#ifdef OCTEON_OPENSSL
#include "cvmx.h"
#include "cvmx-rng.h"
#endif
static inline void
sha3_init_regs(void)
{
    CVMX_MT_SHA3_DAT(0,  0);
    CVMX_MT_SHA3_DAT(0,  1);
    CVMX_MT_SHA3_DAT(0,  2);
    CVMX_MT_SHA3_DAT(0,  3);
    CVMX_MT_SHA3_DAT(0,  4);
    CVMX_MT_SHA3_DAT(0,  5);
    CVMX_MT_SHA3_DAT(0,  6);
    CVMX_MT_SHA3_DAT(0,  7);
    CVMX_MT_SHA3_DAT(0,  8);
    CVMX_MT_SHA3_DAT(0,  9);
    CVMX_MT_SHA3_DAT(0, 10);
    CVMX_MT_SHA3_DAT(0, 11);
    CVMX_MT_SHA3_DAT(0, 12);
    CVMX_MT_SHA3_DAT(0, 13);
    CVMX_MT_SHA3_DAT(0, 14);
    CVMX_MT_SHA3_DAT(0, 15);
    CVMX_MT_SHA3_DAT(0, 16);
    CVMX_MT_SHA3_DAT(0, 17);
    CVMX_MT_SHA3_DAT(0, 18);
    CVMX_MT_SHA3_DAT(0, 19);
    CVMX_MT_SHA3_DAT(0, 20);
    CVMX_MT_SHA3_DAT(0, 21);
    CVMX_MT_SHA3_DAT(0, 22);
    CVMX_MT_SHA3_DAT(0, 23);
    CVMX_MT_SHA3_DAT(0, 24);
}

#if (SHA3_MODE == SHA3_HW_SUPPORT)
static inline int
SHA3_Hw_Init(SHA3_CTX *ctx, int sha3_variant)
{
    if(!ctx || sha3_variant == 0) return 0;

    memset(ctx, 0, sizeof *ctx);

    switch(sha3_variant)
    {
        case KECCAK_TYPE_SHA3_224:
            ctx->rate = 18;
            ctx->type = KECCAK_TYPE_SHA3_224;
            break;
        case KECCAK_TYPE_SHA3_256:
            ctx->rate = 17;
            ctx->type = KECCAK_TYPE_SHA3_256;
            break;
        case KECCAK_TYPE_SHA3_384:
            ctx->rate = 13;
            ctx->type = KECCAK_TYPE_SHA3_384;
            break;
        case KECCAK_TYPE_SHA3_512:
            ctx->rate =  9;
            ctx->type = KECCAK_TYPE_SHA3_512;
        break;
        default: ctx->rate = 0;
        break;
    }

    if(ctx->rate == 0) return 0;

    sha3_init_regs();

    return 1;
}

#endif

int
SHA3_224_Init(SHA3_CTX *ctx)
{
    return SHA3_Init(ctx, KECCAK_TYPE_SHA3_224);
}

int 
SHA3_256_Init(SHA3_CTX *ctx)
{
    return SHA3_Init(ctx, KECCAK_TYPE_SHA3_256);
}

int
SHA3_384_Init(SHA3_CTX *ctx)
{
    return SHA3_Init(ctx, KECCAK_TYPE_SHA3_384);
}

int
SHA3_512_Init(SHA3_CTX *ctx)
{
    return SHA3_Init(ctx, KECCAK_TYPE_SHA3_512);
}


#if (SHA3_MODE == SHA3_HW_SUPPORT)
uint64_t start_cycle;

static inline void
SHA3_permute(uint64_t *input, unsigned long rate)
{
    uint64_t i0, i1, i2, i3;

    i0 = input[0];
    i1 = input[1];
    i2 = input[2];
    i3 = input[3];

    CVMX_MT_SHA3_XORDAT(i0,  0);
    i0 = input[4];
    CVMX_MT_SHA3_XORDAT(i1,  1);
    i1 = input[5];
    CVMX_MT_SHA3_XORDAT(i2,  2);
    i2 = input[6];
    CVMX_MT_SHA3_XORDAT(i3,  3);
    i3 = input[7];
    CVMX_MT_SHA3_XORDAT(i0,  4);
    i0 = input[8];
    CVMX_MT_SHA3_XORDAT(i1,  5);
    i1 = input[9];
    CVMX_MT_SHA3_XORDAT(i2,  6);
    i2 = input[10];
    CVMX_MT_SHA3_XORDAT(i3,  7);
    i3 = input[11];
    CVMX_MT_SHA3_XORDAT(i0,  8);
    if(rate == 9)
      goto sha3_op;
    i0 = input[12];
    CVMX_MT_SHA3_XORDAT(i1,  9);
    i1 = input[13];
    CVMX_MT_SHA3_XORDAT(i2, 10);
    i2 = input[14];
    CVMX_MT_SHA3_XORDAT(i3, 11);
    i3 = input[15];
    CVMX_MT_SHA3_XORDAT(i0, 12);
    if(rate == 13)
      goto sha3_op;
    i0 = input[16];
    CVMX_MT_SHA3_XORDAT(i1, 13);
    i1 = input[17];

    CVMX_MT_SHA3_XORDAT(i2, 14);
    CVMX_MT_SHA3_XORDAT(i3, 15);
    CVMX_MT_SHA3_XORDAT(i0, 16);
    if(rate == 17)
      goto sha3_op;

    CVMX_MT_SHA3_XORDAT(i1, 17);
sha3_op:
    CVMX_MT_SHA3_STARTOP;
}


static int
SHA3_Hw_Update(SHA3_CTX *ctx, const void *data, unsigned long n)
{ 
	unsigned long rbytes = ctx->rate << 3;
	uint64_t *xval = NULL;

	xval = (uint64_t *)&ctx->buf[0];

	if((ctx->buflen+n) >= rbytes)
	{
		if(ctx->buflen) {
			memcpy(&ctx->buf[ctx->buflen], data, rbytes-(ctx->buflen));
			data = (uint8_t *)data + rbytes-(ctx->buflen);
			ctx->buflen = 0;
			SHA3_permute(xval, ctx->rate);
		}
	}
	else {
		memcpy(&ctx->buf[ctx->buflen], data, (size_t)n);
		ctx->buflen += n;
	}

	return 1;
}
#endif
int
SHA3_224_Update(SHA3_CTX *ctx, const void *data, unsigned long n)
{
    return SHA3_Update(ctx, data, n);
}

int
SHA3_256_Update(SHA3_CTX *ctx, const void *data, unsigned long n)
{
    return SHA3_Update(ctx, data, n);
}

int
SHA3_384_Update(SHA3_CTX *ctx, const void *data, unsigned long n)
{
    return SHA3_Update(ctx, data, n);
}

int
SHA3_512_Update(SHA3_CTX *ctx, const void *data, unsigned long n)
{
    return SHA3_Update(ctx, data, n);
}

#if (SHA3_MODE == SHA3_HW_SUPPORT)
static int
SHA3_Hw_Final(unsigned char *md, SHA3_CTX *ctx)
{  
	uint64_t r0, r1;
	unsigned long buflen = ctx->buflen;
	unsigned char *x; 
	unsigned long rbytes = ctx->rate << 3;
	uint64_t *xval = (uint64_t *)&ctx->buf[0];

	if(cvmx_unlikely(buflen < rbytes))
	{
		x = ((unsigned char *)xval) + buflen;
		if(buflen == (rbytes - 1))
		{
			*x = 0x86;
		}
		else
		{
			long t = rbytes - buflen - 2;
			 *x = 0x6;
			x++;
			if(t)
				memset(x, 0, t);
			*(x+t) = 0x80;
		}
		SHA3_permute(xval, ctx->rate);
		buflen = 0;
	}

	CVMX_MF_SHA3_DAT(r0, 0);
	((uint64_t *)md)[0] = r0;
	CVMX_MF_SHA3_DAT(r1, 1);
	((uint64_t *)md)[1] = r1;
	CVMX_MF_SHA3_DAT(r0, 2);
	((uint64_t *)md)[2] = r0;
	CVMX_MF_SHA3_DAT(r1, 3);

	switch(ctx->type)
	{
		case KECCAK_TYPE_SHA3_224:
			((uint32_t *)md)[6] = (r1 >> 32) & 0xFFFFFFFFULL;
			break;
		case KECCAK_TYPE_SHA3_256:
			((uint64_t *)md)[3] = r1;
			break;
		case KECCAK_TYPE_SHA3_384:
			((uint64_t *)md)[3] = r1;
			CVMX_MF_SHA3_DAT(r0, 4);
			((uint64_t *)md)[4] = r0;
			CVMX_MF_SHA3_DAT(r1, 5);
			((uint64_t *)md)[5] = r1;
			break;
		case KECCAK_TYPE_SHA3_512:
			((uint64_t *)md)[3] = r1;
			CVMX_MF_SHA3_DAT(r0, 4);
			((uint64_t *)md)[4] = r0;
			CVMX_MF_SHA3_DAT(r1, 5);
			((uint64_t *)md)[5] = r1;
			CVMX_MF_SHA3_DAT(r0, 6);
			((uint64_t *)md)[6] = r0;
			CVMX_MF_SHA3_DAT(r1, 7);
			((uint64_t *)md)[7] = r1;
			break;
		default:
			break;
	}
    
	return 1;
}
#endif
int
SHA3_256_Final(unsigned char *md, SHA3_CTX *ctx)
{
    return SHA3_Final(md, ctx);
}

int
SHA3_384_Final(unsigned char *md, SHA3_CTX *ctx)
{
    return SHA3_Final(md, ctx);
}

int
SHA3_512_Final(unsigned char *md, SHA3_CTX *ctx)
{
    return SHA3_Final(md, ctx);
}

int
SHA3_224_Final(unsigned char *md, SHA3_CTX *ctx)
{
    return SHA3_Final(md, ctx);
}

#if (SHA3_MODE == SHA3_HW_SUPPORT)
static inline int
SHA3(const unsigned char *in, unsigned long n, unsigned long rate)
{
    unsigned long rbytes = rate << 3;
    uint64_t xval[18];
    uint64_t *dptr = (uint64_t *)in;
    unsigned char *x;

    sha3_init_regs();

    do {
        if(cvmx_unlikely(n < rbytes))
        {
            memcpy(xval, dptr, n);
            x = ((unsigned char *)xval) + n;

            if(n == (rbytes - 1))
            {
                *x = 0x86;
            }
            else
            {
                long t = rbytes - n - 2;

                *x = 0x6;
                x++;
                if(t)
		  memset(x, 0, t);

                *(x+t) = 0x80;
            }

            SHA3_permute(xval, rate);
            n = 0;
        }
        else
        {
            SHA3_permute(dptr, rate);
            dptr += rate;
            n -= rbytes;
        }
    } while(n);

    return 1;
}
#endif
int
SHA3_224(unsigned char *in, unsigned long n, unsigned char *md)
{
#if (SHA3_MODE == SHA3_HW_SUPPORT)
    uint64_t r0, r1;

    SHA3(in, n, 18);

    CVMX_MF_SHA3_DAT(r0, 0);
    ((uint64_t *)md)[0] = r0;
    CVMX_MF_SHA3_DAT(r1, 1);
    ((uint64_t *)md)[1] = r1;
    CVMX_MF_SHA3_DAT(r0, 2);
    ((uint64_t *)md)[2] = r0;
    CVMX_MF_SHA3_DAT(r1, 3);

    ((uint32_t *)md)[6] = (r1 >> 32) & 0xFFFFFFFFULL;
#else
    SHA3_CTX c;
    SHA3_224_Init(&c);
	SHA3_224_Update(&c,in,n);
	SHA3_224_Final(md,&c);
#endif
    return 1;
}

int
SHA3_256(unsigned char *in, unsigned long n, unsigned char *md)
{
#if (SHA3_MODE == SHA3_HW_SUPPORT)
    uint64_t r0, r1;

    SHA3(in, n, 17);

    CVMX_MF_SHA3_DAT(r0, 0);
    ((uint64_t *)md)[0] = r0;
    CVMX_MF_SHA3_DAT(r1, 1);
    ((uint64_t *)md)[1] = r1;
    CVMX_MF_SHA3_DAT(r0, 2);
    ((uint64_t *)md)[2] = r0;
    CVMX_MF_SHA3_DAT(r1, 3);
    ((uint64_t *)md)[3] = r1;
#else
    SHA3_CTX c;
    SHA3_256_Init(&c);
	SHA3_256_Update(&c,in,n);
	SHA3_256_Final(md,&c);
#endif
    return 1;
}

int
SHA3_384(unsigned char *in, unsigned long n, unsigned char *md)
{
#if (SHA3_MODE == SHA3_HW_SUPPORT)
    uint64_t r0, r1;

    SHA3(in, n, 13);

    CVMX_MF_SHA3_DAT(r0, 0);
    ((uint64_t *)md)[0] = r0;
    CVMX_MF_SHA3_DAT(r1, 1);
    ((uint64_t *)md)[1] = r1;
    CVMX_MF_SHA3_DAT(r0, 2);
    ((uint64_t *)md)[2] = r0;
    CVMX_MF_SHA3_DAT(r1, 3);
    ((uint64_t *)md)[3] = r1;
    CVMX_MF_SHA3_DAT(r0, 4);
    ((uint64_t *)md)[4] = r0;
    CVMX_MF_SHA3_DAT(r1, 5);
    ((uint64_t *)md)[5] = r1;
#else
    SHA3_CTX c;
    SHA3_384_Init(&c);
	SHA3_384_Update(&c,in,n);
	SHA3_384_Final(md,&c);
#endif
    return 1;
}


int
SHA3_512(unsigned char *in, unsigned long n, unsigned char *md)
{
#if (SHA3_MODE == SHA3_HW_SUPPORT)
    uint64_t r0, r1;

    SHA3(in, n, 9);

    CVMX_MF_SHA3_DAT(r0, 0);
    ((uint64_t *)md)[0] = r0;
    CVMX_MF_SHA3_DAT(r1, 1);
    ((uint64_t *)md)[1] = r1;
    CVMX_MF_SHA3_DAT(r0, 2);
    ((uint64_t *)md)[2] = r0;
    CVMX_MF_SHA3_DAT(r1, 3);
    ((uint64_t *)md)[3] = r1;
    CVMX_MF_SHA3_DAT(r0, 4);
    ((uint64_t *)md)[4] = r0;
    CVMX_MF_SHA3_DAT(r1, 5);
    ((uint64_t *)md)[5] = r1;
    CVMX_MF_SHA3_DAT(r0, 6);
    ((uint64_t *)md)[6] = r0;
    CVMX_MF_SHA3_DAT(r1, 7);
    ((uint64_t *)md)[7] = r1;
#else
    SHA3_CTX c;
    SHA3_512_Init(&c);
	SHA3_512_Update(&c,in,n);
	SHA3_512_Final(md,&c);
#endif

    return 1;
}


