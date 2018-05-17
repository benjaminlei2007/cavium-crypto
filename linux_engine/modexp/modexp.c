#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include "modexp.h"
#include "cryptolinux.h"

#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <openssl/evp.h>

extern uint32_t cvmx_app_init_processor_id;

int MontMul576(uint64_t * product, uint64_t * mpcand, uint64_t * mplier,
  uint64_t * mod, uint64_t * recip);
int MontMul512(uint64_t * product, uint64_t * mpcand, uint64_t * mplier,
  uint64_t * mod, uint64_t * recip);
int MontMul(uint64_t * product, uint64_t * mpcand, uint64_t * mplier,
  uint64_t * mod, uint64_t * recip, int len);
int MontMul_O3(uint64_t * product, uint64_t * mpcand, uint64_t * mplier,
  uint64_t * mod, uint64_t * recip, int len);
extern int Vadd(uint64_t * accum, uint64_t * addend, int len);
extern int Vsub(uint64_t * accum, uint64_t * addend, int len);
int64_t VCmp (const uint64_t * a, const uint64_t * b, int len);
void VMul (uint64_t * product, const uint64_t * mpcand, const uint64_t * mplier,
  int len);
void MMLoop (uint64_t * product, const uint64_t * base, const uint64_t * exponent,
  const uint64_t * mod, const uint64_t * recip, int len, int elen);

#if _MIPS_SIM == _MIPS_SIM_NABI32
/* a should have atleast ROUNDUP8(len) bytes */
static void
convert_bn32_to_hw(uint8_t *a, int len)
{
    uint32_t l;

    for (; len >= 8; len -= 8, a += 8) {
       l                  = *(uint32_t *)a;
       *(uint32_t *)a     = ((uint32_t *)a)[1];
       ((uint32_t *)a)[1] = l;
    }

    if (len) {
       l                  = *(uint32_t *)a;
       *(uint32_t *)a     = 0;
       ((uint32_t *)a)[1] = l;
    }
    return;
}

static void
convert_hw_to_bn32(uint8_t *a, int len)
{
    convert_bn32_to_hw(a, (len / 8) * 8);

    a += ((len / 8) * 8);

    if (len % 8) {
       uint32_t l         = *(uint32_t *)a;
       *(uint32_t *)a     = ((uint32_t *)a)[1];
       ((uint32_t *)a)[1] = l;
    }
}
#endif

void
VMul(uint64_t *product, const uint64_t *mpcand, const uint64_t *mplier, int len)
{
    int i, k;

    for(i = 0; i < len * 2; i++)
        product[i] = 0;

    for(k = 0; k < len; k++) {
        CVMX_MTM0(mplier[k]);
        CVMX_MTM1(0);
        CVMX_MTM2(0);

        for(i = 0; i < len; i++)
            CVMX_V3MULU(product[i + k], mpcand[i], product[i + k]);

        CVMX_V3MULU(product[i + k], 0, product[i + k]);
    }
}

int64_t
VCmp(const uint64_t *a, const uint64_t *b, int len)
{
    int i = 0;
    
    for (i = len - 1; i >= 0; i--) {
        if (a[i] != b[i]) {
            return ((a[i] > b[i]) ? 1 : -1);
        }
    }

return 0;
}

void
MMLoop(uint64_t *product, const uint64_t *base, const uint64_t *exponent,
       const uint64_t *mod, const uint64_t *recip, int len, int elen)
{
    uint64_t *temp;
    int i, j, size, bits;
    int lenx8 = len * sizeof(uint64_t);

    size = sizeof(uint64_t) * (len + 6);

    uint64_t *precompute[16];
    int max_size = sizeof(uint64_t) * (128 + 6);
    for(i = 0; i < 16; i++) {
        precompute[i] = (uint64_t *)OPENSSL_malloc(max_size);
        if(!precompute[i]) {
            for(j = i - 1; j >= 0; j--) {
                OPENSSL_free(precompute[j]);
            }
            return;
        }
        memset(precompute[i], 0, max_size);
    }

   if((temp = (uint64_t *)OPENSSL_malloc(size)) == NULL) {
        printf("memory allocation failed\n");
        return;
    }
    memset(temp, 0, size);

    memcpy(precompute[0], product, size);
    memcpy(precompute[1], base, size);

    for(i = 2; i < 16; i++) {
        memcpy(temp, precompute[i - 1], lenx8);

        if(len <= 8) {
            MontMul576((uint64_t *)precompute[i], (uint64_t *)temp,
                (uint64_t *)base, (uint64_t *)mod, (uint64_t *)recip);
        } else {
            MontMul((uint64_t *)precompute[i], (uint64_t *)temp,
                (uint64_t *)base, (uint64_t *)mod, (uint64_t *)recip, len);
        }
    }

    for (i = (len * 16) - 1; i >= 0; i--) {
        bits = (int)((exponent[i / 16] >> ((i & 0xf) << 2)) & 0xf);

        if (bits) break;
    }

    for(; i >= 0; i--) {
        bits = (exponent[i / 16] >> ((i & 15) << 2)) & 0xf;

        if(len <= 8) {
            MontMul576((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)product, (uint64_t *)mod, (uint64_t *)recip);

            MontMul576((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)temp, (uint64_t *)mod, (uint64_t *)recip);

            MontMul576((uint64_t *)temp,(uint64_t *)product,
                (uint64_t *)product, (uint64_t *)mod, (uint64_t *)recip);

            MontMul576((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)temp, (uint64_t *)mod, (uint64_t *)recip);

        } else {
            MontMul((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)product, (uint64_t *)mod, (uint64_t *)recip, len);

            MontMul((uint64_t *)product, (uint64_t *)temp,(uint64_t *)temp,
                (uint64_t *)mod,(uint64_t *)recip,len);

            MontMul((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)product, (uint64_t *)mod, (uint64_t *)recip, len);

            MontMul((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)temp, (uint64_t *)mod, (uint64_t *)recip, len);
        }

        if(len <= 8) {
            MontMul576((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)precompute[bits], (uint64_t *)mod,
                (uint64_t *)recip);
        } else {
            MontMul((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)precompute[bits], (uint64_t *)mod,
                (uint64_t *)recip, len);
        }
        memcpy(product, temp, lenx8);
    }

    if (temp)
        OPENSSL_free(temp);

    for (i = 0; i < 16; i++)
        OPENSSL_free(precompute[i]);
}


static inline int
cvm_crypto_vmul_hwbug(void)
{
#ifdef USE_ALWAYS_KERNEL_MODULE
   /* always go through kernel mode for modexp,
      This does not have affect on performance, as crypto
      kernel module implements unlocked ioctls
    */
   return 1;
#else
   if (!cvmx_app_init_processor_id ||
       OCTEON_IS_MODEL(OCTEON_CN38XX_PASS2) ||
       OCTEON_IS_MODEL(OCTEON_CN31XX_PASS1) ||
       OCTEON_IS_MODEL(OCTEON_CN31XX_PASS1_1) ||
       OCTEON_IS_MODEL(OCTEON_CN3020_PASS1_1) ||
       OCTEON_IS_MODEL(OCTEON_CN3020_PASS1))
       return 1;
   return 0;
#endif
}


int
rsa_to_cry_private(RSA *rsa, cvm_rsa_key_t *rkey)
{
    BN_ULONG *buf;
    int buflen;

    buf    = rsa->n->d;
    buflen = rsa->n->top;
    memset(rkey, 0, sizeof(cvm_rsa_key_t));
    rkey->len = BN_num_bytes(rsa->n);

    /* Used for CRT */
    /* TODO : Will all these be the same size? Just use one for loop in
       that case */
    buf    = rsa->dmp1->d;
    buflen = rsa->dmp1->top;

    if (buflen > 256) {
        return -1;
    }

    rkey->eplen = buflen;
    rkey->expp = (uint64_t *)OPENSSL_malloc((buflen * 8) + MODEXP_GUARD);
    memset(rkey->expp, 0, (buflen * 8) + MODEXP_GUARD);
    memcpy(rkey->expp, buf, buflen * sizeof(BN_ULONG));

    buf    = rsa->dmq1->d;
    buflen = rsa->dmq1->top;

    if (buflen > 256) {
        return -1;
    }

    /* ModExp (Octeon) Expects length in 8-byte words */
    rkey->eqlen = buflen;
    rkey->expq  = (uint64_t *)OPENSSL_malloc((buflen * 8) + MODEXP_GUARD);
    memset(rkey->expq, 0, (buflen * 8) + MODEXP_GUARD);
    memcpy(rkey->expq, buf, buflen * sizeof(BN_ULONG));

    buf    = rsa->p->d;
    buflen = rsa->p->top;

    if (buflen > 256) {
        return -1;
    }

    rkey->p = (uint64_t *)OPENSSL_malloc(buflen * 8 + MODEXP_GUARD);
    memset(rkey->p, 0, buflen * 8 + MODEXP_GUARD);
    memcpy(rkey->p, buf, buflen * sizeof(BN_ULONG));

    buf    = rsa->q->d;
    buflen = rsa->q->top;

    if (buflen > 256) {
        return -1;
    }

    rkey->q = (uint64_t *)OPENSSL_malloc(buflen * 8 + MODEXP_GUARD);
    memset(rkey->q, 0, buflen * 8 + MODEXP_GUARD);
    memcpy(rkey->q, buf, buflen * sizeof (BN_ULONG));

    buf    = rsa->iqmp->d;
    buflen = rsa->iqmp->top;

    if (buflen > 256) {
        return -1;
    }

    rkey->coeff = (uint64_t *)OPENSSL_malloc(buflen * 8 + MODEXP_GUARD);
    memset(rkey->coeff, 0, buflen * 8 + MODEXP_GUARD);
    memcpy(rkey->coeff, buf, buflen * sizeof(BN_ULONG));

    return 1;
}

void
rsa_cry_private_free(cvm_rsa_key_t *key)
{
    if (key == NULL)  return;
    if (key->mod)     OPENSSL_free(key->mod);
    if (key->privexp) OPENSSL_free(key->privexp);
    if (key->pubexp)  OPENSSL_free(key->pubexp);
    if (key->expp)    OPENSSL_free(key->expp);
    if (key->expq)    OPENSSL_free(key->expq);
    if (key->p)       OPENSSL_free(key->p);
    if (key->q)       OPENSSL_free(key->q);
    if (key->coeff)   OPENSSL_free(key->coeff);
}

void
ModReduce(uint64_t *result, uint64_t *base, int baselen,
          uint64_t *mod, int modlen)
{
    uint64_t *tmp = NULL;
    uint64_t recip[3];
    uint64_t *negmod = NULL;
    int i, size, negsize;
    int msw, msm;
    int len = baselen;

    size    = (baselen * 8) + MODEXP_GUARD;
    negsize = (baselen * 8 * 3);

    tmp    = (uint64_t *)OPENSSL_malloc(size);
    negmod = (uint64_t *)OPENSSL_malloc(negsize);

    if (tmp == NULL || negmod == NULL)
        goto err;

    memset(tmp, 0, size);
    memset(negmod, 0, negsize);
    /* Calculates negmod i.e. -1 * modulus */

    for (i = 0; i < modlen; i++) {
        *(negmod + i) = 0;
        if (mod[i] != 0)
          break;
    }

    *(negmod + i) = ~mod[i] + 1;
    for (i++; i < modlen + 1; i++)
      *(negmod + i) = ~mod[i];

    /* Finding most significant bit of modulus */
    // I need to know where most significant word of the modulus is
    for (msm = modlen - 1; msm >= 0; msm--) {
        if (mod[msm]) {
            break;
        }
    }

    if ((msm == len - 1) && (mod[msm] >> 36)) {
        return;  /* len needs to be incremented by 1 */
    }

    // I also need to put the modulus msb into the high 32b
    unsigned char normalize = !(mod[msm] >> 32);
    if (normalize) {
        for (i = len * 3 - 1; i >= 1; i--) {
            *(negmod + i) = (*(negmod + i) << 32) | (*(negmod + (i - 1)) >> 32);
        }
        *negmod = (*negmod) << 32;
    }
    /* Calculating reciprocal of mod */
    recip[0] = 0;
    recip[1] = 0;
    recip[2] = 0;
    CVMX_MTM2 (0);

    for (i = 63; i >= 0; i--) {
        uint64_t junk;
        recip[1] |= (uint64_t) 1 << i;
        CVMX_MTM0 (recip[0]);
        CVMX_MTM1 (recip[1]);
        CVMX_MTM2(0);     
        CVMX_V3MULU (junk, negmod[msm - 1], 0);
        CVMX_V3MULU (junk, negmod[msm], 0);
        CVMX_V3MULU (junk, (int64_t) - 1, 0);
        CVMX_V3MULU (junk, (int64_t) - 1, (uint64_t) 1 << 32);

        if ((junk >> 63))
            recip[1] ^= (uint64_t) 1 << i;
    }

    for (i = 63; i >= 0; i--) {
        uint64_t junk;
        recip[0] |= (uint64_t) 1 << i;
        CVMX_MTM0 (recip[0]);
        CVMX_MTM1 (recip[1]);
        CVMX_MTM2(0);

        CVMX_V3MULU (junk, negmod[msm - 1], 0);
        CVMX_V3MULU (junk, negmod[msm], 0);
        CVMX_V3MULU (junk, (int64_t) - 1, 0);
        CVMX_V3MULU (junk, (int64_t) - 1, (uint64_t) 1 << 32);
        
        if ((junk >> 63))
            recip[0] ^= (uint64_t) 1 << i;
    }
    /*
     * This is equivalent to the standard paper-pencil division method
     * Starting from the highest bits of base, calculate quotient,
     * subtract (quotient * mod ) from base. Now we have a base with
     * fewer bits than the original. Keep going till base < mod
     */
    {
        uint64_t q[4];
        uint64_t *temp = NULL;
        int k;
        temp = (uint64_t *) OPENSSL_malloc (size);
        if(temp == NULL)
            goto err;
        
        if (normalize) {
            for (i = len * 3 - 1; i >= 1; i--)
                result[i] = (base[i] << 32) | (base[i - 1] >> 32);
            result[0] = base[0] << 32;
        } else
            memcpy (result, base, sizeof (uint64_t) * (len + 1));

        result[len] = 0;

        CVMX_MTM0 (recip[0]);
        CVMX_MTM1 (recip[1]);
        CVMX_MTM2 (0);

        for (k = 0; k < modlen; k++)
            CVMX_V3MULU (temp[k], mod[k], 0);
        
        CVMX_V3MULU (temp[k], 0, 0);
        k++;
        CVMX_V3MULU (temp[k], 0, 0);
        k++;

        /* Find out where msw of base is */
        msw = baselen - 1;

        do {
            memset (temp, 0, size);

            /* Take reciprocal and multiply with high bits of "base",
               to get Q ~= base/mod */
            CVMX_MTM0 (recip[0]);
            CVMX_MTM1 (recip[1]);
            CVMX_MTM2 (0);
            
            CVMX_V3MULU (q[0], (result[msw] >> 32) | (result[msw + 1] << 32), 0);
            CVMX_V3MULU (q[1], (result[msw + 1] >> 32), 0);
            CVMX_V3MULU (q[2], 0, 0);
            CVMX_V3MULU (q[3], 0, 0);

            CVMX_MTM0 (q[2]);
            CVMX_MTM1 (q[3]);
            CVMX_MTM2 (0);

            for (k = 0; k < baselen; k++)
                CVMX_V3MULU (temp[k], mod[k], 0);
            for (k = 0; k < baselen; k++)
                CVMX_V3MULU (temp[k], negmod[k], 0);

            for (k = 0; k < baselen; k++)   // could be smarter and stop earlier
              CVMX_V3MULU (result[k + msw - msm], negmod[k],
                result[k + msw - msm]);
            
            result[msw + 4] = 0;
            result[msw + 3] = 0;
            // this gets rid of junk left behind because
            //negmod was signextended out to baselen bits
            result[msw + 2] = 0;
            msw--;
        } while (msw >= (modlen - 1));
          OPENSSL_free (temp);
    }

    if (normalize) {
        for (i = 0; i < len * 3; i++)
            result[i] = (result[i + 1] << 32) | (result[i] >> 32);
    }

    memcpy(tmp, result, len * sizeof (uint64_t));

    /* Now finish off by subtracting modulus */
    while (1) {
        Vsub(tmp, mod, modlen + 2);
        if (tmp[modlen] >> 63) {
            break;
        } else {
            memcpy(result, tmp, modlen * sizeof(uint64_t));
        }
    }
err:
    if (tmp)     OPENSSL_free (tmp);
    if (negmod)  OPENSSL_free (negmod);
}

int
find_msw (uint64_t * wptr)
{
    int i = 0;
    while (wptr[i++]);
    return i - 1;
}

static int
oct_crypto_init(void)
{
    int fd ;

    if ((fd = open ("/dev/octcrypto", O_RDONLY)) < 0) {
        static int once = 1;
        if (once) {
            printf("\t\t!!ERROR!! ERROR!!\n\t\tCrypto Module (cavmodexp) is required for this chip\n");
            printf("\t\tinsmod cavmodexp.ko\n");
            once = 0;
        }
        return -errno;
    }

    return fd;
}

static int
crypto_mult(int cryptfd, uint64_t montmul, uint64_t arg)
{
    if (cryptfd) {
        if (montmul == CRYPT_MODEXP)
            return ioctl (cryptfd, CRYPT_MODEXP, arg);        //ModExp
        else if (montmul == CRYPT_MODEXPCRT)
            return ioctl (cryptfd, CRYPT_MODEXPCRT, arg);     //ModExpCrt
	return -1;
    } else {
        return -1;
    }
}

void
MMLoop_O3(uint64_t *product, const uint64_t *base, const uint64_t *exponent,
    const uint64_t *mod, const uint64_t *recip, int len, int elen)
{
    uint64_t *temp;

    int i, size, bits, psize;
    int lenx8 = len * sizeof(uint64_t);

    size = sizeof(uint64_t) * (len + 6);

    uint64_t precompute[16][128 + 8];

    if((temp = OPENSSL_malloc(size)) == NULL) {
        printf("memory allocation failed\n");
        return;
    }
    memset(temp, 0, size);

    psize = (int)sizeof(precompute[0]);
    memset(precompute[0], 0, psize);
    memset(precompute[1], 0, psize);

    memcpy(precompute[0], product, size);
    memcpy(precompute[1], base, size);

    for(i = 2; i < 16; i++) {
       memcpy(temp, precompute[i - 1], lenx8);

        if(len <= 8) {
            MontMul512((uint64_t *)precompute[i], (uint64_t *)temp,
                (uint64_t *)base, (uint64_t *)mod, (uint64_t *)recip);
        } else {
            MontMul_O3((uint64_t *)precompute[i], (uint64_t *)temp,
                (uint64_t *)base, (uint64_t *)mod, (uint64_t *)recip, len);
        }
    }

    for (i = (len * 16) - 1; i >= 0; i--) {
        bits = ((exponent[i / 16] >> ((i & 15) << 2)) & 0xf);

        if (bits) break;
    }

    for (; i >= 0; i--) {
        bits = (exponent[i / 16] >> ((i & 15) << 2)) & 0xf;

        if (len <= 8) {
            MontMul512((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)product, (uint64_t *)mod, (uint64_t *)recip);

            MontMul512((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)temp, (uint64_t *)mod, (uint64_t *)recip);

            MontMul512((uint64_t *)temp,(uint64_t *)product,
                (uint64_t *)product, (uint64_t *)mod, (uint64_t *)recip);

            MontMul512((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)temp, (uint64_t *)mod, (uint64_t *)recip);

        } else {
            MontMul_O3((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)product, (uint64_t *)mod, (uint64_t *)recip, len);

            MontMul_O3((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)temp, (uint64_t *)mod,(uint64_t *)recip, len);

            MontMul_O3((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)product, (uint64_t *)mod, (uint64_t *)recip, len);

            MontMul_O3((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)temp, (uint64_t *)mod, (uint64_t *)recip, len);
        }

        if (len <= 8) {
            MontMul512((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)precompute[bits], (uint64_t *)mod,
                (uint64_t *)recip);
        } else {
            MontMul_O3((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)precompute[bits], (uint64_t *)mod,
                (uint64_t *)recip, len);
        }

        memcpy(product, temp, lenx8);
    }

    if (temp) OPENSSL_free(temp);

}

static int
crypto_modexp_octeon3(uint64_t *product, uint64_t *base, uint64_t *exponent,
    uint64_t *mod, int len, int elen, int mlen, int blen, int convert)
{
#if defined(_MIPS_ARCH_OCTEON3)
    int success = 0;
    
    if(!cvm_crypto_vmul_hwbug())
    {
        uint64_t recip[6];
        // first compute montgomery reciprocal
        int i, size;
        int lenx8;
        int msw = 0;
        uint64_t junk = 0;
        uint64_t *residue = NULL, *temp = NULL,
                  *negmod = NULL, *temp_base = NULL;

        lenx8 = sizeof(uint64_t) * len;
        len   = (len + 3) & 0xfffc;
        size  = sizeof(uint64_t) * (len + 6);

        /* Moved the memory from stack to heap */
        residue   = (uint64_t *)OPENSSL_malloc(size);
        temp      = (uint64_t *)OPENSSL_malloc(size);
        negmod    = (uint64_t *)OPENSSL_malloc(size);
        temp_base = (uint64_t *)OPENSSL_malloc(size);

        if(!temp || !negmod || !residue || !temp_base)
        {
            printf("memory allocation failed\n");
            goto err;
        }

        memset(residue,   0, size);
        memset(temp,      0, size);
        memset(negmod,    0, size);
        memset(temp_base, 0, size);
        memset(recip,     0, sizeof(recip));

        for(i = 0; i < len; i++)
        {
            negmod[i] = 0;
            if(mod[i] != 0) break;
        }

        negmod[i] = ~mod[i] + 1;

        for(i++; i < len; i++)
            negmod[i] = ~mod[i];

        negmod[len] = ~(uint64_t)0;

        /* I need to know where most significant word of the modulus is */
        for(msw = len - 1; msw >= 0; msw--)
            if(mod[msw])
                break;

        int normalize = mod[msw] < ((uint64_t)1 << 32);

        if(normalize)
        {
            for(i = msw; i >= 1; i--)
                negmod[i] = (negmod[i] << 32) | (negmod[i - 1] >> 32);

            negmod[0] = (negmod[0] << 32);
        }

        recip[0] = 0;
        recip[1] = 0;

        junk = 0;
        CVMX_MTM2_V3(0, 0);

        for(i = 63; i >= 0; i--)
        {
            recip[1] |= (uint64_t)1 << i;

            CVMX_MTM0_V3(recip[0], 0);
            CVMX_MTM1_V3(recip[1], 0);

            CVMX_VMULU(junk, negmod[msw - 1], 0);
            CVMX_VMULU(junk, negmod[msw], 0);
            CVMX_VMULU(junk, (int64_t)-1, 0);
            CVMX_VMULU(junk, (int64_t)-1, (uint64_t)1 << 32);

            if((junk >> 63))
                recip[1] ^= (uint64_t)1 << i;
        }

        junk = 0;

        for(i = 63; i >= 0; i--)
        {
            recip[0] |= (uint64_t)1 << i;

            CVMX_MTM0_V3(recip[0], 0);
            CVMX_MTM1_V3(recip[1], 0);

            CVMX_VMULU(junk, negmod[msw - 1], 0);
            CVMX_VMULU(junk, negmod[msw], 0);
            CVMX_VMULU(junk, (int64_t)-1, 0);
            CVMX_VMULU(junk, (int64_t)-1, (uint64_t)1 << 32);

            if((junk >> 63))
                recip[0] ^= (uint64_t)1 << i;
        }

        int r = (len <= 8) ? 8 : ((len + 5) / 6) * 6;
        r = r * 2;

        residue[msw] = (normalize ? ((uint64_t)1 << 32) : 1);
        r -= msw;


        /* Each iteration I'll left shift things 64 bits and do
         * a modular reduction.
         */
        for(i = 0; i < r; i++)
        {
            int k;
            uint64_t q[4] = {0, 0, 0, 0};
            memmove(residue + 1, residue, lenx8);
            residue[0] = 0;

            CVMX_MTM0_V3(recip[0], 0);
            CVMX_MTM1_V3(recip[1], 0);
            CVMX_MTM2_V3(0, 0);

            CVMX_VMULU(q[0], (residue[msw] >> 32) | (residue[msw + 1] << 32), 0);
            CVMX_VMULU(q[1], (residue[msw + 1] >> 32), 0);
            CVMX_VMULU(q[2], 0, 0);
            CVMX_VMULU(q[3], 0, 0);

            CVMX_MTM0_V3(q[2], 0);
            CVMX_MTM1_V3(q[3], 0);
            CVMX_MTM2_V3(0, 0);

           for(k = 0; k < len + 1; k++)
                CVMX_VMULU(residue[k], negmod[k], residue[k]);

            if(residue[len] > 1) FATAL_ERROR;
        }

        if(normalize)
        {
            if(residue[0] << 32) FATAL_ERROR;

            for(i = 0; i < len; i++)
                residue[i] = (residue[i] >> 32) | (residue[i + 1] << 32);

            residue[len] = 0;
        }

        if(len <= 8)
        {
            recip[0] = 0;
            recip[1] = 0;

            CVMX_MTM2_V3(0, 0);

#if defined(USER_SPACE_MODEXP)
            CVMX_MTM0_V3(0, 0);
            CVMX_MTM1_V3(0, 0);
            CVMX_MTM2_V3(0, 0);
#endif

            for(i = 0; i < 128; i++)
            {
                uint64_t *sub = &recip[i / 64];
                int k;
                char undo = 0;
                uint64_t p[2];
                *sub |= (uint64_t)1 << (i & 63);

                CVMX_MTM0_V3(recip[0], 0);
                CVMX_MTM1_V3(recip[1], 0);

#if !defined(USER_SPACE_MODEXP)
                CVMX_VMULU(p[0], mod[0], 1);
                CVMX_VMULU(p[1], mod[1], 0);
#else
                CVMX_MTM2_V3(0, 0);
                CVMX_V3MULU(p[0], mod[0], 1);
                CVMX_V3MULU(p[1], mod[1], 0);
#endif

                for(k = 0; k < (i / 64); k++)
                    undo = undo || p[k];

                undo = undo || (p[i / 64] << (63 - (i & 63)));

                if(undo)
                    *sub ^= (uint64_t)1 << (i & 63);
            }
        }
        else
        {
           for(i = 0; i < 6; i++)
                recip[i] = (uint64_t)0;

            for(i = 0; i < 384; i++)
            {
                uint64_t *sub = &recip[i / 64];
                int k;
                char undo = 0;
                uint64_t p[6];

                *sub |= ((uint64_t)1 << (i & 63));

                CVMX_MTM0_V3(recip[0], recip[3]);
                CVMX_MTM1_V3(recip[1], recip[4]);
                CVMX_MTM2_V3(recip[2], recip[5]);

                CVMX_V3MULU(p[0], mod[0], 1);
                CVMX_V3MULU(p[1], mod[1], 0);
                CVMX_V3MULU(p[2], mod[2], 0);
                CVMX_V3MULU(p[3], mod[3], 0);
                CVMX_V3MULU(p[4], mod[4], 0);
                CVMX_V3MULU(p[5], mod[5], 0);

                for(k = 0; k < (i / 64); k++)
                    undo = undo || p[k];

                undo = undo || (p[i / 64] << (63 - (i & 63)));

                if(undo)
                    *sub ^= ((uint64_t)1 << (i & 63));
            }
        }

        if(len <= 8)
        {
            MontMul512((uint64_t *)product, (uint64_t *)base,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip);
        }
        else
        {
            MontMul_O3((uint64_t *)product, (uint64_t *)base,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip, len);
        }

        memcpy(temp_base, product, lenx8);

#if 0
#ifdef SPEEDUP_CODE
        zero_cache_lines(temp, cache_lines);
#else
        memset(temp, 0, size);
#endif
#endif

        temp[0] = 1;

        if(len <= 8)
        {
            MontMul512((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip);
        }
        else
        {
            MontMul_O3((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip, len);
        }

        MMLoop_O3(product, temp_base, exponent, mod, recip, len, elen);

        memset(residue, 0, size);

        residue[0] = 1;
        memset(temp, 0, size);

        if(len <= 8)
        {
            MontMul512((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip);
        }
        else
        {
            MontMul_O3((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip, len);
        }

        memcpy(product, temp, lenx8);

        Vsub(temp, mod, len + 1);

        if(!(temp[len] >> 63))
            memcpy(product, temp, lenx8);

        success = 1;

err:
        if(residue)    OPENSSL_free(residue);
        if(temp)       OPENSSL_free(temp);
        if(negmod)     OPENSSL_free(negmod);
        if(temp_base)  OPENSSL_free(temp_base);
    }
#if defined(TARGET_LINUX)
    else
    {
        int fd = oct_crypto_init();
        if (fd < 0) {
            printf("Octeon Crypto Library Kernel module[cavmodexp] not available\n");
            return OCT_FAILURE;
        }

#if _MIPS_SIM == _MIPS_SIM_NABI32
        cvm_crypto_op_t tokernel;
        tokernel.sizeofptr = sizeof (void *);
        tokernel.arg1 = (uint64_t) (uint32_t) product;
        tokernel.arg2 = (uint64_t) (uint32_t) base;
        tokernel.arg3 = (uint64_t) (uint32_t) exponent;
        tokernel.arg4 = (uint64_t) (uint32_t) mod;
        tokernel.arg5 = (uint64_t) (uint32_t) 0;      /* recip */
        tokernel.arg6 = (int64_t) len;
        tokernel.arg7 = (int64_t) elen;
        tokernel.arg8 = (int64_t) mlen;
        tokernel.arg9 = (int64_t) blen;
        success = !crypto_mult (fd, CRYPT_MODEXP, (uint64_t) (uint32_t) & tokernel);
#else
        cvm_crypto_op_t tokernel;
        tokernel.sizeofptr = sizeof (void *);
        tokernel.arg1 = (uint64_t) product;
        tokernel.arg2 = (uint64_t) base;
        tokernel.arg3 = (uint64_t) exponent;
        tokernel.arg4 = (uint64_t) mod;
        tokernel.arg5 = (uint64_t) 0; /* recip */
        tokernel.arg6 = (int64_t) len;
        tokernel.arg7 = (int64_t) elen;
        tokernel.arg8 = (int64_t) mlen;
        tokernel.arg9 = (int64_t) blen;
        success = !crypto_mult (fd, CRYPT_MODEXP, (uint64_t) & tokernel);
#endif
    }
#endif
    return success;
#else
    return 0;
#endif
}

static int
crypto_modexp_octeon2(uint64_t *product, uint64_t *base, uint64_t *exponent, uint64_t *mod,
              int len, int elen, int mlen, int blen,int convert)
{
    int success = 0;
    if(!cvm_crypto_vmul_hwbug())
    {
        uint64_t recip[6];
        
        // first compute montgomery reciprocal
        int i, size;
        int lenx8 = len * sizeof(uint64_t);
        int msw = 0;
        uint64_t junk = 0;
        uint64_t *residue = NULL, *temp = NULL,
                  *negmod = NULL, *temp_base = NULL;

        len  = (len + 3) & 0xfffc;

        size = sizeof(uint64_t) * (len + 6);

       /* Moved the memory from stack to heap */
        residue   = (uint64_t *)OPENSSL_malloc(size);
        temp      = (uint64_t *)OPENSSL_malloc(size);
        negmod    = (uint64_t *)OPENSSL_malloc(size);
        temp_base = (uint64_t *)OPENSSL_malloc(size);

        if(!temp || !negmod || !residue || !temp_base)
        {
            printf("memory allocation failed\n");
            goto err;
        }

        memset(residue,   0, size);
        memset(temp,      0, size);
        memset(negmod,    0, size);
        memset(temp_base, 0, size);
        memset(recip,     0, sizeof(recip));

        for(i = 0; i < len; i++)
        {
            negmod[i] = 0;
            if(mod[i] != 0) break;
        }

        negmod[i] = ~mod[i] + 1;

        for(i++; i < len; i++)
            negmod[i] = ~mod[i];

        negmod[len] = ~(uint64_t)0;

        /* I need to know where most significant word of the modulus is */
        for(msw = len - 1; msw >= 0; msw--)
            if(mod[msw])
            {
                break;
            }

/*
        if(0 && msw == len - 1 && (mod[msw] >> 36))
        {
            FATAL_ERROR;     //len needs to be incremented by 1
        }
*/

        int normalize = mod[msw] < ((uint64_t)1 << 32);

        if(normalize)
        {
            for(i = msw; i >= 1; i--)
                negmod[i] = (negmod[i] << 32) | (negmod[i - 1] >> 32);

            negmod[0] = negmod[0] << 32;
        }

        recip[0] = 0;
        recip[1] = 0;

        CVMX_MTM2(0); //70XX adjustment

        junk = 0;

        for(i = 63; i >= 0; i--)
        {
            recip[1] |= (uint64_t)1 << i;

            CVMX_MTM0(recip[0]);
            CVMX_MTM1(recip[1]);
            CVMX_MTM2(0); // 70XX adjustment

            CVMX_V3MULU(junk, negmod[msw - 1], 0);
            CVMX_V3MULU(junk, negmod[msw], 0);
            CVMX_V3MULU(junk, (int64_t)-1, 0);
            CVMX_V3MULU(junk, (int64_t)-1, (uint64_t)1 << 32);

            if((junk >> 63))
                recip[1] ^= (uint64_t)1 << i;
        }

        junk = 0;

        for(i = 63; i >= 0; i--)
        {
            recip[0] |= (uint64_t) 1 << i;

            CVMX_MTM0(recip[0]);
            CVMX_MTM1(recip[1]);
            CVMX_MTM2(0); // 70XX adjustment

            CVMX_V3MULU(junk, negmod[msw - 1], 0);
            CVMX_V3MULU(junk, negmod[msw], 0);
            CVMX_V3MULU(junk, (int64_t)-1, 0);
            CVMX_V3MULU(junk, (int64_t)-1, (uint64_t)1 << 32);

            if((junk >> 63))
                recip[0] ^= (uint64_t)1 << i;
        }

        //memset(residue,0,sizeof(uint64_t)*(len+1));
        residue[0] = 0;

        int r = (len <= 8) ? 8 : ((len + 2) / 3) * 3;
        r = r * 2;

        residue[msw] = normalize ? ((uint64_t)1 << 32) : 1;
        r -= msw;

        uint64_t q[4] = {0, 0, 0, 0};

        /* Each iteration I'll left shift things 64 bits and do
         * a modular reduction.
         */
        for(i = 0; i < r; i++)
        {
            int k;
            memmove(residue + 1, residue, lenx8);
            residue[0] = 0;

            CVMX_MTM0(recip[0]);
            CVMX_MTM1(recip[1]);
            CVMX_MTM2(0);

            CVMX_V3MULU(q[0], (residue[msw] >> 32) | (residue[msw + 1] << 32), 0);
            CVMX_V3MULU(q[1],(residue[msw + 1] >> 32),0);
            CVMX_V3MULU(q[2], 0, 0);
            CVMX_V3MULU(q[3], 0, 0);

            CVMX_MTM0(q[2]);
            CVMX_MTM1(q[3]);
            CVMX_MTM2(0);

           for(k = 0; k < len + 1; k++)
                CVMX_V3MULU(residue[k], negmod[k], residue[k]);

            if(residue[len] > 1) FATAL_ERROR;
        }

        if(normalize)
        {
            if(residue[0] << 32) FATAL_ERROR;

            for(i = 0; i < len; i++)
                residue[i] = (residue[i] >> 32) | (residue[i + 1] << 32);

            residue[len] = 0;
        }

        if(len <= 8)
        {
            recip[0] = 0;
            recip[1] = 0;
#if defined(USER_SPACE_MODEXP)
            CVMX_MTM2(0);
            CVMX_MTM1(0);
#endif
            for(i = 0; i < 64; i++)
            {
                uint64_t *sub = &recip[0];
                int k;
                char undo = 0;
                *sub |= (uint64_t) 1 << (i & 63);

                CVMX_MTM0(recip[0]);
#if !defined(USER_SPACE_MODEXP)
                CVMX_MTM1(0);
                CVMX_MTM2(0);
                CVMX_V3MULU(product[0], mod[0], 1);
#else
                CVMX_MTM1(0);
                CVMX_MTM2(0);
                CVMX_V3MULU(product[0], mod[0], 1);
#endif

                for(k = 0; k < (i / 64); k++)
                    undo = undo || product[k];

                undo = undo || (product[i / 64] << (63 - (i & 63)));

                if(undo)
                    *sub ^= (uint64_t) 1 << (i & 63);
            }
        }
        else
        {
            memset(recip, 0, sizeof(recip));
            for(i = 0; i < 192; i++)
            {
                uint64_t *sub = &recip[i / 64];
                int k;
                char undo = 0;
                *sub |= (uint64_t)1 << (i & 63);

                CVMX_MTM0(recip[0]);
                CVMX_MTM1(recip[1]);
                CVMX_MTM2(recip[2]);

                CVMX_V3MULU(product[0], mod[0], 1);
                CVMX_V3MULU(product[1], mod[1], 0);
                CVMX_V3MULU(product[2], mod[2], 0);

                for(k = 0; k < (i / 64); k++)
                    undo = undo || product[k];

                undo = undo || (product[i / 64] << (63 - (i & 63)));

                if(undo)
                    *sub ^= (uint64_t)1 << (i & 63);
            }
        }

        memset(product, 0, size);

        if(len <= 8)
            MontMul576((uint64_t *)product,(uint64_t *)base,
                (uint64_t *)residue,(uint64_t *)mod,(uint64_t *)recip);
        else
            MontMul((uint64_t *)product, (uint64_t *)base,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip, len);

        memcpy(temp_base, product, lenx8);
        memset(temp, 0, size);

        temp[0] = 1;

        if(len <= 8)
            MontMul576((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip);
        else
            MontMul((uint64_t *)product, (uint64_t *)temp,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip, len);

        MMLoop(product, temp_base, exponent, mod, recip, len, elen);

        memset(residue, 0, size);

        residue[0] = 1;

        if(len <= 8)
        {
            MontMul576((uint64_t *)temp, (uint64_t *)product,
                (uint64_t *)residue, (uint64_t *)mod, (uint64_t *)recip);
        }
        else
        {
            MontMul((uint64_t *)temp, (uint64_t *)product, (uint64_t *)residue,
                (uint64_t *)mod, (uint64_t *)recip, len);
        }

        memcpy(product, temp, lenx8);

        Vsub(temp, mod, len + 1);

        if(!(temp[len] >> 63))
            memcpy(product, temp, lenx8);

        success = 1;

err:
        if(residue)    OPENSSL_free(residue);
        if(temp)       OPENSSL_free(temp);
        if(negmod)     OPENSSL_free(negmod);
        if(temp_base)  OPENSSL_free(temp_base);
    }
 else {
     int fd = oct_crypto_init();
     if (fd < 0) {
        printf("Octeon Crypto Library Kernel module[cavmodexp] not available\n");
        return OCT_FAILURE;
     }
#if _MIPS_SIM == _MIPS_SIM_NABI32
     cvm_crypto_op_t tokernel;
     tokernel.sizeofptr = sizeof (void *);
     tokernel.arg1 = (uint64_t) (uint32_t) product;
     tokernel.arg2 = (uint64_t) (uint32_t) base;
     tokernel.arg3 = (uint64_t) (uint32_t) exponent;
     tokernel.arg4 = (uint64_t) (uint32_t) mod;
     tokernel.arg5 = (uint64_t) (uint32_t) 0;      /* recip */
     tokernel.arg6 = (int64_t) len;
     tokernel.arg7 = (int64_t) elen;
     tokernel.arg8 = (int64_t) mlen;
     tokernel.arg9 = (int64_t) blen;
     success = !crypto_mult (fd, CRYPT_MODEXP, (uint64_t) (uint32_t) & tokernel);
#else
     cvm_crypto_op_t tokernel;
     tokernel.sizeofptr = sizeof (void *);
     tokernel.arg1 = (uint64_t) product;
     tokernel.arg2 = (uint64_t) base;
     tokernel.arg3 = (uint64_t) exponent;
     tokernel.arg4 = (uint64_t) mod;
     tokernel.arg5 = (uint64_t) 0; /* recip */
     tokernel.arg6 = (int64_t) len;
     tokernel.arg7 = (int64_t) elen;
     tokernel.arg8 = (int64_t) mlen;
     tokernel.arg9 = (int64_t) blen;
     success = !crypto_mult (fd, CRYPT_MODEXP, (uint64_t) & tokernel);
#endif
     close(fd);
 }

  return success;
}

static int
_crypto_modexp(uint64_t * product, uint64_t * base, uint64_t * exponent,
    uint64_t * mod, int len, int elen, int mlen, int blen, int convert)
{

    if(OCTEON_IS_OCTEON3()) {
        return crypto_modexp_octeon3(product, base, exponent, mod,
                            len, elen, mlen, blen, convert);
    } else {
        return crypto_modexp_octeon2(product, base, exponent, mod,
                    len, elen, mlen, blen, convert);
    }
}

static int
crypto_modexp (uint64_t * product, uint64_t * base, uint64_t * exponent,
  uint64_t * mod, int len, int elen, int mlen, int blen)
{
    return _crypto_modexp(product, base, exponent, mod, len, elen, mlen, blen, 0);
}

static int
oct_mod_exp_internal(BIGNUM *res, BIGNUM *base, BIGNUM *exp, BIGNUM *mod, BN_CTX * ctx)
{
    uint8_t* copy_base = NULL;
    uint8_t* copy_exp = NULL;
    uint8_t* copy_mod = NULL;
    int ret = OCT_FAILURE; 
    int len, mlen, elen, blen;
 
    copy_base = (uint8_t *)OPENSSL_malloc((ROUNDUP2(mod->top) + MUL_PAD) * 8);
    copy_exp  = (uint8_t *)OPENSSL_malloc((ROUNDUP2(mod->top) + MUL_PAD) * 8);
    copy_mod  = (uint8_t *)OPENSSL_malloc((ROUNDUP2(mod->top) + MUL_PAD) * 8);
     
    if(copy_base == NULL || copy_exp == NULL || copy_mod == NULL) 
         goto  modexp_err;
 
    memset(copy_base, 0, (ROUNDUP2(mod->top) + MUL_PAD) * 8);
    memset(copy_exp,  0, (ROUNDUP2(mod->top) + MUL_PAD) * 8);
    memset(copy_mod,  0, (ROUNDUP2(mod->top) + MUL_PAD) * 8);

    memcpy(copy_exp,  exp->d,  exp->top  * sizeof (BN_ULONG));
    memcpy(copy_mod,  mod->d,  mod->top  * sizeof (BN_ULONG));
    memcpy(copy_base, base->d, base->top * sizeof (BN_ULONG));

    if (bn_wexpand(res, mod->dmax + MUL_PAD) == NULL)
        goto modexp_err;

    memset(res->d, 0, (mod->dmax + MUL_PAD) * sizeof(BN_ULONG));

    mlen = ROUNDUP8(mod->top  * sizeof (BN_ULONG));
    elen = ROUNDUP8(exp->top  * sizeof (BN_ULONG));
    blen = ROUNDUP8(base->top * sizeof (BN_ULONG));
    len  = ((((mod->top * sizeof(BN_ULONG)) * 8) + 63) / 64);


    #if _MIPS_SIM == _MIPS_SIM_NABI32
    /* Convert all input data to format specific to crypto kernel module */
    convert_bn32_to_hw(copy_base, blen);
    convert_bn32_to_hw(copy_exp, elen);
    convert_bn32_to_hw(copy_mod, mlen);
    #endif
 
    ret = crypto_modexp((uint64_t*)res->d, (uint64_t*)copy_base,
                         (uint64_t*)copy_exp, (uint64_t*)copy_mod,
                         len, elen, mlen, blen);
     
    if (ret != OCT_SUCCESS)
        goto modexp_err;
 
    #if _MIPS_SIM == _MIPS_SIM_NABI32
     convert_hw_to_bn32((uint8_t *)res->d, mlen);
    #endif
 
    res->top = mod->top;
    ret = OCT_SUCCESS; // Success

modexp_err:
    if (ret  == OCT_FAILURE) 
        printf("cav_mod_exp error !\n");
    if (copy_base)        OPENSSL_free(copy_base);
    if (copy_exp)         OPENSSL_free(copy_exp);
    if (copy_mod)         OPENSSL_free(copy_mod);
    return ret;
}

/* This code is obtained from crypto component's ModExp */
int oct_mod_exp(BIGNUM *r, BIGNUM *a, BIGNUM *p, BIGNUM *m, BN_CTX *ctx)
{
    
    BIGNUM *pdash,*mdash;
    int ret;
    
    bn_check_top (a);
    bn_check_top (p);
    bn_check_top (m);

    pdash = BN_new();
    mdash = BN_new();

    if (!pdash || !mdash) {
        if(pdash) BN_free(pdash);
        if(mdash) BN_free(mdash);
        /* return error */
        return OCT_FAILURE;
    }

    if(!BN_sub(mdash, m, BN_value_one())) {
        BN_free(pdash);
        BN_free(mdash);
        return OCT_FAILURE;       
    }

    if(!BN_div(NULL, pdash, p, mdash, ctx)) {
        BN_free(pdash);
        BN_free(mdash);
        return OCT_FAILURE;
    }

    ret = oct_mod_exp_internal(r, a, pdash, m, ctx);

    BN_free(pdash);
    BN_free(mdash);
    return ret;  
}

/*
   CRT Algorithm:
   m1 = c^dP mod p
   m2 = c^dQ mod q
   h = qInv(m1 - m2) mod p
   m = m2 + hq
 */
int
_crypto_modexp_crt (uint64_t * product, uint64_t * base,
  cvm_rsa_key_t * rkey, int nonwalign, int convert)
{
    int retc=1; 
#if !defined(TARGET_LINUX) || defined(USER_SPACE_MODEXP)
    if(1)
#else
    if(!cvm_crypto_vmul_hwbug())
#endif
    {
        uint64_t *mod1 = NULL;
        uint64_t *mod2 = NULL;
        uint64_t *tmp = NULL;
        int len = (rkey->len + 1) / 2, size = 0, tmpsize;
        int wlen = (rkey->len / 2) >> 3;      // length in (8 byte) words
        int blen = rkey->len >> 3;
        int wlen1;

        len = len << 3;
        if(nonwalign)
        {
            wlen++;
            blen += 2;                  //zero extended in case of non 8B 
        }
        else if(rkey->len % 16)
        {
            wlen++;
            blen += 2;                  //zero extended in case of non 8B 
        }

        size    = (blen * 8) + MODEXP_GUARD;
        tmpsize = (blen * 24);

        mod1 = (uint64_t *)OPENSSL_malloc(size);
        mod2 = (uint64_t *)OPENSSL_malloc(size);
        tmp  = (uint64_t *)OPENSSL_malloc(tmpsize);

        if(mod1 == NULL || mod2 == NULL || tmp == NULL)
            goto err;

        /* First do modular reduction */
        ModReduce(tmp, base, blen, rkey->p, wlen);

        if(crypto_modexp(mod1, tmp, rkey->expp, rkey->p, (len + 63) / 64,
            rkey->eplen * 8, rkey->len, wlen * 8) <= 0)
        {
            return 0;
        }

        /* Same procedure for second round */
        wlen1 = find_msw (rkey->q);
        ModReduce(tmp, base, blen, rkey->q, wlen1);
        if(crypto_modexp (mod2, tmp, rkey->expq, rkey->q, (len + 63) / 64,
            rkey->eqlen * 8, rkey->len, wlen * 8) <= 0)
        {
            return 0;
        }

        if(VCmp (mod1, mod2, wlen) < 0)
        {
            memcpy(tmp, mod2, wlen * sizeof (uint64_t));
            Vsub(tmp, mod1, wlen);
            /* Since it is negative, add p to make it positive ?? */
            if(VCmp(rkey->p, tmp, wlen) < 0)
            {
                /* p is less than tmp, so a single correction will not make it
                   positive */
                memcpy (mod1, rkey->p, wlen * sizeof (uint64_t));
                Vadd(mod1, rkey->p, wlen);

                mod1[wlen + 1] = 0;
                tmp[wlen] = 0;

                Vsub(mod1, tmp, wlen + 1);
            }
            else
            {
                memcpy (mod1, rkey->p, wlen * sizeof (uint64_t));
                mod1[wlen] = 0;
                tmp[wlen] = 0;

                Vsub(mod1, tmp, wlen + 1);
            }
        }
        else
        {
            Vsub(mod1, mod2, wlen);
        }

        /* zero off any higher bytes that might have been set during
         * mod operations
         */
        memset(&mod1[wlen], 0, wlen * sizeof (uint64_t));
        memset(&mod2[wlen], 0, wlen * sizeof (uint64_t));

        VMul(product, mod1, rkey->coeff, wlen);

        ModReduce(tmp, product, wlen * 2, rkey->p, wlen);

        /* Multiply tmp & rkey->q and put result in product */
        VMul(product, tmp, rkey->q, wlen);

        /* Assuming Vadd needs length in words */
        Vadd(product, mod2, wlen * 2);

err:
        if(mod1)
          OPENSSL_free(mod1);
        if(mod2)
          OPENSSL_free(mod2);
        if(tmp)
          OPENSSL_free(tmp);
    }
#if defined(TARGET_LINUX)
  else {
     if (cryptfd <= 0) {
       retc = crypto_init ();
       if (retc <= 0) {
       #ifdef PRINT_DEBUG
         printf ("Create device /dev/octcrypto \n");
       #endif
        return 0;
       }
     }
#if _MIPS_SIM == _MIPS_SIM_NABI32
     cvm_crypto_op_t tokernel;
     tokernel.sizeofptr = sizeof (void *);
     tokernel.arg1 = (uint64_t) (uint32_t) product;
     tokernel.arg2 = (uint64_t) (uint32_t) base;
     tokernel.arg3 = (uint64_t) (uint32_t) rkey;
     tokernel.arg6 = (int64_t) nonwalign;
     //ioctl on success returns 0
     crypto_mult (CRYPT_MODEXPCRT, (uint64_t) (uint32_t) & tokernel);
#else
     cvm_crypto_op_t tokernel;
     tokernel.sizeofptr = sizeof (void *);
     tokernel.arg1 = (uint64_t) product;
     tokernel.arg2 = (uint64_t) base;
     tokernel.arg3 = (uint64_t) rkey;
     tokernel.arg6 = (int64_t) nonwalign;
     //ioctl on success returns 0
     crypto_mult (CRYPT_MODEXPCRT, (uint64_t) & tokernel);

#endif
  }
#endif
  return retc;
}

static int
crypto_modexp_crt (uint64_t * product, uint64_t * base,
  cvm_rsa_key_t * rkey, int nonwalign)
{
  return _crypto_modexp_crt (product, base, rkey, nonwalign, 0);
}

int oct_mod_exp_crt(BIGNUM *res, BIGNUM *base, RSA *rsa)
{
   cvm_rsa_key_t rkey;
   uint8_t *tmpbase = NULL;
   int num, ret = OCT_FAILURE;

   rsa_to_cry_private(rsa, &rkey);
   num = BN_num_bytes(rsa->n);
   if (bn_wexpand(res, rsa->n->dmax + MUL_PAD) == NULL) {
      goto modexp_crt_err;
   }
   tmpbase = (uint8_t *) OPENSSL_malloc((base->top + MUL_PAD) * 8);
   if (tmpbase == NULL)
      goto modexp_crt_err;
   memset(tmpbase, 0, (base->top + MUL_PAD) * 8);
   memcpy(tmpbase, base->d, base->top * sizeof (BN_ULONG));
#if _MIPS_SIM == _MIPS_SIM_NABI32
     convert_bn32_to_hw ((uint8_t *) tmpbase, ROUNDUP8 (rkey.len));
     /* Converting rkey to H/W specific format */
     convert_bn32_to_hw ((uint8_t *) (rkey.expp),
                          rkey.eplen * sizeof (BN_ULONG));
     convert_bn32_to_hw ((uint8_t *) (rkey.expq),
                         rkey.eqlen * sizeof (BN_ULONG));
    /* eplen, eqlen should be 8-byte words for Octeon ModExp in Kernel */
     rkey.eplen = (rkey.eplen + 1) * sizeof (BN_ULONG) / 8;
     rkey.eqlen = (rkey.eqlen + 1) * sizeof (BN_ULONG) / 8;
     convert_bn32_to_hw ((uint8_t *) (rkey.p), rkey.len);
     convert_bn32_to_hw ((uint8_t *) (rkey.q), rkey.len);
     convert_bn32_to_hw ((uint8_t *) (rkey.coeff), rkey.len);
#endif
     ret = crypto_modexp_crt((uint64_t *)res->d, (uint64_t *)tmpbase, &rkey, num % 8);
     if (ret != OCT_SUCCESS) {
        goto modexp_crt_err;
     }
#if _MIPS_SIM == _MIPS_SIM_NABI32
     convert_hw_to_bn32 ((uint8_t *)res->d, rkey.len);
#endif
     res->top = rsa->n->top;
    ret = OCT_SUCCESS;
   
modexp_crt_err:
   if (tmpbase)
      OPENSSL_free(tmpbase);
    rsa_cry_private_free(&rkey);

   return ret;
}
