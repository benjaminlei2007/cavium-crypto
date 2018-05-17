/*
 * Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
 * Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
 * denoted as "the implementer".
 *
 * For more information, feedback or questions, please refer to our websites:
 * http://keccak.noekeon.org/
 * http://keyak.noekeon.org/
 * http://ketje.noekeon.org/
 *
 * To the extent possible under law, the implementer has waived all copyright
 * and related or neighboring rights to the source code in this file.
 * http://creativecommons.org/publicdomain/zero/1.0/
 * */


#include <openssl/sha.h>
int SHA3_Sw_Init(SHA3_CTX* ctx, int sha3_variant)
{
    uint32_t capacity, rate, result;



    if(!ctx || sha3_variant == 0) return 0;

    memset(ctx, 0, sizeof *ctx);

    switch(sha3_variant)
    {
        case KECCAK_TYPE_SHA3_224:
            capacity = SHA3_224_BITLEN*2;
            rate = SnP_width - capacity;
            result = Keccak_spongeinitialization(&ctx->sponge,rate,capacity);
            if (result != 0)
                return result;
            ctx->fixedOutputLength = SHA3_224_BITLEN;
            ctx->delimitedSuffix = SHA3_DelimitedSuffix;
            break;
        case KECCAK_TYPE_SHA3_256:
            capacity = SHA3_256_BITLEN*2;
            rate = SnP_width - capacity;
            result = Keccak_spongeinitialization(&ctx->sponge,rate,capacity);
            if (result != 0)
                return result;
            ctx->fixedOutputLength = SHA3_256_BITLEN;
            ctx->delimitedSuffix = SHA3_DelimitedSuffix;
            break;
        case KECCAK_TYPE_SHA3_384:
            capacity = SHA3_384_BITLEN*2;
            rate = SnP_width - capacity;
            result = Keccak_spongeinitialization(&ctx->sponge,rate,capacity);
            if (result != 0)
                return result;
            ctx->fixedOutputLength = SHA3_384_BITLEN;
            ctx->delimitedSuffix = SHA3_DelimitedSuffix;
            break;
        case KECCAK_TYPE_SHA3_512:
            capacity = SHA3_512_BITLEN*2;
            rate = SnP_width - capacity;
            result = Keccak_spongeinitialization(&ctx->sponge,rate,capacity);
            if (result != 0)
                return result;
            ctx->fixedOutputLength = SHA3_512_BITLEN;
            ctx->delimitedSuffix = SHA3_DelimitedSuffix;
            break;
        default:
            return -1;
    }
    return 0;

}
/* size should be in byte length of data */
int SHA3_Sw_Update(SHA3_CTX* ctx,const void* data,unsigned long n)
{
    if((n*8) % 8 == 0)
        return Keccak_SpongeAbsorb(&ctx->sponge, (const unsigned char*)data, n);

    else
    {
        int ret = Keccak_SpongeAbsorb(&ctx->sponge, (const unsigned char*)data, n);
        if (ret == 0) {
            // The last partial byte is assumed to be aligned on the least significant bits
            unsigned char lastByte = *((uint8_t*)data+n);
            // Concatenate the last few bits provided here with those of the suffix
            unsigned short delimitedLastBytes = (unsigned short)lastByte | ((unsigned short)ctx->delimitedSuffix << ((n*8) % 8));
            if ((delimitedLastBytes & 0xFF00) == 0x0000) {
                ctx->delimitedSuffix = delimitedLastBytes & 0xFF;
            }
            else {
                unsigned char oneByte[1];
                oneByte[0] = delimitedLastBytes & 0xFF;
                ret = Keccak_SpongeAbsorb(&ctx->sponge, oneByte, 1);
                ctx->delimitedSuffix = (delimitedLastBytes >> 8) & 0xFF;
            }
        }
        return ret;
    }

}

int SHA3_Sw_Final(uint8_t* hash, SHA3_CTX* ctx)
{
    int ret = Keccak_SpongeAbsorbLastFewBits(&ctx->sponge, 
                                                    ctx->delimitedSuffix);
    if (ret == 0)
        return Keccak_SpongeSqueeze(&ctx->sponge, hash, 
                                                ctx->fixedOutputLength/8);
    else
        return ret;

    return 0;
}
