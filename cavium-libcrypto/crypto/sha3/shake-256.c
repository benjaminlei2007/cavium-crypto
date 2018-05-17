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



#include "sha.h"


int SHAKE_256_init(SHAKE_CTX* ctx)
{
    uint32_t capacity = SHAKE_256_SECURITY_STRENGTH*2;
    uint32_t rate = SnP_width - capacity;
    int result = Keccak_spongeinitialization(&ctx->sponge,rate,capacity);
    if (result != 0)
        return result;
    ctx->fixedOutputLength = SHAKE_256_BITLEN;
    ctx->delimitedSuffix = SHAKE_DelimitedSuffix;
    return 0;
}


/* size should be in bit length of data */
int SHAKE_256_Update(SHAKE_CTX* ctx,uint8_t* data,uint32_t size)
{
    if(size % 8 == 0)
        return Keccak_SpongeAbsorb(&ctx->sponge, data, size/8);
    else
    {
        int ret = Keccak_SpongeAbsorb(&ctx->sponge, data, size/8);
        if (ret == 0) {
            // The last partial byte is assumed to be aligned on the least significant bits
            unsigned char lastByte = data[size/8];
            // Concatenate the last few bits provided here with those of the suffix
            unsigned short delimitedLastBytes = (unsigned short)lastByte | ((unsigned short)ctx->delimitedSuffix << (size % 8));
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

int SHAKE_256_Final(SHAKE_CTX* ctx,uint8_t* hash,uint32_t squeezedoutputlength)
{
    int ret = Keccak_SpongeAbsorbLastFewBits(&ctx->sponge, 
                                              ctx->delimitedSuffix);
    if (ret == 0)
        Keccak_SpongeSqueeze(&ctx->sponge, hash, 
                             ctx->fixedOutputLength/8);
/* Pass squeezedoutputlength in bit format */
    ret = shake_256_HashSqueeze(ctx, hash, squeezedoutputlength*8);
    if(ret < 0)
        return ret;

    return 0;
}
int shake_256_HashSqueeze(SHAKE_CTX *ctx, uint8_t *data, 
        uint32_t databitlen)
{
    if ((databitlen % 8) != 0)
        return -1;
    return Keccak_SpongeSqueeze(&ctx->sponge, data, databitlen/8);
}
