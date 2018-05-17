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

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
int Keccak_spongeinitialization(Keccak_SpongeInstance* sponge_instance, 
        uint32_t rate, uint32_t capacity)
{
    if (rate+capacity != SnP_width)
        return 1;
    if ((rate <= 0) || (rate > SnP_width) || ((rate % 8) != 0))
        return 1;
    //KeccakF1600_Initialize();
    KeccakF1600_StateInitialize(sponge_instance->state);
    sponge_instance->rate = rate;
    sponge_instance->byteIOIndex = 0;
    sponge_instance->squeezing = 0;

    return 0;
}


int Keccak_SpongeAbsorb(Keccak_SpongeInstance *instance, 
        const unsigned char *data, unsigned long dataByteLen)
{
    size_t i, j;
    unsigned int partialBlock;
    const unsigned char *curData;
    unsigned int rateInBytes = instance->rate/8;

    if (instance->squeezing)
        return 1; // Too late for additional input

    i = 0;
    curData = data;
    while(i < dataByteLen)
    {
        if ((instance->byteIOIndex == 0) && (dataByteLen >= (i + rateInBytes)))
        {
            // processing full blocks first
            if ((rateInBytes % KeccakF_laneInBytes) == 0)
            {
                // fast lane: whole lane rate
                j = SnP_FBWL_Absorb(instance->state, 
                        rateInBytes/KeccakF_laneInBytes, 
                        curData, dataByteLen - i, 0);
                i += j;
                curData += j;
            }
            else {
                for(j=dataByteLen-i; j>=rateInBytes; j-=rateInBytes) {
                    SnP_XORBytes(instance->state, curData, 0, rateInBytes);
                    SnP_Permute(instance->state);
                    curData+=rateInBytes;
                }
                i = dataByteLen - j;
            }
        }
        else {
            // normal lane: using the message queue
            partialBlock = (unsigned int)(dataByteLen - i);
            if (partialBlock+instance->byteIOIndex > rateInBytes)
                partialBlock = rateInBytes-instance->byteIOIndex;

            i += partialBlock;

            SnP_XORBytes(instance->state, curData, instance->byteIOIndex, 
                            partialBlock);
            curData += partialBlock;
            instance->byteIOIndex += partialBlock;
            if (instance->byteIOIndex == rateInBytes) {
                SnP_Permute(instance->state);
                instance->byteIOIndex = 0;
            }
        }
    }
    return 0;
}

int Keccak_SpongeAbsorbLastFewBits(Keccak_SpongeInstance *instance, 
        unsigned char delimitedData)
{
    unsigned char delimitedData1[1];
    unsigned int rateInBytes = instance->rate/8;

    if (delimitedData == 0)
        return 1;
    if (instance->squeezing)
        return 1; // Too late for additional input

    delimitedData1[0] = delimitedData;
    SnP_XORBytes(instance->state, delimitedData1, 
            instance->byteIOIndex, 1);
    // If the first bit of padding is at position rate-1, we need a whole new block for the second bit of padding
         if ((delimitedData >= 0x80) && 
                 (instance->byteIOIndex == (rateInBytes-1)))
                 SnP_Permute(instance->state);
     // Second bit of padding

         SnP_ComplementBit(instance->state, rateInBytes*8-1);

         SnP_Permute(instance->state);
         instance->byteIOIndex = 0;
         instance->squeezing = 1;
         return 0;
}

int Keccak_SpongeSqueeze(Keccak_SpongeInstance *instance, 
        unsigned char *data, size_t dataByteLen)
{
    size_t i, j;
    unsigned int partialBlock;
    unsigned int rateInBytes = instance->rate/8;
    unsigned char *curData;

    if (!instance->squeezing)
        Keccak_SpongeAbsorbLastFewBits(instance, 0x01);

    i = 0;
    curData = data;
    while(i < dataByteLen)
    {
        if ((instance->byteIOIndex == rateInBytes) && 
                (dataByteLen >= (i + rateInBytes)))
        {
        // processing full blocks first
              if ((rateInBytes % KeccakF_laneInBytes) == 0)
              {
                     // fast lane: whole lane rate
                  j = SnP_FBWL_Squeeze(instance->state, 
                                       rateInBytes/KeccakF_laneInBytes,
                                       curData, 
                                       dataByteLen - i);
                  i += j;
                  curData += j;
              }
              else
              {
                  for(j=dataByteLen-i; j>=rateInBytes; j-=rateInBytes)
                  {
                      SnP_Permute(instance->state);
                      SnP_ExtractBytes(instance->state, curData, 0,
                                        rateInBytes);
                      curData+=rateInBytes;
                  }
                  i = dataByteLen - j;
              }
        }
        else {
            if (instance->byteIOIndex == rateInBytes) {
                SnP_Permute(instance->state);
                instance->byteIOIndex = 0;
            }
            partialBlock = (unsigned int)(dataByteLen - i);
            if (partialBlock+instance->byteIOIndex > rateInBytes)
                partialBlock = rateInBytes-instance->byteIOIndex;
            i += partialBlock;

            SnP_ExtractBytes(instance->state, curData, 
                             instance->byteIOIndex, 
                             partialBlock);
            curData += partialBlock;
            instance->byteIOIndex += partialBlock;
        }
    }
    return 0;
}
