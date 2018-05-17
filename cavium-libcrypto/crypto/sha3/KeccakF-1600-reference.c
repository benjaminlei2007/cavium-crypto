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


#define nrRounds 24
uint64_t KeccakRoundConstants[nrRounds];
#define nrLanes 25
unsigned int KeccakRhoOffsets[nrLanes];
#define ROL64(a, offset) ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset)))
#define    cKeccakNumberOfRounds    24
const uint8_t KeccakF_RotationConstants[25] =
{
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14, 27, 41, 56,  8, 25,
     43, 62, 18, 39, 61, 20, 44
};

const uint8_t KeccakF_PiLane[25] =
{
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4, 15, 23, 19, 13, 12,
    2, 20, 14, 22,  9,  6,  1
};

#if    defined(DIVISION_INSTRUCTION)
#define    MOD5(argValue)    ((argValue) % 5)
#else
const uint8_t KeccakF_Mod5[10] =
{
    0, 1, 2, 3, 4, 0, 1, 2, 3, 4
};
#define    MOD5(argValue)    KeccakF_Mod5[argValue]
#endif

uint64_t KeccakF1600_GetNextRoundConstant( uint8_t *LFSR )
{
    uint32_t i;
    uint64_t    roundConstant;
    uint32_t doXOR;
    uint32_t tempLSFR;

    roundConstant = 0;
    tempLSFR = *LFSR;
    for(i=1; i<128; i <<= 1)
    {
        doXOR = tempLSFR & 1;
        if ((tempLSFR & 0x80) != 0)
            // Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1
            tempLSFR = (tempLSFR << 1) ^ 0x71;
        else
            tempLSFR <<= 1;

        if ( doXOR != 0 )
            roundConstant ^= (uint64_t)1ULL << (i - 1);
    }
    *LFSR = (uint8_t)tempLSFR;
    return ( roundConstant );
}
#define index(x, y) (((x)%5)+5*((y)%5))

void KeccakF1600_StateInitialize(void *state)
{
        memset(state, 0, 200);
}

void KeccakF1600_StateOverwriteWithZeroes(void *argState, 
        unsigned int byteCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memset((unsigned char*)argState, 0, byteCount);
#else
    uint64_t *state = (uint64_t*)argState;
    unsigned int i, j;
    for(i=0; i<byteCount/8; i++)
        state[i] = 0;
    for(j=0; j<byteCount%8; j++)
        state[i] &= ~(((uint64_t)0xFF) << (j*8));
#endif

}



void KeccakF1600_StateComplementBit(void *state, unsigned int position)
{
    uint64_t lane = (uint64_t)1 << (position%64);
    ((uint64_t*)state)[position/64] ^= lane;

}


void KeccakP1600_StatePermute(void *argState, uint8_t rounds, 
        uint8_t LFSRinitialState)
{
    uint32_t x, y, round;
    uint64_t        temp;
    uint64_t        BC[5];
    uint64_t     *state;
    uint8_t           LFSRstate;

    state = (uint64_t*)argState;
    LFSRstate = LFSRinitialState;
    round = rounds;
    do
    {
        // Theta
        for ( x = 0; x < 5; ++x )
        {
            BC[x] = state[x] ^ state[5 + x] ^ state[10 + x] ^ state[15 + x] ^ state[20 + x];
        }
        for ( x = 0; x < 5; ++x )
        {
            temp = BC[MOD5(x+4)] ^ ROL64(BC[MOD5(x+1)], 1);
            for ( y = 0; y < 25; y += 5 )
            {
                state[y + x] ^= temp;
            }
        }

        // Rho Pi
        temp = state[1];
        for ( x = 0; x < 24; ++x )
        {
            BC[0] = state[KeccakF_PiLane[x]];
            state[KeccakF_PiLane[x]] = ROL64( temp, KeccakF_RotationConstants[x] );
            temp = BC[0];
        }

        //    Chi
        for ( y = 0; y < 25; y += 5 )
        {
#if defined(UNROLL_CHILOOP)
            BC[0] = state[y + 0];
            BC[1] = state[y + 1];
            BC[2] = state[y + 2];
            BC[3] = state[y + 3];
            BC[4] = state[y + 4];
#else
            for ( x = 0; x < 5; ++x )
            {
                BC[x] = state[y + x];
            }
#endif
            for ( x = 0; x < 5; ++x )
            {
                state[y + x] = BC[x] ^((~BC[MOD5(x+1)]) & BC[MOD5(x+2)]);
            }
        }

        //    Iota
        state[0] ^= KeccakF1600_GetNextRoundConstant(&LFSRstate);
    }
    while( --round != 0 );
}

void KeccakF1600_StatePermute(void *argState)
{
    KeccakP1600_StatePermute(argState, cKeccakNumberOfRounds, 0x01);
}

void fromBytesToWords(uint64_t *stateAsWords, const unsigned char *state)
{
    unsigned int i, j;

    for(i=0; i<nrLanes; i++) {
        stateAsWords[i] = 0;
        for(j=0; j<(64/8); j++)
            stateAsWords[i] |= (uint64_t)(state[i*(64/8)+j]) << (8*j);
    }
}

void fromWordsToBytes(unsigned char *state, const uint64_t *stateAsWords)
{
    unsigned int i, j;

    for(i=0; i<nrLanes; i++)
        for(j=0; j<(64/8); j++)
            state[i*(64/8)+j] = (stateAsWords[i] >> (8*j)) & 0xFF;
}
#if 0
void KeccakF1600OnWords(uint64_t *state)
{
    unsigned int i;

    for(i=0; i<nrRounds; i++)
        KeccakF1600Round(state, i);
}

void KeccakF1600Round(uint64_t *state, unsigned int indexRound)
{
    displayRoundNumber(3, indexRound);

    theta(state);

    rho(state);

    pi(state);

    chi(state);

    iota(state, indexRound);
}


void theta(uint64_t *A)
{
    unsigned int x, y;
    uint64_t C[5], D[5];

    for(x=0; x<5; x++) {
        C[x] = 0;
        for(y=0; y<5; y++)
            C[x] ^= A[index(x, y)];
    }
    for(x=0; x<5; x++)
        D[x] = ROL64(C[(x+1)%5], 1) ^ C[(x+4)%5];
    for(x=0; x<5; x++)
        for(y=0; y<5; y++)
            A[index(x, y)] ^= D[x];
}

void rho(uint64_t *A)
{
    unsigned int x, y;

    for(x=0; x<5; x++) for(y=0; y<5; y++)
        A[index(x, y)] = ROL64(A[index(x, y)], KeccakRhoOffsets[index(x, y)]);
}

void pi(uint64_t *A)
{
    unsigned int x, y;
    uint64_t tempA[25];

    for(x=0; x<5; x++) for(y=0; y<5; y++)
        tempA[index(x, y)] = A[index(x, y)];
    for(x=0; x<5; x++) for(y=0; y<5; y++)
        A[index(0*x+1*y, 2*x+3*y)] = tempA[index(x, y)];
}

void chi(uint64_t *A)
{
    unsigned int x, y;
    uint64_t C[5];

    for(y=0; y<5; y++) {
        for(x=0; x<5; x++)
            C[x] = A[index(x, y)] ^ ((~A[index(x+1, y)]) & A[index(x+2, y)]);
        for(x=0; x<5; x++)
            A[index(x, y)] = C[x];
    }
}

void iota(uint64_t *A, unsigned int indexRound)
{
    A[index(0, 0)] ^= KeccakRoundConstants[indexRound];
}
#endif
void KeccakF1600_StateExtractBytes(const void *state, unsigned char *data, 
        unsigned int offset, unsigned int length)
{
    memcpy(data, (unsigned char*)state+offset, length);
}

void KeccakF1600_StateExtractAndXORBytes(const void *state, 
        unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int i;

    for(i=0; i<length; i++)
        data[i] ^= ((unsigned char *)state)[offset+i];
}

void KeccakF1600_StateXORLanes(void *state, const unsigned char *data, 
        unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    uint32_t i;
    laneCount *= sizeof(uint64_t);
    for( i = 0; i < laneCount; ++i) {
        ((unsigned char*)state)[i] ^= data[i];
    }
#else
    uint32_t i;
    const uint8_t *curData = data;
    for(i=0; i<laneCount; i++, curData+=8) {
        uint64_t lane = (uint64_t)curData[0] 
            | ((uint64_t)curData[1] << 8)
            | ((uint64_t)curData[2] << 16)
            | ((uint64_t)curData[3] << 24)
            | ((uint64_t)curData[4] << 32)
            | ((uint64_t)curData[5] << 40)
            | ((uint64_t)curData[6] << 48)
            | ((uint64_t)curData[7] << 56);
        ((uint64_t*)state)[i] ^= lane;
    }
#endif
}

void KeccakF1600_StateXORBytesInLane(void *argState, unsigned int lanePosition,
        const unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int i;
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    unsigned char * state = (unsigned char*)argState + 
                            lanePosition * sizeof(uint64_t) + offset;
    for(i=0; i<length; i++)
        ((unsigned char *)state)[i] ^= data[i];
#else
    uint64_t lane = 0;
    for(i=0; i<length; i++)
        lane |= ((uint64_t)data[i]) << ((i+offset)*8);
    ((uint64_t*)argState)[lanePosition] ^= lane;
#endif
}
void KeccakF1600_StateExtractLanes(const void *state, unsigned char *data,
        unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memcpy(data, state, laneCount*8); 
#else
    uint32_t i, j;
    for(i=0; i<laneCount; i++) 
    {
        for(j=0; j<(64/8); j++)
        {
            data[(i*8)+j] = (((const uint64_t*)state)[i] >> (8*j)) & 0xFF;
        }
    }
#endif 
}

void KeccakF1600_StateExtractBytesInLane(const void *state, 
        unsigned int lanePosition, unsigned char *data, unsigned int offset,
        unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memcpy(data, ((uint8_t*)&((uint64_t*)state)[lanePosition])+offset, length);
#else
    uint32_t i;
    uint64_t lane = ((uint64_t*)state)[lanePosition];
    lane >>= offset*8;
    for(i=0; i<length; i++) {
        data[i] = lane & 0xFF;
        lane >>= 8;
    }   
#endif
}

void KeccakF1600_StateExtractAndXORLanes(const void *state,
        unsigned char *data, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    uint32_t i;
    for(i=0; i<laneCount; i++)
        ((uint64_t*)data)[i] ^= ((const uint64_t*)state)[i];
#else
    uint32_t i, j;
    for(i=0; i<laneCount; i++)
    {
        for(j=0; j<(64/8); j++)
        {
            data[(i*8)+j] ^= (((const uint64_t*)state)[i] >> (8*j)) & 0xFF;
        }
    }
#endif
}

void KeccakF1600_StateExtractAndXORBytesInLane(const void *state, 
        unsigned int lanePosition, unsigned char *data, unsigned int offset,
        unsigned int length)
{
    uint32_t i;
    uint64_t lane = ((uint64_t*)state)[lanePosition];
    lane >>= offset*8;
    for(i=0; i<length; i++) {
        data[i] ^= lane & 0xFF;
        lane >>= 8;
    }
}


void displayRoundConstants(FILE *f)
{
    unsigned int i;

    for(i=0; i<nrRounds; i++) {
        fprintf(f, "RC[%02i][0][0] = ", i);
        fprintf(f, "%08X", (unsigned int)(KeccakRoundConstants[i] >> 32));
        fprintf(f, "%08X", (unsigned int)(KeccakRoundConstants[i] & 0xFFFFFFFFULL));
        fprintf(f, "\n");
    }
    fprintf(f, "\n");
}

void displayRhoOffsets(FILE *f)
{
    unsigned int x, y;

    for(y=0; y<5; y++) for(x=0; x<5; x++) {
        fprintf(f, "RhoOffset[%i][%i] = ", x, y);
        fprintf(f, "%2i", KeccakRhoOffsets[index(x, y)]);
        fprintf(f, "\n");
    }
    fprintf(f, "\n");
}
