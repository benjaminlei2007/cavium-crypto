#ifndef _SHA3_H_
#define _SHA3_H_
 
#define KECCAK_SUPPORT
#ifdef KECCAK_SUPPORT

#define KECCAK_RATE_MAX			(18)
#define KECCAK_RATE_MAX_BYTES		(144)

#define KECCAK_TYPE_SHA3_224			1
#define KECCAK_TYPE_SHA3_256			2
#define KECCAK_TYPE_SHA3_384			3
#define KECCAK_TYPE_SHA3_512			4


#define SHA3_SW_SUPPORT           1
#define SHA3_HW_SUPPORT           0
#if (SHA3_MODE == SHA3_SW_SUPPORT)
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#endif

#if (SHA3_MODE == SHA3_SW_SUPPORT)
#define STATE_MAX_SIZE                      1600

#define SHA3_512_BITLEN                     512

#define SHA3_384_BITLEN                     384
#define SHA3_256_BITLEN                     256
#define SHA3_224_BITLEN                     224
#define SHAKE_256_BITLEN                    0
#define SHAKE_128_BITLEN                    0
#define SHAKE_256_SECURITY_STRENGTH         256
#define SHAKE_128_SECURITY_STRENGTH         128

#define SHA3_DelimitedSuffix                0x06
#define SHAKE_DelimitedSuffix               0x1F

#define KeccakF_width                       1600
#define KeccakF_laneInBytes                 8
#define KeccakF_stateSizeInBytes            (KeccakF_width/8)
#define SnP_width                           KeccakF_width
#define SnP_stateSizeInBytes                KeccakF_stateSizeInBytes
#define SnP_laneLengthInBytes               KeccakF_laneInBytes
#define SnP_laneCount                       25

#define SnP_StaticInitialize                KeccakF1600_Initialize
#define SnP_Initialize                      KeccakF1600_StateInitialize
#define SnP_OverwriteWithZeroes             KeccakF1600_StateOverwriteWithZeroes
#define SnP_ComplementBit                   KeccakF1600_StateComplementBit
#define SnP_Permute                         KeccakF1600_StatePermute

#define SnP_FBWL_Absorb                     SnP_FBWL_Absorb_Default
#define SnP_FBWL_Squeeze                    SnP_FBWL_Squeeze_Default
#define SnP_FBWL_Wrap                       SnP_FBWL_Wrap_Default
#define SnP_FBWL_Unwrap                     SnP_FBWL_Unwrap_Default
#define SnP_XORLanes                        KeccakF1600_StateXORLanes
#define SnP_XORBytesInLane                  KeccakF1600_StateXORBytesInLane
#define SnP_ExtractLanes                    KeccakF1600_StateExtractLanes
#define SnP_ExtractAndXORBytesInLane        KeccakF1600_StateExtractAndXORBytesInLane
#define SnP_ExtractAndXORLanes              KeccakF1600_StateExtractAndXORLanes
#define SnP_ExtractBytesInLane              KeccakF1600_StateExtractBytesInLane

#define SnP_XORBytes(state, data, offset, length) \
    { \
        if ((offset) == 0) { \
            SnP_XORLanes(state, data, (length)/SnP_laneLengthInBytes); \
            SnP_XORBytesInLane(state, \
                (length)/SnP_laneLengthInBytes, \
                (data)+((length)/SnP_laneLengthInBytes)*SnP_laneLengthInBytes, \
                0, \
                (length)%SnP_laneLengthInBytes); \
        } \
        else { \
            unsigned int _sizeLeft = (length); \
            unsigned int _lanePosition = (offset)/SnP_laneLengthInBytes; \
            unsigned int _offsetInLane = (offset)%SnP_laneLengthInBytes; \
            const unsigned char *_curData = (data); \
            while(_sizeLeft > 0) { \
                unsigned int _bytesInLane = SnP_laneLengthInBytes - _offsetInLane; \
                if (_bytesInLane > _sizeLeft) \
                    _bytesInLane = _sizeLeft; \
                SnP_XORBytesInLane(state, _lanePosition, _curData, _offsetInLane, _bytesInLane); \
                _sizeLeft -= _bytesInLane; \
                _lanePosition++; \
                _offsetInLane = 0; \
                _curData += _bytesInLane; \
            } \
        } \
    }

#define SnP_OverwriteBytes(state, data, offset, length) \
    { \
        if ((offset) == 0) { \
            SnP_OverwriteLanes(state, data, (length)/SnP_laneLengthInBytes); \
            SnP_OverwriteBytesInLane(state, \
                (length)/SnP_laneLengthInBytes, \
                (data)+((length)/SnP_laneLengthInBytes)*SnP_laneLengthInBytes, \
                0, \
                (length)%SnP_laneLengthInBytes); \
        } \
        else { \
            unsigned int _sizeLeft = (length); \
            unsigned int _lanePosition = (offset)/SnP_laneLengthInBytes; \
            unsigned int _offsetInLane = (offset)%SnP_laneLengthInBytes; \
            const unsigned char *_curData = (data); \
            while(_sizeLeft > 0) { \
                unsigned int _bytesInLane = SnP_laneLengthInBytes - _offsetInLane; \
                if (_bytesInLane > _sizeLeft) \
                    _bytesInLane = _sizeLeft; \
                SnP_OverwriteBytesInLane(state, _lanePosition, _curData, _offsetInLane, _bytesInLane); \
                _sizeLeft -= _bytesInLane; \
                _lanePosition++; \
                _offsetInLane = 0; \
                _curData += _bytesInLane; \
            } \
        } \
    }

#define SnP_ExtractBytes(state, data, offset, length) \
    { \
        if ((offset) == 0) { \
            SnP_ExtractLanes(state, data, (length)/SnP_laneLengthInBytes); \
            SnP_ExtractBytesInLane(state, \
                (length)/SnP_laneLengthInBytes, \
                (data)+((length)/SnP_laneLengthInBytes)*SnP_laneLengthInBytes, \
                0, \
                (length)%SnP_laneLengthInBytes); \
        } \
        else { \
            unsigned int _sizeLeft = (length); \
            unsigned int _lanePosition = (offset)/SnP_laneLengthInBytes; \
            unsigned int _offsetInLane = (offset)%SnP_laneLengthInBytes; \
            unsigned char *_curData = (data); \
            while(_sizeLeft > 0) { \
                unsigned int _bytesInLane = SnP_laneLengthInBytes - _offsetInLane; \
                if (_bytesInLane > _sizeLeft) \
                    _bytesInLane = _sizeLeft; \
                SnP_ExtractBytesInLane(state, _lanePosition, _curData, _offsetInLane, _bytesInLane); \
                _sizeLeft -= _bytesInLane; \
                _lanePosition++; \
                _offsetInLane = 0; \
                _curData += _bytesInLane; \
            } \
        } \
    }

#define SnP_ExtractAndXORBytes(state, data, offset, length) \
    { \
        if ((offset) == 0) { \
            SnP_ExtractAndXORLanes(state, data, (length)/SnP_laneLengthInBytes); \
            SnP_ExtractAndXORBytesInLane(state, \
                (length)/SnP_laneLengthInBytes, \
                (data)+((length)/SnP_laneLengthInBytes)*SnP_laneLengthInBytes, \
                0, \
                (length)%SnP_laneLengthInBytes); \
        } \
        else { \
            unsigned int _sizeLeft = (length); \
            unsigned int _lanePosition = (offset)/SnP_laneLengthInBytes; \
            unsigned int _offsetInLane = (offset)%SnP_laneLengthInBytes; \
            unsigned char *_curData = (data); \
            while(_sizeLeft > 0) { \
                unsigned int _bytesInLane = SnP_laneLengthInBytes - _offsetInLane; \
                if (_bytesInLane > _sizeLeft) \
                    _bytesInLane = _sizeLeft; \
                SnP_ExtractAndXORBytesInLane(state, _lanePosition, _curData, _offsetInLane, _bytesInLane); \
                _sizeLeft -= _bytesInLane; \
                _lanePosition++; \
                _offsetInLane = 0; \
                _curData += _bytesInLane; \
            } \
        } \
    }



typedef struct {
    uint8_t state[STATE_MAX_SIZE];
    uint32_t rate;
    uint32_t byteIOIndex;
    uint32_t squeezing;
    uint32_t reserved;
}Keccak_SpongeInstance;/* total size ==> 1600 + 12 = 1612 ==> 1612 + 4 = 1616*/
typedef struct {
    Keccak_SpongeInstance sponge; // must be aligned to 8 byte for mips support
    uint32_t fixedOutputLength;
    uint8_t reserved[4];
    uint8_t delimitedSuffix;
    uint8_t reserved1[3];
}SHA3_CTX;/* total size ==> 1612 + 4 + 1 = 1617 ==> 1617+7+4 = 1628*/

typedef SHA3_CTX    SHAKE_CTX;

int SHA3_Sw_Init(SHA3_CTX* ctx, int sha3_variant);
int SHA3_Sw_Update(SHA3_CTX* ctx,const void* data,unsigned long n);
int SHA3_Sw_Final(uint8_t* hash, SHA3_CTX* ctx);
int sha3_spongeinitialization(Keccak_SpongeInstance* sponge_instance, 
        uint32_t rate, uint32_t capacity);

void KeccakF1600_Initialize();
void KeccakF1600_StateInitialize(void *state);
void KeccakF1600_InitializeRoundConstants();
void KeccakF1600_InitializeRhoOffsets();

void KeccakF1600_StateXORBytes(void *state, const unsigned char *data, 
        unsigned int offset, unsigned int length);
void KeccakF1600_StateOverwriteBytes(void *state, const unsigned char *data, 
        unsigned int offset, unsigned int length);

void KeccakF1600_StateOverwriteWithZeroes(void *state, unsigned int byteCount);
void KeccakF1600_StateComplementBit(void *state, unsigned int position);
void KeccakF1600_StatePermute(void *state);

void KeccakF1600_StateExtractBytes(const void *state, 
        unsigned char *data, unsigned int offset, unsigned int length);
void KeccakF1600_StateExtractAndXORBytes(const void *state, 
        unsigned char *data, unsigned int offset, unsigned int length);
size_t KeccakF1600_FBWL_Absorb(void *state, unsigned int laneCount, 
        const unsigned char *data, size_t dataByteLen, 
        unsigned char trailingBits);
size_t KeccakF1600_FBWL_Squeeze(void *state, unsigned int laneCount, 
        unsigned char *data, size_t dataByteLen);
size_t KeccakF1600_FBWL_Wrap(void *state, unsigned int laneCount, 
        const unsigned char *dataIn, unsigned char *dataOut, 
        size_t dataByteLen, unsigned char trailingBits);
size_t KeccakF1600_FBWL_Unwrap(void *state, unsigned int laneCount, 
        const unsigned char *dataIn, unsigned char *dataOut, 
        size_t dataByteLen, unsigned char trailingBits);

void KeccakF1600_StateXORLanes(void *state, const unsigned char *data, 
        unsigned int laneCount);
void KeccakF1600_StateXORBytesInLane(void *argState, uint32_t lanePosition,
        const unsigned char *data, unsigned int offset, unsigned int length);

uint64_t KeccakF1600_GetNextRoundConstant( uint8_t *LFSR );
void KeccakF1600_StateExtractLanes(const void *state, unsigned char *data, 
        unsigned int laneCount);


void KeccakF1600OnWords(uint64_t *state);
void KeccakF1600Round(uint64_t *state, unsigned int indexRound);
void KeccakF1600Round(uint64_t *state, unsigned int indexRound);

void fromBytesToWords(uint64_t *stateAsWords, const unsigned char *state);
void fromWordsToBytes(unsigned char *state, const uint64_t *stateAsWords);


int Keccak_spongeinitialization(Keccak_SpongeInstance* sponge_instance, 
        uint32_t rate, uint32_t capacity);
int Keccak_SpongeAbsorb(Keccak_SpongeInstance *instance, 
        const unsigned char *data, size_t dataByteLen);
int Keccak_SpongeAbsorbLastFewBits(Keccak_SpongeInstance *instance, 
        unsigned char delimitedData);
int Keccak_SpongeSqueeze(Keccak_SpongeInstance *instance, 
        unsigned char *data, size_t dataByteLen);
void KeccakF1600_StateExtractBytesInLane(const void *state, 
        unsigned int lanePosition, unsigned char *data, 
        unsigned int offset, unsigned int length);
void KeccakF1600_StateExtractAndXORLanes(const void *state, 
        unsigned char *data, unsigned int laneCount);

void KeccakF1600_StateExtractAndXORBytesInLane(const void *state, 
        unsigned int lanePosition, unsigned char *data, 
        unsigned int offset, unsigned int length);

int shake_128_HashSqueeze(SHA3_CTX *ctx, uint8_t *data, uint32_t databitlen);

int shake_256_HashSqueeze(SHA3_CTX *ctx, uint8_t *data, uint32_t databitlen);
int LFSR86540(uint8_t *LFSR);

size_t SnP_FBWL_Absorb_Default(void *state, unsigned int laneCount, 
        const unsigned char *data, size_t dataByteLen, 
        unsigned char trailingBits);
size_t SnP_FBWL_Squeeze_Default(void *state, unsigned int laneCount, 
        unsigned char *data, size_t dataByteLen);
size_t SnP_FBWL_Wrap_Default(void *state, unsigned int laneCount, 
        const unsigned char *dataIn, unsigned char *dataOut, 
        size_t dataByteLen, unsigned char trailingBits);
size_t SnP_FBWL_Unwrap_Default(void *state, unsigned int laneCount, 
        const unsigned char *dataIn, unsigned char *dataOut, 
        size_t dataByteLen, unsigned char trailingBits);


#else
typedef struct sha3_ctx {
    uint64_t iv[25];
    unsigned long rate;
    uint8_t buf[KECCAK_RATE_MAX_BYTES];
    int buflen;
    int type;
} SHA3_CTX;
#endif
#if (SHA3_MODE == SHA3_SW_SUPPORT)
    #define SHA3_Init       SHA3_Sw_Init
    #define SHA3_Update     SHA3_Sw_Update
    #define SHA3_Final      SHA3_Sw_Final
#else
    #define SHA3_Init       SHA3_Hw_Init
    #define SHA3_Update     SHA3_Hw_Update
    #define SHA3_Final      SHA3_Hw_Final
#endif

#define SHA3_INIT(variant)		\
	SHA3_##variant##_Init(SHA3_CTX *ctx)
#define SHA3_UPDATE(variant)		\
	SHA3_##variant##_Update(SHA3_CTX *ctx, const void *data, unsigned long n)
#define SHA3_FINAL(variant)		\
	SHA3_##variant##_Final(unsigned char *md, SHA3_CTX *ctx)

int SHA3_INIT(224);
int SHA3_INIT(256);
int SHA3_INIT(384);
int SHA3_INIT(512);

int SHA3_UPDATE(224);
int SHA3_UPDATE(256);
int SHA3_UPDATE(384);
int SHA3_UPDATE(512);

int SHA3_FINAL(224);
int SHA3_FINAL(256);
int SHA3_FINAL(384);
int SHA3_FINAL(512);
unsigned char *SHA3_224_hash(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *SHA3_256_hash(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *SHA3_384_hash(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *SHA3_512_hash(const unsigned char *d, size_t n, unsigned char *md);
int SHA3_224(unsigned char *input, unsigned long input_len_bits, unsigned char *result);
int SHA3_256(unsigned char *input, unsigned long input_len_bits, unsigned char *result);
int SHA3_384(unsigned char *input, unsigned long input_len_bits, unsigned char *result);
int SHA3_512(unsigned char *input, unsigned long input_len_bits, unsigned char *result);
#endif
#if 0
int shake_128_hash(char *input, int input_len_bits);
int shake_256_hash(char *input, int input_len_bits);
#endif


#endif
