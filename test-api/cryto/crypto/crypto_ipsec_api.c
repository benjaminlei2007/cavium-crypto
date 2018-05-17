/* 
 * 
 * OCTEON SDK
 * 
 * Copyright (c) 2007 Cavium Networks. All rights reserved.
 * 
 * This file, which is part of the OCTEON SDK which also includes the
 * OCTEON SDK Package from Cavium Networks, contains proprietary and
 * confidential information of Cavium Networks and in some cases its
 * suppliers. 
 * 
 * Any licensed reproduction, distribution, modification, or other use of
 * this file or the confidential information or patented inventions
 * embodied in this file is subject to your license agreement with Cavium
 * Networks. Unless you and Cavium Networks have agreed otherwise in
 * writing, the applicable license terms can be found at:
 * licenses/cavium-license-type2.txt
 * 
 * All other use and disclosure is prohibited.
 * 
 * Contact Cavium Networks at info@caviumnetworks.com for more information.
 * 
 */


#include <cvmx.h>
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#define MAX_PKT_SIZE     65535
#define ESP_HEADER_LENGTH     8
#define DES_CBC_IV_LENGTH     8
#define AES_CBC_IV_LENGTH     16
#define AES_CTR_IV_LENGTH     8 
#define ESP_HMAC_LEN          12
#define IP_HEADER_LENGTH      20
#define AH_HEADER_LENGTH      24 
#define AH_FIXED_LEN          12
#define ICV_LEN_SHA1          12
#define ICV_LEN_SHA224        16
#define ICV_LEN_SHA256        16
#define ICV_LEN_SHA384        24
#define ICV_LEN_SHA512        32

extern int cvm_crypto_aes_xcbc_mac (uint64_t * key,
  uint32_t bits, uint64_t * data, uint32_t dlen, uint64_t * mac);

#define uint64_t_mul(abhi,ablo,a,b) \
{\
    asm volatile("dmultu %[rs],%[rt]" :: [rs] "d" (a), [rt] "d" (b) );\
    asm volatile("mfhi %[rd] " : [rd] "=d" (abhi) : );\
    asm volatile("mflo %[rd] " : [rd] "=d" (ablo) : );\
}

typedef union{
   uint64_t blk[2];
   struct {
      uint32_t nonce;
      uint8_t aes_iv[8];
      uint32_t counter;
   } s;
} cntrblk_t;  

/* Parallelized version for better performance */

#define ESP_HEADER_LENGTH 8
#define DES_CBC_IV_LENGTH 8  

 
#define __CNCRYPTO_INTERNAL_USE__
#include "cop2.h"

/* It is likely 
 * CVMX_SHARED may reduce perf very little in data paths.
 * so better to use SDATA
 */
#define CNCRYPTO_SDATA_SECTION	__attribute__ ((section(".sdata")))

CNCRYPTO_SDATA_SECTION
uint64_t ipad = 0x3636363636363636ULL;


CNCRYPTO_SDATA_SECTION
uint64_t opad = 0x5c5c5c5c5c5c5c5cULL;


CNCRYPTO_SDATA_SECTION
uint64_t sha512defiv[8] = {
	0x6a09e667f3bcc908ull,
	0xbb67ae8584caa73bull,
	0x3c6ef372fe94f82bull,
	0xa54ff53a5f1d36f1ull,
	0x510e527fade682d1ull,
	0x9b05688c2b3e6c1full,
	0x1f83d9abfb41bd6bull,
	0x5be0cd19137e2179ull
};


CNCRYPTO_SDATA_SECTION
uint64_t sha384defiv[8] = {
	0xcbbb9d5dc1059ed8ull,
	0x629a292a367cd507ull,
	0x9159015a3070dd17ull,
	0x152fecd8f70e5939ull,
	0x67332667ffc00b31ull,
	0x8eb44a8768581511ull,
	0xdb0c2e0d64f98fa7ull,
	0x47b5481dbefa4fa4ull
};


CNCRYPTO_SDATA_SECTION
uint64_t sha256defiv[4] = {
      0x6a09e667bb67ae85ull,
      0x3c6ef372a54ff53aull,
      0x510e527f9b05688cull,
      0x1f83d9ab5be0cd19ull
};


CNCRYPTO_SDATA_SECTION
uint64_t sha224defiv[4] = {
      0xc1059ed8367cd507ull,
      0x3070dd17f70e5939ull,
      0xffc00b3168581511ull,
      0x64f98fa7befa4fa4ull
};


CNCRYPTO_SDATA_SECTION
uint64_t sha1defiv[3] = {
	0x67452301EFCDAB89ULL,
	0x98BADCFE10325476ULL,
	0xC3D2E1F000000000ULL
};

CNCRYPTO_SDATA_SECTION
uint64_t md5defiv[2] = {
      0x0123456789abcdefULL,
      0xfedcba9876543210ULL
};



#define INC_MT_HSH (x) (x) = ((x) + 1) % 8
static int hash_key_sha512(uint8_t *key_in, uint16_t keylen, uint8_t *key_out, int sha512)
{
   uint64_t *data = (uint64_t *)key_in;
   uint8_t t_hash[128];
   uint16_t key_len = keylen;
   uint64_t ab[2];
   uint64_t_mul (ab[0],ab[1], key_len, 0x8ull);

   if(sha512) {
     CVMX_M64BT_HSH_IVW(sha512defiv);
   } else {
     CVMX_M64BT_HSH_IVW(sha384defiv);
   }

   while(key_len >= 128) {
      CVMX_M128BT_HSH_DATW_SHA512(*data++);
      key_len-=128;
   }

   memset(t_hash,0x0,128);
   memcpy(t_hash,(uint8_t *)data, key_len);
   *(t_hash+key_len)=0x80;
   if(key_len >= 112) {
      uint64_t *d64 = (void*)t_hash;
      CVMX_M128BT_HSH_DATW_SHA512(*d64++);
      CVMX_MT_HSH_8DATWZS(0,1,2,3,4,5,6,7);
      CVMX_MT_HSH_4DATWZS(8,9,10,11);
      CVMX_MT_HSH_DATWZ(12);
      CVMX_MT_HSH_DATWZ(13);
      CVMX_MT_HSH_DATW(ab[0],14);
      CVMX_MT_HSH_STARTSHA512(ab[1]);
   } else {
      CVMX_MT_HSH_DATW(((uint64_t *)t_hash)[0],0);
      CVMX_MT_HSH_DATW(((uint64_t *)t_hash)[1],1);
      CVMX_MT_HSH_DATW(((uint64_t *)t_hash)[2],2);
      CVMX_MT_HSH_DATW(((uint64_t *)t_hash)[3],3);
      CVMX_MT_HSH_DATW(((uint64_t *)t_hash)[4],4);
      CVMX_MT_HSH_DATW(((uint64_t *)t_hash)[5],5);
      CVMX_MT_HSH_DATW(((uint64_t *)t_hash)[6],6);
      CVMX_MT_HSH_DATW(((uint64_t *)t_hash)[7],7);
      CVMX_MT_HSH_DATW(((uint64_t *)t_hash)[8],8);
      CVMX_MT_HSH_DATW(((uint64_t *)t_hash)[9],9);
      CVMX_MT_HSH_DATW(((uint64_t *)t_hash)[10],10);
      CVMX_MT_HSH_DATW(((uint64_t *)t_hash)[11],11);
      CVMX_MT_HSH_DATW(((uint64_t *)t_hash)[12],12);
      CVMX_MT_HSH_DATW(((uint64_t *)t_hash)[13],13);
      CVMX_MT_HSH_DATW(ab[0],14);
      CVMX_MT_HSH_STARTSHA512(ab[1]);
   }
   CVMX_MF_HSH_IVW(((uint64_t *)key_out)[0],0);   
   CVMX_MF_HSH_IVW(((uint64_t *)key_out)[1],1);   
   CVMX_MF_HSH_IVW(((uint64_t *)key_out)[2],2);   
   CVMX_MF_HSH_IVW(((uint64_t *)key_out)[3],3);   
   CVMX_MF_HSH_IVW(((uint64_t *)key_out)[4],4);   
   CVMX_MF_HSH_IVW(((uint64_t *)key_out)[5],5);   
   if(sha512) {
      CVMX_MF_HSH_IVW(((uint64_t *)key_out)[6],6);   
      CVMX_MF_HSH_IVW(((uint64_t *)key_out)[7],7);   
   }
   return 1;
}
static inline int hash_key(uint8_t *key_in, uint16_t keylen, uint8_t *key_out,int htype)
{
   uint64_t *data = (uint64_t *)key_in;
   uint8_t t_hash[64];
   uint16_t key_len = keylen;
   uint64_t bits=keylen*8;
   switch(htype)
   {
      case 0: 
         CVMX_MT_HSH_IV(0x0123456789abcdefULL,0);
         CVMX_MT_HSH_IV(0xfedcba9876543210ULL,1);
      break;
     case 1:
         CVMX_MT_HSH_IV(0x67452301EFCDAB89ULL,0);
         CVMX_MT_HSH_IV(0x98BADCFE10325476ULL,1);
         CVMX_MT_HSH_IV(0xC3D2E1F000000000ULL,2);
         break;
     case 2:
         CVMX_MT_HSH_IV(0x6a09e667bb67ae85ull,0);
         CVMX_MT_HSH_IV(0x3c6ef372a54ff53aull,1);
         CVMX_MT_HSH_IV(0x510e527f9b05688cull,2);
         CVMX_MT_HSH_IV(0x1f83d9ab5be0cd19ull,3);
         break;
      case 3: 
         CVMX_MT_HSH_IV(0xc1059ed8367cd507ull, 0);
         CVMX_MT_HSH_IV(0x3070dd17f70e5939ull, 1);
         CVMX_MT_HSH_IV(0xffc00b3168581511ull, 2);
         CVMX_MT_HSH_IV(0x64f98fa7befa4fa4ull, 3);
         break;
      default: printf("\n invalid option \n");
            return -1;
         
   } 

   while(key_len >=64) {
      CVMX_MT_HSH_DAT(data[0],0);
      CVMX_MT_HSH_DAT(data[1],1);
      CVMX_MT_HSH_DAT(data[2],2);
      CVMX_MT_HSH_DAT(data[3],3);
      CVMX_MT_HSH_DAT(data[4],4);
      CVMX_MT_HSH_DAT(data[5],5);
      CVMX_MT_HSH_DAT(data[6],6);
      if(htype==0)
         CVMX_MT_HSH_STARTMD5(data[7]);
      else if(htype==1)
         CVMX_MT_HSH_STARTSHA(data[7]);
      else if(htype==2||htype==3)
         CVMX_MT_HSH_STARTSHA256(data[7]);
      key_len-=64;
      data+=8;
   }
   memset(t_hash,0x0,64);
   memcpy(t_hash,(uint8_t *)data, key_len);
   *(t_hash+key_len)=0x80;
   if(key_len >= 56) {
      CVMX_MT_HSH_DAT(((uint64_t *)t_hash)[0],0);
      CVMX_MT_HSH_DAT(((uint64_t *)t_hash)[1],1);
      CVMX_MT_HSH_DAT(((uint64_t *)t_hash)[2],2);
      CVMX_MT_HSH_DAT(((uint64_t *)t_hash)[3],3);
      CVMX_MT_HSH_DAT(((uint64_t *)t_hash)[4],4);
      CVMX_MT_HSH_DAT(((uint64_t *)t_hash)[5],5);
      CVMX_MT_HSH_DAT(((uint64_t *)t_hash)[6],6);
      if(htype==0)
         CVMX_MT_HSH_STARTMD5(((uint64_t *)t_hash)[7]);
      else if(htype==1)
         CVMX_MT_HSH_STARTSHA(((uint64_t *)t_hash)[7]);
      else if(htype==2||htype==3)
         CVMX_MT_HSH_STARTSHA256(((uint64_t *)t_hash)[7]);
      CVMX_MT_HSH_DATZ(0);
      CVMX_MT_HSH_DATZ(1);
      CVMX_MT_HSH_DATZ(2);
      CVMX_MT_HSH_DATZ(3);
      CVMX_MT_HSH_DATZ(4);
      CVMX_MT_HSH_DATZ(5);
      CVMX_MT_HSH_DATZ(6);
      if(htype==0) {
         CVMX_ES64(bits, bits);
         CVMX_MT_HSH_STARTMD5(bits);
      }
      else if(htype==1)
         CVMX_MT_HSH_STARTSHA(bits);
      else if(htype==2||htype==3)
         CVMX_MT_HSH_STARTSHA256(bits);
   } else {
      CVMX_MT_HSH_DAT(((uint64_t *)t_hash)[0],0);
      CVMX_MT_HSH_DAT(((uint64_t *)t_hash)[1],1);
      CVMX_MT_HSH_DAT(((uint64_t *)t_hash)[2],2);
      CVMX_MT_HSH_DAT(((uint64_t *)t_hash)[3],3);
      CVMX_MT_HSH_DAT(((uint64_t *)t_hash)[4],4);
      CVMX_MT_HSH_DAT(((uint64_t *)t_hash)[5],5);
      CVMX_MT_HSH_DAT(((uint64_t *)t_hash)[6],6);
      if(htype==0){
         CVMX_ES64(bits, bits);
         CVMX_MT_HSH_STARTMD5(bits);
      }
      else if(htype==1)
         CVMX_MT_HSH_STARTSHA(bits);
      else if(htype==2||htype==3)
         CVMX_MT_HSH_STARTSHA256(bits);
   }
   CVMX_MF_HSH_IV(((uint64_t *)key_out)[0],0);   
   CVMX_MF_HSH_IV(((uint64_t *)key_out)[1],1);   
   if(htype >0) {
      CVMX_MF_HSH_IV(((uint64_t *)key_out)[2],2);
      if(htype == 2|| htype==3)
         CVMX_MF_HSH_IV(((uint64_t *)key_out)[3],3);   
   }
   if(htype==3) {
      memset(&key_out[28],0x0,4);
   }
   return 1;
}
#define _CVMX_MT_HSH_DAT(dat, next, flag)  { \
   if (next == 0) {                     \
      next = 1;                         \
      CVMX_MT_HSH_DAT (dat, 0);         \
   } else if (next == 1) {              \
      next = 2;                         \
      CVMX_MT_HSH_DAT (dat, 1);         \
   } else if (next == 2) {              \
      next = 3;                    \
      CVMX_MT_HSH_DAT (dat, 2);         \
   } else if (next == 3) {              \
      next = 4;                         \
      CVMX_MT_HSH_DAT (dat, 3);         \
   } else if (next == 4) {              \
      next = 5;                           \
      CVMX_MT_HSH_DAT (dat, 4);         \
   } else if (next == 5) {              \
      next = 6;                         \
      CVMX_MT_HSH_DAT (dat, 5);         \
   } else if (next == 6) {              \
      next = 7;                         \
      CVMX_MT_HSH_DAT (dat, 6);         \
   } else {                             \
   if(flag ==2 )                                       \
        CVMX_MT_HSH_STARTSHA256 (dat);   \
   else if(flag ==1 )                              \
        CVMX_MT_HSH_STARTSHA (dat);         \
   else if(flag ==0)                                 \
        CVMX_MT_HSH_STARTMD5 (dat);         \
     next = 0;                          \
   }                                    \
}

#define _CVMX_MT_HSH_DATW(dat, next)  { \
   if (next == 0) {                     \
      next = 1;                         \
      CVMX_MT_HSH_DATW (dat, 0);        \
   } else if (next == 1) {              \
      next = 2;                         \
      CVMX_MT_HSH_DATW (dat, 1);        \
   } else if (next == 2) {              \
      next = 3;                             \
      CVMX_MT_HSH_DATW (dat, 2);        \
   } else if (next == 3) {              \
      next = 4;                         \
      CVMX_MT_HSH_DATW (dat, 3);        \
   } else if (next == 4) {              \
      next = 5;                           \
      CVMX_MT_HSH_DATW (dat, 4);        \
   } else if (next == 5) {              \
      next = 6;                         \
      CVMX_MT_HSH_DATW (dat, 5);        \
   } else if (next == 6) {              \
      next = 7;                         \
      CVMX_MT_HSH_DATW (dat, 6);        \
   } else if (next == 7) {              \
      next = 8;                         \
      CVMX_MT_HSH_DATW (dat, 7);        \
   } else if (next == 8) {              \
      next = 9;                         \
      CVMX_MT_HSH_DATW (dat, 8);        \
   } else if (next == 9) {              \
      next = 10;                        \
      CVMX_MT_HSH_DATW (dat, 9);        \
   } else if (next == 10) {             \
      next = 11;                        \
      CVMX_MT_HSH_DATW (dat, 10);       \
   } else if (next == 11) {             \
      next = 12;                        \
      CVMX_MT_HSH_DATW (dat, 11);       \
   } else if (next == 12) {             \
      next = 13;                        \
      CVMX_MT_HSH_DATW (dat, 12);       \
   } else if (next == 13) {             \
      next = 14;                        \
      CVMX_MT_HSH_DATW (dat, 13);       \
   } else if (next == 14) {             \
      next = 15;                        \
      CVMX_MT_HSH_DATW (dat, 14);       \
   } else if (next == 15) {             \
        CVMX_MT_HSH_STARTSHA512(dat);   \
      next = 0;                         \
   }                                    \
}

int AES_cbc_sha1_encrypt(uint16_t aes_key_len, uint8_t *aes_key,  uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{

   uint64_t *dptr, *aptr,*rptr;
   uint64_t sha1[3];
   uint32_t dlen;
   uint8_t sha_key[64];
   uint64_t inner_sha[3];

  /* Check input parameters */
   if(pktptr == NULL || pktlen ==0   || aes_key == NULL || aes_iv == NULL || 
      sha1_key == NULL || sha1_keylen ==0 || espheader == NULL ||
      outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if((pktlen < 16) || (pktlen%16)) {
     printf(" packetlen is not proper \n");
     return -1;
   }
   if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-AES_CBC_IV_LENGTH-ICV_LEN_SHA1)) {
     printf("Packet is too big to handle \n");
     return -1;
   }
   CVMX_PREFETCH0(aes_iv);
   CVMX_PREFETCH0(aes_key);
   memset(sha_key,0x0,64);
   if(sha1_keylen > 64){
      if(hash_key(sha1_key, sha1_keylen, sha_key, 1)<0){
         printf(" improper mac secret \n");   
         return -1;
       } 
      sha1_keylen = 20;
   }else
       memcpy(sha_key,sha1_key,sha1_keylen);
   aes_key_len = aes_key_len *8;
   
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128)
   {
     CVMX_MT_AES_KEY (0x0ULL, 2);
     CVMX_MT_AES_KEY (0x0ULL, 3);
   }else if(aes_key_len == 192) {
     CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
     CVMX_MT_AES_KEY (0x0ULL, 3);
   }else if(aes_key_len == 256) {
     CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
     CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   }else{
     printf("Improper key length\n");
     return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);
   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[1], 1);


   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ ipad));


   /* setup arguments */ 
   dptr = (uint64_t *) pktptr;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen;
   if(outptr != NULL){
        ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
        ((uint64_t *)outptr)[1]=((uint64_t *)aes_iv)[0];
        ((uint64_t *)outptr)[2]=((uint64_t *)aes_iv)[1];
        rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
        aptr = (uint64_t *)rptr ;
   }else {
      rptr= (uint64_t *)pktptr;
      aptr = (uint64_t *)rptr ;
   }

   
   /* Load ESP header & AES IV into hash unit */
   CVMX_MT_HSH_DAT (*((uint64_t *)espheader), 0);
   CVMX_MT_HSH_DAT (((uint64_t *)aes_iv)[0],  1);
   CVMX_MT_HSH_DAT (((uint64_t *)aes_iv)[1],  2);
   
   COP2_PARALLEL_AES_ENC_SHA1(dptr,rptr,dlen);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_sha[0], 0);
   CVMX_MF_HSH_IV (inner_sha[1], 1);
   CVMX_MF_HSH_IV (inner_sha[2], 2);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ opad));

    
   CVMX_MT_HSH_DAT (inner_sha[0], 0);
   CVMX_MT_HSH_DAT (inner_sha[1],1);
   ((uint8_t *)inner_sha)[20]=0x80;
   ((uint8_t *)inner_sha)[21]=0x0;
   ((uint8_t *)inner_sha)[22]=0x0;
   ((uint8_t *)inner_sha)[23]=0x0;
   CVMX_MT_HSH_DAT (inner_sha[2], 2);
   CVMX_MT_HSH_DATZ(3);   
   CVMX_MT_HSH_DATZ(4);   
   CVMX_MT_HSH_DATZ(5);   
   CVMX_MT_HSH_DATZ(6);   
   CVMX_MT_HSH_STARTSHA ((uint64_t) ((64 + 20) * 8));

   /* Get the HMAC */
   CVMX_MF_HSH_IV (sha1[0], 0);
   CVMX_MF_HSH_IV (sha1[1], 1);

      /* put HMac at the end of the packet */
   memcpy(rptr, sha1, ICV_LEN_SHA1); 
   if(outlen) {
      if(outptr)  
        *outlen = pktlen +ESP_HEADER_LENGTH +AES_CBC_IV_LENGTH +ICV_LEN_SHA1;
       else
         *outlen = pktlen + ICV_LEN_SHA1;
   }
   return 0;
}


int AES_cbc_sha1_decrypt(uint16_t aes_key_len, uint8_t *aes_key, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t sha1[3];
   uint32_t dlen ;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_sha[3];
  
   /* Check input parameters */
   if(pktptr == NULL || pktlen == 0  || aes_key == NULL || 
   aes_iv == NULL || sha1_key == NULL || sha1_keylen ==0 ||outlen==NULL) {
   printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +AES_CBC_IV_LENGTH+ICV_LEN_SHA1+16)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   CVMX_PREFETCH0(aes_iv);
   CVMX_PREFETCH0(aes_key);
   
   aes_key_len = aes_key_len *8;
   memset(sha_key,0x0,64);
   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 1)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 20;
   } else
        memcpy(sha_key,sha1_key,sha1_keylen);

   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY (0x0ULL, 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 256) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ ipad));

   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   CVMX_PREFETCH0(aptr);
   dptr = (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
   dlen = pktlen-ESP_HEADER_LENGTH-AES_CBC_IV_LENGTH-ICV_LEN_SHA1;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      ((uint64_t *)outptr)[2]=((uint64_t *)pktptr)[2];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
   }
   else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);

   /*load header and IV to hash uint */
   CVMX_MT_HSH_DAT (*aptr++, 0);
   CVMX_MT_HSH_DAT (*aptr++, 1);
   CVMX_MT_HSH_DAT (*aptr++, 2);

   dptr = aptr;
   pktlen = pktlen - ICV_LEN_SHA1;
   COP2_PARALLEL_AES_DEC_SHA1(dptr,rptr,dlen);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_sha[0], 0);
   CVMX_MF_HSH_IV (inner_sha[1], 1);
   CVMX_MF_HSH_IV (inner_sha[2], 2);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;

   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ opad));


   CVMX_MT_HSH_DAT (inner_sha[0], 0);
   CVMX_MT_HSH_DAT (inner_sha[1], 1);
   ((uint8_t *)inner_sha)[20]=0x80;
   ((uint8_t *)inner_sha)[21]=0x0;
   ((uint8_t *)inner_sha)[22]=0x0;
   ((uint8_t *)inner_sha)[23]=0x0;
   CVMX_MT_HSH_DAT (inner_sha[2], 2);
   CVMX_MT_HSH_DATZ(3);
   CVMX_MT_HSH_DATZ(4);
   CVMX_MT_HSH_DATZ(5);
   CVMX_MT_HSH_DATZ(6);
   CVMX_MT_HSH_STARTSHA((uint64_t) ((64 + 20) * 8));

   /* Get the HMAC */
   CVMX_MF_HSH_IV (sha1[0], 0);
   CVMX_MF_HSH_IV (sha1[1], 1);

   /* compare first 96 bits of HMAC with received mac */
   if(compdigest) { 
      if(memcmp(pktptr+pktlen, sha1, ICV_LEN_SHA1)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA1;i++)
            printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA1;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
   } else {
        if(outptr)
         memcpy(outptr+pktlen, sha1, ICV_LEN_SHA1);
   }
   if(outlen)
   *outlen=pktlen; 
   return 0;
}

int DES_ede3_cbc_sha1_encrypt(uint8_t *des_key, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t sha1[3];
   uint32_t dlen;
   uint8_t sha_key[64];
   uint64_t inner_sha[3];

   /*   check input parameters */ 
   if(pktptr == NULL || espheader == NULL || pktlen == 0  ||
      des_key == NULL || des_iv == NULL || sha1_key == NULL 
      || sha1_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
       return -1;
   }
   if((pktlen < 8) || (pktlen%8)) {
      printf(" packetlen is not proper \n");
      return -1;
   }
   if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-DES_CBC_IV_LENGTH-ICV_LEN_SHA1)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   CVMX_PREFETCH0(des_iv);
   CVMX_PREFETCH0(des_key);
   memset(sha_key,0x0,64);
   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 1)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
   sha1_keylen = 20;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);

   /* load 3DES Key and IV */

   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[0], 0);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[1], 1);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[2], 2);

   CVMX_MT_3DES_IV (*((uint64_t *)des_iv));

   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ ipad));
  
   /* Load esp header and IV */ 
   aptr = (uint64_t *)espheader;
   CVMX_MT_HSH_DAT (*aptr, 0);
   aptr = (uint64_t *)des_iv;
   CVMX_MT_HSH_DAT (*aptr, 1);

   /* setup enc/hmac args */
   dptr = (uint64_t *) pktptr;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)des_iv)[0];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
      aptr = (uint64_t *)rptr ;
   }else {
      rptr= (uint64_t *)pktptr;
      aptr = (uint64_t *)rptr ;
   }

   /* Start encryption */
    COP2_PARALLEL_3DES_ENC_SHA1(dptr,rptr,dlen);
    CVMX_MF_3DES_IV (*((uint64_t *)des_iv));

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_sha[0], 0);
   CVMX_MF_HSH_IV (inner_sha[1], 1);
   CVMX_MF_HSH_IV (inner_sha[2], 2);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ opad));

   CVMX_MT_HSH_DAT (inner_sha[0], 0);
   CVMX_MT_HSH_DAT (inner_sha[1], 1);
   ((uint8_t *)inner_sha)[20]=0x80;
   ((uint8_t *)inner_sha)[21]=0x0;
   ((uint8_t *)inner_sha)[22]=0x0;
   ((uint8_t *)inner_sha)[23]=0x0;
   CVMX_MT_HSH_DAT (inner_sha[2], 2);
   CVMX_MT_HSH_DATZ(3);
   CVMX_MT_HSH_DATZ(4);
   CVMX_MT_HSH_DATZ(5);
   CVMX_MT_HSH_DATZ(6);
   CVMX_MT_HSH_STARTSHA ((uint64_t) ((64 + 20) * 8));

   /* Get the HMAC */
   CVMX_MF_HSH_IV (sha1[0], 0);
   CVMX_MF_HSH_IV (sha1[1], 1);

   /* put HMac at the end of the packet */
   memcpy(rptr, sha1, ICV_LEN_SHA1);
   if(outlen) {
      if(outptr)
         *outlen = pktlen + ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH + ICV_LEN_SHA1;
      else
         *outlen = pktlen + ICV_LEN_SHA1;
   }
   return 0;
}


int DES_ede3_cbc_sha1_decrypt(uint8_t *des_key, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen,uint8_t *outptr, uint16_t *outlen,uint8_t compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t sha1[3];
   uint32_t dlen;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_sha[3];
   if(pktptr == NULL ||  pktlen == 0  || des_key == NULL || des_iv == NULL
    || sha1_key == NULL || sha1_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +DES_CBC_IV_LENGTH+ICV_LEN_SHA1+8)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   CVMX_PREFETCH0(des_iv);
   CVMX_PREFETCH0(des_key);
   memset(sha_key,0x0,64);
   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 1)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 20;
   } else
        memcpy(sha_key,sha1_key,sha1_keylen);

   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[0], 0);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[1], 1);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[2], 2);

   CVMX_MT_3DES_IV (*((uint64_t *)des_iv));

   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ ipad));

   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr;
   CVMX_PREFETCH0(aptr);
   dptr = (uint64_t *)(pktptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   dlen = pktlen -ESP_HEADER_LENGTH-DES_CBC_IV_LENGTH-ICV_LEN_SHA1;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   }
   else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);

   /* load ESP_HEADER and IV to hash unit */
   CVMX_MT_HSH_DAT (*aptr++, 0);
   CVMX_MT_HSH_DAT (*aptr++, 1);

   #if 0
   in=*aptr++;
   /* Load first block of data to hash Unit */
   _CVMX_MT_HSH_DAT (in, sha1_next, 1);
  
   /* Load first block of data to DES Unit */
   CVMX_MT_3DES_DEC_CBC (in);
   dlen -=8;
   /* Loop through input */
   while (dlen >= 16) {
      in =*aptr++;
      CVMX_MF_3DES_RESULT (out);
      _CVMX_MT_HSH_DAT (in, sha1_next, 1);
      CVMX_MT_3DES_DEC_CBC(in);
      rptr[0]=out;
      rptr++;
      in =*aptr++;
      CVMX_MF_3DES_RESULT (out);
      _CVMX_MT_HSH_DAT (in, sha1_next, 1);
      CVMX_MT_3DES_DEC_CBC(in);
      rptr[0]=out;
      rptr++;
      dlen-=16;
   }
   if(dlen) {
      in =*aptr++;
      CVMX_MF_3DES_RESULT (out);
      _CVMX_MT_HSH_DAT (in, sha1_next, 1);
      CVMX_MT_3DES_DEC_CBC(in);
      rptr[0]=out;
      rptr++;
      dlen-=8;
   }
   CVMX_MF_3DES_RESULT (out);
   rptr[0]=out;
   rptr++;
   pktlen = pktlen - 12;
   CVMX_MF_3DES_IV (*((uint64_t *)des_iv));

   /* Finish Inner hash */
   {
         int chunk_len=pktlen %64;
         uint8_t i=0;
         if(chunk_len == 56) {
            chunk_len = 72;
         } else
              chunk_len = 64-chunk_len;
         _CVMX_MT_HSH_DAT (0x8000000000000000ULL, sha1_next, 1);
         in = (pktlen+ 64) * 8;
         chunk_len-=16;
         while ( i< chunk_len) {
            _CVMX_MT_HSH_DAT (0x0ULL, sha1_next, 1);
            i += 8;
         }
         _CVMX_MT_HSH_DAT (in, sha1_next, 1);
      } 

   #else
   dptr = aptr;
   pktlen = pktlen - 12;
   COP2_PARALLEL_3DES_DEC_SHA1(dptr,rptr,dlen);
   CVMX_MF_3DES_IV (*((uint64_t *)des_iv));
   #endif

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_sha[0], 0);
   CVMX_MF_HSH_IV (inner_sha[1], 1);
   CVMX_MF_HSH_IV (inner_sha[2], 2);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ opad));

   CVMX_MT_HSH_DAT (inner_sha[0], 0);
   CVMX_MT_HSH_DAT (inner_sha[1], 1);
   ((uint8_t *)inner_sha)[20]=0x80;
   ((uint8_t *)inner_sha)[21]=0x0;
   ((uint8_t *)inner_sha)[22]=0x0;
   ((uint8_t *)inner_sha)[23]=0x0;
   CVMX_MT_HSH_DAT (inner_sha[2], 2);
   CVMX_MT_HSH_DATZ (3);
   CVMX_MT_HSH_DATZ (4);
   CVMX_MT_HSH_DATZ (5);
   CVMX_MT_HSH_DATZ (6);
   CVMX_MT_HSH_STARTSHA ((uint64_t) ((64 + 20) * 8));

   /* Get the HMAC */
   CVMX_MF_HSH_IV (sha1[0], 0);
   CVMX_MF_HSH_IV (sha1[1], 1);
   /* compare first 96 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, sha1, ICV_LEN_SHA1)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA1;i++)
            printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA1;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
       }
   } else {
      if(outptr) {
         memcpy(outptr+pktlen, sha1, ICV_LEN_SHA1);
      }
   }
   if(outlen)
   *outlen =pktlen;
   return 0;
}

int DES_ede3_cbc_md5_encrypt(uint8_t *des_key, uint16_t auth_keylen, uint8_t *auth_key, uint8_t *espheader, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t in;
   uint64_t md5[2];
   uint32_t dlen;
   uint8_t sha_key[64];
   uint64_t inner_hash[2];
   if(pktptr == NULL || espheader == NULL || pktlen == 0  ||
      des_key == NULL || des_iv == NULL || auth_key == NULL || 
      auth_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if((pktlen < 8) || (pktlen%8)) {
      printf(" packetlen is not proper \n");
      return -1;
   }
   if( pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-DES_CBC_IV_LENGTH-12)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   CVMX_PREFETCH0(des_key);
   CVMX_PREFETCH0(des_iv);
   memset(sha_key,0x0,64);
   if(auth_keylen > 64)   {
      if(hash_key(auth_key, auth_keylen, sha_key, 0)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
   auth_keylen = 16;
   } else
        memcpy(sha_key,auth_key,auth_keylen);
   /* load 3DES Key */
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[0], 0);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[1], 1);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[2], 2);

   CVMX_MT_3DES_IV (*((uint64_t *)des_iv));

   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (md5defiv[0], 0);
   CVMX_MT_HSH_IV (md5defiv[1], 1);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ ipad));
   /* load esp header and des_iv */
   aptr = (uint64_t *)espheader;
   CVMX_MT_HSH_DAT (*aptr, 0);
   aptr = (uint64_t *)des_iv;
   CVMX_MT_HSH_DAT (*aptr, 1);
   /* Copy header & setup enc/hmac args */
   dptr = (uint64_t *)pktptr;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)des_iv)[0];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   } else
      rptr = (uint64_t *)pktptr;
   aptr=rptr;   

   /* Start encryption */
   COP2_PARALLEL_3DES_ENC_MD5(dptr,rptr,dlen);
   CVMX_MF_3DES_IV (*((uint64_t *)des_iv));

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_hash[0], 0);
   CVMX_MF_HSH_IV (inner_hash[1], 1);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (md5defiv[0], 0);
   CVMX_MT_HSH_IV (md5defiv[1], 1);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ opad));

   CVMX_MT_HSH_DAT (inner_hash[0],  0);
   CVMX_MT_HSH_DAT (inner_hash[1],  1);
   CVMX_MT_HSH_DAT (0x8000000000000000ULL,2);
   CVMX_MT_HSH_DATZ(3);
   CVMX_MT_HSH_DATZ(4);
   CVMX_MT_HSH_DATZ(5);
   CVMX_MT_HSH_DATZ(6);
   in=(16+64)*8;
   CVMX_ES64(in,in);
   CVMX_MT_HSH_STARTMD5 (in);
   
   /* Get the HMAC */
   CVMX_MF_HSH_IV (md5[0], 0);
   CVMX_MF_HSH_IV (md5[1], 1);
   /* put HMac at the end of the packet */
   memcpy(rptr, md5, 12);
   if(outlen) {
      if(outptr)
         *outlen =pktlen+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH+12;
      else
         *outlen =pktlen+12;
   }
   return 0;
}

int DES_ede3_cbc_md5_decrypt(uint8_t *des_key, uint16_t auth_keylen, uint8_t *auth_key, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen,uint8_t *outptr, uint16_t *outlen,uint8_t compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t in;
   uint64_t md5[2]; 
   uint32_t dlen;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_hash[2];
   if(pktptr == NULL ||  pktlen == 0  || des_key == NULL ||
    des_iv == NULL || auth_key == NULL || auth_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +DES_CBC_IV_LENGTH+12+8)) {
      printf("Packet length is not proper \n");
      return -1;
   }
     CVMX_PREFETCH0(des_iv);
     CVMX_PREFETCH0(des_key);
   memset(sha_key,0x0,64);
   if(auth_keylen > 64) {
   if(hash_key(auth_key, auth_keylen, sha_key, 0)<0) {
      printf(" improper mac secret \n");   
      return -1;
   }
   auth_keylen = 16;
   } else
      memcpy(sha_key,auth_key,auth_keylen);

   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[0], 0);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[1], 1);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[2], 2);

   CVMX_MT_3DES_IV (*((uint64_t *)des_iv));

   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (md5defiv[0], 0);
   CVMX_MT_HSH_IV (md5defiv[1], 1);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ ipad));
   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr;
   CVMX_PREFETCH0(aptr);
   dptr = (uint64_t *)(pktptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   dlen = pktlen -ESP_HEADER_LENGTH-DES_CBC_IV_LENGTH-12;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   } else
      rptr = (uint64_t *)(pktptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);

   /* Load esp header and IV to hash unit */
     
   CVMX_MT_HSH_DAT (*aptr++, 0);
   CVMX_MT_HSH_DAT (*aptr++, 1);

   #if 0
   in=*aptr++;
   /* Load first block of data to DES Unit */
   CVMX_MT_3DES_DEC_CBC (in);
   /* Load first block of data to hash Unit */
   _CVMX_MT_HSH_DAT (in, hash_next, 0);
   dlen -=8;
   /* Loop through input */
   while (dlen >= 16) {
      in=*aptr++;
        CVMX_MF_3DES_RESULT (out);
        CVMX_MT_3DES_DEC_CBC(in);
       _CVMX_MT_HSH_DAT (in, hash_next, 0);
      rptr[0]=out;
      in=*aptr++;
        CVMX_MF_3DES_RESULT (out);
        CVMX_MT_3DES_DEC_CBC(in);
       _CVMX_MT_HSH_DAT (in, hash_next, 0);
      rptr[1]=out;
        rptr+=2;
        dlen-=16;
   }
   if(dlen) {
      in=*aptr++;
        CVMX_MF_3DES_RESULT (out);
       _CVMX_MT_HSH_DAT (in, hash_next, 0);
        CVMX_MT_3DES_DEC_CBC(in);
      rptr[0]=out;
        rptr++;
       dlen-=8;
   }
   CVMX_MF_3DES_RESULT (out);
   rptr[0]=out;
   rptr++;
   pktlen = pktlen -12;
   CVMX_MF_3DES_IV (*((uint64_t *)des_iv));
   /* Finish Inner hash */
   {
      int chunk_len=pktlen%64;
      uint8_t i=0;
      if(chunk_len == 56) {
         chunk_len = 72;
      } else
         chunk_len = 64-chunk_len;
      _CVMX_MT_HSH_DAT (0x8000000000000000ULL, hash_next, 0);
      CVMX_ES64(in, ((pktlen +64) * 8));
      chunk_len-=16;
      while ( i< chunk_len) {
         _CVMX_MT_HSH_DAT (0x0ULL, hash_next, 0);
          i += 8;
      }
      _CVMX_MT_HSH_DAT (in, hash_next, 0);
   }
   #else
   dptr = aptr;
   pktlen = pktlen - 12;
   COP2_PARALLEL_3DES_DEC_MD5(dptr,rptr,dlen);
   CVMX_MF_3DES_IV (*((uint64_t *)des_iv));
   #endif 

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_hash[0], 0);
   CVMX_MF_HSH_IV (inner_hash[1], 1);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (md5defiv[0], 0);
   CVMX_MT_HSH_IV (md5defiv[1], 1);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ opad));

   CVMX_MT_HSH_DAT (inner_hash[0], 0);
   CVMX_MT_HSH_DAT (inner_hash[1], 1);
   CVMX_MT_HSH_DAT (0x8000000000000000ULL, 2);
   CVMX_MT_HSH_DATZ (3);
   CVMX_MT_HSH_DATZ (4);
   CVMX_MT_HSH_DATZ (5);
   CVMX_MT_HSH_DATZ (6);
      in=(64+16)*8;
      CVMX_ES64(in,in);
      CVMX_MT_HSH_STARTMD5 (in);
   /* Get the HMAC */
   CVMX_MF_HSH_IV (md5[0], 0);
   CVMX_MF_HSH_IV (md5[1], 1);
   /* compare first 96 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, md5, 12)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<12;i++)
            printf(" %02x",((uint8_t *)md5)[i]);
         printf("\n Expected");
         for(i=0;i<12;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
   } else
        if(outptr) 
         memcpy(outptr+pktlen, md5, 12);
   *outlen =pktlen;
   return 0;
}


int AES_cbc_md5_decrypt(uint16_t aes_key_len, uint8_t *aes_key, uint16_t auth_keylen, uint8_t *auth_key, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   register uint64_t in1;
   uint64_t md5[2];
   uint32_t dlen;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_hash[2];
   aes_key_len = aes_key_len *8;
   if(pktptr == NULL || pktlen == 0  || aes_key == NULL ||
      aes_iv == NULL || auth_key == NULL || auth_keylen ==0 
      ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
    if(pktlen < (ESP_HEADER_LENGTH +AES_CBC_IV_LENGTH+12+16)) {
      printf("Packet length is not proper \n");
      return -1;
     }
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 256) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[1], 1);

   memset(sha_key,0x0,64);
   if(auth_keylen > 64) {
      if(hash_key(auth_key, auth_keylen, sha_key, 0)<0) {
         printf(" improper mac secret \n");   
         return -1;
   }
   auth_keylen = 16;
   } else
      memcpy(sha_key,auth_key,auth_keylen);

   /* Load MD5 IV */
   CVMX_MT_HSH_IV (md5defiv[0], 0);
   CVMX_MT_HSH_IV (md5defiv[1], 1);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ ipad));

   /* Setup dec/hmac args */
   dptr = (uint64_t *) (pktptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH) ;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen -ESP_HEADER_LENGTH-AES_CBC_IV_LENGTH-12;
   aptr = (uint64_t *) pktptr ;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      ((uint64_t *)outptr)[2]=((uint64_t *)pktptr)[2];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
   }
   else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);

   /* Load esp header and IV to hash unit */

   CVMX_MT_HSH_DAT (*aptr++, 0);
   CVMX_MT_HSH_DAT (*aptr++, 1);
   CVMX_MT_HSH_DAT (*aptr++, 2);

   dptr = aptr;
   pktlen = pktlen - 12;
   COP2_PARALLEL_AES_DEC_MD5(dptr,rptr,dlen);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_hash[0], 0);
   CVMX_MF_HSH_IV (inner_hash[1], 1);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (md5defiv[0], 0);
   CVMX_MT_HSH_IV (md5defiv[1], 1);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ opad));

   CVMX_MT_HSH_DAT (inner_hash[0], 0);
   CVMX_MT_HSH_DAT (inner_hash[1], 1);
   CVMX_MT_HSH_DAT (0x8000000000000000ULL, 2);
   CVMX_MT_HSH_DATZ(3);
   CVMX_MT_HSH_DATZ(4);
   CVMX_MT_HSH_DATZ(5);
   CVMX_MT_HSH_DATZ(6);
   in1 = (64+16)*8;
   CVMX_ES64(in1,in1);
   CVMX_MT_HSH_STARTMD5 (in1);
   /* Get the HMAC */
   CVMX_MF_HSH_IV (md5[0], 0);
   CVMX_MF_HSH_IV (md5[1], 1);
   /* compare first 96 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, md5, 12)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
      for(i=0;i<12;i++)
         printf(" %02x",((uint8_t *)md5)[i]);
      printf("\n Expected");
      for(i=0;i<12;i++)
         printf(" %02x",(pktptr+pktlen)[i]);
      printf("\n");
      return -1;
      }
   } else 
      if(outptr)
         memcpy(outptr+pktlen, md5, 12);
   *outlen =pktlen;
   return 0;
}


int AES_cbc_md5_encrypt(uint16_t aes_key_len, uint8_t *aes_key,  uint16_t auth_keylen, uint8_t *auth_key, uint8_t *espheader, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t in1;
   uint32_t dlen;
   uint64_t md5[2];
   uint8_t sha_key[64];
   uint64_t inner_hash[3];
   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      aes_key == NULL || aes_key_len == 0 || aes_iv == NULL ||
      auth_key == NULL || auth_keylen ==0 ||outlen==NULL){
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if((pktlen < 16) || (pktlen%16)) {
      printf(" packetlen is not proper \n");
      return -1;
   }
   if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-AES_CBC_IV_LENGTH-12)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);
   memset(sha_key,0x0,64);
   if(auth_keylen > 64) {
      if(hash_key(auth_key, auth_keylen, sha_key, 0)<0) {
         printf(" improper mac secret \n");   
      return -1;
   }
   auth_keylen = 16;
   } else
       memcpy(sha_key,auth_key,auth_keylen);
   aes_key_len = aes_key_len *8; 
   
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 256) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (md5defiv[0], 0);
   CVMX_MT_HSH_IV (md5defiv[1], 1);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ ipad));

   /* load esp header and aes_iv */
     aptr =(uint64_t *)espheader;
     CVMX_MT_HSH_DAT (*aptr, 0);
     aptr =(uint64_t *)aes_iv;
     CVMX_MT_HSH_DAT (aptr[0], 1);
     CVMX_MT_HSH_DAT (aptr[1], 2);

   /* setup enc/hmac args */
   dptr = (uint64_t *)pktptr;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen;
      if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)aes_iv)[0];
      ((uint64_t *)outptr)[2]=((uint64_t *)aes_iv)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
   } else 
      rptr= (uint64_t *)pktptr;
   aptr = (uint64_t *)rptr ;

   COP2_PARALLEL_AES_ENC_MD5(dptr,rptr,dlen);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_hash[0], 0);
   CVMX_MF_HSH_IV (inner_hash[1], 1);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (md5defiv[0], 0);
   CVMX_MT_HSH_IV (md5defiv[1], 1);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ opad));

   CVMX_MT_HSH_DAT (inner_hash[0], 0);
   CVMX_MT_HSH_DAT (inner_hash[1], 1);
   CVMX_MT_HSH_DAT (0x8000000000000000ULL, 2);
   CVMX_MT_HSH_DATZ(3);
   CVMX_MT_HSH_DATZ(4);
   CVMX_MT_HSH_DATZ(5);
   CVMX_MT_HSH_DATZ(6);
   in1= (64 +16)*8;
   CVMX_ES64(in1,in1);
   CVMX_MT_HSH_STARTMD5 (in1);

   /* Get the HMAC */
   CVMX_MF_HSH_IV (md5[0], 0);
   CVMX_MF_HSH_IV (md5[1], 1);
   /* put HMac at the end of the packet */
   memcpy(rptr, md5, 12);
   if(outlen) {
      if(outptr)
         *outlen =pktlen+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH+12;
      else
         *outlen =pktlen+12;
   }
   return 0;
}


int NULL_md5_decrypt (uint16_t auth_keylen, uint8_t *auth_key, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *aptr;
   uint64_t md5[2];
   uint32_t dlen, hash_next;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_hash[2];
   uint64_t bits;

   if(pktptr == NULL ||  pktlen == 0  || auth_key == NULL
      || auth_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH+12+1)) {
      printf(" Improper packet length \n");
      return -1;
   } 
   memset(sha_key,0x0,64);
   if(auth_keylen > 64) {
      if(hash_key(auth_key, auth_keylen, sha_key, 0)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
   auth_keylen = 16;
   } else
        memcpy(sha_key,auth_key,auth_keylen);

   /* Load MD5 IV */
   CVMX_MT_HSH_IV (md5defiv[0], 0);
   CVMX_MT_HSH_IV (md5defiv[1], 1);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ ipad));
    
   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   dlen = pktlen -12;
   hash_next = 0;

   /* Loop through input */

   while(dlen >=64) {
     CVMX_MT_HSH_DAT(*aptr++,0);
     CVMX_MT_HSH_DAT(*aptr++,1);
     CVMX_MT_HSH_DAT(*aptr++,2);
     CVMX_MT_HSH_DAT(*aptr++,3);
     CVMX_MT_HSH_DAT(*aptr++,4);
     CVMX_MT_HSH_DAT(*aptr++,5);
     CVMX_MT_HSH_DAT(*aptr++,6);
     CVMX_MT_HSH_STARTMD5(*aptr++);
     dlen -= 64;
   } 
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,0);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,1);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,2);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,3);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,4);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,5);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,6);dlen-=8;}

   pktlen = pktlen - 12;
   hash_next = (pktlen % 64)/8;

   /* Finish Inner hash */
   {
      int chunk_len=pktlen %64;
      uint8_t chunk[100];
      uint8_t i=0;
      uint64_t bits;
      if(chunk_len >= 56) {
         chunk_len = 72;
         chunk_len+=(dlen/8)*8;
      } else {
         chunk_len = 64-chunk_len;
         chunk_len+=dlen;
      }
      if(dlen)
         memcpy(chunk,(pktptr+pktlen-dlen),dlen);
         memset(chunk+dlen,0x0, chunk_len-dlen);
         *(chunk + dlen) = 0x80;
         bits = (pktlen +64)*8;
         CVMX_ES64(bits,bits);
         *((uint64_t *)(chunk + chunk_len -8)) = bits;
         while ( i< chunk_len) {
            _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), hash_next, 0);
            i += 8;
      }
   } 
    
   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_hash[0], 0);
   CVMX_MF_HSH_IV (inner_hash[1], 1);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (md5defiv[0], 0);
   CVMX_MT_HSH_IV (md5defiv[1], 1);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ opad));

   CVMX_MT_HSH_DAT (inner_hash[0], 0);
   CVMX_MT_HSH_DAT (inner_hash[1], 1);
   CVMX_MT_HSH_DAT (0x8000000000000000ULL, 2);
   CVMX_MT_HSH_DATZ(3);
   CVMX_MT_HSH_DATZ(4);
   CVMX_MT_HSH_DATZ(5);
   CVMX_MT_HSH_DATZ(6);
   bits = (64 +16)*8;
   CVMX_ES64(bits,bits);
   CVMX_MT_HSH_STARTMD5 (bits);

   /* Get the HMAC */
   CVMX_MF_HSH_IV (md5[0], 0);
   CVMX_MF_HSH_IV (md5[1], 1);
   /* compare first 96 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, md5, 12)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<12;i++)
            printf(" %02x",((uint8_t *)md5)[i]);
         printf("\n Expected");
         for(i=0;i<12;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
   } else
      if(outptr!=NULL)
         memcpy(outptr+pktlen, md5, 12);
   if(outptr != NULL)
      memcpy(outptr, pktptr, pktlen);
   if(outlen)
      *outlen = pktlen;
   return 0;
}

int NULL_md5_encrypt ( uint16_t auth_keylen, uint8_t *auth_key, uint8_t *espheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *aptr;
   uint32_t dlen, hash_next;
   uint64_t md5[2];
   uint8_t sha_key[64];
   uint64_t inner_hash[3];
   uint64_t bits;
   
   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      auth_key == NULL || auth_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if( pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-12)) {
      printf("Packet is too big to handle \n");
        return -1;
   }
   memset(sha_key,0x0,64);
   if(auth_keylen > 64) {
      if(hash_key(auth_key, auth_keylen, sha_key, 0)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
   auth_keylen = 16;
   } else
        memcpy(sha_key,auth_key,auth_keylen);
   
   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (md5defiv[0], 0);
   CVMX_MT_HSH_IV (md5defiv[1], 1);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ ipad));
   aptr =(uint64_t *)espheader;
   CVMX_MT_HSH_DAT (*aptr, 0);

   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   dlen = pktlen;
   if(outptr)
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
    
   while(dlen >=64) {
     CVMX_MT_HSH_DAT(*aptr++,1);
     CVMX_MT_HSH_DAT(*aptr++,2);
     CVMX_MT_HSH_DAT(*aptr++,3);
     CVMX_MT_HSH_DAT(*aptr++,4);
     CVMX_MT_HSH_DAT(*aptr++,5);
     CVMX_MT_HSH_DAT(*aptr++,6);
     CVMX_MT_HSH_STARTMD5(*aptr++);
     CVMX_MT_HSH_DAT(*aptr++,0);
     dlen -= 64;
   } 
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,1);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,2);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,3);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,4);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,5);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,6);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_STARTMD5(*aptr++);dlen-=8;}

   hash_next = ((pktlen + 8) % 64)/8;
   
   /* Finish inner hash */
   {
      int chunk_len=(pktlen+ESP_HEADER_LENGTH) %64;
      uint8_t chunk[100];
      uint8_t i=0;
      uint64_t bits;
      if(chunk_len >= 56) {
         chunk_len = 72;
         chunk_len+=(dlen/8)*8;
      } else {
         chunk_len = 64-chunk_len;
         chunk_len+=dlen;
      }
      if(dlen)
         memcpy(chunk,(pktptr+pktlen-dlen),dlen);
   
      memset(chunk+dlen,0x0, chunk_len-dlen);
      *(chunk+dlen)= 0x80;
      bits = (pktlen+ESP_HEADER_LENGTH+ 64)*8;
      CVMX_ES64(bits,bits);
      *((uint64_t *)(chunk + chunk_len -8)) = bits;
      while ( i< chunk_len) {
         _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), hash_next, 0);
          i += 8;
      }
   } 

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_hash[0], 0);
   CVMX_MF_HSH_IV (inner_hash[1], 1);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (md5defiv[0], 0);
   CVMX_MT_HSH_IV (md5defiv[1], 1);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ opad));

   CVMX_MT_HSH_DAT (inner_hash[0], 0);
   CVMX_MT_HSH_DAT (inner_hash[1], 1);
   CVMX_MT_HSH_DAT (0x8000000000000000ULL, 2);
   CVMX_MT_HSH_DATZ(3);
   CVMX_MT_HSH_DATZ(4);
   CVMX_MT_HSH_DATZ(5);
   CVMX_MT_HSH_DATZ(6);
   bits = (64 +16)*8;
   CVMX_ES64(bits,bits);
   CVMX_MT_HSH_STARTMD5 (bits);

   /* Get the HMAC */
   CVMX_MF_HSH_IV (md5[0], 0);
   CVMX_MF_HSH_IV (md5[1], 1);
   /* put HMac at the end of the packet */
   if(outptr != NULL) {
      memcpy((outptr+ESP_HEADER_LENGTH),pktptr, pktlen);
      memcpy((outptr+ESP_HEADER_LENGTH+pktlen),md5, 12);
   }
     else {
      memcpy(pktptr+pktlen, md5, 12);
   }
   if(outlen) {
      if(outptr)
         *outlen =pktlen+ESP_HEADER_LENGTH+12;
      else
         *outlen =pktlen+12;
   }
   return 0;
}

int NULL_sha1_encrypt ( uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *aptr;
   uint64_t sha1[3];
   uint32_t dlen, sha1_next;
   uint8_t sha_key[64];
   uint64_t inner_sha[3];
   if(pktptr == NULL || espheader==NULL || pktlen == 0  ||
      sha1_key == NULL || sha1_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
    }
   if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-ICV_LEN_SHA1)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
  
   memset(sha_key,0x0,64);
   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 1)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
   sha1_keylen = 20;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);

   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ ipad));

   aptr = (uint64_t *) espheader;
   CVMX_MT_HSH_DAT (*aptr, 0);

   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   dlen = pktlen;
   if(outptr!=NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
   }

   while(dlen >=64) {
     CVMX_MT_HSH_DAT(*aptr++,1);
     CVMX_MT_HSH_DAT(*aptr++,2);
     CVMX_MT_HSH_DAT(*aptr++,3);
     CVMX_MT_HSH_DAT(*aptr++,4);
     CVMX_MT_HSH_DAT(*aptr++,5);
     CVMX_MT_HSH_DAT(*aptr++,6);
     CVMX_MT_HSH_STARTSHA(*aptr++);
     CVMX_MT_HSH_DAT(*aptr++,0);
     dlen -= 64;
   } 
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,1);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,2);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,3);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,4);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,5);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,6);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_STARTSHA(*aptr++);dlen-=8;}

   sha1_next = ((pktlen + 8) % 64)/8;

   /* Finish inner hash */
   {
      int chunk_len=(pktlen+ESP_HEADER_LENGTH) %64;
      uint8_t chunk[100];
      uint8_t i=0;
      if(chunk_len >= 56) {
         chunk_len = 72;
         chunk_len+=(dlen/8)*8;
      } else {
         chunk_len = 64-chunk_len;
         chunk_len+=dlen;
      }
      if(dlen)
         memcpy(chunk,(pktptr+pktlen-dlen),dlen);
      memset(chunk+dlen,0x0, chunk_len-dlen);
      *(chunk+dlen)= 0x80;
      *((uint64_t *)(chunk + chunk_len -8)) = (pktlen+ESP_HEADER_LENGTH+64) * 8;
      while ( i< chunk_len) {
      _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), sha1_next, 1);
       i += 8;
      }
   } 

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_sha[0], 0);
   CVMX_MF_HSH_IV (inner_sha[1], 1);
   CVMX_MF_HSH_IV (inner_sha[2], 2);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ opad));

   CVMX_MT_HSH_DAT (inner_sha[0], 0);
   CVMX_MT_HSH_DAT (inner_sha[1], 1);
   ((uint8_t *)inner_sha)[20]=0x80;
   ((uint8_t *)inner_sha)[21]=0x0;
   ((uint8_t *)inner_sha)[22]=0x0;
   ((uint8_t *)inner_sha)[23]=0x0;
   CVMX_MT_HSH_DAT (inner_sha[2], 2);
   CVMX_MT_HSH_DATZ (3);
   CVMX_MT_HSH_DATZ (4);
   CVMX_MT_HSH_DATZ (5);
   CVMX_MT_HSH_DATZ (6);
   CVMX_MT_HSH_STARTSHA ((uint64_t) ((64 + 20) * 8));

   /* Get the HMAC */
   CVMX_MF_HSH_IV (sha1[0], 0);
   CVMX_MF_HSH_IV (sha1[1], 1);
   /* put HMac at the end of the packet */
   if(outptr != NULL) {
      memcpy(outptr+ESP_HEADER_LENGTH, pktptr, pktlen);
        memcpy((outptr+ESP_HEADER_LENGTH+ pktlen),(uint8_t *)sha1,ICV_LEN_SHA1);
   }
   else {
      memcpy(pktptr+pktlen, sha1, ICV_LEN_SHA1);
   }
   if(outlen) {
      if(outptr)
         *outlen =pktlen+ESP_HEADER_LENGTH+ICV_LEN_SHA1;
      else
         *outlen =pktlen+ICV_LEN_SHA1;
   }
   return 0;
}

int NULL_sha1_decrypt (uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *aptr;
   uint64_t sha1[3];
   uint32_t dlen, sha1_next;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_sha[3];
   if(pktptr == NULL || pktlen == 0  || sha1_key == NULL || 
      sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
     if(pktlen < (ESP_HEADER_LENGTH+ICV_LEN_SHA1+1)) {
      printf(" Improper packet length \n");
      return -1;
   } 
   memset(sha_key,0x0,64);
   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 1)<0) {
         printf(" improper mac secret \n");    
         return -1;
      }
   sha1_keylen = 20;
   } else
        memcpy(sha_key,sha1_key,sha1_keylen);

   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ ipad));
   
   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   dlen = pktlen -ICV_LEN_SHA1;
   sha1_next = 0;

   /* Loop through input */
   while(dlen >=64) {
     CVMX_MT_HSH_DAT(*aptr++,0);
     CVMX_MT_HSH_DAT(*aptr++,1);
     CVMX_MT_HSH_DAT(*aptr++,2);
     CVMX_MT_HSH_DAT(*aptr++,3);
     CVMX_MT_HSH_DAT(*aptr++,4);
     CVMX_MT_HSH_DAT(*aptr++,5);
     CVMX_MT_HSH_DAT(*aptr++,6);
     CVMX_MT_HSH_STARTSHA(*aptr++);
     dlen -= 64;
   } 
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,0);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,1);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,2);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,3);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,4);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,5);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,6);dlen-=8;}


   pktlen = pktlen - ICV_LEN_SHA1;
   sha1_next = (pktlen % 64)/8;
   /* Finish Inner hash */
   {
      int chunk_len=pktlen %64;
      uint8_t chunk[100];
      uint8_t i=0;
      if(chunk_len >= 56) {
         chunk_len = 72;
         chunk_len+=(dlen/8)*8;
      } else {
         chunk_len = 64-chunk_len;
         chunk_len+=dlen;
      }
      if(dlen)
         memcpy(chunk,(pktptr+pktlen-dlen),dlen);
         memset(chunk+dlen,0x0, chunk_len-dlen);
         *(chunk+dlen)= 0x80;
         *((uint64_t *)(chunk + chunk_len -8)) = (pktlen+ 64) * 8;
         while ( i< chunk_len) {
            _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), sha1_next, 1);
             i += 8;
      }
   } 

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_sha[0], 0);
   CVMX_MF_HSH_IV (inner_sha[1], 1);
   CVMX_MF_HSH_IV (inner_sha[2], 2);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ opad));

   CVMX_MT_HSH_DAT (inner_sha[0], 0);
   CVMX_MT_HSH_DAT (inner_sha[1], 1);
   ((uint8_t *)inner_sha)[20]=0x80;
   ((uint8_t *)inner_sha)[21]=0x0;
   ((uint8_t *)inner_sha)[22]=0x0;
   ((uint8_t *)inner_sha)[23]=0x0;
   CVMX_MT_HSH_DAT (inner_sha[2], 2);
   CVMX_MT_HSH_DATZ(3);
   CVMX_MT_HSH_DATZ(4);
   CVMX_MT_HSH_DATZ(5);
   CVMX_MT_HSH_DATZ(6);
   CVMX_MT_HSH_STARTSHA ((uint64_t) ((64 + 20) * 8));

   /* Get the HMAC */
   CVMX_MF_HSH_IV (sha1[0], 0);
   CVMX_MF_HSH_IV (sha1[1], 1);
   /* compare first 96 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, sha1, ICV_LEN_SHA1)){
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA1;i++)
            printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA1;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
   } else 
      if(outptr)
           memcpy(outptr+pktlen, sha1, ICV_LEN_SHA1);
   if(outptr != NULL)
      memcpy(outptr, pktptr, pktlen);
     if(outlen)
      *outlen=pktlen;
   return 0;
}

int NULL_sha224_encrypt(uint16_t sha2_keylen, uint8_t *sha2_key, uint8_t *espheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
    uint64_t *aptr;
    uint64_t sha2[4];
    uint32_t dlen, sha2_next;
    uint8_t  sha_key[64];
    uint64_t inner_sha[4];

    if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
            sha2_key == NULL || sha2_keylen ==0 || outlen==NULL ) {
        printf("\n Wrong parameters \n");   
        return -1;
    }
    if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-ICV_LEN_SHA224)) {
        printf("Packet is too big to handle \n");
        return -1;
    }

    MEMSET64BTZ(sha_key);

    if(sha2_keylen > 64) {
        if(hash_key(sha2_key, sha2_keylen, sha_key, 2)<0) {
            printf(" improper mac secret \n");   
            return -1;
        }
        sha2_keylen = 32;
    } else
        memcpy(sha_key,sha2_key,sha2_keylen);

    /* Load SHA2 IV */
    CVMX_M32BT_HSH_IV(sha224defiv);

    /* Load key xor ipad */
    aptr = (uint64_t *) sha_key;
    CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad)); 

    /* load Esp header and iv */
    aptr =(uint64_t *)espheader;
    CVMX_MT_HSH_DAT (*aptr, 0);

    /* Copy header & setup enc/hmac args */
    aptr = (uint64_t *) pktptr;
    dlen = pktlen;
    if(outptr != NULL) {
        ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
    } 

    while(dlen >=64) {
        CVMX_MT_HSH_DAT(*aptr++,1);
        CVMX_MT_HSH_DAT(*aptr++,2);
        CVMX_MT_HSH_DAT(*aptr++,3);
        CVMX_MT_HSH_DAT(*aptr++,4);
        CVMX_MT_HSH_DAT(*aptr++,5);
        CVMX_MT_HSH_DAT(*aptr++,6);
        CVMX_MT_HSH_STARTSHA256(*aptr++);
        CVMX_MT_HSH_DAT(*aptr++,0);
        dlen -= 64;
    } 
    if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,1);dlen-=8;}
    if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,2);dlen-=8;}
    if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,3);dlen-=8;}
    if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,4);dlen-=8;}
    if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,5);dlen-=8;}
    if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,6);dlen-=8;}
    if(dlen >= 8) {CVMX_MT_HSH_STARTSHA256(*aptr++);dlen-=8;}

    sha2_next = ((pktlen + 8) % 64)/8;

    /* Finish inner hash */
    {
        int chunk_len=(pktlen+ESP_HEADER_LENGTH) %64;
        uint8_t chunk[100];
        uint8_t i=0;
        if(chunk_len >= 56) {
            chunk_len = 72;
            chunk_len+=(dlen/8)*8;
        } else {
            chunk_len = 64-chunk_len;
            chunk_len+=dlen;
        }
        if(dlen)
            memcpy(chunk,(pktptr+pktlen-dlen),dlen);
        memset(chunk+dlen,0x0, chunk_len-dlen);
        *(chunk+dlen)= 0x80;
        *((uint64_t *)(chunk + chunk_len -8)) = (pktlen+ESP_HEADER_LENGTH+64) * 8;
        while ( i< chunk_len) {
            _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), sha2_next, 2);
            i += 8;
        }
    } 
    /* Get the inner hash of HMAC */
    CVMX_M32BF_HSH_IV(inner_sha);

    /* Initialize hash unit */
    CVMX_M32BT_HSH_IV(sha224defiv);

    /* Load key xor opad */
    aptr = (uint64_t *) sha_key;
    CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));

    CVMX_M64BT_HSH_DAT_SHA224_HMAC(inner_sha);

    /* Get the HMAC */
    CVMX_M16BF_HSH_IV(sha2);

    /* put HMac at the end of the packet */
    if(outptr != NULL) {
        memcpy(outptr+ESP_HEADER_LENGTH, pktptr, pktlen);
        memcpy((outptr+ESP_HEADER_LENGTH+ pktlen),(uint8_t *)sha2,ICV_LEN_SHA224);
    }
    else {
        memcpy(pktptr+pktlen, sha2, ICV_LEN_SHA224);
    }
    if(outlen) {
        if(outptr)
            *outlen = (pktlen + ESP_HEADER_LENGTH +ICV_LEN_SHA224);
        else
            *outlen = (pktlen + ICV_LEN_SHA224);
    }
    return 0;
}

int NULL_sha224_decrypt(uint16_t sha2_keylen, uint8_t *sha2_key, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
    uint64_t *aptr;
    uint64_t sha2[4];
    uint32_t dlen, sha2_next;
    uint32_t i;
    uint8_t sha_key[64];
    uint64_t inner_sha[4];
    if(pktptr == NULL || pktlen == 0  ||
            sha2_key == NULL || sha2_keylen ==0||outlen==NULL ) {
        printf("\n Wrong parameters \n");   
        return -1;
    }
    if(pktlen < (ESP_HEADER_LENGTH +ICV_LEN_SHA224+1)) {
        printf("Packet length is not proper \n");
        return -1;
    }
    memset(sha_key,0x0,64);
    if(sha2_keylen > 64) {
        if(hash_key(sha2_key, sha2_keylen, sha_key, 2)<0) {
            printf(" improper mac secret \n");   
            return -1;
        }
        sha2_keylen = 32;
    } else
        memcpy(sha_key,sha2_key,sha2_keylen);

    /* Load SHA2 IV */
    CVMX_M32BT_HSH_IV(sha224defiv);

    /* Load key xor ipad */
    aptr = (uint64_t *) sha_key;
    CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad));

    /* setup enc/hmac args */
    aptr = (uint64_t *)pktptr ;
    dlen = pktlen - ICV_LEN_SHA224;
    sha2_next = 0;

    /* Loop through input */
    while(dlen >=64) {
        CVMX_MT_HSH_DAT(*aptr++,0);
        CVMX_MT_HSH_DAT(*aptr++,1);
        CVMX_MT_HSH_DAT(*aptr++,2);
        CVMX_MT_HSH_DAT(*aptr++,3);
        CVMX_MT_HSH_DAT(*aptr++,4);
        CVMX_MT_HSH_DAT(*aptr++,5);
        CVMX_MT_HSH_DAT(*aptr++,6);
        CVMX_MT_HSH_STARTSHA256(*aptr++);
        dlen -= 64;
    } 
    if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,0);dlen-=8;}
    if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,1);dlen-=8;}
    if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,2);dlen-=8;}
    if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,3);dlen-=8;}
    if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,4);dlen-=8;}
    if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,5);dlen-=8;}
    if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,6);dlen-=8;}


    pktlen = pktlen - ICV_LEN_SHA224;
    sha2_next = (pktlen % 64)/8;
    /* Finish Inner hash */
    {
        int chunk_len=pktlen %64;
        uint8_t chunk[100];
        uint8_t i=0;
        if(chunk_len >= 56) {
            chunk_len = 72;
            chunk_len+=(dlen/8)*8;
        } else {
            chunk_len = 64-chunk_len;
            chunk_len+=dlen;
        }
        if(dlen)
            memcpy(chunk,(pktptr+pktlen-dlen),dlen);
        memset(chunk+dlen,0x0, chunk_len-dlen);
        *(chunk+dlen)= 0x80;
        *((uint64_t *)(chunk + chunk_len -8)) = (pktlen+ 64) * 8;
        while ( i< chunk_len) {
            _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), sha2_next, 2);
            i += 8;
        }
    } 

    /* Get the inner hash of HMAC */
    CVMX_M32BF_HSH_IV(inner_sha);

    /* Initialize hash unit */
    CVMX_M32BT_HSH_IV(sha224defiv);

    /* Load key xor opad */
    aptr = (uint64_t *) sha_key;
    CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));


    CVMX_M64BT_HSH_DAT_SHA224_HMAC(inner_sha);

    /* Get the HMAC */
    CVMX_M16BF_HSH_IV(sha2);

    /* compare first 128 bits of HMAC with received mac */
    if(compdigest) {
        if(memcmp(pktptr+pktlen, sha2, ICV_LEN_SHA224)) {
            printf("\n INBOUND Mac Mismatch ");
            printf("\n Generated");
            for(i=0;i<ICV_LEN_SHA224;i++)
                printf(" %02x",((uint8_t *)sha2)[i]);
            printf("\n Expected");
            for(i=0;i<ICV_LEN_SHA224;i++)
                printf(" %02x",(pktptr+pktlen)[i]);
            printf("\n");
            return -1;
        }
    } else if(outptr)
        memcpy(outptr+pktlen, sha2, ICV_LEN_SHA224);
    if(outptr != NULL)
        memcpy(outptr, pktptr, pktlen);
    if(outlen)
        *outlen = pktlen;
    return 0;
}

int NULL_sha256_encrypt(uint16_t sha2_keylen, uint8_t *sha2_key, uint8_t *espheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *aptr;
   uint64_t sha2[4];
   uint32_t dlen, sha2_next;
   uint8_t  sha_key[64];
   uint64_t inner_sha[4];
    
   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      sha2_key == NULL || sha2_keylen ==0 || outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
    }
   if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-ICV_LEN_SHA256)) {
      printf("Packet is too big to handle \n");
      return -1;
   }

   MEMSET64BTZ(sha_key);

   if(sha2_keylen > 64) {
      if(hash_key(sha2_key, sha2_keylen, sha_key, 2)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha2_keylen = 32;
   } else
      memcpy(sha_key,sha2_key,sha2_keylen);
   
   /* Load SHA2 IV */
   CVMX_M32BT_HSH_IV(sha256defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad)); 

   /* load Esp header and iv */
   aptr =(uint64_t *)espheader;
   CVMX_MT_HSH_DAT (*aptr, 0);

   /* Copy header & setup enc/hmac args */
   aptr = (uint64_t *) pktptr;
   dlen = pktlen;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
   } 

   while(dlen >=64) {
     CVMX_MT_HSH_DAT(*aptr++,1);
     CVMX_MT_HSH_DAT(*aptr++,2);
     CVMX_MT_HSH_DAT(*aptr++,3);
     CVMX_MT_HSH_DAT(*aptr++,4);
     CVMX_MT_HSH_DAT(*aptr++,5);
     CVMX_MT_HSH_DAT(*aptr++,6);
     CVMX_MT_HSH_STARTSHA256(*aptr++);
     CVMX_MT_HSH_DAT(*aptr++,0);
     dlen -= 64;
   } 
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,1);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,2);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,3);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,4);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,5);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,6);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_STARTSHA256(*aptr++);dlen-=8;}

   sha2_next = ((pktlen + 8) % 64)/8;

   /* Finish inner hash */
   {
      int chunk_len=(pktlen+ESP_HEADER_LENGTH) %64;
      uint8_t chunk[100];
      uint8_t i=0;
      if(chunk_len >= 56) {
         chunk_len = 72;
         chunk_len+=(dlen/8)*8;
      } else {
         chunk_len = 64-chunk_len;
         chunk_len+=dlen;
      }
      if(dlen)
         memcpy(chunk,(pktptr+pktlen-dlen),dlen);
      memset(chunk+dlen,0x0, chunk_len-dlen);
      *(chunk+dlen)= 0x80;
      *((uint64_t *)(chunk + chunk_len -8)) = (pktlen+ESP_HEADER_LENGTH+64) * 8;
      while ( i< chunk_len) {
      _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), sha2_next, 2);
       i += 8;
      }
   } 
   /* Get the inner hash of HMAC */
   CVMX_M32BF_HSH_IV(inner_sha);

   /* Initialize hash unit */
   CVMX_M32BT_HSH_IV(sha256defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));

   CVMX_M64BT_HSH_DAT_SHA256_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_M16BF_HSH_IV(sha2);
   
   /* put HMac at the end of the packet */
   if(outptr != NULL) {
      memcpy(outptr+ESP_HEADER_LENGTH, pktptr, pktlen);
        memcpy((outptr+ESP_HEADER_LENGTH+ pktlen),(uint8_t *)sha2,ICV_LEN_SHA256);
   }
   else {
      memcpy(pktptr+pktlen, sha2, ICV_LEN_SHA256);
   }
   if(outlen) {
      if(outptr)
         *outlen = (pktlen + ESP_HEADER_LENGTH +ICV_LEN_SHA256);
      else
         *outlen = (pktlen + ICV_LEN_SHA256);
   }
   return 0;
}


int NULL_sha256_decrypt(uint16_t sha2_keylen, uint8_t *sha2_key, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *aptr;
   uint64_t sha2[4];
   uint32_t dlen, sha2_next;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_sha[4];
   if(pktptr == NULL || pktlen == 0  ||
      sha2_key == NULL || sha2_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +ICV_LEN_SHA256+1)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   memset(sha_key,0x0,64);
   if(sha2_keylen > 64) {
      if(hash_key(sha2_key, sha2_keylen, sha_key, 2)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha2_keylen = 32;
   } else
   memcpy(sha_key,sha2_key,sha2_keylen);

   /* Load SHA2 IV */
   CVMX_M32BT_HSH_IV(sha256defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad));

   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   dlen = pktlen - ICV_LEN_SHA256;
   sha2_next = 0;

   /* Loop through input */
   while(dlen >=64) {
     CVMX_MT_HSH_DAT(*aptr++,0);
     CVMX_MT_HSH_DAT(*aptr++,1);
     CVMX_MT_HSH_DAT(*aptr++,2);
     CVMX_MT_HSH_DAT(*aptr++,3);
     CVMX_MT_HSH_DAT(*aptr++,4);
     CVMX_MT_HSH_DAT(*aptr++,5);
     CVMX_MT_HSH_DAT(*aptr++,6);
     CVMX_MT_HSH_STARTSHA256(*aptr++);
     dlen -= 64;
   } 
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,0);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,1);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,2);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,3);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,4);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,5);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,6);dlen-=8;}


   pktlen = pktlen - ICV_LEN_SHA256;
   sha2_next = (pktlen % 64)/8;
   /* Finish Inner hash */
   {
      int chunk_len=pktlen %64;
      uint8_t chunk[100];
      uint8_t i=0;
      if(chunk_len >= 56) {
         chunk_len = 72;
         chunk_len+=(dlen/8)*8;
      } else {
         chunk_len = 64-chunk_len;
         chunk_len+=dlen;
      }
      if(dlen)
         memcpy(chunk,(pktptr+pktlen-dlen),dlen);
         memset(chunk+dlen,0x0, chunk_len-dlen);
         *(chunk+dlen)= 0x80;
         *((uint64_t *)(chunk + chunk_len -8)) = (pktlen+ 64) * 8;
         while ( i< chunk_len) {
            _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), sha2_next, 2);
             i += 8;
      }
   } 

   /* Get the inner hash of HMAC */
   CVMX_M32BF_HSH_IV(inner_sha);

   /* Initialize hash unit */
   CVMX_M32BT_HSH_IV(sha256defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));


   CVMX_M64BT_HSH_DAT_SHA256_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_M16BF_HSH_IV(sha2);

   /* compare first 128 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, sha2, ICV_LEN_SHA256)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA256;i++)
            printf(" %02x",((uint8_t *)sha2)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA256;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
   } else if(outptr)
      memcpy(outptr+pktlen, sha2, ICV_LEN_SHA256);
   if(outptr != NULL)
      memcpy(outptr, pktptr, pktlen);
   if(outlen)
      *outlen = pktlen;
   return 0;
}


int NULL_sha384_encrypt(uint16_t sha2_keylen, uint8_t *sha2_key, uint8_t *espheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *aptr;
   uint64_t sha2[8];
   uint32_t dlen, sha2_next;

   uint8_t sha_key[128];
   uint64_t inner_sha[8];

   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      sha2_key == NULL || sha2_keylen == 0 || outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }

   if( pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-ICV_LEN_SHA384)) {
      printf("Packet is too big to handle \n");
      return -1;
   }

   MEMSET128BTZ(sha_key);

   if(sha2_keylen > 128) {
      if(hash_key_sha512(sha2_key, sha2_keylen, sha_key,0)<0) {
         printf(" improper mac secret \n");   
         return -1;
   }
      sha2_keylen = 64;
   } else {
      if(sha2_keylen == 64) 
      {
        MEMCPY64B(sha_key,sha2_key);
      } else {
        memcpy(sha_key,sha2_key,sha2_keylen);
      }
   }


   /* Load SHA2 IV */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ ipad));

   aptr = (uint64_t *)espheader;
   CVMX_MT_HSH_DATW (*aptr, 0);

   /* Copy header & setup enc/hmac args */
   aptr = (uint64_t *) pktptr;
   dlen = pktlen ;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
   }

   while (dlen >= 128) {
     CVMX_MT_HSH_DATW (*aptr++, 1);
     CVMX_MT_HSH_DATW (*aptr++, 2);
     CVMX_MT_HSH_DATW (*aptr++, 3);
     CVMX_MT_HSH_DATW (*aptr++, 4);
     CVMX_MT_HSH_DATW (*aptr++, 5);
     CVMX_MT_HSH_DATW (*aptr++, 6);
     CVMX_MT_HSH_DATW (*aptr++, 7);
     CVMX_MT_HSH_DATW (*aptr++, 8);
     CVMX_MT_HSH_DATW (*aptr++, 9);
     CVMX_MT_HSH_DATW (*aptr++, 10);
     CVMX_MT_HSH_DATW (*aptr++, 11);
     CVMX_MT_HSH_DATW (*aptr++, 12);
     CVMX_MT_HSH_DATW (*aptr++, 13);
     CVMX_MT_HSH_DATW (*aptr++, 14);
     CVMX_MT_HSH_STARTSHA512 (*aptr++);
     CVMX_MT_HSH_DATW (*aptr++, 0);
     dlen -= 128;
   }
  
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,1);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,2);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,3);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,4);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,5);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,6);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,7);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,8);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,9);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,10);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,11);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,12);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,13);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,14);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_STARTSHA512(*aptr++);dlen-=8;}

   sha2_next = ((pktlen + 8) % 128)/8;

   /* Finish inner hash */
   {
      int chunk_len=(pktlen+ESP_HEADER_LENGTH)%128;
      uint8_t chunk[200];
      uint8_t i=0;
      if(chunk_len >= 112 && chunk_len < 120) {
         chunk_len = 144;
         chunk_len+=(dlen/8)*8;
      } else if(chunk_len >=120) {
         chunk_len=136;
         chunk_len+=(dlen/8)*8;
      }
      else {
         chunk_len = 128-chunk_len;
         chunk_len += dlen;
      }
      memset(chunk,0x0, chunk_len);

      if(dlen)
         memcpy(chunk,(pktptr+pktlen-dlen),dlen);
      *(chunk+dlen)= 0x80;
      uint64_t_mul (((uint64_t *)(chunk+chunk_len-16))[0],((uint64_t *)(chunk+chunk_len-16))[1], (pktlen + ESP_HEADER_LENGTH + 128), 0x8ull);

      while ( i< chunk_len) {
        _CVMX_MT_HSH_DATW (*((uint64_t *)(chunk+i)), sha2_next );
        i += 8;
      }
   }

   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ opad));

   CVMX_M128BT_HSH_DATW_SHA384_HMAC(inner_sha);
   
  /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha2[0], 0);
   CVMX_MF_HSH_IVW (sha2[1], 1);
   CVMX_MF_HSH_IVW (sha2[2], 2);
   
  /* put HMac at the end of the packet */
   if(outptr != NULL) {
      memcpy(outptr+ESP_HEADER_LENGTH, pktptr, pktlen);
        memcpy((outptr+ESP_HEADER_LENGTH+ pktlen),(uint8_t *)sha2,ICV_LEN_SHA384);
   }
   else {
      memcpy(pktptr+pktlen, sha2, ICV_LEN_SHA384);
   }
   if(outlen) {
      if(outptr)
         *outlen = pktlen +ESP_HEADER_LENGTH +ICV_LEN_SHA384;
      else
         *outlen = pktlen +ICV_LEN_SHA384;
   }
   return 0;
}


int NULL_sha384_decrypt(uint16_t sha2_keylen, uint8_t *sha2_key, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *aptr;
   uint64_t sha2[8];
   uint32_t dlen, sha2_next;
   int i;
   uint8_t sha_key[128];
   uint64_t inner_sha[8];
   if(pktptr == NULL  || pktlen == 0 || 
      sha2_key == NULL || sha2_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH+ICV_LEN_SHA384+1)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   memset(sha_key,0x0,128);
   if(sha2_keylen > 128) {
      if(hash_key_sha512(sha2_key, sha2_keylen, sha_key,0)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha2_keylen = 64;
   } else
      memcpy(sha_key,sha2_key,sha2_keylen);

   /* Load SHA2 IV */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;

   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ ipad));
   
   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   dlen = pktlen -ICV_LEN_SHA384;
   sha2_next = 0;

   /* Loop through input */
   while (dlen >= 128) {
     CVMX_MT_HSH_DATW (*aptr++, 0);
     CVMX_MT_HSH_DATW (*aptr++, 1);
     CVMX_MT_HSH_DATW (*aptr++, 2);
     CVMX_MT_HSH_DATW (*aptr++, 3);
     CVMX_MT_HSH_DATW (*aptr++, 4);
     CVMX_MT_HSH_DATW (*aptr++, 5);
     CVMX_MT_HSH_DATW (*aptr++, 6);
     CVMX_MT_HSH_DATW (*aptr++, 7);
     CVMX_MT_HSH_DATW (*aptr++, 8);
     CVMX_MT_HSH_DATW (*aptr++, 9);
     CVMX_MT_HSH_DATW (*aptr++, 10);
     CVMX_MT_HSH_DATW (*aptr++, 11);
     CVMX_MT_HSH_DATW (*aptr++, 12);
     CVMX_MT_HSH_DATW (*aptr++, 13);
     CVMX_MT_HSH_DATW (*aptr++, 14);
     CVMX_MT_HSH_STARTSHA512 (*aptr++);
     dlen -= 128;
   }
  
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,0);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,1);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,2);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,3);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,4);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,5);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,6);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,7);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,8);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,9);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,10);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,11);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,12);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,13);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,14);dlen-=8;}

   pktlen = pktlen - ICV_LEN_SHA384;
   sha2_next = (pktlen % 128)/8;
   /* Finish inner hash */
   {
      int chunk_len = pktlen%128;
      uint8_t chunk[200];
      uint8_t i=0;
      if(chunk_len >= 112 && chunk_len < 120) {
         chunk_len = 144;
         chunk_len+=(dlen/8)*8;
      } else if(chunk_len >=120) {
         chunk_len=136;
         chunk_len+=(dlen/8)*8;
      }
      else {
         chunk_len = 128-chunk_len;
         chunk_len += dlen;
      }
      memset(chunk,0x0, chunk_len);

      if(dlen)
         memcpy(chunk,(pktptr+pktlen-dlen),dlen);
      *(chunk+dlen)= 0x80;
      uint64_t_mul (((uint64_t *)(chunk+chunk_len-16))[0],((uint64_t *)(chunk+chunk_len-16))[1], (pktlen + 128), 0x8ull);

      while ( i< chunk_len) {
        _CVMX_MT_HSH_DATW (*((uint64_t *)(chunk+i)), sha2_next );
        i += 8;
      }
   }
   
   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   
   CVMX_M128BT_HSH_DATW_SHA512 ((*aptr++ ^ opad));

   CVMX_M128BT_HSH_DATW_SHA384_HMAC(inner_sha);  

   /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha2[0], 0);
   CVMX_MF_HSH_IVW (sha2[1], 1);
   CVMX_MF_HSH_IVW (sha2[2], 2);

   /* compare first 192 bits of HMAC with received mac */
   if(compdigest) {
        if(memcmp(pktptr+pktlen, sha2, ICV_LEN_SHA384)) {
          printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA384;i++)
              printf(" %02x",((uint8_t *)sha2)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA384;i++)
              printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }   
   } else if(outptr)
        memcpy(outptr+pktlen, sha2, ICV_LEN_SHA384);
   if(outptr != NULL)
      memcpy(outptr, pktptr, pktlen);
        
   *outlen=pktlen;
   return 0;
}

int NULL_sha512_encrypt( uint16_t sha2_keylen, uint8_t *sha2_key, uint8_t *espheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *aptr;
   uint64_t sha2[8];
   uint32_t dlen, sha2_next;
   
   uint8_t sha_key[128];
   uint64_t inner_sha[8];

   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      sha2_key == NULL || sha2_keylen ==0 || outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }

   if( pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-ICV_LEN_SHA512)) {
      printf("Packet is too big to handle \n");
      return -1;
   }

   MEMSET128BTZ(sha_key);

   if(sha2_keylen > 128) {
      if(hash_key_sha512(sha2_key, sha2_keylen, sha_key,1)<0) {
         printf(" improper mac secret \n");   
         return -1;
   }
      sha2_keylen = 64;
   } else {
      if(sha2_keylen == 64) 
      {
        MEMCPY64B(sha_key,sha2_key);
      } else {
        memcpy(sha_key,sha2_key,sha2_keylen);
      }
   }

   /* Load SHA2 IV */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ ipad));

   aptr =(uint64_t *)espheader;
   CVMX_MT_HSH_DATW (*aptr, 0);

   /* Copy header & setup enc/hmac args */
   aptr = (uint64_t *) pktptr;
   dlen = pktlen ;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
   }

   while (dlen >= 128) {
     CVMX_MT_HSH_DATW (*aptr++, 1);
     CVMX_MT_HSH_DATW (*aptr++, 2);
     CVMX_MT_HSH_DATW (*aptr++, 3);
     CVMX_MT_HSH_DATW (*aptr++, 4);
     CVMX_MT_HSH_DATW (*aptr++, 5);
     CVMX_MT_HSH_DATW (*aptr++, 6);
     CVMX_MT_HSH_DATW (*aptr++, 7);
     CVMX_MT_HSH_DATW (*aptr++, 8);
     CVMX_MT_HSH_DATW (*aptr++, 9);
     CVMX_MT_HSH_DATW (*aptr++, 10);
     CVMX_MT_HSH_DATW (*aptr++, 11);
     CVMX_MT_HSH_DATW (*aptr++, 12);
     CVMX_MT_HSH_DATW (*aptr++, 13);
     CVMX_MT_HSH_DATW (*aptr++, 14);
     CVMX_MT_HSH_STARTSHA512 (*aptr++);
     CVMX_MT_HSH_DATW (*aptr++, 0);
     dlen -= 128;
   }
  
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,1);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,2);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,3);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,4);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,5);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,6);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,7);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,8);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,9);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,10);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,11);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,12);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,13);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,14);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_STARTSHA512(*aptr++);dlen-=8;}

   sha2_next = ((pktlen + 8) % 128)/8;
   /* Finish inner hash */
   {
      int chunk_len=(pktlen+ESP_HEADER_LENGTH)%128;
      uint8_t chunk[200];
      uint8_t i=0;
      if(chunk_len >= 112 && chunk_len < 120) {
         chunk_len = 144;
         chunk_len+=(dlen/8)*8;
      } else if(chunk_len >=120) {
         chunk_len=136;
         chunk_len+=(dlen/8)*8;
      }
      else {
         chunk_len = 128-chunk_len;
         chunk_len += dlen;
      }
      memset(chunk,0x0, chunk_len);

      if(dlen)
         memcpy(chunk,(pktptr+pktlen-dlen),dlen);
      *(chunk+dlen)= 0x80;
      uint64_t_mul (((uint64_t *)(chunk+chunk_len-16))[0],((uint64_t *)(chunk+chunk_len-16))[1], (pktlen + ESP_HEADER_LENGTH + 128), 0x8ull);

      while ( i< chunk_len) {
         _CVMX_MT_HSH_DATW (*((uint64_t *)(chunk+i)), sha2_next );
         i += 8;
      }
   }

   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ opad));

   CVMX_M128BT_HSH_DATW_SHA512_HMAC(inner_sha);
   
  /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha2[0], 0);
   CVMX_MF_HSH_IVW (sha2[1], 1);
   CVMX_MF_HSH_IVW (sha2[2], 2);
   CVMX_MF_HSH_IVW (sha2[3], 3);
   
  /* put HMac at the end of the packet */
   if(outptr != NULL) {
      memcpy(outptr+ESP_HEADER_LENGTH, pktptr, pktlen);
        memcpy((outptr+ESP_HEADER_LENGTH+ pktlen),(uint8_t *)sha2,ICV_LEN_SHA512);
   }
   else {
      memcpy(pktptr+pktlen, sha2, ICV_LEN_SHA512);
   }
   if(outlen) {
      if(outptr)
         *outlen = pktlen +ESP_HEADER_LENGTH +ICV_LEN_SHA512;
      else
         *outlen = pktlen +ICV_LEN_SHA512;
   }
   return 0;
}


int NULL_sha512_decrypt(uint16_t sha2_keylen, uint8_t *sha2_key, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *aptr;
   uint64_t sha2[8];
   uint32_t dlen, sha2_next;
   int i;
   uint8_t sha_key[128];
   uint64_t inner_sha[8];
   if(pktptr == NULL  || pktlen == 0 || 
      sha2_key == NULL || sha2_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +ICV_LEN_SHA512+1)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   memset(sha_key,0x0,128);
   if(sha2_keylen > 128) {
      if(hash_key_sha512(sha2_key, sha2_keylen, sha_key,1)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha2_keylen = 64;
   } else
      memcpy(sha_key,sha2_key,sha2_keylen);

   /* Load SHA2 IV */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ ipad));
   
   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   dlen = pktlen -ICV_LEN_SHA512;
   sha2_next = 0;

   /* Loop through input */
   while (dlen >= 128) {
     CVMX_MT_HSH_DATW (*aptr++, 0);
     CVMX_MT_HSH_DATW (*aptr++, 1);
     CVMX_MT_HSH_DATW (*aptr++, 2);
     CVMX_MT_HSH_DATW (*aptr++, 3);
     CVMX_MT_HSH_DATW (*aptr++, 4);
     CVMX_MT_HSH_DATW (*aptr++, 5);
     CVMX_MT_HSH_DATW (*aptr++, 6);
     CVMX_MT_HSH_DATW (*aptr++, 7);
     CVMX_MT_HSH_DATW (*aptr++, 8);
     CVMX_MT_HSH_DATW (*aptr++, 9);
     CVMX_MT_HSH_DATW (*aptr++, 10);
     CVMX_MT_HSH_DATW (*aptr++, 11);
     CVMX_MT_HSH_DATW (*aptr++, 12);
     CVMX_MT_HSH_DATW (*aptr++, 13);
     CVMX_MT_HSH_DATW (*aptr++, 14);
     CVMX_MT_HSH_STARTSHA512 (*aptr++);
     dlen -= 128;
   }
  
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,0);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,1);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,2);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,3);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,4);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,5);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,6);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,7);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,8);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,9);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,10);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,11);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,12);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,13);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++,14);dlen-=8;}

   pktlen = pktlen - ICV_LEN_SHA512;
   sha2_next = (pktlen % 128)/8;
   /* Finish inner hash */
   {
      int chunk_len = pktlen%128;
      uint8_t chunk[200];
      uint8_t i=0;
      if(chunk_len >= 112 && chunk_len < 120) {
         chunk_len = 144;
         chunk_len+=(dlen/8)*8;
      } else if(chunk_len >=120) {
         chunk_len=136;
         chunk_len+=(dlen/8)*8;
      }
      else {
         chunk_len = 128-chunk_len;
         chunk_len += dlen;
      }
      memset(chunk,0x0, chunk_len);

      if(dlen)
         memcpy(chunk,(pktptr+pktlen-dlen),dlen);
      *(chunk+dlen)= 0x80;
      uint64_t_mul (((uint64_t *)(chunk+chunk_len-16))[0],((uint64_t *)(chunk+chunk_len-16))[1], (pktlen + 128), 0x8ull);

      while ( i< chunk_len) {
         _CVMX_MT_HSH_DATW (*((uint64_t *)(chunk+i)), sha2_next );
         i += 8;
      }
   }
   
   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   
   CVMX_M128BT_HSH_DATW_SHA512 ((*aptr++ ^ opad));

   CVMX_M128BT_HSH_DATW_SHA512_HMAC(inner_sha);  


   /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha2[0], 0);
   CVMX_MF_HSH_IVW (sha2[1], 1);
   CVMX_MF_HSH_IVW (sha2[2], 2);
   CVMX_MF_HSH_IVW (sha2[3], 3);

   /* compare first 256 bits of HMAC with received mac */
   if(compdigest) {
        if(memcmp(pktptr+pktlen, sha2, ICV_LEN_SHA512)) {
          printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA512;i++)
              printf(" %02x",((uint8_t *)sha2)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA512;i++)
              printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }   
   } else if(outptr)
        memcpy(outptr+pktlen, sha2, ICV_LEN_SHA512);
   if(outptr != NULL)
      memcpy(outptr, pktptr, pktlen);
        
   *outlen=pktlen;
   return 0;
}

int AH_outbound_sha1 ( uint16_t sha1_keylen, uint8_t *sha1_key,  uint8_t *ah_header, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *aptr;
   uint64_t temp;
   uint64_t sha1[3];
   uint32_t dlen, sha1_next;
   uint8_t sha_key[64];
   uint64_t inner_sha[3];

   if(pktptr == NULL ||  pktlen == 0  ||  sha1_key == NULL || 
      sha1_keylen == 0 || ah_header == NULL || outlen == NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
    }
   if(pktlen > (MAX_PKT_SIZE-AH_FIXED_LEN-ICV_LEN_SHA1)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   if(pktlen < IP_HEADER_LENGTH) {
      printf("\n pktlen should be atleast 20 bytes");
      return -1;
   }

   MEMSET64BTZ(sha_key);
   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 1)<0) {
         printf(" improper mac secret \n");   
           return -1;
      }
   sha1_keylen = 20;
   } else
        memcpy(sha_key, sha1_key, sha1_keylen);

   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ ipad));

   if(outptr != NULL) {
      memcpy(outptr, pktptr, IP_HEADER_LENGTH);
      memcpy(outptr + IP_HEADER_LENGTH, ah_header, AH_FIXED_LEN);
   }
   pktlen += AH_HEADER_LENGTH;
   dlen = pktlen;
   aptr = (uint64_t *)pktptr;
   sha1_next = (dlen % 64) / 8;

   /* Assumed that data is 8 byte aligned */
   /* processing Ist 64 bytes => IP header+AH_header+data */
   CVMX_MT_HSH_DAT(*aptr++, 0);
   CVMX_MT_HSH_DAT(*aptr++, 1);
   temp = *(uint32_t *)aptr;                          /*last 4 bytes of IP header*/
   temp = (temp << 32) | (*(uint32_t *)ah_header);    /*concatenated with Ist 4 bytes of AH header*/
   CVMX_MT_HSH_DAT(temp, 2);

   aptr = (uint64_t *)(ah_header + 4);	  /*last 8 bytes of AH HEADER*/
   CVMX_MT_HSH_DAT(*aptr, 3);
   CVMX_MT_HSH_DATZ(4);                   /*AH header 12 byte ICV part set to zero for computation*/

   dlen  = dlen - 40;		          /*20 byte IP Header and 20 byte AH header processed*/
   if(dlen >= 8){
      temp = *(uint32_t *)(pktptr + IP_HEADER_LENGTH);  /*last 4 byte of AH ICV + Ist 4 byte of data*/
      CVMX_MT_HSH_DAT(temp, 5);dlen -= 8;
   }
   if(dlen >= 8){
      aptr = (uint64_t *)(pktptr + IP_HEADER_LENGTH + 4);
      CVMX_MT_HSH_DAT(*aptr++, 6); dlen -= 8;
   }
   if(dlen >= 8){
      CVMX_MT_HSH_STARTSHA(*aptr++);dlen -= 8;
   }

   /*40 bytes IP header + data and 24 bytes AH_header has been processed*/
   aptr = (uint64_t *)(pktptr + 40);
   while(dlen >= 64) {
     CVMX_MT_HSH_DAT(*aptr++, 0);
     CVMX_MT_HSH_DAT(*aptr++, 1);
     CVMX_MT_HSH_DAT(*aptr++, 2);
     CVMX_MT_HSH_DAT(*aptr++, 3);
     CVMX_MT_HSH_DAT(*aptr++, 4);
     CVMX_MT_HSH_DAT(*aptr++, 5);
     CVMX_MT_HSH_DAT(*aptr++, 6);
     CVMX_MT_HSH_STARTSHA(*aptr++);
     dlen -= 64;
   } 
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 0); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 1); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 2); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 3); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 4); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 5); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 6); dlen -= 8;}

   /* Finish inner hash */
   {
      int chunk_len = pktlen % 64;
      uint8_t chunk[100];
      uint8_t i = 0;
      if(chunk_len >= 56) {
         chunk_len = 72;
         chunk_len += (dlen / 8) * 8;
      } else {
         chunk_len = 64 - chunk_len;
         chunk_len += dlen;
      }
      if(dlen)
         memcpy(chunk, (pktptr + pktlen - dlen - AH_HEADER_LENGTH), dlen);
      memset(chunk + dlen, 0x0, chunk_len - dlen);
      *(chunk+dlen) = 0x80;
      *((uint64_t *)(chunk + chunk_len - 8)) = (pktlen + 64) * 8;
      while ( i< chunk_len) {
         _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk + i)), sha1_next, 1);
          i += 8;
      }
   } 

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_sha[0], 0);
   CVMX_MF_HSH_IV (inner_sha[1], 1);
   CVMX_MF_HSH_IV (inner_sha[2], 2);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ opad));

   CVMX_MT_HSH_DAT (inner_sha[0], 0);
   CVMX_MT_HSH_DAT (inner_sha[1], 1);
   ((uint8_t *)inner_sha)[20] = 0x80;
   ((uint8_t *)inner_sha)[21] = 0x0;
   ((uint8_t *)inner_sha)[22] = 0x0;
   ((uint8_t *)inner_sha)[23] = 0x0;
   CVMX_MT_HSH_DAT (inner_sha[2], 2);
   CVMX_MT_HSH_DATZ(3);
   CVMX_MT_HSH_DATZ(4);
   CVMX_MT_HSH_DATZ(5);
   CVMX_MT_HSH_DATZ(6);
   CVMX_MT_HSH_STARTSHA ((uint64_t) ((64 + 20) * 8));

   /* Get the HMAC */
   CVMX_MF_HSH_IV (sha1[0], 0);
   CVMX_MF_HSH_IV (sha1[1], 1);
   
   /* put HMac in AH ICV */
   if(outptr != NULL) {
        memcpy((outptr + IP_HEADER_LENGTH + AH_FIXED_LEN),(uint8_t *)sha1, ICV_LEN_SHA1);
        memcpy(outptr + IP_HEADER_LENGTH + AH_HEADER_LENGTH,
               pktptr + IP_HEADER_LENGTH,
               (pktlen - IP_HEADER_LENGTH - AH_HEADER_LENGTH));
   } else {
        memmove((pktptr + IP_HEADER_LENGTH + AH_HEADER_LENGTH),
                (pktptr + IP_HEADER_LENGTH), 
                (pktlen - AH_HEADER_LENGTH - IP_HEADER_LENGTH));
        memcpy((pktptr + IP_HEADER_LENGTH), ah_header, AH_FIXED_LEN);
        memcpy((pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN), (uint8_t *)sha1, ICV_LEN_SHA1);
   }
   if(outlen)
      *outlen = pktlen;

   return 0;
}


int AH_inbound_sha1 ( uint16_t sha1_keylen, uint8_t *sha1_key,  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen,int compdigest)
{
   uint64_t *aptr;
   uint64_t sha1[3];
   uint32_t dlen, sha1_next;
   uint32_t i;
   uint8_t sha_key[64];
   uint8_t saved_ah[AH_FIXED_LEN + ICV_LEN_SHA1];
   uint64_t inner_sha[3];
   if(pktptr == NULL ||  pktlen == 0  || 
      sha1_key == NULL || sha1_keylen == 0||outlen == NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
    if(pktlen < (IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA1 )) {
      printf("Packet length is not proper \n");
      return -1;
     }
   MEMSET64BTZ(sha_key);
   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 1) < 0) {
         printf(" improper mac secret \n");   
           return -1;
      }
   sha1_keylen = 20;
   } else
        memcpy(sha_key, sha1_key, sha1_keylen);

   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ ipad));

   memcpy(saved_ah,pktptr + IP_HEADER_LENGTH, AH_HEADER_LENGTH);
   if(outptr == NULL) {
      memset(pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN, 0x0, ICV_LEN_SHA1);
      aptr = (uint64_t *)pktptr ;
   } else {
      memcpy(outptr, pktptr, pktlen);
      memset(outptr + IP_HEADER_LENGTH + AH_FIXED_LEN, 0x0, ICV_LEN_SHA1);
      aptr = (uint64_t *)outptr;
   }
   sha1_next = 0;
   dlen = pktlen;

   /* Loop through input */
  sha1_next = (dlen % 64) / 8;
  while(dlen >= 64) {
     CVMX_MT_HSH_DAT(*aptr++, 0);
     CVMX_MT_HSH_DAT(*aptr++, 1);
     CVMX_MT_HSH_DAT(*aptr++, 2);
     CVMX_MT_HSH_DAT(*aptr++, 3);
     CVMX_MT_HSH_DAT(*aptr++, 4);
     CVMX_MT_HSH_DAT(*aptr++, 5);
     CVMX_MT_HSH_DAT(*aptr++, 6);
     CVMX_MT_HSH_STARTSHA(*aptr++);
     dlen -= 64;
   } 
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 0); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 1); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 2); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 3); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 4); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 5); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 6); dlen -= 8;}
   
   /* Finish Inner hash */
   {
      int chunk_len = pktlen % 64;
      uint8_t chunk[100];
      uint8_t i = 0;
      if(chunk_len >= 56) {
         chunk_len = 72;
         chunk_len += (dlen / 8) * 8;
      } else {
           chunk_len = 64 - chunk_len;
         chunk_len += dlen;
      }
      if(dlen)
         memcpy(chunk, ((uint8_t *)aptr), dlen);
      memset(chunk + dlen, 0x0, chunk_len - dlen);
      *(chunk + dlen) = 0x80;
      *((uint64_t *)(chunk + chunk_len - 8)) = (pktlen + 64) * 8;
      while ( i < chunk_len) {
         _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk + i)), sha1_next, 1);
          i += 8;
      }
   } 

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_sha[0], 0);
   CVMX_MF_HSH_IV (inner_sha[1], 1);
   CVMX_MF_HSH_IV (inner_sha[2], 2);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ opad));

   CVMX_MT_HSH_DAT (inner_sha[0], 0);
   CVMX_MT_HSH_DAT (inner_sha[1], 1);
   ((uint8_t *)inner_sha)[20] = 0x80;
   ((uint8_t *)inner_sha)[21] = 0x0;
   ((uint8_t *)inner_sha)[22] = 0x0;
   ((uint8_t *)inner_sha)[23] = 0x0;
   CVMX_MT_HSH_DAT (inner_sha[2], 2);
   CVMX_MT_HSH_DATZ(3);
   CVMX_MT_HSH_DATZ(4);
   CVMX_MT_HSH_DATZ(5);
   CVMX_MT_HSH_DATZ(6);
   CVMX_MT_HSH_STARTSHA ((uint64_t) ((64 + 20) * 8));

   /* Get the HMAC */
   CVMX_MF_HSH_IV (sha1[0], 0);
   CVMX_MF_HSH_IV (sha1[1], 1);
   /* compare first 96 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(saved_ah + AH_FIXED_LEN, sha1, ICV_LEN_SHA1)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i = 0; i < ICV_LEN_SHA1; i++)
            printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i = 0;i < ICV_LEN_SHA1; i++)
            printf(" %02x", saved_ah[AH_FIXED_LEN + i]);
         printf("\n");
         return -1;
      }
   }
   if(outptr == NULL) 
      memmove(pktptr + IP_HEADER_LENGTH,
              pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA1,
              (pktlen - IP_HEADER_LENGTH - AH_FIXED_LEN - ICV_LEN_SHA1)); 
   else 
      memcpy(outptr + IP_HEADER_LENGTH,
             pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA1,
             pktlen - IP_HEADER_LENGTH - AH_FIXED_LEN - ICV_LEN_SHA1);
   if(outlen)
      *outlen = pktlen - AH_HEADER_LENGTH;

   return 0;
}

int AH_outbound_sha256 ( uint16_t sha256_keylen, uint8_t *sha256_key,  uint8_t *ah_header, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *aptr;
   uint64_t temp;
   uint64_t sha256[4];
   uint32_t dlen, sha256_next;
   uint8_t sha_key[64];
   uint64_t inner_sha[4];
   if(pktptr == NULL ||  pktlen == 0  ||  sha256_key == NULL ||
         sha256_keylen == 0 ||ah_header == NULL||outlen == NULL) {
      printf("\n Wrong parameters \n");
      return -1;
   }
   if(pktlen > (MAX_PKT_SIZE - AH_FIXED_LEN - ICV_LEN_SHA256)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   if(pktlen < IP_HEADER_LENGTH) {
      printf("\n pktlen should be atleast 20 bytes");
      return -1;
   }
   MEMSET64BTZ(sha_key);
   if(sha256_keylen > 64) {
      if(hash_key(sha256_key, sha256_keylen, sha_key,2) < 0) {
         printf(" improper mac secret \n");
         return -1;
      }
      sha256_keylen = 32;
   } else
      memcpy(sha_key, sha256_key, sha256_keylen);

   /* Load SHA256 IV */
   CVMX_M32BT_HSH_IV (sha256defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad));   

   if(outptr != NULL) {
      memcpy(outptr, pktptr, IP_HEADER_LENGTH);
      memcpy(outptr + IP_HEADER_LENGTH, ah_header, AH_FIXED_LEN);
   }
   pktlen += AH_FIXED_LEN + ICV_LEN_SHA256;
   dlen = pktlen;
   sha256_next = (dlen % 64) / 8;
   aptr = (uint64_t *)pktptr;
   
   /* Assumed that data is 8 byte aligned */
   /* processing Ist 64 bytes => IP header+AH_header+data */
   CVMX_MT_HSH_DAT(*aptr++, 0);
   CVMX_MT_HSH_DAT(*aptr++, 1);
   temp = *(uint32_t *)aptr;                         /*last 4 bytes of IP header*/
   temp = (temp << 32) | (*(uint32_t *)ah_header);   /*concatenated with Ist 4 bytes of AH header*/
   CVMX_MT_HSH_DAT(temp, 2);

   aptr = (uint64_t *)(ah_header + 4);                 /*last 8 bytes of AH HEADER*/ 
   CVMX_MT_HSH_DAT(*aptr, 3);
   CVMX_MT_HSH_DATZ(4);                   /*AH header 16 byte ICV part set to zero for computation*/ 
   CVMX_MT_HSH_DATZ(5);
   dlen  = dlen - 48;                      /*20 byte IP Header and 28 byte AH header processed*/
   if(dlen >= 8){
      aptr = (uint64_t *)(pktptr + IP_HEADER_LENGTH); 
      CVMX_MT_HSH_DAT(*aptr++, 6); dlen -= 8;
   }
   if(dlen >= 8){
      CVMX_MT_HSH_STARTSHA256(*aptr++); dlen -= 8;
   }

   /*36 bytes IP header + data and 28 bytes AH_header has been processed*/
   aptr = (uint64_t *)(pktptr + 36);
   while(dlen >= 64) {
      CVMX_MT_HSH_DAT(*aptr++, 0);
      CVMX_MT_HSH_DAT(*aptr++, 1);
      CVMX_MT_HSH_DAT(*aptr++, 2);
      CVMX_MT_HSH_DAT(*aptr++, 3);
      CVMX_MT_HSH_DAT(*aptr++, 4);
      CVMX_MT_HSH_DAT(*aptr++, 5);
      CVMX_MT_HSH_DAT(*aptr++, 6);
      CVMX_MT_HSH_STARTSHA256(*aptr++);
      dlen -= 64;
   }
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 0); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 1); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 2); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 3); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 4); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 5); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 6); dlen -= 8;}
   
   /* Finish inner hash */
   {
      int chunk_len = pktlen % 64;
      uint8_t chunk[100];
      uint8_t i = 0;
      if(chunk_len >= 56) {
         chunk_len = 72;
         chunk_len += (dlen / 8) * 8;
      } else {
         chunk_len = 64 - chunk_len;
         chunk_len += dlen;
      }
      if(dlen)
         memcpy(chunk,(pktptr + pktlen - dlen - AH_FIXED_LEN - ICV_LEN_SHA256), dlen);
      memset(chunk + dlen, 0x0, chunk_len - dlen);
      *(chunk + dlen) = 0x80;         
      *((uint64_t *)(chunk + chunk_len -8)) = (pktlen + 64) * 8;

      while ( i < chunk_len) {
         _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk + i)), sha256_next, 2 ); 
         i += 8; 
      }
   } 

   /* Get the inner hash of HMAC */    
   CVMX_MF_HSH_IV (inner_sha[0], 0);                                
   CVMX_MF_HSH_IV (inner_sha[1], 1);                                
   CVMX_MF_HSH_IV (inner_sha[2], 2);                                
   CVMX_MF_HSH_IV (inner_sha[3], 3);           

   /* Initialize hash unit */
   CVMX_M32BT_HSH_IV (sha256defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));

   CVMX_M64BT_HSH_DAT_SHA256_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_MF_HSH_IV (sha256[0], 0);
   CVMX_MF_HSH_IV (sha256[1], 1);

   /* put HMac in AH ICV */
   if(outptr != NULL) {
      memcpy((outptr + IP_HEADER_LENGTH + AH_FIXED_LEN), (uint8_t *)sha256, ICV_LEN_SHA256); 
      memcpy(outptr + IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA256,
                pktptr + IP_HEADER_LENGTH,
                (pktlen - IP_HEADER_LENGTH - AH_FIXED_LEN - ICV_LEN_SHA256));
   } else {
      memmove((pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA256),
                (pktptr + IP_HEADER_LENGTH),
                (pktlen - AH_FIXED_LEN - ICV_LEN_SHA256 - IP_HEADER_LENGTH));

      memcpy((pktptr + IP_HEADER_LENGTH), ah_header, AH_FIXED_LEN);
      memcpy((pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN), (uint8_t *)sha256, ICV_LEN_SHA256);
   }

   if(outlen)
      *outlen = pktlen;

   return 0;
   
}

int AH_inbound_sha256 ( uint16_t sha256_keylen, uint8_t *sha256_key, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, int compdigest)
{
   uint64_t *aptr;
   uint64_t sha256[4];
   uint32_t dlen, sha256_next;
   uint32_t i;
   uint8_t sha_key[64];
   uint8_t saved_ah[AH_FIXED_LEN + ICV_LEN_SHA256];
   uint64_t inner_sha[4];
   if(pktptr == NULL ||  pktlen == 0  ||
         sha256_key == NULL || sha256_keylen == 0||outlen == NULL ) {
      printf("\n Wrong parameters \n");
      return -1;
   }
   if(pktlen < (IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA256)) {
      printf("Packet length is not proper \n");
      return -1;
   }

   MEMSET64BTZ(sha_key);
   if(sha256_keylen > 64) {
      if(hash_key(sha256_key, sha256_keylen, sha_key, 2) < 0) {   
         printf(" improper mac secret \n");
         return -1;
      }
      sha256_keylen = 32;
   } else
      memcpy(sha_key, sha256_key, sha256_keylen);

   /* Load SHA256 IV */
   CVMX_M32BT_HSH_IV (sha256defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad));

   memcpy(saved_ah, pktptr + IP_HEADER_LENGTH, AH_FIXED_LEN + ICV_LEN_SHA256);

   if(outptr == NULL) {
      memset(pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN, 0x0, ICV_LEN_SHA256);
      aptr = (uint64_t *)pktptr ;
   } else {
      memcpy(outptr, pktptr, pktlen); 
      memset(outptr + IP_HEADER_LENGTH + AH_FIXED_LEN, 0x0, ICV_LEN_SHA256);
      aptr = (uint64_t *)outptr;
   }
     
   sha256_next = 0;
   dlen = pktlen;

   /* Assumed that data is 8 byte aligned */
   sha256_next = (dlen % 64) / 8;
   while(dlen >= 64) {
      CVMX_MT_HSH_DAT(*aptr++, 0);
      CVMX_MT_HSH_DAT(*aptr++, 1);
      CVMX_MT_HSH_DAT(*aptr++, 2);
      CVMX_MT_HSH_DAT(*aptr++, 3);
      CVMX_MT_HSH_DAT(*aptr++, 4);
      CVMX_MT_HSH_DAT(*aptr++, 5);
      CVMX_MT_HSH_DAT(*aptr++, 6);
      CVMX_MT_HSH_STARTSHA256(*aptr++);
      dlen -= 64;
   }
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 0); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 1); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 2); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 3); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 4); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 5); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++, 6); dlen -= 8;}

   /* Finish inner hash */
   {
      int chunk_len=pktlen % 64;
      uint8_t chunk[100];
      uint8_t i = 0;
      if(chunk_len >= 56) {
         chunk_len = 72;
         chunk_len += (dlen / 8) * 8;
      } else {
         chunk_len = 64 - chunk_len;
         chunk_len += dlen;
      }
      if(dlen)
         memcpy(chunk, ((uint8_t *)aptr), dlen);
      memset(chunk + dlen, 0x0, chunk_len - dlen);
      *(chunk + dlen) = 0x80;
      *((uint64_t *)(chunk + chunk_len -8)) = (pktlen + 64) * 8;
      while ( i < chunk_len) {
         _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk + i)), sha256_next, 2); 
         i += 8;
      }
   }

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_sha[0], 0);
   CVMX_MF_HSH_IV (inner_sha[1], 1);                          
   CVMX_MF_HSH_IV (inner_sha[2], 2);                                
   CVMX_MF_HSH_IV (inner_sha[3], 3);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (sha256defiv[0], 0);
   CVMX_MT_HSH_IV (sha256defiv[1], 1);
   CVMX_MT_HSH_IV (sha256defiv[2], 2);
   CVMX_MT_HSH_IV (sha256defiv[3], 3);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));

   CVMX_M64BT_HSH_DAT_SHA256_HMAC(inner_sha);


   /* Get the HMAC */
   CVMX_MF_HSH_IV (sha256[0], 0);
   CVMX_MF_HSH_IV (sha256[1], 1);

   /* compare first 128 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(saved_ah + AH_FIXED_LEN, sha256, ICV_LEN_SHA256)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i = 0; i < ICV_LEN_SHA256; i++)
            printf(" %02x", ((uint8_t *)sha256)[i]);

         printf("\n Expected");
         for(i = 0; i < ICV_LEN_SHA256; i++)
            printf(" %02x", saved_ah[AH_FIXED_LEN + i]);
         printf("\n");
      return -1;
      }
   }

   if(outptr == NULL)
   {
      memmove(pktptr + IP_HEADER_LENGTH,
                pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA256,
                (pktlen - IP_HEADER_LENGTH - AH_FIXED_LEN - ICV_LEN_SHA256)); 
   }
   else
   { 
      memcpy(outptr + IP_HEADER_LENGTH,
                pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA256,
                pktlen - IP_HEADER_LENGTH - AH_FIXED_LEN - ICV_LEN_SHA256);
   }
   if(outlen)
      *outlen = pktlen - AH_FIXED_LEN - ICV_LEN_SHA256;
   
   return 0;
}

int AH_outbound_sha384 (uint16_t sha384_keylen, uint8_t *sha384_key, uint8_t *ah_header, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *aptr;
   uint64_t temp;
   uint64_t sha384[8];
   uint32_t dlen, sha384_next;
   uint8_t sha_key[128];
   uint64_t inner_sha[8];
   if(pktptr == NULL ||  pktlen == 0  ||  sha384_key == NULL ||
         sha384_keylen == 0 || ah_header == NULL|| outlen == NULL) {
      printf("\n Wrong parameters \n");   
      return -1;             
   }                        
   if(pktlen > (MAX_PKT_SIZE - AH_FIXED_LEN - ICV_LEN_SHA384)) {
      printf("Packet is too big to handle \n");
      return -1;             
   }                         
   if(pktlen < IP_HEADER_LENGTH) {
      printf("\n pktlen should be atleast 20 bytes");
      return -1;             
   }           
                 
   MEMSET128BTZ(sha_key);
   if(sha384_keylen > 128) {
      if(hash_key_sha512(sha384_key, sha384_keylen, sha_key, 0) < 0) {
         printf(" improper mac secret \n");
         return -1;
      }
      sha384_keylen = 48;
   } else
      memcpy(sha_key, sha384_key, sha384_keylen);

   /* Load SHA384 IV */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor ipad */ 
   aptr = (uint64_t *) sha_key;   
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ ipad));

   if(outptr != NULL) {
      memcpy(outptr, pktptr, IP_HEADER_LENGTH);
      memcpy(outptr + IP_HEADER_LENGTH, ah_header, 12);
   }
   
   pktlen += AH_FIXED_LEN + ICV_LEN_SHA384;
   dlen = pktlen;
   sha384_next = (dlen % 128) / 8;
   aptr = (uint64_t *)pktptr;

   /* Assumed that data is 8 byte aligned */
   /* processing Ist 128 bytes => IP header+AH_header+data */
   CVMX_MT_HSH_DATW(*aptr++, 0);
   CVMX_MT_HSH_DATW(*aptr++, 1);
   temp = *(uint32_t *)aptr;                         /*last 4 bytes of IP header*/
   temp = (temp << 32) | (*(uint32_t *)ah_header);   /*concatenated with Ist 4 bytes of AH header*/
   CVMX_MT_HSH_DATW(temp, 2);

   aptr = (uint64_t *)(ah_header + 4);                 /*last 8 bytes of AH HEADER*/ 
   CVMX_MT_HSH_DATW(*aptr, 3);
   CVMX_MT_HSH_DATWZ(4);
   CVMX_MT_HSH_DATWZ(5);
   CVMX_MT_HSH_DATWZ(6);                  /*AH header 24 byte ICV part set to zero for computation*/ 
   dlen  = dlen - 56;                      /*20 byte IP Header and 36 byte AH header processed*/
   if(dlen >= 8){
      temp = *(uint64_t *)(pktptr + IP_HEADER_LENGTH); 
      CVMX_MT_HSH_DATW(temp, 7); dlen -= 8;
   }
   if(dlen >= 8){
      aptr = (uint64_t *)(pktptr + IP_HEADER_LENGTH + 8);
      CVMX_MT_HSH_DATW(*aptr++, 8); dlen -= 8;
   }
   
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 9);  dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 10); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 11); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 12); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 13); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 14); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_STARTSHA512(*aptr++);dlen -= 8;}

   /*92 bytes IP header + data and 36 bytes AH_header has been processed*/
   aptr = (uint64_t *)(pktptr + 92);
   while (dlen >= 128) {
      CVMX_MT_HSH_DATW (*aptr++, 0);                                
      CVMX_MT_HSH_DATW (*aptr++, 1);                                
      CVMX_MT_HSH_DATW (*aptr++, 2);                                
      CVMX_MT_HSH_DATW (*aptr++, 3);                                
      CVMX_MT_HSH_DATW (*aptr++, 4);                                
      CVMX_MT_HSH_DATW (*aptr++, 5);                                
      CVMX_MT_HSH_DATW (*aptr++, 6);                                
      CVMX_MT_HSH_DATW (*aptr++, 7);                                
      CVMX_MT_HSH_DATW (*aptr++, 8);                                
      CVMX_MT_HSH_DATW (*aptr++, 9);
      CVMX_MT_HSH_DATW (*aptr++, 10);                               
      CVMX_MT_HSH_DATW (*aptr++, 11);                               
      CVMX_MT_HSH_DATW (*aptr++, 12);                               
      CVMX_MT_HSH_DATW (*aptr++, 13);                               
      CVMX_MT_HSH_DATW (*aptr++, 14);
      CVMX_MT_HSH_STARTSHA512 (*aptr++);                            
      dlen -= 128;                                                  
   }
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 0); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 1); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 2); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 3); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 4); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 5); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 6); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 7); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 8); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 9); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 10); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 11); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 12); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 13); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 14); dlen -= 8;}

   /* Finish inner hash */
   {
      int chunk_len=pktlen % 128;
      uint8_t chunk[200];
      uint8_t i=0;
      if(chunk_len >= 112 && chunk_len < 120) {
         chunk_len = 144;
         chunk_len += (dlen / 8) * 8;
      } else if(chunk_len >= 120) {
         chunk_len = 136;
         chunk_len += (dlen / 8) * 8;
      }
      else {
         chunk_len = 128 - chunk_len;
         chunk_len += dlen;
      }
      memset(chunk, 0x0, chunk_len);

      if(dlen)
         memcpy(chunk, (pktptr + pktlen - dlen - AH_FIXED_LEN - ICV_LEN_SHA384), dlen);
      *(chunk + dlen) = 0x80;
      uint64_t_mul (((uint64_t *)(chunk + chunk_len - 16))[0], ((uint64_t *)(chunk + chunk_len - 16))[1], (pktlen + 128), 0x8ull);

      while ( i < chunk_len) {
         _CVMX_MT_HSH_DATW (*((uint64_t *)(chunk + i)), sha384_next);
         i += 8;
      }
   }

   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ opad));
   CVMX_M128BT_HSH_DATW_SHA384_HMAC(inner_sha); 

   /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha384[0], 0);
   CVMX_MF_HSH_IVW (sha384[1], 1);
   CVMX_MF_HSH_IVW (sha384[2], 2);

   /* put HMac in AH ICV */
   if(outptr != NULL) {        
      memcpy((outptr + IP_HEADER_LENGTH + AH_FIXED_LEN), (uint8_t *)sha384, ICV_LEN_SHA384); 
      memcpy(outptr + IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA384,
                 pktptr + IP_HEADER_LENGTH,
                 (pktlen - IP_HEADER_LENGTH - AH_FIXED_LEN - ICV_LEN_SHA384));
   } else {
      memmove((pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA384),
                 (pktptr + IP_HEADER_LENGTH),
                 (pktlen - AH_FIXED_LEN - ICV_LEN_SHA384 - IP_HEADER_LENGTH));
      memcpy((pktptr + IP_HEADER_LENGTH), ah_header, AH_FIXED_LEN);
      memcpy((pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN), (uint8_t *)sha384, ICV_LEN_SHA384);
   }
   if(outlen)
      *outlen = pktlen;

   return 0;
}

int AH_inbound_sha384 ( uint16_t sha384_keylen, uint8_t *sha384_key,  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen,int compdigest)
{
   uint64_t *aptr;
   uint64_t sha384[8];
   uint32_t dlen, sha384_next;
   uint32_t i;
   uint8_t saved_ah[AH_FIXED_LEN + ICV_LEN_SHA384];
   uint8_t sha_key[128];
   uint64_t inner_sha[8];

   if(pktptr == NULL || pktlen == 0 || sha384_key == NULL ||
         sha384_keylen == 0 || outlen == NULL) {
      printf("\n Wrong parameters \n");
      return -1;
   }
   if(pktlen < (IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA384)) {
      printf("Packet length is not proper \n");
      return -1;
   }

   MEMSET128BTZ(sha_key);
   if(sha384_keylen > 128) {
      if(hash_key_sha512(sha384_key, sha384_keylen, sha_key, 0) < 0) {  
         printf(" improper mac secret \n");
         return -1;
      }
      sha384_keylen = 48;
   } else
      memcpy(sha_key, sha384_key, sha384_keylen);

   /* Load SHA384 IV */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ ipad));

   memcpy(saved_ah, pktptr + IP_HEADER_LENGTH, AH_FIXED_LEN + ICV_LEN_SHA384);

   if(outptr == NULL) {
      memset(pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN, 0x0, ICV_LEN_SHA384);
      aptr = (uint64_t *)pktptr ;
   } else {
      memcpy(outptr, pktptr, pktlen); 
      memset(outptr + IP_HEADER_LENGTH + AH_FIXED_LEN, 0x0, ICV_LEN_SHA384);
      aptr = (uint64_t *)outptr;
   }
     
   sha384_next = 0;
   dlen = pktlen;

   /* Assumed that data is 8 byte aligned */
   sha384_next = (dlen % 128) / 8;
   while (dlen >= 128) {
      CVMX_MT_HSH_DATW (*aptr++, 0);
      CVMX_MT_HSH_DATW (*aptr++, 1);
      CVMX_MT_HSH_DATW (*aptr++, 2);
      CVMX_MT_HSH_DATW (*aptr++, 3);
      CVMX_MT_HSH_DATW (*aptr++, 4);
      CVMX_MT_HSH_DATW (*aptr++, 5);
      CVMX_MT_HSH_DATW (*aptr++, 6);
      CVMX_MT_HSH_DATW (*aptr++, 7);
      CVMX_MT_HSH_DATW (*aptr++, 8);
      CVMX_MT_HSH_DATW (*aptr++, 9);
      CVMX_MT_HSH_DATW (*aptr++, 10);
      CVMX_MT_HSH_DATW (*aptr++, 11);
      CVMX_MT_HSH_DATW (*aptr++, 12);
      CVMX_MT_HSH_DATW (*aptr++, 13);
      CVMX_MT_HSH_DATW (*aptr++, 14);
      CVMX_MT_HSH_STARTSHA512 (*aptr++);
      dlen -= 128;
   }

   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 0); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 1); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 2); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 3); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 4); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 5); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 6); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 7); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 8); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 9); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 10); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 11); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 12); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 13); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 14); dlen -= 8;}
 
   /* Finish inner hash */
   {
      int chunk_len = pktlen % 128;
      uint8_t chunk[200];
      uint8_t i = 0;
      if(chunk_len >= 112 && chunk_len < 120) {
         chunk_len = 144;
         chunk_len += (dlen / 8) * 8;
      } else if(chunk_len >= 120) {
         chunk_len = 136;
         chunk_len += (dlen / 8) * 8;
      }
      else {
         chunk_len = 128 - chunk_len;
         chunk_len += dlen;
      }
      memset(chunk, 0x0, chunk_len);

      if(dlen)
         memcpy(chunk, ((uint8_t *)aptr), dlen);
      *(chunk + dlen) = 0x80;
      uint64_t_mul(((uint64_t *)(chunk + chunk_len - 16))[0], ((uint64_t *)(chunk + chunk_len - 16))[1], (pktlen + 128), 0x8ull);

      while (i < chunk_len) {
         _CVMX_MT_HSH_DATW(*((uint64_t *)(chunk + i)), sha384_next);
         i += 8;
      }
   }

   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ opad));
   CVMX_M128BT_HSH_DATW_SHA384_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha384[0], 0);
   CVMX_MF_HSH_IVW (sha384[1], 1);
   CVMX_MF_HSH_IVW (sha384[2], 2);

   /* compare first 192 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(saved_ah + AH_FIXED_LEN, sha384, ICV_LEN_SHA384)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i = 0; i < ICV_LEN_SHA384; i++)
            printf(" %02x", ((uint8_t *)sha384)[i]);
         printf("\n Expected");
         for(i = 0; i < ICV_LEN_SHA384; i++)
            printf(" %02x", saved_ah[AH_FIXED_LEN + i]);
         printf("\n");
       return -1;
      }
   }
   if(outptr == NULL) 
      memmove(pktptr + IP_HEADER_LENGTH,
                pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA384,
                (pktlen - IP_HEADER_LENGTH - AH_FIXED_LEN - ICV_LEN_SHA384)); 
   else 
      memcpy(outptr + IP_HEADER_LENGTH,
                pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA384,
                pktlen - IP_HEADER_LENGTH - AH_FIXED_LEN - ICV_LEN_SHA384);
   if(outlen)
      *outlen = pktlen - AH_FIXED_LEN - ICV_LEN_SHA384;

   return 0;

}

int AH_outbound_sha512 (uint16_t sha512_keylen, uint8_t *sha512_key, uint8_t *ah_header, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen) 
{
   uint64_t *aptr;
   uint64_t temp;
   uint64_t sha512[8];
   uint32_t dlen, sha512_next;
   uint8_t sha_key[128];
   uint64_t inner_sha[8];
   if(pktptr == NULL || pktlen == 0 || sha512_key == NULL ||
         sha512_keylen == 0 || ah_header == NULL || outlen == NULL) {
      printf("\n Wrong parameters \n");
      return -1;
   }
   if(pktlen > (MAX_PKT_SIZE - AH_FIXED_LEN - ICV_LEN_SHA512)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   if(pktlen < IP_HEADER_LENGTH) {
      printf("\n pktlen should be atleast 20 bytes");
      return -1;
   }

   MEMSET128BTZ(sha_key);
   if(sha512_keylen > 128) {
      if(hash_key_sha512(sha512_key, sha512_keylen, sha_key, 1) < 0) {   
         printf(" improper mac secret \n");
         return -1;
      }
      sha512_keylen = 64;
   }else 
      memcpy(sha_key , sha512_key , sha512_keylen);

   /* Load SHA1 IV */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor ipad */ 
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ ipad));

   if(outptr != NULL) {
      memcpy(outptr, pktptr, IP_HEADER_LENGTH);
      memcpy(outptr + IP_HEADER_LENGTH, ah_header, 12);
   }
   pktlen += AH_FIXED_LEN + ICV_LEN_SHA512;
   dlen = pktlen;
   sha512_next = (dlen % 128) / 8;
   aptr = (uint64_t *)pktptr;

   /* Assumed that data is 8 byte aligned */
   /* processing Ist 128 bytes => IP header+AH_header+data */
   CVMX_MT_HSH_DATW(*aptr++, 0);
   CVMX_MT_HSH_DATW(*aptr++, 1);
   temp = *(uint32_t *)aptr;                         /*last 4 bytes of IP header*/
   temp = (temp << 32) | (*(uint32_t *)ah_header);   /*concatenated with Ist 4 bytes of AH header*/
   CVMX_MT_HSH_DATW(temp, 2);

   aptr = (uint64_t *)(ah_header + 4);                 /*last 8 bytes of AH HEADER*/ 
   CVMX_MT_HSH_DATW(*aptr, 3);
   CVMX_MT_HSH_DATWZ(4);
   CVMX_MT_HSH_DATWZ(5);
   CVMX_MT_HSH_DATWZ(6);
   CVMX_MT_HSH_DATWZ(7);                    /*AH header 32 byte ICV part set to zero for computation*/ 

   dlen  = dlen - 64;                           /*20 byte IP Header and 44 byte AH header processed*/
   if(dlen >= 8){
      temp = *(uint64_t *)(pktptr + IP_HEADER_LENGTH); 
      CVMX_MT_HSH_DATW(temp, 8); dlen -= 8;
   }
   if(dlen >= 8){
      aptr = (uint64_t *)(pktptr +  IP_HEADER_LENGTH + 8);
      CVMX_MT_HSH_DATW(*aptr++, 9); dlen -= 8;
   }
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 10); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 11); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 12); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 13); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 14); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_STARTSHA512(*aptr++); dlen -= 8;}

   /*84 bytes IP header + data and 44 bytes AH_header has been processed*/
   aptr = (uint64_t *)(pktptr + 84);
   while (dlen >= 128) {
      CVMX_MT_HSH_DATW (*aptr++, 0);
      CVMX_MT_HSH_DATW (*aptr++, 1);
      CVMX_MT_HSH_DATW (*aptr++, 2);
      CVMX_MT_HSH_DATW (*aptr++, 3);
      CVMX_MT_HSH_DATW (*aptr++, 4);
      CVMX_MT_HSH_DATW (*aptr++, 5);
      CVMX_MT_HSH_DATW (*aptr++, 6);
      CVMX_MT_HSH_DATW (*aptr++, 7);
      CVMX_MT_HSH_DATW (*aptr++, 8);
      CVMX_MT_HSH_DATW (*aptr++, 9);
      CVMX_MT_HSH_DATW (*aptr++, 10);
      CVMX_MT_HSH_DATW (*aptr++, 11);
      CVMX_MT_HSH_DATW (*aptr++, 12);
      CVMX_MT_HSH_DATW (*aptr++, 13);
      CVMX_MT_HSH_DATW (*aptr++, 14);
      CVMX_MT_HSH_STARTSHA512 (*aptr++);
      dlen -= 128;
   }
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 0); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 1); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 2); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 3); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 4); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 5); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 6); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 7); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 8); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 9); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 10); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 11); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 12); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 13); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 14); dlen -= 8;}
   
   /* Finish inner hash */ 
   {
      int chunk_len = pktlen % 128;    
      uint8_t chunk[200];  
      uint8_t i = 0;
      if(chunk_len >= 112 && chunk_len < 120) {
         chunk_len = 144;
         chunk_len += (dlen / 8) * 8;
      } else if(chunk_len >= 120) {
         chunk_len = 136;
         chunk_len += (dlen / 8) * 8;
      }
      else {
         chunk_len = 128 - chunk_len;
         chunk_len += dlen;
      }
      memset(chunk, 0x0, chunk_len);

      if(dlen)
         memcpy(chunk, (pktptr + pktlen - dlen - AH_FIXED_LEN - ICV_LEN_SHA512), dlen);
      *(chunk + dlen) = 0x80;
      uint64_t_mul(((uint64_t *)(chunk + chunk_len - 16))[0], ((uint64_t *)(chunk + chunk_len - 16))[1], (pktlen + 128), 0x8ull);

      while (i < chunk_len) {
         _CVMX_MT_HSH_DATW(*((uint64_t *)(chunk + i)), sha512_next);
         i += 8;
      }
   }

   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ opad));
   CVMX_M128BT_HSH_DATW_SHA512_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha512[0], 0);
   CVMX_MF_HSH_IVW (sha512[1], 1);
   CVMX_MF_HSH_IVW (sha512[2], 2);
   CVMX_MF_HSH_IVW (sha512[3], 3);

   /* put HMac in AH ICV */
   if(outptr != NULL) {       
      memcpy((outptr + IP_HEADER_LENGTH + AH_FIXED_LEN), (uint8_t *)sha512, ICV_LEN_SHA512);  
      memcpy(outptr + IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA512,
                 pktptr + IP_HEADER_LENGTH,
                 (pktlen - IP_HEADER_LENGTH - AH_FIXED_LEN - ICV_LEN_SHA512));
   } 
   else {
      memmove((pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA512),
                 (pktptr + IP_HEADER_LENGTH),
                 (pktlen - AH_FIXED_LEN - ICV_LEN_SHA512 - IP_HEADER_LENGTH));
      memcpy((pktptr + IP_HEADER_LENGTH), ah_header, AH_FIXED_LEN);
      memcpy((pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN), (uint8_t *)sha512, ICV_LEN_SHA512);
   }
   if(outlen)
      *outlen = pktlen;

   return 0;
}

int AH_inbound_sha512(uint16_t sha512_keylen, uint8_t *sha512_key, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, int compdigest)
{
   uint64_t *aptr;
   uint64_t sha512[8];
   uint32_t dlen, sha512_next; 
   uint32_t i;
   uint8_t saved_ah[AH_FIXED_LEN + ICV_LEN_SHA512];
   uint8_t sha_key[128];
   uint64_t inner_sha[8];

   if(pktptr == NULL || pktlen == 0 || sha512_key == NULL ||
         sha512_keylen == 0 || outlen == NULL) {
      printf("\n Wrong parameters \n");
      return -1;
   }   
   if(pktlen < (IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA512)) {
      printf("Packet length is not proper \n");
      return -1;
   }

   MEMSET128BTZ(sha_key);
   if(sha512_keylen > 128) {
      if(hash_key_sha512(sha512_key, sha512_keylen, sha_key, 1) < 0) {    
         printf(" improper mac secret \n");
         return -1;
      }
      sha512_keylen = 64;
   } else 
      memcpy(sha_key, sha512_key, sha512_keylen);

   /* Load SHA512 IV */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ ipad));

   memcpy(saved_ah, pktptr + IP_HEADER_LENGTH , AH_FIXED_LEN + ICV_LEN_SHA512);
   
   if(outptr == NULL) {
      memset(pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN, 0x0, ICV_LEN_SHA512);
      aptr = (uint64_t *)pktptr ;
   } else {
      memcpy(outptr, pktptr, pktlen); 
      memset(outptr + IP_HEADER_LENGTH + AH_FIXED_LEN, 0x0, ICV_LEN_SHA512);
      aptr = (uint64_t *)outptr;
   }
      
   sha512_next = 0;
   dlen = pktlen;

   /* Assumed that data is 8 byte aligned */
   sha512_next = (dlen % 128) / 8;
   while (dlen >= 128) {
      CVMX_MT_HSH_DATW (*aptr++, 0);
      CVMX_MT_HSH_DATW (*aptr++, 1);
      CVMX_MT_HSH_DATW (*aptr++, 2);
      CVMX_MT_HSH_DATW (*aptr++, 3);
      CVMX_MT_HSH_DATW (*aptr++, 4);
      CVMX_MT_HSH_DATW (*aptr++, 5);
      CVMX_MT_HSH_DATW (*aptr++, 6);
      CVMX_MT_HSH_DATW (*aptr++, 7);
      CVMX_MT_HSH_DATW (*aptr++, 8);
      CVMX_MT_HSH_DATW (*aptr++, 9);
      CVMX_MT_HSH_DATW (*aptr++, 10);
      CVMX_MT_HSH_DATW (*aptr++, 11);
      CVMX_MT_HSH_DATW (*aptr++, 12);
      CVMX_MT_HSH_DATW (*aptr++, 13);
      CVMX_MT_HSH_DATW (*aptr++, 14);
      CVMX_MT_HSH_STARTSHA512 (*aptr++);
      dlen -= 128;
   }
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 0); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 1); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 2); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 3); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 4); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 5); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 6); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 7); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 8); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 9); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 10); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 11); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 12); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 13); dlen -= 8;}
   if(dlen >= 8) {CVMX_MT_HSH_DATW(*aptr++, 14); dlen -= 8;}

   /* Finish inner hash */
   {
      int chunk_len = pktlen % 128;        
      uint8_t chunk[200];       
      uint8_t i= 0;
      if(chunk_len >= 112 && chunk_len < 120) {
         chunk_len = 144;
         chunk_len += (dlen / 8) * 8;
      } else if(chunk_len >= 120) {
         chunk_len = 136;
         chunk_len += (dlen / 8) * 8;
      }
      else {
         chunk_len = 128 - chunk_len;
         chunk_len += dlen;
      }
      memset(chunk, 0x0, chunk_len);

      if(dlen)
         memcpy(chunk, ((uint8_t *)aptr), dlen);
      *(chunk + dlen) = 0x80;
      uint64_t_mul(((uint64_t *)(chunk + chunk_len - 16))[0], ((uint64_t *)(chunk + chunk_len - 16))[1], (pktlen + 128), 0x8ull);

      while ( i < chunk_len) {
         _CVMX_MT_HSH_DATW(*((uint64_t *)(chunk + i)), sha512_next);
         i += 8;
      }
   }

   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ opad));
   CVMX_M128BT_HSH_DATW_SHA512_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha512[0], 0);
   CVMX_MF_HSH_IVW (sha512[1], 1);
   CVMX_MF_HSH_IVW (sha512[2], 2);
   CVMX_MF_HSH_IVW (sha512[3], 3);

   /* compare first 256 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(saved_ah + AH_FIXED_LEN, sha512, ICV_LEN_SHA512)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for( i = 0; i < ICV_LEN_SHA512; i++)
            printf(" %02x",((uint8_t *)sha512)[i]);

         printf("\n Expected");
         for(i = 0 ;i < ICV_LEN_SHA512; i++)
            printf(" %02x",saved_ah[AH_FIXED_LEN + i]);
         printf("\n");
         return -1;
      }
   }
   if(outptr == NULL)
     memmove(pktptr + IP_HEADER_LENGTH,
                pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA512,
                (pktlen - IP_HEADER_LENGTH - AH_FIXED_LEN - ICV_LEN_SHA512)); 
   else
     memcpy(outptr + IP_HEADER_LENGTH,
                pktptr + IP_HEADER_LENGTH + AH_FIXED_LEN + ICV_LEN_SHA512,
                pktlen - IP_HEADER_LENGTH - AH_FIXED_LEN - ICV_LEN_SHA512);
   
   if(outlen)
      *outlen = pktlen - AH_FIXED_LEN - ICV_LEN_SHA512;

   return 0;
}

int AH_inbound_md5 ( uint16_t auth_keylen, uint8_t *auth_key,  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen,int compdigest)
{
   uint64_t *aptr;
   uint64_t md5[2];
   uint32_t dlen, hash_next;
   uint32_t i;
   uint8_t sha_key[64];
   uint8_t saved_ah[24];
   uint64_t inner_hash[2];
   uint64_t bits;
   
   if(pktptr == NULL || pktlen == 0  || 
      auth_key == NULL || auth_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
    }
    if(pktlen < (IP_HEADER_LENGTH +AH_HEADER_LENGTH )) {
      printf("Packet length is not proper \n");
      return -1;
     }
   MEMSET64BTZ(sha_key);
   if(auth_keylen > 64) {
      if(hash_key(auth_key, auth_keylen, sha_key, 0)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
   auth_keylen = 16;
   } else
        memcpy(sha_key,auth_key,auth_keylen);

   /* Load MD5 IV */
   CVMX_MT_HSH_IV (md5defiv[0], 0);
   CVMX_MT_HSH_IV (md5defiv[1], 1);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ ipad));

   /* setup enc/hmac args */
   memcpy(saved_ah, pktptr+IP_HEADER_LENGTH, 24);  
   if(outptr==NULL) {
      memmove(pktptr+IP_HEADER_LENGTH,pktptr+IP_HEADER_LENGTH+24,(pktlen-IP_HEADER_LENGTH-24));
      aptr = (uint64_t *)pktptr ;
   } else {
      memcpy(outptr, pktptr, IP_HEADER_LENGTH);
        memcpy(outptr+IP_HEADER_LENGTH, pktptr+IP_HEADER_LENGTH+AH_HEADER_LENGTH, pktlen-IP_HEADER_LENGTH-AH_HEADER_LENGTH);
      aptr=(uint64_t *)outptr;
   }
   pktlen-=AH_HEADER_LENGTH;
   dlen = pktlen;
   /* Loop through input */
   hash_next = (dlen % 64)/8;
   while(dlen >=64) {
     CVMX_MT_HSH_DAT(*aptr++,0);
     CVMX_MT_HSH_DAT(*aptr++,1);
     CVMX_MT_HSH_DAT(*aptr++,2);
     CVMX_MT_HSH_DAT(*aptr++,3);
     CVMX_MT_HSH_DAT(*aptr++,4);
     CVMX_MT_HSH_DAT(*aptr++,5);
     CVMX_MT_HSH_DAT(*aptr++,6);
     CVMX_MT_HSH_STARTMD5(*aptr++);
     dlen -= 64;
   } 
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,0);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,1);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,2);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,3);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,4);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,5);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,6);dlen-=8;}
   /* Finish Inner hash */
   {
      int chunk_len=pktlen %64;
      uint8_t chunk[100];
      uint8_t i=0;
      if(chunk_len >= 56) {
         chunk_len = 72;
           chunk_len+=(dlen/8)*8;
      } else {
         chunk_len = 64-chunk_len;
         chunk_len += dlen;
      }
      if(dlen)
         memcpy(chunk,((uint8_t *)aptr),dlen);
      memset(chunk+dlen,0x0, chunk_len-dlen);
      *(chunk + dlen) = 0x80;
      {
          uint64_t bits;
          bits = (pktlen+64)*8;
          CVMX_ES64(bits, bits);
          *((uint64_t *)(chunk + chunk_len -8)) = bits;
      }
      while ( i< chunk_len) {
         _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), hash_next, 0);
          i += 8;
      }
   } 

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_hash[0], 0);
   CVMX_MF_HSH_IV (inner_hash[1], 1);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (md5defiv[0], 0);
   CVMX_MT_HSH_IV (md5defiv[1], 1);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ opad));

   CVMX_MT_HSH_DAT (inner_hash[0], 0);
   CVMX_MT_HSH_DAT (inner_hash[1], 1);
   CVMX_MT_HSH_DAT (0x8000000000000000ULL, 2);
   CVMX_MT_HSH_DATZ(3);
   CVMX_MT_HSH_DATZ(4);
   CVMX_MT_HSH_DATZ(5);
   CVMX_MT_HSH_DATZ(6);
   bits = (16+64)*8;
   CVMX_ES64(bits, bits);
   CVMX_MT_HSH_STARTMD5 (bits);

   /* Get the HMAC */
   CVMX_MF_HSH_IV (md5[0], 0);
   CVMX_MF_HSH_IV (md5[1], 1);
   /* compare first 96 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(saved_ah+12, md5, 12)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<12;i++)
            printf(" %02x",((uint8_t *)md5)[i]);
         printf("\n Expected");
         for(i=0;i<12;i++)
            printf(" %02x",saved_ah[12+i]);
         printf("\n");
         return -1;
      }
   }
   if(outlen)
      *outlen=pktlen;
   return 0;
}


int AH_outbound_md5 ( uint16_t auth_keylen, uint8_t *auth_key,  uint8_t *ah_header, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *aptr;
   uint32_t dlen;
   register int hash_next;
   uint64_t md5[2];
   uint8_t sha_key[64];
   uint64_t inner_hash[3];
   if(pktptr == NULL || pktlen == 0  || auth_key == NULL || 
      auth_keylen ==0 ||ah_header == NULL||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
    }
    if(pktlen<IP_HEADER_LENGTH) {
      printf("\n pktlen should be atleast 20 bytes");
      return -1;
   }
   if(pktlen >(MAX_PKT_SIZE-AH_HEADER_LENGTH)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   MEMSET64BTZ(sha_key);
   if(auth_keylen > 64) {
      if(hash_key(auth_key, auth_keylen, sha_key, 0)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      auth_keylen = 16;
   } else
      memcpy(sha_key,auth_key,auth_keylen);
   
   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (md5defiv[0], 0);
   CVMX_MT_HSH_IV (md5defiv[1], 1);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ ipad));
   if(outptr != NULL) {
      memcpy(outptr, pktptr, IP_HEADER_LENGTH);
      memcpy(outptr+IP_HEADER_LENGTH, ah_header, 12);
   }
   dlen = pktlen;
   aptr=(uint64_t *)pktptr;
   /* Start encryption */
   
   hash_next = (dlen % 64)/8;
   while(dlen >=64) {
     CVMX_MT_HSH_DAT(*aptr++,0);
     CVMX_MT_HSH_DAT(*aptr++,1);
     CVMX_MT_HSH_DAT(*aptr++,2);
     CVMX_MT_HSH_DAT(*aptr++,3);
     CVMX_MT_HSH_DAT(*aptr++,4);
     CVMX_MT_HSH_DAT(*aptr++,5);
     CVMX_MT_HSH_DAT(*aptr++,6);
     CVMX_MT_HSH_STARTMD5(*aptr++);
     dlen -= 64;
   } 
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,0);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,1);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,2);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,3);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,4);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,5);dlen-=8;}
   if(dlen >= 8) {CVMX_MT_HSH_DAT(*aptr++,6);dlen-=8;}

   /* Finish inner hash */
   {
      int chunk_len=pktlen %64;
      uint8_t chunk[100];
      uint8_t i=0;
      if(chunk_len >= 56) {
         chunk_len = 72;
         chunk_len+=(dlen/8)*8;
      } else {
         chunk_len = 64-chunk_len;
         chunk_len += dlen;
      }
      if(dlen)
         memcpy(chunk,(pktptr+pktlen-dlen),dlen);
      memset(chunk+dlen,0x0, chunk_len-dlen);
      *(chunk+dlen)= 0x80;
      {
         uint64_t bits;
         bits = (pktlen +64)*8;
         CVMX_ES64(bits, bits);
         *((uint64_t *)(chunk + chunk_len -8)) = bits;
      }
      while ( i< chunk_len){
         _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), hash_next, 0);
          i += 8;
      }
   } 
   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_hash[0], 0);
   CVMX_MF_HSH_IV (inner_hash[1], 1);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (md5defiv[0], 0);
   CVMX_MT_HSH_IV (md5defiv[1], 1);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ opad));

   CVMX_MT_HSH_DAT (inner_hash[0], 0);
   CVMX_MT_HSH_DAT (inner_hash[1], 1);
   CVMX_MT_HSH_DAT (0x8000000000000000ULL, 2);
   CVMX_MT_HSH_DATZ(3);
   CVMX_MT_HSH_DATZ(4);
   CVMX_MT_HSH_DATZ(5);
   CVMX_MT_HSH_DATZ(6);
   {
      uint64_t bits;
      bits = (16 +64)*8;
      CVMX_ES64(bits, bits);
      CVMX_MT_HSH_STARTMD5 (bits);
   }

   /* Get the HMAC */
   CVMX_MF_HSH_IV (md5[0], 0);
   CVMX_MF_HSH_IV (md5[1], 1);
   /* put HMac at the end of the packet */
   if(outptr != NULL) {
      memcpy((outptr+IP_HEADER_LENGTH+12),(uint8_t *)md5,12);
      memcpy((outptr+IP_HEADER_LENGTH+AH_HEADER_LENGTH),(pktptr+IP_HEADER_LENGTH),(pktlen-IP_HEADER_LENGTH));
   }
   else {
       memmove((pktptr+IP_HEADER_LENGTH+AH_HEADER_LENGTH),(pktptr+IP_HEADER_LENGTH),(pktlen-IP_HEADER_LENGTH));
       memcpy((pktptr+IP_HEADER_LENGTH),ah_header,12);
       memcpy((pktptr+IP_HEADER_LENGTH+12),(uint8_t *)md5,12);
   }
   if(outlen)
      *outlen=pktlen+AH_HEADER_LENGTH;
   return 0;
}

int AES_ctr_md5_encrypt(uint64_t *aes_key, uint32_t aes_key_len, uint32_t nonce, uint16_t auth_keylen, uint8_t *auth_key, uint8_t *espheader, uint8_t *aes_iv,  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
    uint64_t *dptr, *aptr,*rptr;
    register uint64_t in1,in2,out1,out2;
    register int sha1_next;
    uint64_t md5[2];
    uint32_t dlen;
    uint64_t in;
    uint32_t i;
    uint8_t sha_key[64];
    uint64_t inner_hash[2];
    cntrblk_t cntrblk;
    uint64_t enc_cntrblk[2];
    if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
            aes_key == NULL || aes_iv == NULL || auth_key == NULL || 
            auth_keylen ==0 ||outlen==NULL) {
        printf("\n Wrong parameters \n");   
        return -1;
    }
    if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-AES_CTR_IV_LENGTH-12)) {
        printf("Packet is too big to handle \n");
        return -1;
    }
    aes_key_len = aes_key_len *8;
    CVMX_PREFETCH0(aes_key);
    CVMX_PREFETCH0(aes_iv);
    memset(sha_key,0,64);
    if(auth_keylen > 64) {
        if(hash_key(auth_key, auth_keylen, sha_key, 0)<0) {
            printf(" improper mac secret \n");   
            return -1;
        }
        auth_keylen = 16;
    } else
        memcpy(sha_key,auth_key,auth_keylen);
    cntrblk.blk[0] = 0;
    cntrblk.blk[1] = 0;
    cntrblk.s.nonce = nonce;
    for(i = 0; i < AES_CTR_IV_LENGTH; i++)
        cntrblk.s.aes_iv[i] = aes_iv[i];
    cntrblk.s.counter = 1;

    in1=cntrblk.blk[0];
    in2=cntrblk.blk[1];

    /* Load AES Key and IV */
    CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
    CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
    if(aes_key_len == 128) {
        CVMX_MT_AES_KEY ((uint64_t *)0x0, 2);
        CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
    } else if(aes_key_len == 192) {
        CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
        CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
    } else if(aes_key_len == 256) {
        CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
        CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
    } else {
        printf(" Improper Key length \n");
        return -1;
    }
    CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);


    /* Load SHA1 IV */
    CVMX_MT_HSH_IV (md5defiv[0], 0);
    CVMX_MT_HSH_IV (md5defiv[1], 1);

    /* Load key xor ipad */
    aptr = (uint64_t *) sha_key;
    sha1_next = 0;
    CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ ipad));

    aptr =(uint64_t *)espheader;
    CVMX_MT_HSH_DAT (*aptr++, 0);
    aptr =(uint64_t *)aes_iv;
    CVMX_MT_HSH_DAT (*aptr++, 1);

    /* Copy header & setup enc/hmac args */
    dptr = (uint64_t *)pktptr;
    dlen = pktlen;
    if(outptr != NULL) {
        ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
        ((uint64_t *)outptr)[1]=((uint64_t *)aes_iv)[0];
        rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
    } else
        rptr= (uint64_t *)pktptr;

    
    COP2_PARALLEL_128BN_AES_CTR_ENC_MD5(dptr,rptr,dlen);

    if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_MD5_STEP(2,3);
    if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_MD5_STEP(4,5);
    if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_MD5_STEP(6,7);
    if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_MD5_STEP(0,1);
    if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_MD5_STEP(2,3);
    if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_MD5_STEP(4,5);
    if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_MD5_STEP(6,7);

    sha1_next = ((pktlen+16) % 64)/8;

    aptr =rptr;      
    /* Loop through input */
    if(dlen) {
        uint32_t i;
        CVMX_MT_AES_ENC0(in1);
        CVMX_MT_AES_ENC1(in2);
        CVMX_MF_AES_RESULT (enc_cntrblk[0], 0);
        CVMX_MF_AES_RESULT (enc_cntrblk[1], 1);
        for(i=0;i<dlen;i++)
            ((uint8_t *)rptr)[i]=((uint8_t *)dptr)[i]^((uint8_t *)enc_cntrblk)[i];
    }
    /* Finish inner hash */
    {
        int chunk_len=(pktlen+ESP_HEADER_LENGTH +AES_CTR_IV_LENGTH) %64;
        uint8_t chunk[100];
        uint8_t i=0;
        if(chunk_len >= 56) { 
            chunk_len = 72;
            chunk_len+=(dlen/8)*8;
        } else {
            chunk_len = 64-chunk_len;
            chunk_len += dlen;
        }
        memset(chunk,0x0, chunk_len);
        if(dlen) {
            memcpy(chunk,(uint8_t *)rptr,dlen);
            rptr = (uint64_t *)(((uint8_t *)rptr)+dlen);
            *(chunk+dlen)=0x80;
        } else
            chunk[0]= 0x80;
        *((uint64_t *)(chunk + chunk_len -8)) = (pktlen+ESP_HEADER_LENGTH +AES_CTR_IV_LENGTH+ 64) * 8;
        i=0;
        while ( i< chunk_len) {
            _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), sha1_next, 0);
            i += 8;
        }
    } 

    /* Get the inner hash of HMAC */
    CVMX_MF_HSH_IV (inner_hash[0], 0);
    CVMX_MF_HSH_IV (inner_hash[1], 1);

    /* Initialize hash unit */
    CVMX_MT_HSH_IV (md5defiv[0], 0);
    CVMX_MT_HSH_IV (md5defiv[1], 1);

    /* Load key xor opad */
    aptr = (uint64_t *) sha_key;
    sha1_next = 0;
    CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ opad));

    CVMX_MT_HSH_DAT (inner_hash[0], 0);
    CVMX_MT_HSH_DAT (inner_hash[1], 1);
    CVMX_MT_HSH_DAT (0x8000000000000000ULL,2);
    CVMX_MT_HSH_DATZ(3);
    CVMX_MT_HSH_DATZ(4);
    CVMX_MT_HSH_DATZ(5);
    CVMX_MT_HSH_DATZ(6);
    in=(16+64)*8;
    CVMX_ES64(in,in);
    CVMX_MT_HSH_STARTMD5 (in);

    /* Get the HMAC */
    CVMX_MF_HSH_IV (md5[0], 0);
    CVMX_MF_HSH_IV (md5[1], 1);
    /* put HMac at the end of the packet */
    memcpy(rptr, md5, 12);
    if(outlen) {
        if(outptr)
            *outlen = pktlen+ESP_HEADER_LENGTH +AES_CTR_IV_LENGTH+12;
        else
            *outlen = pktlen+12;
    }
    return 0;
}

int AES_ctr_md5_decrypt(uint64_t *aes_key, uint32_t aes_key_len, uint32_t nonce, uint16_t auth_keylen, uint8_t *auth_key, uint8_t *aes_iv,  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
    uint64_t *dptr, *aptr,*rptr;
    register uint64_t in1,in2,out1,out2;
    register int sha1_next;
    uint64_t md5[2];
    uint32_t dlen;
    uint64_t in;
    uint32_t i;
    uint8_t sha_key[64];
    uint64_t inner_hash[2];
    cntrblk_t cntrblk;
    uint64_t enc_cntrblk[2];
    if(pktptr == NULL || pktlen == 0  || aes_key == NULL || 
            aes_iv == NULL || auth_key == NULL || auth_keylen ==0 ||outlen==NULL) {
        printf("\n Wrong parameters \n");   
        return -1;
    }
    if(pktlen < (ESP_HEADER_LENGTH +AES_CTR_IV_LENGTH+ 12 +1)) {
        printf("Packet length is not proper \n");
        return -1;
    }
    aes_key_len = aes_key_len *8;
    CVMX_PREFETCH0(aes_iv);
    CVMX_PREFETCH0(aes_key);
    memset(sha_key,0x0,64);
    if(auth_keylen > 64) {
        if(hash_key(auth_key, auth_keylen, sha_key, 0)<0) {
            printf(" improper mac secret \n");   
            return -1;
        }
        auth_keylen = 16;
    } else
        memcpy(sha_key,auth_key,auth_keylen);
    cntrblk.blk[0] = 0;
    cntrblk.blk[1] = 0;
    cntrblk.s.nonce = nonce;
    for(i = 0; i < AES_CTR_IV_LENGTH; i++)
        cntrblk.s.aes_iv[i] = aes_iv[i];
    cntrblk.s.counter = 1;

    in1=cntrblk.blk[0];
    in2=cntrblk.blk[1];

    /* Load AES Key and IV */
    CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
    CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
    if(aes_key_len == 128) {
        CVMX_MT_AES_KEY ((uint64_t *)0x0, 2);
        CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
    } else if(aes_key_len == 192) {
        CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
        CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
    } else if(aes_key_len == 256) {
        CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
        CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
    } else {
        printf(" Improper Key length \n");
        return -1;
    }
    CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

    /* Load SHA1 IV */
    CVMX_MT_HSH_IV (md5defiv[0], 0);
    CVMX_MT_HSH_IV (md5defiv[1], 1);

    /* Load key xor ipad */
    aptr = (uint64_t *) sha_key;
    CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ ipad));

    /* setup enc/hmac args */
    aptr = (uint64_t *)pktptr ;
    CVMX_PREFETCH0(aptr);
    dptr = (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
    dlen = pktlen -ESP_HEADER_LENGTH- AES_CTR_IV_LENGTH - 12;
    if(outptr != NULL) {
        ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
        ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
        rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
    }
    else
        rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);


    /* load esp header and iv to hash unit */
    CVMX_MT_HSH_DAT (*aptr++, 0);
    CVMX_MT_HSH_DAT (*aptr++, 1);

    sha1_next = ((dlen + 16) % 64) / 8;

    while(dlen >= 128)
    {
        COP2_PARALLEL_16B_AES_CTR_DEC_MD5_STEP(2,3);
        COP2_PARALLEL_16B_AES_CTR_DEC_MD5_STEP(4,5);
        COP2_PARALLEL_16B_AES_CTR_DEC_MD5_STEP(6,7);
        COP2_PARALLEL_16B_AES_CTR_DEC_MD5_STEP(0,1);
        COP2_PARALLEL_16B_AES_CTR_DEC_MD5_STEP(2,3);
        COP2_PARALLEL_16B_AES_CTR_DEC_MD5_STEP(4,5);
        COP2_PARALLEL_16B_AES_CTR_DEC_MD5_STEP(6,7);
        COP2_PARALLEL_16B_AES_CTR_DEC_MD5_STEP(0,1);
    }

    if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_MD5_STEP(2,3);
    if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_MD5_STEP(4,5);
    if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_MD5_STEP(6,7);
    if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_MD5_STEP(0,1);
    if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_MD5_STEP(2,3);
    if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_MD5_STEP(4,5);
    if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_MD5_STEP(6,7);

    aptr = dptr;

    /* Loop through input */
    pktlen = pktlen - 12;
    /* Finish Inner hash */
    {
        int chunk_len=pktlen %64;
        uint8_t chunk[100];
        uint8_t i=0;
        if(chunk_len >= 56) {
            chunk_len = 72;
            chunk_len+=(dlen/8)*8;
        } else {
            chunk_len = 64-chunk_len;
            chunk_len += dlen;
        }
        memset(chunk,0x0, chunk_len);
        if(dlen) {
            memcpy(chunk,(uint8_t *)dptr,dlen);
            *(chunk+dlen)=0x80;
            CVMX_MT_AES_ENC0 (in1);
            CVMX_MT_AES_ENC1 (in2);
            CVMX_MF_AES_RESULT (enc_cntrblk[0], 0);
            CVMX_MF_AES_RESULT (enc_cntrblk[1], 1);
            for(i=0;i<dlen;i++)
                ((uint8_t *)rptr)[i]=((uint8_t *)dptr)[i] ^((uint8_t *)enc_cntrblk)[i];
            rptr =(uint64_t *)((uint8_t *)rptr +dlen);
        } else
            chunk[0]= 0x80;
        *((uint64_t *)(chunk + chunk_len -8)) = (pktlen+ 64) * 8;
        i=0;
        while ( i< chunk_len) {
            _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), sha1_next, 0);
            i += 8;
        }
    } 

    /* Get the inner hash of HMAC */
    CVMX_MF_HSH_IV (inner_hash[0], 0);
    CVMX_MF_HSH_IV (inner_hash[1], 1);

    /* Initialize hash unit */
    CVMX_MT_HSH_IV (md5defiv[0], 0);
    CVMX_MT_HSH_IV (md5defiv[1], 1);

    /* Load key xor opad */
    aptr = (uint64_t *) sha_key;
    CVMX_M64BT_HSH_DAT_MD5((*aptr++ ^ opad));

    CVMX_MT_HSH_DAT (inner_hash[0], 0);
    CVMX_MT_HSH_DAT (inner_hash[1], 1);
    CVMX_MT_HSH_DAT (0x8000000000000000ULL, 2);
    CVMX_MT_HSH_DATZ (3);
    CVMX_MT_HSH_DATZ (4);
    CVMX_MT_HSH_DATZ (5);
    CVMX_MT_HSH_DATZ (6);
    in=(64+16)*8;
    CVMX_ES64(in,in);
    CVMX_MT_HSH_STARTMD5 (in);

    /* Get the HMAC */
    CVMX_MF_HSH_IV (md5[0], 0);
    CVMX_MF_HSH_IV (md5[1], 1);

    /* compare first 96 bits of HMAC with received mac */
    if(compdigest) {
        if(memcmp(pktptr+pktlen, md5, 12))   {
            printf("\n INBOUND Mac Mismatch ");
            printf("\n Generated");
            for(i=0; i<12; i++)
                printf(" %02x",((uint8_t *)md5)[i]);
            printf("\n Expected");
            for(i=0; i<12; i++)
                printf(" %02x",(pktptr+pktlen)[i]);
            printf("\n");
            return -1;
        }
    } else if(outptr)
        memcpy(outptr+pktlen, md5, 12);

    if(outlen)
        *outlen = pktlen;
    return 0;
}


int AES_ctr_sha1_encrypt(uint64_t *aes_key, uint32_t aes_key_len, uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *aes_iv,  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr;
   register uint64_t in1,in2,out1,out2;
   register int sha1_next;
   uint64_t sha1[3];
   uint32_t dlen;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_sha[3];
   cntrblk_t cntrblk;
   uint64_t enc_cntrblk[2];
   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      aes_key == NULL || aes_iv == NULL || sha1_key == NULL || 
      sha1_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-AES_CTR_IV_LENGTH-ICV_LEN_SHA1)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   aes_key_len = aes_key_len *8;
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);
   memset(sha_key,0,64);
   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 1)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 20;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);
   cntrblk.blk[0] = 0;
   cntrblk.blk[1] = 0;
   cntrblk.s.nonce = nonce;
   for(i = 0; i < AES_CTR_IV_LENGTH; i++)
      cntrblk.s.aes_iv[i] = aes_iv[i];
   cntrblk.s.counter = 1;

   in1=cntrblk.blk[0];
   in2=cntrblk.blk[1];

   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 192) {
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 256) {
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
        CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);


   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   sha1_next = 0;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ ipad));
   
   aptr =(uint64_t *)espheader;
   CVMX_MT_HSH_DAT (*aptr++, 0);
   aptr =(uint64_t *)aes_iv;
   CVMX_MT_HSH_DAT (*aptr++, 1);

   /* Copy header & setup enc/hmac args */
   dptr = (uint64_t *)pktptr;
   dlen = pktlen;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)aes_iv)[0];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
   } else
      rptr= (uint64_t *)pktptr;
  

   COP2_PARALLEL_128BN_AES_CTR_ENC_SHA1(dptr,rptr,dlen);

   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA1_STEP(2,3);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA1_STEP(4,5);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA1_STEP(6,7);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA1_STEP(0,1);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA1_STEP(2,3);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA1_STEP(4,5);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA1_STEP(6,7);

   sha1_next = (((pktlen+16) % 64)/16) * 2;
 
   aptr =rptr;      
   /* Loop through input */
   if(dlen) {
      uint32_t i;
      CVMX_MT_AES_ENC0(in1);
      CVMX_MT_AES_ENC1(in2);
      CVMX_MF_AES_RESULT (enc_cntrblk[0], 0);
      CVMX_MF_AES_RESULT (enc_cntrblk[1], 1);
      for(i=0;i<dlen;i++)
         ((uint8_t *)rptr)[i]=((uint8_t *)dptr)[i]^((uint8_t *)enc_cntrblk)[i];
   }
   /* Finish inner hash */
   {
      int chunk_len=(pktlen+ESP_HEADER_LENGTH +AES_CTR_IV_LENGTH) %64;
      uint8_t chunk[100];
      uint8_t i=0;
      if(chunk_len >= 56) { 
         chunk_len = 72;
         chunk_len+=(dlen/8)*8;
      } else {
         chunk_len = 64-chunk_len;
         chunk_len += dlen;
      }
      memset(chunk,0x0, chunk_len);
      if(dlen) {
         memcpy(chunk,(uint8_t *)rptr,dlen);
         rptr = (uint64_t *)(((uint8_t *)rptr)+dlen);
         *(chunk+dlen)=0x80;
      } else
         chunk[0]= 0x80;
      *((uint64_t *)(chunk + chunk_len -8)) = (pktlen+ESP_HEADER_LENGTH +AES_CTR_IV_LENGTH+ 64) * 8;
      i=0;
      while ( i< chunk_len) {
         _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), sha1_next, 1);
          i += 8;
      }
   } 

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_sha[0], 0);
   CVMX_MF_HSH_IV (inner_sha[1], 1);
   CVMX_MF_HSH_IV (inner_sha[2], 2);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   sha1_next = 0;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ opad));

   CVMX_MT_HSH_DAT (inner_sha[0], 0);
   CVMX_MT_HSH_DAT (inner_sha[1], 1);
   ((uint8_t *)inner_sha)[20]=0x80;
   ((uint8_t *)inner_sha)[21]=0x0;
   ((uint8_t *)inner_sha)[22]=0x0;
   ((uint8_t *)inner_sha)[23]=0x0;
   CVMX_MT_HSH_DAT (inner_sha[2], 2);
   CVMX_MT_HSH_DATZ(3);
   CVMX_MT_HSH_DATZ(4);
   CVMX_MT_HSH_DATZ(5);
   CVMX_MT_HSH_DATZ(6);
   CVMX_MT_HSH_STARTSHA ((uint64_t) ((64 + 20) * 8));

   /* Get the HMAC */
   CVMX_MF_HSH_IV (sha1[0], 0);
   CVMX_MF_HSH_IV (sha1[1], 1);
   /* put HMac at the end of the packet */
   memcpy(rptr, sha1, ICV_LEN_SHA1);
   if(outlen) {
      if(outptr)
         *outlen = pktlen+ESP_HEADER_LENGTH +AES_CTR_IV_LENGTH+ICV_LEN_SHA1;
      else
         *outlen = pktlen+ICV_LEN_SHA1;
   }
   return 0;
}

int AES_ctr_sha1_decrypt(uint64_t *aes_key, uint32_t aes_key_len, uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv,  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   register uint64_t in1,in2,out1,out2;
   register int sha1_next;
   uint64_t sha1[3];
   uint32_t dlen;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_sha[3];
   cntrblk_t cntrblk;
   uint64_t enc_cntrblk[2];
   if(pktptr == NULL || pktlen == 0  || aes_key == NULL || 
      aes_iv == NULL || sha1_key == NULL || sha1_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +AES_CTR_IV_LENGTH+ICV_LEN_SHA1+1)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   aes_key_len = aes_key_len *8;
   CVMX_PREFETCH0(aes_iv);
   CVMX_PREFETCH0(aes_key);
   memset(sha_key,0x0,64);
   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 1)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
   sha1_keylen = 20;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);
   cntrblk.blk[0] = 0;
   cntrblk.blk[1] = 0;
   cntrblk.s.nonce = nonce;
   for(i = 0; i < AES_CTR_IV_LENGTH; i++)
      cntrblk.s.aes_iv[i] = aes_iv[i];
   cntrblk.s.counter = 1;

   in1=cntrblk.blk[0];
   in2=cntrblk.blk[1];

   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 192) {
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 256) {
        CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
        CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ ipad));
   
   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   CVMX_PREFETCH0(aptr);
   dptr = (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
   dlen = pktlen -ESP_HEADER_LENGTH- AES_CTR_IV_LENGTH -ICV_LEN_SHA1;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
   }
   else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);


   /* load esp header and iv to hash unit */
   CVMX_MT_HSH_DAT (*aptr++, 0);
   CVMX_MT_HSH_DAT (*aptr++, 1);

   sha1_next = (((dlen + 16) % 64) / 16) * 2;
   
   while(dlen >= 128)
   {
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA1_STEP(2,3);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA1_STEP(4,5);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA1_STEP(6,7);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA1_STEP(0,1);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA1_STEP(2,3);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA1_STEP(4,5);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA1_STEP(6,7);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA1_STEP(0,1);
   }

   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA1_STEP(2,3);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA1_STEP(4,5);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA1_STEP(6,7);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA1_STEP(0,1);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA1_STEP(2,3);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA1_STEP(4,5);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA1_STEP(6,7);

   aptr = dptr;
  
   /* Loop through input */
   pktlen = pktlen -ICV_LEN_SHA1;
   /* Finish Inner hash */
   {
      int chunk_len=pktlen %64;
      uint8_t chunk[100];
      uint8_t i=0;
      if(chunk_len >= 56) {
         chunk_len = 72;
         chunk_len+=(dlen/8)*8;
      } else {
         chunk_len = 64-chunk_len;
         chunk_len += dlen;
      }
      memset(chunk,0x0, chunk_len);
      if(dlen) {
         memcpy(chunk,(uint8_t *)dptr,dlen);
         *(chunk+dlen)=0x80;
         CVMX_MT_AES_ENC0 (in1);
         CVMX_MT_AES_ENC1 (in2);
         CVMX_MF_AES_RESULT (enc_cntrblk[0], 0);
         CVMX_MF_AES_RESULT (enc_cntrblk[1], 1);
         for(i=0;i<dlen;i++)
            ((uint8_t *)rptr)[i]=((uint8_t *)dptr)[i] ^((uint8_t *)enc_cntrblk)[i];
         rptr =(uint64_t *)((uint8_t *)rptr +dlen);
      } else
         chunk[0]= 0x80;
      *((uint64_t *)(chunk + chunk_len -8)) = (pktlen+ 64) * 8;
      i=0;
      while ( i< chunk_len) {
         _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), sha1_next, 1);
         i += 8;
      }
   } 

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_sha[0], 0);
   CVMX_MF_HSH_IV (inner_sha[1], 1);
   CVMX_MF_HSH_IV (inner_sha[2], 2);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (sha1defiv[0], 0);
   CVMX_MT_HSH_IV (sha1defiv[1], 1);
   CVMX_MT_HSH_IV (sha1defiv[2], 2);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA1((*aptr++ ^ opad));

   CVMX_MT_HSH_DAT (inner_sha[0], 0);
   CVMX_MT_HSH_DAT (inner_sha[1], 1);
   ((uint8_t *)inner_sha)[20]=0x80;
   ((uint8_t *)inner_sha)[21]=0x0;
   ((uint8_t *)inner_sha)[22]=0x0;
   ((uint8_t *)inner_sha)[23]=0x0;
   CVMX_MT_HSH_DAT (inner_sha[2], 2);
   CVMX_MT_HSH_DATZ(3);
   CVMX_MT_HSH_DATZ(4);
   CVMX_MT_HSH_DATZ(5);
   CVMX_MT_HSH_DATZ(6);
   CVMX_MT_HSH_STARTSHA ((uint64_t) ((64 + 20) * 8));

   /* Get the HMAC */
   CVMX_MF_HSH_IV (sha1[0], 0);
   CVMX_MF_HSH_IV (sha1[1], 1);
   /* compare first 96 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, sha1, ICV_LEN_SHA1))   {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA1;i++)
            printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA1;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
   } else if(outptr)
      memcpy(outptr+pktlen, sha1, ICV_LEN_SHA1);
      
   if(outlen)
      *outlen = pktlen;
   return 0;
}


int DES_ede3_cbc_sha256_encrypt(uint8_t *des_key, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t sha1[4];
   uint32_t dlen;
   uint8_t sha_key[64];
   uint64_t inner_sha[4];
   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
   des_key == NULL || des_iv == NULL || sha1_key == NULL || 
   sha1_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
    }
   if((pktlen < 8) || (pktlen%8)) {
      printf(" packetlen is not proper \n");
      return -1;
   }
   if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-DES_CBC_IV_LENGTH-ICV_LEN_SHA256)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   CVMX_PREFETCH0(des_key);
   CVMX_PREFETCH0(des_iv);

   MEMSET64BTZ(sha_key);

   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 2)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
   sha1_keylen = 32;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);
   /* load 3DES Key */
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[0], 0);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[1], 1);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[2], 2);

   CVMX_MT_3DES_IV (*((uint64_t *)des_iv));

   /* Load SHA1 IV */
   CVMX_M32BT_HSH_IV(sha256defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad));

   aptr = (uint64_t *) espheader;
   CVMX_MT_HSH_DAT (*aptr, 0);
   aptr = (uint64_t *) des_iv;
   CVMX_MT_HSH_DAT (*aptr, 1);
   /* Copy header & setup enc/hmac args */
   dptr = (uint64_t *) pktptr;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *) espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *) des_iv)[0];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   } else
      rptr = (uint64_t *)pktptr;
   aptr = rptr;

   COP2_PARALLEL_3DES_ENC_SHA256(dptr,rptr,dlen);
   CVMX_MF_3DES_IV (*((uint64_t *)des_iv));

   /* Get the inner hash of HMAC */
   CVMX_M32BF_HSH_IV(inner_sha);

   /* Initialize hash unit */
   CVMX_M32BT_HSH_IV(sha256defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));

   CVMX_M64BT_HSH_DAT_SHA256_HMAC(inner_sha);
    
   /* Get the HMAC */
   CVMX_M16BF_HSH_IV (sha1);

   /* put HMac at the end of the packet */
   memcpy(rptr, sha1, ICV_LEN_SHA256);
   if(outlen) {
      if(outptr)
         *outlen =pktlen+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH+ICV_LEN_SHA256;
      else
         *outlen =pktlen+ICV_LEN_SHA256;
   }
   return 0;
}


int DES_ede3_cbc_sha256_decrypt(uint8_t *des_key, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen,uint8_t *outptr, uint16_t *outlen,uint8_t compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t sha1[4];
   uint32_t dlen;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_sha[4];
   if(pktptr == NULL ||  pktlen == 0  || des_key == NULL || 
      des_iv == NULL || sha1_key == NULL || sha1_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +DES_CBC_IV_LENGTH+ICV_LEN_SHA256+8)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   CVMX_PREFETCH0(des_key);
   CVMX_PREFETCH0(des_iv);
   memset(sha_key,0x0,64);
   if(sha1_keylen > 64)   {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 2)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 32;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);

   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[0], 0);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[1], 1);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[2], 2);

   CVMX_MT_3DES_IV (*((uint64_t *)des_iv));

   /* Load SHA1 IV */
   CVMX_M32BT_HSH_IV(sha256defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad));

   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   CVMX_PREFETCH0(aptr);
   dptr = (uint64_t *) (pktptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   dlen = pktlen -ESP_HEADER_LENGTH-DES_CBC_IV_LENGTH-ICV_LEN_SHA256;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *) pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *) pktptr)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   } else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   /* load esp header and iv to hash unit */
   CVMX_MT_HSH_DAT (*aptr++, 0);
   CVMX_MT_HSH_DAT (*aptr++, 1);

   pktlen = pktlen - ICV_LEN_SHA256;
   dptr = aptr;
   COP2_PARALLEL_3DES_DEC_SHA256(dptr,rptr,dlen);
   CVMX_MF_3DES_IV (*((uint64_t *)des_iv));

   /* Get the inner hash of HMAC */
   CVMX_M32BF_HSH_IV(inner_sha);

   /* Initialize hash unit */
   CVMX_M32BT_HSH_IV(sha256defiv);

   /* Load key xor opad */
   
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));

   CVMX_M64BT_HSH_DAT_SHA256_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_M16BF_HSH_IV(sha1);
   
   /* compare first 96 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, sha1, ICV_LEN_SHA256)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA256;i++)
            printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA256;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
   } else if(outptr)
      memcpy(outptr+pktlen, sha1, ICV_LEN_SHA256);
  
   if(outlen)
      *outlen = pktlen;
   return 0;
}

int AES_cbc_sha256_encrypt(uint16_t aes_key_len, uint8_t *aes_key,  uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t sha1[4];
   uint32_t dlen;
   uint8_t sha_key[64];
   uint64_t inner_sha[4];
    
   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      aes_key == NULL || aes_iv == NULL || sha1_key == NULL || 
      sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
    }
   if((pktlen < 16) || (pktlen%16)) {
      printf(" packetlen is not proper \n");
      return -1;
   }
   if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-AES_CBC_IV_LENGTH-ICV_LEN_SHA256)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);

   MEMSET64BTZ(sha_key);

   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 2)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 32;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);
   aes_key_len = aes_key_len *8; 
   
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY (0x0ULL, 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 256) {
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Load SHA1 IV */
   CVMX_M32BT_HSH_IV(sha256defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad)); 

   /* load Esp header and iv */
   aptr =(uint64_t *)espheader;
   CVMX_MT_HSH_DAT (*aptr, 0);
   aptr =(uint64_t *)aes_iv;
   CVMX_MT_HSH_DAT (aptr[0], 1);
   CVMX_MT_HSH_DAT (aptr[1], 2);

   /* Copy header & setup enc/hmac args */
   dptr = (uint64_t *) pktptr;
   CVMX_PREFETCH0(dptr);

   dlen = pktlen;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)aes_iv)[0];
      ((uint64_t *)outptr)[2]=((uint64_t *)aes_iv)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
   } else
      rptr =(uint64_t *)pktptr;
   aptr =rptr;

   /* Start encryption */
   COP2_PARALLEL_AES_ENC_SHA256(dptr,rptr,dlen);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Get the inner hash of HMAC */
   CVMX_M32BF_HSH_IV(inner_sha);

   /* Initialize hash unit */
   CVMX_M32BT_HSH_IV(sha256defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));

   CVMX_M64BT_HSH_DAT_SHA256_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_M16BF_HSH_IV(sha1);

   /* put HMac at the end of the packet */
   memcpy(rptr, sha1, ICV_LEN_SHA256);

   if(outlen) {
      if(outptr)
         *outlen = (pktlen + ESP_HEADER_LENGTH +AES_CBC_IV_LENGTH +ICV_LEN_SHA256);
      else
         *outlen = (pktlen +ICV_LEN_SHA256);
   }
   return 0;
}


int AES_cbc_sha256_decrypt(uint16_t aes_key_len, uint8_t *aes_key, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t sha1[4];
   uint32_t dlen;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_sha[4];
   if(pktptr == NULL || pktlen == 0  || aes_key == NULL || 
      aes_iv == NULL || sha1_key == NULL || sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +AES_CBC_IV_LENGTH+ICV_LEN_SHA256)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   memset(sha_key,0x0,64);
   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 2)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 32;
   } else
   memcpy(sha_key,sha1_key,sha1_keylen);
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);
   aes_key_len = aes_key_len * 8;
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY (0x0ULL, 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 256) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Load SHA1 IV */
   CVMX_M32BT_HSH_IV(sha256defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad));

   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   CVMX_PREFETCH0(aptr);
   dptr = (uint64_t *) (pktptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH) ;
   dlen = pktlen - ESP_HEADER_LENGTH- AES_CBC_IV_LENGTH -ICV_LEN_SHA256;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      ((uint64_t *)outptr)[2]=((uint64_t *)pktptr)[2];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
   } else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
    
   /* load esp header and iv to hash unit */
   CVMX_MT_HSH_DAT (*aptr++, 0);
   CVMX_MT_HSH_DAT (*aptr++, 1);
   CVMX_MT_HSH_DAT (*aptr++, 2);
   
   dptr = aptr;
   pktlen = pktlen -ICV_LEN_SHA256;
   COP2_PARALLEL_AES_DEC_SHA256(dptr,rptr,dlen);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Get the inner hash of HMAC */
   CVMX_M32BF_HSH_IV(inner_sha);

   /* Initialize hash unit */
   CVMX_M32BT_HSH_IV(sha256defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));


   CVMX_M64BT_HSH_DAT_SHA256_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_M16BF_HSH_IV(sha1);
   
   /* compare first 128 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, sha1, ICV_LEN_SHA256)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA256;i++)
            printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA256;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
   } else if(outptr)
      memcpy(outptr+pktlen, sha1, ICV_LEN_SHA256);
   if(outlen)
      *outlen = pktlen;
   return 0;
}

int AES_ctr_sha256_encrypt(uint64_t *aes_key, uint32_t aes_key_len, uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr;
   register uint64_t in1,in2,out1,out2;
   register int sha1_next;
   uint64_t sha1[4];

   uint32_t dlen;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_sha[4];
   cntrblk_t cntrblk;
   uint64_t enc_cntrblk[2];
   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      aes_key == NULL || aes_iv == NULL || sha1_key == NULL || 
      sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-AES_CTR_IV_LENGTH-ICV_LEN_SHA256)) {
      printf("Packet is too big to handle \n");
      return -1;
   } 
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);
   memset(sha_key,0x0,64);
   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 2)<0) {  
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 32;
   } else
     memcpy(sha_key,sha1_key,sha1_keylen);
   aes_key_len =aes_key_len *8;  
   cntrblk.blk[0] = 0;
   cntrblk.blk[1] = 0;
   cntrblk.s.nonce = nonce;
   for(i = 0; i < AES_CTR_IV_LENGTH; i++)
      cntrblk.s.aes_iv[i] = aes_iv[i];
   cntrblk.s.counter = 1;

   in1=cntrblk.blk[0];
   in2=cntrblk.blk[1];
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 256) {
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);


   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (sha256defiv[0], 0);
   CVMX_MT_HSH_IV (sha256defiv[1], 1);
   CVMX_MT_HSH_IV (sha256defiv[2], 2);
   CVMX_MT_HSH_IV (sha256defiv[3], 3);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad));
   aptr =(uint64_t *)espheader;
   CVMX_MT_HSH_DAT (*aptr,0);
   aptr =(uint64_t *)aes_iv;
   CVMX_MT_HSH_DAT (*aptr,1);
   /* Copy header & setup enc/hmac args */

   dptr = (uint64_t *) pktptr ;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen ;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)aes_iv)[0];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
   } else
      rptr=(uint64_t *)pktptr;
   aptr=rptr;
   /* Start encryption */

   COP2_PARALLEL_128BN_AES_CTR_ENC_SHA256(dptr,rptr,dlen);

   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA256_STEP(2,3);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA256_STEP(4,5);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA256_STEP(6,7);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA256_STEP(0,1);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA256_STEP(2,3);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA256_STEP(4,5);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA256_STEP(6,7);

   sha1_next = (((pktlen+16) % 64)/16) * 2;

   /* Loop through input */
   if(dlen) {
      uint32_t i;
      CVMX_MT_AES_ENC0(in1);
      CVMX_MT_AES_ENC1(in2);
      CVMX_MF_AES_RESULT (enc_cntrblk[0], 0);
      CVMX_MF_AES_RESULT (enc_cntrblk[1], 1);
      for(i=0;i<dlen;i++)
         ((uint8_t *)rptr)[i]=((uint8_t *)dptr)[i]^((uint8_t *)enc_cntrblk)[i];
   }
   /* Finish inner hash */
   {
      int chunk_len=(pktlen+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH) %64;
      uint8_t i=0;
      uint8_t chunk[100];
      if(chunk_len >= 56) {
         chunk_len = 72;
         chunk_len += (dlen/8)*8;
      } else {
         chunk_len = 64-chunk_len;
         chunk_len+=dlen;
      }
      memset(chunk,0x0, chunk_len);
      if(dlen) {
         memcpy(chunk,(uint8_t *)rptr,dlen);
         rptr=(uint64_t *)((uint8_t *)rptr+dlen);
         *(chunk+dlen)=0x80;
      } else
         chunk[0]= 0x80;
      *((uint64_t *)(chunk + chunk_len -8)) = (pktlen+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH+64) * 8;
       i=0;
      while ( i< chunk_len) {
         _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), sha1_next, 2);
          i += 8;
      }
   } 

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_sha[0], 0);
   CVMX_MF_HSH_IV (inner_sha[1], 1);
   CVMX_MF_HSH_IV (inner_sha[2], 2);
   CVMX_MF_HSH_IV (inner_sha[3], 3);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (sha256defiv[0], 0);
   CVMX_MT_HSH_IV (sha256defiv[1], 1);
   CVMX_MT_HSH_IV (sha256defiv[2], 2);
   CVMX_MT_HSH_IV (sha256defiv[3], 3);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));

   CVMX_M64BT_HSH_DAT_SHA256_HMAC(inner_sha);
   /* Get the HMAC */
   CVMX_MF_HSH_IV (sha1[0], 0);
   CVMX_MF_HSH_IV (sha1[1], 1);
   /* put HMac at the end of the packet */
   memcpy(rptr, sha1, ICV_LEN_SHA256);
   if(outlen) {   
      if(outptr)
         *outlen = (pktlen+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH+ICV_LEN_SHA256);
      else
         *outlen = (pktlen+ICV_LEN_SHA256);
   }
   return 0;
}


int AES_ctr_sha256_decrypt(uint64_t *aes_key, uint32_t aes_key_len, uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   register uint64_t in1,in2,out1,out2;
   register int sha1_next;
   uint64_t sha1[4];
   uint32_t dlen;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_sha[4];
   cntrblk_t cntrblk;
   uint64_t enc_cntrblk[2];
   if(pktptr == NULL ||  pktlen == 0  || aes_key == NULL || 
      aes_iv == NULL || sha1_key == NULL || sha1_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +AES_CTR_IV_LENGTH+ICV_LEN_SHA256+1)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   memset(sha_key,0x0,64);
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);
   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 2)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 32;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);
   aes_key_len = aes_key_len * 8;
   cntrblk.blk[0] = 0;
   cntrblk.blk[1] = 0;
   cntrblk.s.nonce = nonce;
   for(i = 0; i < AES_CTR_IV_LENGTH; i++)
      cntrblk.s.aes_iv[i] = aes_iv[i];
   cntrblk.s.counter = 1;

   in1=cntrblk.blk[0];
   in2=cntrblk.blk[1];
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY (0x0ULL, 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (0x0, 3);
   } else if(aes_key_len == 256) {
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (sha256defiv[0], 0);
   CVMX_MT_HSH_IV (sha256defiv[1], 1);
   CVMX_MT_HSH_IV (sha256defiv[2], 2);
   CVMX_MT_HSH_IV (sha256defiv[3], 3);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad));
   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr;
   CVMX_PREFETCH0(aptr);
   dptr = (uint64_t *) (pktptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH) ;
   dlen = pktlen - ESP_HEADER_LENGTH- AES_CTR_IV_LENGTH- ICV_LEN_SHA256;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
   } else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
    
   /* load esp header and iv to hash unit */
   CVMX_MT_HSH_DAT (*aptr++, 0);
   CVMX_MT_HSH_DAT (*aptr++, 1);

   sha1_next = (((dlen + 16) % 64) / 16) * 2;
   
   while(dlen >= 128)
   {
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(2,3);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(4,5);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(6,7);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(0,1);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(2,3);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(4,5);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(6,7);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(0,1);
   }

   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(2,3);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(4,5);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(6,7);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(0,1);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(2,3);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(4,5);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(6,7);

   aptr = dptr;

   pktlen = pktlen -ICV_LEN_SHA256;
   /* Finish Inner hash */
   {
      int chunk_len=pktlen %64;
      uint8_t i=0;
      uint8_t chunk[100];
      if(chunk_len >= 56) {
         chunk_len = 72;
         chunk_len += (dlen/8)*8;
      } else {
         chunk_len = 64-chunk_len;
          chunk_len+=dlen;
      }
      memset(chunk,0x0, chunk_len);
      if(dlen) {
         memcpy(chunk,(uint8_t *)dptr,dlen);
         *(chunk+dlen)=0x80;
         CVMX_MT_AES_ENC0 (in1);
         CVMX_MT_AES_ENC1 (in2);
         CVMX_MF_AES_RESULT (enc_cntrblk[0], 0);
         CVMX_MF_AES_RESULT (enc_cntrblk[1], 1);
         for(i=0;i<dlen;i++)
            ((uint8_t *)rptr)[i]=((uint8_t *)dptr)[i] ^((uint8_t *)enc_cntrblk)[i];
      } else
         chunk[0]= 0x80;
      *((uint64_t *)(chunk + chunk_len -8)) = (pktlen+ 64) * 8;
      i=0;
      while ( i< chunk_len) {
      _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), sha1_next, 2);
       i += 8;
      }
   } 

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_sha[0], 0);
   CVMX_MF_HSH_IV (inner_sha[1], 1);
   CVMX_MF_HSH_IV (inner_sha[2], 2);
   CVMX_MF_HSH_IV (inner_sha[3], 3);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (sha256defiv[0], 0);
   CVMX_MT_HSH_IV (sha256defiv[1], 1);
   CVMX_MT_HSH_IV (sha256defiv[2], 2);
   CVMX_MT_HSH_IV (sha256defiv[3], 3);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));

   CVMX_M64BT_HSH_DAT_SHA256_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_MF_HSH_IV (sha1[0], 0);
   CVMX_MF_HSH_IV (sha1[1], 1);
   
   /* compare first 128 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, sha1, ICV_LEN_SHA256)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA256;i++)
            printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA256;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
   } else
      if(outptr)
          memcpy(outptr+pktlen, sha1, ICV_LEN_SHA256);

    *outlen=pktlen;
    return 0;
}


int DES_ede3_cbc_sha512_encrypt(uint8_t *des_key, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr;
   uint32_t dlen;
   uint64_t sha1[8];
 
   uint8_t sha_key[128];
   uint64_t inner_sha[8];
   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      des_key == NULL || des_iv == NULL || sha1_key == NULL 
      || sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if((pktlen < 8) || (pktlen%8)) {
      printf(" packetlen is not proper \n");
      return -1;
   }
   if( pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-DES_CBC_IV_LENGTH-ICV_LEN_SHA512)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   CVMX_PREFETCH0(des_key);
   CVMX_PREFETCH0(des_iv);
   
   MEMSET128BTZ(sha_key);

   if(sha1_keylen > 128) {
      if(hash_key_sha512(sha1_key, sha1_keylen, sha_key, 1)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 64;
   } else {
      if(sha1_keylen == 64) {
        MEMCPY64B(sha_key,sha1_key);
      } else {
        memcpy(sha_key,sha1_key,sha1_keylen);
      }
   }


   /* load 3DES Key */
   CVMX_M24BT_3DES_KEY(((uint64_t*)des_key));
   CVMX_MT_3DES_IV (*((uint64_t *)des_iv));

   /* Load SHA1 IV */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512 ((*aptr++ ^ ipad));
   
   aptr =(uint64_t *)espheader;
   CVMX_MT_HSH_DATW (*aptr, 0);
   aptr =(uint64_t *)des_iv;
   CVMX_MT_HSH_DATW (*aptr, 1);
   
   /* Copy header & setup enc/hmac args */
   dptr = (uint64_t *)pktptr ;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen ;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)des_iv)[0];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   } else
      rptr= (uint64_t *)pktptr;
   aptr =rptr;
    

   COP2_PARALLEL_3DES_ENC_SHA512(dptr, rptr, dlen);
   CVMX_MF_3DES_IV(*(uint64_t*)des_iv);

   CVMX_M64BF_HSH_IVW(inner_sha);
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512 ((*aptr++ ^ opad));

   CVMX_M128BT_HSH_DATW_SHA512_HMAC(inner_sha);


   /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha1[0], 0);
   CVMX_MF_HSH_IVW (sha1[1], 1);
   CVMX_MF_HSH_IVW (sha1[2], 2);
   CVMX_MF_HSH_IVW (sha1[3], 3);
   
   /* put HMac at the end of the packet */
   memcpy(rptr, sha1, ICV_LEN_SHA512);
   if(outlen) {
     *outlen = outptr ? (pktlen+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH+ICV_LEN_SHA512) : (pktlen+ICV_LEN_SHA512);
   }
    return 0;
}


int DES_ede3_cbc_sha512_decrypt(uint8_t *des_key, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen,uint8_t *outptr, uint16_t *outlen,uint8_t compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   uint32_t dlen;
   uint64_t sha1[8];

   uint32_t i;
   uint8_t sha_key[128];
   uint64_t inner_sha[8];
   if(pktptr == NULL || pktlen == 0  || des_key == NULL || 
      des_iv == NULL || sha1_key == NULL || sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +DES_CBC_IV_LENGTH+ICV_LEN_SHA512+8)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   CVMX_PREFETCH0(des_key);
   CVMX_PREFETCH0(des_iv);
   //memset(sha_key,0x0,128);
   MEMSET128BTZ(sha_key);
   if(sha1_keylen > 128) {
      if(hash_key_sha512(sha1_key, sha1_keylen, sha_key, 1)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 64;
   } else {
      if(sha1_keylen == 64)
	{
		MEMCPY64B(sha_key,sha1_key);
	}
      else
      memcpy(sha_key,sha1_key,sha1_keylen);
   }


   CVMX_M24BT_3DES_KEY(((uint64_t*)des_key));
   CVMX_MT_3DES_IV (*((uint64_t *)des_iv));

   /* Load SHA1 IV */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512(*aptr++ ^ ipad);


   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   CVMX_PREFETCH0(aptr);
   CVMX_SYNCW;
   dptr = (uint64_t *)(pktptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   dlen = pktlen -ESP_HEADER_LENGTH-DES_CBC_IV_LENGTH- ICV_LEN_SHA512;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   } else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);

   /* load esp header and iv to hash unit*/
   CVMX_MT_HSH_DATW (*aptr++, 0);
   CVMX_MT_HSH_DATW (*aptr++, 1);

   dptr = aptr;
   pktlen = pktlen - ICV_LEN_SHA512;
   COP2_PARALLEL_3DES_DEC_SHA512(dptr, rptr, dlen);
   CVMX_MF_3DES_IV(*(uint64_t*)des_iv);

   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512(*aptr++ ^ opad);


   CVMX_M128BT_HSH_DATW_SHA512_HMAC(inner_sha);



   /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha1[0], 0);
   CVMX_MF_HSH_IVW (sha1[1], 1);
   CVMX_MF_HSH_IVW (sha1[2], 2);
   CVMX_MF_HSH_IVW (sha1[3], 3);

   /* compare first 256 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, sha1, ICV_LEN_SHA512)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA512;i++)
            printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA512;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
   } else if(outptr)
      memcpy(outptr+pktlen, sha1, ICV_LEN_SHA512);
    
   *outlen=pktlen;
   return 0;
}


int AES_cbc_sha512_encrypt(uint16_t aes_key_len, uint8_t *aes_key,  uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t sha1[8];
   uint32_t dlen;
   
   uint8_t sha_key[128];
   uint64_t inner_sha[8];

   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      aes_key == NULL || aes_iv == NULL || sha1_key == NULL || 
      sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }

   if((pktlen < 16) || (pktlen%16)) {
      printf(" packetlen is not proper \n");
      return -1;
   }

   if( pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-AES_CBC_IV_LENGTH-ICV_LEN_SHA512)) {
      printf("Packet is too big to handle \n");
      return -1;
   }

   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);

   MEMSET128BTZ(sha_key);

   if(sha1_keylen > 128) {
      if(hash_key_sha512(sha1_key, sha1_keylen, sha_key,1)<0) {
         printf(" improper mac secret \n");   
         return -1;
   }
      sha1_keylen = 64;
   } else {
      if(sha1_keylen == 64) 
      {
        MEMCPY64B(sha_key,sha1_key);
      } else {
        memcpy(sha_key,sha1_key,sha1_keylen);
      }
   }


   aes_key_len= aes_key_len *8;  
   
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 256) {
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
         return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Load SHA1 IV */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ ipad));

   aptr =(uint64_t *)espheader;
   CVMX_MT_HSH_DATW (*aptr, 0);
   aptr =(uint64_t *)aes_iv;
   CVMX_MT_HSH_DATW (aptr[0], 1);
   CVMX_MT_HSH_DATW (aptr[1], 2);

   /* Copy header & setup enc/hmac args */
   dptr = (uint64_t *) pktptr;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen ;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)aes_iv)[0];
      ((uint64_t *)outptr)[2]=((uint64_t *)aes_iv)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
      aptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
   } else {
      rptr= (uint64_t *)pktptr;
      aptr= (uint64_t *)pktptr;
   }
  

   COP2_PARALLEL_AES_ENC_SHA512(dptr,rptr,dlen);
   
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ opad));

   CVMX_M128BT_HSH_DATW_SHA512_HMAC(inner_sha);
   
  /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha1[0], 0);
   CVMX_MF_HSH_IVW (sha1[1], 1);
   CVMX_MF_HSH_IVW (sha1[2], 2);
   CVMX_MF_HSH_IVW (sha1[3], 3);
   
  /* put HMac at the end of the packet */
   memcpy(rptr, sha1, ICV_LEN_SHA512);
   if(outlen) {
      if(outptr)
         *outlen = pktlen +ESP_HEADER_LENGTH +AES_CBC_IV_LENGTH+ICV_LEN_SHA512;
      else
         *outlen = pktlen +ICV_LEN_SHA512;
   }
   return 0;
}


int AES_cbc_sha512_decrypt(uint16_t aes_key_len, uint8_t *aes_key, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t sha1[8];
   uint32_t dlen;
   int i;
   uint8_t sha_key[128];
   uint64_t inner_sha[8];
   if(pktptr == NULL  || pktlen == 0  || aes_key == NULL || 
      aes_iv == NULL || sha1_key == NULL || sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +AES_CBC_IV_LENGTH+ICV_LEN_SHA512+16)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);
   memset(sha_key,0x0,128);
   if(sha1_keylen > 128) {
      if(hash_key_sha512(sha1_key, sha1_keylen, sha_key,1)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 64;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);
   aes_key_len = aes_key_len * 8;
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY (0x0ULL, 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 256) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Load SHA1 IV */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;

   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ ipad));
   
   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   CVMX_PREFETCH0(aptr);
   dptr = (uint64_t *) (pktptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
   dlen = pktlen - ESP_HEADER_LENGTH- AES_CBC_IV_LENGTH-ICV_LEN_SHA512;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      ((uint64_t *)outptr)[2]=((uint64_t *)pktptr)[2];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
   }
   else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);

   /* load esp header and IV to hash unit */
   CVMX_MT_HSH_DATW (*aptr++, 0);
   CVMX_MT_HSH_DATW (*aptr++, 1);
   CVMX_MT_HSH_DATW (*aptr++, 2);

   dptr = aptr;
   pktlen = pktlen - ICV_LEN_SHA512;
   COP2_PARALLEL_AES_DEC_SHA512(dptr,rptr,dlen);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   
   CVMX_M128BT_HSH_DATW_SHA512 ((*aptr++ ^ opad));

   CVMX_M128BT_HSH_DATW_SHA512_HMAC(inner_sha);  


   /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha1[0], 0);
   CVMX_MF_HSH_IVW (sha1[1], 1);
   CVMX_MF_HSH_IVW (sha1[2], 2);
   CVMX_MF_HSH_IVW (sha1[3], 3);

   /* compare first 256 bits of HMAC with received mac */
   if(compdigest) {
        if(memcmp(pktptr+pktlen, sha1, ICV_LEN_SHA512)) {
          printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA512;i++)
              printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA512;i++)
              printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }   
   } else if(outptr)
        memcpy(outptr+pktlen, sha1, ICV_LEN_SHA512);
        
   *outlen=pktlen;
   return 0;
}

int AES_ctr_sha512_encrypt(uint64_t *aes_key, uint32_t aes_key_len, uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *aes_iv,  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr;
   register uint64_t in1,in2,out1,out2;
   uint64_t sha1[8];
   uint32_t dlen;
   register int sha1_next;
   uint32_t i;
   uint8_t sha_key[128];
   uint64_t inner_sha[8];
   cntrblk_t cntrblk;
   uint64_t enc_cntrblk[2];
   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      aes_key == NULL || aes_iv == NULL || sha1_key == NULL || 
      sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if( pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-AES_CTR_IV_LENGTH-ICV_LEN_SHA512)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);
   memset(sha_key,0x0,128);
   if(sha1_keylen > 128) {
      if(hash_key_sha512(sha1_key, sha1_keylen, sha_key,1)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
   sha1_keylen = 64;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);
   aes_key_len = aes_key_len * 8;
   cntrblk.blk[0] = 0;
   cntrblk.blk[1] = 0;
   cntrblk.s.nonce = nonce;
   for(i = 0; i < AES_CTR_IV_LENGTH; i++)
      cntrblk.s.aes_iv[i] = aes_iv[i];
   cntrblk.s.counter = 1;

   in1=cntrblk.blk[0];
   in2=cntrblk.blk[1];
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY (0x0ULL, 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 256) {
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   /* Load SHA1 IV */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ ipad));
   aptr = (uint64_t *) espheader;
   CVMX_MT_HSH_DATW (*aptr++, 0);
   aptr = (uint64_t *) aes_iv;
   CVMX_MT_HSH_DATW (*aptr++, 1);



   /* Copy header & setup enc/hmac args */
   dptr = (uint64_t *)pktptr;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)aes_iv)[0];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
   } else
      rptr =(uint64_t *)pktptr;


   sha1_next = (((dlen + 16) % 128) / 16) * 2;
   COP2_PARALLEL_128BN_AES_CTR_ENC_SHA512(dptr,rptr,dlen);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA512_STEP(2,3); 
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA512_STEP(4,5); 
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA512_STEP(6,7); 
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA512_STEP(8,9); 
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA512_STEP(10,11); 
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA512_STEP(12,13); 
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA512_STEP(14,15); 

   aptr = rptr;
   
   if(dlen) {
      uint32_t i;
      CVMX_MT_AES_ENC0(in1);
      CVMX_MT_AES_ENC1(in2);
      CVMX_MF_AES_RESULT (enc_cntrblk[0], 0);
      CVMX_MF_AES_RESULT (enc_cntrblk[1], 1);
      for(i=0;i<dlen;i++)
         ((uint8_t *)rptr)[i]=((uint8_t *)dptr)[i]^((uint8_t *)enc_cntrblk)[i];
   }
   /* Finish inner hash */
   {
      int chunk_len=(pktlen+ ESP_HEADER_LENGTH+ AES_CTR_IV_LENGTH) %128;
      uint8_t i=0;
      uint8_t chunk[200];
      if(chunk_len >= 112 && chunk_len < 120) {
         chunk_len = 144;
         chunk_len+=(dlen/8)*8;
      } else if(chunk_len >=120) {
         chunk_len=136;
         chunk_len+=(dlen/8)*8;
      }
      else {
         chunk_len = 128-chunk_len;
         chunk_len += dlen;
      }
      memset(chunk,0x0, chunk_len);
      if(dlen) {
         memcpy(chunk,(uint8_t *)rptr,dlen);
         *(chunk+dlen)=0x80;
         rptr =(uint64_t *)((uint8_t *)rptr+dlen);
       } else
         chunk[0]= 0x80;
      uint64_t_mul (((uint64_t *)(chunk+chunk_len-16))[0],((uint64_t *)(chunk+chunk_len-16))[1], (pktlen+ESP_HEADER_LENGTH + AES_CTR_IV_LENGTH+ 128), 0x8ull);
      i=0;
      while ( i< chunk_len) {
         _CVMX_MT_HSH_DATW (*((uint64_t *)(chunk+i)), sha1_next);
          i += 8;
      }
   } 

   CVMX_M64BF_HSH_IVW(inner_sha);


   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ opad));

   CVMX_M128BT_HSH_DATW_SHA512_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha1[0], 0);
   CVMX_MF_HSH_IVW (sha1[1], 1);
   CVMX_MF_HSH_IVW (sha1[2], 2);
   CVMX_MF_HSH_IVW (sha1[3], 3);

   /* put HMac at the end of the packet */
   memcpy(rptr, sha1, 32);
   if(outlen) {
      if(outptr)
         *outlen = pktlen+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH+ICV_LEN_SHA512;
      else
         *outlen = pktlen+ICV_LEN_SHA512;
   }
   return 0;
}

int AES_ctr_sha512_decrypt(uint64_t *aes_key, uint32_t aes_key_len, uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv,  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   register uint64_t in1,in2,out1,out2;
   uint64_t sha1[8]; 
   uint32_t dlen, sha1_next;
   uint32_t i;
   uint8_t sha_key[128];
   uint64_t inner_sha[8];
   cntrblk_t cntrblk;
   uint64_t enc_cntrblk[2];
   if(pktptr == NULL ||  pktlen == 0  || aes_key == NULL || 
   aes_iv == NULL || sha1_key == NULL || sha1_keylen ==0||outlen==NULL ) {
   printf("\n Wrong parameters \n");   
   return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +AES_CTR_IV_LENGTH+ICV_LEN_SHA512+1)) {
      printf("Packet length is not proper \n");
      return -1;
     }
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);
   memset(sha_key,0x0,128);
   if(sha1_keylen > 128) {
      if(hash_key_sha512(sha1_key, sha1_keylen, sha_key, 1)<0)   {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 64;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);
   aes_key_len = aes_key_len * 8;
   cntrblk.blk[0] = 0;
   cntrblk.blk[1] = 0;
   cntrblk.s.nonce = nonce;
   for(i = 0; i < AES_CTR_IV_LENGTH; i++)
      cntrblk.s.aes_iv[i] = aes_iv[i];
   cntrblk.s.counter = 1;

   in1=cntrblk.blk[0];
   in2=cntrblk.blk[1];
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY (0x0ULL, 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 256) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   /* Load SHA1 IV */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ ipad));

   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr;
   CVMX_PREFETCH0(aptr);
   dptr = (uint64_t *) (pktptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH) ;
   dlen = pktlen - ESP_HEADER_LENGTH - AES_CTR_IV_LENGTH -ICV_LEN_SHA512;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
   } else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);

   /* load esp header and iv to hash unit */    
   CVMX_MT_HSH_DATW (*aptr++, 0);
   CVMX_MT_HSH_DATW (*aptr++, 1);

    
   /* Loop through input */
   sha1_next = (((dlen + 16) % 128) / 16) * 2;
   while(dlen >= 128)
   {
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(2,3);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(4,5);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(6,7);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(8,9);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(10,11);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(12,13);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(14,15);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(0,1);
   }


   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(2,3);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(4,5);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(6,7);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(8,9);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(10,11);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(12,13);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(14,15);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(0,1);

   pktlen = pktlen -ICV_LEN_SHA512;
   /* Finish Inner hash */
   {
      int chunk_len=pktlen %128;
      uint8_t i=0;
      uint8_t chunk[200];
      if(chunk_len >= 112 && chunk_len < 120) {
         chunk_len = 144;
         chunk_len+=(dlen/8)*8;
      } else if(chunk_len >=120){
         chunk_len=136;
         chunk_len+=(dlen/8)*8;
      } else {
         chunk_len = 128-chunk_len;
         chunk_len += dlen;
      }
      memset(chunk,0x0, chunk_len);
      if(dlen) {
         memcpy(chunk,(uint8_t *)dptr,dlen);
         *(chunk+dlen)=0x80;
         CVMX_MT_AES_ENC0 (in1);
         CVMX_MT_AES_ENC1 (in2);
         CVMX_MF_AES_RESULT (enc_cntrblk[0], 0);
         CVMX_MF_AES_RESULT (enc_cntrblk[1], 1);
         for(i=0;i<dlen;i++)
            ((uint8_t *)rptr)[i]=((uint8_t *)dptr)[i] ^((uint8_t *)enc_cntrblk)[i];
      } else
         chunk[0]= 0x80;
      uint64_t_mul (((uint64_t *)(chunk+chunk_len-16))[0],((uint64_t *)(chunk+chunk_len-16))[1], (pktlen+128), 0x8ull);
        i=0;
      while ( i< chunk_len) {
         _CVMX_MT_HSH_DATW (*((uint64_t *)(chunk+i)), sha1_next);
          i += 8;
      }
   } 

   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha512defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ opad));

   CVMX_M128BT_HSH_DATW_SHA512_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha1[0], 0);
   CVMX_MF_HSH_IVW (sha1[1], 1);
   CVMX_MF_HSH_IVW (sha1[2], 2);
   CVMX_MF_HSH_IVW (sha1[3], 3);
   
   /* compare first 256 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, sha1, ICV_LEN_SHA512)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA512;i++)
            printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA512;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
   } else if(outptr)
       memcpy(outptr+pktlen, sha1, ICV_LEN_SHA512);
        
   *outlen=pktlen;
   return 0;
}

int DES_ede3_cbc_sha224_encrypt(uint8_t *des_key, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t sha1[4];
   uint32_t dlen;
   uint8_t sha_key[64];
   uint64_t inner_sha[4];
   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
   des_key == NULL || des_iv == NULL || sha1_key == NULL || 
   sha1_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
    }
   if((pktlen < 8) || (pktlen%8)) {
      printf(" packetlen is not proper \n");
      return -1;
   }
   if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-DES_CBC_IV_LENGTH-ICV_LEN_SHA224)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   CVMX_PREFETCH0(des_key);
   CVMX_PREFETCH0(des_iv);

   MEMSET64BTZ(sha_key);

   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 3)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
   sha1_keylen = 32;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);
   /* load 3DES Key */
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[0], 0);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[1], 1);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[2], 2);

   CVMX_MT_3DES_IV (*((uint64_t *)des_iv));

   /* Load SHA1 IV */
   CVMX_M32BT_HSH_IV(sha224defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad));

   aptr = (uint64_t *) espheader;
   CVMX_MT_HSH_DAT (*aptr, 0);
   aptr = (uint64_t *) des_iv;
   CVMX_MT_HSH_DAT (*aptr, 1);
   /* Copy header & setup enc/hmac args */
   dptr = (uint64_t *) pktptr;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *) espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *) des_iv)[0];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   } else
      rptr = (uint64_t *)pktptr;
   aptr = rptr;

   COP2_PARALLEL_3DES_ENC_SHA256(dptr,rptr,dlen);
   CVMX_MF_3DES_IV (*((uint64_t *)des_iv));

   /* Get the inner hash of HMAC */
   CVMX_M32BF_HSH_IV(inner_sha);

   /* Initialize hash unit */
   CVMX_M32BT_HSH_IV(sha224defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));

   CVMX_M64BT_HSH_DAT_SHA224_HMAC(inner_sha);
    
   /* Get the HMAC */
   CVMX_M16BF_HSH_IV (sha1);

   /* put HMac at the end of the packet */
   memcpy(rptr, sha1, ICV_LEN_SHA224);
   if(outlen) {
      if(outptr)
         *outlen =pktlen+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH+ICV_LEN_SHA224;
      else
         *outlen =pktlen+ICV_LEN_SHA224;
   }
   return 0;
}


int DES_ede3_cbc_sha224_decrypt(uint8_t *des_key, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen,uint8_t *outptr, uint16_t *outlen,uint8_t compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t sha1[4];
   uint32_t dlen;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_sha[4];
   if(pktptr == NULL ||  pktlen == 0  || des_key == NULL || 
      des_iv == NULL || sha1_key == NULL || sha1_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +DES_CBC_IV_LENGTH+ICV_LEN_SHA224+8)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   CVMX_PREFETCH0(des_key);
   CVMX_PREFETCH0(des_iv);
   memset(sha_key,0x0,64);
   if(sha1_keylen > 64)   {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 3)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 32;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);

   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[0], 0);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[1], 1);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[2], 2);

   CVMX_MT_3DES_IV (*((uint64_t *)des_iv));

   /* Load SHA1 IV */
   CVMX_M32BT_HSH_IV(sha224defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad));

   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   CVMX_PREFETCH0(aptr);
   dptr = (uint64_t *) (pktptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   dlen = pktlen -ESP_HEADER_LENGTH-DES_CBC_IV_LENGTH-ICV_LEN_SHA224;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *) pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *) pktptr)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   } else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   /* load esp header and iv to hash unit */
   CVMX_MT_HSH_DAT (*aptr++, 0);
   CVMX_MT_HSH_DAT (*aptr++, 1);

   pktlen = pktlen - ICV_LEN_SHA224;
   dptr = aptr;
   COP2_PARALLEL_3DES_DEC_SHA256(dptr,rptr,dlen);
   CVMX_MF_3DES_IV (*((uint64_t *)des_iv));

   /* Get the inner hash of HMAC */
   CVMX_M32BF_HSH_IV(inner_sha);

   /* Initialize hash unit */
   CVMX_M32BT_HSH_IV(sha224defiv);

   /* Load key xor opad */
   
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));

   CVMX_M64BT_HSH_DAT_SHA224_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_M16BF_HSH_IV(sha1);
   
   /* compare first 128 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, sha1, ICV_LEN_SHA224)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA224;i++)
            printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA224;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
   } else if(outptr)
      memcpy(outptr+pktlen, sha1, ICV_LEN_SHA224);
  
   if(outlen)
      *outlen = pktlen;
   return 0;
}



int AES_cbc_sha224_encrypt(uint16_t aes_key_len, uint8_t *aes_key,  uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t sha1[4];
   uint32_t dlen;
   uint8_t sha_key[64];
   uint64_t inner_sha[4];
    
   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      aes_key == NULL || aes_iv == NULL || sha1_key == NULL || 
      sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
    }
   if((pktlen < 16) || (pktlen%16)) {
      printf(" packetlen is not proper \n");
      return -1;
   }
   if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-AES_CBC_IV_LENGTH-ICV_LEN_SHA224)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);

   MEMSET64BTZ(sha_key);

   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 3)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 32;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);
   aes_key_len = aes_key_len *8; 
   
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY (0x0ULL, 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 256) {
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Load SHA1 IV */
   CVMX_M32BT_HSH_IV(sha224defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad)); 

   /* load Esp header and iv */
   aptr =(uint64_t *)espheader;
   CVMX_MT_HSH_DAT (*aptr, 0);
   aptr =(uint64_t *)aes_iv;
   CVMX_MT_HSH_DAT (aptr[0], 1);
   CVMX_MT_HSH_DAT (aptr[1], 2);

   /* Copy header & setup enc/hmac args */
   dptr = (uint64_t *) pktptr;
   CVMX_PREFETCH0(dptr);

   dlen = pktlen;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)aes_iv)[0];
      ((uint64_t *)outptr)[2]=((uint64_t *)aes_iv)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
   } else
      rptr =(uint64_t *)pktptr;
   aptr =rptr;

   /* Start encryption */
   COP2_PARALLEL_AES_ENC_SHA256(dptr,rptr,dlen);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Get the inner hash of HMAC */
   CVMX_M32BF_HSH_IV(inner_sha);

   /* Initialize hash unit */
   CVMX_M32BT_HSH_IV(sha224defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));

   CVMX_M64BT_HSH_DAT_SHA224_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_M16BF_HSH_IV(sha1);
   
   /* put HMac at the end of the packet */
   memcpy(rptr, sha1, ICV_LEN_SHA224);
   if(outlen) {
      if(outptr)
         *outlen = (pktlen + ESP_HEADER_LENGTH +AES_CBC_IV_LENGTH +ICV_LEN_SHA224);
      else
         *outlen = (pktlen + ICV_LEN_SHA224);
   }
   return 0;
}




int AES_cbc_sha224_decrypt(uint16_t aes_key_len, uint8_t *aes_key, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t sha1[4];
   uint32_t dlen;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_sha[4];
   if(pktptr == NULL || pktlen == 0  || aes_key == NULL || 
      aes_iv == NULL || sha1_key == NULL || sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +AES_CBC_IV_LENGTH+ICV_LEN_SHA224+16)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   memset(sha_key,0x0,64);
   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 3)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 32;
   } else
   memcpy(sha_key,sha1_key,sha1_keylen);
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);
   aes_key_len = aes_key_len * 8;
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY (0x0ULL, 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 256) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Load SHA1 IV */
   CVMX_M32BT_HSH_IV(sha224defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad));

   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   CVMX_PREFETCH0(aptr);
   dptr = (uint64_t *) (pktptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH) ;
   dlen = pktlen - ESP_HEADER_LENGTH- AES_CBC_IV_LENGTH- ICV_LEN_SHA224;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      ((uint64_t *)outptr)[2]=((uint64_t *)pktptr)[2];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
   } else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
    
   /* load esp header and iv to hash unit */
   CVMX_MT_HSH_DAT (*aptr++, 0);
   CVMX_MT_HSH_DAT (*aptr++, 1);
   CVMX_MT_HSH_DAT (*aptr++, 2);
   
   dptr = aptr;
   pktlen = pktlen - 16;
   COP2_PARALLEL_AES_DEC_SHA256(dptr,rptr,dlen);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Get the inner hash of HMAC */
   CVMX_M32BF_HSH_IV(inner_sha);

   /* Initialize hash unit */
   CVMX_M32BT_HSH_IV(sha224defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));


   CVMX_M64BT_HSH_DAT_SHA224_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_M16BF_HSH_IV(sha1);
   
   /* compare first 128 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, sha1, ICV_LEN_SHA224)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA224;i++)
            printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA224;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
   } else if(outptr)
      memcpy(outptr+pktlen, sha1, ICV_LEN_SHA224);
   if(outlen)
      *outlen = pktlen;
   return 0;
}



int AES_ctr_sha224_encrypt(uint64_t *aes_key, uint32_t aes_key_len, uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr;
   register uint64_t in1,in2,out1,out2;
   register int sha1_next;
   uint64_t sha1[4];
   uint32_t dlen;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_sha[4];
   cntrblk_t cntrblk;
   uint64_t enc_cntrblk[2];
   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      aes_key == NULL || aes_iv == NULL || sha1_key == NULL || 
      sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if( pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-AES_CTR_IV_LENGTH-ICV_LEN_SHA224)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);
   memset(sha_key,0x0,64);
   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 3)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 28;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);
   aes_key_len =aes_key_len *8;  
   cntrblk.blk[0] = 0;
   cntrblk.blk[1] = 0;
   cntrblk.s.nonce = nonce;
   for(i = 0; i < AES_CTR_IV_LENGTH; i++)
      cntrblk.s.aes_iv[i] = aes_iv[i];
   cntrblk.s.counter = 1;

   in1=cntrblk.blk[0];
   in2=cntrblk.blk[1];
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY (0x0ULL, 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 256) {
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
        printf(" Improper Key length \n");
        return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);


   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (sha224defiv[0], 0);
   CVMX_MT_HSH_IV (sha224defiv[1], 1);
   CVMX_MT_HSH_IV (sha224defiv[2], 2);
   CVMX_MT_HSH_IV (sha224defiv[3], 3);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad));
   
   aptr =(uint64_t *)espheader;
   CVMX_MT_HSH_DAT (*aptr,0);
   aptr =(uint64_t *)aes_iv;
   CVMX_MT_HSH_DAT (*aptr,1);
   sha1_next = 2;
   /* Copy header & setup enc/hmac args */

   dptr = (uint64_t *) pktptr ;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen ;
   if(outptr != NULL) {
        ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)aes_iv)[0];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
   } else
      rptr=(uint64_t *)pktptr;
   aptr=rptr;
   /* Start encryption */

   COP2_PARALLEL_128BN_AES_CTR_ENC_SHA256(dptr,rptr,dlen);

   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA256_STEP(2,3);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA256_STEP(4,5);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA256_STEP(6,7);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA256_STEP(0,1);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA256_STEP(2,3);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA256_STEP(4,5);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA256_STEP(6,7);

   sha1_next = (((pktlen+16) % 64)/16) * 2;


   /* Loop through input */
   if(dlen) {
      uint32_t i;
      CVMX_MT_AES_ENC0(in1);
      CVMX_MT_AES_ENC1(in2);
      CVMX_MF_AES_RESULT (enc_cntrblk[0], 0);
      CVMX_MF_AES_RESULT (enc_cntrblk[1], 1);
      for(i=0;i<dlen;i++)
         ((uint8_t *)rptr)[i]=((uint8_t *)dptr)[i]^((uint8_t *)enc_cntrblk)[i];
   }
/* Finish inner hash */
   {
      int chunk_len=(pktlen+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH) %64;
      uint8_t i=0;
      uint8_t chunk[100];
      if(chunk_len >= 56) {
         chunk_len = 72;
         chunk_len += (dlen/8)*8;
      } else {
           chunk_len = 64-chunk_len;
         chunk_len+=dlen;
      }
      memset(chunk,0x0, chunk_len);
      if(dlen) {
         memcpy(chunk,(uint8_t *)rptr,dlen);
         rptr=(uint64_t *)((uint8_t *)rptr+dlen);
         *(chunk+dlen)=0x80;
      } else
         chunk[0]= 0x80;
       *((uint64_t *)(chunk + chunk_len -8)) = (pktlen+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH+64) * 8;
       i=0;
      while ( i< chunk_len) {
         _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), sha1_next, 2);
          i += 8;
      }
   } 

    /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_sha[0], 0);
   CVMX_MF_HSH_IV (inner_sha[1], 1);
   CVMX_MF_HSH_IV (inner_sha[2], 2);
   CVMX_MF_HSH_IV (inner_sha[3], 3);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (sha224defiv[0], 0);
   CVMX_MT_HSH_IV (sha224defiv[1], 1);
   CVMX_MT_HSH_IV (sha224defiv[2], 2);
   CVMX_MT_HSH_IV (sha224defiv[3], 3);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));

   CVMX_M64BT_HSH_DAT_SHA224_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_MF_HSH_IV (sha1[0], 0);
   CVMX_MF_HSH_IV (sha1[1], 1);
   
   /* put HMac at the end of the packet */
   memcpy(rptr, sha1, ICV_LEN_SHA224);
   if(outlen) {   
       if(outptr)
         *outlen = (pktlen+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH+ICV_LEN_SHA224);
      else
         *outlen = (pktlen+ICV_LEN_SHA224);
   }
    return 0;
}

int AES_ctr_sha224_decrypt(uint64_t *aes_key, uint32_t aes_key_len, uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   register uint64_t in1,in2,out1,out2;
   register int sha1_next;
   uint64_t sha1[4];
   uint32_t dlen;
   uint32_t i;
   uint8_t sha_key[64];
   uint64_t inner_sha[4];
   cntrblk_t cntrblk;
   uint64_t enc_cntrblk[2];
   if(pktptr == NULL ||  pktlen == 0  || aes_key == NULL || 
      aes_iv == NULL || sha1_key == NULL || sha1_keylen ==0 
      ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +AES_CTR_IV_LENGTH+ICV_LEN_SHA224+1)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);
   memset(sha_key,0x0,64);
   if(sha1_keylen > 64) {
      if(hash_key(sha1_key, sha1_keylen, sha_key, 3)<0) {
         printf(" improper mac secret \n");   
            return -1;
      }
   sha1_keylen = 28;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);
   aes_key_len = aes_key_len * 8;
   
   cntrblk.blk[0] = 0;
   cntrblk.blk[1] = 0;
   cntrblk.s.nonce = nonce;
   for(i = 0; i < AES_CTR_IV_LENGTH; i++)
      cntrblk.s.aes_iv[i] = aes_iv[i];
   cntrblk.s.counter = 1;

   in1=cntrblk.blk[0];
   in2=cntrblk.blk[1];
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY (0x0ULL, 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   }else if(aes_key_len == 192) {
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   }else if(aes_key_len == 256) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   /* Load SHA1 IV */
   CVMX_MT_HSH_IV (sha224defiv[0], 0);
   CVMX_MT_HSH_IV (sha224defiv[1], 1);
   CVMX_MT_HSH_IV (sha224defiv[2], 2);
   CVMX_MT_HSH_IV (sha224defiv[3], 3);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ ipad));

   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   CVMX_PREFETCH0(aptr);
   dptr = (uint64_t *) (pktptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH) ;
   dlen = pktlen - ESP_HEADER_LENGTH- AES_CTR_IV_LENGTH- ICV_LEN_SHA224;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
   } else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
    
   /* load esp header and iv to hash unit */
   CVMX_MT_HSH_DAT (*aptr++, 0);
   CVMX_MT_HSH_DAT (*aptr++, 1);

   sha1_next = (((dlen + 16) % 64) / 16) * 2;
   
   while(dlen >= 128)
   {
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(2,3);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(4,5);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(6,7);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(0,1);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(2,3);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(4,5);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(6,7);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(0,1);
   }

   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(2,3);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(4,5);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(6,7);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(0,1);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(2,3);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(4,5);
   if(dlen >=16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(6,7);

   aptr = dptr;
   pktlen = pktlen -ICV_LEN_SHA224;
   
   /* Finish Inner hash */
   {
      int chunk_len=pktlen %64;
      uint8_t i=0;
      uint8_t chunk[100];
      if(chunk_len >= 56) {
         chunk_len = 72;
         chunk_len += (dlen/8)*8;
      } else {
         chunk_len = 64-chunk_len;
          chunk_len+=dlen;
      }
      memset(chunk,0x0, chunk_len);
      if(dlen) {
         memcpy(chunk,(uint8_t *)dptr,dlen);
         *(chunk+dlen)=0x80;
         CVMX_MT_AES_ENC0 (in1);
         CVMX_MT_AES_ENC1 (in2);
         CVMX_MF_AES_RESULT (enc_cntrblk[0], 0);
         CVMX_MF_AES_RESULT (enc_cntrblk[1], 1);
         for(i=0;i<dlen;i++)
            ((uint8_t *)rptr)[i]=((uint8_t *)dptr)[i] ^((uint8_t *)enc_cntrblk)[i];
      
      } else
         chunk[0]= 0x80;
      *((uint64_t *)(chunk + chunk_len -8)) = (pktlen+ 64) * 8;
      i=0;
      while ( i< chunk_len) {
         _CVMX_MT_HSH_DAT (*((uint64_t *)(chunk+i)), sha1_next, 2);
          i += 8;
      }
   } 

   /* Get the inner hash of HMAC */
   CVMX_MF_HSH_IV (inner_sha[0], 0);
   CVMX_MF_HSH_IV (inner_sha[1], 1);
   CVMX_MF_HSH_IV (inner_sha[2], 2);
   CVMX_MF_HSH_IV (inner_sha[3], 3);

   /* Initialize hash unit */
   CVMX_MT_HSH_IV (sha224defiv[0], 0);
   CVMX_MT_HSH_IV (sha224defiv[1], 1);
   CVMX_MT_HSH_IV (sha224defiv[2], 2);
   CVMX_MT_HSH_IV (sha224defiv[3], 3);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M64BT_HSH_DAT_SHA256((*aptr++ ^ opad));
   
   CVMX_M64BT_HSH_DAT_SHA224_HMAC(inner_sha);


   /* Get the HMAC */
   CVMX_MF_HSH_IV (sha1[0], 0);
   CVMX_MF_HSH_IV (sha1[1], 1);

   /* compare first 128 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, sha1, ICV_LEN_SHA224)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA224;i++)
            printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA224;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
   } else if(outptr) 
           memcpy(outptr+pktlen, sha1, ICV_LEN_SHA224);
    
   *outlen=pktlen;
   return 0;
}

int DES_ede3_cbc_sha384_encrypt(uint8_t *des_key, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr;
   uint32_t dlen;
   uint64_t sha1[8];

   uint8_t sha_key[128];
   uint64_t inner_sha[8];
   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      des_key == NULL || des_iv == NULL || sha1_key == NULL 
      || sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if((pktlen < 8) || (pktlen%8)) {
      printf(" packetlen is not proper \n");
      return -1;
   }
   if( pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-DES_CBC_IV_LENGTH-ICV_LEN_SHA384)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   CVMX_PREFETCH0(des_key);
   CVMX_PREFETCH0(des_iv);
   
   MEMSET128BTZ(sha_key);

   if(sha1_keylen > 128) {
      if(hash_key_sha512(sha1_key, sha1_keylen, sha_key, 0)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 64;
   } else {
      if(sha1_keylen == 64) {
        MEMCPY64B(sha_key,sha1_key);
      } else {
        memcpy(sha_key,sha1_key,sha1_keylen);
      }
   }


   /* load 3DES Key */
   CVMX_M24BT_3DES_KEY(((uint64_t*)des_key));
   CVMX_MT_3DES_IV (*((uint64_t *)des_iv));

   /* Load SHA1 IV */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512 ((*aptr++ ^ ipad));
   
   aptr =(uint64_t *)espheader;
   CVMX_MT_HSH_DATW (*aptr, 0);
   aptr =(uint64_t *)des_iv;
   CVMX_MT_HSH_DATW (*aptr, 1);
   
   /* Copy header & setup enc/hmac args */
   dptr = (uint64_t *)pktptr ;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen ;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)des_iv)[0];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   } else
      rptr= (uint64_t *)pktptr;
   aptr =rptr;
    

   COP2_PARALLEL_3DES_ENC_SHA512(dptr, rptr, dlen);
   CVMX_MF_3DES_IV(*(uint64_t*)des_iv);

   CVMX_M64BF_HSH_IVW(inner_sha);
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512 ((*aptr++ ^ opad));

   CVMX_M128BT_HSH_DATW_SHA384_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha1[0], 0);
   CVMX_MF_HSH_IVW (sha1[1], 1);
   CVMX_MF_HSH_IVW (sha1[2], 2);
   
   /* put HMac at the end of the packet */
   memcpy(rptr, sha1, ICV_LEN_SHA384);
   if(outlen) {
     *outlen = outptr ? (pktlen+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH+ICV_LEN_SHA384) : (pktlen+ICV_LEN_SHA384);
   }
    return 0;
}


int DES_ede3_cbc_sha384_decrypt(uint8_t *des_key, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen,uint8_t *outptr, uint16_t *outlen,uint8_t compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   uint32_t dlen;
   uint64_t sha1[8];

   uint32_t i;
   uint8_t sha_key[128];
   uint64_t inner_sha[8];
   if(pktptr == NULL || pktlen == 0  || des_key == NULL || 
      des_iv == NULL || sha1_key == NULL || sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +DES_CBC_IV_LENGTH+ICV_LEN_SHA384+8)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   CVMX_PREFETCH0(des_key);
   CVMX_PREFETCH0(des_iv);
   //memset(sha_key,0x0,128);
   MEMSET128BTZ(sha_key);
   if(sha1_keylen > 128) {
      if(hash_key_sha512(sha1_key, sha1_keylen, sha_key, 0)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 64;
   } else {
      if(sha1_keylen == 64)
	{
		MEMCPY64B(sha_key,sha1_key);
	}
      else
      memcpy(sha_key,sha1_key,sha1_keylen);
   }


   CVMX_M24BT_3DES_KEY(((uint64_t*)des_key));
   CVMX_MT_3DES_IV (*((uint64_t *)des_iv));

   /* Load SHA1 IV */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512(*aptr++ ^ ipad);


   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   CVMX_PREFETCH0(aptr);
   dptr = (uint64_t *)(pktptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   dlen = pktlen -ESP_HEADER_LENGTH-DES_CBC_IV_LENGTH- ICV_LEN_SHA384;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   } else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);

   /* load esp header and iv to hash unit*/
   CVMX_MT_HSH_DATW (*aptr++, 0);
   CVMX_MT_HSH_DATW (*aptr++, 1);

   dptr = aptr;
   pktlen = pktlen - ICV_LEN_SHA384;
   COP2_PARALLEL_3DES_DEC_SHA512(dptr, rptr, dlen);
   CVMX_MF_3DES_IV(*(uint64_t*)des_iv);

   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512(*aptr++ ^ opad);


   CVMX_M128BT_HSH_DATW_SHA384_HMAC(inner_sha);



   /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha1[0], 0);
   CVMX_MF_HSH_IVW (sha1[1], 1);
   CVMX_MF_HSH_IVW (sha1[2], 2);

   /* compare first 192 bits of HMAC with received mac */
   
   if(compdigest) {
      if(memcmp(pktptr+pktlen, sha1, ICV_LEN_SHA384)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA384;i++)
            printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA384;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
   } else if(outptr)
      memcpy(outptr+pktlen, sha1, ICV_LEN_SHA384);
    
   *outlen=pktlen;
   return 0;
}

int AES_cbc_sha384_encrypt(uint16_t aes_key_len, uint8_t *aes_key,  uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t sha1[8];
   uint32_t dlen;

   uint8_t sha_key[128];
   uint64_t inner_sha[8];

   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      aes_key == NULL || aes_iv == NULL || sha1_key == NULL || 
      sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }

   if((pktlen < 16) || (pktlen%16)) {
      printf(" packetlen is not proper \n");
      return -1;
   }

   if( pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-AES_CBC_IV_LENGTH-ICV_LEN_SHA384)) {
      printf("Packet is too big to handle \n");
      return -1;
   }

   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);

   MEMSET128BTZ(sha_key);

   if(sha1_keylen > 128) {
      if(hash_key_sha512(sha1_key, sha1_keylen, sha_key,0)<0) {
         printf(" improper mac secret \n");   
         return -1;
   }
      sha1_keylen = 64;
   } else {
      if(sha1_keylen == 64) 
      {
        MEMCPY64B(sha_key,sha1_key);
      } else {
        memcpy(sha_key,sha1_key,sha1_keylen);
      }
   }


   aes_key_len= aes_key_len *8;  
   
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 256) {
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
         return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Load SHA1 IV */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ ipad));

   aptr =(uint64_t *)espheader;
   CVMX_MT_HSH_DATW (*aptr, 0);
   aptr =(uint64_t *)aes_iv;
   CVMX_MT_HSH_DATW (aptr[0], 1);
   CVMX_MT_HSH_DATW (aptr[1], 2);

   /* Copy header & setup enc/hmac args */
   dptr = (uint64_t *) pktptr;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen ;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)aes_iv)[0];
      ((uint64_t *)outptr)[2]=((uint64_t *)aes_iv)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
      aptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
   } else {
      rptr= (uint64_t *)pktptr;
      aptr= (uint64_t *)pktptr;
   }
  

   COP2_PARALLEL_AES_ENC_SHA512(dptr,rptr,dlen);
   
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ opad));

   CVMX_M128BT_HSH_DATW_SHA384_HMAC(inner_sha);
   
  /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha1[0], 0);
   CVMX_MF_HSH_IVW (sha1[1], 1);
   CVMX_MF_HSH_IVW (sha1[2], 2);
   
  /* put HMac at the end of the packet */
   memcpy(rptr, sha1, ICV_LEN_SHA384);
   if(outlen) {
      if(outptr)
         *outlen = pktlen +ESP_HEADER_LENGTH +AES_CBC_IV_LENGTH+ICV_LEN_SHA384;
      else
         *outlen = pktlen +ICV_LEN_SHA384;
   }
   return 0;
}


int AES_cbc_sha384_decrypt(uint16_t aes_key_len, uint8_t *aes_key, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t sha1[8];
   uint32_t dlen;
   int i;
   uint8_t sha_key[128];
   uint64_t inner_sha[8];
   if(pktptr == NULL  || pktlen == 0  || aes_key == NULL || 
      aes_iv == NULL || sha1_key == NULL || sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +AES_CBC_IV_LENGTH+ICV_LEN_SHA384+16)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);
   memset(sha_key,0x0,128);
   if(sha1_keylen > 128) {
      if(hash_key_sha512(sha1_key, sha1_keylen, sha_key,0)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 64;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);
   aes_key_len = aes_key_len * 8;
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY (0x0ULL, 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 256) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Load SHA1 IV */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;

   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ ipad));
   
   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   CVMX_PREFETCH0(aptr);
   dptr = (uint64_t *) (pktptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
   dlen = pktlen - ESP_HEADER_LENGTH- AES_CBC_IV_LENGTH-ICV_LEN_SHA384;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      ((uint64_t *)outptr)[2]=((uint64_t *)pktptr)[2];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
   }
   else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);

   /* load esp header and IV to hash unit */
   CVMX_MT_HSH_DATW (*aptr++, 0);
   CVMX_MT_HSH_DATW (*aptr++, 1);
   CVMX_MT_HSH_DATW (*aptr++, 2);

   dptr = aptr;
   pktlen = pktlen - ICV_LEN_SHA384;
   COP2_PARALLEL_AES_DEC_SHA512(dptr,rptr,dlen);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MF_AES_IV (((uint64_t *)aes_iv)[1], 1);

   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   
   CVMX_M128BT_HSH_DATW_SHA512 ((*aptr++ ^ opad));

   CVMX_M128BT_HSH_DATW_SHA384_HMAC(inner_sha);  

   /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha1[0], 0);
   CVMX_MF_HSH_IVW (sha1[1], 1);
   CVMX_MF_HSH_IVW (sha1[2], 2);

   /* compare first 192 bits of HMAC with received mac */
   if(compdigest) {
        if(memcmp(pktptr+pktlen, sha1, ICV_LEN_SHA384)) {
          printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA384;i++)
              printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA384;i++)
              printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }   
   } else if(outptr)
        memcpy(outptr+pktlen, sha1, ICV_LEN_SHA384);
        
   *outlen=pktlen;
   return 0;
}


int AES_ctr_sha384_encrypt(uint64_t *aes_key, uint32_t aes_key_len,  uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *espheader, uint8_t *aes_iv,  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr; 
   register uint64_t in1,in2,out1,out2;
   register int sha1_next;
   uint64_t sha1[8];
   uint32_t dlen ;
   uint32_t i;
   uint8_t sha_key[128];
   uint64_t inner_sha[8];
   cntrblk_t cntrblk;
   uint64_t enc_cntrblk[2];
   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      aes_key == NULL || aes_iv == NULL || sha1_key == NULL || 
      sha1_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-AES_CTR_IV_LENGTH-ICV_LEN_SHA384)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);
   memset(sha_key,0x0,128);
   if(sha1_keylen > 128) {
      if(hash_key_sha512(sha1_key, sha1_keylen, sha_key, 0)<0) {
         printf(" improper mac secret \n");   
         return -1;
   }
   sha1_keylen = 48;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);
   aes_key_len = aes_key_len * 8;
   cntrblk.blk[0] = 0;
   cntrblk.blk[1] = 0;
   cntrblk.s.nonce = nonce;
   for(i = 0; i < AES_CTR_IV_LENGTH; i++)
   cntrblk.s.aes_iv[i] = aes_iv[i];
   cntrblk.s.counter = 1;

   in1=cntrblk.blk[0];
   in2=cntrblk.blk[1];
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY (0x0ULL, 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 192) {
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 256) {
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);


   /* Load SHA1 IV */
   CVMX_M64BT_HSH_IVW(sha384defiv);


   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ ipad));
   aptr = (uint64_t *) espheader;
   CVMX_MT_HSH_DATW (*aptr++, 0);
   aptr = (uint64_t *) aes_iv;
   CVMX_MT_HSH_DATW (*aptr++, 1);

   /* Copy header & setup enc/hmac args */
   dptr = (uint64_t *)pktptr;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)aes_iv)[0];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
   } else
      rptr =(uint64_t *)pktptr;
   
   sha1_next = (((dlen + 16) % 128) / 16) * 2;
   COP2_PARALLEL_128BN_AES_CTR_ENC_SHA512(dptr,rptr,dlen);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA512_STEP(2,3); 
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA512_STEP(4,5); 
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA512_STEP(6,7); 
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA512_STEP(8,9); 
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA512_STEP(10,11); 
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA512_STEP(12,13); 
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_ENC_SHA512_STEP(14,15); 

   aptr = rptr;
 
   if(dlen) {
      uint32_t i;
      CVMX_MT_AES_ENC0(in1);
      CVMX_MT_AES_ENC1(in2);
      CVMX_MF_AES_RESULT (enc_cntrblk[0], 0);
      CVMX_MF_AES_RESULT (enc_cntrblk[1], 1);
      for(i=0;i<dlen;i++)
         ((uint8_t *)rptr)[i]=((uint8_t *)dptr)[i]^((uint8_t *)enc_cntrblk)[i];
   }
   /* Finish inner hash */
   {
      int chunk_len=(pktlen+ ESP_HEADER_LENGTH+ AES_CTR_IV_LENGTH) %128;
      uint8_t i=0;
      uint8_t chunk[200];
      if(chunk_len >= 112 && chunk_len < 120) {
         chunk_len = 144;
         chunk_len+=(dlen/8)*8;
      }else if(chunk_len >=120) {
         chunk_len=136;
         chunk_len+=(dlen/8)*8;
      } else {
         chunk_len = 128-chunk_len;
         chunk_len += dlen;
      }
      memset(chunk,0x0, chunk_len);
      if(dlen) {
         memcpy(chunk,(uint8_t *)rptr,dlen);
         *(chunk+dlen)=0x80;
         rptr =(uint64_t *)((uint8_t *)rptr+dlen);
      } else
         chunk[0]= 0x80;
      uint64_t_mul (((uint64_t *)(chunk+chunk_len-16))[0],((uint64_t *)(chunk+chunk_len-16))[1], (pktlen+ESP_HEADER_LENGTH + AES_CTR_IV_LENGTH+ 128), 0x8ull);
      i=0;
      while ( i< chunk_len) {
         _CVMX_MT_HSH_DATW (*((uint64_t *)(chunk+i)), sha1_next);
          i += 8;
      }
   } 

   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ opad));

   CVMX_M128BT_HSH_DATW_SHA384_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha1[0], 0);
   CVMX_MF_HSH_IVW (sha1[1], 1);
   CVMX_MF_HSH_IVW (sha1[2], 2);

   /* put HMac at the end of the packet */
   memcpy(rptr, sha1, ICV_LEN_SHA384);
   if(outlen) {
      if(outptr)
         *outlen = pktlen+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH+ICV_LEN_SHA384;
      else
         *outlen = pktlen+ICV_LEN_SHA384;
   }
 return 0;
}

int AES_ctr_sha384_decrypt(uint64_t *aes_key, uint32_t aes_key_len, uint32_t nonce, uint16_t sha1_keylen, uint8_t *sha1_key, uint8_t *aes_iv,  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   register uint64_t in1,in2;
   register uint64_t out1,out2;
   register int sha1_next;
   uint64_t sha1[8];
   uint32_t dlen;
   uint32_t i;
   uint8_t sha_key[128];
   uint64_t inner_sha[8];
   cntrblk_t cntrblk;
   uint64_t enc_cntrblk[2];
   if(pktptr == NULL ||  pktlen == 0  || aes_key == NULL || 
      aes_iv == NULL || sha1_key == NULL || sha1_keylen ==0||
      outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +AES_CTR_IV_LENGTH+ICV_LEN_SHA384+1)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   CVMX_PREFETCH0(aes_iv);
   CVMX_PREFETCH0(aes_key);
   memset(sha_key,0x0,128);
   if(sha1_keylen > 128) {
      if(hash_key_sha512(sha1_key, sha1_keylen, sha_key, 0)<0) {
         printf(" improper mac secret \n");   
         return -1;
      }
      sha1_keylen = 48;
   } else
      memcpy(sha_key,sha1_key,sha1_keylen);
   aes_key_len = aes_key_len * 8;
   cntrblk.blk[0] = 0;
   cntrblk.blk[1] = 0;
   cntrblk.s.nonce = nonce;
   for(i = 0; i < AES_CTR_IV_LENGTH; i++)
   cntrblk.s.aes_iv[i] = aes_iv[i];
   cntrblk.s.counter = 1;

   in1=cntrblk.blk[0];
   in2=cntrblk.blk[1];
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY (0x0ULL, 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 256) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   /* Load SHA1 IV */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor ipad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ ipad));

   /* setup enc/hmac args */
   aptr = (uint64_t *)pktptr ;
   CVMX_PREFETCH0(aptr);
   dptr = (uint64_t *) (pktptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH) ;
   dlen = pktlen - ESP_HEADER_LENGTH - AES_CTR_IV_LENGTH -ICV_LEN_SHA384;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
   }
   else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);

   /* load esp header and iv to hash unit */    
   CVMX_MT_HSH_DATW (*aptr++, 0);
   CVMX_MT_HSH_DATW (*aptr++, 1);

   /* Loop through input */
   sha1_next = (((dlen + 16) % 128) / 16) * 2;
   while(dlen >= 128)
   {
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(2,3);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(4,5);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(6,7);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(8,9);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(10,11);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(12,13);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(14,15);
     COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(0,1);
   }


   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(2,3);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(4,5);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(6,7);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(8,9);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(10,11);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(12,13);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(14,15);
   if(dlen >= 16) COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(0,1);

   pktlen = pktlen -ICV_LEN_SHA384;
   /* Finish Inner hash */
   {
      int chunk_len=pktlen %128;
      uint8_t i=0;
      uint8_t chunk[200];
      if(chunk_len >= 112 && chunk_len < 120) {
         chunk_len = 144;
         chunk_len+=(dlen/8)*8;
      } else if(chunk_len >=120) {
         chunk_len=136;
         chunk_len+=(dlen/8)*8;
      } else {
         chunk_len = 128-chunk_len;
         chunk_len += dlen;
      }
      memset(chunk,0x0, chunk_len);
      if(dlen) {
         memcpy(chunk,(uint8_t *)dptr,dlen);
         *(chunk+dlen)=0x80;
         CVMX_MT_AES_ENC0 (in1);
         CVMX_MT_AES_ENC1 (in2);
         CVMX_MF_AES_RESULT (enc_cntrblk[0], 0);
         CVMX_MF_AES_RESULT (enc_cntrblk[1], 1);
         for(i=0;i<dlen;i++)
            ((uint8_t *)rptr)[i]=((uint8_t *)dptr)[i] ^((uint8_t *)enc_cntrblk)[i];
      
      } else
         chunk[0]= 0x80;
      uint64_t_mul (((uint64_t *)(chunk+chunk_len-16))[0],((uint64_t *)(chunk+chunk_len-16))[1], (pktlen+128), 0x8ull);
      i=0;
      while ( i< chunk_len) {
         _CVMX_MT_HSH_DATW (*((uint64_t *)(chunk+i)), sha1_next);
          i += 8;
      }
   } 

   /* Get the inner hash of HMAC */
   CVMX_M64BF_HSH_IVW(inner_sha);

   /* Initialize hash unit */
   CVMX_M64BT_HSH_IVW(sha384defiv);

   /* Load key xor opad */
   aptr = (uint64_t *) sha_key;
   CVMX_M128BT_HSH_DATW_SHA512((*aptr++ ^ opad));

   CVMX_M128BT_HSH_DATW_SHA384_HMAC(inner_sha);

   /* Get the HMAC */
   CVMX_MF_HSH_IVW (sha1[0], 0);
   CVMX_MF_HSH_IVW (sha1[1], 1);
   CVMX_MF_HSH_IVW (sha1[2], 2);

   /* compare first 192 bits of HMAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, sha1, ICV_LEN_SHA384)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<ICV_LEN_SHA384;i++)
            printf(" %02x",((uint8_t *)sha1)[i]);
         printf("\n Expected");
         for(i=0;i<ICV_LEN_SHA384;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
       }        
   } else
      if(outptr)
           memcpy(outptr + pktlen, sha1, ICV_LEN_SHA384);
   *outlen=pktlen;
    return 0;
}

int AES_cbc_aes_xcbc_encrypt(uint16_t aes_key_len, uint8_t *aes_key,  uint16_t auth_keylen, uint8_t *auth_key, uint8_t *espheader, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr,*aptr,*rptr,aes_xcbc_mac[2];
   uint32_t dlen;
   AES_XCBC_MAC_CTX ctx[1];
   AES_KEY k;

   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      aes_key == NULL || aes_key_len == 0 || aes_iv == NULL ||
      auth_key == NULL || auth_keylen ==0 ||outlen==NULL){
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if((pktlen < 16) || (pktlen%16)) {
      printf(" packetlen is not proper \n");
      return -1;
   }
   if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-AES_CBC_IV_LENGTH-12)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);

   aes_key_len = aes_key_len *8; 
   
   /* Load AES encryption Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);

   if(aes_key_len == (uint16_t)128) {
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 256) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length => aes_key_len=%d \n",aes_key_len);
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);


   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[1], 1);

   dptr = (uint64_t *)pktptr;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen;
      if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)aes_iv)[0];
      ((uint64_t *)outptr)[2]=((uint64_t *)aes_iv)[1];
      rptr= aptr=(uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
   } else {
      rptr= aptr= (uint64_t *)pktptr;
   }
   /* encrypt packet */
   while( dlen >= (16)){
	CVMX_MT_AES_ENC_CBC0(dptr[0]);
	CVMX_MT_AES_ENC_CBC1(dptr[1]);
	dlen -= 16;
	dptr+=2;
	rptr+=2;
	CVMX_MF_AES_RESULT(rptr[-2],0);
	CVMX_MF_AES_RESULT(rptr[-1],1);
}
    /* AES XCBC multicall call */
    cvm_crypto_aes_xcbc_mac_init ((uint8_t *) auth_key, auth_keylen, &k, ctx);
    cvm_crypto_aes_xcbc_mac_update (&k, (uint8_t *) espheader,ESP_HEADER_LENGTH , ctx);
    cvm_crypto_aes_xcbc_mac_update (&k, (uint8_t *) aes_iv,AES_CBC_IV_LENGTH , ctx);
    cvm_crypto_aes_xcbc_mac_update (&k, (uint8_t *) aptr,pktlen, ctx);
    cvm_crypto_aes_xcbc_mac_final (&k, ctx, aes_xcbc_mac);

   memcpy(rptr, aes_xcbc_mac, 12);
   if(outlen) {
      if(outptr)
         *outlen =pktlen+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH+12;
      else
         *outlen =pktlen+12;
   }
   return 0;
}

int AES_cbc_aes_xcbc_decrypt(uint16_t aes_key_len, uint8_t *aes_key, uint16_t auth_keylen, uint8_t *auth_key, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *dptr,*rptr;
   uint64_t aes_xcbc_mac[2];
   uint32_t dlen;
   uint32_t i;
   aes_key_len = aes_key_len * 8 ;

   if(pktptr == NULL || pktlen == 0  || aes_key == NULL ||
      aes_iv == NULL || auth_key == NULL || auth_keylen ==0 
      ||outlen==NULL || aes_key_len==0 ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
    if(pktlen < (ESP_HEADER_LENGTH +AES_CBC_IV_LENGTH+12+16)) {
      printf("Packet length is not proper \n");
      return -1;
     }
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);

   dptr = (uint64_t *) (pktptr) ;
   CVMX_PREFETCH0(dptr);

   dlen = pktlen -ESP_HEADER_LENGTH-AES_CBC_IV_LENGTH-12;
   if(outptr != NULL) /*Non-inplace */
   {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      ((uint64_t *)outptr)[2]=((uint64_t *)pktptr)[2];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);
   }
   else /* In place */
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);

   pktlen = pktlen - 12;

   /* generate mac */
   cvm_crypto_aes_xcbc_mac ((uint64_t *) auth_key,auth_keylen, (uint64_t *) pktptr,pktlen, aes_xcbc_mac);

   /* Verify Mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, aes_xcbc_mac, 12)) {
         printf("\n FAILURE : XCBC INBOUND Mac Mismatch ");
         printf("\n Generated: ");
      for(i=0;i<12;i++)
         printf("%02x",((uint8_t *)aes_xcbc_mac)[i]);
      printf("\nExpected");
      for(i=0;i<12;i++)
         printf("%02x",(pktptr+pktlen)[i]);
      printf("\n");
      return -1;
      }
   } else  {
      if(outptr)
         memcpy(outptr+pktlen,aes_xcbc_mac , 12);
   }

   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 256) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[0], 0);
   CVMX_MT_AES_IV (((uint64_t *)aes_iv)[1], 1);

   dptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH);

   /* decrypt packet */
   while (dlen >= 16) {

	CVMX_MT_AES_DEC_CBC0(dptr[0]);
	CVMX_MT_AES_DEC_CBC1(dptr[1]);
	dlen -= 16;
	rptr+=2;
	dptr+=2;
	CVMX_MF_AES_RESULT(rptr[-2],0);
	CVMX_MF_AES_RESULT(rptr[-1],1);
   }
  
   return 0;
}


int NULL_aes_xcbc_encrypt(uint16_t auth_keylen, uint8_t *auth_key, uint8_t *espheader, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr,aes_xcbc_mac[2];
   AES_XCBC_MAC_CTX ctx[1];
   AES_KEY k;

   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      auth_key == NULL || auth_keylen ==0 ||outlen==NULL){
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-12)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   CVMX_PREFETCH0(auth_key);

   dptr = (uint64_t *)pktptr;
   CVMX_PREFETCH0(dptr);


    /* AES XCBC multicall call */
    cvm_crypto_aes_xcbc_mac_init ((uint8_t *) auth_key, auth_keylen, &k, ctx);
    cvm_crypto_aes_xcbc_mac_update (&k, (uint8_t *) espheader,ESP_HEADER_LENGTH , ctx);
    cvm_crypto_aes_xcbc_mac_update (&k, (uint8_t *) dptr,pktlen, ctx);
    cvm_crypto_aes_xcbc_mac_final (&k, ctx, aes_xcbc_mac);

      if(outptr!=NULL){
         memcpy(outptr,espheader,ESP_HEADER_LENGTH);
         memcpy(outptr+ESP_HEADER_LENGTH,pktptr,pktlen);
         memcpy(outptr+ESP_HEADER_LENGTH+pktlen,aes_xcbc_mac,12);
         *outlen =pktlen+ESP_HEADER_LENGTH+12;
      }
      else{
   	 memcpy(pktptr+pktlen,aes_xcbc_mac, 12);
         *outlen =pktlen+12;
      }
   return 0;
}

int NULL_aes_xcbc_decrypt(uint16_t auth_keylen, uint8_t *auth_key, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *dptr;
   uint64_t aes_xcbc_mac[2];
   uint32_t i;

   if(pktptr == NULL || pktlen == 0  || auth_key == NULL || auth_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
    if(pktlen < (ESP_HEADER_LENGTH +12+16)) {
      printf("Packet length is not proper \n");
      return -1;
     }
   CVMX_PREFETCH0(auth_key);

   dptr = (uint64_t *) (pktptr) ;
   CVMX_PREFETCH0(dptr);

   pktlen = pktlen - 12;

   /* generate mac */
   cvm_crypto_aes_xcbc_mac ((uint64_t *) auth_key,auth_keylen, (uint64_t *) pktptr,pktlen, aes_xcbc_mac);

   /* Verify Mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen, aes_xcbc_mac, 12)) {
         printf("\n FAILURE : XCBC INBOUND Mac Mismatch ");
         printf("\n Generated: ");
      for(i=0;i<12;i++)
         printf("%02x",((uint8_t *)aes_xcbc_mac)[i]);
      printf("\nExpected");
      for(i=0;i<12;i++)
         printf("%02x",(pktptr+pktlen)[i]);
      printf("\n");
      return -1;
      }
   } else  {
      if(outptr)
         memcpy(outptr+pktlen,aes_xcbc_mac , 12);
   }
   *outlen =pktlen;
	
   if(outptr){
	memcpy(outptr,pktptr,pktlen);
   }
   return 0;
}

int DES_ede3_cbc_aes_xcbc_encrypt(uint8_t *des_key, uint16_t auth_keylen, uint8_t *auth_key, uint8_t *espheader, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr,*aptr,*rptr,aes_xcbc_mac[2];
   uint32_t dlen;
   AES_XCBC_MAC_CTX ctx[1];
   AES_KEY k;

   if(pktptr == NULL || espheader == NULL || pktlen == 0  ||
      des_key == NULL || des_iv == NULL || auth_key == NULL || 
      auth_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if((pktlen < 8) || (pktlen%8)) {
      printf(" packetlen is not proper \n");
      return -1;
   }
   if( pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-DES_CBC_IV_LENGTH-12)) {
      printf("Packet is too big to handle \n");
      return -1;
   }
   CVMX_PREFETCH0(des_key);
   CVMX_PREFETCH0(des_iv);

   /* load 3DES Key */
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[0], 0);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[1], 1);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[2], 2);

   CVMX_MT_3DES_IV (*((uint64_t *)des_iv));

   dptr = (uint64_t *)pktptr;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)des_iv)[0];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   } else
      rptr = (uint64_t *)pktptr;
   aptr=rptr;

   /* Start encryption */
   while(dlen >= 16){
	CVMX_MT_3DES_ENC_CBC(dptr[0]);
	CVMX_MF_3DES_RESULT(rptr[0]);
	CVMX_MT_3DES_ENC_CBC(dptr[1]);
	CVMX_MF_3DES_RESULT(rptr[1]);
	dptr+=2;
	rptr+=2;
	dlen-=16;
   }	
   if(dlen){
	CVMX_MT_3DES_ENC_CBC(dptr[0]);
        CVMX_MF_3DES_RESULT(rptr[0]);
	dptr++; 
	rptr++;
	dlen-=8;
   }
   /* start generating mac*/
    cvm_crypto_aes_xcbc_mac_init ((uint8_t *) auth_key, auth_keylen, &k, ctx);
    cvm_crypto_aes_xcbc_mac_update (&k, (uint8_t *) espheader,ESP_HEADER_LENGTH , ctx);
    cvm_crypto_aes_xcbc_mac_update (&k, (uint8_t *) des_iv,DES_CBC_IV_LENGTH , ctx);
    cvm_crypto_aes_xcbc_mac_update (&k, (uint8_t *) aptr,pktlen, ctx);
    cvm_crypto_aes_xcbc_mac_final (&k, ctx, aes_xcbc_mac);

   memcpy(rptr,aes_xcbc_mac, 12);
   if(outlen) {
      if(outptr)
         *outlen =pktlen+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH+12;
      else
         *outlen =pktlen+12;
   }
   return 0;
}

int DES_ede3_cbc_aes_xcbc_decrypt(uint8_t *des_key, uint16_t auth_keylen, uint8_t *auth_key, uint8_t *des_iv, uint8_t *pktptr, uint16_t pktlen,uint8_t *outptr, uint16_t *outlen,uint8_t compdigest)
{
   uint64_t *dptr,*rptr;
   uint64_t aes_xcbc_mac[2]; 
   uint32_t dlen;
   uint32_t i;

   if(pktptr == NULL ||  pktlen == 0  || des_key == NULL ||
    des_iv == NULL || auth_key == NULL || auth_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +DES_CBC_IV_LENGTH+12+8)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   CVMX_PREFETCH0(des_iv);
   CVMX_PREFETCH0(des_key);

   /* Load esp header and IV to hash unit */
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[0], 0);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[1], 1);
   CVMX_MT_3DES_KEY (((uint64_t *)des_key)[2], 2);

   CVMX_MT_3DES_IV (*((uint64_t *)des_iv));

   rptr = (uint64_t *)pktptr;
   CVMX_PREFETCH0(rptr);


   dptr = (uint64_t *)(pktptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   dlen = pktlen -ESP_HEADER_LENGTH-DES_CBC_IV_LENGTH-12;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
   } else
      rptr = (uint64_t *)(pktptr+ESP_HEADER_LENGTH+DES_CBC_IV_LENGTH);
	
   /* generate Mac */
   cvm_crypto_aes_xcbc_mac ((uint64_t *) auth_key,auth_keylen, (uint64_t *) pktptr,pktlen-12, aes_xcbc_mac);


   /* compare first 96 bits of MAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen-12, aes_xcbc_mac, 12)) {
         printf("\n INBOUND Mac Mismatch: DES_ede3_cbc_aes_xcbc_decrypt()");
         printf("\n Generated");
         for(i=0;i<12;i++)
            printf(" %02x",((uint8_t *)aes_xcbc_mac)[i]);
         printf("\n Expected");
         for(i=0;i<12;i++)
            printf(" %02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
     
   } else{
        if(outptr) 
         memcpy(outptr+pktlen,aes_xcbc_mac , 12);
   }
   *outlen =pktlen;

   /* Decrypt packet */
   while(dlen >= 16){
	CVMX_MT_3DES_DEC_CBC (dptr[0]);
	CVMX_MF_3DES_RESULT (rptr[0]);
	CVMX_MT_3DES_DEC_CBC (dptr[1]);
	CVMX_MF_3DES_RESULT (rptr[1]);
	dptr+=2;
	rptr+=2;
	dlen-=16;
   }
   if(dlen){
	CVMX_MT_3DES_DEC_CBC (dptr[0]);
	CVMX_MF_3DES_RESULT (rptr[0]);
	dptr++; 
	rptr++;
	dlen-=8;
   }
   return 0;
}

int AES_ctr_aes_xcbc_encrypt(uint64_t *aes_key, uint32_t aes_key_len, uint32_t nonce, uint16_t auth_keylen, uint8_t *auth_key, uint8_t *espheader, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t d1,d2,in1,in2,out1,out2;
   uint32_t dlen;
   uint32_t i;
   uint64_t aes_xcbc_mac[2];
   cntrblk_t cntrblk;
   uint64_t enc_cntrblk[2];
   AES_XCBC_MAC_CTX ctx[1];
   AES_KEY k;

   if(pktptr == NULL || espheader == NULL || pktlen == 0  || 
      aes_key == NULL || aes_iv == NULL || auth_key == NULL || 
      auth_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen >(MAX_PKT_SIZE-ESP_HEADER_LENGTH-AES_CTR_IV_LENGTH-12)) {
      printf("Packet is too big to handle \n");
      return -1;
   } 
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);
   aes_key_len =aes_key_len *8;  
   cntrblk.blk[0] = 0;
   cntrblk.blk[1] = 0;
   cntrblk.s.nonce = nonce;
   for(i = 0; i < AES_CTR_IV_LENGTH; i++)
      cntrblk.s.aes_iv[i] = aes_iv[i];
   cntrblk.s.counter = 1;

   in1=cntrblk.blk[0];
   in2=cntrblk.blk[1];
   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY ((uint64_t *)0x0, 3);
   } else if(aes_key_len == 256) {
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_IV (0, 0);
   CVMX_MT_AES_IV (0, 1);
   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   dptr = (uint64_t *) pktptr ;
   CVMX_PREFETCH0(dptr);
   dlen = pktlen ;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)espheader)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)aes_iv)[0];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
   } else
      rptr=(uint64_t *)pktptr;
   aptr=rptr;
   /* Start encryption */

   CVMX_M16BT_AES_ENC(in1,in2);
   d1 = dptr[0];d2 = dptr[1];
   dlen -= 16; rptr += 2; dptr += 2;
   if(in2 != UEND) {in2++;} else {in2 = 0; in1++;}
   CVMX_M16BF_AES_RESULT(out1,out2);
   while(dlen >= 16){
	CVMX_M16BT_AES_ENC(in1,in2);
	rptr[-2] = d1 ^ out1;
	rptr[-1] = d2 ^ out2;
	d1 = dptr[0];d2 = dptr[1];
	dlen -= 16; rptr += 2; dptr += 2;
	if(in2 != UEND) {in2++;} else {in2 = 0; in1++;}
        CVMX_M16BF_AES_RESULT(out1,out2);
   } 
   rptr[-2] = d1 ^ out1;
   rptr[-1] = d2 ^ out2;
 
   if(dlen) {
      uint32_t i;
      CVMX_MT_AES_ENC0(in1);
      CVMX_MT_AES_ENC1(in2);
      CVMX_MF_AES_RESULT (enc_cntrblk[0], 0);
      CVMX_MF_AES_RESULT (enc_cntrblk[1], 1);
      for(i=0;i<dlen;i++)
         ((uint8_t *)rptr)[i]=((uint8_t *)dptr)[i]^((uint8_t *)enc_cntrblk)[i];
   }
   /* calculate mac */
    cvm_crypto_aes_xcbc_mac_init ((uint8_t *) auth_key, auth_keylen, &k, ctx);
    cvm_crypto_aes_xcbc_mac_update (&k, (uint8_t *) espheader,ESP_HEADER_LENGTH , ctx);
    cvm_crypto_aes_xcbc_mac_update (&k, (uint8_t *) aes_iv,AES_CTR_IV_LENGTH , ctx);
    cvm_crypto_aes_xcbc_mac_update (&k, (uint8_t *) aptr,pktlen, ctx);
    cvm_crypto_aes_xcbc_mac_final (&k, ctx, aes_xcbc_mac);

   /* put Mac at the end of the packet */
   memcpy((uint8_t *)aptr+pktlen,aes_xcbc_mac, 12);
   if(outlen) {   
      if(outptr)
         *outlen = (pktlen+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH+12);
      else
         *outlen = (pktlen+12);
   }
   return 0;
}

int AES_ctr_aes_xcbc_decrypt(uint64_t *aes_key, uint32_t aes_key_len, uint32_t nonce, uint16_t auth_keylen, uint8_t *auth_key, uint8_t *aes_iv, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen, uint8_t  compdigest)
{
   uint64_t *dptr, *aptr,*rptr;
   uint64_t d1,d2,aes_xcbc_mac[2];
   uint64_t in1,in2,out1,out2;
   uint32_t dlen;
   uint32_t i;
   cntrblk_t cntrblk;
   uint64_t enc_cntrblk[2];

   if(pktptr == NULL ||  pktlen == 0  || aes_key == NULL || 
      aes_iv == NULL || auth_key == NULL || auth_keylen ==0 ||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
   }
   if(pktlen < (ESP_HEADER_LENGTH +AES_CTR_IV_LENGTH+12+1)) {
      printf("Packet length is not proper \n");
      return -1;
   }
   CVMX_PREFETCH0(aes_key);
   CVMX_PREFETCH0(aes_iv);
   aptr = (uint64_t *)pktptr;
   CVMX_PREFETCH0(aptr);
   CVMX_PREFETCH0(auth_key);

   cvm_crypto_aes_xcbc_mac ((uint64_t *) auth_key,auth_keylen, (uint64_t *) pktptr,pktlen-12, aes_xcbc_mac);

   /* compare first 96 bits of MAC with received mac */
   if(compdigest) {
      if(memcmp(pktptr+pktlen-12, aes_xcbc_mac, 12)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated:  ");
         for(i=0;i<12;i++)
            printf("%02x",((uint8_t *)aes_xcbc_mac)[i]);
         printf("\n Expected:  ");
         for(i=0;i<12;i++)
            printf("%02x",(pktptr+pktlen)[i]);
         printf("\n");
         return -1;
      }
   } else
      if(outptr)
          memcpy(outptr+pktlen, aes_xcbc_mac, 12);

   aes_key_len = aes_key_len * 8;
   cntrblk.blk[0] = 0;
   cntrblk.blk[1] = 0;
   cntrblk.s.nonce = nonce;
   for(i = 0; i < AES_CTR_IV_LENGTH; i++)
      cntrblk.s.aes_iv[i] = aes_iv[i];
   cntrblk.s.counter = 1;

   in1=cntrblk.blk[0];
   in2=cntrblk.blk[1];

   /* Load AES Key and IV */
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[0], 0);
   CVMX_MT_AES_KEY (((uint64_t *)aes_key)[1], 1);
   if(aes_key_len == 128) {
      CVMX_MT_AES_KEY (0x0ULL, 2);
      CVMX_MT_AES_KEY (0x0ULL, 3);
   } else if(aes_key_len == 192) {
      CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
      CVMX_MT_AES_KEY (0x0, 3);
   } else if(aes_key_len == 256) {
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[2], 2);
       CVMX_MT_AES_KEY (((uint64_t *)aes_key)[3], 3);
   } else {
      printf(" Improper Key length \n");
      return -1;
   }
   CVMX_MT_AES_IV (0, 0);
   CVMX_MT_AES_IV (0, 1);

   CVMX_MT_AES_KEYLENGTH (aes_key_len / 64 - 1);

   /* setup enc args */
   dptr = (uint64_t *) (pktptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH) ;
   dlen = pktlen - ESP_HEADER_LENGTH- AES_CTR_IV_LENGTH- 12;
   if(outptr != NULL) {
      ((uint64_t *)outptr)[0]=((uint64_t *)pktptr)[0];
      ((uint64_t *)outptr)[1]=((uint64_t *)pktptr)[1];
      rptr= (uint64_t *)(outptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
   } else
      rptr= (uint64_t *)(pktptr+ESP_HEADER_LENGTH+AES_CTR_IV_LENGTH);
   aptr=rptr;

   CVMX_M16BT_AES_ENC(in1,in2);
   d1 = dptr[0];d2 = dptr[1];
   dlen -= 16; rptr += 2; dptr += 2;
   if(in2 != UEND) {in2++;} else {in2 = 0; in1++;}
   CVMX_M16BF_AES_RESULT(out1,out2);
   while(dlen >= 16){
	CVMX_M16BT_AES_ENC(in1,in2);
	rptr[-2] = d1 ^ out1;
	rptr[-1] = d2 ^ out2;
	d1 = dptr[0];d2 = dptr[1];
	dlen -= 16; rptr += 2; dptr += 2;
	if(in2 != UEND) {in2++;} else {in2 = 0; in1++;}
        CVMX_M16BF_AES_RESULT(out1,out2);
   } 
   rptr[-2] = d1 ^ out1;
   rptr[-1] = d2 ^ out2;
 
      if(dlen) {
         CVMX_MT_AES_ENC0 (in1);
         CVMX_MT_AES_ENC1 (in2);
         CVMX_MF_AES_RESULT (enc_cntrblk[0], 0);
         CVMX_MF_AES_RESULT (enc_cntrblk[1], 1);
         for(i=0;i<dlen;i++)
            ((uint8_t *)rptr)[i]=((uint8_t *)dptr)[i] ^((uint8_t *)enc_cntrblk)[i];
      }

    *outlen=pktlen;
    return 0;
}


int AH_outbound_aes_xcbc( uint16_t auth_keylen, uint8_t *auth_key,  uint8_t *ah_header, uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen)
{
   uint64_t aes_xcbc_mac[2];

   if(pktptr == NULL || pktlen == 0  || auth_key == NULL || 
      auth_keylen ==0 ||ah_header == NULL||outlen==NULL) {
      printf("\n Wrong parameters \n");   
      return -1;
    }
    if(pktlen < IP_HEADER_LENGTH) {
      printf("\n pktlen should be atleast 20 bytes");
      return -1;
   }
   if(pktlen > (MAX_PKT_SIZE-AH_HEADER_LENGTH)) {
      printf("Packet is too big to handle \n");
      return -1;
   }

   if(outptr != NULL) {
      memcpy(outptr, pktptr, IP_HEADER_LENGTH);
      memcpy(outptr+IP_HEADER_LENGTH, ah_header, 12);
   }
   /* Generate MAC */
   
   cvm_crypto_aes_xcbc_mac ((uint64_t *) auth_key,auth_keylen, (uint64_t *) pktptr,pktlen, aes_xcbc_mac);

   if(outptr != NULL) {
      memcpy((outptr+IP_HEADER_LENGTH+12),(uint8_t *)aes_xcbc_mac,12);
      memcpy((outptr+IP_HEADER_LENGTH+AH_HEADER_LENGTH),(pktptr+IP_HEADER_LENGTH),(pktlen-IP_HEADER_LENGTH));
   }
   else {
       memmove((pktptr+IP_HEADER_LENGTH+AH_HEADER_LENGTH),(pktptr+IP_HEADER_LENGTH),(pktlen-IP_HEADER_LENGTH));
       memcpy((pktptr+IP_HEADER_LENGTH),ah_header,12);
       memcpy((pktptr+IP_HEADER_LENGTH+12),(uint8_t *)aes_xcbc_mac,12);
   }
   if(outlen)
      *outlen=pktlen+AH_HEADER_LENGTH;
   return 0;
}


int AH_inbound_aes_xcbc ( uint16_t auth_keylen, uint8_t *auth_key,  uint8_t *pktptr, uint16_t pktlen, uint8_t *outptr, uint16_t *outlen,int compdigest)
{
   uint64_t *aptr;
   uint64_t aes_xcbc_mac[2];
   uint8_t saved_ah[24];
   uint32_t i;
   if(pktptr == NULL || pktlen == 0  || 
      auth_key == NULL || auth_keylen ==0||outlen==NULL ) {
      printf("\n Wrong parameters \n");   
      return -1;
    }
    if(pktlen < (IP_HEADER_LENGTH +AH_HEADER_LENGTH )) {
      printf("Packet length is not proper \n");
      return -1;
     }

   /* setup mac args */
   memcpy(saved_ah, pktptr+IP_HEADER_LENGTH, 24);  
   if(outptr==NULL) {
      memmove(pktptr+IP_HEADER_LENGTH,pktptr+IP_HEADER_LENGTH+24,(pktlen-IP_HEADER_LENGTH-24));
      aptr = (uint64_t *)pktptr ;
   } else {
      memcpy(outptr, pktptr, IP_HEADER_LENGTH);
      memcpy(outptr+IP_HEADER_LENGTH, pktptr+IP_HEADER_LENGTH+AH_HEADER_LENGTH, pktlen-IP_HEADER_LENGTH-AH_HEADER_LENGTH);
      aptr=(uint64_t *)outptr;
   }
   pktlen-=AH_HEADER_LENGTH;

   /* Generate MAC */
   cvm_crypto_aes_xcbc_mac ((uint64_t *) auth_key,auth_keylen, (uint64_t *) aptr,pktlen, aes_xcbc_mac);

   /* compare generated MAC with received mac */
   if(compdigest) {
      if(memcmp(saved_ah+12,aes_xcbc_mac , 12)) {
         printf("\n INBOUND Mac Mismatch ");
         printf("\n Generated");
         for(i=0;i<12;i++)
            printf(" %02x",((uint8_t *)aes_xcbc_mac)[i]);
         printf("\n Expected");
         for(i=0;i<12;i++)
            printf(" %02x",saved_ah[12+i]);
         printf("\n");
         return -1;
      }
   }
   if(outlen)
      *outlen=pktlen;
   return 0;
}
