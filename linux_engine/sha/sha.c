#include <openssl/engine.h>
#include "sha.h"

int Oct_SHA1_Update(oct_sha_ctx_data *digest_data, uint64_t *data, size_t count)
{
   uint32_t pending = digest_data->pending;
   uint64_t *ptr = (uint64_t *)data;

   /* TODO : Overflow ?? */
   digest_data->total += count;

   /* Less than 64 bytes --> store it in digest_data */
   if ((pending + count) < SHA_CBLOCK) {
      memcpy(digest_data->data + pending, data, count);
      digest_data->pending += count;
      return OCT_SUCCESS;
   }

   /* Prefetch the data pointer (sure we need it soon) */
   CVMX_PREFETCH(ptr,128);

   CVMX_MT_HSH_IV(digest_data->H1, 0);
   CVMX_MT_HSH_IV(digest_data->H2, 1);
   CVMX_MT_HSH_IV(digest_data->H3, 2);
   
   /* Load the pending bytes */
   if (pending) {
      memcpy(&digest_data->data[pending], data, SHA_CBLOCK - pending);
      ptr = (uint64_t *)(digest_data->data);

      CVMX_MT_HSH_DAT(*ptr++, 0);
      CVMX_MT_HSH_DAT(*ptr++, 1);
      CVMX_MT_HSH_DAT(*ptr++, 2);
      CVMX_MT_HSH_DAT(*ptr++, 3);
      CVMX_MT_HSH_DAT(*ptr++, 4);
      CVMX_MT_HSH_DAT(*ptr++, 5);
      CVMX_MT_HSH_DAT(*ptr++, 6);
      CVMX_MT_HSH_STARTSHA(*ptr++);
      ptr = (uint64_t *)((uint8_t *)data + (SHA_CBLOCK - pending));
      count -= (SHA_CBLOCK - pending);
   }

   /* At this stage, No more pending */
   while (count >= SHA_CBLOCK) {
        CVMX_MT_HSH_DAT(*ptr++, 0);
        CVMX_MT_HSH_DAT(*ptr++, 1);
        CVMX_MT_HSH_DAT(*ptr++, 2);
        CVMX_MT_HSH_DAT(*ptr++, 3);
        CVMX_MT_HSH_DAT(*ptr++, 4);
        CVMX_MT_HSH_DAT(*ptr++, 5);
        CVMX_MT_HSH_DAT(*ptr++, 6);
        CVMX_MT_HSH_STARTSHA(*ptr++);
        count -= SHA_CBLOCK;
   }

    /* Update the IVs */
    CVMX_MF_HSH_IV(digest_data->H1, 0);
    CVMX_MF_HSH_IV(digest_data->H2, 1);
    CVMX_MF_HSH_IV(digest_data->H3, 2);

   if (count) {
      memcpy(digest_data->data, ptr, count);
   }
   digest_data->pending = count;

   return OCT_SUCCESS;
}

int Oct_SHA1_Final(oct_sha_ctx_data *digest_data, unsigned char *md)
{
	uint64_t *ptr = (uint64_t *)digest_data->data;
	uint64_t tmp, bits = (digest_data->total << 3);

	digest_data->data[digest_data->pending] = 0x80;
	if (digest_data->pending == (SHA_CBLOCK - 1)) {
		;
	} else if (digest_data->pending > (SHA_CBLOCK - 1)) {
		return OCT_FAILURE;
	}  else {
		memset(&digest_data->data[digest_data->pending + 1], 0, 
				SHA_CBLOCK - digest_data->pending - 1);
	}

	CVMX_MT_HSH_IV(digest_data->H1, 0);
	CVMX_MT_HSH_IV(digest_data->H2, 1);
	CVMX_MT_HSH_IV(digest_data->H3, 2);

	CVMX_MT_HSH_DAT(*ptr++, 0);
	CVMX_MT_HSH_DAT(*ptr++, 1);
	CVMX_MT_HSH_DAT(*ptr++, 2);
	CVMX_MT_HSH_DAT(*ptr++, 3);
	CVMX_MT_HSH_DAT(*ptr++, 4);
	CVMX_MT_HSH_DAT(*ptr++, 5);
	CVMX_MT_HSH_DAT(*ptr++, 6);

	if (digest_data->pending < (SHA_CBLOCK - 8)) {
		CVMX_MT_HSH_STARTSHA(bits);
	} else {
		/* No space for bits. Fill another block */
		CVMX_MT_HSH_STARTSHA(*ptr);
		CVMX_MT_HSH_DATZ(0);
		CVMX_MT_HSH_DATZ(1);
		CVMX_MT_HSH_DATZ(2);
		CVMX_MT_HSH_DATZ(3);
		CVMX_MT_HSH_DATZ(4);
		CVMX_MT_HSH_DATZ(5);
		CVMX_MT_HSH_DATZ(6);
		CVMX_MT_HSH_STARTSHA(bits);
	}

	/* Get the final SHA1 */
	CVMX_MF_HSH_IV(*(uint64_t *)md, 0);
	CVMX_MF_HSH_IV((((uint64_t *)md)[1]), 1);
	CVMX_MF_HSH_IV(tmp, 2);
	(((uint32_t *)md)[4]) = (tmp >> 32);
	digest_data->init_done = 0;

	return OCT_SUCCESS;
}

int Oct_SHA256_Update(oct_sha256_ctx_data *digest_data, uint64_t *data, size_t count)
{
   uint32_t pending = digest_data->pending;
   uint64_t *ptr;
   
   /* TODO : Overflow ?? */
   digest_data->total += count;

   /* Less than 64 bytes --> store it in digest_data */
   if ((pending + count) < SHA256_CBLOCK) {
      memcpy(digest_data->data + pending, data, count);
      digest_data->pending += count;
      return OCT_SUCCESS;
   }

   CVMX_MT_HSH_IV(digest_data->iv[0], 0);
   CVMX_MT_HSH_IV(digest_data->iv[1], 1);
   CVMX_MT_HSH_IV(digest_data->iv[2], 2);
   CVMX_MT_HSH_IV(digest_data->iv[3], 3);
 
   /* Load the pending bytes */
   if (pending) {
      memcpy(&digest_data->data[pending], data, SHA256_CBLOCK - pending);
      digest_data->pending = 0; 
      ptr = (uint64_t *)(digest_data->data);

      CVMX_MT_HSH_DAT(*ptr++, 0);
      CVMX_MT_HSH_DAT(*ptr++, 1);
      CVMX_MT_HSH_DAT(*ptr++, 2);
      CVMX_MT_HSH_DAT(*ptr++, 3);
      CVMX_MT_HSH_DAT(*ptr++, 4);
      CVMX_MT_HSH_DAT(*ptr++, 5);
      CVMX_MT_HSH_DAT(*ptr++, 6);
      CVMX_MT_HSH_STARTSHA256 (*ptr++);
      data = (uint8_t *) data + (SHA256_CBLOCK - pending);
      count -= (SHA256_CBLOCK - pending);
   }

   ptr = (uint64_t *)data;
   /* At this stage, No more pending */
   while (count >= SHA256_CBLOCK) {
        CVMX_MT_HSH_DAT(*ptr++, 0);
        CVMX_MT_HSH_DAT(*ptr++, 1);
        CVMX_MT_HSH_DAT(*ptr++, 2);
        CVMX_MT_HSH_DAT(*ptr++, 3);
        CVMX_MT_HSH_DAT(*ptr++, 4);
        CVMX_MT_HSH_DAT(*ptr++, 5);
        CVMX_MT_HSH_DAT(*ptr++, 6);
        CVMX_MT_HSH_STARTSHA256 (*ptr++);
        count -= SHA256_CBLOCK;
   }

    /* Update the IVs */
    CVMX_MF_HSH_IV(digest_data->iv[0], 0);
    CVMX_MF_HSH_IV(digest_data->iv[1], 1);
    CVMX_MF_HSH_IV(digest_data->iv[2], 2);
    CVMX_MF_HSH_IV(digest_data->iv[3], 3);

   if (count) {
      memcpy(digest_data->data, ptr, count);
      digest_data->pending = count;
   }
   
   return OCT_SUCCESS;
}

int Oct_SHA256_Final(oct_sha256_ctx_data *digest_data, unsigned char *md)
{
	uint64_t *ptr = (uint64_t *)digest_data->data;
	uint64_t  bits = (digest_data->total << 3);

	digest_data->data[digest_data->pending] = 0x80;
	if (digest_data->pending == (SHA256_CBLOCK - 1)) {
		;
	} else if (digest_data->pending > (SHA256_CBLOCK - 1)) {
		return OCT_FAILURE;
	}  else {
		memset(&digest_data->data[digest_data->pending + 1], 0, 
				SHA256_CBLOCK - digest_data->pending - 1);
	}

	CVMX_MT_HSH_IV(digest_data->iv[0], 0);
	CVMX_MT_HSH_IV(digest_data->iv[1], 1);
	CVMX_MT_HSH_IV(digest_data->iv[2], 2);
	CVMX_MT_HSH_IV(digest_data->iv[3], 3);

	CVMX_MT_HSH_DAT(*ptr++, 0);
	CVMX_MT_HSH_DAT(*ptr++, 1);
	CVMX_MT_HSH_DAT(*ptr++, 2);
	CVMX_MT_HSH_DAT(*ptr++, 3);
	CVMX_MT_HSH_DAT(*ptr++, 4);
	CVMX_MT_HSH_DAT(*ptr++, 5);
	CVMX_MT_HSH_DAT(*ptr++, 6);

	if (digest_data->pending < (SHA256_CBLOCK - 8)) {
		CVMX_MT_HSH_STARTSHA256 (bits);
	} else {
		/* No space for bits. Fill another block */
		CVMX_MT_HSH_STARTSHA256 (*ptr);
		CVMX_MT_HSH_DATZ(0);
		CVMX_MT_HSH_DATZ(1);
		CVMX_MT_HSH_DATZ(2);
		CVMX_MT_HSH_DATZ(3);
		CVMX_MT_HSH_DATZ(4);
		CVMX_MT_HSH_DATZ(5);
		CVMX_MT_HSH_DATZ(6);
		CVMX_MT_HSH_STARTSHA256 (bits);
	}

	/* Get the final SHA1 */
	CVMX_MF_HSH_IV(*(uint64_t *)md, 0);
	CVMX_MF_HSH_IV((((uint64_t *)md)[1]), 1);
	CVMX_MF_HSH_IV((((uint64_t *)md)[2]), 2);

	if (digest_data->sha256) {
		CVMX_MF_HSH_IV (((uint64_t *) md)[3], 3);
	} else {
		CVMX_MF_HSH_IV (digest_data->iv[3], 3);
		memcpy (md + 24, &digest_data->iv[3], 4);
	}

	return OCT_SUCCESS;
}

int Oct_SHA512_Update(oct_sha512_ctx_data *digest_data, uint64_t *data, size_t count)
{
   uint32_t pending = digest_data->pending;
   uint64_t *ptr; 

   /* TODO : Overflow ?? */
   digest_data->total += count;

   /* Less than 128 bytes --> store it in digest_data */
   if ((pending + count) < SHA512_CBLOCK) {
      memcpy(digest_data->data + pending, data, count);
      digest_data->pending += count;
      return OCT_SUCCESS;
   }

   CVMX_MT_HSH_IVW(digest_data->iv[0], 0);
   CVMX_MT_HSH_IVW(digest_data->iv[1], 1);
   CVMX_MT_HSH_IVW(digest_data->iv[2], 2);
   CVMX_MT_HSH_IVW(digest_data->iv[3], 3);
   CVMX_MT_HSH_IVW(digest_data->iv[4], 4);
   CVMX_MT_HSH_IVW(digest_data->iv[5], 5);
   CVMX_MT_HSH_IVW(digest_data->iv[6], 6);
   CVMX_MT_HSH_IVW(digest_data->iv[7], 7);

   /* Load the pending bytes */
   if (pending) {
      memcpy(&digest_data->data[pending], data, SHA512_CBLOCK - pending);
      digest_data->pending = 0; 
      ptr = (uint64_t *)(digest_data->data);

      CVMX_MT_HSH_DATW(*ptr++, 0);
      CVMX_MT_HSH_DATW(*ptr++, 1);
      CVMX_MT_HSH_DATW(*ptr++, 2);
      CVMX_MT_HSH_DATW(*ptr++, 3);
      CVMX_MT_HSH_DATW(*ptr++, 4);
      CVMX_MT_HSH_DATW(*ptr++, 5);
      CVMX_MT_HSH_DATW(*ptr++, 6);
      CVMX_MT_HSH_DATW(*ptr++, 7);
      CVMX_MT_HSH_DATW(*ptr++, 8);
      CVMX_MT_HSH_DATW(*ptr++, 9);
      CVMX_MT_HSH_DATW(*ptr++, 10);
      CVMX_MT_HSH_DATW(*ptr++, 11);
      CVMX_MT_HSH_DATW(*ptr++, 12);
      CVMX_MT_HSH_DATW(*ptr++, 13);
      CVMX_MT_HSH_DATW(*ptr++, 14);
      CVMX_MT_HSH_STARTSHA512 (*ptr++);

      data = (uint8_t *) data + (SHA512_CBLOCK - pending);
      count -= (SHA512_CBLOCK - pending);
   }

   ptr = (uint64_t *)data;
   /* At this stage, No more pending */
   while (count >= SHA512_CBLOCK) {
      CVMX_MT_HSH_DATW(*ptr++, 0);
      CVMX_MT_HSH_DATW(*ptr++, 1);
      CVMX_MT_HSH_DATW(*ptr++, 2);
      CVMX_MT_HSH_DATW(*ptr++, 3);
      CVMX_MT_HSH_DATW(*ptr++, 4);
      CVMX_MT_HSH_DATW(*ptr++, 5);
      CVMX_MT_HSH_DATW(*ptr++, 6);
      CVMX_MT_HSH_DATW(*ptr++, 7);
      CVMX_MT_HSH_DATW(*ptr++, 8);
      CVMX_MT_HSH_DATW(*ptr++, 9);
      CVMX_MT_HSH_DATW(*ptr++, 10);
      CVMX_MT_HSH_DATW(*ptr++, 11);
      CVMX_MT_HSH_DATW(*ptr++, 12);
      CVMX_MT_HSH_DATW(*ptr++, 13);
      CVMX_MT_HSH_DATW(*ptr++, 14);
      CVMX_MT_HSH_STARTSHA512 (*ptr++);

      count -= SHA512_CBLOCK;
   }

    /* Update the IVs */
    CVMX_MF_HSH_IVW(digest_data->iv[0], 0);
    CVMX_MF_HSH_IVW(digest_data->iv[1], 1);
    CVMX_MF_HSH_IVW(digest_data->iv[2], 2);
    CVMX_MF_HSH_IVW(digest_data->iv[3], 3);
    CVMX_MF_HSH_IVW(digest_data->iv[4], 4);
    CVMX_MF_HSH_IVW(digest_data->iv[5], 5);
    CVMX_MF_HSH_IVW(digest_data->iv[6], 6);
    CVMX_MF_HSH_IVW(digest_data->iv[7], 7);

   if (count) {
      memcpy(digest_data->data, ptr, count);
      digest_data->pending = count;
   }
   
   return OCT_SUCCESS;
}

#define uint64_t_mul(abhi,ablo,a,b) \
{\
    asm volatile("dmultu %[rs],%[rt]" :: [rs] "d" (a), [rt] "d" (b) );\
    asm volatile("mfhi %[rd] " : [rd] "=d" (abhi) : );\
    asm volatile("mflo %[rd] " : [rd] "=d" (ablo) : );\
} 

int Oct_SHA512_Final(oct_sha512_ctx_data *digest_data, unsigned char *md)
{
   uint64_t *ptr = (uint64_t *)digest_data->data;

   digest_data->data[digest_data->pending] = 0x80;
   if (digest_data->pending == (SHA512_CBLOCK - 1)) {
         ;
   } else if (digest_data->pending > (SHA512_CBLOCK -1)) {
         return OCT_FAILURE;
   }  else {
   memset(&digest_data->data[digest_data->pending + 1], 0, 
          SHA512_CBLOCK - digest_data->pending - 1);
   }
   
   CVMX_MT_HSH_IVW(digest_data->iv[0], 0);
   CVMX_MT_HSH_IVW(digest_data->iv[1], 1);
   CVMX_MT_HSH_IVW(digest_data->iv[2], 2);
   CVMX_MT_HSH_IVW(digest_data->iv[3], 3);
   CVMX_MT_HSH_IVW(digest_data->iv[4], 4);
   CVMX_MT_HSH_IVW(digest_data->iv[5], 5);
   CVMX_MT_HSH_IVW(digest_data->iv[6], 6);
   CVMX_MT_HSH_IVW(digest_data->iv[7], 7);

   CVMX_MT_HSH_DATW(*ptr++, 0);
   CVMX_MT_HSH_DATW(*ptr++, 1);
   CVMX_MT_HSH_DATW(*ptr++, 2);
   CVMX_MT_HSH_DATW(*ptr++, 3);
   CVMX_MT_HSH_DATW(*ptr++, 4);
   CVMX_MT_HSH_DATW(*ptr++, 5);
   CVMX_MT_HSH_DATW(*ptr++, 6);
   CVMX_MT_HSH_DATW(*ptr++, 7);
   CVMX_MT_HSH_DATW(*ptr++, 8);
   CVMX_MT_HSH_DATW(*ptr++, 9);
   CVMX_MT_HSH_DATW(*ptr++, 10);
   CVMX_MT_HSH_DATW(*ptr++, 11);
   CVMX_MT_HSH_DATW(*ptr++, 12);
   CVMX_MT_HSH_DATW(*ptr++, 13);

   if (digest_data->pending < (SHA512_CBLOCK - 16)) {
      uint64_t ab[2];
      uint64_t_mul (ab[0], ab[1], digest_data->total, 8);
      CVMX_MT_HSH_DATW (ab[0], 14);
      CVMX_MT_HSH_STARTSHA512 (ab[1]);
   } else {
      CVMX_MT_HSH_DATW (*ptr++, 14);
      CVMX_MT_HSH_STARTSHA512 (*ptr);
      /* Another block was needed */
      CVMX_MT_HSH_DATWZ (0);
      CVMX_MT_HSH_DATWZ (1);
      CVMX_MT_HSH_DATWZ (2);
      CVMX_MT_HSH_DATWZ (3);
      CVMX_MT_HSH_DATWZ (4);
      CVMX_MT_HSH_DATWZ (5);
      CVMX_MT_HSH_DATWZ (6);
      CVMX_MT_HSH_DATWZ (7);
      CVMX_MT_HSH_DATWZ (8);
      CVMX_MT_HSH_DATWZ (9);
      CVMX_MT_HSH_DATWZ (10);
      CVMX_MT_HSH_DATWZ (11);
      CVMX_MT_HSH_DATWZ (12);
      CVMX_MT_HSH_DATWZ (13);
      uint64_t ab[2];
      uint64_t_mul (ab[0], ab[1], digest_data->total, 0x8ull);
      CVMX_MT_HSH_DATW (ab[0], 14);
      CVMX_MT_HSH_STARTSHA512 (ab[1]);
 
   }

   /* Get the final SHA1 */
   CVMX_MF_HSH_IVW(*(uint64_t *)md, 0);
   CVMX_MF_HSH_IVW((((uint64_t *)md)[1]), 1);
   CVMX_MF_HSH_IVW((((uint64_t *)md)[2]), 2);
   CVMX_MF_HSH_IVW (((uint64_t *) md)[3], 3);
   CVMX_MF_HSH_IVW (((uint64_t *) md)[4], 4);
   CVMX_MF_HSH_IVW (((uint64_t *) md)[5], 5);

   if (digest_data->sha512) {
      CVMX_MF_HSH_IVW (((uint64_t *) md)[6], 6);
      CVMX_MF_HSH_IVW (((uint64_t *) md)[7], 7);
   }
   return OCT_SUCCESS;
}
