#include <openssl/engine.h>
#include <openssl/md5.h>
#include "md5.h"

int Oct_MD5_Update(oct_md5_ctx_data *digest_data, uint64_t *data, size_t count)
{
   uint32_t pending = digest_data->pending;
   uint64_t *ptr = (uint64_t *)data;
   /* TODO : Overflow ?? */
   digest_data->total += count;

   /* Less than 64 bytes --> store it in digest_data */
   if ((pending + count) < MD5_CBLOCK) {
      memcpy(digest_data->data + pending, data, count);
      digest_data->pending += count;
      return OCT_SUCCESS;
   }

   /* Prefetch the data pointer (sure we need it soon) */
   CVMX_PREFETCH(ptr, 128);

   CVMX_MT_HSH_IV(digest_data->H1, 0);
   CVMX_MT_HSH_IV(digest_data->H2, 1);
   
   /* Load the pending bytes */
   if (pending) {
      memcpy(&digest_data->data[pending], data, MD5_CBLOCK - pending);
      ptr = (uint64_t *)(digest_data->data);

      CVMX_MT_HSH_DAT(*ptr++, 0);
      CVMX_MT_HSH_DAT(*ptr++, 1);
      CVMX_MT_HSH_DAT(*ptr++, 2);
      CVMX_MT_HSH_DAT(*ptr++, 3);
      CVMX_MT_HSH_DAT(*ptr++, 4);
      CVMX_MT_HSH_DAT(*ptr++, 5);
      CVMX_MT_HSH_DAT(*ptr++, 6);
      CVMX_MT_HSH_STARTMD5(*ptr++);
      ptr = (uint64_t *)((uint8_t *)data + (MD5_CBLOCK - pending));
      count -= (MD5_CBLOCK - pending);
   }

   /* At this stage, No more pending-- */
   /* TODO: Check unaligned load */
   while (count >= MD5_CBLOCK) {
        CVMX_MT_HSH_DAT(*ptr++, 0);
        CVMX_MT_HSH_DAT(*ptr++, 1);
        CVMX_MT_HSH_DAT(*ptr++, 2);
        CVMX_MT_HSH_DAT(*ptr++, 3);
        CVMX_MT_HSH_DAT(*ptr++, 4);
        CVMX_MT_HSH_DAT(*ptr++, 5);
        CVMX_MT_HSH_DAT(*ptr++, 6);
        CVMX_MT_HSH_STARTMD5(*ptr++);
        count -= MD5_CBLOCK;
   }

    /* Update the IVs */
    CVMX_MF_HSH_IV(digest_data->H1, 0);
    CVMX_MF_HSH_IV(digest_data->H2, 1);

   if (count) {
      memcpy(digest_data->data, ptr, count);
   }
   digest_data->pending = count;
   
   return OCT_SUCCESS;
}

static inline uint64_t swap64(uint64_t v)
{
    return ((v >> 56) |
            (((v >> 48) & 0xfful) << 8) |
            (((v >> 40) & 0xfful) << 16) |
            (((v >> 32) & 0xfful) << 24) |
            (((v >> 24) & 0xfful) << 32) |
            (((v >> 16) & 0xfful) << 40) |
            (((v >>  8) & 0xfful) << 48) |
            (((v >>  0) & 0xfful) << 56));
}

int Oct_MD5_Final(oct_md5_ctx_data *digest_data, unsigned char *md)
{
   uint64_t *ptr = (uint64_t *)digest_data->data;
   uint64_t bits = swap64((digest_data->total*8));

   digest_data->data[digest_data->pending] = 0x80;
   if (digest_data->pending == (MD5_CBLOCK - 1)) {
        ;
   } else if (digest_data->pending > (MD5_CBLOCK - 1)) {
         return OCT_FAILURE;
   } else {
   memset(&digest_data->data[digest_data->pending + 1], 0, 
          MD5_CBLOCK - digest_data->pending - 1);
   }
   
   CVMX_MT_HSH_IV(digest_data->H1, 0);
   CVMX_MT_HSH_IV(digest_data->H2, 1);

   CVMX_MT_HSH_DAT(*ptr++, 0);
   CVMX_MT_HSH_DAT(*ptr++, 1);
   CVMX_MT_HSH_DAT(*ptr++, 2);
   CVMX_MT_HSH_DAT(*ptr++, 3);
   CVMX_MT_HSH_DAT(*ptr++, 4);
   CVMX_MT_HSH_DAT(*ptr++, 5);
   CVMX_MT_HSH_DAT(*ptr++, 6);

   if (digest_data->pending < (MD5_CBLOCK - 8)) {
      CVMX_MT_HSH_STARTMD5(bits);
   } else {
      /* No space for bits. Fill another block */
      CVMX_MT_HSH_STARTMD5(*ptr);
      CVMX_MT_HSH_DATZ(0);
      CVMX_MT_HSH_DATZ(1);
      CVMX_MT_HSH_DATZ(2);
      CVMX_MT_HSH_DATZ(3);
      CVMX_MT_HSH_DATZ(4);
      CVMX_MT_HSH_DATZ(5);
      CVMX_MT_HSH_DATZ(6);
      CVMX_MF_HSH_IV(digest_data->H1, 0); // Added to increase the MD5 write stall  
                      // needed only for 63xx pass 1.x boards
      CVMX_MT_HSH_STARTMD5(bits);
   }

   /* Get the final MD51 */
   CVMX_MF_HSH_IV(*(uint64_t *)md, 0);
   CVMX_MF_HSH_IV(((uint64_t *)md)[1], 1);
   digest_data->init_done = 0;
   return OCT_SUCCESS;
}
