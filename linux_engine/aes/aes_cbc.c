#include "aes.h"
#include <stdio.h>
#include "cryptolinux.h"

int Oct_AES_cbc_encrypt(uint64_t *inp64, uint64_t *outp64, size_t inl, uint64_t *key,
		int key_len, uint64_t *iv, int enc)
{
    register uint64_t i0, i1, r0, r1;

	CVMX_MT_AES_IV(iv[0], 0);
    CVMX_MT_AES_IV(iv[1], 1);

    CVMX_MT_AES_KEY(key[0], 0);
    CVMX_MT_AES_KEY(key[1], 1);
    CVMX_MT_AES_KEY(key[2], 2);
    CVMX_MT_AES_KEY(key[3], 3);
    CVMX_MT_AES_KEYLENGTH(key_len/8 - 1);

    CVMX_PREFETCH0(inp64);

    i0 = inp64[0];
    i1 = inp64[1];
   
    if (enc) {
        if ((int)inl >= 32) {
            CVMX_MT_AES_ENC_CBC0(i0);
            CVMX_MT_AES_ENC_CBC1(i1);
            inl -= 16;
            inp64  += 2;
            outp64 += 2;

            if ((int)inl >= 16) {
                CVMX_MF_AES_RESULT(r0, 0);
                CVMX_MF_AES_RESULT(r1, 1);
                i0 = inp64[0];
                i1 = inp64[1];
                CVMX_MT_AES_ENC_CBC0(i0);
                CVMX_MT_AES_ENC_CBC1(i1);

                for (;;) {
                    outp64[-2] = r0;
                    outp64[-1] = r1;
                    outp64 += 2;
                    inp64 += 2;
                    inl -= 16;
                    i0 = inp64[0];
                    i1 = inp64[1];

                    if ((int)inl < 16) break;

                    CVMX_PREFETCH(inp64, 64);
                    CVMX_MF_AES_RESULT(r0, 0);
                    CVMX_MF_AES_RESULT(r1, 1);
                    CVMX_MT_AES_ENC_CBC0(i0);
                    CVMX_MT_AES_ENC_CBC1(i1);
                }
            }

            CVMX_MF_AES_RESULT(r0, 0);
            CVMX_MF_AES_RESULT(r1, 1);
            outp64[-2] = r0;
            outp64[-1] = r1;
        }

        if ((int)inl > 0) {
            if ((int)inl <= 16) {
                uint64_t in64[2] = { 0, 0 };
                memcpy(in64, inp64, inl);
                CVMX_MT_AES_ENC_CBC0(in64[0]);
                CVMX_MT_AES_ENC_CBC1(in64[1]);
                CVMX_MF_AES_RESULT(r0, 0);
                CVMX_MF_AES_RESULT(r1, 1);
                outp64[0] = r0;
                outp64[1] = r1;
            } else {
                uint64_t in64[2] = { 0, 0 };
                CVMX_MT_AES_ENC_CBC0(i0);
                CVMX_MT_AES_ENC_CBC1(i1);
                CVMX_MF_AES_RESULT(r0, 0);
                CVMX_MF_AES_RESULT(r1, 1);
                inl -= 16;
                outp64[0] = r0;
                outp64[1] = r1;
                inp64 += 2;
                outp64 += 2;
                memcpy(in64, inp64, inl);
                CVMX_MT_AES_ENC_CBC0(in64[0]);
                CVMX_MT_AES_ENC_CBC1(in64[1]);
                CVMX_MF_AES_RESULT(r0, 0);
                CVMX_MF_AES_RESULT(r1, 1);
                outp64[0] = r0;
                outp64[1] = r1;
            }
        }
    } else {
        if ((int)inl >= 32) {
            CVMX_MT_AES_DEC_CBC0(i0);
            CVMX_MT_AES_DEC_CBC1(i1);
            inp64 += 2;
            outp64 += 2;
            inl -= 16;

            if ((int)inl >= 16) {
                i0 = inp64[0];
                i1 = inp64[1];
                CVMX_MF_AES_RESULT(r0, 0);
                CVMX_MF_AES_RESULT(r1, 1);
                CVMX_MT_AES_DEC_CBC0(i0);
                CVMX_MT_AES_DEC_CBC1(i1);

                for (;;) {
                    outp64[-2] = r0;
                    outp64[-1] = r1;
                    outp64 += 2;
                    inp64 += 2;
                    inl -= 16;
                    i0 = inp64[0];
                    i1 = inp64[1];

                    if((int)inl < 16) break;

                    CVMX_PREFETCH(inp64, 64);
                    CVMX_MF_AES_RESULT(r0, 0);
                    CVMX_MF_AES_RESULT(r1, 1);
                    CVMX_MT_AES_DEC_CBC0(i0);
                    CVMX_MT_AES_DEC_CBC1(i1);
               }
            }

            CVMX_MF_AES_RESULT(r0, 0);
            CVMX_MF_AES_RESULT(r1, 1);
            outp64[-2] = r0;
            outp64[-1] = r1;
        }

        if ((int)inl > 0) {
            uint64_t in64[2] = { 0, 0 };
            memcpy((uint8_t *)in64, (uint8_t *)inp64, inl);
            CVMX_MT_AES_DEC_CBC0(in64[0]);
            CVMX_MT_AES_DEC_CBC1(in64[1]);
            CVMX_MF_AES_RESULT(r0, 0);
            CVMX_MF_AES_RESULT(r1, 1);
            outp64[0] = r0;
            outp64[1] = r1;
        }
    }

   CVMX_MF_AES_IV(iv[0], 0);
   CVMX_MF_AES_IV(iv[1], 1);

   return OCT_SUCCESS;
}
