#include "des.h"
#include <stdio.h>

int Oct_DES_ede3_cbc_encrypt(uint64_t *inp64, uint64_t *outp64, size_t inl, uint64_t *key1,
		uint64_t *key2, uint64_t *key3, uint64_t *iv, int enc)
{
    register uint64_t i0, r0;

	CVMX_MT_3DES_KEY(*key1, 0);
    CVMX_MT_3DES_KEY(*key2, 1);
    CVMX_MT_3DES_KEY(*key3, 2);

    CVMX_MT_3DES_IV(*iv);
    CVMX_PREFETCH0(inp64);

    i0 = *inp64;

    if (enc) {

        if ((int)inl >= 16) {
            CVMX_MT_3DES_ENC_CBC(i0);
            inl -= 8;
            inp64++;
            outp64++;

            if ((int)inl >= 8) {
               i0 = inp64[0];
               CVMX_MF_3DES_RESULT(r0);
               CVMX_MT_3DES_ENC_CBC(i0);

                for (;;) {
                    outp64[-1] = r0;
                    inl -= 8;
                    inp64++;
                    outp64++;
                    i0 = *inp64;

                    if ((int)inl < 8) break;
                    CVMX_PREFETCH(inp64, 64);
                    CVMX_MF_3DES_RESULT(r0);
                    CVMX_MT_3DES_ENC_CBC(i0);
                }
            }
        }

        CVMX_MF_3DES_RESULT(r0);
        outp64[-1] = r0;

        if ((int)inl > 0) {
            if ((int)inl <= 8) {
                uint64_t r = 0;
                memcpy((uint8_t *)&r, (uint8_t *)&inp64[0], inl);
                CVMX_MT_3DES_ENC_CBC(r);
                CVMX_MF_3DES_RESULT(*outp64);
            } else {
                uint64_t r = 0;
                i0 = *inp64;
                CVMX_MT_3DES_ENC_CBC(i0);
                CVMX_MF_3DES_RESULT(*outp64);
                inp64++, outp64++;

                memcpy((uint8_t *)&r, (uint8_t *)&inp64[0], inl);
                CVMX_MT_3DES_ENC_CBC(r);
                CVMX_MF_3DES_RESULT(*outp64);
            }
        }
     } else {

        if ((int)inl >= 16) {
            CVMX_MT_3DES_DEC_CBC(i0);
            inl -= 8;
            inp64++;
            outp64++;

            if ((int)inl >= 8) {
                i0 = inp64[0];
                CVMX_MF_3DES_RESULT(r0);
                CVMX_MT_3DES_DEC_CBC(i0);

                for (;;) {
                    outp64[-1] = r0;
                    inl -= 8;
                    inp64++;
                    outp64++;
                    i0 = *inp64;

                    if ((int)inl < 8) break;

                    CVMX_PREFETCH(inp64, 64);
                    CVMX_MF_3DES_RESULT(r0);
                    CVMX_MT_3DES_DEC_CBC(i0);
                }
            }

            CVMX_MF_3DES_RESULT(r0);
            outp64[-1] = r0;
        }

        if ((int)inl > 0) {
            if ((int)inl <= 8) {
                uint64_t r = 0;
                memcpy((uint8_t *)&r, (uint8_t *)&inp64[0], inl);
                CVMX_MT_3DES_DEC_CBC(r);
                CVMX_MF_3DES_RESULT(*outp64);
            } else {
                uint64_t r = 0;
                i0 = *inp64;
                CVMX_MT_3DES_DEC_CBC(i0);
                CVMX_MF_3DES_RESULT(*outp64);
                inp64++, outp64++;

                memcpy((uint64_t *)&r, (uint8_t *)&inp64[0], inl);
                CVMX_MT_3DES_DEC_CBC(r);
                CVMX_MF_3DES_RESULT(*outp64);
            }
        }
    }

    CVMX_MF_3DES_IV(iv);
    
    return 1;
}
