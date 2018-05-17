// Copyright (c) 2003-2014 Cavium Networks (support@cavium.com) All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation and/or
// other materials provided with the distribution.
//
// 3. Cavium Networks name may not be used to endorse or promote products derived
// from this software without specific prior written permission.
//
// This Software, including technical data, may be subject to U.S. export control laws,
// including the U.S. Export Administration Act and its associated regulations, and may be
// subject to export or import regulations in other countries. You warrant that You will comply
// strictly in all respects with all such regulations and acknowledge that you have the responsibility
// to obtain licenses to export, re-export or import the Software.
//
// TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND WITH ALL FAULTS
// AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY,
// OR OTHERWISE, WITH RESPECT TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY
// REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM
// SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT,
// FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT,
// QUIET POSSESSION OR CORRESPONDENCE TO DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE
// OF THE SOFTWARE LIES WITH YOU.
//


#include <openssl/err.h>
#include "ec_lcl.h"
#include "ec_longAddition.h"

#define m0 0x00000000FFFFFFFFull
#define m1 0xFFFFFFFF00000000ull
#define m2 0xFFFFFFFFFFFFFFFEull
#define m3 0xFFFFFFFFFFFFFFFFull
#define m4 0xFFFFFFFFFFFFFFFFull
#define m5 0xFFFFFFFFFFFFFFFFull
		
#define cm0 0xffffffff00000001ull
#define cm1 0x00000000ffffffffull
#define cm2 0x0000000000000001ull
#define cm3 0x0000000000000000ull
#define cm4 0x0000000000000000ull
#define cm5 0x0000000000000000ull


//
// this is the workaround for non-functional vmulu on O2. Bug 17731
//


void 	fecc_MulP384AsmB17731(uint64_t *b, uint64_t *res1, uint64_t *res2) 
		{ 
		uint64_t a[12];
		uint64_t S1[6],S2[6],S3[6],S4[6],S5[6],S6[6],D1[6],D2[6],D3[6]; 
        register uint64_t Zero = 0;
        uint64_t sigmaS[7],sigmaD[7]; 
        uint64_t ci,bi;
		//
		// multiply to 12 words
		//

		CVMX_MTM0(res2[0]);
		CVMX_MTM1(res2[1]);
		CVMX_MTM2(res2[2]);
		CVMX_V3MULU(a[0],res1[0],0);
		CVMX_V3MULU(a[1],res1[1],0);
		CVMX_V3MULU(a[2],res1[2],0);
		CVMX_V3MULU(a[3],res1[3],0);
		CVMX_V3MULU(a[4],res1[4],0);
		CVMX_V3MULU(a[5],res1[5],0);
		CVMX_V3MULU(a[6],0,0);
		CVMX_V3MULU(a[7],0,0);
		CVMX_V3MULU(a[8],0,0);
		CVMX_MTM0(res2[3]);
		CVMX_MTM1(res2[4]);
		CVMX_MTM2(res2[5]);
		CVMX_V3MULU(a[3],res1[0],a[3]);
		CVMX_V3MULU(a[4],res1[1],a[4]);
		CVMX_V3MULU(a[5],res1[2],a[5]);
		CVMX_V3MULU(a[6],res1[3],a[6]);
		CVMX_V3MULU(a[7],res1[4],a[7]);
		CVMX_V3MULU(a[8],res1[5],a[8]);
		CVMX_V3MULU(a[9],0,0);
		CVMX_V3MULU(a[10],0,0);
		CVMX_V3MULU(a[11],0,0);

		//
		// multiply done, next is the Solinas reduction
		//
		// broken into 32 bit words...
		//               4       3          2          1       0  
		/* S1 = (0 | 0 | 0 | 0 | 0 | A23 | A22 | A21 | 0 | 0 | 0 | 0 ) */ 

		S1[2] = (a[11]<<32)|(a[10]>>32); S1[3] = (a[11]>>32);  


	   /* S2 = (A23 | A22 | A21 | A20 | A19 | A18 | A17 | A16 | A15 | A14 | A13 | A12) */ 
		S2[0] = a[6]; S2[1] = a[7]; S2[2] = a[8]; S2[3] = a[9]; S2[4] = a[10]; S2[5] = a[11]; 
	   /* S3 = (A20 | A19 | A18 | A17 | A16 | A15 | A14 | A13 | A12 | A23 | A22 | A21) */ 
		S3[0] = a[11]<<32|a[10]>>32;S3[1] = a[6]<<32|a[11]>>32; S3[2] = a[7]<<32|a[6]>>32; 
		S3[3] = a[8]<<32|a[7]>>32; S3[4] = a[9]<<32|a[8]>>32;  S3[5] = a[10]<<32|a[9]>>32; 
	   /* S4 = (A19 | A18 | A17 | A16 | A15 | A14 | A13 | A12 | A20 | 0 | A23 | 0) */ 
		S4[0] = (a[11]>>32)<<32;S4[1] = a[10]<<32; S4[2] = a[6]; S4[3] = a[7]; S4[4] = a[8];S4[5] = a[9]; 
	   /* S5 = (0 | 0 | 0 | 0 | A23 | A22 | A21 | A20 | 0 | 0 | 0 | 0 ) */ 
		S5[2] = a[10]; S5[3] = a[11];  
	   /* S6 = (0 | 0 | 0 | 0 | 0 | 0 | A23 | A22 | A21 | 0 | 0 | A20) */ 
		S6[0] = (a[10]<<32)>>32; S6[1] = (a[10]>>32)<<32; S6[2] = a[11]; 
	   /* D1 = (A22 | A21 | A20 | A19 | A18 | A17 | A16 | A15 | A14 | A13 | A12| A23) */ 
		D1[0] = a[6]<<32|a[11]>>32; D1[1] = a[7]<<32|a[6]>>32; D1[2] = a[8]<<32|a[7]>>32; 
		D1[3] = a[9]<<32|a[8]>>32;  D1[4] = a[10]<<32|a[9]>>32;D1[5] = a[11]<<32|a[10]>>32; 
	   /* D2 = (0 | 0 | 0 | 0 | 0 | 0 | 0 | A23 | A22 | A21 | A20 | 0) */ 
		D2[0] = a[10]<<32; D2[1] = a[11]<<32|a[10]>>32; D2[2] = a[11]>>32; 
	   /* D3 = (0 | 0 | 0 | 0 | 0 | 0 | 0 | A23 | A23 | 0 | 0 | 0) */ 
		D3[1] = (a[11]>>32)<<32; D3[2] = a[11]>>32;  


		// s2+t (t is the low part of a)
		ci = 0;
		ADDCS(ci,sigmaS[0],S2[0],a[0]);
		ADDCS(ci,sigmaS[1],S2[1],a[1]);
		ADDCS(ci,sigmaS[2],S2[2],a[2]);
		ADDCS(ci,sigmaS[3],S2[3],a[3]);
		ADDCS(ci,sigmaS[4],S2[4],a[4]);
		ADDCS(ci,sigmaS[5],S2[5],a[5]);
		sigmaS[6] = ci;

		{
uint64_t s1times2[3]; // only middle terms
		s1times2[0] = S1[2]<<1;
		s1times2[1] = (S1[2]>>63) | (S1[3]<<1);
		s1times2[2] = S1[3]>>63;

		ci = 0;
		ADDCS(ci,sigmaS[2],s1times2[0],sigmaS[2]);
		ADDCS(ci,sigmaS[3],s1times2[1],sigmaS[3]);
		ADDCS(ci,sigmaS[4],s1times2[2],sigmaS[4]);
		ADDCS(ci,sigmaS[5],Zero,sigmaS[5]);
		ADDCS(ci,sigmaS[6],Zero,sigmaS[6]);
		}

		
		// + s4
		ci = 0;
		ADDCS(ci,sigmaS[0],S4[0],sigmaS[0]);
		ADDCS(ci,sigmaS[1],S4[1],sigmaS[1]);
		ADDCS(ci,sigmaS[2],S4[2],sigmaS[2]);
		ADDCS(ci,sigmaS[3],S4[3],sigmaS[3]);
		ADDCS(ci,sigmaS[4],S4[4],sigmaS[4]);
		ADDCS(ci,sigmaS[5],S4[5],sigmaS[5]);
		ADDCS(ci,sigmaS[6],Zero,sigmaS[6]);

		// + s5
		ci = 0;
		ADDCS(ci,sigmaS[2],S5[2],sigmaS[2]);
		ADDCS(ci,sigmaS[3],S5[3],sigmaS[3]);
		ADDCS(ci,sigmaS[4],Zero,sigmaS[4]);
		ADDCS(ci,sigmaS[5],Zero,sigmaS[5]);
		ADDCS(ci,sigmaS[6],Zero,sigmaS[6]);

		// + s3
		ci = 0;
		ADDCS(ci,sigmaS[0],S3[0],sigmaS[0]);
		ADDCS(ci,sigmaS[1],S3[1],sigmaS[1]);
		ADDCS(ci,sigmaS[2],S3[2],sigmaS[2]);
		ADDCS(ci,sigmaS[3],S3[3],sigmaS[3]);
		ADDCS(ci,sigmaS[4],S3[4],sigmaS[4]);
		ADDCS(ci,sigmaS[5],S3[5],sigmaS[5]);
		ADDCS(ci,sigmaS[6],Zero,sigmaS[6]);
		
		// + s6
		ci = 0;
		ADDCS(ci,sigmaS[0],S6[0],sigmaS[0]);
		ADDCS(ci,sigmaS[1],S6[1],sigmaS[1]);
		ADDCS(ci,sigmaS[2],S6[2],sigmaS[2]);
		ADDCS(ci,sigmaS[3],Zero,sigmaS[3]);
		ADDCS(ci,sigmaS[4],Zero,sigmaS[4]);
		ADDCS(ci,sigmaS[5],Zero,sigmaS[5]);
		ADDCS(ci,sigmaS[6],Zero,sigmaS[6]);
		
		// now sD terms
		ci = 0;
		ADDCS(ci,sigmaD[0],D1[0],D2[0]); 
		ADDCS(ci,sigmaD[1],D1[1],D2[1]); 
		ADDCS(ci,sigmaD[2],D1[2],D2[2]); 
		ADDCS(ci,sigmaD[3],D1[3],0); 
		ADDCS(ci,sigmaD[4],D1[4],0); 
		ADDCS(ci,sigmaD[5],D1[5],0); 
		ADDCS(ci,sigmaD[6],Zero,0); 

		ci = 0;
		ADDCS(ci,sigmaD[1],D3[1],sigmaD[1]); 
		ADDCS(ci,sigmaD[2],D3[2],sigmaD[2]); 
		ADDCS(ci,sigmaD[3],Zero,sigmaD[3]); 
		ADDCS(ci,sigmaD[4],Zero,sigmaD[4]); 
		ADDCS(ci,sigmaD[5],Zero,sigmaD[5]); 
		ADDCS(ci,sigmaD[6],Zero,sigmaD[6]); 
		
		if(sigmaS[6]<=sigmaD[6]) 
		{ 
		CVMX_MTM0(sigmaD[6]-sigmaS[6]+1); 
		CVMX_MTM1(0);
		CVMX_MTM2(0);
		CVMX_V3MULU(sigmaS[0],m0,sigmaS[0]); 
		CVMX_V3MULU(sigmaS[1],m1,sigmaS[1]); 
		CVMX_V3MULU(sigmaS[2],m2,sigmaS[2]); 
		CVMX_V3MULU(sigmaS[3],m3,sigmaS[3]); 
		CVMX_V3MULU(sigmaS[4],m4,sigmaS[4]); 
		CVMX_V3MULU(sigmaS[5],m5,sigmaS[5]); 
		CVMX_V3MULU(sigmaS[6],0ull,sigmaS[6]); 
		} 
    {
        register uint64_t u0,u1,u2,u3,u4,u5,u6;
        register uint64_t v0,v1,v2,v3,v4,v5,v6;

		bi = 0;
		SUBCS(bi,u0,sigmaS[0],sigmaD[0]);
		SUBCS(bi,u1,sigmaS[1],sigmaD[1]);
		SUBCS(bi,u2,sigmaS[2],sigmaD[2]);
		SUBCS(bi,u3,sigmaS[3],sigmaD[3]);
		SUBCS(bi,u4,sigmaS[4],sigmaD[4]);
		SUBCS(bi,u5,sigmaS[5],sigmaD[5]);
		SUBCS(bi,u6,sigmaS[6],sigmaD[6]);

		while (1)
		{
			bi = 0;
			ADDCS(bi,v0,u0,cm0);
			ADDCS(bi,v1,u1,cm1);
			ADDCS(bi,v2,u2,cm2);
			ADDCS(bi,v3,u3,cm3);
			ADDCS(bi,v4,u4,cm4);
			ADDCS(bi,v5,u5,cm5);
			ADDCS(bi,v6,u6,~0ull);
			if (!bi)
			{
				b[0] = u0;
				b[1] = u1;
				b[2] = u2;
				b[3] = u3;
				b[4] = u4;
				b[5] = u5;
				break;
			}

			bi = 0;
			ADDCS(bi,u0,v0,cm0);
			ADDCS(bi,u1,v1,cm1);
			ADDCS(bi,u2,v2,cm2);
			ADDCS(bi,u3,v3,cm3);
			ADDCS(bi,u4,v4,cm4);
			ADDCS(bi,u5,v5,cm5);
			ADDCS(bi,u6,v6,~0ull);
			if (!bi)
			{
				b[0] = v0;
				b[1] = v1;
				b[2] = v2;
				b[3] = v3;
				b[4] = v4;
				b[5] = v5;
				break;
			}
		}
    }        
}

void fecc_ConstMulP384AsmB17731(uint64_t *r, uint64_t *a, uint64_t c)
{
uint64_t bi;
register uint64_t u0,u1,u2,u3,u4,u5,u6;
register uint64_t v0,v1,v2,v3,v4,v5,v6;


	CVMX_MTM0(c);
	CVMX_MTM1(0);
	CVMX_MTM2(0);
	CVMX_V3MULU(u0,a[0],0);
	CVMX_V3MULU(u1,a[1],0);
	CVMX_V3MULU(u2,a[2],0);
	CVMX_V3MULU(u3,a[3],0);
	CVMX_V3MULU(u4,a[4],0);
	CVMX_V3MULU(u5,a[5],0);
	CVMX_V3MULU(u6,0,0);

	if (!((u5 == 0xffffffffffffffffull) || (u6 != 0)))
	{
		r[0] = u0;
		r[1] = u1;
		r[2] = u2;
		r[3] = u3;
		r[4] = u4;
		r[5] = u5;
		return;
	}

	while (1)
                {
		bi = 0;
                ADDCS(bi,v0,u0,cm0);
                ADDCS(bi,v1,u1,cm1);
                ADDCS(bi,v2,u2,cm2);
                ADDCS(bi,v3,u3,cm3);
                ADDCS(bi,v4,u4,cm4);
                ADDCS(bi,v5,u5,cm5);
                ADDCS(bi,v6,u6,~0ull);
                if (!bi)
                {
                      r[0] = u0;
                      r[1] = u1;
                      r[2] = u2;
                      r[3] = u3;
                      r[4] = u4;
                      r[5] = u5;
                      break;
                }

		bi = 0;
                ADDCS(bi,u0,v0,cm0);
                ADDCS(bi,u1,v1,cm1);
                ADDCS(bi,u2,v2,cm2);
                ADDCS(bi,u3,v3,cm3);
                ADDCS(bi,u4,v4,cm4);
                ADDCS(bi,u5,v5,cm5);
                ADDCS(bi,u6,v6,~0ull);
                if (!bi)
                {
                      r[0] = v0;
                      r[1] = v1;
                      r[2] = v2;
                      r[3] = v3;
                      r[4] = v4;
                      r[5] = v5;
                      break;
                }
                }

}


void fecc_SubP384AsmB17731(uint64_t *r, uint64_t *a, uint64_t *b)
{
uint64_t ci,bi;

        bi = 0;
	SUBCS(bi,r[0],a[0],b[0]);
	SUBCS(bi,r[1],a[1],b[1]);
	SUBCS(bi,r[2],a[2],b[2]);
	SUBCS(bi,r[3],a[3],b[3]);
	SUBCS(bi,r[4],a[4],b[4]);
	SUBCS(bi,r[5],a[5],b[5]);

	if (!bi) return;

        ci = 0;
	ADDCS(ci,r[0],m0,r[0]);
	ADDCS(ci,r[1],m1,r[1]);
	ADDCS(ci,r[2],m2,r[2]);
	ADDCS(ci,r[3],m3,r[3]);
	ADDCS(ci,r[4],m4,r[4]);
	ADDCS(ci,r[5],m5,r[5]);
}


