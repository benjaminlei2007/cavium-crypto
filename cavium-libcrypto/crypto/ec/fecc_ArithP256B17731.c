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

#define m0 0XFFFFFFFFFFFFFFFFull
#define m1 0X00000000FFFFFFFFull
#define m2 0X0000000000000000ull
#define m3 0XFFFFFFFF00000001ull

#define cm0 0x0000000000000001ull
#define cm1 0xffffffff00000000ull
#define cm2 0xffffffffffffffffull
#define cm3 0x00000000fffffffeull


//
// this is the workaround for non-functional vmulu on O2. Bug 17731
//


void fecc_MulP256AsmB17731(uint64_t *b, uint64_t *res1, uint64_t *res2) 
	{ 
	uint64_t a[12];
	uint64_t T[4],S1[4],S2[4],S3[4],S4[4],D1[4],D2[4],D3[4],D4[4];
        uint64_t twoS1plusS3[5]; 
        uint64_t twoS2plusS4[5]; 
	uint64_t sigmaS[5], sigmaD[5];
	uint64_t ci,bi,Zero = 0;
	register uint64_t u0,u1,u2,u3,u4;
	register uint64_t v0,v1,v2,v3,v4;
 

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
		CVMX_V3MULU(a[4],0,0);
		CVMX_V3MULU(a[5],0,0);
		CVMX_V3MULU(a[6],0,0);
		CVMX_MTM0(res2[3]);
		CVMX_MTM1(0);
		CVMX_MTM2(0);
		CVMX_V3MULU(a[3],res1[0],a[3]);
		CVMX_V3MULU(a[4],res1[1],a[4]);
		CVMX_V3MULU(a[5],res1[2],a[5]);
		CVMX_V3MULU(a[6],res1[3],a[6]);
		CVMX_V3MULU(a[7],0,0);

		//
		// multiply done, next is the Solinas reduction
		//

        T[3] = a[3]; T[2] = a[2]; T[1] = a[1]; T[0] = a[0]; 
        S1[3] = a[7]; S1[2] = a[6]; S1[1] = (a[5]>>32)<<32; 
        S2[3] = a[7]>>32; S2[2] = (a[7]<<32) | (a[6]>>32); S2[1] = (a[6]<<32); 
        S3[3] = a[7]; S3[1] = (a[5]<<32)>>32; S3[0] = a[4]; 
        S4[3] = (a[4]<<32) | (a[6]>>32); S4[2] = a[7]; S4[1] = ((a[6]>>32)<<32) | (a[5]>>32); 
        D1[3] = (a[5]<<32) | (a[4]<<32)>>32; D1[1] = (a[6]>>32); D1[0] = (a[6]<<32) | (a[5]>>32); 
        D2[3] = ((a[5]>>32)<<32) | (a[4]>>32); D2[1] = a[7]; D2[0] = a[6]; 
        D3[3] = a[6]<<32; D3[2] = (a[5]<<32) | (a[4]>>32); D3[1] = (a[4]<<32) | (a[7]>>32); D3[0] = (a[7]<<32) | (a[6]>>32); 
        D4[3] = (a[6]>>32)<<32; D4[2] = a[5]; D4[1] = (a[4]>>32)<<32; D4[0] = a[7]; 

//
// do 2(S1+S3), but for now do it the slow way
//


	ci = 0;
	ADDCS(ci,twoS1plusS3[1],S1[1],S1[1]);
	ADDCS(ci,twoS1plusS3[2],S1[2],S1[2]);
	ADDCS(ci,twoS1plusS3[3],S1[3],S1[3]);
	twoS1plusS3[4] = ci;

	ci = 0;
	ADDCS(ci,twoS2plusS4[1],S2[1],S2[1]);
	ADDCS(ci,twoS2plusS4[2],S2[2],S2[2]);
	ADDCS(ci,twoS2plusS4[3],S2[3],S2[3]);
	twoS2plusS4[4] = ci;

	ci = 0;
	twoS1plusS3[0] = a[4];
	ADDCS(ci,twoS1plusS3[1],S3[1],twoS1plusS3[1]);
	ADDCS(ci,twoS1plusS3[2],Zero,twoS1plusS3[2]);
	ADDCS(ci,twoS1plusS3[3],S3[3],twoS1plusS3[3]);
	twoS1plusS3[4] += ci;

	ci = 0;
	twoS2plusS4[0] = ((a[5]<<32) | (a[4]>>32));
	ADDCS(ci,twoS2plusS4[1],S4[1],twoS2plusS4[1]);
	ADDCS(ci,twoS2plusS4[2],S4[2],twoS2plusS4[2]);
	ADDCS(ci,twoS2plusS4[3],S4[3],twoS2plusS4[3]);
	twoS2plusS4[4] += ci;

	ci = 0;
	ADDCS(ci,sigmaS[0],twoS1plusS3[0],twoS2plusS4[0]);
	ADDCS(ci,sigmaS[1],twoS1plusS3[1],twoS2plusS4[1]);
	ADDCS(ci,sigmaS[2],twoS1plusS3[2],twoS2plusS4[2]);
	ADDCS(ci,sigmaS[3],twoS1plusS3[3],twoS2plusS4[3]);
	ADDCS(ci,sigmaS[4],twoS1plusS3[4],twoS2plusS4[4]);

	ci = 0;
	ADDCS(ci,sigmaS[0],T[0],sigmaS[0]);
	ADDCS(ci,sigmaS[1],T[1],sigmaS[1]);
	ADDCS(ci,sigmaS[2],T[2],sigmaS[2]);
	ADDCS(ci,sigmaS[3],T[3],sigmaS[3]);
	sigmaS[4] += ci;

	ci = 0;
	ADDCS(ci,sigmaD[0],D1[0],D2[0]);
	ADDCS(ci,sigmaD[1],D1[1],D2[1]);
	sigmaD[2] = ci; 
	ci = 0;
	ADDCS(ci,sigmaD[3],D1[3],D2[3]);
	sigmaD[4] = ci; 

	ci = 0;
	ADDCS(ci,sigmaD[0],D3[0],sigmaD[0]);
	ADDCS(ci,sigmaD[1],D3[1],sigmaD[1]);
	ADDCS(ci,sigmaD[2],D3[2],sigmaD[2]);
	ADDCS(ci,sigmaD[3],D3[3],sigmaD[3]);
	sigmaD[4] += ci; 

	ci = 0;
	ADDCS(ci,sigmaD[0],D4[0],sigmaD[0]);
	ADDCS(ci,sigmaD[1],D4[1],sigmaD[1]);
	ADDCS(ci,sigmaD[2],D4[2],sigmaD[2]);
	ADDCS(ci,sigmaD[3],D4[3],sigmaD[3]);
	sigmaD[4] += ci; 

	if(sigmaS[4]<=sigmaD[4])
	{
                CVMX_MTM0(sigmaD[4]-sigmaS[4]+1);
		CVMX_MTM1(0);
		CVMX_MTM2(0);
                CVMX_V3MULU(sigmaS[0],m0,sigmaS[0]); 
                CVMX_V3MULU(sigmaS[1],m1,sigmaS[1]);
                CVMX_V3MULU(sigmaS[2],m2,sigmaS[2]);
                CVMX_V3MULU(sigmaS[3],m3,sigmaS[3]);
                CVMX_V3MULU(sigmaS[4],0,sigmaS[4]);
	}


		bi = 0;
		SUBCS(bi,u0,sigmaS[0],sigmaD[0]);
		SUBCS(bi,u1,sigmaS[1],sigmaD[1]);
		SUBCS(bi,u2,sigmaS[2],sigmaD[2]);
		SUBCS(bi,u3,sigmaS[3],sigmaD[3]);
		SUBCS(bi,u4,sigmaS[4],sigmaD[4]);

		while (1)
		{
			bi = 0;
			ADDCS(bi,v0,u0,cm0);
			ADDCS(bi,v1,u1,cm1);
			ADDCS(bi,v2,u2,cm2);
			ADDCS(bi,v3,u3,cm3);
			ADDCS(bi,v4,u4,~0ull);
			if (!bi)
			{
				b[0] = u0;
				b[1] = u1;
				b[2] = u2;
				b[3] = u3;
				break;
			}

			bi = 0;
			ADDCS(bi,u0,v0,cm0);
			ADDCS(bi,u1,v1,cm1);
			ADDCS(bi,u2,v2,cm2);
			ADDCS(bi,u3,v3,cm3);
			ADDCS(bi,u4,v4,~0ull);
			if (!bi)
			{
				b[0] = v0;
				b[1] = v1;
				b[2] = v2;
				b[3] = v3;
				break;
			}
		}

}


void fecc_SubP256AsmB17731(uint64_t *r, uint64_t *a, uint64_t *b)
{
uint64_t ci,bi,Zero = 0;

        bi = 0;
	SUBCS(bi,r[0],a[0],b[0]);
	SUBCS(bi,r[1],a[1],b[1]);
	SUBCS(bi,r[2],a[2],b[2]);
	SUBCS(bi,r[3],a[3],b[3]);

	if (!bi) return;

        ci = 0;
	ADDCS(ci,r[0],m0,r[0]);
	ADDCS(ci,r[1],m1,r[1]);
	ADDCS(ci,r[2],Zero,r[2]);
	ADDCS(ci,r[3],m3,r[3]);
}


