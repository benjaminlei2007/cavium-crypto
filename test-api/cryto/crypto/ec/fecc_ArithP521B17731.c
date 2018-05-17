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


//
	//b = (a*c) mod m
	//                //
#include <openssl/err.h>
#include "ec_lcl.h"
#include "ec_longAddition.h"

#define cm0P521 0x0000000000000001ull
#define cm1P521 0x0000000000000000ull
#define cm2P521 0x0000000000000000ull
#define cm3P521 0x0000000000000000ull
#define cm4P521 0x0000000000000000ull
#define cm5P521 0x0000000000000000ull
#define cm6P521 0x0000000000000000ull
#define cm7P521 0x0000000000000000ull
#define cm8P521 0xfffffffffffffe00ull

#define m0P521 0xffffffffffffffffull
#define m1P521 0xffffffffffffffffull
#define m2P521 0xffffffffffffffffull
#define m3P521 0xffffffffffffffffull
#define m4P521 0xffffffffffffffffull
#define m5P521 0xffffffffffffffffull
#define m6P521 0xffffffffffffffffull
#define m7P521 0xffffffffffffffffull
#define m8P521 0x00000000000001ffull


void    fecc_MulP521AsmB17731(uint64_t *b, uint64_t *res1, uint64_t *res2)
{
uint64_t ci;
register uint64_t a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16;
uint64_t A1[9]; 
register uint64_t u0,u1,u2,u3,u4,u5,u6,u7,u8;

        CVMX_MTM0(res2[0]);
        CVMX_MTM1(res2[1]);
        CVMX_MTM2(res2[2]);
	CVMX_V3MULU(a0,res1[0],0);
	CVMX_V3MULU(a1,res1[1],0);
	CVMX_V3MULU(a2,res1[2],0);
	CVMX_V3MULU(a3,res1[3],0);
	CVMX_V3MULU(a4,res1[4],0);
	CVMX_V3MULU(a5,res1[5],0);
	CVMX_V3MULU(a6,res1[6],0);
	CVMX_V3MULU(a7,res1[7],0);
	CVMX_V3MULU(a8,res1[8],0);
	CVMX_V3MULU(a9,0,0);
	CVMX_V3MULU(a10,0,0);
	CVMX_V3MULU(a11,0,0);
        CVMX_MTM0(res2[3]);
        CVMX_MTM1(res2[4]);
        CVMX_MTM2(res2[5]);
	CVMX_V3MULU(a3,res1[0],a3);
	CVMX_V3MULU(a4,res1[1],a4);
	CVMX_V3MULU(a5,res1[2],a5);
	CVMX_V3MULU(a6,res1[3],a6);
	CVMX_V3MULU(a7,res1[4],a7);
	CVMX_V3MULU(a8,res1[5],a8);
	CVMX_V3MULU(a9,res1[6],a9);
	CVMX_V3MULU(a10,res1[7],a10);
	CVMX_V3MULU(a11,res1[8],a11);
	CVMX_V3MULU(a12,0,0);
	CVMX_V3MULU(a13,0,0);
	CVMX_V3MULU(a14,0,0);
        CVMX_MTM0(res2[6]);
        CVMX_MTM1(res2[7]);
        CVMX_MTM2(res2[8]);
	CVMX_V3MULU(a6,res1[0],a6);
	CVMX_V3MULU(a7,res1[1],a7);
	CVMX_V3MULU(a8,res1[2],a8);
	CVMX_V3MULU(a9,res1[3],a9);
	CVMX_V3MULU(a10,res1[4],a10);
	CVMX_V3MULU(a11,res1[5],a11);
	A1[0] = a8>>9 |(a9<<55); 
	ci = 0;
	ADDCS(ci,u0,a0,A1[0]);
	CVMX_V3MULU(a12,res1[6],a12);
	A1[1] = a9>>9 |(a10<<55); 
	ADDCS(ci,u1,a1,A1[1]);
	CVMX_V3MULU(a13,res1[7],a13);
	A1[2] = a10>>9|(a11<<55); 
	ADDCS(ci,u2,a2,A1[2]);
	CVMX_V3MULU(a14,res1[8],a14);
	A1[3] = a11>>9|(a12<<55); 
	ADDCS(ci,u3,a3,A1[3]);
	CVMX_V3MULU(a15,0,0);
	A1[4] = a12>>9|(a13<<55); 
	ADDCS(ci,u4,a4,A1[4]);
	CVMX_V3MULU(a16,0,0);

	/*b = A0+A1 mod p*/ 
	A1[5] = a13>>9|(a14<<55); 
	ADDCS(ci,u5,a5,A1[5]);
	A1[6] = a14>>9|(a15<<55); 
	ADDCS(ci,u6,a6,A1[6]);
	A1[7] = a15>>9|(a16<<55); 
	ADDCS(ci,u7,a7,A1[7]);
	A1[8] = a16>>9; 
	ADDCS(ci,u8,((a8<<55)>>55),A1[8]);

	//
	// the Solinas reduction for P521 only requires up to 1 subtraction
	//
	if (!ci && (u8 < m8P521)) // sure we are < prime
	{
                b[0] = u0;
                b[1] = u1;
                b[2] = u2;
                b[3] = u3;
                b[4] = u4;
                b[5] = u5;
                b[6] = u6;
                b[7] = u7;
                b[8] = u8;
		return;
	}

	ci = 0;
	ADDCS(ci,b[0],u0,cm0P521);
        ADDCS(ci,b[1],u1,cm1P521);
        ADDCS(ci,b[2],u2,cm2P521);
        ADDCS(ci,b[3],u3,cm3P521);
        ADDCS(ci,b[4],u4,cm4P521);
        ADDCS(ci,b[5],u5,cm5P521);
        ADDCS(ci,b[6],u6,cm6P521);
        ADDCS(ci,b[7],u7,cm7P521);
        ADDCS(ci,b[8],u8,cm8P521);
        if (!ci)
        {
                b[0] = u0;
                b[1] = u1;
                b[2] = u2;
                b[3] = u3;
                b[4] = u4;
                b[5] = u5;
                b[6] = u6;
                b[7] = u7;
                b[8] = u8;
	}

}


void fecc_ConstMulP521AsmB17731(uint64_t *r, uint64_t *a, uint64_t c)
{
uint64_t ci;
register uint64_t u0,u1,u2,u3,u4,u5,u6,u7,u8;
uint64_t Zero = 0;

	CVMX_MTM0(c);
	CVMX_MTM1(0);
	CVMX_MTM2(0);
	CVMX_V3MULU(u0,a[0],0);
	CVMX_V3MULU(u1,a[1],0);
	CVMX_V3MULU(u2,a[2],0);
	CVMX_V3MULU(u3,a[3],0);
	CVMX_V3MULU(u4,a[4],0);
	CVMX_V3MULU(u5,a[5],0);
	CVMX_V3MULU(u6,a[6],0);
	CVMX_V3MULU(u7,a[7],0);
	CVMX_V3MULU(u8,a[8],0);

	if (u8 < m8P521)
	{
		r[0] = u0;
		r[1] = u1;
		r[2] = u2;
		r[3] = u3;
		r[4] = u4;
		r[5] = u5;
		r[6] = u6;
		r[7] = u7;
		r[8] = u8;
		return;
	}

	ci = 0;
	ADDCS(ci,r[0],u0,(u8>>9));
	ADDCS(ci,r[1],u1,0);
	ADDCS(ci,r[2],u2,0);
	ADDCS(ci,r[3],u3,0);
	ADDCS(ci,r[4],u4,0);
	ADDCS(ci,r[5],u5,0);
	ADDCS(ci,r[6],u6,0);
	ADDCS(ci,r[7],u7,0);
	ADDCS(ci,r[8],Zero,(u8 & m8P521));


}


void fecc_SubP521AsmB17731(uint64_t *r, uint64_t *a, uint64_t *b)
{
uint64_t ci,bi;

	bi = 0;
	SUBCS(bi,r[0],a[0],b[0]);
	SUBCS(bi,r[1],a[1],b[1]);
	SUBCS(bi,r[2],a[2],b[2]);
	SUBCS(bi,r[3],a[3],b[3]);
	SUBCS(bi,r[4],a[4],b[4]);
	SUBCS(bi,r[5],a[5],b[5]);
	SUBCS(bi,r[6],a[6],b[6]);
	SUBCS(bi,r[7],a[7],b[7]);
	SUBCS(bi,r[8],a[8],b[8]);

	if (bi) 
	{
	ci = 0;
	ADDCS(ci,r[0],m0P521,r[0]);
	ADDCS(ci,r[1],m1P521,r[1]);
	ADDCS(ci,r[2],m2P521,r[2]);
	ADDCS(ci,r[3],m3P521,r[3]);
	ADDCS(ci,r[4],m4P521,r[4]);
	ADDCS(ci,r[5],m5P521,r[5]);
	ADDCS(ci,r[6],m6P521,r[6]);
	ADDCS(ci,r[7],m7P521,r[7]);
	ADDCS(ci,r[8],m8P521,r[8]);
	}

}


