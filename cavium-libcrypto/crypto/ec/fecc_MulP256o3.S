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

        .file   1 "fecc_MulP256o3.S"

///////////////////////////////////////////////////////////////////////
// Edit History
///////////////////////////////////////////////////////////////////////
// created:     1 September 2012
// by:          Emery Davis for Cavium Networks
//
// modified:    
// by:          
// changes:     
//
///////////////////////////////////////////////////////////////////////
//
// caviumMulP256o3.S
//
// DESCRIPTION:
//
// modular multiplication of form
//
//   res3 = res1 * res2 mod p
//
// OPERATION:
//
//   res3 = (res1 * res2) mod p
//
// The intermediate result of the multiply is an 8 word (512 bit) BN.
// The result res3 is 256 bits.
//
// PROTOTYPE:
//
// void caviumMulP256o3Asm(uint64_t * res3, uint64_t * res1, uint64_t * res2);
//
// p is known for the p256 case, referred to as 'm' in the original code.
//
// HEADER FILE:
//   vanillaRegisters.h (provides simple numbered reg defs)
//
// REGISTERS USED:
//
// r4 = res3
// r5 = res1
// r6 = res2
//
// r1-r22 are used for various temporaries, but volatile r16-r22 are restored 
// early.
//
// r8-r15 contain the BN multiply result mres.
//
// FUNCTION TIMING:
//
// The entire operation consumes between 97 - 105 to 167 - 175 cycles if all branches
// are correctly predicted, depending on data.  Since this will not usually be the 
// case the actual number will increase by NB*7, with NB = [0,9].
//
// In the case of correct prediction branch latency (that is waiting for the correct
// evaluation of the branch condition) is absorbed by speculative execution along
// the SW predicted path.  This amounts to SW pipelining the condition codes in the
// final loop.
//
// The BN multiply consumes 34 (branchless) cycles.
//
// COMMENTS:
//
// The operation may be performed in place.
//
// The coding style makes a rough attempt at showing expected IPC through 
// instruction grouping.  Delay slot instructions are always 
// put with the associated branch, however.
//

#ifndef __linux__
#include <machine/asm.h>
#include <machine/regdef.h>
#else
#include "asm.h"
#endif

#include "vanillaRegisters.h"

LEAF(fecc_MulP256o3Asm)
	.set    noreorder
	.set    nomacro
	.set    noat
	.set	arch=octeon3
	.align	3

 #
 # first carry out the low 3 terms of the multiply
 #
	ld	r8,0(r6)			# r2[0]
	daddiu	sp,sp,-(12*8)			# make stack frame

	ld	r9,8(r6)			# r2[1]

	ld	r2,0(r5)			# r1[0]

	ld	r3,8(r5)			# r1[1]
	mtm0	r8,r0				# r2[0] -> m0, 

	ld	r24,16(r5)			# r1[2]
	mtm1	r9,r0				# r2[1] -> m1

	ld	r25,24(r5)			# r1[3] (r5 free)
 # 
	sd	r16,8*1(sp)			# save volatile reg
	vmulu	r8,r2,r0			# mres[0]

	sd	r17,8*2(sp)			# save volatile reg
	vmulu	r9,r3,r0			# mres[1]

	ld	r14,16(r6)			# r2[2]
	vmulu	r10,r24,r0			# t[2]

	ld	r15,24(r6)			# r2[3] 
	vmulu	r11,r25,r0			# t[3]

	sd	r18,8*3(sp)			# save volatile reg
	vmulu	r12,r0,r0			# t[4]

	sd	r19,8*4(sp)			# save volatile reg
	vmulu	r13,r0,r0			# t[5]
	
	sd	r20,8*5(sp)			# save volatile reg
	mtm0	r14,r0				# r2[2] -> m0

	sd	r21,8*6(sp)			# save volatile reg
	mtm1	r15,r0				# r2[3] -> m1

	sd	r22,8*7(sp)			# save volatile reg

	sd	r23,8*8(sp)
	vmulu	r10,r2,r10			# mres[2]

	daddiu	r5,r0,-1			# r5 = -1
	vmulu	r11,r3,r11			# mres[3]

	pref	0,0(r4)				# normal pref on dst
	vmulu	r12,r24,r12			# mres[4]

	dsrl32	r5,r5,0				# r5 = 0x0000 0000 ffff ffff 
	vmulu	r13,r25,r13			# mres[5]

	dsll32	r6,r5,0				# r6 = 0xffff ffff 0000 0000 (saves a cycle later)
	vmulu	r14,r0,r0			# mres[6]

	li	r1,2				# for 
	vmulu	r15,r0,r0			# mres[7]

 #
 # 21 cycs to here, to do multiply
 #

	mtm0	r1				# load 2 for next multiply

 #
 # now the calculation of twoS1plusS3 begins with S1[1] and S3[1], which are the
 # high and low word of mres[5] respectively.  So we can't begin until mres[5] has
 # come out of the pipe.  twoS1plusS3[0] is given by mres[4] directly.
 # The method (from macro) is comprised of:
 # 
 #       CVMX_MTM0(2); \
 #       twoS1plusS3[0] = mres[4];\
 #       CVMX_VMULU(twoS1plusS3[1],S1[1],S3[1]); \
 #       CVMX_VMULU(twoS1plusS3[2],mres[6],0); \
 #       CVMX_VMULU(twoS1plusS3[3],mres[7],mres[7]); \
 #       CVMX_VMULU(twoS1plusS3[4],0,0); \
 #


	dsll32	r19,r12,0			# mres[4]<<32 (1 stall)
	dsrl32	r20,r12,0			# mres[4]>>32

 # mres[5] now available

	and	r24,r6,r13			# S1[1] = HW(mres[5])
	and	r25,r5,r13			# S3[1] = LW(mres[5])

	vmulu	r1,r24,r25			# twoS1plusS3[1]
	dsll32	r24,r14,0			# S2[1] (=mres[6]<<32)

	vmulu	r2,r14,r0			# twoS1plusS3[2]
	and	r25,r6,r14			# HW(mres[6])

	vmulu	r3,r15,r15			# twoS1plusS3[3]
	dsrl32	r5,r13,0			# mres[5]>>32
	
	vmulu	r7,r0,r0			# twoS1plusS3[4]
	or	r25,r25,r5			# S4[1]
 #
 # the twoS2plusS4 term is calculated next, with the following definitions:
 # 
 # twoS2plusS4[0] = (mres[5]<<32) | (mres[4]>>32)
 # S2[1] = mres[6] << 32
 # S4[1] = HW(mres[6]) | mres[5]>>32
 # S2[2] = (mres[7]<<32) | (mres[6]>>32)
 # S4[2] = mres[7]
 # S2[3] = mres[7]>>32
 # S4[3] = (mres[4]<<32) | (mres[6]>>32)
 # 
 # note that m0 = 2 already.
 #
 # these 2 cycles can't be moved up because the mres are not ready early enough 

	dsll32	r17,r15,0			# (mres[7]<<32)
	dsrl32	r18,r14,0			# (mres[6]>>32)

	or	r17,r17,r18			# S2[2] = (mres[7]<<32) | (mres[6]>>32)
	or	r19,r19,r18			# S4[3] = (mres[4]<<32) | (mres[6]>>32)
	
	vmulu	r16,r24,r25			# twoS2plusS4[1]
	dsrl32	r18,r15,0			# S2[3] (= mres[7]>>32)

	vmulu	r17,r17,r15			# twoS2plusS4[2]
	dsll32	r21,r13,0			# mres[5]<<32

	vmulu	r18,r18,r19			# twoS2plusS4[3]
	li	r24,1				# for upcoming add

	vmulu	r19,r0,r0			# twoS2plusS4[4]
	or	r25,r21,r20			# twoS2plusS4[0] (=(mres[5]<<32) | (mres[4]>>32)) =D3[2])

 # does putting the mtm0 here cause a stall?
 # r5 = mres[5]>>32, r21 = mres[5]<<32, r20 = mres[4]>>32, r25 = D3[2] = twoS2plusS4[0]

	mtm0	r24				# load m0 = 1 for add
	dsll32	r6,r14,0			# r6 <- D3[3] =mres[6]<<32

 # 
 # now we can calculate the sigmaS term, which liberates the twoPlus registers
 #
 # sigmaS = twoS1plusS3 + twoS2plusS4
 #
	vmulu	r24,r12,r25			# sigmaS[0]
	dsll32	r22,r5,0			# (mres[5]>>32)<<32)

	vmulu	r1,r1,r16			# sigmaS[1]
	or	r5,r6,r5			# r5 <- D1[0] = mres[6]<<32 | mres[5]>>32; 

	vmulu	r2,r2,r17			# sigmaS[2]
	or	r22,r22,r20			# r22 <- D2[3] =((mres[5]>>32)<<32) | (mres[4]>>32)

	vmulu	r3,r3,r18			# sigmaS[3]
	dsrl32	r16,r14,0			# r16 <- D1[1] =mres[6]>>32

	vmulu	r7,r7,r19			# sigmaS[4]
	dsll32	r17,r12,0			# mres[4]<<32
 #
 # D1[3] = (mres[5]<<32) | (mres[4]<<32)>>32 
 #
 # the second part adds the mres terms
 #
	dsrl32	r17,r17,0			# (mres[4]<<32)>>32
	or	r23,r21,r20			# r21 <- D3[2] = (a[5]<<32) | (a[4]>>32)

 # sigmaS[0] ready

	vmulu	r24,r24,r8			# add mres[0] term
	dsrl32	r18,r15,0			# mres[7]>>32

	vmulu	r1,r1,r9			# add mres[1]
	or	r18,r17,r18			# r18 <- D3[1] = (mres[4]<<32) | (mres[7]>>32)

	vmulu	r2,r2,r10			# add mres[2]
	or	r17,r21,r17			# r17 <- D1[3] = (mres[5]<<32) | (mres[4]<<32)>>32

	vmulu	r3,r3,r11			# add mres[3]
	dsll32	r8,r12,0			# mres[4]<<32

	vmulu	r7,r7,r0			# collect carry bits
	dsrl32	r9,r15,0			# mres[7]>>32

 # finished w/ mres[0-3] (r8-r11) these registers available,

 # 
 # we can now proceed with the sigmaD terms, which are defined in the following way
 # 
 # D1[0] = (mres[6]<<32) | (mres[5]>>32); (r5)
 # D1[1] = (mres[6]>>32) (r16)
 # D1[2] = 0
 # D1[3] = (mres[5]<<32) | (mres[4]<<32)>>32 (r17)
 # D2[0] = mres[6];
 # D2[1] = mres[7] 
 # D2[2] = 0
 # D2[3] = ((mres[5]>>32)<<32) | (mres[4]>>32) (r22)
 #
 # sigmaD = D1 + D2
 #
	vmulu	r5,r5,r14			# sigmaD[0] 
	or	r8,r8,r9			# r8 <- [1] = (mres[4]<<32) | (mres[7]>>32)

	vmulu	r16,r16,r15			# sigmaD[1]
	dsrl32	r9,r14,0			# mres[6]>>32

	vmulu	r18,r0,r0				# sigmaD[2]
	dsll32	r10,r15,0			# mres[7]<<32

	vmulu	r17,r17,r22			# sigmaD[3]
	or	r9,r9,r10			# r9 <- D3[0] = (mres[7]<<32) | (mres[6]>>32)

	vmulu	r19,r0,r0			# sigmaD[4]
	dsrl32	r12,r12,0			# mres[4]>>32

 #
 # D3[0] = (mres[7]<<32) | (mres[6]>>32) (r9)
 # D3[1] = (mres[4]<<32) | (mres[7]>>32) (r8)
 # D3[2] = (mres[5]<<32) | (mres[4]>>32) (r23)
 # D3[3] = mres[6]<<32 (r6)
 #
 # sigmaD = sigmaD + D3
 #

	dsrl32	r14,r14,0			# mres[6]>>32
	dsll32	r12,r12,0			# D4[1] = (mres[4]>>32)<<32 = HW(mres[4])

 # sigmaD[0] ready

	vmulu	r5,r5,r9			# + D3[0] -> r5
	dsll32	r14,r14,0			# D4[3] = (mres[6]>>32)<<32 = HW(mres[6])

 #
 # reg restore starts concurrently here
 #

	vmulu	r8,r16,r8			# + D3[1] -> r8
	ld	r22,8*7(sp)			# restore volatile reg

	vmulu	r9,r18,r23			# + D3[2] -> r9
	ld	r16,8*1(sp)			# restore volatile reg

	vmulu	r10,r17,r6			# + D3[3] -> r10
	ld	r18,8*3(sp)			# restore volatile reg

	vmulu	r11,r19,r0			# + D3[4] -> r11
	ld	r17,8*2(sp)			# restore volatile reg

 # 
 # D4[0] = mres[7]
 # D4[1] = (mres[4]>>32)<<32 = HW(mres[4])
 # D4[2] = mres[5]	
 # D4[3] = (mres[6]>>32)<<32 = HW(mres[6])

 #
	ld	r19,8*4(sp)			# restore volatile reg

 # sigmaD[0] ready

	vmulu	r5,r5,r15			# + D4[0]
	ld	r20,8*5(sp)			# restore volatile reg

	vmulu	r8,r8,r12			# + D4[1]
	ld	r21,8*6(sp)			# restore volatile reg

	vmulu	r9,r9,r13			# + D4[2]
	ld	r23,8*8(sp)

	vmulu	r10,r10,r14			# + D4[3]

	vmulu	r11,r11,r0			# carry out (sD[4])
	li	r6,1				# for mtm0
	
 #
 # now rather than wait to see whether sigmaS[4] <= sigmaD[4], we proceed under the
 # assumption that this test will evaluate as false.  This is analogous to predicting
 # execution along this path.
 #
	mtm0	r6				# m0 <- 1
	daddiu	r25,r0,-1			# r25 to all f's

 # sigmaD[0] ready

	mtp0	r6				# p0 <- 1
	nor	r5,r0,r5			# ~sigmaD[0]

 # p0 stall 1 cycle

	vmulu	r12,r24,r5			# t[0] <- sigmaS*~sigmaD+1
	nor	r8,r0,r8			# ~sD[1]

	vmulu	r13,r1,r8			# t[1]
	nor	r9,r0,r9			# ~sD[2]

 # sD[4] ready, so we can do the test. Note that the slt and branch dual issue.
 # now if (sS[4] <= sD[4]) branch sS[4]=r7, sD[4]=r11
 #
 # so set if (r11<r7), if set, cond evals false
 # is sltu correct here?

	sltu	r15,r11,r7			# set if sigD[4] < sigS[4] 
	beq	r15,r0,.LS4geD4			# go and do that path if opposite true
	dsll32	r15,r25,0			# r15 = 0xffff ffff 0000 0000
	

 # 
 # here we don't have to muck with sigmaS, so continue on directly.  82 cycles to here.
 #
.Lcommon00:
	nor	r10,r0,r10			# ~sD[3]
	vmulu	r14,r2,r9			# t[2]

	nor	r11,r0,r11			# ~sD[4]
	vmulu	r10,r3,r10			# t[3] 

 # t[0-4] = r12,r13,r14,r10,r2

	li	r8,1				# initial carryu
	vmulu	r2,r7,r11			# t[4]
 #
 # now the strategy is to unwind the while loop so as to eliminate waiting 
 # for any carry out. The original loop looks like this:
 #
 #        while(1) { 
 #                CVMX_MTM0(1); 
 #                CVMX_MTP0(1); 
 #                CVMX_VMULU(v[0],u[0],~m[0]); 
 #                CVMX_VMULU(v[1],u[1],~m[1]); 
 #                CVMX_VMULU(v[2],u[2],~m[2]); 
 #                CVMX_VMULU(v[3],u[3],~m[3]); 
 #                CVMX_VMULU(v[4],u[4],~0ull); 
 #                CVMX_VMULU(carry,0,0); 
 #                doif(!carry) { 
 #                        b[0] = u[0]; 
 #                        b[1] = u[1]; 
 #                        b[2] = u[2]; 
 #                        b[3] = u[3]; 
 #                        break; \
 #                } 
 #                { 
 #                        uint64_t *t = u; 
 #                        u = v; 
 #                        v = t; 
 #                } 
 #        } 
 #
 # The idea is to rewrite this, double unrolled, to eliminate waiting for the multiplier
 # to finish the carry term.  That gives code that looks something like this in C:
 # 
 #        carryu = 1; 
 #        CVMX_VMULU(u4,v4,~u4); 
 #        while(1) { 
 #                CVMX_MTM0(1); 
 #                CVMX_MTP0(1); 
 #                b[0] = v0; 
 #                CVMX_VMULU(v0,u0,m0); 
 #                b[1] = v1; 
 #                CVMX_VMULU(v1,u1,m1); 
 #                b[2] = v2; 
 #                CVMX_VMULU(v2,u2,m2);
 #                b[3] = v3; 
 #                CVMX_VMULU(v3,u3,m3); 
 #                doif(!carryu) break; 
 #                CVMX_VMULU(v4,u4,m4);
 #                CVMX_VMULU(carryv,0,0);
 #                CVMX_MTM0(1);
 #                CVMX_MTP0(1);
 #                b[0] = u0;
 #                CVMX_VMULU(u0,v0,m0);
 #                b[1] = u1;
 #                CVMX_VMULU(u1,v1,m1);
 #                b[2] = u2;
 #                CVMX_VMULU(u2,v2,m2);
 #                b[3] = u3;
 #                CVMX_VMULU(u3,v3,m3);
 #                doif(!carryv) break;
 #                CVMX_VMULU(u4,v4,m4);
 #                CVMX_VMULU(carryu,0,0); 
 #        } 
 #
 #
 #
 # 
 # Currently ~m[2]=0xffffffffffffffff=r25, 
 # ~m[1]=0xffffffff00000000=r15. carryu(r8) starts as 1. 
 # 
 # for convenience we rename t -> u
 #
 # at this point only t and the const registers count, others can be used
 # first store is always bogus
 #

	daddu	r1,r15,r6			# r1=0xffffffff00000001
	mtm0	r6				# m0 = 1

	nor	r1,r1,r0			# r1=~m[3]=0x00000000fffffffe
	mtp0	r6				# p0 = 1 (+ stall)

 #
 # 87 - 95 cycles to here if branches predicted correctly.
 #

.Lexpandoloop:
	sd	r9,0(r4)			# conditional b[0] (u0)

	vmulu	r9,r12,r0			# v0
	sd	r11,8(r4)			# conditional b[1] (u1)

	bne	r8,r0,.Lexpando01		# early bottom exit (sounds bad)
	vmulu	r11,r13,r15			# v1

 #
 # this is the bottom condition exit from the loop and routine  All that remains to be done is fix the
 # stack pointer, (which we can do in the delay slot),  the registers are already restored.
 #
	sd	r3,16(r4)			# last b[2] (u2)

	sd	r5,24(r4)			# last b[3] (u3)
	jr	r31				# bail out the boat
	daddiu	sp,sp,12*8			# fix stack pointer

.Lexpando01:
	sd	r3,16(r4)			# conditional b[2] (u2)
	vmulu	r3,r14,r25			# v2

	sd	r5,24(r4)			# conditional b[3] (u3)
	vmulu	r5,r10,r1			# v3

	vmulu	r7,r2,r25			# v4 (~0 = -1)

	vmulu	r24,r0,r0			# carryv out
	
 # bottom part of loop 

	mtm0	r6				# m0 = 1

	mtp0	r6				# p0=1, + stall
	sd	r12,0(r4)			# cond b[0] (v0)

	vmulu	r12,r9,r0			# u0
	sd	r13,8(r4)			# cond b[1] (v1)

	bne	r24,r0,.Lexpando02		# early top exit
	vmulu	r13,r11,r15			# u1

 #
 # this is the top condition exit from the loop and routine  All that remains to be done is fix the
 # stack pointer, (which we can do in the delay slot),  the registers are already restored.
 #
	sd	r14,16(r4)			# last b[2] (v2)

	sd	r10,24(r4)			# last b[3] (v3)
	jr	r31				# bail out the boat
	daddiu	sp,sp,12*8			# fix stack pointer

.Lexpando02:
	sd	r14,16(r4)			# cond b[2] (v2)

	vmulu	r14,r3,r25			# u2
	sd	r10,24(r4)			# cond b[3] (v3)

	vmulu	r10,r5,r1			# u3

	vmulu	r2,r7,r25			# u4

	vmulu	r8,r0,r0			# carryu out

	mtm0	r6				# m0 = 1
	j	.Lexpandoloop
	mtp0	r6				# p0 = 1

 #
 # this evaluates the path where we have to recalculate the sigmaS term.  Since
 # the t terms calculation is already in progress, we'll need to bring that up
 # to the same point before joining common code.
 #
 # Here we need
 # 
 # m0 <- sigmaD[4]-sigmaS[4]+1
 #
 # sigmaS += m * (HW(sigmaD) - HW(sigmaS) + 1)
 #

.LS4geD4:
	dsubu	r12,r11,r7			# sD[4] - sS[4]
	nor	r13,r0,r15			# r13 = m[1] (0x0000 0000 ffffffff)

	daddiu	r12,r12,1			# + 1

	mtm0	r12				# m0 <- sD[4] - sS[4] + 1
	daddiu	r14,r15,1			# m[3] = 0xffff ffff 0000 0001

	vmulu	r24,r25,r24			# sS[0] 

	vmulu	r1,r13,r1			# sS[1]

	vmulu	r2,r0,r2			# sS[2]

	vmulu	r3,r14,r3			# sS[3]

	vmulu	r7,r0,r7			# sS[4]

	mtm0	r6				# m0 <- 1
						# sS[0] ready

	mtp0	r6				# p0 <- 1

	vmulu	r12,r24,r5			# t[0] <- sigmaS*~sigmaD+1

	j	.Lcommon00			# join common code
	vmulu	r13,r1,r8			# t[1]
 #
	.set    reorder
	.set    macro
	.set    at
	.end 	fecc_MulP256o3Asm
