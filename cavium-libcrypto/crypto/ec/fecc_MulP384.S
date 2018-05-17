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

        .file   1 "fecc_MulP384.S"

///////////////////////////////////////////////////////////////////////
// Edit History
///////////////////////////////////////////////////////////////////////
// created:     17 January 2012
// by:          Emery Davis for Cavium Networks
//
// modified:    
// by:          
// changes:     
//
///////////////////////////////////////////////////////////////////////
//
// caviumMulP384.S
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
// The intermediate result of the multiply is an 12 word (768 bit) BN.
// The result res3 is 384 bits.
//
// PROTOTYPE:
//
// void caviumMulP384Asm(uint64_t * res3, uint64_t * res1, uint64_t * res2);
//
// p is known for the p384 case, referred to as 'm' in the original code.
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
// r1-r31 are used for various temporaries, with the exception of of r26, r27 and r29.
// All are restored early except for r16-r19 which are required for the unrolled loop
// operation, and are restored at the end.
//
// r8-r19 contain the BN multiply result mres (the 'a's) and other register usage is
// described inline.
//
// FUNCTION TIMING:
//
// The entire operation consumes between 163 - 174 to 203 - 214 cycles if all branches
// are correctly predicted, depending on data.  Since this will not usually be the 
// case the actual number will increase by NB*7, with NB = [0,5].
//
// In the case of correct prediction branch latency (that is waiting for the correct
// evaluation of the branch condition) is absorbed by speculative execution along
// the SW predicted path.  This amounts to SW pipelining the condition codes in the
// final loop.
//
// The BN multiply consumes 63 (branchless) cycles.
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

LEAF(fecc_MulP384Asm)
	.set    noreorder
	.set    nomacro
	.set    noat
	.align	3

#define stackFrame	(16*8)
#define regBase		(0*8)
	
 #
 # first carry out the low 3 terms of the multiply
 #
	ld	r8,0*8(r6)			# r2[0]

	ld	r9,1*8(r6)			# r2[1]
	daddiu	sp,sp,-stackFrame			# make stack frame

	ld	r10,2*8(r6)			# r2[2]

	ld	r2,0*8(r5)			# r1[0]
	mtm0	r8				# r2[0] -> m0

	ld	r3,1*8(r5)			# r1[1]
	mtm1	r9				# r2[1] -> m1

	ld	r24,2*8(r5)			# r1[2]
	mtm2	r10				# r2[2] -> m2

	ld	r25,3*8(r5)			# r1[3] (r5 free)
	v3mulu	r8,r2,r0			# first 4 word terms, r8 = mres[0]

	sd	r16,(regBase+8*1)(sp)		# save volatile reg
	sd	r17,(regBase+8*2)(sp)		# save volatile reg

	v3mulu	r9,r3,r0			# mul intermediate w[1-4], accum w[1-3], r9 = mres[1]

	sd	r18,(regBase+8*3)(sp)		# save volatile reg
	sd	r19,(regBase+8*4)(sp)		# save volatile reg

	v3mulu	r10,r24,r0			# mul intermediate w[2-5], accum w[2-4], r10 = mres[2]

	sd	r20,(regBase+8*5)(sp)		# save volatile reg
	sd	r21,(regBase+8*6)(sp)		# save volatile reg

	ld	r2,4*8(r5)			# r1[4]
	v3mulu	r11,r25,r0			# mul intermediate w[3-6], accum w[3-5], r11 = mres[3] 

	sd	r22,(regBase+8*7)(sp)		# save volatile reg
	sd	r23,(regBase+8*8)(sp)		# save volatile reg

	ld	r3,5*8(r5)			# r1[5]
	v3mulu	r12,r2,r0			# mul intermediate w[4-7], accum w[4-6], r12 = mres[4]

	sd	r28,(regBase+8*10)(sp)		# save volatile reg
	sd	r30,(regBase+8*11)(sp)		# save volatile reg

	v3mulu	r13,r3,r0			# mul intermediate w[5-8], accum w[5-7], r13 = mres[5]

	ld	r1,3*8(r6)			# r2[3]
	v3mulu	r14,r0,r0			# r14 = mres[6]

	sd	r31,(regBase+8*12)(sp)		# save volatile reg

	ld	r2,4*8(r6)			# r2[4]
	v3mulu	r15,r0,r0			# r15 = mres[7]

	ld	r3,5*8(r6)			# r2[5]
	v3mulu	r16,r0,r0			# r16 = mres[8]

	ld	r24,0*8(r5)			# r1[0]
	mtm0	r1				# m0 <- r2[3]

	ld	r25,1*8(r5)			# r1[1]
	mtm1	r2				# m1 <- r2[4]

	ld	r1,2*8(r5)			# r1[2]
	mtm2	r3				# m2 <- r2[5]

	ld	r2,3*8(r5)			# r1[3]
	v3mulu	r11,r24,r11			# mres[3]

	v3mulu	r12,r25,r12			# mres[4]

	ld	r24,4*8(r5)			# r1[4]
	v3mulu	r13,r1,r13			# mres[5]

	ld	r25,5*8(r5)			# r1[5]
	v3mulu	r14,r2,r14			# mres[6]

	v3mulu	r15,r24,r15			# mres[7]
 	pref	0,0(r4)				# normal pref on dst

	v3mulu	r16,r25,r16			# mres[8]

	v3mulu	r17,r0,r0			# mres[9]

	v3mulu	r18,r0,r0			# mres[10]
        li	r24,1 

	v3mulu	r19,r0,r0			# mres[11]

 #
 # mul done, a := r8 - r19, 63 cycles for multiply part (to mtm0 dispatch).
 #
 # instead of (2*S1 + T) + S2, do (S2 + T) + (2*S1), absorb another mtm0 to kill wait
 #
 # S2 = (A23 | A22 | A21 | A20 | A19 | A18 | A17 | A16 | A15 | A14 | A13 | A12) in 32 bit
 # T = (a11 | a10 | a9 | a8 | a7 | a6 | a5 | a4 | a3 | a2 | a1 | a0 )
 #

	mtm0	r24				# m0 <- 1
	dsrl32	r23,r14,0			# hw(a[6]) (a13)

	vmulu	r1,r14,r8			# sS[0] = s2[0] + t[0] 
	dsll32	r28,r15,0			# lw(a[7]) (a14)

	vmulu	r2,r15,r9			# sS[1] = s2[1] + t[1] + c
	or	r23,r23,r28			# r23 = a14 || a13 (s3[2], d1[1])

	vmulu	r3,r16,r10			# sS[2] = s2[2] + t[2] + c
	dsrl32	r28,r18,0			# hw(a[10]) (a21)

	vmulu	r5,r17,r11			# sS[3] = s2[3] + t[3] + c
	dsll32	r21,r19,0			# lw(a11) || 0

	vmulu	r6,r18,r12			# sS[4] = s2[4] + t[4] + c
	dsrl32	r22,r18,0			# 0 || hw(a10)

	vmulu	r7,r19,r13			# sS[5] = s2[5] + t[5] + c
        li	r24,2 				# for mul add 

	vmulu	r20,r0,r0			# sS[6] =  c
	or	r21,r21,r22			# r21 = s1[2] = lw(a11) || hw (a10)
 #
 # add 2*s1 with
 #
 # s1 = (0 | 0 | 0 | 0 | 0 | a23 | a22 | a21 | 0 | 0 | 0 | 0)
 # 
 # this means s1[2] = lw(a11) || hw (a10), which is accomplished with an 
 # unaligned load, latency 4 cycles.
 #

	mtm0	r24				# m0 <- 2
	dsrl32	r22,r19,0			# r22 = s1[3] = 0 || hw (a11)
	
	vmulu	r1,r0,r1			# + s1[0]
	dsll32	r30,r19,0			# lw(a[11]) (a22)

	vmulu	r2,r0,r2			# + s1[1]
	or	r28,r28,r30			# r28 = a22 || a21 (s3[0], d1[5])

	vmulu	r3,r21,r3			# + s1[2]

	vmulu	r5,r22,r5			# + s1[3]
	dsrl32	r21,r19,0			# 0 || a23

	vmulu	r6,r0,r6			# + s1[4]
	dsll32	r21,r21,0			# r21 = a23 || 0 = s4[0]

	vmulu	r7,r0,r7			# + s1[5]
	li	r24,1				# for mtm0

	vmulu	r20,r0,r20			# + s1[6]
	dsll32	r22,r18,0			# r22 = (a20 || 0) = s4[1]

 # 
 # add s4 terms, with
 #
 # s4 = (a19 | a18 | a17 | a16 | a15 | a14 | a12 | a20 | 0 | a23 | 0)
 # 

	mtm0	r24				# m0 <- 1
	dsrl32	r30,r19,0			# hw(a[11]) (a23)

	vmulu	r1,r1,r21			# + s4[0]
	dsll32	r31,r14,0			# lw(a[6]) (a12)

	vmulu	r2,r2,r22			# + s4[1]
	or	r30,r30,r31			# r30 = a12 || a23 (s3[1], d1[0])

	vmulu	r3,r3,r14			# + s4[2]
	dsrl32	r31,r15,0			# hw(a[7]) (a15)

	vmulu	r5,r5,r15			# + s4[3]
	dsll32	r25,r16,0			# lw(a[8]) (a16)

	vmulu	r6,r6,r16			# + s4[4]
	or	r31,r31,r25			# r31 = a16 || a15 (s3[3], d1[2]

	vmulu	r7,r7,r17			# + s4[5]
	dsrl32	r25,r16,0			# hw(a[8]) (a17)

	vmulu	r20,r20,r0			# + c
	dsll32	r24,r17,0			# lw(a[9]) (a18)

 # 
 # add s5 terms, no calculation necessary since
 # 
 # s5 = (0 | 0 | 0 | 0 | a23 | a22 | a21 | a20 | 0 | 0 | 0 | 0)
 # 
 # there is no need to add 0 to the lower terms, leaving a 2 cycle stall
 # before sS[2] is ready

	or	r25,r25,r24			# r25 = a18 || a17 (s3[4], d1[3])
	dsrl32	r24,r17,0			# hw(a[9]) (a19)

	dsll32	r21,r18,0			# lw(a[10]) (a20)
	or	r24,r24,r21			# r24 = a20 || a19 (s3[5], d1[4])

	vmulu	r3,r3,r18			# + s5[2]

	vmulu	r5,r5,r19			# + s5[3]

	vmulu	r6,r6,r0			# accum sS[4]

	vmulu	r7,r7,r0			# accum sS[5]

	vmulu	r20,r20,r0			# accum sS[6]

 #
 # add s3 terms, which are the same as d1 (shifted):
 # 
 # s3 = (a20 | a19 | a18 | a17 | a16 | a15 | a14 | a13 | a12 | a23 | a22 | a21)
 # 

	vmulu	r1,r1,r28			# + s3[0]
	dsll32	r10,r18,0			# a20 || 0 (=d2[0] (r10))

	vmulu	r2,r2,r30			# + s3[1]
	dsrl32	r8,r10,0			# r8 = 0 || a20 (s6[0])

	vmulu	r3,r3,r23			# + s3[2]
	dsrl32	r9,r18,0			# 0 || a21

	vmulu	r5,r5,r31			# + s3[3]
	dsll32	r9,r9,0				# r9 = a21 || 0 (s6[1])

	vmulu	r6,r6,r25			# + s3[4]

	vmulu	r7,r7,r24			# + s3[5]

	vmulu	r20,r20,r0			# + c

 # 
 # finally complete sigmaS with the s6 terms, defined as
 #
 # s6 = (0 | 0 | 0 | 0 | 0 | 0 | a23 | a22 | a21 | 0 | 0 | a20)
 #
 # 4 inst + 4 (D2) + 3 (d3)


	vmulu	r1,r1,r8			# + s6[0]
	dsll32	r11,r19,0			# a22 || 0

	vmulu	r2,r2,r9			# + s6[1]
	dsrl32	r12,r18,0			# 0 || a21

	vmulu	r3,r3,r19			# + s6[2] (=a[11] (a23 || a22))
	or	r11,r11,r12			# r11 = a22 || a21 d2[1]

	vmulu	r5,r5,r0			# + s6[3] (=0)
	dsrl32	r12,r19,0			# r12 = 0 || a23 (d2[2],d3[2]

	vmulu	r6,r6,r0			# + s6[4] (=0)
	dsll32	r13,r12,0			# r13 = a23 || 0 (d3[1])

	vmulu	r7,r7,r0			# + s6[5] (=0)
	ld	r22,(regBase+8*7)(sp)		# restore volatile reg

	vmulu	r20,r20,r0			# + c

 # 
 # now ready to add up the sigmaD terms.  We already have d1. d2 is defined as
 # 
 # d2 = (0 | 0 | 0 | 0 | 0 | 0 | 0 | a23 | a22 | a21 | a20 | 0)
 # 

	vmulu	r14,r30,r10			# d1[0] + d2[0]
	ld	r30,(regBase+8*11)(sp)		# restore volatile reg

	vmulu	r15,r23,r11			# d1[1] + d2[1]
	ld	r23,(regBase+8*8)(sp)		# restore volatile reg

	vmulu	r16,r31,r12			# d1[2] + d2[2]
	ld	r31,(regBase+8*12)(sp)		# restore volatile reg

	vmulu	r17,r25,r0			# d1[3] + d2[3](0)

	vmulu	r18,r24,r0			# d1[4] + d2[4](0)

	vmulu	r19,r28,r0			# d1[5] + d2[5](0)
	ld	r28,(regBase+8*10)(sp)		# restore volatile reg

	vmulu	r21,r0,r0			# c

 # 
 # add in d3, and rotate to lower registers. r14 is the [0] term
 #

	vmulu	r15,r15,r13			# + d3[1]

	vmulu	r8,r16,r12			# + d3[2]
	daddiu	r25,r0,-1			# r25 = all f's (m3,m4,m5)

	vmulu	r9,r17,r0			# carry out
	dsrl32	r17,r25,0			# r17 = m0 = 0x0000 0000 ffff ffff

	vmulu	r10,r18,r0			# carry out
	dsll32	r18,r25,0			# r18 = m1 = 0xffff ffff 0000 0000

	vmulu	r11,r19,r0			# carry out
	or	r13,r0,r20			# copy to r13 (non-volatile)

	vmulu	r12,r0,r21			# carry out
	li	r24,1				# for mtm/mtp


 # sD in 14,15,8,9,10,11,12; sS in 1,2,3,5,6,7,20 (20->13)	
 #
 # next is the test and branch.
 # we don't have enough registers for speculative execution, so we fill
 # the wait however we can.

	mtm0	r24				# m0<-1
	ld	r20,(regBase+8*5)(sp)		# restore volatile reg
	mtp0	r24				# p0<-1
	ld	r21,(regBase+8*6)(sp)		# restore volatile reg

 # 2 stalls available here if needed

	nor	r14,r0,r14			# ~sD[0]
	sltu	r25,r13,r12			# clear if sS[6]<=sD[6]
	bne	r25,r0,.Lcommon00		# skip if no need
	daddiu	r25,r0,-1			# r25 = all f's (m3,m4,m5)
 #
 # fix sS pre-subtract
 # 

	dsubu	r24,r13,r12			# sD[6] - sS[6]
	daddiu	r24,r24,1			# + 1

	mtm0	r24				# m0 <- sD[6] - sS[6] + 1

	vmulu	r1,r17,r1			# sS[0]

	vmulu	r2,r18,r2			# sS[1]
	daddi	r24,r25,-1			# m2 = 0xffff ffff ffff fffe

	vmulu	r3,r24,r3			# sS[2]

	vmulu	r5,r25,r5			# sS[3]

	vmulu	r6,r25,r6			# sS[4]

	vmulu	r7,r25,r7			# sS[5]

	vmulu	r13,r0,r13			# sS[6]
	li	r24,1				# for mtm,mtp

	mtm0	r24				# m0 <- 1

	mtp0	r24				# p0 <- 1

 # 
 # common code continues with subtract
 #

.Lcommon00:
	vmulu	r1,r1,r14			# u0
	nor	r15,r0,r15			# ~sD[1]

	vmulu	r2,r2,r15			# u1
	nor	r8,r0,r8			# ~sD[2]

	vmulu	r3,r3,r8			# u2
	nor	r9,r0,r9			# ~sD[3]

	vmulu	r5,r5,r9			# u3
	nor	r10,r0,r10			# ~sD[4]

	vmulu	r6,r6,r10			# u4
	nor	r11,r0,r11			# ~sD[5]

	vmulu	r7,r7,r11			# u5
	nor	r12,r0,r12			# ~sD[6]

	vmulu	r13,r13,r12			# u6
	li	r16,1				# cu = 1

 # 
 # the main while loop, which can execute up to 4 times
 # note, ~m0 = m1, ~m1 = m0, ~m2 = 1. r16=cu,r19=cv
 #
.Lloop:
	mtm0	r24				# m0 <- 1
	sd	r14,0*8(r4)			# b[0] = v0

	mtp0	r24				# p0 <- 1
	sd	r15,1*8(r4)			# b[1] = v1

	sd	r8,2*8(r4)			# b[2] = v2

	vmulu	r14,r1,r18			# v0 
	sd	r9,3*8(r4)			# b[3] = v3

	vmulu	r15,r2,r17			# v1
	sd	r10,4*8(r4)			# b[4] = v4

	vmulu	r8,r3,r24			# v2
	sd	r11,5*8(r4)			# b[5] = v5

	vmulu	r9,r5,r0			# v3
	beq	r16,r0,.Ldone			# continue if cu
	vmulu	r10,r6,r0			# v4
	vmulu	r11,r7,r0			# v5
	vmulu	r12,r13,r25			# v6

	vmulu	r19,r0,r0			# cv

 #
 # 2nd half of loop
 #
.Lloop01:
	mtm0	r24				# m0 <- 1
	sd	r1,0*8(r4)			# b[0] = u0

	mtp0	r24				# p0 <- 1
	sd	r2,1*8(r4)			# b[1] = u1
	
	sd	r3,2*8(r4)			# b[2] = u2

	vmulu	r1,r14,r18			# u0 
	sd	r5,3*8(r4)			# b[3] = u3

	vmulu	r2,r15,r17			# u1
	sd	r6,4*8(r4)			# b[4] = u4

	vmulu	r3,r8,r24			# u2
	sd	r7,5*8(r4)			# b[5] = u5

	vmulu	r5,r9,r0			# u3
	vmulu	r6,r10,r0			# u4
	vmulu	r7,r11,r0			# u5
	vmulu	r13,r12,r25			# u6

	bne	r19,r0,.Lloop			# continue if cv
	vmulu	r16,r0,r0			# cu

.Ldone:
	ld	r16,(regBase+8*1)(sp)		# restore volatile reg
	ld	r17,(regBase+8*2)(sp)		# restore volatile reg
	ld	r18,(regBase+8*3)(sp)		# restore volatile reg
	ld	r19,(regBase+8*4)(sp)		# restore volatile reg

	jr	r31
	daddiu	sp,sp,stackFrame

 #
	.set    reorder
	.set    macro
	.set    at
	.end 	fecc_MulP384Asm
