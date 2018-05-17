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

        .file   1 "fecc_MulP521o3.S"

///////////////////////////////////////////////////////////////////////
// Edit History
///////////////////////////////////////////////////////////////////////
// created:     6 May 2012, modified from O2 version
// by:          Emery Davis for Cavium Networks
//
// modified:    
// by:          
// changes:     
//
///////////////////////////////////////////////////////////////////////
//
// caviumMulP521o3.S
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
// The intermediate result of the multiply is an 17 word BN.
// The result res3 is 521 bits.
//
// PROTOTYPE:
//
// void caviumMulP521o3Asm(uint64_t * res3, uint64_t * res1, uint64_t * res2);
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
// The entire operation consumes around 160 - 170 cycles depending if all branches
// are correctly predicted, depending on data.  
//
// The BN multiply consumes 117 (branchless) cycles.
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

LEAF(fecc_MulP521o3Asm)
	.set    noreorder
	.set    nomacro
	.set    noat
	.set	arch=octeon3
	.align	3

#define stackFrame	(16*8)
#define regBase		(0*8)
	
 #
 # first carry out the low 3 terms of the multiply
 #
	ld	r8,0*8(r6)			# r2[0]
	ld	r1,3*8(r6)			# r2[3]
	daddiu	sp,sp,-stackFrame		# make stack frame

	ld	r9,1*8(r6)			# r2[1]
	ld	r2,4*8(r6)			# r2[4]

	ld	r10,2*8(r6)			# r2[2]
	ld	r3,5*8(r6)			# r2[5]

	mtm0	r8,r1				# r2[0,3] -> m0, m3
	ld	r1,0*8(r5)			# r1[0]

	mtm1	r9,r2				# r2[1,4] -> m1, m4
	ld	r2,1*8(r5)			# r1[1]

	mtm2	r10,r3				# r2[2] -> m2, m5
	ld	r24,2*8(r5)			# r1[2]

	v3mulu	r8,r1,r0			# first 4 word terms, r8 = mres[0]
	ld	r25,3*8(r5)			# r1[3] 

	sd	r16,(regBase+8*1)(sp)		# save volatile reg
	sd	r17,(regBase+8*2)(sp)		# save volatile reg

	v3mulu	r9,r2,r0			# mul intermediate w[1-4], accum w[1-3], r9 = mres[1]

	sd	r18,(regBase+8*3)(sp)		# save volatile reg
	sd	r19,(regBase+8*4)(sp)		# save volatile reg

	v3mulu	r10,r24,r0			# mul intermediate w[2-5], accum w[2-4], r10 = mres[2]

	sd	r20,(regBase+8*5)(sp)		# save volatile reg
	sd	r21,(regBase+8*6)(sp)		# save volatile reg

	ld	r12,4*8(r5)			# r1[4]
	v3mulu	r11,r25,r0			# mul intermediate w[3-6], accum w[3-5], r11 = mres[3] 

	sd	r22,(regBase+8*7)(sp)		# save volatile reg
	sd	r23,(regBase+8*8)(sp)		# save volatile reg

	ld	r13,5*8(r5)			# r1[5]
	v3mulu	r12,r12,r0			# mul intermediate w[4-7], accum w[4-6], r12 = mres[4]


	ld	r14,6*8(r5)			# r1[6]
	v3mulu	r13,r13,r0			# mul intermediate w[5-8], accum w[5-7], r13 = mres[5]

	ld	r15,7*8(r5)			# r1[7]
	
	v3mulu	r14,r14,r0			# r14 = mres[6]

	ld	r16,8*8(r5)			# r1[8]

	v3mulu	r15,r15,r0			# r15 = mres[7]

	v3mulu	r16,r16,r0			# r16 = mres[8]

	v3mulu	r17,r0,r0			# r17 = mres[9]
	v3mulu	r18,r0,r0			# r18 = mres[10]
	v3mulu	r19,r0,r0			# r19 = mres[11]
	ld	r1,6*8(r6)			# r2[6]
	v3mulu	r20,r0,r0			# r20 = mres[12]
	ld	r2,7*8(r6)			# r2[7]
	v3mulu	r21,r0,r0			# r21 = mres[13]
	ld	r3,8*8(r6)			# r2[8]
	v3mulu	r22,r0,r0			# r22 = mres[14]




	ld	r24,0*8(r5)			# r1[0]
	mtm0	r1,r0				# m0 <- r2[3]

	ld	r25,1*8(r5)			# r1[1]
	mtm1	r2,r0				# m1 <- r2[4]

	ld	r1,2*8(r5)			# r1[2]
	mtm2	r3,r0				# m2 <- r2[5]

	ld	r2,3*8(r5)			# r1[3]
	v3mulu	r14,r24,r14			# mres[6]

	v3mulu	r15,r25,r15			# mres[7]

	ld	r24,4*8(r5)			# r1[4]
	v3mulu	r16,r1,r16			# mres[8]

	ld	r25,5*8(r5)			# r1[5]
	v3mulu	r17,r2,r17			# mres[6]

	v3mulu	r18,r24,r18			# mres[7]
 	pref	0,0(r4)				# normal pref on dst

	dsrl	r3,r16,9			# mr[8]>>9

	ld	r24,6*8(r5)			# r1[6]
	v3mulu	r19,r25,r19			# mres[8]

	dsll32	r1,r17,(55-32)			# mr[9]<<55
	dsrl	r17,r17,9			# mr[9]>>9

	or	r3,r3,r1			# A1[0] = a[8]>>9 |(a[9]<<55)

	ld	r25,7*8(r5)			# r1[7]
	v3mulu	r20,r24,r20			# mres[9]

	dsll32	r1,r18,(55-32)			# mr[10]<<55
	dsrl	r18,r18,9			# mr[10]>>9

	or	r17,r17,r1			# A1[1] = a[9]>>9 |(a[10]<<55)

	ld	r24,8*8(r5)			# r1[8]
	v3mulu	r21,r25,r21			# mres[10]

	dsll32	r1,r19,(55-32)			# mr[11]<<55
	dsrl	r19,r19,9			# mr[11]>>9

	or	r18,r18,r1			# A1[2] = a[10]>>9 |(a[11]<<55)

	v3mulu	r22,r24,r22			# mres[11]

	dsll32	r1,r20,(55-32)			# mr[12]<<55
	dsrl	r20,r20,9			# mr[12]>>9

	or	r19,r19,r1			# A1[3] = a[11]>>9 |(a[12]<<55)

	v3mulu	r23,r0,r0			# mres[15]

	dsll32	r1,r21,(55-32)			# mr[13]<<55
	dsrl	r21,r21,9			# mr[13]>>9

	or	r20,r20,r1			# A1[4] = a[12]>>9 |(a[13]<<55)

	v3mulu 	r7,r0,r0			# mres[16]


# o3 mul done








 	dsll32	r1,r22,(55-32)			# mr[14]<<55
	dsrl	r22,r22,9			# mr[14]>>9

        li	r24,1 
	or	r21,r21,r1			# A1[5] = a[13]>>9 |(a[14]<<55)

 #
 # mul done, a := r8 - r23, r7 total 117 cycles for multiply part (to mtm0 dispatch).
 #

	dsll32	r1,r23,(55-32)			# mr[15]<<55
	mtm0	r24,r0				# m0 <- 1 for add

	dsrl	r23,r23,9			# mr[15]>>9
	vmulu	r8,r8,r3			# mr[0] + A1[0]

	or	r22,r22,r1			# A1[6] = a[14]>>9|(a[15]<<55)
	vmulu	r9,r9,r17			# mr[1] + A1[1]

	dsll32	r1,r7,(55-32)			# mr[16]<<55
	vmulu	r10,r10,r18			# mr[2] + A1[2]

	or	r23,r23,r1			# A1[7] = a[15]>>9|(a[16]<<55)
	vmulu	r11,r11,r19			# mr[3] + A1[3]

	dsrl	r7,r7,9				# mr[16]>>9 = A1[8]
	vmulu	r12,r12,r20			# mr[4] + A1[4]

	li	r1,0x1ff			# mask low 9 bits, also m8
	vmulu	r13,r13,r21			# mr[5] + A1[5]

	and	r16,r1,r16			# low 9 bits(mr[8])
	vmulu	r14,r14,r22			# mr[6] + A1[6]

 	nor	r1,r1,r0			# ~m8
	vmulu	r15,r15,r23			# mr[7] + A1[7]

	ld	r20,(regBase+8*5)(sp)		# restore volatile reg
	vmulu	r16,r16,r7			# low 9 bits(mr[8]) + A1[8]

	ld	r21,(regBase+8*6)(sp)		# restore volatile reg
	mtm0	r24,r0				# m0 <- 1

	ld	r22,(regBase+8*7)(sp)		# restore volatile reg
	mtp0	r24,r0				# mp <- 1

	ld	r23,(regBase+8*8)(sp)		# restore volatile reg

 #
 # see if subtracting p is < 0.  If not, we're done.
 #

	vmulu	r2,r8,r0			# s[0]
	sd	r8,0*8(r4)			# b[0]

	vmulu	r3,r9,r0			# s[1]
	sd	r9,1*8(r4)			# b[1]

	vmulu	r5,r10,r0			# s[2]
	sd	r10,2*8(r4)			# b[2]

	vmulu	r6,r11,r0			# s[3]
	ld	r17,(regBase+8*2)(sp)		# restore volatile reg

	vmulu	r7,r12,r0			# s[4]
	ld	r18,(regBase+8*3)(sp)		# restore volatile reg

	vmulu	r24,r13,r0			# s[5]
	ld	r19,(regBase+8*4)(sp)		# restore volatile reg

	vmulu	r25,r14,r0			# s[6]
	sd	r16,8*8(r4)			# b[8]

	vmulu	r8,r15,r0			# s[7]

	vmulu	r9,r16,r1			# s[8]

	ld	r16,(regBase+8*1)(sp)		# restore volatile reg
	vmulu	r10,r0,r0			# carry

	sd	r11,3*8(r4)			# b[3]
	sd	r12,4*8(r4)			# b[4]
	sd	r13,5*8(r4)			# b[5]
	sd	r14,6*8(r4)			# b[6]
	sd	r15,7*8(r4)			# b[7]

 	bne	r10,r0,.Lusesmall
	daddiu	sp,sp,stackFrame

	jr	r31				# quel honte
	nop					# je me sente tout vide

.Lusesmall:
	sd	r2,0*8(r4)			# b[0]
	sd	r3,1*8(r4)			# b[1]
	sd	r5,2*8(r4)			# b[2]
	sd	r6,3*8(r4)			# b[3]
	sd	r7,4*8(r4)			# b[4]
	sd	r24,5*8(r4)			# b[5]
	sd	r25,6*8(r4)			# b[6]
	sd	r8,7*8(r4)			# b[7]
	jr	r31				# have a mug o cidre
	sd	r9,8*8(r4)			# b[8]

 #
	.set    reorder
	.set    macro
	.set    at
	.end 	fecc_MulP521o3Asm
