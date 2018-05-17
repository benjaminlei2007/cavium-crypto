
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

        .file   1 "fecc_ConstMulP384.S"

///////////////////////////////////////////////////////////////////////
// Edit History
///////////////////////////////////////////////////////////////////////
// created:     25 January 2012
// by:          Emery Davis for Cavium Networks
//
// modified:    
// by:          
// changes:     
//
///////////////////////////////////////////////////////////////////////
//
// caviumConstMulP384.S
//
// DESCRIPTION:
//
// Modular multiply of BN and constant.  Mod is performed by subtraction, so 
// it is better not to use very large constants.
//
// OPERATION:
//
// res = (const * source) mod p
//
// PROTOTYPE:
//
// void caviumConstMulP384Asm(uint64_t *res, uint64_t *source, uint64_t const);
//
// HEADER FILE:
//
// vanillaRegisters.h provides standard register definitions.
//
// REGISTERS USED:
//
// r1-r19, r24, r25.  There is no early restore possible for r16-r19 because of 
// the number of required live registers in the loop.
//
// FUNCTION TIMING:
//
// 23 + (approx) 11*N, N the number of subtracts to get back into 384 bits.
//
// COMMENTS:
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
#define Frame	(4*32)

LEAF(fecc_ConstMulP384Asm)

        .set    noreorder
        .set    nomacro
        .set    noat
        .align  3

	ld	r8,0*8(r5)			# s[0]
	mtm0	r6				# M0 <- constant multiplier

	ld	r9,1*8(r5)			# s[1]
	daddiu	sp,sp,-Frame			# allocate stack

	ld	r10,2*8(r5)			# s[2]
	li	r3,1				# like it sez

	vmulu	r8,r8,r0			# c*s[0]
	ld	r11,3*8(r5)			# s[3]

	vmulu	r9,r9,r0			# c*s[1]
	ld	r12,4*8(r5)			# s[4]

	vmulu	r10,r10,r0			# c*s[2]
	ld	r13,5*8(r5)			# s[5]

	vmulu	r11,r11,r0			# c*s[3]
	sd	r16,0*8(sp)

	vmulu	r12,r12,r0			# c*s[4]
	sd	r17,1*8(sp)

	vmulu	r13,r13,r0			# c*s[5]
	sd	r18,2*8(sp)

	vmulu	r14,r0,r0			# carry through last term
	sd	r8,0*8(r4)			# save r[0]

	mtm0	r3				# for sub
	sd	r9,1*8(r4)			# save r[1]

	mtp0	r3				# for sub
	sd	r10,2*8(r4)			# save r[2]

	sd	r11,3*8(r4)			# save r[3]
	daddiu	r25,r0,-1			# r25 = all f's (m3,m4,m5)

	sd	r12,4*8(r4)			# save r[4]
	dsrl32	r24,r25,0			# r24 = m0  = 0x0000 0000 ffff ffff

 # this is written as u[5] >= m[5], but since m5 = 0xffffffffffffffff there is no >. We can test ==.
	sd	r13,5*8(r4)			# save r[5]
	seq	r2,r13,r25			# r2 = (r[5] == m5)

 # could do a branch on next potentially, but not advisable for prediction hit.

	sd	r19,3*8(sp)
	sne	r1,r14,r0			# r1 = (r[6] != 0)

	or	r1,r2,r1			# or 2 conditions
	dsll32	r15,r25,0			# r15 = m1 = 0xffff ffff 0000 0000

 	beq	r1,r0,.Ldone			# maybe done?
	li	r18,1				# cu = 1

 # m,p already loaded
 # note, ~m0 = m1, ~m1 = m0, ~m2 = 1

.Lloop:
	sd	r1,0*8(r4)			# save r[0]
	vmulu	r1,r8,r15			# u,v,~m0 r[0]

	sd	r2,1*8(r4)			# save r[1]
	vmulu	r2,r9,r24			# u,v,~m1 r[1]

	sd	r5,2*8(r4)			# save r[2]
	vmulu	r5,r10,r3			# u,v,~m2 r[2]

	sd	r6,3*8(r4)			# save r[3]
	vmulu	r6,r11,r0			# u,v,~m3 r[3]

	sd	r7,4*8(r4)			# save r[4]
	vmulu	r7,r12,r0			# u,v,~m4 r[4]

	sd	r16,5*8(r4)			# save r[5]
	vmulu	r16,r13,r0			# u,v,~m5 r[5]

	beq	r18,r0,.Ldone			# continue if cu
	vmulu	r17,r14,r25			# u,v,-1 r[6]

	vmulu	r19,r0,r0			# cv

	mtm0	r3				# m0 <- 1
	sd	r8,0*8(r4)			# save r[0]

	mtp0	r3				# p0 <- 1
	sd	r9,1*8(r4)			# save r[1]

	sd	r10,2*8(r4)			# save r[2]

	vmulu	r8,r1,r15			# u,v,~m0 r[0]
	sd	r11,3*8(r4)			# save r[3]

	vmulu	r9,r2,r24			# u,v,~m1 r[1]
	sd	r12,4*8(r4)			# save r[4]

	vmulu	r10,r5,r3			# u,v,~m2 r[2]
	sd	r13,5*8(r4)			# save r[5]

	vmulu	r11,r6,r0			# u,v,~m3 r[3]

	vmulu	r12,r7,r0			# u,v,~m4 r[4]

	vmulu	r13,r16,r0			# u,v,~m5 r[5]

	vmulu	r14,r17,r25			# u,v,-1 r[6]

	vmulu	r18,r0,r0			# cv

	mtm0	r3				# m0 <- 1
	bne	r19,r0,.Lloop			# continue if cv
	mtp0	r3				# p0 <- 1
 #
 # cleanup registers and exit
 #
.Ldone:
	ld	r16,0*8(sp)
	ld	r17,1*8(sp)
	ld	r18,2*8(sp)
	ld	r19,3*8(sp)
	jr	r31				# miller time
	daddiu	sp,sp,Frame			# restore stack

        .set    reorder
        .set    macro
        .set    at
        .end    fecc_ConstMulP384Asm

