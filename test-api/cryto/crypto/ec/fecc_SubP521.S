
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

        .file   1 "fecc_SubP521.S"

///////////////////////////////////////////////////////////////////////
// Edit History
///////////////////////////////////////////////////////////////////////
// created:     10 February 2012
// by:          Emery Davis for Cavium Networks
//
// modified:    
// by:          
// changes:     
//
///////////////////////////////////////////////////////////////////////
//
// caviumSubP521.S
//
// DESCRIPTION:
//
// performs 521 bit modular subtract.
//
// OPERATION:
//
// res = (s1 - s2) mod p
//
// PROTOTYPE:
//
// void caviumSubP521Asm (uint64_t *res, uint64_t *s1, uint64_t *s2);
//
// HEADER FILE:
//
// vanillaRegisters,h provides standard register names.
//
// REGISTERS USED:
//
// r1 - r15, r24,r25.  No stack.
//
// FUNCTION TIMING:
//
// 30 or 38 cycles if correctly predicted.
//
// COMMENTS:
//
// The coding style makes a rough attempt at showing expected IPC through 
// instruction grouping.  Delay slot instructions are always 
// put with the associated branch, however.
//
//

#ifndef __linux__
#include <machine/asm.h>
#include <machine/regdef.h>
#else
#include "asm.h"
#endif


#include "vanillaRegisters.h"

LEAF(fecc_SubP521Asm)

        .set    noreorder
        .set    nomacro
        .set    noat
        .align  3

	ld	r1,0*8(r6)			# q[0]
	li	r3,1				# play that music

	ld	r2,1*8(r6)			# q[1]
	mtm0	r3				# M0 <- 1

	ld	r8,0*8(r5)			# s[0]
	mtp0	r3				# P0 <- 1

	nor	r1,r1,r0			# ~q[0]
	ld	r9,1*8(r5)			# s[1]

	nor	r2,r2,r0			# ~q[1]
	ld	r7,2*8(r6)			# q[2]

	ld	r10,2*8(r5)			# s[2]
	vmulu	r8,r8,r1			# r[0]

	ld	r14,3*8(r6)			# q[3]
	vmulu	r9,r9,r2			# r[1]

	ld	r11,3*8(r5)			# s[3]
	nor	r7,r7,r0			# ~q[2]

	ld	r24,4*8(r6)			# q[4]
	vmulu	r10,r10,r7			# r[2]

	ld	r12,4*8(r5)			# s[4]
	nor	r14,r14,r0			# ~q[3]

	ld	r25,5*8(r6)			# q[5]
	vmulu	r11,r11,r14			# r[3]

	ld	r13,5*8(r5)			# s[5]
	nor	r24,r24,r0			# ~q[4]

	ld	r1,6*8(r6)			# q[6]
	vmulu	r12,r12,r24			# r[4]

	ld	r14,6*8(r5)			# s[6]
	nor	r25,r25,r0			# ~q[5]

	ld	r2,7*8(r6)			# q[7]
	vmulu	r13,r13,r25			# r[5]


	ld	r15,7*8(r5)			# s[7]
	nor	r1,r1,r0			# ~q[6]

	ld	r6,8*8(r6)			# q[8]
	vmulu	r14,r14,r1			# r[6]

	ld	r7,8*8(r5)			# s[8]
	nor	r2,r2,r0			# ~q[7]

	vmulu	r15,r15,r2			# r[7]
	sd	r8,0*8(r4)			# save r[0]

	sd	r9,1*8(r4)			# save r[1]
	nor	r6,r6,r0			# ~q[8]

	vmulu	r7,r7,r6			# r[8]
	sd	r10,2*8(r4)			# save r[2]

	vmulu	r6,r0,r0			# carry
	daddiu	r5,r0,-1			# 0xffffffffffffffff (m0 - m7)

	mtm0	r3				# m0 <- 1
	sd	r11,3*8(r4)			# save r[3]

	vmulu	r8,r5,r8			# a[0]
	sd	r12,4*8(r4)			# save r[4]
	
	vmulu	r9,r5,r9			# a[1]
	sd	r13,5*8(r4)			# save r[5]

	vmulu	r10,r5,r10			# a[2]
	sd	r14,6*8(r4)			# save r[6]

	vmulu	r11,r5,r11			# a[3]
	sd	r15,7*8(r4)			# save r[7]

	sd	r7,8*8(r4)			# save r[8]
	beq	r6,r0,.Laddback			# if !carry, use adds
	vmulu	r12,r5,r12			# a[4]

	jr	r31				# my mama done tole me
	nop

.Laddback:
	vmulu	r13,r5,r13			# a[5]
	sd	r8,0*8(r4)			# save r[0]

	vmulu	r14,r5,r14			# a[6]
	sd	r9,1*8(r4)			# save r[1]

	vmulu	r15,r5,r15			# a[7]
	ori	r6,r0,0x1ff			# m8

	vmulu	r7,r6,r7			# a[8]
	sd	r10,2*8(r4)			# save r[2]

	sd	r11,3*8(r4)			# save r[3]
	sd	r12,4*8(r4)			# save r[4]
	sd	r13,5*8(r4)			# save r[5]
	sd	r14,6*8(r4)			# save r[6]

	sd	r15,7*8(r4)			# save r[7]
	jr	r31				# to eeta my breakfast
	sd	r7,8*8(r4)			# save r[8]
 #
        .set    reorder
        .set    macro
        .set    at
        .end    fecc_SubP521Asm

