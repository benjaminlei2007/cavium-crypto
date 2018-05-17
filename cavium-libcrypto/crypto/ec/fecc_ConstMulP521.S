
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

        .file   1 "fecc_ConstMulP521.S"

///////////////////////////////////////////////////////////////////////
// Edit History
///////////////////////////////////////////////////////////////////////
// created:     12 February 2012
// by:          Emery Davis for Cavium Networks
//
// modified:    
// by:          
// changes:     
//
///////////////////////////////////////////////////////////////////////
//
// caviumConstMulP521.S
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
// void caviumConstMulP521Asm(uint64_t *res, uint64_t *source, uint64_t const);
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
// 20 or 35 cycles depending on range
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

LEAF(fecc_ConstMulP521Asm)

        .set    noreorder
        .set    nomacro
        .set    noat
        .align  3

	ld	r8,0*8(r5)			# s[0]
	mtm0	r6				# M0 <- constant multiplier

	ld	r9,1*8(r5)			# s[1]
	ori	r6,r0,0x1ff			# m8 for later

	ld	r10,2*8(r5)			# s[2]
	li	r3,1				# like it sez

	vmulu	r8,r8,r0			# c*s[0]
	ld	r11,3*8(r5)			# s[3]

	vmulu	r9,r9,r0			# c*s[1]
	ld	r12,4*8(r5)			# s[4]

	vmulu	r10,r10,r0			# c*s[2]
	ld	r13,5*8(r5)			# s[5]

	vmulu	r11,r11,r0			# c*s[3]
	ld	r14,6*8(r5)			# s[6]

	vmulu	r12,r12,r0			# c*s[4]
	ld	r15,7*8(r5)			# s[7]

	vmulu	r13,r13,r0			# c*s[5]
	ld	r7,8*8(r5)			# s[8]

	vmulu	r14,r14,r0			# c*s[6]
	sd	r8,0*8(r4)			# d[0]

	vmulu	r15,r15,r0			# c*s[7]
	sd	r9,1*8(r4)			# d[1]

	vmulu	r7,r7,r0			# c*s[8]
	sd	r10,2*8(r4)			# d[2]

	mtm0	r3				# m0 <- 1 for mod
	sd	r11,3*8(r4)			# d[3]

 #
 # cannot start mod yet since first term needs d[8]
 # so just save values to kill time

	sd	r12,4*8(r4)			# d[4]
	sd	r13,5*8(r4)			# d[5]
	sd	r14,6*8(r4)			# d[6]
	sd	r15,7*8(r4)			# d[7]

	sltu	r3,r7,r6			# set if d[8] < m8
	beq	r3,r0,.Ldomod			# do mod is required
	dsrl	r1,r7,9				# d[8] >> 9
	
 #
	jr	r31				# time for a courgette bake
	sd	r7,8*8(r4)			# d[8], with cheese
 #
.Ldomod:
	vmulu	r8,r8,r1			# d[0]
	and	r6,r7,r6			# d[8] & 0x1ff

	vmulu	r9,r9,r0			# d[1]
	vmulu	r10,r10,r0			# d[2]
	vmulu	r11,r11,r0			# d[3]
	vmulu	r12,r12,r0			# d[4]
	vmulu	r13,r13,r0			# d[5]

	sd	r8,0*8(r4)			# d[0]
	vmulu	r14,r14,r0			# d[6]

	sd	r9,1*8(r4)			# d[1]
	vmulu	r15,r15,r0			# d[7]

	sd	r10,2*8(r4)			# d[2]
	vmulu	r7,r6,r0			# d[8]

	sd	r11,3*8(r4)			# d[3]
	sd	r12,4*8(r4)			# d[4]
	sd	r13,5*8(r4)			# d[5]
	sd	r14,6*8(r4)			# d[6]
	sd	r15,7*8(r4)			# d[7]
	jr	r31				# getting here deserves schnitzel
	sd	r7,8*8(r4)			# d[8], with pickel
 #
        .set    reorder
        .set    macro
        .set    at
        .end    fecc_ConstMulP521Asm

