
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

        .file   1 "fecc_SubP384.S"

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
// caviumSubP384.S
//
// DESCRIPTION:
//
// performs 384 bit modular subtract.
//
// OPERATION:
//
// res = (s1 - s2) mod p
//
// PROTOTYPE:
//
// void caviumSubP384Asm (uint64_t *res, uint64_t *s1, uint64_t *s2);
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
// 23 or 33 cycles if correctly predicted.
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

LEAF(fecc_SubP384Asm)

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

	sd	r8,0*8(r4)			# save r[0]
	vmulu	r12,r12,r24			# r[4]

	nor	r25,r25,r0			# ~q[5]
	sd	r9,1*8(r4)			# save r[1]

	vmulu	r13,r13,r25			# r[5]
	daddiu	r1,r0,-1			# r1 = m3,m4,m5 = all 1's

	vmulu	r14,r0,r0			# carry through last term
	sd	r10,2*8(r4)			# save r[2]

	dsrl32	r2,r1,0				# r2 = m0 = 0x00000000ffffffff
	sd	r11,3*8(r4)			# save r[3]

	dsll32	r7,r1,0				# r7 = m1 = 0xffffffff00000000
	nor	r24,r3,r0			# r24 = m2 = 0xfffffffffffffffe

	mtm0	r3				# m0 <= 1
	sd	r12,4*8(r4)			# save r[4]

	vmulu	r8,r2,r8			# r[0]
	sd	r13,5*8(r4)			# save r[5]

	vmulu	r9,r7,r9			# r[1]

	beq	r14,r0,.Laddback		# if !carry, add back m (note stall)
	vmulu	r10,r24,r10			# r[2]

	jr	r31				# down by the old mill stream
	nop

.Laddback:
	vmulu	r11,r1,r11			# r[3]

	vmulu	r12,r1,r12			# r[4]

	vmulu	r13,r1,r13			# r[5]
	sd	r8,0*8(r4)			# save new r[0]

	sd	r9,1*8(r4)			# save new r[1]

	sd	r10,2*8(r4)			# save new r[2]

	sd	r11,3*8(r4)			# save new r[3]

	sd	r12,4*8(r4)			# save new r[4]
	jr	r31				# is where I first met you
	sd	r13,5*8(r4)			# save new r[5]



        .set    reorder
        .set    macro
        .set    at
        .end    fecc_SubP384Asm

