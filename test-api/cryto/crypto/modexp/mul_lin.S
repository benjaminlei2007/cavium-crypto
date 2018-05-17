
#if !defined(USER_SPACE_MODEXP)


#define zero    $0	/* always returns 0 */
#define AT      $1	/* reserved for use by assembler */

#define v0      $2	/* value returned by subroutine */
#define v1      $3	

#define a0      $4	/* parameters for a subroutine */
#define a1      $5	
#define a2      $6
#define a3      $7

#define t0      $8	/* subroutines can use without saving */
#define t1      $9
#define t2      $10
#define t3      $11
#define t4      $12
#define t5      $13
#define t6      $14
#define t7      $15

#define s0      $16	/* subroutine register variables */
#define s1      $17
#define s2      $18
#define s3      $19
#define s4      $20
#define s5      $21
#define s6      $22
#define s7      $23

#define s8      $30	/* frame pointer */

#define t8      $24
#define t9      $25

#define k0      $26	/* reserved for use by interrupt/trap handler */
#define k1      $27

#define gp      $28	/* global pointer */

#define sp      $29	/* stack pointer */
#define fp      $30	/* frame pointer */
#define ra      $31	/* return address for subroutine */

#define LEAF(symbol)						\
		.globl   symbol;				\
		.align   2;					\
		.type    symbol, @function;			\
		.ent     symbol, 0;				\
symbol:		.frame   sp, 0, ra

/*
 * END - mark end of function
 */
#define END(function)						\
		.end     function;				\
		.size    function, .-function

#define EXPORT(symbol)						\
		.globl   symbol;				\
symbol:


# void Vadd(__uint64 *accum, const __uint64 *addend, int len)
#void Vadd(__uint64 *a, const __uint64 *b, int len)
#   {
#   int i;

#   MTM0(1, 0);
#   for (i=0; i<len; i++)
#      {
#      VMULU(a[i], b[i], a[i]);
#      }
#   }



#define accum	a0
#define addend	a1
#define len	a2
#define i	v0

.set noreorder 
.set noat

# len must be >1

LEAF(Vadd)

Vadd:
    ld	    t3, 0(addend)
    addiu   t0, zero, 1
    ld	    t2, 0(accum)
    mtm0    t0
    mtm1    zero
    mtm2    zero

    daddiu  i, len, -1	    # i=len-1
    
    daddiu  addend, addend, 8
    daddiu  accum, accum, 8    

    ld	    t1, 0(addend)
    v3mulu  t3, t3, t2


VADD$L1: 
    ld	    t2, 0(accum)
    daddiu  i, i, -1
    
    daddiu  accum, accum, 8
    daddiu  addend, addend, 8

    sd	    t3, -16(accum)
    v3mulu  t3, t1, t2

    bne	    i, zero, VADD$L1
    ld	    t1, 0(addend)


VADD$DONE:
    jr	    ra
    sd	    t3, -8(accum)

END(Vadd)



LEAF(Vsub)

# Since I don't support signed vmul's for subtract I will
# skip over all trailing 0's and then do an add of 1's complement

Vsub:
    daddiu  i, len, 	    # i=len
    daddiu  t8, zero, -1

VSUB$L1:
    ld	    t1, 0(addend)
    daddiu  i, i, -1
    bltz    i, VSUB$DONE
    daddiu  addend,addend, 8
    ld	    t3, 0(accum)
    beq	    t1, zero, VSUB$L1
    daddiu  accum,accum, 8

    ld	    t3, -8(addend)
    daddiu  t0, zero, 1
    ld	    t2, -8(accum)
    mtm0    t0
    mtm1    zero
    mtm2    zero
    xor	    t3, t3, t8
    daddiu  t3, t3, 1    

    ld	    t1, 0(addend)
    v3mulu  t3, t3, t2
    beq     i, zero, VSUB$DONE
    nop


VSUB$L2: 
    ld	    t2, 0(accum)
    daddiu  i, i, -1
    
    daddiu  accum, accum, 8
    daddiu  addend, addend, 8

    xor	    t1, t1, t8

    sd	    t3, -16(accum)
    v3mulu  t3, t1, t2

    bne	    i, zero, VSUB$L2
    ld	    t1, 0(addend)


VSUB$DONE:
    jr	    ra
    sd	    t3, -8(accum)

END(Vsub)

#undef accum
#undef addend
#undef len
#undef i



#define product		a0
#define mpcand		a1
#define mplier		a2
#define modulus		a3
#define recip		t0
#define len		t1
#define i               v0
#define l               s0

# len will be * 192b

LEAF(MontMul_O3)
MontMul_O3:
# Simpler routine without good scheduling
# stash all the registers
    .set push
    .set arch=octeon3
    daddiu  sp, sp, -64        # be sure to match this at epilog
    sd      mpcand, 0(sp)
    sd      product, 8(sp)
    sd      len, 16(sp)
    sd      modulus, 24(sp)
    sd      s0, 32(sp)
    sd      s1, 40(sp)
    sd      s2, 48(sp)
    sd      s3, 56(sp)


# I want to clear the product registers. This will clear len+6 
    daddiu  i, len, 4-1
MM$L1:
    sd      zero, 0(product)
    daddiu  i, i, -4
    sd      zero, 8(product)
    daddiu  product, product, 32
    sd      zero, -16(product)
    bgez    i, MM$L1
    sd      zero, -8(product)

    sd      zero, 0(product)
    daddiu  l, len, -1
    sd      zero, 8(product)

MM$L2:
    ld      product, 8(sp)
    ld      mpcand, 0(sp)
    ld	    t2, 0(mplier)
    ld	    t3, 24(mplier)
    ld	    t4, 8(mplier)
    ld	    t5, 32(mplier)
    mtm0    t2, t3
    ld	    t6, 16(mplier)
    ld	    t7, 40(mplier)
    daddiu  mplier, mplier, 48
    ld	    t2, 0(product)
    mtm1    t4, t5
    ld	    t3, 0(mpcand)
    mtm2    t6, t7

    ld	    t4, 8(product)
    v3mulu  t7, t3, t2
    ld	    t5, 8(mpcand)
    daddiu  i, len, -5

    ld	    t2, 16(product)
    v3mulu  t8, t5, t4
    ld	    t3, 16(mpcand)
    daddiu  mpcand, mpcand, 32
    daddiu  product, product, 32

    ld	    t4, -8(product)
    v3mulu  t9, t3, t2
    ld	    t5, -8(mpcand)
    sd	    t7, -32(product)

#Main loop
.align 3
MM$L3:
    ld	    t2, 0(product)
    v3mulu  t6, t5, t4
    ld	    t3, 0(mpcand)
    sd	    t8, -24(product)

    ld	    t4, 8(product)
    v3mulu  t7, t3, t2
    ld	    t5, 8(mpcand)
    daddiu  i, i, -4
    sd	    t9, -16(product)

    ld	    t2, 16(product)
    v3mulu  t8, t5, t4
    ld	    t3, 16(mpcand)
    daddiu  mpcand, mpcand, 32
    sd	    t6, -8(product)
    daddiu  product, product, 32

    ld	    t4, -8(product)
    v3mulu  t9, t3, t2
    ld	    t5, -8(mpcand)
    bgez    i, MM$L3
    sd	    t7, -32(product)

#cleanup after loop
    v3mulu  t6, t5, t4
    ld	    t2, 0(product)
    sd	    t8, -24(product)
    sd	    t9, -16(product)
    v3mulu  t2, zero, t2
    ld      modulus, 24(sp)
    daddiu  v0, product, 0
    ld      product, 8(sp)
    v3mulu  t4, zero, zero

    sd	    t6, -8(v0)
    v3mulu  t6, zero, zero
    ld	    t3, 0(recip)
    ld	    t5, 24(recip)
    sd	    t2, 0(v0)
    v3mulu  t2, zero, zero
    ld	    t7, 8(recip)
    ld	    t9, 32(recip)
    sd	    t4, 8(v0)
    v3mulu  t4, zero, zero
    ld	    s2, 16(recip)
    ld	    s3, 40(recip)
    sd	    t6, 16(v0)
    v3mulu  t6, zero, zero
    sd	    t2, 24(v0)
    ld	    t2, 0(product)
    sd	    t4, 32(v0)
    mtm0    t3, t5
    ld	    t3, 8(product)
    mtm1    t7, t9
    sd	    t6, 40(v0)
    mtm2    s2, s3

    ld	    t4, 16(product)
    v3mulu  t2, t2, zero
    ld	    t5, 24(product)
    ld	    t6, 32(product)
    ld	    t7, 40(product)
    v3mulu  t3, t3, zero
    v3mulu  t4, t4, zero
    v3mulu  t5, t5, zero
    v3mulu  t6, t6, zero
    ld	    s2, 0(product)
    ld	    s3, 0(modulus)
    v3mulu  t7, t7, zero

    mtm0    t2, t5
    mtm1    t3, t6
    ld	    t5, 8(modulus)
    mtm2    t4, t7

    ld	    t4, 8(product)
    v3mulu  s2, s3, s2

    ld	    t6, 16(product)
    ld	    t7, 16(modulus)
    v3mulu  t4, t5, t4
#    tne	    s2, zero

    ld	    t2, 24(product)
    ld	    t3, 24(modulus)
    v3mulu  t6, t7, t6
#    tne	    t4, zero

    ld	    t4, 32(product)
    ld	    t5, 32(modulus)
    v3mulu  t2, t3, t2
#    tne	    t6, zero

    ld	    t6, 40(product)
    ld	    t7, 40(modulus)
    v3mulu  t4, t5, t4
#    tne	    t2, zero

    v3mulu  t6, t7, t6
#    tne	    t4, zero
#    tne	    t6, zero

#First iteration through loop
    ld	    t2, 48(product)
    daddiu  i, len, -1
    ld	    t3, 48(modulus)

    ld	    t4, 56(product)
    v3mulu  t7, t3, t2
    ld	    t5, 56(modulus)
    daddiu  i, i, -4

    ld	    t2, 64(product)
    v3mulu  t8, t5, t4
    ld	    t3, 64(modulus)
    daddiu  modulus, modulus, 32
    daddiu  product, product, 32

    ld	    t4, 40(product)
    v3mulu  t9, t3, t2
    ld	    t5, 40(modulus)
    sd	    t7, -32(product)

#Main loop
.align 3
MM$L4:
    ld	    t2, 48(product)
    v3mulu  t6, t5, t4
    ld	    t3, 48(modulus)
    sd	    t8, -24(product)

    ld	    t4, 56(product)
    v3mulu  t7, t3, t2
    ld	    t5, 56(modulus)
    daddiu  i, i, -4
    sd	    t9, -16(product)

    ld	    t2, 64(product)
    v3mulu  t8, t5, t4
    ld	    t3, 64(modulus)
    daddiu  modulus, modulus, 32
    sd	    t6, -8(product)
    daddiu  product, product, 32

    ld	    t4, 40(product)
    v3mulu  t9, t3, t2
    ld	    t5, 40(modulus)
    bgez    i, MM$L4
    sd	    t7, -32(product)

#cleanup after loop
    v3mulu  t6, t5, t4
    sd	    t8, -24(product)
    sd	    zero, 8(product)
    sd	    zero, 16(product)
    v3mulu  t2, zero, zero
    sd	    zero, 24(product)
    sd	    zero, 32(product)
    daddiu  l, l, -6
    sd	    zero, 40(product)
    sd	    t9, -16(product)
    sd	    t6, -8(product)

    bgez    l, MM$L2
    sd	    t2, 0(product)
    
    ld      s0, 32(sp)
    ld      s1, 40(sp)
    ld      s2, 48(sp)
    bne	    t2, zero, MM$VSUB	    # there's a reasonably rare case where we overflow 1b, subtracting a modulus gets us back where we need to be
    ld      s3, 56(sp)

    jr      ra
    daddiu  sp, sp, 64

MM$VSUB:
    ld      a0, 8(sp)
    ld      a1, 24(sp)
    daddiu  a2, len, 1
    j	    Vsub	
    daddiu  sp, sp, 64
    .set pop

END(MontMul_O3)



#len must be a multiple of 4 for this function as well as mplier, mpcand, modulus must be padded with zero for 3 qwords
LEAF(MontMul)
# stash all the registers
    .set push
    .set arch=octeon2
    daddiu  sp, sp, -64        # be sure to match this at epilog
    sd      mpcand, 0(sp)
    sd      product, 8(sp)
    sd      len, 16(sp)
    sd      modulus, 24(sp)
    andi    v0, len, 0x3
    sd      s0, 32(sp)
    tne	    v0, zero		// check that len is multiple of 4
    sd      s1, 40(sp)
    


# I want to clear the product registers. This will clear len+3
    daddiu  i, len, 1
MML$L1:
    sd      zero, 0(product)
    daddiu  i, i, -4
    sd      zero, 8(product)
    daddiu  product, product, 32
    sd      zero, -16(product)
    bgez    i, MML$L1
    sd      zero, -8(product)

    sd      zero, 0(product)
    sd      zero, 8(product)
    sd      zero, 16(product)

    daddiu  l, len, -1


MML$L2:
    ld	    t2, 0(mplier)
    daddiu  mplier, mplier, 24
    ld	    t3, -16(mplier)
    ld      product, 8(sp)
    ld	    t4, -8(mplier)
    ld      mpcand, 0(sp)
    mtm0    t2
    mtm1    t3
    ld	    t2, 0(product)
    mtm2    t4
    ld	    t3, 0(mpcand)

    ld	    t4, 8(product)
    v3mulu  t7, t3, t2
    ld	    t5, 8(mpcand)
    daddiu  i, len, -5

    ld	    t2, 16(product)
    v3mulu  t8, t5, t4
    ld	    t3, 16(mpcand)
    daddiu  mpcand, mpcand, 32
    daddiu  product, product, 32

    ld	    t4, -8(product)
    v3mulu  t9, t3, t2
    ld	    t5, -8(mpcand)
    sd	    t7, -32(product)

#Main loop
.align 3
MML$L3:
    ld	    t2, 0(product)
    v3mulu  t6, t5, t4
    ld	    t3, 0(mpcand)
    sd	    t8, -24(product)

    ld	    t4, 8(product)
    v3mulu  t7, t3, t2
    ld	    t5, 8(mpcand)
    daddiu  i, i, -4
    sd	    t9, -16(product)

    ld	    t2, 16(product)
    v3mulu  t8, t5, t4
    ld	    t3, 16(mpcand)
    daddiu  mpcand, mpcand, 32
    sd	    t6, -8(product)
    daddiu  product, product, 32

    ld	    t4, -8(product)
    v3mulu  t9, t3, t2
    ld	    t5, -8(mpcand)
    bgez    i, MML$L3
    sd	    t7, -32(product)

#cleanup after loop
    ld	    t2, 0(product)
    v3mulu  t6, t5, t4
    daddiu  v0, product, 0
    sd	    t8, -24(v0)
    sd	    t9, -16(v0)
    ld      product, 8(sp)

    v3mulu  t2, zero, t2
    ld	    t3, 0(recip)
    ld	    t8, 8(recip)
    ld	    t7, 16(recip)
    v3mulu  t4, zero, zero
    sd	    t6, -8(v0)
    ld      modulus, 24(sp)
    sd	    t2, 0(v0)

    v3mulu  t6, zero, zero
    ld	    t5, 0(product)
    mtm0    t3
    ld	    t2, 8(product)
    mtm1    t8
    mtm2    t7
    ld	    t7, 16(product)

    v3mulu  t5, t5, zero
    sd	    t4, 8(v0)
    sd	    t6, 16(v0)
    v3mulu  t2, t2, zero
    v3mulu  t7, t7, zero

    mtm0    t5
    mtm1    t2
    ld	    t2, 0(product)
    mtm2    t7

    ld	    t3, 0(modulus)
    v3mulu  t2, t3, t2

    ld	    t4, 8(product)
    ld	    t5, 8(modulus)
    v3mulu  t4, t5, t4

    ld	    t6, 16(product)
    ld	    t7, 16(modulus)
    v3mulu  t6, t7, t6

#First iteration through loop
    ld	    t2, 24(product)
    daddiu  i, len, -1
    ld	    t3, 24(modulus)

    ld	    t4, 32(product)
    v3mulu  t7, t3, t2
    ld	    t5, 32(modulus)
    daddiu  i, i, -4

    ld	    t2, 40(product)
    v3mulu  t8, t5, t4
    ld	    t3, 40(modulus)
    daddiu  modulus, modulus, 32
    daddiu  product, product, 32

    ld	    t4, 16(product)
    v3mulu  t9, t3, t2
    ld	    t5, 16(modulus)
    sd	    t7, -32(product)

#Main loop
.align 3
MML$L4:
    ld	    t2, 24(product)
    v3mulu  t6, t5, t4
    ld	    t3, 24(modulus)
    sd	    t8, -24(product)

    ld	    t4, 32(product)
    v3mulu  t7, t3, t2
    ld	    t5, 32(modulus)
    daddiu  i, i, -4
    sd	    t9, -16(product)

    ld	    t2, 40(product)
    v3mulu  t8, t5, t4
    ld	    t3, 40(modulus)
    daddiu  modulus, modulus, 32
    sd	    t6, -8(product)
    daddiu  product, product, 32

    ld	    t4, 16(product)
    v3mulu  t9, t3, t2
    ld	    t5, 16(modulus)
    bgez    i, MML$L4
    sd	    t7, -32(product)

#cleanup after loop
    v3mulu  t6, t5, t4
    sd	    t8, -24(product)
    sd	    t9, -16(product)
    sd	    zero, 8(product)
    v3mulu  t2, zero, zero
    sd	    zero, 16(product)
    daddiu  l, l, -3
    sd	    t6, -8(product)

    bgez    l, MML$L2
    sd	    t2, 0(product)
    
    ld      s0, 32(sp)
    bne	    t2, zero, MML$VSUB	    # we overflowed, this indicates something bad happened
    ld      s1, 40(sp)

    jr      ra
    daddiu  sp, sp, 64

MML$VSUB:
    ld      a0, 8(sp)
    ld      a1, 24(sp)
    daddiu  a2, len, 1
    j	    Vsub	
    daddiu  sp, sp, 64
    .set pop

END(MontMul)

/*
Simpler routine without good scheduling
LEAF(MontMul)
# stash all the registers
    daddiu  sp, sp, -64        # be sure to match this at epilog
    sd      mpcand, 0(sp)
    sd      product, 8(sp)
    sd      len, 16(sp)
    sd      modulus, 24(sp)
    sd      s0, 32(sp)
    sd      s1, 40(sp)


# I want to clear the product registers. This will clear len+3 
    daddiu  i, len, -1
MML$L1:
    sd      zero, 0(product)
    sd      zero, 8(product)
    daddiu  i, i, -4
    sd      zero, 16(product)
    sd      zero, 24(product)
    bgez    i, MML$L1
    daddiu  product, product, 32

    sd      zero, 0(product)
    sd      zero, 8(product)
    sd      zero, 16(product)

    daddiu  l, len, -1


MML$L2:
    ld	    t2, 0(mplier)
    ld	    t3, 8(mplier)
    ld	    t4, 16(mplier)
    daddiu  mplier, mplier, 24
    ld      mpcand, 0(sp)
    mtm0    t2
    ld      product, 8(sp)
    mtm1    t3
    daddiu  i, len, -1
    mtm2    t4


#  for (k=0; k<len; k+=4)
#    {
#    V3MULU(product[k+0], mpcand[k+0], product[k+0]);
#    V3MULU(product[k+1], mpcand[k+1], product[k+1]);
#    V3MULU(product[k+2], mpcand[k+2], product[k+2]);
#    V3MULU(product[k+3], mpcand[k+3], product[k+3]);
#    }
# V3MULU(product[k], 0, product[k]); k++;
# V3MULU(product[k], 0, 0); k++;
# V3MULU(product[k], 0, 0);

MML$L3:
    ld	    t2, 0(product)
    ld	    t3, 0(mpcand)
    v3mulu  t2, t3, t2
    sd	    t2, 0(product)

    ld	    t4, 8(product)
    ld	    t5, 8(mpcand)
    v3mulu  t4, t5, t4
    sd	    t4, 8(product)

    ld	    t6, 16(product)
    ld	    t7, 16(mpcand)
    v3mulu  t6, t7, t6
    sd	    t6, 16(product)

    ld	    t2, 24(product)
    ld	    t3, 24(mpcand)
    v3mulu  t2, t3, t2
    sd	    t2, 24(product)

    daddiu  product, product, 32
    daddiu  mpcand, mpcand, 32

    daddiu  i, i, -4
    bgez    i, MML$L3
    nop

    ld	    t2, 0(product)
    v3mulu  t2, zero, t2
    sd	    t2, 0(product)

    v3mulu  t4, zero, zero
    sd	    t4, 8(product)

    v3mulu  t6, zero, zero
    sd	    t6, 16(product)

    ld	    t2, 0(recip)
    ld	    t3, 8(recip)
    ld	    t4, 16(recip)
    mtm0    t2
    mtm1    t3
    mtm2    t4

    ld      product, 8(sp)
    ld      modulus, 24(sp)

    ld	    t5, 0(product)
    ld	    t6, 8(product)
    ld	    t7, 16(product)

    v3mulu  t5, t5, zero
    v3mulu  t6, t6, zero
    v3mulu  t7, t7, zero

    mtm0    t5
    mtm1    t6
    mtm2    t7

    ld	    t2, 0(product)
    ld	    t3, 0(modulus)
    v3mulu  t2, t3, t2
    tne	    t2, zero

    ld	    t4, 8(product)
    ld	    t5, 8(modulus)
    v3mulu  t4, t5, t4
    tne	    t4, zero

    ld	    t6, 16(product)
    ld	    t7, 16(modulus)
    v3mulu  t6, t7, t6
    tne	    t6, zero

    daddiu  i, len, -1
MML$L4:
    ld	    t2, 24(product)
    ld	    t3, 24(modulus)
    v3mulu  t2, t3, t2
    sd	    t2, 0(product)

    ld	    t4, 32(product)
    ld	    t5, 32(modulus)
    v3mulu  t4, t5, t4
    sd	    t4, 8(product)

    ld	    t6, 40(product)
    ld	    t7, 40(modulus)
    v3mulu  t6, t7, t6
    sd	    t6, 16(product)

    ld	    t2, 48(product)
    ld	    t3, 48(modulus)
    v3mulu  t2, t3, t2
    sd	    t2, 24(product)

    daddiu  product, product, 32
    daddiu  modulus, modulus, 32

    daddiu  i, i, -4
    bgez    i, MML$L4
    nop

    v3mulu  t2, zero, zero
    sd	    t2, 0(product)
    sd	    zero, 8(product)
    sd	    zero, 16(product)

    daddiu  l, l, -3
    bgez    l, MML$L2
    
    ld	    v0, 0(product)
    tne	    v0, zero	    # we overflowed, this indicates something bad happened
    ld      s0, 32(sp)
    ld      s1, 40(sp)

    jr      ra
    daddiu  sp, sp, 64

END(MontMul)
*/    



LEAF(MontMul512)
MontMul512:
# stash all the registers
    .set push
    .set arch=octeon3
    ld	    t5, 0(mplier)
    daddiu  sp, sp, -64        # be sure to match this at epilog    
    sd	    s0,	0(sp)
    or	    s0, zero, zero
    sd	    s1,	8(sp)
    or	    s1, zero, zero
    sd	    s2,	16(sp)
    or	    s2, zero, zero
    sd	    s3,	24(sp)
    or	    s3, zero, zero
    sd	    s4,	32(sp)
    or	    s4, zero, zero
    sd	    s5,	40(sp)
    or	    s5, zero, zero
    sd	    s6,	48(sp)
    or	    s6, zero, zero
    sd	    s7,	56(sp)
    or	    s7, zero, zero

    ld	    t6, 8(mplier)
    daddiu  len, zero, 8
    ld	    t7, 8(recip)
    ld	    recip, 0(recip)
    or	    t8, zero, zero
    ld	    t2, 0(mpcand)
    mtm0    t5
    ld	    t3, 8(mpcand)
    mtm1    t6
    or	    t9, zero, zero

.align 3
MM512$L1:
    ld	    t4, 16(mpcand)
    vmulu   s0, t2, s0
    ld	    t2, 24(mpcand)
    vmulu   s1, t3, s1
    ld	    t3, 32(mpcand)
    vmulu   s2, t4, s2
    ld	    t4, 40(mpcand)
    vmulu   s3, t2, s3
    ld	    t2, 48(mpcand)
    vmulu   s4, t3, s4
    ld	    t3, 56(mpcand)
    vmulu   s5, t4, s5
    vmulu   s6, t2, s6
    vmulu   s7, t3, s7
    vmulu   t8, zero, t8
    vmulu   t9, zero, zero
    
    mtm0    recip
    daddiu  mplier, mplier, 16
    mtm1    t7
    daddiu  len, len, -2
    vmulu   t4, s0, zero
    ld	    t2, 0(modulus)
    vmulu   t5, s1, zero
    ld	    t3, 8(modulus)
    mtm0    t4
    mtm1    t5

    ld	    t4, 16(modulus)
    vmulu   zero, t2, s0
    ld	    t2, 24(modulus)
    vmulu   zero, t3, s1
    ld	    t3, 32(modulus)
    vmulu   s0, t4, s2
    ld	    t4, 40(modulus)
    vmulu   s1, t2, s3
    ld	    t2, 48(modulus)
    vmulu   s2, t3, s4
    ld	    t3, 56(modulus)
    vmulu   s3, t4, s5
    vmulu   s4, t2, s6
    ld	    t5, 0(mplier)
    vmulu   s5, t3, s7
    ld	    t6, 8(mplier)
    vmulu   s6, zero, t8
    ld	    t2, 0(mpcand)
    vmulu   s7, zero, t9
    ld	    t3, 8(mpcand)
    vmulu   t8, zero, zero
    mtm0    t5
    bne	    len, zero, MM512$L1
    mtm1    t6

    sd	    s0,	0(product)
    sd	    s1,	8(product)
    sd	    s2,	16(product)
    sd	    s3,	24(product)
    sd	    s4,	32(product)
    sd	    s5,	40(product)
    sd	    s6,	48(product)
    sd	    s7,	56(product)
    bne	    t8, zero, MM512$VSUB
    sd	    t8,	64(product)

    ld	    s0,	0(sp)
    ld	    s1,	8(sp)
    ld	    s2,	16(sp)
    ld	    s3,	24(sp)
    ld	    s4, 32(sp)
    ld	    s5,	40(sp)
    ld	    s6,	48(sp)
    ld	    s7,	56(sp)
    tne	    t8, zero		# assertion for overflow, if this fires something bad happened
    jr      ra
    daddiu  sp, sp, 64

MM512$VSUB:
    ld	    s0,	0(sp)
    ld	    s1,	8(sp)
    ld	    s2,	16(sp)
    ld	    s3,	24(sp)
    ld	    s4, 32(sp)
    ld	    s5,	40(sp)
    ld	    s6,	48(sp)
    ld	    s7,	56(sp)
    daddiu  a0, product, 0
    daddiu  a1, modulus, 0
    daddiu  a2, zero, 9
    j	    Vsub	
    daddiu  sp, sp, 64
    .set pop

END(MontMul512)


// len will be *64
LEAF(MontMul576)
MontMul576:
# stash all the registers
    .set push
    .set arch=octeon2
    daddiu  sp, sp, -64        # be sure to match this at epilog    
    sd	    s0,	0(sp)
    or	    s0, zero, zero
    sd	    s1,	8(sp)
    or	    s1, zero, zero
    sd	    s2,	16(sp)
    or	    s2, zero, zero
    sd	    s3,	24(sp)
    or	    s3, zero, zero
    sd	    s4,	32(sp)
    or	    s4, zero, zero
    sd	    s5,	40(sp)
    or	    s5, zero, zero
    sd	    s6,	48(sp)
    or	    s6, zero, zero
    sd	    s7,	56(sp)
    or	    s7, zero, zero

    ld	    t5, 0(mplier)
    daddiu  len, zero, 8
    ld	    recip, 0(recip)
    or	    t8, zero, zero
    ld	    t2, 0(mpcand)
    mtm0    t5
    mtm1    zero
    mtm2    zero
    ld	    t3, 8(mpcand)
    or	    t9, zero, zero

.align 3
MML512$L3:
    ld	    t4, 16(mpcand)
    v3mulu  s0, t2, s0
    ld	    t2, 24(mpcand)
    v3mulu  s1, t3, s1
    ld	    t3, 32(mpcand)
    v3mulu  s2, t4, s2
    ld	    t4, 40(mpcand)
    v3mulu  s3, t2, s3
    ld	    t2, 48(mpcand)
    v3mulu  s4, t3, s4
    ld	    t3, 56(mpcand)
    v3mulu  s5, t4, s5
    daddiu  mplier, mplier, 8
    v3mulu  s6, t2, s6
    daddiu  len, len, -1
    v3mulu  s7, t3, s7
    v3mulu  t8, zero, t8
    
    mtm0    recip
    ld	    t2, 0(modulus)
    v3mulu  t5,s0,zero
    mtm0    t5
    ld	    t3, 8(modulus)

    ld	    t4, 16(modulus)
    v3mulu  zero, t2, s0
    ld	    t2, 24(modulus)
    v3mulu  s0, t3, s1
    ld	    t3, 32(modulus)
    v3mulu  s1, t4, s2
    ld	    t4, 40(modulus)
    v3mulu  s2, t2, s3
    ld	    t2, 48(modulus)
    v3mulu  s3, t3, s4
    ld	    t3, 56(modulus)
    v3mulu  s4, t4, s5
    v3mulu  s5, t2, s6
    ld	    t5, 0(mplier)
    v3mulu  s6, t3, s7
    ld	    t2, 0(mpcand)
    v3mulu  s7, zero, t8
    ld	    t3, 8(mpcand)
    v3mulu  t8, zero, zero
    sd	    s0,	0(product)
    bne	    len, zero, MML512$L3
    mtm0    t5

    sd	    s1,	8(product)
    sd	    s2,	16(product)
    sd	    s3,	24(product)
    sd	    s4,	32(product)
    sd	    s5,	40(product)
    sd	    s6,	48(product)
    sd	    s7,	56(product)
    bne	    t8, zero, MML512$VSUB
    sd	    t8,	64(product)


MM512$DONE: 
    ld	    s0,	0(sp)
    ld	    s1,	8(sp)
    ld	    s2,	16(sp)
    ld	    s3,	24(sp)
    ld	    s4, 32(sp)
    ld	    s5,	40(sp)
    ld	    s6,	48(sp)
    ld	    s7,	56(sp)
    tne	    t8, zero		# assertion for overflow, if this fires something bad happened
    jr      ra
    daddiu  sp, sp, 64

MML512$VSUB:
    ld	    s0,	0(sp)
    ld	    s1,	8(sp)
    ld	    s2,	16(sp)
    ld	    s3,	24(sp)
    ld	    s4, 32(sp)
    ld	    s5,	40(sp)
    ld	    s6,	48(sp)
    ld	    s7,	56(sp)
    daddiu  a0, product, 0
    daddiu  a1, modulus, 0
    daddiu  a2, zero, 9
    j	    Vsub	
    daddiu  sp, sp, 64
    .set pop

END(MontMul576)

#else

#define zero    $0	/* always returns 0 */
#define AT      $1	/* reserved for use by assembler */

#define v0      $2	/* value returned by subroutine */
#define v1      $3	

#define a0      $4	/* parameters for a subroutine */
#define a1      $5	
#define a2      $6
#define a3      $7

#define t0      $8	/* subroutines can use without saving */
#define t1      $9
#define t2      $10
#define t3      $11
#define t4      $12
#define t5      $13
#define t6      $14
#define t7      $15

#define s0      $16	/* subroutine register variables */
#define s1      $17
#define s2      $18
#define s3      $19
#define s4      $20
#define s5      $21
#define s6      $22
#define s7      $23

#define s8      $30	/* frame pointer */

#define t8      $24
#define t9      $25

#define k0      $26	/* reserved for use by interrupt/trap handler */
#define k1      $27

#define gp      $28	/* global pointer */

#define sp      $29	/* stack pointer */
#define fp      $30	/* frame pointer */
#define ra      $31	/* return address for subroutine */

#define LEAF(symbol)						\
		.globl   symbol;				\
		.align   2;					\
		.type    symbol, @function;			\
		.ent     symbol, 0;				\
symbol:		.frame   sp, 0, ra

/*
 * END - mark end of function
 */
#define END(function)						\
		.end     function;				\
		.size    function, .-function

#define EXPORT(symbol)						\
		.globl   symbol;				\
symbol:


# void Vadd(__uint64 *accum, const __uint64 *addend, int len)
#void Vadd(__uint64 *a, const __uint64 *b, int len)
#   {
#   int i;

#   MTM0(1, 0);
#   for (i=0; i<len; i++)
#      {
#      VMULU(a[i], b[i], a[i]);
#      }
#   }



#define accum	a0
#define addend	a1
#define len	a2
#define i	v0

.set noreorder 
.set noat

# len must be >1

LEAF(Vadd)

Vadd:
    ld	    t3, 0(addend)
    addiu   t0, zero, 1
    ld	    t2, 0(accum)
    mtm0    t0
    mtm1    zero
    mtm2    zero

    daddiu  i, len, -1	    # i=len-1
    
    daddiu  addend, addend, 8
    daddiu  accum, accum, 8    

    ld	    t1, 0(addend)
    v3mulu  t3, t3, t2


VADD$L1: 
    ld	    t2, 0(accum)
    daddiu  i, i, -1
    
    daddiu  accum, accum, 8
    daddiu  addend, addend, 8

    sd	    t3, -16(accum)
    v3mulu  t3, t1, t2

    bne	    i, zero, VADD$L1
    ld	    t1, 0(addend)


VADD$DONE:
    jr	    ra
    sd	    t3, -8(accum)

END(Vadd)



LEAF(Vsub)

# Since I don't support signed vmul's for subtract I will
# skip over all trailing 0's and then do an add of 1's complement

Vsub:
    daddiu  i, len, 	    # i=len
    daddiu  t8, zero, -1

VSUB$L1:
    ld	    t1, 0(addend)
    daddiu  i, i, -1
    bltz    i, VSUB$DONE
    daddiu  addend,addend, 8
    ld	    t3, 0(accum)
    beq	    t1, zero, VSUB$L1
    daddiu  accum,accum, 8

    ld	    t3, -8(addend)
    daddiu  t0, zero, 1
    ld	    t2, -8(accum)
    mtm0    t0
    mtm1    zero
    mtm2    zero
    xor	    t3, t3, t8
    daddiu  t3, t3, 1    

    ld	    t1, 0(addend)
    v3mulu  t3, t3, t2
    beq     i, zero, VSUB$DONE
    nop


VSUB$L2: 
    ld	    t2, 0(accum)
    daddiu  i, i, -1
    
    daddiu  accum, accum, 8
    daddiu  addend, addend, 8

    xor	    t1, t1, t8

    sd	    t3, -16(accum)
    v3mulu  t3, t1, t2

    bne	    i, zero, VSUB$L2
    ld	    t1, 0(addend)


VSUB$DONE:
    jr	    ra
    sd	    t3, -8(accum)

END(Vsub)

#undef accum
#undef addend
#undef len
#undef i



#define product		a0
#define mpcand		a1
#define mplier		a2
#define modulus		a3
#define recip		t0
#define len		t1
#define i               v0
#define l               s0

# len will be * 192b

LEAF(MontMul_O3)
MontMul_O3:
# Simpler routine without good scheduling
# stash all the registers
    .set push
    .set arch=octeon3
    daddiu  sp, sp, -64        # be sure to match this at epilog
    sd      mpcand, 0(sp)
    sd      product, 8(sp)
    sd      len, 16(sp)
    sd      modulus, 24(sp)
    sd      s0, 32(sp)
    sd      s1, 40(sp)
    sd      s2, 48(sp)
    sd      s3, 56(sp)


# I want to clear the product registers. This will clear len+6 
    daddiu  i, len, 4-1
MM$L1:
    sd      zero, 0(product)
    daddiu  i, i, -4
    sd      zero, 8(product)
    daddiu  product, product, 32
    sd      zero, -16(product)
    bgez    i, MM$L1
    sd      zero, -8(product)

    sd      zero, 0(product)
    daddiu  l, len, -1
    sd      zero, 8(product)

MM$L2:
    ld      product, 8(sp)
    ld      mpcand, 0(sp)
    ld	    t2, 0(mplier)
    ld	    t3, 24(mplier)
    ld	    t4, 8(mplier)
    ld	    t5, 32(mplier)
    mtm0    t2, t3
    ld	    t6, 16(mplier)
    ld	    t7, 40(mplier)
    daddiu  mplier, mplier, 48
    ld	    t2, 0(product)
    mtm1    t4, t5
    ld	    t3, 0(mpcand)
    mtm2    t6, t7

    ld	    t4, 8(product)
    v3mulu  t7, t3, t2
    ld	    t5, 8(mpcand)
    daddiu  i, len, -5

    ld	    t2, 16(product)
    v3mulu  t8, t5, t4
    ld	    t3, 16(mpcand)
    daddiu  mpcand, mpcand, 32
    daddiu  product, product, 32

    ld	    t4, -8(product)
    v3mulu  t9, t3, t2
    ld	    t5, -8(mpcand)
    sd	    t7, -32(product)

#Main loop
.align 3
MM$L3:
    ld	    t2, 0(product)
    v3mulu  t6, t5, t4
    ld	    t3, 0(mpcand)
    sd	    t8, -24(product)

    ld	    t4, 8(product)
    v3mulu  t7, t3, t2
    ld	    t5, 8(mpcand)
    daddiu  i, i, -4
    sd	    t9, -16(product)

    ld	    t2, 16(product)
    v3mulu  t8, t5, t4
    ld	    t3, 16(mpcand)
    daddiu  mpcand, mpcand, 32
    sd	    t6, -8(product)
    daddiu  product, product, 32

    ld	    t4, -8(product)
    v3mulu  t9, t3, t2
    ld	    t5, -8(mpcand)
    bgez    i, MM$L3
    sd	    t7, -32(product)

#cleanup after loop
    v3mulu  t6, t5, t4
    ld	    t2, 0(product)
    sd	    t8, -24(product)
    sd	    t9, -16(product)
    v3mulu  t2, zero, t2
    ld      modulus, 24(sp)
    daddiu  v0, product, 0
    ld      product, 8(sp)
    v3mulu  t4, zero, zero

    sd	    t6, -8(v0)
    v3mulu  t6, zero, zero
    ld	    t3, 0(recip)
    ld	    t5, 24(recip)
    sd	    t2, 0(v0)
    v3mulu  t2, zero, zero
    ld	    t7, 8(recip)
    ld	    t9, 32(recip)
    sd	    t4, 8(v0)
    v3mulu  t4, zero, zero
    ld	    s2, 16(recip)
    ld	    s3, 40(recip)
    sd	    t6, 16(v0)
    v3mulu  t6, zero, zero
    sd	    t2, 24(v0)
    ld	    t2, 0(product)
    sd	    t4, 32(v0)
    mtm0    t3, t5
    ld	    t3, 8(product)
    mtm1    t7, t9
    sd	    t6, 40(v0)
    mtm2    s2, s3

    ld	    t4, 16(product)
    v3mulu  t2, t2, zero
    ld	    t5, 24(product)
    ld	    t6, 32(product)
    ld	    t7, 40(product)
    v3mulu  t3, t3, zero
    v3mulu  t4, t4, zero
    v3mulu  t5, t5, zero
    v3mulu  t6, t6, zero
    ld	    s2, 0(product)
    ld	    s3, 0(modulus)
    v3mulu  t7, t7, zero

    mtm0    t2, t5
    mtm1    t3, t6
    ld	    t5, 8(modulus)
    mtm2    t4, t7

    ld	    t4, 8(product)
    v3mulu  s2, s3, s2

    ld	    t6, 16(product)
    ld	    t7, 16(modulus)
    v3mulu  t4, t5, t4
#    tne	    s2, zero

    ld	    t2, 24(product)
    ld	    t3, 24(modulus)
    v3mulu  t6, t7, t6
#    tne	    t4, zero

    ld	    t4, 32(product)
    ld	    t5, 32(modulus)
    v3mulu  t2, t3, t2
#    tne	    t6, zero

    ld	    t6, 40(product)
    ld	    t7, 40(modulus)
    v3mulu  t4, t5, t4
#    tne	    t2, zero

    v3mulu  t6, t7, t6
#    tne	    t4, zero
#    tne	    t6, zero

#First iteration through loop
    ld	    t2, 48(product)
    daddiu  i, len, -1
    ld	    t3, 48(modulus)

    ld	    t4, 56(product)
    v3mulu  t7, t3, t2
    ld	    t5, 56(modulus)
    daddiu  i, i, -4

    ld	    t2, 64(product)
    v3mulu  t8, t5, t4
    ld	    t3, 64(modulus)
    daddiu  modulus, modulus, 32
    daddiu  product, product, 32

    ld	    t4, 40(product)
    v3mulu  t9, t3, t2
    ld	    t5, 40(modulus)
    sd	    t7, -32(product)

#Main loop
.align 3
MM$L4:
    ld	    t2, 48(product)
    v3mulu  t6, t5, t4
    ld	    t3, 48(modulus)
    sd	    t8, -24(product)

    ld	    t4, 56(product)
    v3mulu  t7, t3, t2
    ld	    t5, 56(modulus)
    daddiu  i, i, -4
    sd	    t9, -16(product)

    ld	    t2, 64(product)
    v3mulu  t8, t5, t4
    ld	    t3, 64(modulus)
    daddiu  modulus, modulus, 32
    sd	    t6, -8(product)
    daddiu  product, product, 32

    ld	    t4, 40(product)
    v3mulu  t9, t3, t2
    ld	    t5, 40(modulus)
    bgez    i, MM$L4
    sd	    t7, -32(product)

#cleanup after loop
    v3mulu  t6, t5, t4
    sd	    t8, -24(product)
    sd	    zero, 8(product)
    sd	    zero, 16(product)
    v3mulu  t2, zero, zero
    sd	    zero, 24(product)
    sd	    zero, 32(product)
    daddiu  l, l, -6
    sd	    zero, 40(product)
    sd	    t9, -16(product)
    sd	    t6, -8(product)

    bgez    l, MM$L2
    sd	    t2, 0(product)
    
    ld      s0, 32(sp)
    ld      s1, 40(sp)
    ld      s2, 48(sp)
    bne	    t2, zero, MM$VSUB	    # there's a reasonably rare case where we overflow 1b, subtracting a modulus gets us back where we need to be
    ld      s3, 56(sp)

    jr      ra
    daddiu  sp, sp, 64

MM$VSUB:
    ld      a0, 8(sp)
    ld      a1, 24(sp)
    daddiu  a2, len, 1
    j	    Vsub	
    daddiu  sp, sp, 64
    .set pop

END(MontMul_O3)



#len must be a multiple of 4 for this function as well as mplier, mpcand, modulus must be padded with zero for 3 qwords
LEAF(MontMul)
# stash all the registers
    .set push
    .set arch=octeon2
    daddiu  sp, sp, -64        # be sure to match this at epilog
    sd      mpcand, 0(sp)
    sd      product, 8(sp)
    sd      len, 16(sp)
    sd      modulus, 24(sp)
    andi    v0, len, 0x3
    sd      s0, 32(sp)
    tne	    v0, zero		// check that len is multiple of 4
    sd      s1, 40(sp)
    


# I want to clear the product registers. This will clear len+3
    daddiu  i, len, 1
MML$L1:
    sd      zero, 0(product)
    daddiu  i, i, -4
    sd      zero, 8(product)
    daddiu  product, product, 32
    sd      zero, -16(product)
    bgez    i, MML$L1
    sd      zero, -8(product)

    sd      zero, 0(product)
    sd      zero, 8(product)
    sd      zero, 16(product)

    daddiu  l, len, -1


MML$L2:
    ld	    t2, 0(mplier)
    daddiu  mplier, mplier, 24
    ld	    t3, -16(mplier)
    ld      product, 8(sp)
    ld	    t4, -8(mplier)
    ld      mpcand, 0(sp)
    mtm0    t2
    mtm1    t3
    ld	    t2, 0(product)
    mtm2    t4
    ld	    t3, 0(mpcand)

    ld	    t4, 8(product)
    v3mulu  t7, t3, t2
    ld	    t5, 8(mpcand)
    daddiu  i, len, -5

    ld	    t2, 16(product)
    v3mulu  t8, t5, t4
    ld	    t3, 16(mpcand)
    daddiu  mpcand, mpcand, 32
    daddiu  product, product, 32

    ld	    t4, -8(product)
    v3mulu  t9, t3, t2
    ld	    t5, -8(mpcand)
    sd	    t7, -32(product)

#Main loop
.align 3
MML$L3:
    ld	    t2, 0(product)
    v3mulu  t6, t5, t4
    ld	    t3, 0(mpcand)
    sd	    t8, -24(product)

    ld	    t4, 8(product)
    v3mulu  t7, t3, t2
    ld	    t5, 8(mpcand)
    daddiu  i, i, -4
    sd	    t9, -16(product)

    ld	    t2, 16(product)
    v3mulu  t8, t5, t4
    ld	    t3, 16(mpcand)
    daddiu  mpcand, mpcand, 32
    sd	    t6, -8(product)
    daddiu  product, product, 32

    ld	    t4, -8(product)
    v3mulu  t9, t3, t2
    ld	    t5, -8(mpcand)
    bgez    i, MML$L3
    sd	    t7, -32(product)

#cleanup after loop
    ld	    t2, 0(product)
    v3mulu  t6, t5, t4
    daddiu  v0, product, 0
    sd	    t8, -24(v0)
    sd	    t9, -16(v0)
    ld      product, 8(sp)

    v3mulu  t2, zero, t2
    ld	    t3, 0(recip)
    ld	    t8, 8(recip)
    ld	    t7, 16(recip)
    v3mulu  t4, zero, zero
    sd	    t6, -8(v0)
    ld      modulus, 24(sp)
    sd	    t2, 0(v0)

    v3mulu  t6, zero, zero
    ld	    t5, 0(product)
    mtm0    t3
    ld	    t2, 8(product)
    mtm1    t8
    mtm2    t7
    ld	    t7, 16(product)

    v3mulu  t5, t5, zero
    sd	    t4, 8(v0)
    sd	    t6, 16(v0)
    v3mulu  t2, t2, zero
    v3mulu  t7, t7, zero

    mtm0    t5
    mtm1    t2
    ld	    t2, 0(product)
    mtm2    t7

    ld	    t3, 0(modulus)
    v3mulu  t2, t3, t2

    ld	    t4, 8(product)
    ld	    t5, 8(modulus)
    v3mulu  t4, t5, t4

    ld	    t6, 16(product)
    ld	    t7, 16(modulus)
    v3mulu  t6, t7, t6

#First iteration through loop
    ld	    t2, 24(product)
    daddiu  i, len, -1
    ld	    t3, 24(modulus)

    ld	    t4, 32(product)
    v3mulu  t7, t3, t2
    ld	    t5, 32(modulus)
    daddiu  i, i, -4

    ld	    t2, 40(product)
    v3mulu  t8, t5, t4
    ld	    t3, 40(modulus)
    daddiu  modulus, modulus, 32
    daddiu  product, product, 32

    ld	    t4, 16(product)
    v3mulu  t9, t3, t2
    ld	    t5, 16(modulus)
    sd	    t7, -32(product)

#Main loop
.align 3
MML$L4:
    ld	    t2, 24(product)
    v3mulu  t6, t5, t4
    ld	    t3, 24(modulus)
    sd	    t8, -24(product)

    ld	    t4, 32(product)
    v3mulu  t7, t3, t2
    ld	    t5, 32(modulus)
    daddiu  i, i, -4
    sd	    t9, -16(product)

    ld	    t2, 40(product)
    v3mulu  t8, t5, t4
    ld	    t3, 40(modulus)
    daddiu  modulus, modulus, 32
    sd	    t6, -8(product)
    daddiu  product, product, 32

    ld	    t4, 16(product)
    v3mulu  t9, t3, t2
    ld	    t5, 16(modulus)
    bgez    i, MML$L4
    sd	    t7, -32(product)

#cleanup after loop
    v3mulu  t6, t5, t4
    sd	    t8, -24(product)
    sd	    t9, -16(product)
    sd	    zero, 8(product)
    v3mulu  t2, zero, zero
    sd	    zero, 16(product)
    daddiu  l, l, -3
    sd	    t6, -8(product)

    bgez    l, MML$L2
    sd	    t2, 0(product)
    
    ld      s0, 32(sp)
    bne	    t2, zero, MML$VSUB	    # we overflowed, this indicates something bad happened
    ld      s1, 40(sp)

    jr      ra
    daddiu  sp, sp, 64

MML$VSUB:
    ld      a0, 8(sp)
    ld      a1, 24(sp)
    daddiu  a2, len, 1
    j	    Vsub	
    daddiu  sp, sp, 64
    .set pop

END(MontMul)

/*
Simpler routine without good scheduling
LEAF(MontMul)
# stash all the registers
    daddiu  sp, sp, -64        # be sure to match this at epilog
    sd      mpcand, 0(sp)
    sd      product, 8(sp)
    sd      len, 16(sp)
    sd      modulus, 24(sp)
    sd      s0, 32(sp)
    sd      s1, 40(sp)


# I want to clear the product registers. This will clear len+3 
    daddiu  i, len, -1
MML$L1:
    sd      zero, 0(product)
    sd      zero, 8(product)
    daddiu  i, i, -4
    sd      zero, 16(product)
    sd      zero, 24(product)
    bgez    i, MML$L1
    daddiu  product, product, 32

    sd      zero, 0(product)
    sd      zero, 8(product)
    sd      zero, 16(product)

    daddiu  l, len, -1


MML$L2:
    ld	    t2, 0(mplier)
    ld	    t3, 8(mplier)
    ld	    t4, 16(mplier)
    daddiu  mplier, mplier, 24
    ld      mpcand, 0(sp)
    mtm0    t2
    ld      product, 8(sp)
    mtm1    t3
    daddiu  i, len, -1
    mtm2    t4


#  for (k=0; k<len; k+=4)
#    {
#    V3MULU(product[k+0], mpcand[k+0], product[k+0]);
#    V3MULU(product[k+1], mpcand[k+1], product[k+1]);
#    V3MULU(product[k+2], mpcand[k+2], product[k+2]);
#    V3MULU(product[k+3], mpcand[k+3], product[k+3]);
#    }
# V3MULU(product[k], 0, product[k]); k++;
# V3MULU(product[k], 0, 0); k++;
# V3MULU(product[k], 0, 0);

MML$L3:
    ld	    t2, 0(product)
    ld	    t3, 0(mpcand)
    v3mulu  t2, t3, t2
    sd	    t2, 0(product)

    ld	    t4, 8(product)
    ld	    t5, 8(mpcand)
    v3mulu  t4, t5, t4
    sd	    t4, 8(product)

    ld	    t6, 16(product)
    ld	    t7, 16(mpcand)
    v3mulu  t6, t7, t6
    sd	    t6, 16(product)

    ld	    t2, 24(product)
    ld	    t3, 24(mpcand)
    v3mulu  t2, t3, t2
    sd	    t2, 24(product)

    daddiu  product, product, 32
    daddiu  mpcand, mpcand, 32

    daddiu  i, i, -4
    bgez    i, MML$L3
    nop

    ld	    t2, 0(product)
    v3mulu  t2, zero, t2
    sd	    t2, 0(product)

    v3mulu  t4, zero, zero
    sd	    t4, 8(product)

    v3mulu  t6, zero, zero
    sd	    t6, 16(product)

    ld	    t2, 0(recip)
    ld	    t3, 8(recip)
    ld	    t4, 16(recip)
    mtm0    t2
    mtm1    t3
    mtm2    t4

    ld      product, 8(sp)
    ld      modulus, 24(sp)

    ld	    t5, 0(product)
    ld	    t6, 8(product)
    ld	    t7, 16(product)

    v3mulu  t5, t5, zero
    v3mulu  t6, t6, zero
    v3mulu  t7, t7, zero

    mtm0    t5
    mtm1    t6
    mtm2    t7

    ld	    t2, 0(product)
    ld	    t3, 0(modulus)
    v3mulu  t2, t3, t2
    tne	    t2, zero

    ld	    t4, 8(product)
    ld	    t5, 8(modulus)
    v3mulu  t4, t5, t4
    tne	    t4, zero

    ld	    t6, 16(product)
    ld	    t7, 16(modulus)
    v3mulu  t6, t7, t6
    tne	    t6, zero

    daddiu  i, len, -1
MML$L4:
    ld	    t2, 24(product)
    ld	    t3, 24(modulus)
    v3mulu  t2, t3, t2
    sd	    t2, 0(product)

    ld	    t4, 32(product)
    ld	    t5, 32(modulus)
    v3mulu  t4, t5, t4
    sd	    t4, 8(product)

    ld	    t6, 40(product)
    ld	    t7, 40(modulus)
    v3mulu  t6, t7, t6
    sd	    t6, 16(product)

    ld	    t2, 48(product)
    ld	    t3, 48(modulus)
    v3mulu  t2, t3, t2
    sd	    t2, 24(product)

    daddiu  product, product, 32
    daddiu  modulus, modulus, 32

    daddiu  i, i, -4
    bgez    i, MML$L4
    nop

    v3mulu  t2, zero, zero
    sd	    t2, 0(product)
    sd	    zero, 8(product)
    sd	    zero, 16(product)

    daddiu  l, l, -3
    bgez    l, MML$L2
    
    ld	    v0, 0(product)
    tne	    v0, zero	    # we overflowed, this indicates something bad happened
    ld      s0, 32(sp)
    ld      s1, 40(sp)

    jr      ra
    daddiu  sp, sp, 64

END(MontMul)
*/    



LEAF(MontMul512)
MontMul512:
# stash all the registers
    .set push
    .set arch=octeon3
    ld	    t5, 0(mplier)
    daddiu  sp, sp, -64        # be sure to match this at epilog    
    sd	    s0,	0(sp)
    or	    s0, zero, zero
    sd	    s1,	8(sp)
    or	    s1, zero, zero
    sd	    s2,	16(sp)
    or	    s2, zero, zero
    sd	    s3,	24(sp)
    or	    s3, zero, zero
    sd	    s4,	32(sp)
    or	    s4, zero, zero
    sd	    s5,	40(sp)
    or	    s5, zero, zero
    sd	    s6,	48(sp)
    or	    s6, zero, zero
    sd	    s7,	56(sp)
    or	    s7, zero, zero

    ld	    t6, 8(mplier)
    daddiu  len, zero, 8
    ld	    t7, 8(recip)
    ld	    recip, 0(recip)
    or	    t8, zero, zero
    ld	    t2, 0(mpcand)
    mtm0    t5
    ld	    t3, 8(mpcand)
    mtm1    t6
    or	    t9, zero, zero

.align 3
MM512$L1:
    ld	    t4, 16(mpcand)
    vmulu   s0, t2, s0
    ld	    t2, 24(mpcand)
    vmulu   s1, t3, s1
    ld	    t3, 32(mpcand)
    vmulu   s2, t4, s2
    ld	    t4, 40(mpcand)
    vmulu   s3, t2, s3
    ld	    t2, 48(mpcand)
    vmulu   s4, t3, s4
    ld	    t3, 56(mpcand)
    vmulu   s5, t4, s5
    vmulu   s6, t2, s6
    vmulu   s7, t3, s7
    vmulu   t8, zero, t8
    vmulu   t9, zero, zero
    
    mtm0    recip
    daddiu  mplier, mplier, 16
    mtm1    t7
    daddiu  len, len, -2
    vmulu   t4, s0, zero
    ld	    t2, 0(modulus)
    vmulu   t5, s1, zero
    ld	    t3, 8(modulus)
    mtm0    t4
    mtm1    t5

    ld	    t4, 16(modulus)
    vmulu   zero, t2, s0
    ld	    t2, 24(modulus)
    vmulu   zero, t3, s1
    ld	    t3, 32(modulus)
    vmulu   s0, t4, s2
    ld	    t4, 40(modulus)
    vmulu   s1, t2, s3
    ld	    t2, 48(modulus)
    vmulu   s2, t3, s4
    ld	    t3, 56(modulus)
    vmulu   s3, t4, s5
    vmulu   s4, t2, s6
    ld	    t5, 0(mplier)
    vmulu   s5, t3, s7
    ld	    t6, 8(mplier)
    vmulu   s6, zero, t8
    ld	    t2, 0(mpcand)
    vmulu   s7, zero, t9
    ld	    t3, 8(mpcand)
    vmulu   t8, zero, zero
    mtm0    t5
    bne	    len, zero, MM512$L1
    mtm1    t6

    sd	    s0,	0(product)
    sd	    s1,	8(product)
    sd	    s2,	16(product)
    sd	    s3,	24(product)
    sd	    s4,	32(product)
    sd	    s5,	40(product)
    sd	    s6,	48(product)
    sd	    s7,	56(product)
    bne	    t8, zero, MM512$VSUB
    sd	    t8,	64(product)

    ld	    s0,	0(sp)
    ld	    s1,	8(sp)
    ld	    s2,	16(sp)
    ld	    s3,	24(sp)
    ld	    s4, 32(sp)
    ld	    s5,	40(sp)
    ld	    s6,	48(sp)
    ld	    s7,	56(sp)
    tne	    t8, zero		# assertion for overflow, if this fires something bad happened
    jr      ra
    daddiu  sp, sp, 64

MM512$VSUB:
    ld	    s0,	0(sp)
    ld	    s1,	8(sp)
    ld	    s2,	16(sp)
    ld	    s3,	24(sp)
    ld	    s4, 32(sp)
    ld	    s5,	40(sp)
    ld	    s6,	48(sp)
    ld	    s7,	56(sp)
    daddiu  a0, product, 0
    daddiu  a1, modulus, 0
    daddiu  a2, zero, 9
    j	    Vsub	
    daddiu  sp, sp, 64
    .set pop

END(MontMul512)


// len will be *64
LEAF(MontMul576)
MontMul576:
# stash all the registers
    .set push
    .set arch=octeon2
    daddiu  sp, sp, -64        # be sure to match this at epilog    
    sd	    s0,	0(sp)
    or	    s0, zero, zero
    sd	    s1,	8(sp)
    or	    s1, zero, zero
    sd	    s2,	16(sp)
    or	    s2, zero, zero
    sd	    s3,	24(sp)
    or	    s3, zero, zero
    sd	    s4,	32(sp)
    or	    s4, zero, zero
    sd	    s5,	40(sp)
    or	    s5, zero, zero
    sd	    s6,	48(sp)
    or	    s6, zero, zero
    sd	    s7,	56(sp)
    or	    s7, zero, zero

    ld	    t5, 0(mplier)
    daddiu  len, zero, 8
    ld	    recip, 0(recip)
    or	    t8, zero, zero
    ld	    t2, 0(mpcand)
    mtm0    t5
    mtm1    zero
    mtm2    zero
    ld	    t3, 8(mpcand)
    or	    t9, zero, zero

.align 3
MML512$L3:
    ld	    t4, 16(mpcand)
    v3mulu  s0, t2, s0
    ld	    t2, 24(mpcand)
    v3mulu  s1, t3, s1
    ld	    t3, 32(mpcand)
    v3mulu  s2, t4, s2
    ld	    t4, 40(mpcand)
    v3mulu  s3, t2, s3
    ld	    t2, 48(mpcand)
    v3mulu  s4, t3, s4
    ld	    t3, 56(mpcand)
    v3mulu  s5, t4, s5
    daddiu  mplier, mplier, 8
    v3mulu  s6, t2, s6
    daddiu  len, len, -1
    v3mulu  s7, t3, s7
    v3mulu  t8, zero, t8
    
    mtm0    recip
    ld	    t2, 0(modulus)
    v3mulu  t5, s0, zero
    mtm0    t5
    ld	    t3, 8(modulus)

    ld	    t4, 16(modulus)
    v3mulu  zero, t2, s0
    ld	    t2, 24(modulus)
    v3mulu  s0, t3, s1
    ld	    t3, 32(modulus)
    v3mulu  s1, t4, s2
    ld	    t4, 40(modulus)
    v3mulu  s2, t2, s3
    ld	    t2, 48(modulus)
    v3mulu  s3, t3, s4
    ld	    t3, 56(modulus)
    v3mulu  s4, t4, s5
    v3mulu  s5, t2, s6
    ld	    t5, 0(mplier)
    v3mulu  s6, t3, s7
    ld	    t2, 0(mpcand)
    v3mulu  s7, zero, t8
    ld	    t3, 8(mpcand)
    v3mulu  t8, zero, zero
    sd	    s0,	0(product)
    bne	    len, zero, MML512$L3
    mtm0    t5

    sd	    s1,	8(product)
    sd	    s2,	16(product)
    sd	    s3,	24(product)
    sd	    s4,	32(product)
    sd	    s5,	40(product)
    sd	    s6,	48(product)
    sd	    s7,	56(product)
    bne	    t8, zero, MML512$VSUB
    sd	    t8,	64(product)


MM512$DONE: 
    ld	    s0,	0(sp)
    ld	    s1,	8(sp)
    ld	    s2,	16(sp)
    ld	    s3,	24(sp)
    ld	    s4, 32(sp)
    ld	    s5,	40(sp)
    ld	    s6,	48(sp)
    ld	    s7,	56(sp)
    tne	    t8, zero		# assertion for overflow, if this fires something bad happened
    jr      ra
    daddiu  sp, sp, 64

MML512$VSUB:
    ld	    s0,	0(sp)
    ld	    s1,	8(sp)
    ld	    s2,	16(sp)
    ld	    s3,	24(sp)
    ld	    s4, 32(sp)
    ld	    s5,	40(sp)
    ld	    s6,	48(sp)
    ld	    s7,	56(sp)
    daddiu  a0, product, 0
    daddiu  a1, modulus, 0
    daddiu  a2, zero, 9
    j	    Vsub	
    daddiu  sp, sp, 64
    .set pop

END(MontMul576)

#endif
