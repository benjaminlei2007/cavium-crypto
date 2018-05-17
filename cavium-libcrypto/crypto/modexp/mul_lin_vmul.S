//#include <machine/cpu.h>
//#include <sys/init.h>


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

LEAF(Vadd_vmul)

Vadd_vmul:
    ld	    t3, 0(addend)
    addiu   t0, zero, 1
    ld	    t2, 0(accum)
    mtm0    t0

    daddiu  i, len, -1	    # i=len-1
    
    daddiu  addend, addend, 8
    daddiu  accum, accum, 8    

    ld	    t1, 0(addend)
    vmulu   t3, t3, t2


VADD$L1: 
    ld	    t2, 0(accum)
    daddiu  i, i, -1
    
    daddiu  accum, accum, 8
    daddiu  addend, addend, 8

    sd	    t3, -16(accum)
    vmulu   t3, t1, t2

    bne	    i, zero, VADD$L1
    ld	    t1, 0(addend)


VADD$DONE:
    jr	    ra
    sd	    t3, -8(accum)

END(Vadd_vmul)



LEAF(Vsub_vmul)

# Since I don't support signed vmul's for subtract I will
# skip over all trailing 0's and then do an add of 1's complement

Vsub_vmul:
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
    xor	    t3, t3, t8
    daddiu  t3, t3, 1    

    ld	    t1, 0(addend)
    vmulu   t3, t3, t2
    beq     i, zero, VSUB$DONE
    nop


VSUB$L2: 
    ld	    t2, 0(accum)
    daddiu  i, i, -1
    
    daddiu  accum, accum, 8
    daddiu  addend, addend, 8

    xor	    t1, t1, t8

    sd	    t3, -16(accum)
    vmulu   t3, t1, t2

    bne	    i, zero, VSUB$L2
    ld	    t1, 0(addend)


VSUB$DONE:
    jr	    ra
    sd	    t3, -8(accum)

END(Vsub_vmul)

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

// len will be *64
LEAF(MontMul576_vmul)
MontMul576_vmul:
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
    ld	    t3, 8(mpcand)
    or	    t9, zero, zero

.align 3
MML512$L3:
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
    daddiu  mplier, mplier, 8
    vmulu   s6, t2, s6
    daddiu  len, len, -1
    vmulu   s7, t3, s7
    vmulu   t8, zero, t8
    
    mtm0    recip
    ld	    t2, 0(modulus)
    vmm0    t5, s0, zero
    ld	    t3, 8(modulus)

    ld	    t4, 16(modulus)
    vmulu   zero, t2, s0
    ld	    t2, 24(modulus)
    vmulu   s0, t3, s1
    ld	    t3, 32(modulus)
    vmulu   s1, t4, s2
    ld	    t4, 40(modulus)
    vmulu   s2, t2, s3
    ld	    t2, 48(modulus)
    vmulu   s3, t3, s4
    ld	    t3, 56(modulus)
    vmulu   s4, t4, s5
    vmulu   s5, t2, s6
    ld	    t5, 0(mplier)
    vmulu   s6, t3, s7
    ld	    t2, 0(mpcand)
    vmulu   s7, zero, t8
    ld	    t3, 8(mpcand)
    vmulu   t8, zero, zero
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
    j	    Vsub_vmul	
    daddiu  sp, sp, 64
    .set pop

END(MontMul576_vmul)
