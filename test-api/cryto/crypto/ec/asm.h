
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


