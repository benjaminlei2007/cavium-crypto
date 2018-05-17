/* 
 * 
 * OCTEON SDK
 * 
 * Copyright (c) 2007 Cavium Networks. All rights reserved.
 * 
 * This file, which is part of the OCTEON SDK which also includes the
 * OCTEON SDK Package from Cavium Networks, contains proprietary and
 * confidential information of Cavium Networks and in some cases its
 * suppliers. 
 * 
 * Any licensed reproduction, distribution, modification, or other use of
 * this file or the confidential information or patented inventions
 * embodied in this file is subject to your license agreement with Cavium
 * Networks. Unless you and Cavium Networks have agreed otherwise in
 * writing, the applicable license terms can be found at:
 * licenses/cavium-license-type2.txt
 * 
 * All other use and disclosure is prohibited.
 * 
 * Contact Cavium Networks at info@caviumnetworks.com for more information.
 * 
 */



#ifndef __COP2_H__
#define __COP2_H__ 

#ifdef __CNCRYPTO_INTERNAL_USE__



#include <cvmx.h>

/*
 * cpp neatly expands the macros for typical developer usage of MACRO(*data++)
 * Naming convention:
 *
 * CVMX_Move64ByteTo_COP2Unit
 * CVMX_Move64ByteZeroesTo_COP2Unit
 *
 * CVMX_Move128ByteTo_COP2Unit
 * CVMX_Move128ByteZeroesTo_COP2Unit
 * 
 */

#define UEND 0xFFFFFFFFFFFFFFFF

#define CVMX_M128BT_HSH_DATW_SHA512(expr) {\
  CVMX_MT_HSH_DATW(expr,0);\
  CVMX_MT_HSH_DATW(expr,1);\
  CVMX_MT_HSH_DATW(expr,2);\
  CVMX_MT_HSH_DATW(expr,3);\
  CVMX_MT_HSH_DATW(expr,4);\
  CVMX_MT_HSH_DATW(expr,5);\
  CVMX_MT_HSH_DATW(expr,6);\
  CVMX_MT_HSH_DATW(expr,7);\
  CVMX_MT_HSH_DATW(expr,8);\
  CVMX_MT_HSH_DATW(expr,9);\
  CVMX_MT_HSH_DATW(expr,10);\
  CVMX_MT_HSH_DATW(expr,11);\
  CVMX_MT_HSH_DATW(expr,12);\
  CVMX_MT_HSH_DATW(expr,13);\
  CVMX_MT_HSH_DATW(expr,14);\
  CVMX_MT_HSH_STARTSHA512(expr);\
}


#define CVMX_M128BZT_HSH_DATWZ(expr) {\
  CVMX_MT_HSH_DATWZ(0);\
  CVMX_MT_HSH_DATWZ(1);\
  CVMX_MT_HSH_DATWZ(2);\
  CVMX_MT_HSH_DATWZ(3);\
  CVMX_MT_HSH_DATWZ(4);\
  CVMX_MT_HSH_DATWZ(5);\
  CVMX_MT_HSH_DATWZ(6);\
  CVMX_MT_HSH_DATWZ(7);\
  CVMX_MT_HSH_DATWZ(8);\
  CVMX_MT_HSH_DATWZ(9);\
  CVMX_MT_HSH_DATWZ(10);\
  CVMX_MT_HSH_DATWZ(11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  CVMX_MT_HSH_DATWZ(14);\
  CVMX_MT_HSH_STARTSHA512(expr);\
}

//0x600 = (64+128)*8
#define CVMX_M128BT_HSH_DATW_SHA512_HMAC(a)\
{\
  CVMX_MT_HSH_DATW(a[0],0);\
  CVMX_MT_HSH_DATW(a[1],1);\
  CVMX_MT_HSH_DATW(a[2],2);\
  CVMX_MT_HSH_DATW(a[3],3);\
  CVMX_MT_HSH_DATW(a[4],4);\
  CVMX_MT_HSH_DATW(a[5],5);\
  CVMX_MT_HSH_DATW(a[6],6);\
  CVMX_MT_HSH_DATW(a[7],7);\
  CVMX_MT_HSH_DATW(0x8000000000000000ull,8);\
  CVMX_MT_HSH_DATWZ(9);\
  CVMX_MT_HSH_DATWZ(10);\
  CVMX_MT_HSH_DATWZ(11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  CVMX_MT_HSH_DATWZ(14);\
  CVMX_MT_HSH_STARTSHA512(0x600);\
}


//0x580 = (48+128)*8
#define CVMX_M128BT_HSH_DATW_SHA384_HMAC(a)\
{\
  CVMX_MT_HSH_DATW(a[0],0);\
  CVMX_MT_HSH_DATW(a[1],1);\
  CVMX_MT_HSH_DATW(a[2],2);\
  CVMX_MT_HSH_DATW(a[3],3);\
  CVMX_MT_HSH_DATW(a[4],4);\
  CVMX_MT_HSH_DATW(a[5],5);\
  CVMX_MT_HSH_DATW(0x8000000000000000ull,6);\
  CVMX_MT_HSH_DATWZ(7);\
  CVMX_MT_HSH_DATWZ(8);\
  CVMX_MT_HSH_DATWZ(9);\
  CVMX_MT_HSH_DATWZ(10);\
  CVMX_MT_HSH_DATWZ(11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  CVMX_MT_HSH_DATWZ(14);\
  CVMX_MT_HSH_STARTSHA512(0x580);\
}


#define CVMX_M64BF_HSH_IVW(a)\
{\
  CVMX_MF_HSH_IVW(a[0],0);\
  CVMX_MF_HSH_IVW(a[1],1);\
  CVMX_MF_HSH_IVW(a[2],2);\
  CVMX_MF_HSH_IVW(a[3],3);\
  CVMX_MF_HSH_IVW(a[4],4);\
  CVMX_MF_HSH_IVW(a[5],5);\
  CVMX_MF_HSH_IVW(a[6],6);\
  CVMX_MF_HSH_IVW(a[7],7);\
}

#define CVMX_M16BF_HSH_IVW(a)\
{\
  CVMX_MF_HSH_IVW(a[0],0);\
  CVMX_MF_HSH_IVW(a[1],1);\
}



#define CVMX_M64BT_HSH_IVW(a)\
{\
  CVMX_MT_HSH_IVW(a[0],0);\
  CVMX_MT_HSH_IVW(a[1],1);\
  CVMX_MT_HSH_IVW(a[2],2);\
  CVMX_MT_HSH_IVW(a[3],3);\
  CVMX_MT_HSH_IVW(a[4],4);\
  CVMX_MT_HSH_IVW(a[5],5);\
  CVMX_MT_HSH_IVW(a[6],6);\
  CVMX_MT_HSH_IVW(a[7],7);\
}

#define MEMSET128BTZ(ptr) \
{\
	uint64_t *d = (void*)ptr;\
	d[0] = 0;\
	d[1] = 0;\
	d[2] = 0;\
	d[3] = 0;\
	d[4] = 0;\
	d[5] = 0;\
	d[6] = 0;\
	d[7] = 0;\
	d[8] = 0;\
	d[9] = 0;\
	d[10] = 0;\
	d[11] = 0;\
	d[12] = 0;\
	d[13] = 0;\
	d[14] = 0;\
	d[15] = 0;\
}

#define MEMSET64BTZ(ptr) \
{\
	uint64_t *d = (void*)ptr;\
	d[0] = 0;\
	d[1] = 0;\
	d[2] = 0;\
	d[3] = 0;\
	d[4] = 0;\
	d[5] = 0;\
	d[6] = 0;\
	d[7] = 0;\
}



#define CVMX_M24BT_3DES_KEY(a)\
CVMX_MT_3DES_KEY(a[0],0);\
CVMX_MT_3DES_KEY(a[1],1);\
CVMX_MT_3DES_KEY(a[2],2);



#define MEMCPY64B(dst,src)\
{\
  uint64_t *d,*s;\
  d = (void*)dst;\
  s = (void*)src;\
  d[0] = s[0];\
  d[1] = s[1];\
  d[2] = s[2];\
  d[3] = s[3];\
  d[4] = s[4];\
  d[5] = s[5];\
  d[6] = s[6];\
  d[7] = s[7];\
}

#define MEMCPY128B(dst,src)\
{\
  uint64_t *d,*s;\
  d = (void*)dst;\
  s = (void*)src;\
  d[0] = s[0];\
  d[1] = s[1];\
  d[2] = s[2];\
  d[3] = s[3];\
  d[4] = s[4];\
  d[5] = s[5];\
  d[6] = s[6];\
  d[7] = s[7];\
  d[8] = s[8];\
  d[9] = s[9];\
  d[10] = s[10];\
  d[11] = s[11];\
  d[12] = s[12];\
  d[13] = s[13];\
  d[14] = s[14];\
  d[15] = s[15];\
}



#define COP2_PARALLEL_16B_3DES_ENC_SHA512_STEP(dptr,rptr,dlen, offset0, offset1)\
{\
      	in1=dptr[0];\
      	in2=dptr[1];\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DATW(out,offset0);\
	rptr[0]=out;\
	dlen -= 16;\
	rptr+=2;\
	dptr+=2;\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_HSH_DATW(out,offset1);\
      	rptr[-1]=out;\
}

#define COP2_PARALLEL_16B_3DES_ENC_SHA512_STEP_FINAL(dptr,rptr,dlen)\
{\
      	in1=dptr[0];\
      	in2=dptr[1];\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DATW(out,14);\
	rptr[0]=out;\
	dlen -= 16;\
	rptr+=2;\
	dptr+=2;\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_HSH_STARTSHA512(out);\
      	rptr[-1]=out;\
}


#define CVMX_MT_HSH_4DATWZS(a,b,c,d)\
CVMX_MT_HSH_DATWZ(a);\
CVMX_MT_HSH_DATWZ(b);\
CVMX_MT_HSH_DATWZ(c);\
CVMX_MT_HSH_DATWZ(d);

#define CVMX_MT_HSH_8DATWZS(a,b,c,d,e,f,g,h)\
CVMX_MT_HSH_4DATWZS(a,b,c,d)\
CVMX_MT_HSH_4DATWZS(e,f,g,h)


#define CVMX_MT_HSH_2DATWZS(a,b)\
CVMX_MT_HSH_DATWZ(a);\
CVMX_MT_HSH_DATWZ(b)

#define CVMX_MT_HSH_3DATWZS(a,b,c)\
CVMX_MT_HSH_DATWZ(a);\
CVMX_MT_HSH_DATWZ(b);\
CVMX_MT_HSH_DATWZ(c);




#define COP2_PARALLEL_3DES_ENC_SHA512(dptr, rptr, dlen )\
{\
uint64_t in1,in2;\
uint64_t out1,out2;\
uint64_t in,out=0;\
uint64_t bitshi,bitslo;\
uint64_t_mul(bitshi,bitslo,((uint64_t)(pktlen+16+128)),0x8ull);\
\
while( dlen >= (128) )\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_PREFETCH128(dptr);\
	CVMX_MF_3DES_RESULT(out1);\
\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DATW(out1,2);\
	rptr[0] = out1;\
	in1 = dptr[2];\
	in2 = dptr[3];\
	CVMX_MF_3DES_RESULT(out2);\
\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DATW(out2,3);\
	rptr[1] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DATW(out1,4);\
	rptr[2] = out1;\
	in1 = dptr[4];\
	in2 = dptr[5];\
	CVMX_MF_3DES_RESULT(out2);\
\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DATW(out2,5);\
	rptr[3] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DATW(out1,6);\
	rptr[4] = out1;\
	in1 = dptr[6];\
	in2 = dptr[7];\
	CVMX_MF_3DES_RESULT(out2);\
\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DATW(out2,7);\
	rptr[5] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DATW(out1,8);\
	rptr[6] = out1;\
	in1 = dptr[8];\
	in2 = dptr[9];\
	CVMX_MF_3DES_RESULT(out2);\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DATW(out2,9);\
	rptr[7] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DATW(out1,10);\
	rptr[8] = out1;\
	in1 = dptr[10];\
	in2 = dptr[11];\
	CVMX_MF_3DES_RESULT(out2);\
\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DATW(out2,11);\
	rptr[9] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DATW(out1,12);\
	rptr[10] = out1;\
	in1 = dptr[12];\
	in2 = dptr[13];\
	CVMX_MF_3DES_RESULT(out2);\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DATW(out2,13);\
	rptr[11] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DATW(out1,14);\
	rptr[12] = out1;\
	in1 = dptr[14];\
	in2 = dptr[15];\
	CVMX_MF_3DES_RESULT(out2);\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_STARTSHA512(out2);\
	rptr[13] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DATW(out1,0);\
	rptr[14] = out1;\
\
	dptr += 16;\
	rptr += 16;\
	dlen -= 128;\
\
	CVMX_MF_3DES_RESULT(out2);\
\
	rptr[-1] = out2;\
	CVMX_MT_HSH_DATW(out2,1);\
}\
\
\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA512_STEP(dptr,rptr,dlen,2,3);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA512_STEP(dptr,rptr,dlen,4,5);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA512_STEP(dptr,rptr,dlen,6,7);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA512_STEP(dptr,rptr,dlen,8,9);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA512_STEP(dptr,rptr,dlen,10,11);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA512_STEP(dptr,rptr,dlen,12,13);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA512_STEP_FINAL(dptr,rptr,dlen);\
\
\
\
\
\
if(dlen)\
{\
  in = *dptr++;\
  CVMX_MT_3DES_ENC_CBC(in);\
  CVMX_MF_3DES_RESULT(out);\
  *rptr++ = out;\
  dlen = 0;\
}\
\
switch( (pktlen + ESP_HEADER_LENGTH + DES_CBC_IV_LENGTH) % 128 )\
{\
  case 0:\
  {\
  CVMX_MT_HSH_DATW( 0x1ull<<63 , 0);\
  CVMX_MT_HSH_8DATWZS(1,2,3,4,5,6,7,8);\
  CVMX_MT_HSH_4DATWZS(9,10,11,12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
\
  case 8:\
  {\
  CVMX_MT_HSH_DATW(out,0);\
  CVMX_MT_HSH_DATW(0x1ull<<63 , 1);\
  CVMX_MT_HSH_8DATWZS(2,3,4,5,6,7,8,9);\
  CVMX_MT_HSH_4DATWZS(10,11,12,13);\
  break;\
  };\
  \
\
  case 16:\
  {\
  CVMX_MT_HSH_DATW(0x1ull<<63,2);\
  CVMX_MT_HSH_8DATWZS(3,4,5,6,7,8,9,10);\
  CVMX_MT_HSH_DATWZ(11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  };\
\
  case 24:\
  {\
  CVMX_MT_HSH_DATW(out,2);\
  CVMX_MT_HSH_DATW( 0x1ull<<63 , 3);\
  CVMX_MT_HSH_8DATWZS(4,5,6,7,8,9,10,11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  };\
\
\
  case 32:\
  {\
  CVMX_MT_HSH_DATW(0x1ull<<63,4);\
  CVMX_MT_HSH_8DATWZS(5,6,7,8,9,10,11,12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  };\
\
\
\
 case 40:\
  {\
  CVMX_MT_HSH_DATW(out,4);\
  CVMX_MT_HSH_DATW(0x1ull<<63, 5);\
  CVMX_MT_HSH_4DATWZS(6,7,8,9);\
  CVMX_MT_HSH_4DATWZS(10,11,12,13);\
  break;\
  }\
\
\
  case 48:\
  {\
  CVMX_MT_HSH_DATW(0x1ull<<63,6);\
  CVMX_MT_HSH_4DATWZS(7,8,9,10);\
  CVMX_MT_HSH_DATWZ(11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
\
  case 56:\
  {\
  CVMX_MT_HSH_DATW(out,6);\
  CVMX_MT_HSH_DATW(0x1ull<<63, 7);\
  CVMX_MT_HSH_4DATWZS(8,9,10,11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
\
\
  case 64:\
  {\
  CVMX_MT_HSH_DATW(0x1ull<<63,8);\
  CVMX_MT_HSH_4DATWZS(9,10,11,12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
\
\
  case 72:\
  {\
  CVMX_MT_HSH_DATW(out,8);\
  CVMX_MT_HSH_DATW(0x1ull<<63, 9);\
  CVMX_MT_HSH_4DATWZS(10,11,12,13);\
  break;\
  }\
\
  case 80:\
  {\
  CVMX_MT_HSH_DATW(0x1ull<<63,10);\
  CVMX_MT_HSH_DATWZ(11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
\
  \
  case 88:\
  {\
  CVMX_MT_HSH_DATW(out,10);\
  CVMX_MT_HSH_DATW(0x1ull<<63, 11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
\
\
  case 96:\
  {\
  CVMX_MT_HSH_DATW(0x1ull<<63,12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
\
\
  case 104:\
  {\
  CVMX_MT_HSH_DATW(out,12);\
  CVMX_MT_HSH_DATW(0x1ull<<63, 13);\
  break;\
  }\
\
\
  case 112:\
  {\
  CVMX_MT_HSH_DATW(0x1ull<<63,14);\
  CVMX_MT_HSH_STARTSHA512(0);\
  CVMX_MT_HSH_8DATWZS(0,1,2,3,4,5,6,7);\
  CVMX_MT_HSH_4DATWZS(8,9,10,11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
\
\
  case 120:\
  {\
  CVMX_MT_HSH_DATW(out,14);\
  CVMX_MT_HSH_STARTSHA512(0x1ull<<63);\
  CVMX_MT_HSH_8DATWZS(0,1,2,3,4,5,6,7);\
  CVMX_MT_HSH_4DATWZS(8,9,10,11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
  default:break;\
}\
\
CVMX_MT_HSH_DATW(bitshi,14);\
CVMX_MT_HSH_STARTSHA512(bitslo);\
dlen = 0;\
\
}


#define COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP(dptr,rptr,dlen, offset0, offset1)\
{\
      	in1=dptr[0];\
      	in2=dptr[1];\
	CVMX_MT_3DES_DEC_CBC(in1);\
	CVMX_MT_HSH_DATW(in1,offset0);\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_3DES_DEC_CBC(in2);\
	CVMX_MT_HSH_DATW(in2,offset1);\
	rptr[0]=out;\
	dlen -= 16;\
	rptr+=2;\
	dptr+=2;\
	CVMX_MF_3DES_RESULT(out);\
      	rptr[-1]=out;\
}

#define COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP_FINAL(dptr,rptr,dlen)\
{\
      	in1=dptr[0];\
      	in2=dptr[1];\
	CVMX_MT_3DES_DEC_CBC(in1);\
	CVMX_MT_HSH_DATW(in1,14);\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_3DES_DEC_CBC(in2);\
	CVMX_MT_HSH_STARTSHA512(in2);\
	rptr[0]=out;\
	dlen -= 16;\
	rptr+=2;\
	dptr+=2;\
	CVMX_MF_3DES_RESULT(out);\
      	rptr[-1]=out;\
}



#define COP2_PARALLEL_3DES_DEC_SHA512(dptr, rptr, dlen )\
{\
uint64_t in1,in2;\
uint64_t in,out=0;\
uint64_t bitshi,bitslo;\
uint64_t_mul(bitshi,bitslo,((uint64_t)(pktlen+128)),0x8ull);\
\
while( dlen >= (128) )\
{\
 CVMX_PREFETCH128(dptr+8);\
 COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP(dptr,rptr,dlen,2,3);\
 COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP(dptr,rptr,dlen,4,5);\
 COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP(dptr,rptr,dlen,6,7);\
 COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP(dptr,rptr,dlen,8,9);\
 COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP(dptr,rptr,dlen,10,11);\
 COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP(dptr,rptr,dlen,12,13);\
 COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP_FINAL(dptr,rptr,dlen);\
 COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP(dptr,rptr,dlen,0,1);\
}\
\
\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP(dptr,rptr,dlen,2,3);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP(dptr,rptr,dlen,4,5);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP(dptr,rptr,dlen,6,7);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP(dptr,rptr,dlen,8,9);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP(dptr,rptr,dlen,10,11);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP(dptr,rptr,dlen,12,13);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA512_STEP_FINAL(dptr,rptr,dlen);\
\
\
\
\
\
if(dlen)\
{\
  in = *dptr++;\
  CVMX_MT_3DES_DEC_CBC(in);\
  CVMX_MF_3DES_RESULT(out);\
  *rptr++ = out;\
  dlen = 0;\
  out = in;\
}\
\
switch( (pktlen) % 128 )\
{\
  case 0:\
  {\
  CVMX_MT_HSH_DATW( 0x1ull<<63 , 0);\
  CVMX_MT_HSH_8DATWZS(1,2,3,4,5,6,7,8);\
  CVMX_MT_HSH_4DATWZS(9,10,11,12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
\
  case 8:\
  {\
  CVMX_MT_HSH_DATW(out,0);\
  CVMX_MT_HSH_DATW(0x1ull<<63 , 1);\
  CVMX_MT_HSH_8DATWZS(2,3,4,5,6,7,8,9);\
  CVMX_MT_HSH_4DATWZS(10,11,12,13);\
  break;\
  };\
  \
\
  case 16:\
  {\
  CVMX_MT_HSH_DATW(0x1ull<<63,2);\
  CVMX_MT_HSH_8DATWZS(3,4,5,6,7,8,9,10);\
  CVMX_MT_HSH_DATWZ(11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  };\
\
  case 24:\
  {\
  CVMX_MT_HSH_DATW(out,2);\
  CVMX_MT_HSH_DATW( 0x1ull<<63 , 3);\
  CVMX_MT_HSH_8DATWZS(4,5,6,7,8,9,10,11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  };\
\
\
  case 32:\
  {\
  CVMX_MT_HSH_DATW(0x1ull<<63,4);\
  CVMX_MT_HSH_8DATWZS(5,6,7,8,9,10,11,12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  };\
\
\
\
 case 40:\
  {\
  CVMX_MT_HSH_DATW(out,4);\
  CVMX_MT_HSH_DATW(0x1ull<<63, 5);\
  CVMX_MT_HSH_4DATWZS(6,7,8,9);\
  CVMX_MT_HSH_4DATWZS(10,11,12,13);\
  break;\
  }\
\
\
  case 48:\
  {\
  CVMX_MT_HSH_DATW(0x1ull<<63,6);\
  CVMX_MT_HSH_4DATWZS(7,8,9,10);\
  CVMX_MT_HSH_DATWZ(11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
\
  case 56:\
  {\
  CVMX_MT_HSH_DATW(out,6);\
  CVMX_MT_HSH_DATW(0x1ull<<63, 7);\
  CVMX_MT_HSH_4DATWZS(8,9,10,11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
\
\
  case 64:\
  {\
  CVMX_MT_HSH_DATW(0x1ull<<63,8);\
  CVMX_MT_HSH_4DATWZS(9,10,11,12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
\
\
  case 72:\
  {\
  CVMX_MT_HSH_DATW(out,8);\
  CVMX_MT_HSH_DATW(0x1ull<<63, 9);\
  CVMX_MT_HSH_4DATWZS(10,11,12,13);\
  break;\
  }\
\
  case 80:\
  {\
  CVMX_MT_HSH_DATW(0x1ull<<63,10);\
  CVMX_MT_HSH_DATWZ(11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
\
  \
  case 88:\
  {\
  CVMX_MT_HSH_DATW(out,10);\
  CVMX_MT_HSH_DATW(0x1ull<<63, 11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
\
\
  case 96:\
  {\
  CVMX_MT_HSH_DATW(0x1ull<<63,12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
\
\
  case 104:\
  {\
  CVMX_MT_HSH_DATW(out,12);\
  CVMX_MT_HSH_DATW(0x1ull<<63, 13);\
  break;\
  }\
\
\
  case 112:\
  {\
  CVMX_MT_HSH_DATW(0x1ull<<63,14);\
  CVMX_MT_HSH_STARTSHA512(0);\
  CVMX_MT_HSH_8DATWZS(0,1,2,3,4,5,6,7);\
  CVMX_MT_HSH_4DATWZS(8,9,10,11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
\
\
  case 120:\
  {\
  CVMX_MT_HSH_DATW(out,14);\
  CVMX_MT_HSH_STARTSHA512(0x1ull<<63);\
  CVMX_MT_HSH_8DATWZS(0,1,2,3,4,5,6,7);\
  CVMX_MT_HSH_4DATWZS(8,9,10,11);\
  CVMX_MT_HSH_DATWZ(12);\
  CVMX_MT_HSH_DATWZ(13);\
  break;\
  }\
  default:break;\
}\
\
CVMX_MT_HSH_DATW(bitshi,14);\
CVMX_MT_HSH_STARTSHA512(bitslo);\
dlen = 0;\
\
}


#define COP2_PARALLEL_16B_AES_ENC_SHA512_STEP(dptr,rptr,dlen,offset0,offset1)\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
	rptr+=2;\
	dptr+=2;\
	CVMX_MT_HSH_DATW(out1,offset0);\
	CVMX_MT_HSH_DATW(out2,offset1);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
	dlen -= 16;\
}


#define COP2_PARALLEL_16B_AES_ENC_SHA512_STEP_FINAL(dptr,rptr,dlen)\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
	rptr+=2;\
	dptr+=2;\
	CVMX_MT_HSH_STARTSHA512(out1);\
	CVMX_MT_HSH_DATW(out2,0);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
	dlen -= 16;\
}


#define COP2_PARALLEL_AES_ENC_SHA512(dptr, rptr, dlen )\
{\
uint64_t in1,in2;\
uint64_t out1,out2;\
uint64_t bitshi,bitslo;\
uint64_t_mul(bitshi,bitslo,((uint64_t)(pktlen+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH+128)),0x8ull);\
\
while( dlen >= (128) )\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	CVMX_PREFETCH128(dptr);\
	in1 = dptr[2];\
	in2 = dptr[3];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[0] = out1;\
	rptr[1] = out2;\
	CVMX_MT_HSH_DATW(out1,3);\
	CVMX_MT_HSH_DATW(out2,4);\
	in1 = dptr[4];\
	in2 = dptr[5];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[2] = out1;\
	rptr[3] = out2;\
	CVMX_MT_HSH_DATW(out1,5);\
	CVMX_MT_HSH_DATW(out2,6);\
	in1 = dptr[6];\
	in2 = dptr[7];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[4] = out1;\
	rptr[5] = out2;\
	CVMX_MT_HSH_DATW(out1,7);\
	CVMX_MT_HSH_DATW(out2,8);\
	in1 = dptr[8];\
	in2 = dptr[9];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[6] = out1;\
	rptr[7] = out2;\
	CVMX_MT_HSH_DATW(out1,9);\
	CVMX_MT_HSH_DATW(out2,10);\
	in1 = dptr[10];\
	in2 = dptr[11];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[8] = out1;\
	rptr[9] = out2;\
	CVMX_MT_HSH_DATW(out1,11);\
	CVMX_MT_HSH_DATW(out2,12);\
	in1 = dptr[12];\
	in2 = dptr[13];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[10] = out1;\
	rptr[11] = out2;\
	CVMX_MT_HSH_DATW(out1,13);\
	CVMX_MT_HSH_DATW(out2,14);\
	in1 = dptr[14];\
	in2 = dptr[15];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[12] = out1;\
	rptr[13] = out2;\
	CVMX_MT_HSH_STARTSHA512(out1);\
	CVMX_MT_HSH_DATW(out2,0);\
	dlen -= 128;\
	dptr += 16;\
	rptr += 16;\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
	CVMX_MT_HSH_DATW(out1,1);\
	CVMX_MT_HSH_DATW(out2,2);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
}\
\
\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA512_STEP(dptr,rptr,dlen,3,4);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA512_STEP(dptr,rptr,dlen,5,6);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA512_STEP(dptr,rptr,dlen,7,8);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA512_STEP(dptr,rptr,dlen,9,10);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA512_STEP(dptr,rptr,dlen,11,12);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA512_STEP(dptr,rptr,dlen,13,14);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA512_STEP_FINAL(dptr,rptr,dlen);\
\
\
\
switch( (pktlen + ESP_HEADER_LENGTH + AES_CBC_IV_LENGTH) % 128 )\
{\
  case 8:\
  {\
    CVMX_MT_HSH_DATW(0x1ull<<63,1);\
    CVMX_MT_HSH_8DATWZS(2,3,4,5,6,7,8,9);\
    CVMX_MT_HSH_4DATWZS(10,11,12,13);\
    break;\
  }\
\
  case 24:\
  {\
    CVMX_MT_HSH_DATW(0x1ull<<63,3);\
    CVMX_MT_HSH_8DATWZS(4,5,6,7,8,9,10,11);\
    CVMX_MT_HSH_2DATWZS(12,13);\
    break;\
  }\
\
  case 40:\
  {\
    CVMX_MT_HSH_DATW(0x1ull<<63,5);\
    CVMX_MT_HSH_8DATWZS(6,7,8,9,10,11,12,13);\
    break;\
  }\
\
  case 56:\
  {\
    CVMX_MT_HSH_DATW(0x1ull<<63,7);\
    CVMX_MT_HSH_4DATWZS(8,9,10,11);\
    CVMX_MT_HSH_2DATWZS(12,13);\
    break;\
  }\
\
  case 72:\
  {\
    CVMX_MT_HSH_DATW(0x1ull<<63,9);\
    CVMX_MT_HSH_4DATWZS(10,11,12,13);\
    break;\
  }\
\
  case 88:\
  {\
    CVMX_MT_HSH_DATW(0x1ull<<63,11);\
    CVMX_MT_HSH_2DATWZS(12,13);\
    break;\
  }\
  case 104:\
  {\
    CVMX_MT_HSH_DATW(0x1ull<<63,13);\
    break;\
  }\
  case 120:\
  {\
    CVMX_MT_HSH_STARTSHA512(0x1ull<<63);\
    CVMX_MT_HSH_8DATWZS(0,1,2,3,4,5,6,7);\
    CVMX_MT_HSH_4DATWZS(8,9,10,11);\
    CVMX_MT_HSH_2DATWZS(12,13);\
    break;\
  }\
\
  default:break;\
}\
\
CVMX_MT_HSH_DATW(bitshi,14);\
CVMX_MT_HSH_STARTSHA512(bitslo);\
dlen = 0;\
\
}



#define COP2_PARALLEL_16B_AES_DEC_SHA512_STEP(dptr,rptr,dlen,offset0,offset1)\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_DEC_CBC0(in1);\
	CVMX_MT_AES_DEC_CBC1(in2);\
	CVMX_MT_HSH_DATW(in1,offset0);\
	CVMX_MT_HSH_DATW(in2,offset1);\
	rptr+=2;\
	dptr+=2;\
	dlen -= 16;\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
}


#define COP2_PARALLEL_16B_AES_DEC_SHA512_STEP_FINAL(dptr,rptr,dlen)\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_DEC_CBC0(in1);\
	CVMX_MT_AES_DEC_CBC1(in2);\
	rptr+=2;\
	dptr+=2;\
	dlen -= 16;\
	CVMX_MT_HSH_STARTSHA512(in1);\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
	CVMX_MT_HSH_DATW(in2,0);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
}







#define COP2_PARALLEL_AES_DEC_SHA512(dptr, rptr, dlen )\
{\
uint64_t in1,in2;\
uint64_t out1,out2;\
uint64_t bitshi,bitslo;\
uint64_t_mul(bitshi,bitslo,((uint64_t)(pktlen+128)),0x8ull);\
\
while( dlen >= (128) )\
{\
  COP2_PARALLEL_16B_AES_DEC_SHA512_STEP(dptr,rptr,dlen,3,4);\
  COP2_PARALLEL_16B_AES_DEC_SHA512_STEP(dptr,rptr,dlen,5,6);\
  COP2_PARALLEL_16B_AES_DEC_SHA512_STEP(dptr,rptr,dlen,7,8);\
  COP2_PARALLEL_16B_AES_DEC_SHA512_STEP(dptr,rptr,dlen,9,10);\
  COP2_PARALLEL_16B_AES_DEC_SHA512_STEP(dptr,rptr,dlen,11,12);\
  COP2_PARALLEL_16B_AES_DEC_SHA512_STEP(dptr,rptr,dlen,13,14);\
  COP2_PARALLEL_16B_AES_DEC_SHA512_STEP_FINAL(dptr,rptr,dlen);\
  COP2_PARALLEL_16B_AES_DEC_SHA512_STEP(dptr,rptr,dlen,1,2);\
}\
\
\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA512_STEP(dptr,rptr,dlen,3,4);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA512_STEP(dptr,rptr,dlen,5,6);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA512_STEP(dptr,rptr,dlen,7,8);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA512_STEP(dptr,rptr,dlen,9,10);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA512_STEP(dptr,rptr,dlen,11,12);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA512_STEP(dptr,rptr,dlen,13,14);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA512_STEP_FINAL(dptr,rptr,dlen);\
\
\
\
switch( pktlen  % 128 )\
{\
  case 8:\
  {\
    CVMX_MT_HSH_DATW(0x1ull<<63,1);\
    CVMX_MT_HSH_8DATWZS(2,3,4,5,6,7,8,9);\
    CVMX_MT_HSH_4DATWZS(10,11,12,13);\
    break;\
  }\
\
  case 24:\
  {\
    CVMX_MT_HSH_DATW(0x1ull<<63,3);\
    CVMX_MT_HSH_8DATWZS(4,5,6,7,8,9,10,11);\
    CVMX_MT_HSH_2DATWZS(12,13);\
    break;\
  }\
\
  case 40:\
  {\
    CVMX_MT_HSH_DATW(0x1ull<<63,5);\
    CVMX_MT_HSH_8DATWZS(6,7,8,9,10,11,12,13);\
    break;\
  }\
\
  case 56:\
  {\
    CVMX_MT_HSH_DATW(0x1ull<<63,7);\
    CVMX_MT_HSH_4DATWZS(8,9,10,11);\
    CVMX_MT_HSH_2DATWZS(12,13);\
    break;\
  }\
\
  case 72:\
  {\
    CVMX_MT_HSH_DATW(0x1ull<<63,9);\
    CVMX_MT_HSH_4DATWZS(10,11,12,13);\
    break;\
  }\
\
  case 88:\
  {\
    CVMX_MT_HSH_DATW(0x1ull<<63,11);\
    CVMX_MT_HSH_2DATWZS(12,13);\
    break;\
  }\
  case 104:\
  {\
    CVMX_MT_HSH_DATW(0x1ull<<63,13);\
    break;\
  }\
  case 120:\
  {\
    CVMX_MT_HSH_STARTSHA512(0x1ull<<63);\
    CVMX_MT_HSH_8DATWZS(0,1,2,3,4,5,6,7);\
    CVMX_MT_HSH_4DATWZS(8,9,10,11);\
    CVMX_MT_HSH_2DATWZS(12,13);\
    break;\
  }\
\
  default:break;\
}\
\
CVMX_MT_HSH_DATW(bitshi,14);\
CVMX_MT_HSH_STARTSHA512(bitslo);\
dlen = 0;\
\
}


#define CVMX_M64BT_HSH_DAT_SHA256(expr) {\
  CVMX_MT_HSH_DAT(expr,0);\
  CVMX_MT_HSH_DAT(expr,1);\
  CVMX_MT_HSH_DAT(expr,2);\
  CVMX_MT_HSH_DAT(expr,3);\
  CVMX_MT_HSH_DAT(expr,4);\
  CVMX_MT_HSH_DAT(expr,5);\
  CVMX_MT_HSH_DAT(expr,6);\
  CVMX_MT_HSH_STARTSHA256(expr);\
}

#define CVMX_M64BT_HSH_DAT_SHA1(expr) {\
  CVMX_MT_HSH_DAT(expr,0);\
  CVMX_MT_HSH_DAT(expr,1);\
  CVMX_MT_HSH_DAT(expr,2);\
  CVMX_MT_HSH_DAT(expr,3);\
  CVMX_MT_HSH_DAT(expr,4);\
  CVMX_MT_HSH_DAT(expr,5);\
  CVMX_MT_HSH_DAT(expr,6);\
  CVMX_MT_HSH_STARTSHA(expr);\
}

#define CVMX_M64BT_HSH_DAT_MD5(expr) {\
  CVMX_MT_HSH_DAT(expr,0);\
  CVMX_MT_HSH_DAT(expr,1);\
  CVMX_MT_HSH_DAT(expr,2);\
  CVMX_MT_HSH_DAT(expr,3);\
  CVMX_MT_HSH_DAT(expr,4);\
  CVMX_MT_HSH_DAT(expr,5);\
  CVMX_MT_HSH_DAT(expr,6);\
  CVMX_MT_HSH_STARTMD5(expr);\
}



#define CVMX_M64BT_HSH_DAT_SHA256_HMAC(expr) {\
  CVMX_MT_HSH_DAT(expr[0],0);\
  CVMX_MT_HSH_DAT(expr[1],1);\
  CVMX_MT_HSH_DAT(expr[2],2);\
  CVMX_MT_HSH_DAT(expr[3],3);\
  CVMX_MT_HSH_DAT(0x1ull<<63,4);\
  CVMX_MT_HSH_DATZ(5);\
  CVMX_MT_HSH_DATZ(6);\
  CVMX_MT_HSH_STARTSHA256(96ull*8ull);\
}

#define CVMX_M64BT_HSH_DAT_SHA224_HMAC(expr) {\
  CVMX_MT_HSH_DAT(expr[0],0);\
  CVMX_MT_HSH_DAT(expr[1],1);\
  CVMX_MT_HSH_DAT(expr[2],2);\
  ((uint8_t*)expr)[28] = 0x80;\
  ((uint8_t*)expr)[29] = 0x0;\
  ((uint8_t*)expr)[30] = 0x0;\
  ((uint8_t*)expr)[31] = 0x0;\
  CVMX_MT_HSH_DAT(expr[3],3);\
  CVMX_MT_HSH_DATZ(4);\
  CVMX_MT_HSH_DATZ(5);\
  CVMX_MT_HSH_DATZ(6);\
  CVMX_MT_HSH_STARTSHA256((64ull+28ull)*8ull);\
}


#define CVMX_M32BF_HSH_IV(expr) {\
  CVMX_MF_HSH_IV(expr[0],0);\
  CVMX_MF_HSH_IV(expr[1],1);\
  CVMX_MF_HSH_IV(expr[2],2);\
  CVMX_MF_HSH_IV(expr[3],3);\
}

#define CVMX_M16BF_HSH_IV(expr) {\
  CVMX_MF_HSH_IV(expr[0],0);\
  CVMX_MF_HSH_IV(expr[1],1);\
}


#define CVMX_M32BT_HSH_IV(expr) {\
  CVMX_MT_HSH_IV(expr[0],0);\
  CVMX_MT_HSH_IV(expr[1],1);\
  CVMX_MT_HSH_IV(expr[2],2);\
  CVMX_MT_HSH_IV(expr[3],3);\
}

#define CVMX_M16BT_HSH_DATZ(a,b) {\
  CVMX_MT_HSH_DATZ(a);\
  CVMX_MT_HSH_DATZ(b);\
}

#define CVMX_M24BT_HSH_DATZ(a,b,c) {\
  CVMX_M16BT_HSH_DATZ(a,b);\
  CVMX_MT_HSH_DATZ(c);\
}

#define CVMX_M32BT_HSH_DATZ(a,b,c,d) {\
  CVMX_M16BT_HSH_DATZ(a,b);\
  CVMX_M16BT_HSH_DATZ(c,d);\
}



#define COP2_PARALLEL_16B_3DES_ENC_SHA256_STEP(dptr,rptr,dlen, offset0, offset1)\
{\
      	in1=dptr[0];\
      	in2=dptr[1];\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out,offset0);\
	rptr[0]=out;\
	dlen -= 16;\
	rptr+=2;\
	dptr+=2;\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_HSH_DAT(out,offset1);\
      	rptr[-1]=out;\
}

#define COP2_PARALLEL_16B_3DES_ENC_SHA256_STEP_FINAL(dptr,rptr,dlen)\
{\
      	in1=dptr[0];\
      	in2=dptr[1];\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out,6);\
	rptr[0]=out;\
	dlen -= 16;\
	rptr+=2;\
	dptr+=2;\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_HSH_STARTSHA256(out);\
      	rptr[-1]=out;\
}





#define COP2_PARALLEL_3DES_ENC_SHA256(dptr,rptr,dlen)\
{\
uint64_t in1,in2;\
uint64_t out1,out2;\
uint64_t in,out=0;\
uint64_t bits = ((uint64_t)(pktlen+16+64))* 0x8ull;\
\
while( dlen >= (128) )\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out1);\
\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,2);\
	rptr[0] = out1;\
	in1 = dptr[2];\
	in2 = dptr[3];\
	CVMX_MF_3DES_RESULT(out2);\
\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DAT(out2,3);\
	rptr[1] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,4);\
	rptr[2] = out1;\
	in1 = dptr[4];\
	in2 = dptr[5];\
	CVMX_MF_3DES_RESULT(out2);\
\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DAT(out2,5);\
	rptr[3] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,6);\
	rptr[4] = out1;\
	in1 = dptr[6];\
	in2 = dptr[7];\
	CVMX_MF_3DES_RESULT(out2);\
\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_STARTSHA256(out2);\
	rptr[5] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,0);\
	rptr[6] = out1;\
	in1 = dptr[8];\
	in2 = dptr[9];\
	CVMX_MF_3DES_RESULT(out2);\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DAT(out2,1);\
	rptr[7] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,2);\
	rptr[8] = out1;\
	in1 = dptr[10];\
	in2 = dptr[11];\
	CVMX_MF_3DES_RESULT(out2);\
\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DAT(out2,3);\
	rptr[9] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,4);\
	rptr[10] = out1;\
	in1 = dptr[12];\
	in2 = dptr[13];\
	CVMX_MF_3DES_RESULT(out2);\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DAT(out2,5);\
	rptr[11] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,6);\
	rptr[12] = out1;\
	in1 = dptr[14];\
	in2 = dptr[15];\
	CVMX_MF_3DES_RESULT(out2);\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_STARTSHA256(out2);\
	rptr[13] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,0);\
	rptr[14] = out1;\
\
	dptr += 16;\
	rptr += 16;\
	dlen -= 128;\
\
	CVMX_MF_3DES_RESULT(out2);\
\
	rptr[-1] = out2;\
	CVMX_MT_HSH_DAT(out2,1);\
}\
\
\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA256_STEP(dptr,rptr,dlen,2,3);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA256_STEP(dptr,rptr,dlen,4,5);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA256_STEP_FINAL(dptr,rptr,dlen);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA256_STEP(dptr,rptr,dlen,0,1);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA256_STEP(dptr,rptr,dlen,2,3);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA256_STEP(dptr,rptr,dlen,4,5);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA256_STEP_FINAL(dptr,rptr,dlen);\
\
\
\
\
\
if(dlen)\
{\
  in = *dptr++;\
  CVMX_MT_3DES_ENC_CBC(in);\
  CVMX_MF_3DES_RESULT(out);\
  *rptr++ = out;\
  dlen = 0;\
}\
\
switch( (pktlen + ESP_HEADER_LENGTH + DES_CBC_IV_LENGTH) % 64 )\
{\
  case 0:\
  {\
  CVMX_MT_HSH_DAT( 0x1ull<<63 , 0);\
  CVMX_M32BT_HSH_DATZ(1,2,3,4);\
  CVMX_M16BT_HSH_DATZ(5,6);\
  break;\
  }\
\
  case 8:\
  {\
  CVMX_MT_HSH_DAT(out,0);\
  CVMX_MT_HSH_DAT(0x1ull<<63 , 1);\
  CVMX_M32BT_HSH_DATZ(2,3,4,5);\
  CVMX_MT_HSH_DATZ(6);\
  break;\
  };\
  \
\
  case 16:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,2);\
  CVMX_M32BT_HSH_DATZ(3,4,5,6);\
  break;\
  };\
\
  case 24:\
  {\
  CVMX_MT_HSH_DAT(out,2);\
  CVMX_MT_HSH_DAT( 0x1ull<<63 , 3);\
  CVMX_M24BT_HSH_DATZ(4,5,6);\
  break;\
  };\
\
\
  case 32:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,4);\
  CVMX_M16BT_HSH_DATZ(5,6);\
  break;\
  };\
\
\
\
 case 40:\
  {\
  CVMX_MT_HSH_DAT(out,4);\
  CVMX_MT_HSH_DAT(0x1ull<<63, 5);\
  CVMX_MT_HSH_DATZ(6);\
  break;\
  }\
\
\
  case 48:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,6);\
  break;\
  }\
\
  case 56:\
  {\
  CVMX_MT_HSH_DAT(out,6);\
  CVMX_MT_HSH_STARTSHA256(0x1ull<<63);\
  CVMX_M32BT_HSH_DATZ(0,1,2,3);\
  CVMX_M24BT_HSH_DATZ(4,5,6);\
  break;\
  }\
\
  default:break;\
}\
\
CVMX_MT_HSH_STARTSHA256(bits);\
dlen = 0;\
\
}


#define COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP(dptr,rptr,dlen, offset0, offset1)\
{\
      	in1=dptr[0];\
      	in2=dptr[1];\
	CVMX_MT_3DES_DEC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_3DES_DEC_CBC(in2);\
	CVMX_MT_HSH_DAT(in1,offset0);\
	rptr[0]=out;\
	dlen -= 16;\
	rptr+=2;\
	dptr+=2;\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_HSH_DAT(in2,offset1);\
      	rptr[-1]=out;\
}

#define COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP_FINAL(dptr,rptr,dlen)\
{\
      	in1=dptr[0];\
      	in2=dptr[1];\
	CVMX_MT_3DES_DEC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_3DES_DEC_CBC(in2);\
	CVMX_MT_HSH_DAT(in1,6);\
	rptr[0]=out;\
	dlen -= 16;\
	rptr+=2;\
	dptr+=2;\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_HSH_STARTSHA256(in2);\
      	rptr[-1]=out;\
}





#define COP2_PARALLEL_3DES_DEC_SHA256(dptr,rptr,dlen)\
{\
uint64_t in1,in2;\
uint64_t in,out=0;\
uint64_t bits = ((uint64_t)(pktlen+64))* 0x8ull;\
\
while( dlen >= (128) )\
{\
  COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP(dptr,rptr,dlen,2,3);\
  COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP(dptr,rptr,dlen,4,5);\
  COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP_FINAL(dptr,rptr,dlen);\
  COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP(dptr,rptr,dlen,0,1);\
  COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP(dptr,rptr,dlen,2,3);\
  COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP(dptr,rptr,dlen,4,5);\
  COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP_FINAL(dptr,rptr,dlen);\
  COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP(dptr,rptr,dlen,0,1);\
}\
\
\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP(dptr,rptr,dlen,2,3);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP(dptr,rptr,dlen,4,5);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP_FINAL(dptr,rptr,dlen);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP(dptr,rptr,dlen,0,1);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP(dptr,rptr,dlen,2,3);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP(dptr,rptr,dlen,4,5);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA256_STEP_FINAL(dptr,rptr,dlen);\
\
\
\
\
\
if(dlen)\
{\
  in = *dptr++;\
  CVMX_MT_3DES_DEC_CBC(in);\
  CVMX_MF_3DES_RESULT(out);\
  *rptr++ = out;\
  out = in;\
  dlen = 0;\
}\
\
switch( pktlen  % 64 )\
{\
  case 0:\
  {\
  CVMX_MT_HSH_DAT( 0x1ull<<63 , 0);\
  CVMX_M32BT_HSH_DATZ(1,2,3,4);\
  CVMX_M16BT_HSH_DATZ(5,6);\
  break;\
  }\
\
  case 8:\
  {\
  CVMX_MT_HSH_DAT(out,0);\
  CVMX_MT_HSH_DAT(0x1ull<<63 , 1);\
  CVMX_M32BT_HSH_DATZ(2,3,4,5);\
  CVMX_MT_HSH_DATZ(6);\
  break;\
  };\
  \
\
  case 16:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,2);\
  CVMX_M32BT_HSH_DATZ(3,4,5,6);\
  break;\
  };\
\
  case 24:\
  {\
  CVMX_MT_HSH_DAT(out,2);\
  CVMX_MT_HSH_DAT( 0x1ull<<63 , 3);\
  CVMX_M24BT_HSH_DATZ(4,5,6);\
  break;\
  };\
\
\
  case 32:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,4);\
  CVMX_M16BT_HSH_DATZ(5,6);\
  break;\
  };\
\
\
\
 case 40:\
  {\
  CVMX_MT_HSH_DAT(out,4);\
  CVMX_MT_HSH_DAT(0x1ull<<63, 5);\
  CVMX_MT_HSH_DATZ(6);\
  break;\
  }\
\
\
  case 48:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,6);\
  break;\
  }\
\
  case 56:\
  {\
  CVMX_MT_HSH_DAT(out,6);\
  CVMX_MT_HSH_STARTSHA256(0x1ull<<63);\
  CVMX_M32BT_HSH_DATZ(0,1,2,3);\
  CVMX_M24BT_HSH_DATZ(4,5,6);\
  break;\
  }\
\
  default:break;\
}\
\
CVMX_MT_HSH_STARTSHA256(bits);\
dlen = 0;\
\
}


#define COP2_PARALLEL_16B_AES_ENC_SHA256_STEP(dptr,rptr,dlen,offset0,offset1)\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
	rptr+=2;\
	dptr+=2;\
	CVMX_MT_HSH_DAT(out1,offset0);\
	CVMX_MT_HSH_DAT(out2,offset1);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
	dlen -= 16;\
}


#define COP2_PARALLEL_16B_AES_ENC_SHA256_STEP_FINAL(dptr,rptr,dlen)\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
	rptr+=2;\
	dptr+=2;\
	CVMX_MT_HSH_STARTSHA256(out1);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
	dlen -= 16;\
	CVMX_MT_HSH_DAT(out2,0);\
}


#define COP2_PARALLEL_AES_ENC_SHA256(dptr, rptr, dlen )\
{\
uint64_t in1,in2;\
uint64_t out1,out2;\
uint64_t bits = ((uint64_t)(pktlen+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH+64))*0x8ull;\
\
while( dlen >= (128) )\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	CVMX_PREFETCH128(dptr);\
	in1 = dptr[2];\
	in2 = dptr[3];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[0] = out1;\
	rptr[1] = out2;\
	CVMX_MT_HSH_DAT(out1,3);\
	CVMX_MT_HSH_DAT(out2,4);\
	in1 = dptr[4];\
	in2 = dptr[5];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[2] = out1;\
	rptr[3] = out2;\
	CVMX_MT_HSH_DAT(out1,5);\
	CVMX_MT_HSH_DAT(out2,6);\
	in1 = dptr[6];\
	in2 = dptr[7];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[4] = out1;\
	rptr[5] = out2;\
	CVMX_MT_HSH_STARTSHA256(out1);\
	in1 = dptr[8];\
	in2 = dptr[9];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MT_HSH_DAT(out2,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[6] = out1;\
	rptr[7] = out2;\
	CVMX_MT_HSH_DAT(out1,1);\
	CVMX_MT_HSH_DAT(out2,2);\
	in1 = dptr[10];\
	in2 = dptr[11];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[8] = out1;\
	rptr[9] = out2;\
	CVMX_MT_HSH_DAT(out1,3);\
	CVMX_MT_HSH_DAT(out2,4);\
	in1 = dptr[12];\
	in2 = dptr[13];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[10] = out1;\
	rptr[11] = out2;\
	CVMX_MT_HSH_DAT(out1,5);\
	CVMX_MT_HSH_DAT(out2,6);\
	in1 = dptr[14];\
	in2 = dptr[15];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[12] = out1;\
	rptr[13] = out2;\
	CVMX_MT_HSH_STARTSHA256(out1);\
	dlen -= 128;\
	dptr += 16;\
	rptr += 16;\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MT_HSH_DAT(out2,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
	CVMX_MT_HSH_DAT(out1,1);\
	CVMX_MT_HSH_DAT(out2,2);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
}\
\
\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA256_STEP(dptr,rptr,dlen,3,4);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA256_STEP(dptr,rptr,dlen,5,6);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA256_STEP_FINAL(dptr,rptr,dlen);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA256_STEP(dptr,rptr,dlen,1,2);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA256_STEP(dptr,rptr,dlen,3,4);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA256_STEP(dptr,rptr,dlen,5,6);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA256_STEP_FINAL(dptr,rptr,dlen);\
\
\
\
switch( (pktlen + ESP_HEADER_LENGTH + AES_CBC_IV_LENGTH) % 64 )\
{\
  case 8:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,1);\
    CVMX_M32BT_HSH_DATZ(2,3,4,5);\
    CVMX_MT_HSH_DATZ(6);\
    break;\
  }\
\
  case 24:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,3);\
    CVMX_M24BT_HSH_DATZ(4,5,6);\
    break;\
  }\
\
  case 40:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,5);\
    CVMX_MT_HSH_DATZ(6);\
    break;\
  }\
\
  case 56:\
  {\
    CVMX_MT_HSH_STARTSHA256(0x1ull<<63);\
    CVMX_M32BT_HSH_DATZ(0,1,2,3);\
    CVMX_M24BT_HSH_DATZ(4,5,6);\
    break;\
  }\
  default:break;\
}\
\
CVMX_MT_HSH_STARTSHA256(bits);\
dlen = 0;\
\
}


#define COP2_PARALLEL_16B_AES_DEC_SHA256_STEP(dptr,rptr,dlen,offset0,offset1)\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_DEC_CBC0(in1);\
	CVMX_MT_AES_DEC_CBC1(in2);\
	CVMX_MT_HSH_DAT(in1,offset0);\
	CVMX_MT_HSH_DAT(in2,offset1);\
	rptr+=2;\
	dptr+=2;\
	dlen -= 16;\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
}


#define COP2_PARALLEL_16B_AES_DEC_SHA256_STEP_FINAL(dptr,rptr,dlen)\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_DEC_CBC0(in1);\
	CVMX_MT_AES_DEC_CBC1(in2);\
	CVMX_MT_HSH_STARTSHA256(in1);\
	rptr+=2;\
	dptr+=2;\
	dlen -= 16;\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
	CVMX_MT_HSH_DAT(in2,0);\
}


#define COP2_PARALLEL_AES_DEC_SHA256(dptr, rptr, dlen )\
{\
uint64_t in1,in2;\
uint64_t out1,out2;\
uint64_t bits = ((uint64_t)(pktlen+64))*0x8ull;\
\
while( dlen >= (128) )\
{\
  COP2_PARALLEL_16B_AES_DEC_SHA256_STEP(dptr,rptr,dlen,3,4);\
  COP2_PARALLEL_16B_AES_DEC_SHA256_STEP(dptr,rptr,dlen,5,6);\
  COP2_PARALLEL_16B_AES_DEC_SHA256_STEP_FINAL(dptr,rptr,dlen);\
  COP2_PARALLEL_16B_AES_DEC_SHA256_STEP(dptr,rptr,dlen,1,2);\
  COP2_PARALLEL_16B_AES_DEC_SHA256_STEP(dptr,rptr,dlen,3,4);\
  COP2_PARALLEL_16B_AES_DEC_SHA256_STEP(dptr,rptr,dlen,5,6);\
  COP2_PARALLEL_16B_AES_DEC_SHA256_STEP_FINAL(dptr,rptr,dlen);\
  COP2_PARALLEL_16B_AES_DEC_SHA256_STEP(dptr,rptr,dlen,1,2);\
}\
\
\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA256_STEP(dptr,rptr,dlen,3,4);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA256_STEP(dptr,rptr,dlen,5,6);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA256_STEP_FINAL(dptr,rptr,dlen);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA256_STEP(dptr,rptr,dlen,1,2);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA256_STEP(dptr,rptr,dlen,3,4);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA256_STEP(dptr,rptr,dlen,5,6);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA256_STEP_FINAL(dptr,rptr,dlen);\
\
\
\
switch( (pktlen ) % 64 )\
{\
  case 8:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,1);\
    CVMX_M32BT_HSH_DATZ(2,3,4,5);\
    CVMX_MT_HSH_DATZ(6);\
    break;\
  }\
\
  case 24:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,3);\
    CVMX_M24BT_HSH_DATZ(4,5,6);\
    break;\
  }\
\
  case 40:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,5);\
    CVMX_MT_HSH_DATZ(6);\
    break;\
  }\
\
  case 56:\
  {\
    CVMX_MT_HSH_STARTSHA256(0x1ull<<63);\
    CVMX_M32BT_HSH_DATZ(0,1,2,3);\
    CVMX_M24BT_HSH_DATZ(4,5,6);\
    break;\
  }\
  default:break;\
}\
\
CVMX_MT_HSH_STARTSHA256(bits);\
dlen = 0;\
\
}



#define COP2_PARALLEL_16B_AES_ENC_SHA1_STEP(dptr,rptr,dlen,offset0,offset1)\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
	rptr+=2;\
	dptr+=2;\
	CVMX_MT_HSH_DAT(out1,offset0);\
	CVMX_MT_HSH_DAT(out2,offset1);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
	dlen -= 16;\
}


#define COP2_PARALLEL_16B_AES_ENC_SHA1_STEP_FINAL(dptr,rptr,dlen)\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
	rptr+=2;\
	dptr+=2;\
	CVMX_MT_HSH_STARTSHA(out1);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
	dlen -= 16;\
	CVMX_MT_HSH_DAT(out2,0);\
}


#define COP2_PARALLEL_AES_ENC_SHA1(dptr, rptr, dlen )\
{\
uint64_t in1,in2;\
uint64_t out1,out2;\
uint64_t bits = ((uint64_t)(pktlen+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH+64))*0x8ull;\
\
while( dlen >= (128) )\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	CVMX_PREFETCH128(dptr);\
	in1 = dptr[2];\
	in2 = dptr[3];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[0] = out1;\
	rptr[1] = out2;\
	CVMX_MT_HSH_DAT(out1,3);\
	CVMX_MT_HSH_DAT(out2,4);\
	in1 = dptr[4];\
	in2 = dptr[5];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[2] = out1;\
	rptr[3] = out2;\
	CVMX_MT_HSH_DAT(out1,5);\
	CVMX_MT_HSH_DAT(out2,6);\
	in1 = dptr[6];\
	in2 = dptr[7];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[4] = out1;\
	rptr[5] = out2;\
	CVMX_MT_HSH_STARTSHA(out1);\
	in1 = dptr[8];\
	in2 = dptr[9];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MT_HSH_DAT(out2,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[6] = out1;\
	rptr[7] = out2;\
	CVMX_MT_HSH_DAT(out1,1);\
	CVMX_MT_HSH_DAT(out2,2);\
	in1 = dptr[10];\
	in2 = dptr[11];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[8] = out1;\
	rptr[9] = out2;\
	CVMX_MT_HSH_DAT(out1,3);\
	CVMX_MT_HSH_DAT(out2,4);\
	in1 = dptr[12];\
	in2 = dptr[13];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[10] = out1;\
	rptr[11] = out2;\
	CVMX_MT_HSH_DAT(out1,5);\
	CVMX_MT_HSH_DAT(out2,6);\
	in1 = dptr[14];\
	in2 = dptr[15];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[12] = out1;\
	rptr[13] = out2;\
	CVMX_MT_HSH_STARTSHA(out1);\
	dlen -= 128;\
	dptr += 16;\
	rptr += 16;\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MT_HSH_DAT(out2,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
	CVMX_MT_HSH_DAT(out1,1);\
	CVMX_MT_HSH_DAT(out2,2);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
}\
\
\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA1_STEP(dptr,rptr,dlen,3,4);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA1_STEP(dptr,rptr,dlen,5,6);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA1_STEP_FINAL(dptr,rptr,dlen);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA1_STEP(dptr,rptr,dlen,1,2);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA1_STEP(dptr,rptr,dlen,3,4);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA1_STEP(dptr,rptr,dlen,5,6);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_SHA1_STEP_FINAL(dptr,rptr,dlen);\
\
\
\
switch( (pktlen + ESP_HEADER_LENGTH + AES_CBC_IV_LENGTH) % 64 )\
{\
  case 8:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,1);\
    CVMX_M32BT_HSH_DATZ(2,3,4,5);\
    CVMX_MT_HSH_DATZ(6);\
    break;\
  }\
\
  case 24:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,3);\
    CVMX_M24BT_HSH_DATZ(4,5,6);\
    break;\
  }\
\
  case 40:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,5);\
    CVMX_MT_HSH_DATZ(6);\
    break;\
  }\
\
  case 56:\
  {\
    CVMX_MT_HSH_STARTSHA(0x1ull<<63);\
    CVMX_M32BT_HSH_DATZ(0,1,2,3);\
    CVMX_M24BT_HSH_DATZ(4,5,6);\
    break;\
  }\
  default:break;\
}\
\
CVMX_MT_HSH_STARTSHA(bits);\
dlen = 0;\
\
}


#define COP2_PARALLEL_16B_AES_DEC_SHA1_STEP(dptr,rptr,dlen,offset0,offset1)\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_DEC_CBC0(in1);\
	CVMX_MT_AES_DEC_CBC1(in2);\
	CVMX_MT_HSH_DAT(in1,offset0);\
	CVMX_MT_HSH_DAT(in2,offset1);\
	rptr+=2;\
	dptr+=2;\
	dlen -= 16;\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
}


#define COP2_PARALLEL_16B_AES_DEC_SHA1_STEP_FINAL(dptr,rptr,dlen)\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_DEC_CBC0(in1);\
	CVMX_MT_AES_DEC_CBC1(in2);\
	CVMX_MT_HSH_STARTSHA(in1);\
	rptr+=2;\
	dptr+=2;\
	dlen -= 16;\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
	CVMX_MT_HSH_DAT(in2,0);\
}


#define COP2_PARALLEL_AES_DEC_SHA1(dptr, rptr, dlen )\
{\
uint64_t in1,in2;\
uint64_t out1,out2;\
uint64_t bits = ((uint64_t)(pktlen+64))*0x8ull;\
\
while( dlen >= (128) )\
{\
  COP2_PARALLEL_16B_AES_DEC_SHA1_STEP(dptr,rptr,dlen,3,4);\
  COP2_PARALLEL_16B_AES_DEC_SHA1_STEP(dptr,rptr,dlen,5,6);\
  COP2_PARALLEL_16B_AES_DEC_SHA1_STEP_FINAL(dptr,rptr,dlen);\
  COP2_PARALLEL_16B_AES_DEC_SHA1_STEP(dptr,rptr,dlen,1,2);\
  COP2_PARALLEL_16B_AES_DEC_SHA1_STEP(dptr,rptr,dlen,3,4);\
  COP2_PARALLEL_16B_AES_DEC_SHA1_STEP(dptr,rptr,dlen,5,6);\
  COP2_PARALLEL_16B_AES_DEC_SHA1_STEP_FINAL(dptr,rptr,dlen);\
  COP2_PARALLEL_16B_AES_DEC_SHA1_STEP(dptr,rptr,dlen,1,2);\
}\
\
\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA1_STEP(dptr,rptr,dlen,3,4);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA1_STEP(dptr,rptr,dlen,5,6);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA1_STEP_FINAL(dptr,rptr,dlen);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA1_STEP(dptr,rptr,dlen,1,2);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA1_STEP(dptr,rptr,dlen,3,4);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA1_STEP(dptr,rptr,dlen,5,6);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_SHA1_STEP_FINAL(dptr,rptr,dlen);\
\
\
\
switch( (pktlen ) % 64 )\
{\
  case 8:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,1);\
    CVMX_M32BT_HSH_DATZ(2,3,4,5);\
    CVMX_MT_HSH_DATZ(6);\
    break;\
  }\
\
  case 24:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,3);\
    CVMX_M24BT_HSH_DATZ(4,5,6);\
    break;\
  }\
\
  case 40:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,5);\
    CVMX_MT_HSH_DATZ(6);\
    break;\
  }\
\
  case 56:\
  {\
    CVMX_MT_HSH_STARTSHA(0x1ull<<63);\
    CVMX_M32BT_HSH_DATZ(0,1,2,3);\
    CVMX_M24BT_HSH_DATZ(4,5,6);\
    break;\
  }\
  default:break;\
}\
\
CVMX_MT_HSH_STARTSHA(bits);\
dlen = 0;\
\
}




#define COP2_PARALLEL_16B_AES_ENC_MD5_STEP(dptr,rptr,dlen,offset0,offset1)\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
	rptr+=2;\
	dptr+=2;\
	CVMX_MT_HSH_DAT(out1,offset0);\
	CVMX_MT_HSH_DAT(out2,offset1);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
	dlen -= 16;\
}


#define COP2_PARALLEL_16B_AES_ENC_MD5_STEP_FINAL(dptr,rptr,dlen)\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
	rptr+=2;\
	dptr+=2;\
	CVMX_MT_HSH_STARTMD5(out1);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
	dlen -= 16;\
	CVMX_MT_HSH_DAT(out2,0);\
}


#define COP2_PARALLEL_AES_ENC_MD5(dptr, rptr, dlen )\
{\
uint64_t in1,in2;\
uint64_t out1,out2;\
uint64_t bits = ((uint64_t)(pktlen+ESP_HEADER_LENGTH+AES_CBC_IV_LENGTH+64))*0x8ull;\
\
while( dlen >= (128) )\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	CVMX_PREFETCH128(dptr);\
	in1 = dptr[2];\
	in2 = dptr[3];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[0] = out1;\
	rptr[1] = out2;\
	CVMX_MT_HSH_DAT(out1,3);\
	CVMX_MT_HSH_DAT(out2,4);\
	in1 = dptr[4];\
	in2 = dptr[5];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[2] = out1;\
	rptr[3] = out2;\
	CVMX_MT_HSH_DAT(out1,5);\
	CVMX_MT_HSH_DAT(out2,6);\
	in1 = dptr[6];\
	in2 = dptr[7];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[4] = out1;\
	rptr[5] = out2;\
	CVMX_MT_HSH_STARTMD5(out1);\
	in1 = dptr[8];\
	in2 = dptr[9];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MT_HSH_DAT(out2,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[6] = out1;\
	rptr[7] = out2;\
	CVMX_MT_HSH_DAT(out1,1);\
	CVMX_MT_HSH_DAT(out2,2);\
	in1 = dptr[10];\
	in2 = dptr[11];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[8] = out1;\
	rptr[9] = out2;\
	CVMX_MT_HSH_DAT(out1,3);\
	CVMX_MT_HSH_DAT(out2,4);\
	in1 = dptr[12];\
	in2 = dptr[13];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[10] = out1;\
	rptr[11] = out2;\
	CVMX_MT_HSH_DAT(out1,5);\
	CVMX_MT_HSH_DAT(out2,6);\
	in1 = dptr[14];\
	in2 = dptr[15];\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
\
	CVMX_MT_AES_ENC_CBC0(in1);\
	CVMX_MT_AES_ENC_CBC1(in2);\
	rptr[12] = out1;\
	rptr[13] = out2;\
	CVMX_MT_HSH_STARTMD5(out1);\
	dlen -= 128;\
	dptr += 16;\
	rptr += 16;\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MT_HSH_DAT(out2,0);\
	CVMX_MF_AES_RESULT(out2,1);\
\
\
	CVMX_MT_HSH_DAT(out1,1);\
	CVMX_MT_HSH_DAT(out2,2);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
}\
\
\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_MD5_STEP(dptr,rptr,dlen,3,4);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_MD5_STEP(dptr,rptr,dlen,5,6);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_MD5_STEP_FINAL(dptr,rptr,dlen);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_MD5_STEP(dptr,rptr,dlen,1,2);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_MD5_STEP(dptr,rptr,dlen,3,4);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_MD5_STEP(dptr,rptr,dlen,5,6);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_ENC_MD5_STEP_FINAL(dptr,rptr,dlen);\
\
\
\
switch( (pktlen + ESP_HEADER_LENGTH + AES_CBC_IV_LENGTH) % 64 )\
{\
  case 8:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,1);\
    CVMX_M32BT_HSH_DATZ(2,3,4,5);\
    CVMX_MT_HSH_DATZ(6);\
    break;\
  }\
\
  case 24:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,3);\
    CVMX_M24BT_HSH_DATZ(4,5,6);\
    break;\
  }\
\
  case 40:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,5);\
    CVMX_MT_HSH_DATZ(6);\
    break;\
  }\
\
  case 56:\
  {\
    CVMX_MT_HSH_STARTMD5(0x1ull<<63);\
    CVMX_M32BT_HSH_DATZ(0,1,2,3);\
    CVMX_M24BT_HSH_DATZ(4,5,6);\
    break;\
  }\
  default:break;\
}\
\
CVMX_ES64(bits,bits);\
CVMX_MT_HSH_STARTMD5(bits);\
dlen = 0;\
\
}


#define COP2_PARALLEL_16B_AES_DEC_MD5_STEP(dptr,rptr,dlen,offset0,offset1)\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_DEC_CBC0(in1);\
	CVMX_MT_AES_DEC_CBC1(in2);\
	CVMX_MT_HSH_DAT(in1,offset0);\
	CVMX_MT_HSH_DAT(in2,offset1);\
	rptr+=2;\
	dptr+=2;\
	dlen -= 16;\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
}


#define COP2_PARALLEL_16B_AES_DEC_MD5_STEP_FINAL(dptr,rptr,dlen)\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_AES_DEC_CBC0(in1);\
	CVMX_MT_AES_DEC_CBC1(in2);\
	CVMX_MT_HSH_STARTMD5(in1);\
	rptr+=2;\
	dptr+=2;\
	dlen -= 16;\
	CVMX_MF_AES_RESULT(out1,0);\
	CVMX_MF_AES_RESULT(out2,1);\
	rptr[-2] = out1;\
	rptr[-1] = out2;\
	CVMX_MT_HSH_DAT(in2,0);\
}


#define COP2_PARALLEL_AES_DEC_MD5(dptr, rptr, dlen )\
{\
uint64_t in1,in2;\
uint64_t out1,out2;\
uint64_t bits = ((uint64_t)(pktlen+64))*0x8ull;\
\
while( dlen >= (128) )\
{\
  COP2_PARALLEL_16B_AES_DEC_MD5_STEP(dptr,rptr,dlen,3,4);\
  COP2_PARALLEL_16B_AES_DEC_MD5_STEP(dptr,rptr,dlen,5,6);\
  COP2_PARALLEL_16B_AES_DEC_MD5_STEP_FINAL(dptr,rptr,dlen);\
  COP2_PARALLEL_16B_AES_DEC_MD5_STEP(dptr,rptr,dlen,1,2);\
  COP2_PARALLEL_16B_AES_DEC_MD5_STEP(dptr,rptr,dlen,3,4);\
  COP2_PARALLEL_16B_AES_DEC_MD5_STEP(dptr,rptr,dlen,5,6);\
  COP2_PARALLEL_16B_AES_DEC_MD5_STEP_FINAL(dptr,rptr,dlen);\
  COP2_PARALLEL_16B_AES_DEC_MD5_STEP(dptr,rptr,dlen,1,2);\
}\
\
\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_MD5_STEP(dptr,rptr,dlen,3,4);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_MD5_STEP(dptr,rptr,dlen,5,6);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_MD5_STEP_FINAL(dptr,rptr,dlen);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_MD5_STEP(dptr,rptr,dlen,1,2);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_MD5_STEP(dptr,rptr,dlen,3,4);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_MD5_STEP(dptr,rptr,dlen,5,6);\
if(dlen >= 16) COP2_PARALLEL_16B_AES_DEC_MD5_STEP_FINAL(dptr,rptr,dlen);\
\
\
\
switch( (pktlen ) % 64 )\
{\
  case 8:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,1);\
    CVMX_M32BT_HSH_DATZ(2,3,4,5);\
    CVMX_MT_HSH_DATZ(6);\
    break;\
  }\
\
  case 24:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,3);\
    CVMX_M24BT_HSH_DATZ(4,5,6);\
    break;\
  }\
\
  case 40:\
  {\
    CVMX_MT_HSH_DAT(0x1ull<<63,5);\
    CVMX_MT_HSH_DATZ(6);\
    break;\
  }\
\
  case 56:\
  {\
    CVMX_MT_HSH_STARTMD5(0x1ull<<63);\
    CVMX_M32BT_HSH_DATZ(0,1,2,3);\
    CVMX_M24BT_HSH_DATZ(4,5,6);\
    break;\
  }\
  default:break;\
}\
\
CVMX_ES64(bits,bits);\
CVMX_MT_HSH_STARTMD5(bits);\
dlen = 0;\
\
}




#define COP2_PARALLEL_16B_3DES_ENC_SHA1_STEP(dptr,rptr,dlen, offset0, offset1)\
{\
      	in1=dptr[0];\
      	in2=dptr[1];\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out,offset0);\
	rptr[0]=out;\
	dlen -= 16;\
	rptr+=2;\
	dptr+=2;\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_HSH_DAT(out,offset1);\
      	rptr[-1]=out;\
}

#define COP2_PARALLEL_16B_3DES_ENC_SHA1_STEP_FINAL(dptr,rptr,dlen)\
{\
      	in1=dptr[0];\
      	in2=dptr[1];\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out,6);\
	rptr[0]=out;\
	dlen -= 16;\
	rptr+=2;\
	dptr+=2;\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_HSH_STARTSHA(out);\
      	rptr[-1]=out;\
}





#define COP2_PARALLEL_3DES_ENC_SHA1(dptr,rptr,dlen)\
{\
uint64_t in1,in2;\
uint64_t out1,out2;\
uint64_t in,out=0;\
uint64_t bits = ((uint64_t)(pktlen+16+64))* 0x8ull;\
\
while( dlen >= (128) )\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out1);\
\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,2);\
	rptr[0] = out1;\
	in1 = dptr[2];\
	in2 = dptr[3];\
	CVMX_MF_3DES_RESULT(out2);\
\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DAT(out2,3);\
	rptr[1] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,4);\
	rptr[2] = out1;\
	in1 = dptr[4];\
	in2 = dptr[5];\
	CVMX_MF_3DES_RESULT(out2);\
\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DAT(out2,5);\
	rptr[3] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,6);\
	rptr[4] = out1;\
	in1 = dptr[6];\
	in2 = dptr[7];\
	CVMX_MF_3DES_RESULT(out2);\
\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_STARTSHA(out2);\
	rptr[5] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,0);\
	rptr[6] = out1;\
	in1 = dptr[8];\
	in2 = dptr[9];\
	CVMX_MF_3DES_RESULT(out2);\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DAT(out2,1);\
	rptr[7] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,2);\
	rptr[8] = out1;\
	in1 = dptr[10];\
	in2 = dptr[11];\
	CVMX_MF_3DES_RESULT(out2);\
\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DAT(out2,3);\
	rptr[9] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,4);\
	rptr[10] = out1;\
	in1 = dptr[12];\
	in2 = dptr[13];\
	CVMX_MF_3DES_RESULT(out2);\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DAT(out2,5);\
	rptr[11] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,6);\
	rptr[12] = out1;\
	in1 = dptr[14];\
	in2 = dptr[15];\
	CVMX_MF_3DES_RESULT(out2);\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_STARTSHA(out2);\
	rptr[13] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,0);\
	rptr[14] = out1;\
\
	dptr += 16;\
	rptr += 16;\
	dlen -= 128;\
\
	CVMX_MF_3DES_RESULT(out2);\
\
	rptr[-1] = out2;\
	CVMX_MT_HSH_DAT(out2,1);\
}\
\
\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA1_STEP(dptr,rptr,dlen,2,3);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA1_STEP(dptr,rptr,dlen,4,5);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA1_STEP_FINAL(dptr,rptr,dlen);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA1_STEP(dptr,rptr,dlen,0,1);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA1_STEP(dptr,rptr,dlen,2,3);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA1_STEP(dptr,rptr,dlen,4,5);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_SHA1_STEP_FINAL(dptr,rptr,dlen);\
\
\
\
\
\
if(dlen)\
{\
  in = *dptr++;\
  CVMX_MT_3DES_ENC_CBC(in);\
  CVMX_MF_3DES_RESULT(out);\
  *rptr++ = out;\
  dlen = 0;\
}\
\
switch( (pktlen + ESP_HEADER_LENGTH + DES_CBC_IV_LENGTH) % 64 )\
{\
  case 0:\
  {\
  CVMX_MT_HSH_DAT( 0x1ull<<63 , 0);\
  CVMX_M32BT_HSH_DATZ(1,2,3,4);\
  CVMX_M16BT_HSH_DATZ(5,6);\
  break;\
  }\
\
  case 8:\
  {\
  CVMX_MT_HSH_DAT(out,0);\
  CVMX_MT_HSH_DAT(0x1ull<<63 , 1);\
  CVMX_M32BT_HSH_DATZ(2,3,4,5);\
  CVMX_MT_HSH_DATZ(6);\
  break;\
  };\
  \
\
  case 16:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,2);\
  CVMX_M32BT_HSH_DATZ(3,4,5,6);\
  break;\
  };\
\
  case 24:\
  {\
  CVMX_MT_HSH_DAT(out,2);\
  CVMX_MT_HSH_DAT( 0x1ull<<63 , 3);\
  CVMX_M24BT_HSH_DATZ(4,5,6);\
  break;\
  };\
\
\
  case 32:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,4);\
  CVMX_M16BT_HSH_DATZ(5,6);\
  break;\
  };\
\
\
\
 case 40:\
  {\
  CVMX_MT_HSH_DAT(out,4);\
  CVMX_MT_HSH_DAT(0x1ull<<63, 5);\
  CVMX_MT_HSH_DATZ(6);\
  break;\
  }\
\
\
  case 48:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,6);\
  break;\
  }\
\
  case 56:\
  {\
  CVMX_MT_HSH_DAT(out,6);\
  CVMX_MT_HSH_STARTSHA(0x1ull<<63);\
  CVMX_M32BT_HSH_DATZ(0,1,2,3);\
  CVMX_M24BT_HSH_DATZ(4,5,6);\
  break;\
  }\
\
  default:break;\
}\
\
CVMX_MT_HSH_STARTSHA(bits);\
dlen = 0;\
\
}


#define COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP(dptr,rptr,dlen, offset0, offset1)\
{\
      	in1=dptr[0];\
      	in2=dptr[1];\
	CVMX_MT_3DES_DEC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_3DES_DEC_CBC(in2);\
	CVMX_MT_HSH_DAT(in1,offset0);\
	rptr[0]=out;\
	dlen -= 16;\
	rptr+=2;\
	dptr+=2;\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_HSH_DAT(in2,offset1);\
      	rptr[-1]=out;\
}

#define COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP_FINAL(dptr,rptr,dlen)\
{\
      	in1=dptr[0];\
      	in2=dptr[1];\
	CVMX_MT_3DES_DEC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_3DES_DEC_CBC(in2);\
	CVMX_MT_HSH_DAT(in1,6);\
	rptr[0]=out;\
	dlen -= 16;\
	rptr+=2;\
	dptr+=2;\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_HSH_STARTSHA(in2);\
      	rptr[-1]=out;\
}





#define COP2_PARALLEL_3DES_DEC_SHA1(dptr,rptr,dlen)\
{\
uint64_t in1,in2;\
uint64_t in,out=0;\
uint64_t bits = ((uint64_t)(pktlen+64))* 0x8ull;\
\
while( dlen >= (128) )\
{\
  COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP(dptr,rptr,dlen,2,3);\
  COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP(dptr,rptr,dlen,4,5);\
  COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP_FINAL(dptr,rptr,dlen);\
  COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP(dptr,rptr,dlen,0,1);\
  COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP(dptr,rptr,dlen,2,3);\
  COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP(dptr,rptr,dlen,4,5);\
  COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP_FINAL(dptr,rptr,dlen);\
  COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP(dptr,rptr,dlen,0,1);\
}\
\
\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP(dptr,rptr,dlen,2,3);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP(dptr,rptr,dlen,4,5);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP_FINAL(dptr,rptr,dlen);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP(dptr,rptr,dlen,0,1);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP(dptr,rptr,dlen,2,3);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP(dptr,rptr,dlen,4,5);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_SHA1_STEP_FINAL(dptr,rptr,dlen);\
\
\
\
\
\
if(dlen)\
{\
  in = *dptr++;\
  CVMX_MT_3DES_DEC_CBC(in);\
  CVMX_MF_3DES_RESULT(out);\
  *rptr++ = out;\
  out = in;\
  dlen = 0;\
}\
\
switch( pktlen  % 64 )\
{\
  case 0:\
  {\
  CVMX_MT_HSH_DAT( 0x1ull<<63 , 0);\
  CVMX_M32BT_HSH_DATZ(1,2,3,4);\
  CVMX_M16BT_HSH_DATZ(5,6);\
  break;\
  }\
\
  case 8:\
  {\
  CVMX_MT_HSH_DAT(out,0);\
  CVMX_MT_HSH_DAT(0x1ull<<63 , 1);\
  CVMX_M32BT_HSH_DATZ(2,3,4,5);\
  CVMX_MT_HSH_DATZ(6);\
  break;\
  };\
  \
\
  case 16:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,2);\
  CVMX_M32BT_HSH_DATZ(3,4,5,6);\
  break;\
  };\
\
  case 24:\
  {\
  CVMX_MT_HSH_DAT(out,2);\
  CVMX_MT_HSH_DAT( 0x1ull<<63 , 3);\
  CVMX_M24BT_HSH_DATZ(4,5,6);\
  break;\
  };\
\
\
  case 32:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,4);\
  CVMX_M16BT_HSH_DATZ(5,6);\
  break;\
  };\
\
\
\
 case 40:\
  {\
  CVMX_MT_HSH_DAT(out,4);\
  CVMX_MT_HSH_DAT(0x1ull<<63, 5);\
  CVMX_MT_HSH_DATZ(6);\
  break;\
  }\
\
\
  case 48:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,6);\
  break;\
  }\
\
  case 56:\
  {\
  CVMX_MT_HSH_DAT(out,6);\
  CVMX_MT_HSH_STARTSHA(0x1ull<<63);\
  CVMX_M32BT_HSH_DATZ(0,1,2,3);\
  CVMX_M24BT_HSH_DATZ(4,5,6);\
  break;\
  }\
\
  default:break;\
}\
\
CVMX_MT_HSH_STARTSHA(bits);\
dlen = 0;\
\
}


#define COP2_PARALLEL_16B_3DES_ENC_MD5_STEP(dptr,rptr,dlen, offset0, offset1)\
{\
      	in1=dptr[0];\
      	in2=dptr[1];\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out,offset0);\
	rptr[0]=out;\
	dlen -= 16;\
	rptr+=2;\
	dptr+=2;\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_HSH_DAT(out,offset1);\
      	rptr[-1]=out;\
}

#define COP2_PARALLEL_16B_3DES_ENC_MD5_STEP_FINAL(dptr,rptr,dlen)\
{\
      	in1=dptr[0];\
      	in2=dptr[1];\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out,6);\
	rptr[0]=out;\
	dlen -= 16;\
	rptr+=2;\
	dptr+=2;\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_HSH_STARTMD5(out);\
      	rptr[-1]=out;\
}





#define COP2_PARALLEL_3DES_ENC_MD5(dptr,rptr,dlen)\
{\
uint64_t in1,in2;\
uint64_t out1,out2;\
uint64_t in,out=0;\
uint64_t bits = ((uint64_t)(pktlen+16+64))* 0x8ull;\
\
while( dlen >= (128) )\
{\
	in1 = dptr[0];\
	in2 = dptr[1];\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out1);\
\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,2);\
	rptr[0] = out1;\
	in1 = dptr[2];\
	in2 = dptr[3];\
	CVMX_MF_3DES_RESULT(out2);\
\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DAT(out2,3);\
	rptr[1] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,4);\
	rptr[2] = out1;\
	in1 = dptr[4];\
	in2 = dptr[5];\
	CVMX_MF_3DES_RESULT(out2);\
\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DAT(out2,5);\
	rptr[3] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,6);\
	rptr[4] = out1;\
	in1 = dptr[6];\
	in2 = dptr[7];\
	CVMX_MF_3DES_RESULT(out2);\
\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_STARTMD5(out2);\
	rptr[5] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,0);\
	rptr[6] = out1;\
	in1 = dptr[8];\
	in2 = dptr[9];\
	CVMX_MF_3DES_RESULT(out2);\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DAT(out2,1);\
	rptr[7] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,2);\
	rptr[8] = out1;\
	in1 = dptr[10];\
	in2 = dptr[11];\
	CVMX_MF_3DES_RESULT(out2);\
\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DAT(out2,3);\
	rptr[9] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,4);\
	rptr[10] = out1;\
	in1 = dptr[12];\
	in2 = dptr[13];\
	CVMX_MF_3DES_RESULT(out2);\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_DAT(out2,5);\
	rptr[11] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,6);\
	rptr[12] = out1;\
	in1 = dptr[14];\
	in2 = dptr[15];\
	CVMX_MF_3DES_RESULT(out2);\
\
	CVMX_MT_3DES_ENC_CBC(in1);\
	CVMX_MT_HSH_STARTMD5(out2);\
	rptr[13] = out2;\
	CVMX_MF_3DES_RESULT(out1);\
	CVMX_MT_3DES_ENC_CBC(in2);\
	CVMX_MT_HSH_DAT(out1,0);\
	rptr[14] = out1;\
\
	dptr += 16;\
	rptr += 16;\
	dlen -= 128;\
\
	CVMX_MF_3DES_RESULT(out2);\
\
	rptr[-1] = out2;\
	CVMX_MT_HSH_DAT(out2,1);\
}\
\
\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_MD5_STEP(dptr,rptr,dlen,2,3);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_MD5_STEP(dptr,rptr,dlen,4,5);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_MD5_STEP_FINAL(dptr,rptr,dlen);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_MD5_STEP(dptr,rptr,dlen,0,1);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_MD5_STEP(dptr,rptr,dlen,2,3);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_MD5_STEP(dptr,rptr,dlen,4,5);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_ENC_MD5_STEP_FINAL(dptr,rptr,dlen);\
\
\
\
\
\
if(dlen)\
{\
  in = *dptr++;\
  CVMX_MT_3DES_ENC_CBC(in);\
  CVMX_MF_3DES_RESULT(out);\
  *rptr++ = out;\
  dlen = 0;\
}\
\
switch( (pktlen + ESP_HEADER_LENGTH + DES_CBC_IV_LENGTH) % 64 )\
{\
  case 0:\
  {\
  CVMX_MT_HSH_DAT( 0x1ull<<63 , 0);\
  CVMX_M32BT_HSH_DATZ(1,2,3,4);\
  CVMX_M16BT_HSH_DATZ(5,6);\
  break;\
  }\
\
  case 8:\
  {\
  CVMX_MT_HSH_DAT(out,0);\
  CVMX_MT_HSH_DAT(0x1ull<<63 , 1);\
  CVMX_M32BT_HSH_DATZ(2,3,4,5);\
  CVMX_MT_HSH_DATZ(6);\
  break;\
  };\
  \
\
  case 16:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,2);\
  CVMX_M32BT_HSH_DATZ(3,4,5,6);\
  break;\
  };\
\
  case 24:\
  {\
  CVMX_MT_HSH_DAT(out,2);\
  CVMX_MT_HSH_DAT( 0x1ull<<63 , 3);\
  CVMX_M24BT_HSH_DATZ(4,5,6);\
  break;\
  };\
\
\
  case 32:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,4);\
  CVMX_M16BT_HSH_DATZ(5,6);\
  break;\
  };\
\
\
\
 case 40:\
  {\
  CVMX_MT_HSH_DAT(out,4);\
  CVMX_MT_HSH_DAT(0x1ull<<63, 5);\
  CVMX_MT_HSH_DATZ(6);\
  break;\
  }\
\
\
  case 48:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,6);\
  break;\
  }\
\
  case 56:\
  {\
  CVMX_MT_HSH_DAT(out,6);\
  CVMX_MT_HSH_STARTMD5(0x1ull<<63);\
  CVMX_M32BT_HSH_DATZ(0,1,2,3);\
  CVMX_M24BT_HSH_DATZ(4,5,6);\
  break;\
  }\
\
  default:break;\
}\
\
CVMX_ES64(bits,bits);\
CVMX_MT_HSH_STARTMD5(bits);\
dlen = 0;\
\
}


#define COP2_PARALLEL_16B_3DES_DEC_MD5_STEP(dptr,rptr,dlen, offset0, offset1)\
{\
      	in1=dptr[0];\
      	in2=dptr[1];\
	CVMX_MT_3DES_DEC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_3DES_DEC_CBC(in2);\
	CVMX_MT_HSH_DAT(in1,offset0);\
	rptr[0]=out;\
	dlen -= 16;\
	rptr+=2;\
	dptr+=2;\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_HSH_DAT(in2,offset1);\
      	rptr[-1]=out;\
}

#define COP2_PARALLEL_16B_3DES_DEC_MD5_STEP_FINAL(dptr,rptr,dlen)\
{\
      	in1=dptr[0];\
      	in2=dptr[1];\
	CVMX_MT_3DES_DEC_CBC(in1);\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_3DES_DEC_CBC(in2);\
	CVMX_MT_HSH_DAT(in1,6);\
	rptr[0]=out;\
	dlen -= 16;\
	rptr+=2;\
	dptr+=2;\
	CVMX_MF_3DES_RESULT(out);\
	CVMX_MT_HSH_STARTMD5(in2);\
      	rptr[-1]=out;\
}





#define COP2_PARALLEL_3DES_DEC_MD5(dptr,rptr,dlen)\
{\
uint64_t in1,in2;\
uint64_t in,out=0;\
uint64_t bits = ((uint64_t)(pktlen+64))* 0x8ull;\
\
while( dlen >= (128) )\
{\
  COP2_PARALLEL_16B_3DES_DEC_MD5_STEP(dptr,rptr,dlen,2,3);\
  COP2_PARALLEL_16B_3DES_DEC_MD5_STEP(dptr,rptr,dlen,4,5);\
  COP2_PARALLEL_16B_3DES_DEC_MD5_STEP_FINAL(dptr,rptr,dlen);\
  COP2_PARALLEL_16B_3DES_DEC_MD5_STEP(dptr,rptr,dlen,0,1);\
  COP2_PARALLEL_16B_3DES_DEC_MD5_STEP(dptr,rptr,dlen,2,3);\
  COP2_PARALLEL_16B_3DES_DEC_MD5_STEP(dptr,rptr,dlen,4,5);\
  COP2_PARALLEL_16B_3DES_DEC_MD5_STEP_FINAL(dptr,rptr,dlen);\
  COP2_PARALLEL_16B_3DES_DEC_MD5_STEP(dptr,rptr,dlen,0,1);\
}\
\
\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_MD5_STEP(dptr,rptr,dlen,2,3);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_MD5_STEP(dptr,rptr,dlen,4,5);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_MD5_STEP_FINAL(dptr,rptr,dlen);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_MD5_STEP(dptr,rptr,dlen,0,1);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_MD5_STEP(dptr,rptr,dlen,2,3);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_MD5_STEP(dptr,rptr,dlen,4,5);\
if(dlen >= 16) COP2_PARALLEL_16B_3DES_DEC_MD5_STEP_FINAL(dptr,rptr,dlen);\
\
\
\
\
\
if(dlen)\
{\
  in = *dptr++;\
  CVMX_MT_3DES_DEC_CBC(in);\
  CVMX_MF_3DES_RESULT(out);\
  *rptr++ = out;\
  out = in;\
  dlen = 0;\
}\
\
switch( pktlen  % 64 )\
{\
  case 0:\
  {\
  CVMX_MT_HSH_DAT( 0x1ull<<63 , 0);\
  CVMX_M32BT_HSH_DATZ(1,2,3,4);\
  CVMX_M16BT_HSH_DATZ(5,6);\
  break;\
  }\
\
  case 8:\
  {\
  CVMX_MT_HSH_DAT(out,0);\
  CVMX_MT_HSH_DAT(0x1ull<<63 , 1);\
  CVMX_M32BT_HSH_DATZ(2,3,4,5);\
  CVMX_MT_HSH_DATZ(6);\
  break;\
  };\
  \
\
  case 16:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,2);\
  CVMX_M32BT_HSH_DATZ(3,4,5,6);\
  break;\
  };\
\
  case 24:\
  {\
  CVMX_MT_HSH_DAT(out,2);\
  CVMX_MT_HSH_DAT( 0x1ull<<63 , 3);\
  CVMX_M24BT_HSH_DATZ(4,5,6);\
  break;\
  };\
\
\
  case 32:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,4);\
  CVMX_M16BT_HSH_DATZ(5,6);\
  break;\
  };\
\
\
\
 case 40:\
  {\
  CVMX_MT_HSH_DAT(out,4);\
  CVMX_MT_HSH_DAT(0x1ull<<63, 5);\
  CVMX_MT_HSH_DATZ(6);\
  break;\
  }\
\
\
  case 48:\
  {\
  CVMX_MT_HSH_DAT(0x1ull<<63,6);\
  break;\
  }\
\
  case 56:\
  {\
  CVMX_MT_HSH_DAT(out,6);\
  CVMX_MT_HSH_STARTMD5(0x1ull<<63);\
  CVMX_M32BT_HSH_DATZ(0,1,2,3);\
  CVMX_M24BT_HSH_DATZ(4,5,6);\
  break;\
  }\
\
  default:break;\
}\
\
CVMX_ES64(bits,bits);\
CVMX_MT_HSH_STARTMD5(bits);\
dlen = 0;\
\
}



#define CVMX_M16BT_AES_ENC(in1,in2)\
CVMX_MT_AES_ENC0(in1);\
CVMX_MT_AES_ENC1(in2);

#define CVMX_M16BF_AES_RESULT(out1,out2)\
CVMX_MF_AES_RESULT(out1, 0);\
CVMX_MF_AES_RESULT(out2, 1);


#define CVMX_AES_CTR_ENC_MD5_DELAY_SLOT0(void)\
{\
  d1 = dptr[0];d2 = dptr[1];\
  dlen -= 16; rptr += 2; dptr += 2;\
  if(in2 != UEND) {in2++;} else {in2 = 0; in1++;}\
}

#define CVMX_AES_CTR_ENC_MD5_DELAY_SLOT(offset0,offset1)\
{\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
  d1 = dptr[0];d2 = dptr[1];\
  dlen -= 16; rptr += 2; dptr += 2;\
  if(in2 != UEND) {in2++;} else {in2 = 0; in1++;}\
  CVMX_MT_HSH_DAT(rptr[-4],offset0);\
  CVMX_MT_HSH_DAT(rptr[-3],offset1);\
}

#define CVMX_AES_CTR_ENC_MD5_DELAY_SLOT_FINAL(void)\
{\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
  d1 = dptr[0];d2 = dptr[1];\
  dlen -= 16; rptr += 2; dptr += 2; \
  if(in2 != UEND) {in2++;} else {in2 = 0; in1++;}\
  CVMX_MT_HSH_DAT(rptr[-4],6);\
  CVMX_MT_HSH_STARTMD5(rptr[-3]);\
}

#define COP2_PARALLEL_16B_AES_CTR_ENC_MD5_STEP(offset0,offset1)\
{\
  uint64_t d1,d2;\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_MD5_DELAY_SLOT0(void);\
  CVMX_M16BF_AES_RESULT(out1,out2);\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
  CVMX_MT_HSH_DAT(rptr[-2],offset0);\
  if(offset1 == 7)\
  CVMX_MT_HSH_STARTMD5(rptr[-1]);\
  else\
  CVMX_MT_HSH_DAT(rptr[-1],offset1);\
}

#define COP2_PARALLEL_128BN_AES_CTR_ENC_MD5(dptr,rptr,dlen)\
while(dlen >= 128)\
{\
  uint64_t d1,d2;\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_MD5_DELAY_SLOT0(void);\
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_MD5_DELAY_SLOT(2,3);\
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_MD5_DELAY_SLOT(4,5);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_MD5_DELAY_SLOT_FINAL(void);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_MD5_DELAY_SLOT(0,1);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_MD5_DELAY_SLOT(2,3);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_MD5_DELAY_SLOT(4,5);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_MD5_DELAY_SLOT_FINAL(void);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
  CVMX_MT_HSH_DAT(rptr[-2],0);\
  CVMX_MT_HSH_DAT(rptr[-1],1);\
}

#define COP2_PARALLEL_16B_AES_CTR_DEC_MD5_STEP(offset0,offset1)\
{\
  uint64_t d1,d2;\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_MD5_DELAY_SLOT0(void);\
\
  CVMX_MT_HSH_DAT(d1,offset0);\
  if(offset1 == 7)\
  CVMX_MT_HSH_STARTMD5(d2);\
  else\
  CVMX_MT_HSH_DAT(d2,offset1);\
\
  CVMX_M16BF_AES_RESULT(out1,out2);\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
}

#define CVMX_AES_CTR_ENC_SHA1_DELAY_SLOT0(void)\
{\
  d1 = dptr[0];d2 = dptr[1];\
  dlen -= 16; rptr += 2; dptr += 2;\
  if(in2 != UEND) {in2++;} else {in2 = 0; in1++;}\
}


#define CVMX_AES_CTR_ENC_SHA1_DELAY_SLOT(offset0,offset1)\
{\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
  d1 = dptr[0];d2 = dptr[1];\
  dlen -= 16; rptr += 2; dptr += 2;\
  if(in2 != UEND) {in2++;} else {in2 = 0; in1++;}\
  CVMX_MT_HSH_DAT(rptr[-4],offset0);\
  CVMX_MT_HSH_DAT(rptr[-3],offset1);\
}

#define CVMX_AES_CTR_ENC_SHA1_DELAY_SLOT_FINAL(void)\
{\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
  d1 = dptr[0];d2 = dptr[1];\
  dlen -= 16; rptr += 2; dptr += 2; \
  if(in2 != UEND) {in2++;} else {in2 = 0; in1++;}\
  CVMX_MT_HSH_DAT(rptr[-4],6);\
  CVMX_MT_HSH_STARTSHA(rptr[-3]);\
}

#define COP2_PARALLEL_16B_AES_CTR_ENC_SHA1_STEP(offset0,offset1)\
{\
  uint64_t d1,d2;\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA1_DELAY_SLOT0(void);\
  CVMX_M16BF_AES_RESULT(out1,out2);\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
  CVMX_MT_HSH_DAT(rptr[-2],offset0);\
  if(offset1 == 7)\
  CVMX_MT_HSH_STARTSHA(rptr[-1]);\
  else\
  CVMX_MT_HSH_DAT(rptr[-1],offset1);\
}

#define COP2_PARALLEL_128BN_AES_CTR_ENC_SHA1(dptr,rptr,dlen)\
while(dlen >= 128)\
{\
  uint64_t d1,d2;\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA1_DELAY_SLOT0(void);\
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA1_DELAY_SLOT(2,3);\
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA1_DELAY_SLOT(4,5);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA1_DELAY_SLOT_FINAL(void);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA1_DELAY_SLOT(0,1);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA1_DELAY_SLOT(2,3);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA1_DELAY_SLOT(4,5);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA1_DELAY_SLOT_FINAL(void);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
  CVMX_MT_HSH_DAT(rptr[-2],0);\
  CVMX_MT_HSH_DAT(rptr[-1],1);\
}

#define COP2_PARALLEL_16B_AES_CTR_DEC_SHA1_STEP(offset0,offset1)\
{\
  uint64_t d1,d2;\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA1_DELAY_SLOT0(void);\
\
  CVMX_MT_HSH_DAT(d1,offset0);\
  if(offset1 == 7)\
  CVMX_MT_HSH_STARTSHA(d2);\
  else\
  CVMX_MT_HSH_DAT(d2,offset1);\
\
  CVMX_M16BF_AES_RESULT(out1,out2);\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
}


#define CVMX_AES_CTR_ENC_SHA256_DELAY_SLOT0(void)\
{\
  d1 = dptr[0];d2 = dptr[1];\
  dlen -= 16; rptr += 2; dptr += 2;\
  if(in2 != UEND) {in2++;} else {in2 = 0; in1++;}\
}


#define CVMX_AES_CTR_ENC_SHA256_DELAY_SLOT(offset0,offset1)\
{\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
  d1 = dptr[0];d2 = dptr[1];\
  dlen -= 16; rptr += 2; dptr += 2;\
  if(in2 != UEND) {in2++;} else {in2 = 0; in1++;}\
  CVMX_MT_HSH_DAT(rptr[-4],offset0);\
  CVMX_MT_HSH_DAT(rptr[-3],offset1);\
}

#define CVMX_AES_CTR_ENC_SHA256_DELAY_SLOT_FINAL(void)\
{\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
  d1 = dptr[0];d2 = dptr[1];\
  dlen -= 16; rptr += 2; dptr += 2; \
  if(in2 != UEND) {in2++;} else {in2 = 0; in1++;}\
  CVMX_MT_HSH_DAT(rptr[-4],6);\
  CVMX_MT_HSH_STARTSHA256(rptr[-3]);\
}

#define COP2_PARALLEL_16B_AES_CTR_ENC_SHA256_STEP(offset0,offset1)\
{\
  uint64_t d1,d2;\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA256_DELAY_SLOT0(void);\
  CVMX_M16BF_AES_RESULT(out1,out2);\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
  CVMX_MT_HSH_DAT(rptr[-2],offset0);\
  if(offset1 == 7)\
  CVMX_MT_HSH_STARTSHA256(rptr[-1]);\
  else\
  CVMX_MT_HSH_DAT(rptr[-1],offset1);\
}

#define COP2_PARALLEL_128BN_AES_CTR_ENC_SHA256(dptr,rptr,dlen)\
while(dlen >= 128)\
{\
  uint64_t d1,d2;\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA256_DELAY_SLOT0(void);\
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA256_DELAY_SLOT(2,3);\
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA256_DELAY_SLOT(4,5);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA256_DELAY_SLOT_FINAL(void);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA256_DELAY_SLOT(0,1);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA256_DELAY_SLOT(2,3);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA256_DELAY_SLOT(4,5);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA256_DELAY_SLOT_FINAL(void);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
  CVMX_MT_HSH_DAT(rptr[-2],0);\
  CVMX_MT_HSH_DAT(rptr[-1],1);\
}

#define COP2_PARALLEL_16B_AES_CTR_DEC_SHA256_STEP(offset0,offset1)\
{\
  uint64_t d1,d2;\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA256_DELAY_SLOT0(void);\
\
  CVMX_MT_HSH_DAT(d1,offset0);\
  if(offset1 == 7)\
  CVMX_MT_HSH_STARTSHA256(d2);\
  else\
  CVMX_MT_HSH_DAT(d2,offset1);\
\
  CVMX_M16BF_AES_RESULT(out1,out2);\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
}


#define CVMX_AES_CTR_ENC_SHA512_DELAY_SLOT0(void)\
{\
  d1 = dptr[0];d2 = dptr[1];\
  dlen -= 16; rptr += 2; dptr += 2;\
  if(in2 != UEND) {in2++;} else {in2 = 0; in1++;}\
}


#define CVMX_AES_CTR_ENC_SHA512_DELAY_SLOT(offset0,offset1)\
{\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
  d1 = dptr[0];d2 = dptr[1];\
  dlen -= 16; rptr += 2; dptr += 2;\
  if(in2 != UEND) {in2++;} else {in2 = 0; in1++;}\
  CVMX_MT_HSH_DATW(rptr[-4],offset0);\
  CVMX_MT_HSH_DATW(rptr[-3],offset1);\
}

#define CVMX_AES_CTR_ENC_SHA512_DELAY_SLOT_FINAL(void)\
{\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
  d1 = dptr[0];d2 = dptr[1];\
  dlen -= 16; rptr += 2; dptr += 2; \
  if(in2 != UEND) {in2++;} else {in2 = 0; in1++;}\
  CVMX_MT_HSH_DATW(rptr[-4],14);\
  CVMX_MT_HSH_STARTSHA512(rptr[-3]);\
}

#define COP2_PARALLEL_16B_AES_CTR_ENC_SHA512_STEP(offset0,offset1)\
{\
  uint64_t d1,d2;\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA512_DELAY_SLOT0(void);\
  CVMX_M16BF_AES_RESULT(out1,out2);\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
  CVMX_MT_HSH_DATW(rptr[-2],offset0);\
  if(offset1 == 15)\
  CVMX_MT_HSH_STARTSHA512(rptr[-1]);\
  else\
  CVMX_MT_HSH_DATW(rptr[-1],offset1);\
}

#define COP2_PARALLEL_128BN_AES_CTR_ENC_SHA512(dptr,rptr,dlen)\
while(dlen >= 128)\
{\
  uint64_t d1,d2;\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA512_DELAY_SLOT0(void);\
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA512_DELAY_SLOT(2,3);\
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA512_DELAY_SLOT(4,5);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA512_DELAY_SLOT(6,7);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA512_DELAY_SLOT(8,9);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA512_DELAY_SLOT(10,11);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA512_DELAY_SLOT(12,13);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA512_DELAY_SLOT_FINAL(void);  \
  CVMX_M16BF_AES_RESULT(out1,out2);\
\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
  CVMX_MT_HSH_DATW(rptr[-2],0);\
  CVMX_MT_HSH_DATW(rptr[-1],1);\
}

#define COP2_PARALLEL_16B_AES_CTR_DEC_SHA512_STEP(offset0,offset1)\
{\
  uint64_t d1,d2;\
  CVMX_M16BT_AES_ENC(in1,in2);\
  CVMX_AES_CTR_ENC_SHA512_DELAY_SLOT0(void);\
\
  CVMX_MT_HSH_DATW(d1,offset0);\
  if(offset1 == 15)\
  CVMX_MT_HSH_STARTSHA512(d2);\
  else\
  CVMX_MT_HSH_DATW(d2,offset1);\
\
  CVMX_M16BF_AES_RESULT(out1,out2);\
  rptr[-2] = d1 ^ out1;\
  rptr[-1] = d2 ^ out2;\
}


#endif

#endif
