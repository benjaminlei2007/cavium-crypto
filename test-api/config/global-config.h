/* ====================================================================
 * Copyright (c) 1998-2008 The OpenSSL Project.  All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


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


/**
 * @file comp-config.template
 *
 *  copy this file to the application directory as
 *
 *    config/comp-config.h
 *
 *  and customize the flags/settings as appropriate
 *
 * $Id: global-config.h 28667 2007-09-27 10:15:55Z apappu $ $Name$
 *
 *
 */
 
#ifndef __GLOBAL_CONFIG_H__
#define __GLOBAL_CONFIG_H__
 
/*
 * some example flags:
 *
 * #define  COMP_FLAG_ONE
 * #define  COMP_FLAG_TWO
 *
 */
#define STACK_PERF
#define SANITY_CHECKS
#define DUTY_CYCLE

/*
 * some example settings:
 *
 * #define  COMP_SETTING_ONE  10
 * #define  COMP_SETTING_TWO  20
 *
 */
 
 
/* Content below this point is only used by the cvmx-config tool, and is
** not used by any C files as CAVIUM_COMPONENT_REQUIREMENT is never
defined.
*/
#ifdef CAVIUM_COMPONENT_REQUIREMENT
 
        /* global resource requirement */
 
        cvmxconfig
        {
                fpa CVM_FPA_128B_POOL
                        size = 1
                        description = "128-byte FPA pool";

                fpa CVM_FPA_DRV_POOL
                        size = 32
		        protected = true
                        description = "4096-byte Core drv FPA pool";

                fau CVMX_FAU_REG_POOL_0_USE_COUNT
                        size = 4
                        description = "pool 0 use count";

                fau CVMX_FAU_REG_POOL_1_USE_COUNT
                        size = 4
                        description = "pool 1 use count";

                fau CVMX_FAU_REG_POOL_2_USE_COUNT
                        size = 4
                        description = "pool 2 use count";

                fau CVMX_FAU_REG_POOL_3_USE_COUNT
                        size = 4
                        description = "pool 3 use count";

                fau CVMX_FAU_REG_POOL_4_USE_COUNT
                        size = 4
                        description = "pool 4 use count";

                fau CVMX_FAU_REG_POOL_5_USE_COUNT
                        size = 4
                        description = "pool 5 use count";

                fau CVMX_FAU_REG_POOL_6_USE_COUNT
                        size = 4
                        description = "pool 6 use count";

                fau CVMX_FAU_REG_POOL_7_USE_COUNT
                        size = 4
                        description = "pool 7 use count";


                scratch CVMX_SCR_WQE_BUF_PTR
                        size = 8
                        iobdma = true
                        permanent = true
                        description = "Scratch pad location for 256-byte buffer pointer";

                scratch CVMX_SCR_PACKET_BUF_PTR
                        size = 8
                        iobdma = true
                        permanent = true
                        description = "Scratch pad location for packet buffer pointer";

                scratch CVM_SCR_128B_BUF_PTR
                        size = 8
                        iobdma = true
                        permanent = true
                        description = "Scratch pad location for 128-byte buffer pointer";

                scratch CVM_SCR_ADDITIONAL_128B_BUF_PTR
                        size = 8
                        iobdma = true
                        permanent = true
                        description = "Another scratch pad location for 128-byte buffer pointer";

                scratch CVM_SCR_DRV_BUF_PTR
                        size = 8
                        iobdma = true
                        permanent = true
                        description = "Scratch pad location for 4096-byte core drv buffer pointer";

                scratch CVM_SCR_GATHER_BUF_PTR
                        size = 8
                        iobdma = true
                        permanent = true
                        description = "Scratch pad location for gather buffer pointer";
                scratch CVM_SCR_MBUFF_INFO_PTR
                        size = 8
                        iobdma = true
                        permanent = true
                        description = "Scratch pad location for  mbuff sizes";

	}

 
#endif
 
#endif  /* __GLOBAL_CONFIG_H__ */
