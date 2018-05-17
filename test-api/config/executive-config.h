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


/*************************************************************************
Copyright (c) 2003-2005, Cavium Networks. All rights reserved.

This Software is the property of Cavium Networks.  The Software and all
accompanying documentation are copyrighted.  The Software made available
here constitutes the proprietary information of Cavium Networks.  You
agree to take reasonable steps to prevent the disclosure, unauthorized use
or unauthorized distribution of the Software.  You shall use this Software
solely with Cavium hardware.

Except as expressly permitted in a separate Software License Agreement
between You and Cavium Networks, you shall not modify, decompile,
disassemble, extract, or otherwise reverse engineer this Software.  You
shall not make any copy of the Software or its accompanying documentation,
except for copying incident to the ordinary and intended use of the
Software and the Underlying Program and except for the making of a single
archival copy.

This Software, including technical data, may be subject to U.S.  export
control laws, including the U.S.  Export Administration Act and its
associated regulations, and may be subject to export or import regulations
in other countries.  You warrant that You will comply strictly in all
respects with all such regulations and acknowledge that you have the
responsibility to obtain licenses to export, re-export or import the
Software.

TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
AND WITH ALL FAULTS AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR
WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT
TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY
REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT
DEFECTS, AND CAVIUM SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES
OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR
PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET
POSSESSION OR CORRESPONDENCE TO DESCRIPTION.  THE ENTIRE RISK ARISING OUT
OF USE OR PERFORMANCE OF THE SOFTWARE LIES WITH YOU.

*************************************************************************/

/*
 * File version info: $Id: executive-config.h 31089 2008-01-16 11:44:20Z apappu $
 *
 */
#ifndef __EXECUTIVE_CONFIG_H__
#define __EXECUTIVE_CONFIG_H__

/* Define to enable the use of simple executive DFA functions */
//#define CVMX_ENABLE_DFA_FUNCTIONS

/* Define to enable the use of simple executive packet output functions.
** For packet I/O setup enable the helper functions below. 
*/ 
#define CVMX_ENABLE_PKO_FUNCTIONS

/* Define to enable the use of simple executive timer bucket functions. 
** Refer to cvmx-tim.[ch] for more information
*/
//#define CVMX_ENABLE_TIMER_FUNCTIONS

/* Define to enable the use of simple executive helper functions. These
** include many harware setup functions.  See cvmx-helper.[ch] for
** details.
*/
#define CVMX_ENABLE_HELPER_FUNCTIONS

/* CVMX_HELPER_FIRST_MBUFF_SKIP is the number of bytes to reserve before
** the beginning of the packet. If necessary, override the default  
** here.  See the IPD section of the hardware manual for MBUFF SKIP 
** details.*/ 
#define CVMX_HELPER_FIRST_MBUFF_SKIP 184

/* CVMX_HELPER_NOT_FIRST_MBUFF_SKIP is the number of bytes to reserve in each
** chained packet element. If necessary, override the default here */
#define CVMX_HELPER_NOT_FIRST_MBUFF_SKIP 0

/* CVMX_HELPER_ENABLE_BACK_PRESSURE controls whether back pressure is enabled
** for all input ports. This controls if IPD sends backpressure to all ports if
** Octeon's FPA pools don't have enough packet or work queue entries. Even when
** this is off, it is still possible to get backpressure from individual
** hardware ports. When configuring backpressure, also check
** CVMX_HELPER_DISABLE_*_BACKPRESSURE below. If necessary, override the default
** here */
#define CVMX_HELPER_ENABLE_BACK_PRESSURE 1

/* CVMX_HELPER_ENABLE_IPD controls if the IPD is enabled in the helper
**  function. Once it is enabled the hardware starts accepting packets. You
**  might want to skip the IPD enable if configuration changes are need
**  from the default helper setup. If necessary, override the default here */
#define CVMX_HELPER_ENABLE_IPD 1

/* CVMX_HELPER_INPUT_TAG_TYPE selects the type of tag that the IPD assigns
** to incoming packets. */
#define CVMX_HELPER_INPUT_TAG_TYPE CVMX_POW_TAG_TYPE_ORDERED

/* The following select which fields are used by the PIP to generate
** the tag on INPUT
** 0: don't include
** 1: include */
#define CVMX_HELPER_INPUT_TAG_IPV6_SRC_IP	0
#define CVMX_HELPER_INPUT_TAG_IPV6_DST_IP   	0
#define CVMX_HELPER_INPUT_TAG_IPV6_SRC_PORT 	0
#define CVMX_HELPER_INPUT_TAG_IPV6_DST_PORT 	0
#define CVMX_HELPER_INPUT_TAG_IPV6_NEXT_HEADER 	0
#define CVMX_HELPER_INPUT_TAG_IPV4_SRC_IP	0
#define CVMX_HELPER_INPUT_TAG_IPV4_DST_IP   	0
#define CVMX_HELPER_INPUT_TAG_IPV4_SRC_PORT 	0
#define CVMX_HELPER_INPUT_TAG_IPV4_DST_PORT 	0
#define CVMX_HELPER_INPUT_TAG_IPV4_PROTOCOL	0
#define CVMX_HELPER_INPUT_TAG_INPUT_PORT	1

/* Select skip mode for input ports */
#define CVMX_HELPER_INPUT_PORT_SKIP_MODE	CVMX_PIP_PORT_CFG_MODE_SKIPL2

/* Define the number of queues per output port */
#define CVMX_HELPER_PKO_QUEUES_PER_PORT_INTERFACE0	1
#define CVMX_HELPER_PKO_QUEUES_PER_PORT_INTERFACE1	1

/* Configure PKO to use per-core queues (PKO lockless operation). 
** Please see the related SDK documentation for PKO that illustrates 
** how to enable and configure this option. */
//#define CVMX_ENABLE_PKO_LOCKLESS_OPERATION 1
//#define CVMX_HELPER_PKO_MAX_PORTS_INTERFACE0 8
//#define CVMX_HELPER_PKO_MAX_PORTS_INTERFACE1 8

/* Force backpressure to be disabled.  This overrides all other
** backpressure configuration */
#define CVMX_HELPER_DISABLE_RGMII_BACKPRESSURE 1

/* Disable the SPI4000's processing of backpressure packets and backpressure
** generation. When this is 1, the SPI4000 will not stop sending packets when
** receiving backpressure. It will also not generate backpressure packets when
** its internal FIFOs are full. */
#define CVMX_HELPER_DISABLE_SPI4000_BACKPRESSURE 1

/* Select the number of low latency memory ports (interfaces) that
** will be configured.  Valid values are 1 and 2.
*/
#define CVMX_LLM_CONFIG_NUM_PORTS 1

/* Enable the fix for PKI-100 errata ("Size field is 8 too large in WQE and next
** pointers"). If CVMX_ENABLE_LEN_M8_FIX is set to 0, the fix for this errata will 
** not be enabled. 
** 0: Fix is not enabled
** 1: Fix is enabled, if supported by hardware
*/
#define CVMX_ENABLE_LEN_M8_FIX  1

#if defined(CVMX_ENABLE_HELPER_FUNCTIONS) && !defined(CVMX_ENABLE_PKO_FUNCTIONS)
#define CVMX_ENABLE_PKO_FUNCTIONS
#endif

/* Executive resource descriptions provided in cvmx-resources.config */
#include "cvmx-resources.config"

#endif
