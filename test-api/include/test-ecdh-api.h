
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

#ifdef TEST_CPU_CYCLES
	static uint64_t start_cycle = 0;
	static uint64_t end_cycle = 0;
	static uint64_t cpucycles, tps;
	static int iter;
	unsigned int core;
	cvmx_sysinfo_t *sysinfo;

	#define START_CYCLE  \
		start_cycle = end_cycle = 0;  \
 		sysinfo = cvmx_sysinfo_get();\
		start_cycle = cvmx_clock_get_count (CVMX_CLOCK_CORE);\
		for (iter = 0; iter < MAX_ITERATIONS; iter++) {

	#define END_CYCLE(str)  \
		} \
		end_cycle = cvmx_clock_get_count (CVMX_CLOCK_CORE); \
		cpucycles = (long)(end_cycle - start_cycle)/MAX_ITERATIONS; \
		tps = cpufreq * 1000000 / cpucycles; \
 		for (core = 0; core < CVMX_MAX_CORES; core++) {\
			if (cvmx_coremask_is_core_set(&sysinfo->core_mask, core) && core == cvmx_get_core_num()){ \
			total_cpucycles+=cpucycles;\
			total_tps +=tps;\
			}\
			cvmx_coremask_barrier_sync(&sysinfo->core_mask);\
		}\
		cvmx_coremask_barrier_sync(&sysinfo->core_mask);\
		if(cvmx_is_init_core()){\
 			printf ("API :%-20s total tps :%-10lu average values per core    cpucycles :%lu tps :%lu\n", str, total_tps, (total_cpucycles/numcores), (total_tps/numcores));\
			total_cpucycles = 0;\
			total_tps = 0;\
		}

#else
#define START_CYCLE
#define END_CYCLE(str)
#endif

#ifdef TEST_CPU_CYCLES
	char *curve_name;
	#define PRINT_HDR \
		if (cvmx_is_init_core()) { \
			if (nid == NID_X9_62_prime192v1)\
				curve_name = "NID_X9_62_prime192v1";\
			else if (nid == NID_secp224r1)\
				curve_name = "NID_secp224r1";\
			else if (nid == NID_X9_62_prime256v1)\
				curve_name = "NID_X9_62_prime256v1";\
			else if (nid == NID_secp384r1)\
				curve_name = "NID_secp384r1";\
			else if (nid == NID_secp521r1)\
				curve_name = "NID_secp521r1";\
			printf ("\n\n#############################################################\n"); \
        	printf ("           Prime Curve %s \n",curve_name); \
        	printf ("#############################################################\n"); \
		}
#else
    #define PRINT_HDR
#endif

#define NUM_CURVES 5 


struct TEST_DATA
{
	char *priv_key_a;
	char *pub_key_a_x;
	char *pub_key_a_y;
	char *priv_key_b;
	char *pub_key_b_x;
	char *pub_key_b_y;
	char *shared_key;
};
/* test vectors from rfc 5114 */
struct TEST_DATA ecdh_test_vectors[NUM_CURVES]={
{"323FA3169D8E9C6593F59476BC142000AB5BE0E249C43426",
"CD46489ECFD6C105E7B3D32566E2B122E249ABAADD870612",
"68887B4877DF51DD4DC3D6FD11F0A26F8FD3844317916E9A",
"631F95BB4A67632C9C476EEE9AB695AB240A0499307FCF62",
"519A121680E0045466BA21DF2EEE47F5973B500577EF13D5",
"FF613AB4D64CEE3A20875BDB10F953F6B30CA072C60AA57F",
"AD420182633F8526BFE954ACDA376F05E5FF4F837F54FEBE"
//"4371545ED772A59741D0EDA32C671112B7FDDD51461FCF32"
},
{"B558EB6C288DA707BBB4F8FBAE2AB9E9CB62E3BC5C7573E22E26D37F",
"49DFEF309F81488C304CFF5AB3EE5A2154367DC7833150E0A51F3EEB",
"4F2B5EE45762C4F654C1A0C67F54CF88B016B51BCE3D7C228D57ADB4",
"AC3B1ADD3D9770E6F6A708EE9F3B8E0AB3B480E9F27F85C88B5E6D18",
"6B3AC96A8D0CDE6A5599BE8032EDF10C162D0A8AD219506DCD42A207",
"D491BE99C213A7D1CA3706DEBFE305F361AFCBB33E2609C8B1618AD5",
"52272F50F46F4EDC9151569092F46DF2D96ECC3B6DC1714A4EA949FA"
//"5F30C6AA36DDC403C0ACB712BB88F1763C3046F6D919BD9C524322BF"
},
{"814264145F2F56F2E96A8E337A1284993FAF432A5ABCE59E867B7291D507A3AF",
"2AF502F3BE8952F2C9B5A8D4160D09E97165BE50BC42AE4A5E8D3B4BA83AEB15",
"EB0FAF4CA986C4D38681A0F9872D79D56795BD4BFF6E6DE3C0F5015ECE5EFD85",
"2CE1788EC197E096DB95A200CC0AB26A19CE6BCCAD562B8EEE1B593761CF7F41",
"B120DE4AA36492795346E8DE6C2C8646AE06AAEA279FA775B3AB0715F6CE51B0",
"9F1B7EECE20D7B5ED8EC685FA3F071D83727027092A8411385C34DDE5708B2B6",
"DD0F5396219D1EA393310412D19A08F1F5811E9DC8EC8EEA7F80D21C820C2788"
},
{"D27335EA71664AF244DD14E9FD1260715DFD8A7965571C48D709EE7A7962A156D706A90CBCB5DF2986F05FEADB9376F1",
"793148F1787634D5DA4C6D9074417D05E057AB62F82054D10EE6B0403D6279547E6A8EA9D1FD77427D016FE27A8B8C66",
"C6C41294331D23E6F480F4FB4CD40504C947392E94F4C3F06B8F398BB29E42368F7A685923DE3B67BACED214A1A1D128",
"52D1791FDB4B70F89C0F00D456C2F7023B6125262C36A7DF1F80231121CCE3D39BE52E00C194A4132C4A6C768BCD94D2",
"5CD42AB9C41B5347F74B8D4EFB708B3D5B36DB65915359B44ABC17647B6B9999789D72A84865AE2F223F12B5A1ABC120",
"E171458FEAA939AAA3A8BFAC46B404BD8F6D5B348C0FA4D80CECA16356CA933240BDE8723415A8ECE035B0EDF36755DE",
"5EA1FC4AF7256D2055981B110575E0A8CAE53160137D904C59D926EB1B8456E427AA8A4540884C37DE159A58028ABC0E"
},
{"0113F82DA825735E3D97276683B2B74277BAD27335EA71664AF2430CC4F33459B9669EE78B3FFB9B8683015D344DCBFEF6FB9AF4C6C470BE254516CD3C1A1FB47362",
"01EBB34DD75721ABF8ADC9DBED17889CBB9765D90A7C60F2CEF007BB0F2B26E14881FD4442E689D61CB2DD046EE30E3FFD20F9A45BBDF6413D583A2DBF59924FD35C",
"00F6B632D194C0388E22D8437E558C552AE195ADFD153F92D74908351B2F8C4EDA94EDB0916D1B53C020B5EECAED1A5FC38A233E4830587BB2EE3489B3B42A5A86A4",
"00CEE3480D8645A17D249F2776D28BAE616952D1791FDB4B70F7C3378732AA1B22928448BCD1DC2496D435B01048066EBE4F72903C361B1A9DC1193DC2C9D0891B96",
"010EBFAFC6E85E08D24BFFFCC1A4511DB0E634BEEB1B6DEC8C5939AE44766201AF6200430BA97C8AC6A0E9F08B33CE7E9FEEB5BA4EE5E0D81510C24295B8A08D0235",
"00A4A6EC300DF9E257B0372B5E7ABFEF093436719A77887EBB0B18CF8099B9F4212B6E30A1419C18E029D36863CC9D448F4DBA4D2A0E60711BE572915FBD4FEF2695",
"00CDEA89621CFA46B132F9E4CFE2261CDE2D4368EB5656634C7CC98C7A00CDE54ED1866A0DD3E6126C9D2F845DAFF82CEB1DA08F5D87521BB0EBECA77911169C20CC"
}
};
struct CURVE_DATA 
{
	int nid;
	char curvename[50];
};

struct CURVE_DATA curves[NUM_CURVES]={
    {NID_X9_62_prime192v1, "NIST Prime-Curve P-192"},
    {NID_secp224r1, "NIST Prime-Curve P-224"},
	{NID_X9_62_prime256v1,"NIST Prime-Curve P-256"},
	{NID_secp384r1,"NIST Prime-Curve P-384"},
	{NID_secp521r1,"NIST Prime-Curve P-521"}
};



