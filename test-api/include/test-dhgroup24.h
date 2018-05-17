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
 *The following test data is taken from RFC5114
 */

char *prime=		"87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597";
char *gen=		"3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659";
char *peer_pub_key =	"575F0351BD2B1B817448BDF87A6C362C1E289D3903A30B9832C5741FA250363E7ACBC7F77F3DACBC1F131ADD8E03367EFF8FBBB3E1C5784424809B25AFE4D2262A1A6FD2FAB64105CA30A674E07F7809852088632FC049233791AD4EDD083A978B883EE618BC5E0DD047415F2D95E683CF14826B5FBE10D3CE41C6C120C78AB20008C698BF7F0BCAB9D7F407BED0F43AFB2970F57F8D12043963E66DDD320D599AD9936C8F44137C08B180EC5E985CEBE186F3D549677E80607331EE17AF3380A725B0782317D7DD43F59D7AF9568A9BB63A84D365F92244ED120988219302F42924C7CA90B89D24F71B0AB697823D7DEB1AFF5B0E8E4A45D49F7F53757E1913";
char *pub_key =		"2E9380C8323AF97545BC4941DEB0EC3742C62FE0ECE824A6ABDBE66C59BEE0242911BFB967235CEBA35AE13E4EC752BE630B92DC4BDE2847A9C62CB8152745421FB7EB60A63C0FE9159FCCE726CE7CD8523D7450667EF840E4919121EB5F01C8C9B0D3D648A93BFB75689E8244AC134AF544711CE79A02DCC34226684780DDDCB498594106C37F5BC79856487AF5AB022A2E5E42F09897C1A85A11EA0212AF04D9B4CEBC937C3C1A3E15A8A0342E337615C84E7FE3B8B9B87FB1E73A15AF12A30D746E06DFC34F290D797CE51AA13AA785BF6658AFF5E4B093003CBEAF665B3C2E113A3A4E905269341DC0711426685F4EF37E868A8126FF3F2279B57CA67E29";
char *shared_key_req =	"86C70BF8D0BB81BB01078A17219CB7D27203DB2A19C877F1D1F19FD7D77EF22546A68F005AD52DC84553B78FC60330BE51EA7C0672CAC1515E4B35C047B9A551B88F39DC26DA14A09EF74774D47C762DD177F9ED5BC2F11E52C879BD95098504CD9EECD8A8F9B3EFBD1F008AC5853097D9D1837F2B18F77CD7BE01AF80A7C7B5EA3CA54CC02D0C116FEE3F95BB87399385875D7E86747E676E728938ACBFF7098E05BE4DCFB24052B83AEFFB14783F029ADBDE7F53FAE92084224090E007CEE94D4BF2BACE9FFD4B57D2AF7C724D0CAA19BF0501F6F17B4AA10F425E3EA76080B4B9D6B3CEFEA115B2CEB8789BB8A3B0EA87FEBE63B6C8F846EC6DB0C26C5D7C";
char *priv_key =	"0881382CDB87660C6DC13E614938D5B9C8B2F248581CC5E31B35454397FCE50E";
int peer_pub_key_len = 2048;

#ifdef EC_DEBUG
static void
hex_dump (uint8_t *inp, uint32_t len, const char *s)
{
    uint32_t i;
    printf ("%s : ", s);
    for (i = 0; i < len; i++)
        printf ("%02x", *(inp + i));
    printf ("\n");
    return;
}
#endif

#if 0
static int 
hex_comp (uint8_t *inp, uint8_t *inp1, uint32_t len)
{
    uint32_t i;
    for (i = 0; i < len; i++)
	    if(inp[i]!=inp1[i]){
		    return -1;
	    }
    return 0;
}
#endif


