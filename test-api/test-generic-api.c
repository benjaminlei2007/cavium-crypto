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



#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/rc4.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/cryptlib.h>
#include "openssl/crypto-generic-api.h"


#define TEST_MULTICALL
#define GENERIC_INPUT_LENGTH (1024)
#define FILLDATA 1
#define OUTPUT_BUFF 0
#define MAX_RAND 100

unsigned char buff_in[GENERIC_INPUT_LENGTH];
buffers_t *head_in = NULL, *head_encrypt = NULL, *head_decrypt = NULL;



buffers_t *
create_link_in (buffers_t * head_in, int fill_datain)
{
  buffers_t *temp;
  int i;
  unsigned char buff = 0x01;
  buffers_t *inbuff;
  unsigned long count = 0;
  unsigned int rnd;

  srand (cvmx_get_cycle ());

  if (head_in == NULL) {
    temp = (buffers_t *) malloc (sizeof (buffers_t));
    if (temp == NULL)
      printf ("Memory allocation to temp Failed\n");

    rnd = rand () % MAX_RAND;
    head_in = temp;
    if (rnd > GENERIC_INPUT_LENGTH)
      head_in->size = GENERIC_INPUT_LENGTH;
    else
      head_in->size = rnd;

    head_in->data =
      (unsigned char *) malloc (sizeof (char) * (head_in->size));
    if (head_in->data == NULL)
      printf ("Memory allocation to head_in->data Failed\n");

    memset (head_in->data, 0, head_in->size);
    if (fill_datain) {
      for (i = 0; i < head_in->size; i++) {
        head_in->data[i] = buff_in[count++] = buff++;
      }
    } else {
      count += head_in->size;
    }
    head_in->next = NULL;
  }

  inbuff = head_in;
  while (count != GENERIC_INPUT_LENGTH) {
    rnd = rand () % MAX_RAND;
    temp = (buffers_t *) malloc (sizeof (buffers_t));
    if ((GENERIC_INPUT_LENGTH - count) < rnd)
      temp->size = GENERIC_INPUT_LENGTH - count;
    else
      temp->size = rnd;

    temp->data = (unsigned char *) malloc (sizeof (char) * (temp->size));
    if (temp->data == NULL)
      printf ("Memory allocation to temp->data Failed\n");

    memset (temp->data, 0, temp->size);
    if (fill_datain) {
      for (i = 0; i < temp->size; i++)
        temp->data[i] = buff_in[count++] = buff++;
    } else {
      count += temp->size;
    }
    inbuff->next = temp;

    inbuff = inbuff->next;
    inbuff->next = NULL;
  }
  return head_in;
}

void
parse_link_list (unsigned char *data, buffers_t * temp)
{
  long count = 0;
  while (temp != NULL) {
    memcpy (data + count, temp->data, temp->size);
    count += temp->size;
    temp = temp->next;
  }
}


void
free_link_list (buffers_t * head)
{
  buffers_t *temp, *walk_ptr;

  walk_ptr = head;
  while (walk_ptr != NULL) {
    temp = walk_ptr;
    free (temp->data);
    walk_ptr = walk_ptr->next;
    free (temp);
  }

}


void
generic_test_des ()
{
  unsigned char des_key[8] = { 0xf2, 0xe0, 0xd5, 0xc2, 0xb5, 0xa1, 0x97, 0x85 };
  unsigned char des_iv[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
  unsigned char orig_iv[8];
  unsigned char encrypted_data[GENERIC_INPUT_LENGTH];
  unsigned char orig_data[GENERIC_INPUT_LENGTH];
  int ret;

  memcpy (orig_iv, des_iv, 8);
  ret = des_encrypt (SINGLEDES, des_key, des_iv, head_in, head_encrypt);
  if (ret != 0) {
    printf ("des_encrypt Failed (Error Code) : %x\n", ret);
    return;
  }
  parse_link_list (encrypted_data, head_encrypt);
  memcpy (des_iv, orig_iv, 8);
  ret =
    des_decrypt (SINGLEDES, des_key, des_iv, head_encrypt, head_decrypt);
  if (ret != 0) {
    printf ("des_decrypt Failed (Error Code) : %x\n", ret);
    return;
  }
  memset (orig_data, 0, GENERIC_INPUT_LENGTH);
  parse_link_list (orig_data, head_decrypt);

  if (!memcmp (orig_data, buff_in, GENERIC_INPUT_LENGTH))
    printf ("Single DES Encryption/Decryption Passed\n");
  else
    printf ("Single DES Encryption/Decryption Failed\n");
}


void
generic_test_3des ()
{
  unsigned char des_key[24] = { 
    0xf2, 0xe0, 0xd5, 0xc2, 0xb5, 0xa1, 0x97, 0x85,
    0xf2, 0xe0, 0xd5, 0xc2, 0xb5, 0xa1, 0x97, 0x85,
    0x31, 0xe3, 0xd0, 0x51, 0xb3, 0xa4, 0x97, 0x83
  };
  unsigned char des_iv[8] =
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
  unsigned char orig_iv[8];
  unsigned char encrypted_data[GENERIC_INPUT_LENGTH];
  unsigned char orig_data[GENERIC_INPUT_LENGTH];
  int ret;

  memcpy (orig_iv, des_iv, 8);
  ret = des_encrypt (TRIPLEDES, des_key, des_iv, head_in, head_encrypt);
  if (ret != 0) {
    printf ("des_encrypt Failed (Error Code) : %x\n", ret);
    goto err;
  }
  parse_link_list (encrypted_data, head_encrypt);
  memcpy (des_iv, orig_iv, 8);
  ret =
    des_decrypt (TRIPLEDES, des_key, des_iv, head_encrypt, head_decrypt);
  if (ret != 0) {
    printf ("des_decrypt Failed (Error Code) : %x\n", ret);
    goto err;
  }
  memset (orig_data, 0, GENERIC_INPUT_LENGTH);
  parse_link_list (orig_data, head_decrypt);

  if (!memcmp (orig_data, buff_in, GENERIC_INPUT_LENGTH))
    printf ("Triple DES Encryption/Decryption Passed\n");
  else
    printf ("Triple DES Encryption/Decryption Failed\n");

  return;

err:
  printf ("%s\n", ERR_error_string (ret, NULL));
}


void
generic_test_aes ()
{
  int ret;
  unsigned char orig_iv[16], orig_data[GENERIC_INPUT_LENGTH];
  unsigned char encrypted_data[GENERIC_INPUT_LENGTH];
  unsigned char key_128[] = { 
    0x09, 0x28, 0x34, 0x74, 0x00, 0x12, 0xab, 0x45,
    0x93, 0x67, 0x56, 0x37, 0xca, 0xaf, 0xff, 0xbb
  };

  unsigned char key_192[] = { 
    0x23, 0x98, 0x74, 0xaa, 0xbd, 0xef, 0xad, 0x94,
    0x8b, 0xcd, 0xf7, 0x36, 0x4b, 0xca, 0xc7, 0xbc,
    0x84, 0xd8, 0x47, 0x46, 0x69, 0x47, 0x00, 0xcd
  };

  unsigned char key_256[] = { 
    0x91, 0x28, 0x73, 0x48, 0x72, 0x13, 0x46, 0x87,
    0x16, 0xab, 0xde, 0x84, 0x7b, 0xc4, 0x87, 0xad,
    0x98, 0x8d, 0xdf, 0xff, 0xf7, 0x38, 0x46, 0xbc,
    0xad, 0xef, 0x54, 0x76, 0x84, 0x73, 0x64, 0x78
  };

  unsigned char iv[] = { 
    0x08, 0x93, 0x78, 0x67, 0x49, 0x32, 0x87, 0x21,
    0x67, 0xab, 0xcd, 0xef, 0xaf, 0xcd, 0xef, 0xff
  };

/**************** AES 128 Bit Test ******************/
  memcpy (orig_iv, iv, 16);
  memset (encrypted_data, 0, GENERIC_INPUT_LENGTH);
  memset (orig_data, 0, GENERIC_INPUT_LENGTH);

  ret = aes_encrypt (AES128_CBC, key_128, iv, head_in, head_encrypt);
  if (ret != 0) {
    printf ("aes_encrypt Failed (Error Code) : %x\n", ret);
    goto err;
  }
  parse_link_list (encrypted_data, head_encrypt);
  memcpy (iv, orig_iv, 16);

  ret = aes_decrypt (AES128_CBC, key_128, iv, head_encrypt, head_decrypt);
  if (ret != 0) {
    printf ("aes_decrypt Failed (Error Code) : %x\n", ret);
    goto err;
  }
  parse_link_list (orig_data, head_decrypt);

  if (!memcmp (orig_data, buff_in, GENERIC_INPUT_LENGTH))
    printf ("AES-128 bit Encryption/Decryption Passed\n");
  else
    printf ("AES-128 bit Encryption/Decryption Failed\n");


/**************** AES 192 Bit Test ******************/
  memset (encrypted_data, 0, GENERIC_INPUT_LENGTH);
  memset (orig_data, 0, GENERIC_INPUT_LENGTH);
  memcpy (iv, orig_iv, 16);

  ret = aes_encrypt (AES192_CBC, key_192, iv, head_in, head_encrypt);
  if (ret != 0) {
    printf ("aes_encrypt Failed (Error Code) : %x\n", ret);
    goto err;
  }
  parse_link_list (encrypted_data, head_encrypt);
  memcpy (iv, orig_iv, 16);

  ret = aes_decrypt (AES192_CBC, key_192, iv, head_encrypt, head_decrypt);
  if (ret != 0) {
    printf ("aes_decrypt Failed (Error Code) : %x\n", ret);
    goto err;
  }
  parse_link_list (orig_data, head_decrypt);

  if (!memcmp (orig_data, buff_in, GENERIC_INPUT_LENGTH))
    printf ("AES-192 bit Encryption/Decryption Passed\n");
  else
    printf ("AES-192 bit Encryption/Decryption Failed\n");


/**************** AES 256 Bit Test ******************/
  memset (encrypted_data, 0, GENERIC_INPUT_LENGTH);
  memset (orig_data, 0, GENERIC_INPUT_LENGTH);
  memcpy (iv, orig_iv, 16);

  ret = aes_encrypt (AES256_CBC, key_256, iv, head_in, head_encrypt);
  if (ret != 0) {
    printf ("aes_encrypt Failed (Error Code) : %x\n", ret);
    goto err;
  }
  parse_link_list (encrypted_data, head_encrypt);
  memcpy (iv, orig_iv, 16);

  ret = aes_decrypt (AES256_CBC, key_256, iv, head_encrypt, head_decrypt);
  if (ret != 0) {
    printf ("aes_decrypt Failed (Error Code) : %x\n", ret);
    goto err;
  }
  parse_link_list (orig_data, head_decrypt);

  if (!memcmp (orig_data, buff_in, GENERIC_INPUT_LENGTH))
    printf ("AES-256 bit Encryption/Decryption Passed\n");
  else
    printf ("AES-256 bit Encryption/Decryption Failed\n");

  return;

err:
  printf ("%s\n", ERR_error_string (ret, NULL));
}

void
generic_test_hmac ()
{
  unsigned char key[] = "This is the Secret key";
  unsigned char hash[100];
  int ret;
  unsigned char hmac_hash[100];
  unsigned int md_len;

/**************** HMAC SHA1 **************/
  ret = hmac (HMACSHA1, sizeof (key), key, head_in, hash);
  if (ret != 0) {
    printf ("hmac sha1 Failed (Error Code) : %x\n", ret);
    goto err;
  }

  HMAC (EVP_sha1 (), key, sizeof (key), buff_in, GENERIC_INPUT_LENGTH,
    hmac_hash, &md_len);

  if (!memcmp (hash, hmac_hash, 20))
    printf ("HMAC SHA1 Passed\n");
  else
    printf ("HMAC SHA1 Failed\n");

/**************** HMAC SHA224 **************/
  ret = hmac (HMACSHA224, sizeof (key), key, head_in, hash);
  if (ret != 0) {
    printf ("hmac sha224 Failed (Error Code) : %x\n", ret);
    goto err;
  }

  HMAC (EVP_sha224 (), key, sizeof (key), buff_in, GENERIC_INPUT_LENGTH,
    hmac_hash, &md_len);

  if (!memcmp (hash, hmac_hash, 28))
    printf ("HMAC SHA224 Passed\n");
  else
    printf ("HMAC SHA224 Failed\n");

/**************** HMAC SHA256 **************/
  ret = hmac (HMACSHA256, sizeof (key), key, head_in, hash);
  if (ret != 0) {
    printf ("hmac sha256 Failed (Error Code) : %x\n", ret);
    goto err;
  }

  HMAC (EVP_sha256 (), key, sizeof (key), buff_in, GENERIC_INPUT_LENGTH,
    hmac_hash, &md_len);

  if (!memcmp (hash, hmac_hash, 32))
    printf ("HMAC SHA256 Passed\n");
  else
    printf ("HMAC SHA256 Failed\n");

/**************** HMAC SHA384 **************/
  ret = hmac (HMACSHA384, sizeof (key), key, head_in, hash);
  if (ret != 0) {
    printf ("hmac sha384 Failed (Error Code) : %x\n", ret);
    goto err;
  }

  HMAC (EVP_sha384 (), key, sizeof (key), buff_in, GENERIC_INPUT_LENGTH,
    hmac_hash, &md_len);

  if (!memcmp (hash, hmac_hash, 48))
    printf ("HMAC SHA384 Passed\n");
  else
    printf ("HMAC SHA384 Failed\n");

/**************** HMAC SHA512 **************/
  ret = hmac (HMACSHA512, sizeof (key), key, head_in, hash);
  if (ret != 0) {
    printf ("hmac sha512 Failed (Error Code) : %x\n", ret);
    goto err;
  }

  HMAC (EVP_sha512 (), key, sizeof (key), buff_in, GENERIC_INPUT_LENGTH,
    hmac_hash, &md_len);

  if (!memcmp (hash, hmac_hash, 64))
    printf ("HMAC SHA512 Passed\n");
  else
    printf ("HMAC SHA512 Failed\n");

/******* HMAC MD4 *******/
  ret = hmac (HMACMD5, sizeof (key), key, head_in, hash);
  if (ret != 0) {
    printf ("hmac md5 Failed (Error Code) : %x\n", ret);
    goto err;
  }

  HMAC (EVP_md5 (), key, sizeof (key), buff_in, GENERIC_INPUT_LENGTH,
    hmac_hash, &md_len);

  if (!memcmp (hash, hmac_hash, 16))
    printf ("HMAC MD5 Passed\n");
  else
    printf ("HMAC MD5 Failed\n");

  return;

err:
  printf ("%s\n", ERR_error_string (ret, NULL));
}


void
generic_test_dh ()
{
  unsigned char *plocal, *glocal;
  DH *dh = NULL;
  unsigned char *private_key = NULL, *public_key = NULL, *sh_secret = NULL;
  int plen, glen, ret;

  dh = DH_generate_parameters (128, DH_GENERATOR_5, NULL, NULL);
  if (dh == NULL)
    printf ("DH_generate_parameters Failed\n");

  plocal = (unsigned char *) malloc (sizeof (char) * 1024);
  if (!(plen = BN_bn2bin (dh->p, plocal)))
    printf ("plen : Error BN_bn2bin\n");

  glocal = (unsigned char *) malloc (sizeof (char) * 1024);
  if (!(glen = BN_bn2bin (dh->g, glocal)))
    printf ("glen : Error BN_bn2bin\n");

  if (!(private_key = (unsigned char *) malloc (sizeof (char) * plen)))
    printf ("Memory allocation to private key Failed\n");

  if (!(public_key = (unsigned char *) malloc (sizeof (char) * plen)))
    printf ("Memory allocation to public key Failed\n");

  sh_secret = (unsigned char *) malloc (sizeof (char) * 1024);
  if (sh_secret == NULL)
    printf ("Memory allocation to sh_secret Failed\n");

  ret = dh_generate_key_pair (plen, plocal, glen, glocal, private_key,
    public_key);
  if (ret != 0) {
    printf ("dh_generate_key_pair Failed (Error Code) : %d\n", ret);
    goto err;
  }

  ret = dh_generate_shared_secret (plen, plocal, public_key,
    private_key, sh_secret);
  if (ret != 0) {
    printf ("dh_generate_shared_secret Failed (Error Code : %d)\n", ret);
    goto err;
  } else {
    printf ("DH Passed\n");
  }

err:
  free (sh_secret);
  free (plocal);
  free (glocal);
  free (private_key);
  free (public_key);

  DH_free (dh);
  if (ret != 0)
    printf ("%s\n", ERR_error_string (ret, NULL));
}

void
generic_test_dh2 ()
{
  unsigned int dhbits = 128;
  unsigned int dhbytes = dhbits/8;

  /* shared data structures */
  DH *dh = NULL;
  unsigned int plen;
  unsigned char *p = NULL;
  unsigned int glen;
  unsigned char *g = NULL;

  /* alice data structures */
  unsigned int alice_privkeylen;
  unsigned char *alice_privkey = NULL;
  unsigned int alice_pubkeylen;
  unsigned char *alice_pubkey = NULL;
  unsigned int alice_shared_secret_len;
  unsigned char *alice_shared_secret = NULL;

  /* bob data structures */
  unsigned int bob_privkeylen;
  unsigned char *bob_privkey = NULL;
  unsigned int bob_pubkeylen;
  unsigned char *bob_pubkey = NULL;
  unsigned int bob_shared_secret_len;
  unsigned char *bob_shared_secret = NULL;

  /* misc */
  int ret;

  dh = DH_generate_parameters(dhbits,DH_GENERATOR_5,NULL,NULL);
  if(dh == NULL) {
    printf("DH_generate_parameters Failed\n");
    ret = -1;
    goto err;
  }

  p = (unsigned char*)malloc(sizeof(char)*dhbytes);
  if(p == NULL) {
    printf("Malloc Failed\n");
    ret = -1;
    goto err;
  }
  if (!(plen = BN_bn2bin(dh->p,p))) {
     printf("plen: Failed : BN_bn2bin\n");
     ret = -1;
     goto err;
  }

  g = (unsigned char*)malloc(sizeof(char)*dhbytes);
  if(g == NULL) {
    printf("Malloc Failed\n");
    ret = -1;
    goto err;
  }
  if(!(glen = BN_bn2bin(dh->g,g))) {
    printf("glen: Failed :BN_bn2bin\n");
    ret = -1;
    goto err;
  }
     
  /* setup alice side */
  /* force api to generate privkey of this length */
  alice_privkeylen = 184/8;
  if(!(alice_privkey = (unsigned char*)malloc(alice_privkeylen))) {
    printf("privkey Malloc Failed\n");
    ret = -1;
    goto err;
  }
  
  if(!(alice_pubkey = (unsigned char*)malloc(sizeof(char)*plen))) {
    printf("pubkey Malloc Failed\n");
    ret = -1;
    goto err;
  }

  if(!(alice_shared_secret = (unsigned char*)malloc(sizeof(char)*plen))) {
    printf("shared_secret Malloc Failed\n");
    ret = -1;
    goto err;
  }

  ret = dh_generate_key_pair2(
          plen,p,
          glen,g,
          &alice_pubkeylen,alice_pubkey,
          &alice_privkeylen,alice_privkey
        );
  if(ret) {
    printf("dh_generate_key_pair2 Failed (Error Code) :%d\n",ret);
    ret = -1;
    goto err;
  }

 /* setup bob side */
  if(!(bob_privkey = (unsigned char*)malloc(sizeof(char)*plen))) {
    printf("privkey Malloc Failed\n");
    ret = -1;
    goto err;
  }
  
  if(!(bob_pubkey = (unsigned char*)malloc(sizeof(char)*plen))) {
    printf("pubkey Malloc Failed\n");
    ret = -1;
    goto err;
  }

  if(!(bob_shared_secret = (unsigned char*)malloc(sizeof(char)*plen))) {
    printf("shared_secret Malloc Failed\n");
    ret = -1;
    goto err;
  }

  /* let api decide the length of the private key */
  bob_privkeylen = 0;
  ret = dh_generate_key_pair2(
          plen,p,
          glen,g,
          &bob_pubkeylen,bob_pubkey,
          &bob_privkeylen,bob_privkey
        );
  if(ret) {
    printf("dh_generate_key_pair2 Failed (Error Code) :%d\n",ret);
    ret = -1;
    goto err;
  } 

  /* alice side shared secret */
  ret = dh_generate_shared_secret2(
          plen,p,
          bob_pubkeylen,bob_pubkey,
          alice_privkeylen,alice_privkey,
          &alice_shared_secret_len,alice_shared_secret);
  if(ret) {
    printf("dh_generate_shared_secret2 Failed (Error code: %d\n",ret);
    ret = -1;
    goto err;
  }

   /* bob side shared secret */
  ret = dh_generate_shared_secret2(
          plen,p,
          alice_pubkeylen,alice_pubkey,
          bob_privkeylen,bob_privkey,
          &bob_shared_secret_len,bob_shared_secret);
  if(ret) {
    printf("dh_generate_shared_secret2 Failed (Error code: %d\n",ret);
    ret = -1;
    goto err;
  }


  if(alice_shared_secret_len != bob_shared_secret_len) {
    printf("DH Failed\n");
    printf("alice_shared_secret_len = %u\n", alice_shared_secret_len);
    printf("bob_shared_secret_len = %u\n", bob_shared_secret_len);
    ret = -1;
    goto err;
  }

  if(memcmp(alice_shared_secret,bob_shared_secret,alice_shared_secret_len)) {
    printf("DH Failed\n");
    printf("alice and bob shared secrets mismatch\n");
    ret = -1;
    goto err;  
  }
 
  err:
  /* free alice data structures */
  if(alice_privkey)
    free(alice_privkey);

  if(alice_pubkey)
    free(alice_pubkey);

  if(alice_shared_secret)
    free(alice_shared_secret);

  /* free bob data structures */
  if(bob_privkey)
    free(bob_privkey);

  if(bob_pubkey)
    free(bob_pubkey);

  if(bob_shared_secret)
    free(bob_shared_secret);

  /* free common data structures */
  if(p)
    free(p);

  if(g)
    free(g);

  if(dh)
    DH_free(dh);

  if (ret!=0)
    printf("%s\n",ERR_error_string (ret,NULL)); 
}

void
generic_test_rsa_pkcs1_padding ()
{
  rsa_st_t rsast;
  rsast.modulus_length = 1024;
  int ret = -1;
  unsigned char outdata[1024];
  unsigned char orig_data[GENERIC_INPUT_LENGTH];
  unsigned int outlen, orig_len;
  unsigned char buff_in[] = "Hello, World";
  int inlen = sizeof (buff_in);

  rsast.e_ptr = (unsigned long *) malloc (sizeof (unsigned long));
  *(rsast.e_ptr) = 65537;
  rsast.n_ptr = (unsigned char *) malloc (rsast.modulus_length);
  rsast.p_ptr = (unsigned char *) malloc (rsast.modulus_length);
  rsast.q_ptr = (unsigned char *) malloc (rsast.modulus_length);
  rsast.d_ptr = (unsigned char *) malloc (rsast.modulus_length);
  rsast.dp_ptr = (unsigned char *) malloc (rsast.modulus_length);
  rsast.dq_ptr = (unsigned char *) malloc (rsast.modulus_length);
  rsast.pinv = (unsigned char *) malloc (rsast.modulus_length);

  if ((rsast.n_ptr == NULL) || (rsast.p_ptr == NULL) ||
    (rsast.q_ptr == NULL) || (rsast.d_ptr == NULL) ||
    (rsast.dp_ptr == NULL) || (rsast.dq_ptr == NULL) ||
    (rsast.pinv == NULL)) {
    printf ("Memory Allocation Failed\n");
    return;
  }
  ret = rsa_create_key_pair (&rsast);
  if (ret != 0) {
    printf ("rsa_create_key_pair Failed (Error Code : %x)\n", ret);
    goto err;
  }

  ret = rsa_encrypt_with_private_key (&rsast, inlen, buff_in,
    &outlen, outdata,RSA_PKCS1_PADDING);
  if (ret != 0) {
    printf ("rsa_encrypt_with_private_key Failed (Error Code) : %x\n",
      ret);
    goto err;
  }

  ret = rsa_decrypt_with_public_key (&rsast, outlen, outdata,
    &orig_len, orig_data,RSA_PKCS1_PADDING);
  if (ret != 0) {
    printf ("rsa_decrypt_with_public_key Failed(Error Code) : %x\n", ret);
    goto err;
  }

  if (!memcmp (orig_data, buff_in, inlen))
    printf ("PKCS1 RSA PKCS1 PADDING Encrypt/Decrypt Passed\n");
  else
    printf ("PKCS1 RSA PKCS1 PADDING Encrypt/Decrypt Failed\n");

  memset (outdata, 0, sizeof (outdata));
  memset (orig_data, 0, sizeof (orig_data));

  ret = rsa_encrypt_with_public_key (&rsast, inlen,
    buff_in, &outlen, outdata,RSA_PKCS1_PADDING);
  if (ret != 0) {
    printf ("rsa_encrypt_with_public_key Failed (Error Code) : %d\n", ret);
    goto err;
  }

  ret = rsa_decrypt_with_private_key (&rsast, outlen, outdata,
    &orig_len, orig_data,RSA_PKCS1_PADDING);
  if (ret != 0) {
    printf ("rsa_decrypt_with_private_key Failed (Error Code) : %d\n", ret);
    goto err;
  }

  if (!memcmp (orig_data, buff_in, inlen))
    printf ("PKCS1 RSA PKCS1 PADDING Encrypt/Decrypt Passed\n");
  else
    printf ("PKCS1 RSA PKCS1 PADDING Encrypt/Decrypt Failed\n");

err:
  free (rsast.n_ptr);
  free (rsast.p_ptr);
  free (rsast.q_ptr);
  free (rsast.d_ptr);
  free (rsast.dp_ptr);
  free (rsast.dq_ptr);
  free (rsast.pinv);
  free (rsast.e_ptr);

  if (ret != 0)
    printf ("%s\n", ERR_error_string (ret, NULL));
}

void
generic_test_rsa_no_padding ()
{
  rsa_st_t rsast;
  rsast.modulus_length = 1024;
  int ret = -1;
  unsigned char outdata[1024];
  unsigned char orig_data[GENERIC_INPUT_LENGTH];
  unsigned int outlen, orig_len;
  unsigned char buff_in[128];
  int inlen = sizeof (buff_in);

  memset(buff_in,0xc,sizeof(buff_in));

  rsast.e_ptr = (unsigned long *) malloc (sizeof (unsigned long));
  *(rsast.e_ptr) = 65537;
  rsast.n_ptr = (unsigned char *) malloc (rsast.modulus_length);
  rsast.p_ptr = (unsigned char *) malloc (rsast.modulus_length);
  rsast.q_ptr = (unsigned char *) malloc (rsast.modulus_length);
  rsast.d_ptr = (unsigned char *) malloc (rsast.modulus_length);
  rsast.dp_ptr = (unsigned char *) malloc (rsast.modulus_length);
  rsast.dq_ptr = (unsigned char *) malloc (rsast.modulus_length);
  rsast.pinv = (unsigned char *) malloc (rsast.modulus_length);

  if ((rsast.n_ptr == NULL) || (rsast.p_ptr == NULL) ||
    (rsast.q_ptr == NULL) || (rsast.d_ptr == NULL) ||
    (rsast.dp_ptr == NULL) || (rsast.dq_ptr == NULL) ||
    (rsast.pinv == NULL)) {
    printf ("Memory Allocation Failed\n");
    return;
  }
  ret = rsa_create_key_pair (&rsast);
  if (ret != 0) {
    printf ("rsa_create_key_pair Failed (Error Code : %x)\n", ret);
    goto err;
  }

  ret = rsa_encrypt_with_private_key (&rsast, inlen, buff_in,
    &outlen, outdata,RSA_NO_PADDING);
  if (ret != 0) {
    printf ("rsa_encrypt_with_private_key Failed (Error Code) : %x\n",
      ret);
    goto err;
  }

  ret = rsa_decrypt_with_public_key (&rsast, outlen, outdata,
    &orig_len, orig_data,RSA_NO_PADDING);
  if (ret != 0) {
    printf ("rsa_decrypt_with_public_key Failed (Error Code) : %x\n", ret);
    goto err;
  }

  if (!memcmp (orig_data, buff_in, inlen))
    printf ("PKCS1 RSA NO PADDING Encrypt/Decrypt Passed\n");
  else
    printf ("PKCS1 RSA NO PADDING Encrypt/Decrypt Failed\n");

  memset (outdata, 0, sizeof (outdata));
  memset (orig_data, 0, sizeof (orig_data));

  ret = rsa_encrypt_with_public_key (&rsast, inlen,
    buff_in, &outlen, outdata,RSA_NO_PADDING);
  if (ret != 0) {
    printf ("rsa_encrypt_with_public_key Failed (Error Code) : %d\n", ret);
    goto err;
  }

  ret = rsa_decrypt_with_private_key (&rsast, outlen, outdata,
    &orig_len, orig_data,RSA_NO_PADDING);
  if (ret != 0) {
    printf ("rsa_decrypt_with_private_key Failed (Error Code) : %d\n", ret);
    goto err;
  }

  if (!memcmp (orig_data, buff_in, inlen))
    printf ("PKCS1 RSA NO PADDING Encrypt/Decrypt Passed\n");
  else
    printf ("PKCS1 RSA NO PADDING Encrypt/Decrypt Failed\n");

err:
  free (rsast.n_ptr);
  free (rsast.p_ptr);
  free (rsast.q_ptr);
  free (rsast.d_ptr);
  free (rsast.dp_ptr);
  free (rsast.dq_ptr);
  free (rsast.pinv);
  free (rsast.e_ptr);

  if (ret != 0)
    printf ("%s\n", ERR_error_string (ret, NULL));
}




int main ()
{
#ifdef OCTEON_OPENSSL_NO_DYNAMIC_MEMORY
    if (cvmx_user_app_init() < 0) {
        printf ("User Application Initialization Failed\n");
        return -1;
    }
#endif

#if (OCTEON_SDK_VERSION_NUMBER > 106000217ull)
    if (cvm_crypto_model_check()) {
        printf("This model is Not supported \n");
        return -1;
    }
#endif
 
  memset (buff_in, 0, GENERIC_INPUT_LENGTH);

  /* Crypto Generic Inplace */
  head_in = head_encrypt = head_decrypt = create_link_in (head_in, FILLDATA);
  generic_test_des ();
  free_link_list (head_in);
  head_in = head_encrypt = head_decrypt = NULL;

  head_in = head_encrypt = head_decrypt = create_link_in (head_in, FILLDATA);
  generic_test_3des ();
  free_link_list (head_in);
  head_in = head_encrypt = head_decrypt = NULL;

  head_in = head_encrypt = head_decrypt = create_link_in (head_in, FILLDATA);
  generic_test_aes ();
  free_link_list (head_in);
  head_in = head_encrypt = head_decrypt = NULL;

  /* Crypto Generic NonInplace */
  head_in = create_link_in (head_in, FILLDATA);
  head_encrypt = create_link_in (head_encrypt, OUTPUT_BUFF);
  head_decrypt = create_link_in (head_decrypt, OUTPUT_BUFF);

  generic_test_des ();
  generic_test_3des ();
  generic_test_aes ();
  generic_test_hmac ();
  generic_test_dh ();
  generic_test_dh2 ();
  generic_test_rsa_pkcs1_padding ();
  generic_test_rsa_no_padding ();

  free_link_list (head_in);
  free_link_list (head_encrypt);
  free_link_list (head_decrypt);
  head_in = head_encrypt = head_decrypt = NULL;

  printf ("************** End of test **************\n");
  return 0;
}
