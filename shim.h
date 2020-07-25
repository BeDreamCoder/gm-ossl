/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>

int X_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid);
int X_EVP_SignInit(EVP_MD_CTX *ctx, const EVP_MD *type);
int X_EVP_SignUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt);
int X_EVP_VerifyInit(EVP_MD_CTX *ctx, const EVP_MD *type);
int X_EVP_VerifyUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt);
int X_EC_GROUP_get_curve_name(EVP_PKEY *sk);
EVP_PKEY *X_export_pk_from_sk(EVP_PKEY *sk);
unsigned char *X_ECWithSM3_Sign(EVP_PKEY *sk, const unsigned char *digest,
                                size_t digestlen, size_t *siglen, ENGINE *eng);
int X_ECWithSM3_Verify(EVP_PKEY *pk, const unsigned char *digest, size_t digestlen,
                        const unsigned char *sig, size_t siglen, ENGINE *eng);
unsigned char *X_pk_encrypt(EVP_PKEY *pk, const unsigned char *in,
							size_t inlen, size_t *outlen, ENGINE *eng);
unsigned char *X_sk_decrypt(EVP_PKEY *sk, const unsigned char *in,
							size_t inlen, size_t *outlen, ENGINE *eng);