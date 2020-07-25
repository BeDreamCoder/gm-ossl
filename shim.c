#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>

int X_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid) {
	return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
}

int X_EVP_SignInit(EVP_MD_CTX *ctx, const EVP_MD *type) {
	return EVP_SignInit(ctx, type);
}

int X_EVP_SignUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt) {
	return EVP_SignUpdate(ctx, d, cnt);
}

int X_EVP_VerifyInit(EVP_MD_CTX *ctx, const EVP_MD *type) {
	return EVP_VerifyInit(ctx, type);
}

int X_EVP_VerifyUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt) {
	return EVP_VerifyUpdate(ctx, d, cnt);
}

int X_EC_GROUP_get_curve_name(EVP_PKEY *sk) {
	return EC_GROUP_get_curve_name(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(sk)));
}

EVP_PKEY *X_export_pk_from_sk(EVP_PKEY *sk) {
	EVP_PKEY *pk = NULL;
  	EC_KEY *pkec = NULL;

	int type = EVP_PKEY_id(sk);
	if (EVP_PKEY_EC != type) {
		if (EVP_PKEY_set_alias_type(sk, EVP_PKEY_EC) != 1)
			return NULL;
	}

	pk = EVP_PKEY_new();
	if (pk == NULL)
		return NULL;

	pkec = EC_KEY_new();
	if (pkec == NULL)
		goto err;

	EC_KEY *ec = EVP_PKEY_get0_EC_KEY(sk);
	if (ec == NULL)
		goto err;

    if (EC_KEY_set_group(pkec, EC_KEY_get0_group(ec)) == 0)
		goto err;

	if (!EC_KEY_set_public_key(pkec, EC_KEY_get0_public_key(ec)))
		goto err;

	EVP_PKEY_set1_EC_KEY(pk, pkec);

	if (EVP_PKEY_EC != type) {
		EVP_PKEY_set_alias_type(sk, type);
		EVP_PKEY_set_alias_type(pk, type);
	}

	return pk;

err:
   	EVP_PKEY_free(pk);
	EC_KEY_free(pkec);
	return NULL;
}

// 传入的数据是已经hash过后的，该方法只对数据进行签名
unsigned char *X_ECWithSM3_Sign(EVP_PKEY *sk, const unsigned char *digest,
								size_t digestlen, size_t *siglen, ENGINE *eng)
{
	unsigned char *sig = NULL;
    EVP_PKEY_CTX *ctx = NULL;

	ctx = EVP_PKEY_CTX_new(sk, eng);
	if (ctx == NULL)
		return NULL;

	//int r = EVP_PKEY_check(ctx);
	//if (1 != r)
	//	goto err;

	if (EVP_PKEY_sign_init(ctx) <= 0)
		goto err;

	sig = OPENSSL_zalloc(EVP_PKEY_size(sk));
	if (sig == NULL)
		goto err;

	*siglen = EVP_PKEY_size(sk);
	if (EVP_PKEY_sign(ctx, sig, siglen, digest, digestlen) <= 0)
		goto err;

err:
	EVP_PKEY_CTX_free(ctx);
	//OPENSSL_free(sig);
	return sig;
}

int X_ECWithSM3_Verify(EVP_PKEY *pk, const unsigned char *digest, size_t digestlen,
						const unsigned char *sig, size_t siglen, ENGINE *eng)
{
	int ret = -1;
	EVP_PKEY_CTX *ctx = NULL;

	ctx = EVP_PKEY_CTX_new(pk, eng);
    if (ctx == NULL)
        return ret;

	//int r = EVP_PKEY_public_check(ctx);
	//if (1 != r)
	//	goto err;

    if (EVP_PKEY_verify_init(ctx) <= 0)
        goto err;

	ret = EVP_PKEY_verify(ctx, sig, siglen, digest, digestlen);
err:
	EVP_PKEY_CTX_free(ctx);
	return ret;
}

unsigned char *X_pk_encrypt(EVP_PKEY *pk, const unsigned char *in,
							size_t inlen, size_t *outlen, ENGINE *eng)
{
	EVP_PKEY_CTX *ctx = NULL;
	unsigned char *out = NULL;

	ctx = EVP_PKEY_CTX_new(pk, eng);
	if (ctx == NULL)
		return NULL;

	if (EVP_PKEY_encrypt_init(ctx) <= 0)
		goto err;

	if (EVP_PKEY_encrypt(ctx, NULL, outlen, in, inlen) <= 0)
		goto err;

	out = OPENSSL_zalloc(*outlen);
	if (out == NULL)
		goto err;

	if (EVP_PKEY_encrypt(ctx, out, outlen, in, inlen) <= 0)
		goto err;

err:
	EVP_PKEY_CTX_free(ctx);
	return out;
}

unsigned char *X_sk_decrypt(EVP_PKEY *sk, const unsigned char *in,
							size_t inlen, size_t *outlen, ENGINE *eng)
{
	EVP_PKEY_CTX *ctx = NULL;
	unsigned char *out = NULL;

	ctx = EVP_PKEY_CTX_new(sk, eng);
	if (ctx == NULL)
		return NULL;

	if (EVP_PKEY_decrypt_init(ctx) <= 0)
		goto err;

	if (EVP_PKEY_decrypt(ctx, NULL, outlen, in, inlen) <= 0)
		goto err;

	out = OPENSSL_zalloc(*outlen);
	if (out == NULL)
		goto err;

	if (EVP_PKEY_decrypt(ctx, out, outlen, in, inlen) <= 0)
		goto err;

err:
	EVP_PKEY_CTX_free(ctx);
	return out;
}
