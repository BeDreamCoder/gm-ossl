/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_ossl

/*
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

int X_EVP_VerifyUpdate(EVP_MD_CTX *ctx, const void *d,
		unsigned int cnt) {
	return EVP_VerifyUpdate(ctx, d, cnt);
}

int X_EC_GROUP_get_curve_name(EVP_PKEY *sk) {
	return EC_GROUP_get_curve_name(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(sk)));
}

// EVP_SignFinal p_sign.c
unsigned char *X_ECWithSM3_Sign(EVP_PKEY *sk, const unsigned char *digest,
	size_t digestlen, size_t *siglen) {
	unsigned char *ret = NULL;
	unsigned char *sig = NULL;
    EVP_PKEY_CTX *pkctx = NULL;

	pkctx = EVP_PKEY_CTX_new(sk, NULL);
	if (pkctx == NULL)
		goto err;

	if (EVP_PKEY_sign_init(pkctx) <= 0)
		goto err;

	//if (EVP_PKEY_id(sk) != EVP_PKEY_EC || X_EC_GROUP_get_curve_name(sk) != NID_sm2) {
	//	goto err;
	//}
    //if (EVP_PKEY_CTX_set_signature_md(pkctx, EVP_sm3()) <= 0)
    //   goto err;

	if (!(sig = OPENSSL_zalloc(EVP_PKEY_size(sk))))
		goto err;

	*siglen = EVP_PKEY_size(sk);
	if (EVP_PKEY_sign(pkctx, sig, siglen, digest, digestlen) <= 0) {
		goto err;
	}
	ret = sig;
	sig = NULL;
err:
	EVP_PKEY_CTX_free(pkctx);
	OPENSSL_free(sig);
	return ret;
}


int X_ECWithSM3_Verify(EVP_PKEY *pk, const unsigned char *digest,
	size_t digestlen, const unsigned char *sig, size_t siglen) {
	int ret = -1;
	EVP_PKEY_CTX *pkctx = NULL;

	pkctx = EVP_PKEY_CTX_new(pk, NULL);
    if (pkctx == NULL)
        goto err;

    if (EVP_PKEY_verify_init(pkctx) <= 0)
        goto err;

	ret = EVP_PKEY_verify(pkctx, sig, siglen, digest, digestlen);
err:
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

*/
import "C"

import (
	"runtime"
	"unsafe"

	"github.com/pkg/errors"
)

type NID int

const (
	NID_ED25519 NID = 1087
	NID_sm2     NID = 1172
	NID_sm3     NID = 1143
)

// EllipticCurve repesents the ASN.1 OID of an elliptic curve.
// see https://www.openssl.org/docs/apps/ecparam.html for a list of implemented curves.
type EllipticCurve int

const (
	SM2EC EllipticCurve = C.NID_sm2
	// P-256: NIST/SECG curve over a 256 bit prime field
	Secp256k1 EllipticCurve = C.NID_secp256k1
	// P-384: NIST/SECG curve over a 384 bit prime field
	Secp384r1 EllipticCurve = C.NID_secp384r1
	// P-521: NIST/SECG curve over a 521 bit prime field
	Secp521r1 EllipticCurve = C.NID_secp521r1
)

type MsgDigest *C.EVP_MD

//var (
//	SM3_MD    MsgDigest = C.EVP_sm3()
//	SHA1_MD   MsgDigest = C.EVP_sha1()
//	SHA256_MD MsgDigest = C.EVP_sha256()
//	SHA512_MD MsgDigest = C.EVP_sha512()
//)

func GetDigestByName(name string) (MsgDigest, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	p := C.EVP_get_digestbyname(cname)
	if p == nil {
		return nil, errors.Errorf("digest [%d] not found", cname)
	}
	// we can consider ciphers to use static mem; don't need to free
	return p, nil
}

type PrivateKey interface {
	KeyType() NID
	Sign(data []byte, md MsgDigest) (signature []byte, err error)
	Verify(data, sig []byte, md MsgDigest) error
}

type privateKey struct {
	key *C.EVP_PKEY
}

// GenerateECKey generates a new elliptic curve private key on the speicified curve.
func GenerateECKey(curve EllipticCurve) (PrivateKey, error) {
	// Create context for parameter generation
	paramCtx := C.EVP_PKEY_CTX_new_id(C.EVP_PKEY_EC, nil)
	if paramCtx == nil {
		return nil, errors.New("failed creating EC parameter generation context")
	}
	defer C.EVP_PKEY_CTX_free(paramCtx)

	// Intialize the parameter generation
	if int(C.EVP_PKEY_paramgen_init(paramCtx)) != 1 {
		return nil, errors.New("failed initializing EC parameter generation context")
	}

	// Set curve in EC parameter generation context
	if int(C.X_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramCtx, C.int(curve))) != 1 {
		return nil, errors.New("failed setting curve in EC parameter generation context")
	}

	// Create parameter object
	var params *C.EVP_PKEY
	if int(C.EVP_PKEY_paramgen(paramCtx, &params)) != 1 {
		return nil, errors.New("failed creating EC key generation parameters")
	}
	defer C.EVP_PKEY_free(params)

	// Create context for the key generation
	keyCtx := C.EVP_PKEY_CTX_new(params, nil)
	if keyCtx == nil {
		return nil, errors.New("failed creating EC key generation context")
	}
	defer C.EVP_PKEY_CTX_free(keyCtx)

	// Generate the key
	var privKey *C.EVP_PKEY
	if int(C.EVP_PKEY_keygen_init(keyCtx)) != 1 {
		return nil, errors.New("failed initializing EC key generation context")
	}
	if int(C.EVP_PKEY_keygen(keyCtx, &privKey)) != 1 {
		return nil, errors.New("failed generating EC private key")
	}

	p := &privateKey{key: privKey}
	runtime.SetFinalizer(p, func(p *privateKey) {
		C.EVP_PKEY_free(p.key)
	})
	return p, nil
}

func (p *privateKey) KeyType() NID {
	return NID(C.EVP_PKEY_id(p.key))
}

func (p *privateKey) Sign(data []byte, md MsgDigest) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("0-length data")
	}

	ctx := C.EVP_MD_CTX_new()
	defer C.EVP_MD_CTX_free(ctx)

	if p.KeyType() == NID_ED25519 {
		// do ED specific one-shot sign
		if md != nil {
			return nil, errors.New("message digest must null")
		}
		if 1 != C.EVP_DigestSignInit(ctx, nil, nil, nil, p.key) {
			return nil, errors.New("failed to init signature")
		}
		// evp signatures are 64 bytes
		sig := make([]byte, 64, 64)
		var siglen C.size_t = 64
		if 1 != C.EVP_DigestSign(ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), &siglen,
			(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) {
			return nil, errors.New("failed to do one-shot signature")
		}
		return sig[:siglen], nil
	} else {
		if md == nil {
			return nil, errors.New("message digest must not null")
		}
		//if NID(C.X_EC_GROUP_get_curve_name(p.key)) == NID_sm2 {
		if NID(C.EVP_MD_type(md)) == NID_sm3 {
			digest, err := SM3(data)
			if err != nil {
				return nil, err
			}
			var siglen C.size_t
			sig := C.X_ECWithSM3_Sign(p.key, (*C.uchar)(unsafe.Pointer(&digest[0])),
				C.size_t(len(digest)), &siglen)
			if sig == nil {
				C.ERR_print_errors_fp(C.stderr)
				return nil, errors.New("failed to ECWithSM3 signature")
			}
			defer C.free(unsafe.Pointer(sig))
			return C.GoBytes(unsafe.Pointer(sig), C.int(siglen)), nil
		} else {
			if 1 != C.X_EVP_SignInit(ctx, md) {
				return nil, errors.New("failed to init signature")
			}
			if 1 != C.X_EVP_SignUpdate(ctx, unsafe.Pointer(&data[0]), C.uint(len(data))) {
				return nil, errors.New("failed to update signature")
			}

			sig := make([]byte, C.EVP_PKEY_size(p.key))
			var siglen C.uint
			if 1 != C.EVP_SignFinal(ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), &siglen, p.key) {
				C.ERR_print_errors_fp(C.stderr)
				return nil, errors.New("failed to finalize signature")
			}
			return sig[:siglen], nil
		}
	}
}

func (p *privateKey) Verify(data, sig []byte, md MsgDigest) error {
	if len(data) == 0 || len(sig) == 0 {
		return errors.New("0-length data or sig")
	}

	ctx := C.EVP_MD_CTX_new()
	defer C.EVP_MD_CTX_free(ctx)

	if p.KeyType() == NID_ED25519 {
		// do ED specific one-shot sign
		if md != nil {
			return errors.New("message digest must null")
		}
		if 1 != C.EVP_DigestVerifyInit(ctx, nil, nil, nil, p.key) {
			return errors.New("failed to init verify")
		}

		if 1 != C.EVP_DigestVerify(ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
			(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) {
			return errors.New("failed to do one-shot verify")
		}
		return nil
	} else {
		if md == nil {
			return errors.New("message digest must not null")
		}
		if NID(C.EVP_MD_type(md)) == NID_sm3 {
			digest, err := SM3(data)
			if err != nil {
				return err
			}

			if 1 != C.X_ECWithSM3_Verify(p.key, (*C.uchar)(&digest[0]), C.size_t(len(digest)),
				(*C.uchar)(&sig[0]), C.size_t(len(sig))) {
				return errors.New("failed to verify ECWithSM3 signature")
			}
			return nil
		} else {
			if 1 != C.X_EVP_VerifyInit(ctx, md) {
				return errors.New("failed to init verify")
			}
			if 1 != C.X_EVP_VerifyUpdate(ctx, unsafe.Pointer(&data[0]), C.uint(len(data))) {
				return errors.New("failed to update verify")
			}

			if 1 != C.EVP_VerifyFinal(ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), C.uint(len(sig)), p.key) {
				C.ERR_print_errors_fp(C.stderr)
				return errors.New("failed to finalize verify")
			}
			return nil
		}
	}
}
