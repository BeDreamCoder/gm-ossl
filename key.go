/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_ossl

// #include "shim.h"
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
	SM2 EllipticCurve = C.NID_sm2
	// P-256: NIST/SECG curve over a 256 bit prime field
	Secp256k1 EllipticCurve = C.NID_secp256k1
	// P-384: NIST/SECG curve over a 384 bit prime field
	Secp384r1 EllipticCurve = C.NID_secp384r1
	// P-521: NIST/SECG curve over a 521 bit prime field
	Secp521r1 EllipticCurve = C.NID_secp521r1
)

type MsgDigest *C.EVP_MD

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
	PublicKey() PublicKey
	Sign(data []byte, md MsgDigest) (signature []byte, err error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type PublicKey interface {
	KeyType() NID
	Verify(data, sig []byte, md MsgDigest) error
	Encrypt(plaintext []byte) ([]byte, error)
}

type privateKey struct {
	sk *C.EVP_PKEY
}

type publicKey struct {
	pk *C.EVP_PKEY
}

// openssl: test_EVP_SM2
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

	if curve == SM2 {
		if C.EVP_PKEY_set_alias_type(privKey, C.EVP_PKEY_SM2) != 1 {
			return nil, errors.New("failed generating EC private key")
		}
	}

	p := &privateKey{sk: privKey}
	runtime.SetFinalizer(p, func(p *privateKey) {
		C.EVP_PKEY_free(p.sk)
	})
	return p, nil
}

func (p *privateKey) KeyType() NID {
	return NID(C.EVP_PKEY_id(p.sk))
}

func (p *privateKey) PublicKey() PublicKey {
	pk := C.X_export_pk_from_sk(p.sk)
	pub := &publicKey{pk}
	runtime.SetFinalizer(pub, func(p *publicKey) {
		C.EVP_PKEY_free(p.pk)
	})
	return pub
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
		if 1 != C.EVP_DigestSignInit(ctx, nil, nil, nil, p.sk) {
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
			digest := SM3(data)
			if len(digest) == 0 {
				return nil, errors.New("message digest is null after sm3 hash")
			}

			var siglen C.size_t
			sig := C.X_ECWithSM3_Sign(p.sk, (*C.uchar)(unsafe.Pointer(&digest[0])),
				C.size_t(len(digest)), &siglen, nil)
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

			sig := make([]byte, C.EVP_PKEY_size(p.sk))
			var siglen C.uint
			if 1 != C.EVP_SignFinal(ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), &siglen, p.sk) {
				return nil, errors.New("failed to finalize signature")
			}
			return sig[:siglen], nil
		}
	}
}

func (p *privateKey) Decrypt(ciphertext []byte) ([]byte, error) {
	var outlen C.size_t
	out := C.X_sk_decrypt(p.sk, (*C.uchar)(&ciphertext[0]), C.size_t(len(ciphertext)), &outlen, nil)
	if out == nil {
		return nil, errors.Errorf("failed to decrypt msg [%s]", string(ciphertext))
	}
	defer C.free(unsafe.Pointer(out))

	return C.GoBytes(unsafe.Pointer(out), C.int(outlen)), nil
}

func (p *publicKey) KeyType() NID {
	return NID(C.EVP_PKEY_id(p.pk))
}

func (p *publicKey) Verify(data, sig []byte, md MsgDigest) error {
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
		if 1 != C.EVP_DigestVerifyInit(ctx, nil, nil, nil, p.pk) {
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
			digest := SM3(data)
			if len(digest) == 0 {
				return errors.New("message digest is null after sm3 hash")
			}

			if 1 != C.X_ECWithSM3_Verify(p.pk, (*C.uchar)(&digest[0]), C.size_t(len(digest)),
				(*C.uchar)(&sig[0]), C.size_t(len(sig)), nil) {
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

			if 1 != C.EVP_VerifyFinal(ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), C.uint(len(sig)), p.pk) {
				return errors.New("failed to finalize verify")
			}
			return nil
		}
	}
}

func (p *publicKey) Encrypt(plaintext []byte) ([]byte, error) {
	var outlen C.size_t
	out := C.X_pk_encrypt(p.pk, (*C.uchar)(&plaintext[0]), C.size_t(len(plaintext)), &outlen, nil)
	if out == nil {
		return nil, errors.Errorf("failed to encrypt msg [%s]", string(plaintext))
	}
	defer C.free(unsafe.Pointer(out))

	return C.GoBytes(unsafe.Pointer(out), C.int(outlen)), nil
}
