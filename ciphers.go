/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_ossl

// #include <openssl/evp.h>
import "C"

import (
	"runtime"
	"unsafe"

	"github.com/pkg/errors"
)

type Cipher interface {
	BlockSize() int
	KeySize() int
	IVSize() int
	NewEncryptionCipher(e *Engine, key, iv []byte) (CipherCtx, error)
	NewDecryptionCipher(e *Engine, key, iv []byte) (CipherCtx, error)
}

type CipherCtx interface {
	Update([]byte) ([]byte, error)
	Final() ([]byte, error)
}

type cipher struct {
	ptr *C.EVP_CIPHER
}

func GetCipherByName(name string) (Cipher, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	p := C.EVP_get_cipherbyname(cname)
	if p == nil {
		return nil, errors.Errorf("cipher %s not found", name)
	}
	// we can consider ciphers to use static mem; don't need to free
	return &cipher{ptr: p}, nil
}

func (c *cipher) BlockSize() int {
	return int(C.EVP_CIPHER_block_size(c.ptr))
}

func (c *cipher) KeySize() int {
	return int(C.EVP_CIPHER_key_length(c.ptr))
}

func (c *cipher) IVSize() int {
	return int(C.EVP_CIPHER_iv_length(c.ptr))
}

func (c *cipher) NewEncryptionCipher(e *Engine, key, iv []byte) (CipherCtx, error) {
	ctx, err := newCipherCtx()
	if err != nil {
		return nil, err
	}
	var eptr *C.ENGINE
	if e != nil {
		eptr = engineRef(e)
	}
	if 1 != C.EVP_EncryptInit_ex(ctx.ctx, c.ptr, eptr, nil, nil) {
		return nil, errors.New("failed to initialize cipher context")
	}
	err = ctx.applyKeyAndIV(key, iv)
	if err != nil {
		return nil, err
	}
	return &encryptionCipherCtx{cipherCtx: ctx}, nil
}

func (c *cipher) NewDecryptionCipher(e *Engine, key, iv []byte) (CipherCtx, error) {
	if c == nil {
		return nil, errors.New("null cipher not allowed")
	}
	ctx, err := newCipherCtx()
	if err != nil {
		return nil, err
	}
	var eptr *C.ENGINE
	if e != nil {
		eptr = engineRef(e)
	}
	if 1 != C.EVP_DecryptInit_ex(ctx.ctx, c.ptr, eptr, nil, nil) {
		return nil, errors.New("failed to initialize cipher context")
	}
	err = ctx.applyKeyAndIV(key, iv)
	if err != nil {
		return nil, err
	}
	return &decryptionCipherCtx{cipherCtx: ctx}, nil
}

type cipherCtx struct {
	ctx *C.EVP_CIPHER_CTX
}

func newCipherCtx() (*cipherCtx, error) {
	cctx := C.EVP_CIPHER_CTX_new()
	if cctx == nil {
		return nil, errors.New("failed to allocate cipher context")
	}
	ctx := &cipherCtx{cctx}
	runtime.SetFinalizer(ctx, func(ctx *cipherCtx) {
		C.EVP_CIPHER_CTX_free(ctx.ctx)
	})
	return ctx, nil
}

func (ctx *cipherCtx) applyKeyAndIV(key, iv []byte) error {
	var kptr, iptr *C.uchar
	if key != nil {
		if len(key) != ctx.KeySize() {
			return errors.Errorf("bad key size (%d bytes instead of %d)", len(key), ctx.KeySize())
		}
		kptr = (*C.uchar)(&key[0])
	}
	if iv != nil {
		if len(iv) != ctx.IVSize() {
			return errors.Errorf("bad IV size (%d bytes instead of %d)",
				len(iv), ctx.IVSize())
		}
		iptr = (*C.uchar)(&iv[0])
	}
	if kptr != nil || iptr != nil {
		var res C.int
		if C.EVP_CIPHER_CTX_encrypting(ctx.ctx) != 0 {
			res = C.EVP_EncryptInit_ex(ctx.ctx, nil, nil, kptr, iptr)
		} else {
			res = C.EVP_DecryptInit_ex(ctx.ctx, nil, nil, kptr, iptr)
		}
		if 1 != res {
			return errors.New("failed to apply key/IV")
		}
	}
	return nil
}

func (ctx *cipherCtx) BlockSize() int {
	return int(C.EVP_CIPHER_CTX_block_size(ctx.ctx))
}

func (ctx *cipherCtx) KeySize() int {
	return int(C.EVP_CIPHER_CTX_key_length(ctx.ctx))
}

func (ctx *cipherCtx) IVSize() int {
	return int(C.EVP_CIPHER_CTX_iv_length(ctx.ctx))
}

type encryptionCipherCtx struct {
	*cipherCtx
}

// pass in plaintext, get back ciphertext. can be called
// multiple times as needed
func (ctx *encryptionCipherCtx) Update(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}
	outbuf := make([]byte, len(input)+ctx.BlockSize())
	outlen := C.int(len(outbuf))
	res := C.EVP_EncryptUpdate(ctx.ctx, (*C.uchar)(&outbuf[0]), &outlen,
		(*C.uchar)(&input[0]), C.int(len(input)))
	if res != 1 {
		return nil, errors.Errorf("failed to encrypt [result %d]", res)
	}
	return outbuf[:outlen], nil
}

// call after all plaintext has been passed in; may return
// additional ciphertext if needed to finish off a block
// or extra padding information
func (ctx *encryptionCipherCtx) Final() ([]byte, error) {
	outbuf := make([]byte, ctx.BlockSize())
	var outlen C.int
	if 1 != C.EVP_EncryptFinal_ex(ctx.ctx, (*C.uchar)(&outbuf[0]), &outlen) {
		return nil, errors.New("encryption failed")
	}
	return outbuf[:outlen], nil
}

type decryptionCipherCtx struct {
	*cipherCtx
}

// pass in ciphertext, get back plaintext. can be called
// multiple times as needed
func (ctx *decryptionCipherCtx) Update(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}
	outbuf := make([]byte, len(input)+ctx.BlockSize())
	outlen := C.int(len(outbuf))
	res := C.EVP_DecryptUpdate(ctx.ctx, (*C.uchar)(&outbuf[0]), &outlen,
		(*C.uchar)(&input[0]), C.int(len(input)))
	if res != 1 {
		return nil, errors.Errorf("failed to decrypt [result %d]", res)
	}
	return outbuf[:outlen], nil
}

// call after all ciphertext has been passed in; may return
// additional plaintext if needed to finish off a block
func (ctx *decryptionCipherCtx) Final() ([]byte, error) {
	outbuf := make([]byte, ctx.BlockSize())
	var outlen C.int
	if 1 != C.EVP_DecryptFinal_ex(ctx.ctx, (*C.uchar)(&outbuf[0]), &outlen) {
		// this may mean the tag failed to verify- all previous plaintext
		// returned must be considered faked and invalid
		return nil, errors.New("decryption failed")
	}
	return outbuf[:outlen], nil
}
