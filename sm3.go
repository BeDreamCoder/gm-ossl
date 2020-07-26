/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_ossl

// #include <openssl/evp.h>
import "C"

import (
	"errors"
	"hash"
	"runtime"
	"unsafe"
)

type SM3Hash struct{}

type sm3Hash struct {
	ctx    *C.EVP_MD_CTX
	engine *Engine
}

func SM3(data []byte) []byte {
	sh := new(SM3Hash)
	hasher := sh.NewSm3()
	if _, err := hasher.Write(data); err != nil {
		return nil
	}
	return hasher.Sum(nil)
}

func (h *SM3Hash) NewSm3() hash.Hash {
	sm3 := new(sm3Hash)
	sm3.ctx = C.EVP_MD_CTX_new()
	if sm3.ctx == nil {
		panic("openssl: sm3: unable to allocate ctx")
	}
	runtime.SetFinalizer(sm3, func(hash *sm3Hash) { hash.Close() })
	sm3.Reset()
	return sm3
}

func (s *sm3Hash) Close() {
	if s.ctx != nil {
		C.EVP_MD_CTX_free(s.ctx)
		s.ctx = nil
	}
}

func (s *sm3Hash) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if 1 != C.EVP_DigestUpdate(s.ctx, unsafe.Pointer(&p[0]),
		C.size_t(len(p))) {
		return 0, errors.New("openssl: sm3: cannot update digest")
	}
	return len(p), nil
}

func (s *sm3Hash) Sum(in []byte) []byte {
	if len(in) > 0 {
		if 1 != C.EVP_DigestUpdate(s.ctx, unsafe.Pointer(&in[0]), C.size_t(len(in))) {
			return nil
		}
	}

	out := make([]byte, 32)
	var outlen C.uint
	if 1 != C.EVP_DigestFinal(s.ctx, (*C.uchar)(unsafe.Pointer(&out[0])), &outlen) {
		return nil
	}
	return out[:outlen]
}

func (s *sm3Hash) Reset() {
	C.EVP_DigestInit_ex(s.ctx, C.EVP_sm3(), engineRef(s.engine))
}

func (s *sm3Hash) Size() int {
	md := C.EVP_MD_CTX_md(s.ctx)
	if md == nil {
		return 0
	}
	return int(C.EVP_MD_size(md))
}

func (s *sm3Hash) BlockSize() int {
	md := C.EVP_MD_CTX_md(s.ctx)
	if md == nil {
		return 0
	}
	return int(C.EVP_MD_block_size(md))
}
