/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_ossl

// #include <openssl/evp.h>
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

type SM3Hash struct {
	ctx    *C.EVP_MD_CTX
	engine *Engine
}

func NewSM3Hash() (*SM3Hash, error) {
	hash := &SM3Hash{}
	hash.ctx = C.EVP_MD_CTX_new()
	if hash.ctx == nil {
		return nil, errors.New("openssl: sm3: unable to allocate ctx")
	}
	runtime.SetFinalizer(hash, func(hash *SM3Hash) { hash.Close() })
	if err := hash.Reset(); err != nil {
		return nil, err
	}
	return hash, nil
}

func (s *SM3Hash) Close() {
	if s.ctx != nil {
		C.EVP_MD_CTX_free(s.ctx)
		s.ctx = nil
	}
}

func (s *SM3Hash) Reset() error {
	if 1 != C.EVP_DigestInit_ex(s.ctx, C.EVP_sm3(), engineRef(s.engine)) {
		return errors.New("openssl: sm3: cannot init digest ctx")
	}
	return nil
}

func (s *SM3Hash) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if 1 != C.EVP_DigestUpdate(s.ctx, unsafe.Pointer(&p[0]),
		C.size_t(len(p))) {
		return 0, errors.New("openssl: sm3: cannot update digest")
	}
	return len(p), nil
}

func (s *SM3Hash) Sum() (result [32]byte, err error) {
	if 1 != C.EVP_DigestFinal_ex(s.ctx,
		(*C.uchar)(unsafe.Pointer(&result[0])), nil) {
		return result, errors.New("openssl: sm3: cannot finalize ctx")
	}
	return result, s.Reset()
}

func SM3(data []byte) (result [32]byte, err error) {
	hash, err := NewSM3Hash()
	if err != nil {
		return result, err
	}
	defer hash.Close()
	if _, err := hash.Write(data); err != nil {
		return result, err
	}
	return hash.Sum()
}
