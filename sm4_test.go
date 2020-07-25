/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_ossl

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

var key = []byte("1234567890abcdef")

func TestSM4(t *testing.T) {
	s4 := new(SM4Cipher)
	sc, err := s4.NewSm4Cipher(key)
	assert.NoError(t, err)

	plaintextIn := []byte("testing sm4 cipher")

	padding := len(plaintextIn) % sc.BlockSize()
	nSize := sc.BlockSize() - padding
	inDataVLen := len(plaintextIn) + nSize

	ciphertext := make([]byte, inDataVLen)
	sc.Encrypt(ciphertext, plaintextIn)

	plaintextOut := make([]byte, len(ciphertext))
	sc.Decrypt(plaintextOut, ciphertext)

	actualPlaintext := bytes.TrimRight(plaintextOut, "\x00")

	assert.Equal(t, plaintextIn, actualPlaintext)
}

func BenchmarkSM4Crypt(b *testing.B) {
	b.ReportAllocs()
	s4 := new(SM4Cipher)
	sc, err := s4.NewSm4Cipher(key)
	if err != nil {
		b.Fatal(err)
	}

	length := 1024 * 1024
	buf := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		b.Fatal(err)
	}
	padding := length % sc.BlockSize()
	nSize := sc.BlockSize() - padding
	inDataVLen := length + nSize

	b.SetBytes(int64(length*2 + inDataVLen))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in := make([]byte, length)
		out := make([]byte, inDataVLen)
		sc.Encrypt(out, buf)
		sc.Decrypt(in, out)
	}
}
