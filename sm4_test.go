/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_ossl

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

var key = []byte("1234567890abcdef")

func TestSM4(t *testing.T) {
	sc, err := NewSM4Cipher("", key)
	assert.NoError(t, err)

	plaintextIn := []byte("testing sm4 cipher")
	ciphertext, err := sc.Encrypt(plaintextIn)
	assert.NoError(t, err)

	plaintextOut, err := sc.Decrypt(ciphertext)
	assert.NoError(t, err)

	assert.Equal(t, plaintextIn, plaintextOut)
}

func BenchmarkSM4Encrypt(b *testing.B) {
	b.ReportAllocs()
	sc, _ := NewSM4Cipher("", key)

	var length int64 = 1024 * 1024
	buf := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(length)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sc.Encrypt(buf)
	}
}

func BenchmarkSM4Decrypt(b *testing.B) {
	b.ReportAllocs()
	sc, _ := NewSM4Cipher("", key)

	var length int64 = 1024 * 1024
	buf := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(length)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sc.Decrypt(buf)
	}
}
