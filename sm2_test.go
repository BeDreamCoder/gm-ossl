/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_ossl

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
)

func TestSm2(t *testing.T) {
	sk, err := GenerateECKey(SM2)
	assert.NoError(t, err)

	pk := sk.PublicKey()

	sc := &SM2Cipher{}
	msg := []byte("testing sm2 cipher")

	sig, err := sc.Sign(sk, msg, nil)
	assert.NoError(t, err)

	ok, err := sc.Verify(pk, msg, sig, nil)
	assert.NoError(t, err)
	assert.Equal(t, true, ok)
}

func BenchmarkSM2Sign(b *testing.B) {
	b.ReportAllocs()
	var length int64 = 1024 * 1024
	buf := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(length)
	sk, err := GenerateECKey(SM2)
	if err != nil {
		b.Fatal(err)
	}
	pk := sk.PublicKey()
	sc := &SM2Cipher{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := sc.Sign(sk, buf, nil)
		if err != nil {
			b.Fatal(err)
		}
		_, err = sc.Verify(pk, buf, sig, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
