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

func TestSm2(t *testing.T) {
	key, err := GenerateECKey(SM2EC)
	assert.NoError(t, err)

	sc := &SM2Cipher{}
	msg := []byte("testing sm2 cipher")

	sig, err := sc.Sign(key, msg, nil)
	assert.NoError(t, err)

	ok, err := sc.Verify(key, msg, sig, nil)
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
	key, err := GenerateECKey(SM2EC)
	if err != nil {
		b.Fatal(err)
	}
	sc := &SM2Cipher{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := sc.Sign(key, buf, nil)
		if err != nil {
			b.Fatal(err)
		}
		_, err = sc.Verify(key, buf, sig, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
