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
	sk, err := GenerateECKey(SM2)
	assert.NoError(t, err)

	pk := sk.PublicKey()

	sc := &SM2Cipher{}
	msg := []byte("testing sm2 cipher")

	sig, err := sc.Sign(sk, msg, nil)
	assert.NoError(t, err)

	err = sc.Verify(pk, msg, sig, nil)
	assert.NoError(t, err)
}

func TestSM2Crypt(t *testing.T) {
	sk, err := GenerateECKey(SM2)
	assert.NoError(t, err)

	pk := sk.PublicKey()

	sc := &SM2Cipher{}
	msg := []byte("testing sm2 crypt")

	ciphertext, err := sc.Encrypt(pk, msg)
	assert.NoError(t, err)

	plaintext, err := sc.Decrypt(sk, ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, msg, plaintext)
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
		err = sc.Verify(pk, buf, sig, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
