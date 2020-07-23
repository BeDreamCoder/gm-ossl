/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_ossl

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSM3(t *testing.T) {
	testdata := []byte("testing sm3 hash")
	got, err := SM3(testdata)
	assert.NoError(t, err)

	assert.Equal(t, "edffff59b9951e6b4b76af9846fcb1cc43455df09b944520843ec32a7a421c5a", hex.EncodeToString(got[:]))
}

func BenchmarkSM3(b *testing.B) {
	b.ReportAllocs()
	var length int64 = 1024 * 1024
	buf := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(length)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SM3(buf)
	}
}
