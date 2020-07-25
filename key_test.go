/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_ossl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var testdata = []byte("the quick brown fox jumps over the lazy dog")

func TestECKey(t *testing.T) {
	t.Parallel()

	sk, err := GenerateECKey(SM2)
	assert.NoError(t, err)

	pk := sk.PublicKey()

	t.Run("sm2/sm3", func(t *testing.T) {
		t.Parallel()
		md, err := GetDigestByName("SM3")
		assert.NoError(t, err)

		sig, err := sk.Sign(testdata, md)
		assert.NoError(t, err)

		err = pk.Verify(testdata, sig, md)
		assert.NoError(t, err)
	})

	t.Run("sm2/sha1", func(t *testing.T) {
		t.Parallel()
		md, err := GetDigestByName("SHA1")
		assert.NoError(t, err)

		sig, err := sk.Sign(testdata, md)
		assert.NoError(t, err)

		err = pk.Verify(testdata, sig, md)
		assert.NoError(t, err)
	})

	t.Run("sm2/sha256", func(t *testing.T) {
		t.Parallel()
		md, err := GetDigestByName("SHA256")
		assert.NoError(t, err)

		sig, err := sk.Sign(testdata, md)
		assert.NoError(t, err)

		err = pk.Verify(testdata, sig, md)
		assert.NoError(t, err)
	})

	t.Run("sm2/sha512", func(t *testing.T) {
		t.Parallel()
		md, err := GetDigestByName("SHA512")
		assert.NoError(t, err)

		sig, err := sk.Sign(testdata, md)
		assert.NoError(t, err)

		err = pk.Verify(testdata, sig, md)
		assert.NoError(t, err)
	})
}

func TestExportPubKey(t *testing.T) {
	sk, err := GenerateECKey(SM2)
	assert.NoError(t, err)

	pk := sk.PublicKey()

	md, err := GetDigestByName("SM3")
	assert.NoError(t, err)

	sig, err := sk.Sign(testdata, md)
	assert.NoError(t, err)

	err = pk.Verify(testdata, sig, md)
	assert.NoError(t, err)
}

func TestECKeyCrypt(t *testing.T) {
	sk, err := GenerateECKey(SM2)
	assert.NoError(t, err)

	pk := sk.PublicKey()

	ciphertext, err := pk.Encrypt(testdata)
	assert.NoError(t, err)

	plaintext, err := sk.Decrypt(ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, testdata, plaintext)
}
