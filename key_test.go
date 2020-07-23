/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_ossl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECKey(t *testing.T) {
	t.Parallel()

	key, err := GenerateECKey(SM2EC)
	assert.NoError(t, err)

	data := []byte("the quick brown fox jumps over the lazy dog")

	t.Run("sm2/sm3", func(t *testing.T) {
		t.Parallel()
		md, err := GetDigestByName("SM3")
		assert.NoError(t, err)

		sig, err := key.Sign(data, md)
		assert.NoError(t, err)

		err = key.Verify(data, sig, md)
		assert.NoError(t, err)
	})

	t.Run("sm2/sha1", func(t *testing.T) {
		t.Parallel()
		md, err := GetDigestByName("SHA1")
		assert.NoError(t, err)

		sig, err := key.Sign(data, md)
		assert.NoError(t, err)

		err = key.Verify(data, sig, md)
		assert.NoError(t, err)
	})

	t.Run("sm2/sha256", func(t *testing.T) {
		t.Parallel()
		md, err := GetDigestByName("SHA256")
		assert.NoError(t, err)

		sig, err := key.Sign(data, md)
		assert.NoError(t, err)

		err = key.Verify(data, sig, md)
		assert.NoError(t, err)
	})

	t.Run("sm2/sha512", func(t *testing.T) {
		t.Parallel()
		md, err := GetDigestByName("SHA512")
		assert.NoError(t, err)

		sig, err := key.Sign(data, md)
		assert.NoError(t, err)

		err = key.Verify(data, sig, md)
		assert.NoError(t, err)
	})
}
