/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_ossl

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptionCipher(t *testing.T) {
	var key = []byte("1234567890abcdef")
	iv := []byte("mean init vector")
	plaintext1 := "stay hungry"
	plaintext2 := "stay foolish"

	cipher, err := GetCipherByName("sm4-cbc")
	assert.NoError(t, err, "Could not get cipher")

	eCtx, err := cipher.NewEncryptionCipher(nil, key, iv)
	assert.NoError(t, err, "Could not create encryption context")

	cipherbuffer := new(bytes.Buffer)

	cipherbytes, err := eCtx.Update([]byte(plaintext1))
	assert.NoError(t, err, "Encrypt Update(plaintext1) failure")
	cipherbuffer.Write(cipherbytes)

	cipherbytes, err = eCtx.Update([]byte(plaintext2))
	assert.NoError(t, err, "Encrypt Update(plaintext2) failure")
	cipherbuffer.Write(cipherbytes)

	cipherbytes, err = eCtx.Final()
	assert.NoError(t, err, "Encrypt Final failure")
	cipherbuffer.Write(cipherbytes)

	dCtx, err := cipher.NewDecryptionCipher(nil, key, iv)
	assert.NoError(t, err, "Could not create decryption context")

	plainOut := new(bytes.Buffer)
	plainbytes, err := dCtx.Update(cipherbuffer.Bytes()[:cipher.BlockSize()-1])
	assert.NoError(t, err, "Decrypt Update(ciphertext part 1) failure")
	plainOut.Write(plainbytes)

	plainbytes, err = dCtx.Update(cipherbuffer.Bytes()[15:])
	assert.NoError(t, err, "Decrypt Update(ciphertext part 2) failure")
	plainOut.Write(plainbytes)

	plainbytes, err = dCtx.Final()
	assert.NoError(t, err, "Decrypt Final failure")
	plainOut.Write(plainbytes)

	assert.Equal(t, plainOut.String(), plaintext1+plaintext2)
}
