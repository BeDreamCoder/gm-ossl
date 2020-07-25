/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_ossl

import (
	ci "crypto/cipher"
	"fmt"

	"github.com/pkg/errors"
)

type SM4Cipher struct{}

type sm4Cipher struct {
	Cipher
	key []byte
}

func (sc *SM4Cipher) NewSm4Cipher(key []byte) (ci.Block, error) {
	cipher, err := GetCipherByName("sm4-cbc")
	if err != nil {
		return nil, errors.Errorf("Could not get cipher: %s", err.Error())
	}
	return &sm4Cipher{cipher, key}, nil
}

func (s *sm4Cipher) BlockSize() int {
	return s.Cipher.BlockSize()
}

func (s *sm4Cipher) Encrypt(ciphertext, plaintext []byte) {
	encCtx, err := s.NewEncryptionCipher(nil, s.key, nil)
	if err != nil {
		panic(fmt.Sprintf("Could not create encryption context: %s", err.Error()))
	}

	cipherbytes, err := encCtx.Update(plaintext)
	if err != nil {
		panic(fmt.Sprintf("Encrypt Update plaintext: %s failure: %s", string(plaintext), err.Error()))
	}
	dataSize := len(cipherbytes)
	copy(ciphertext[:dataSize], cipherbytes)

	cipherbytes, err = encCtx.Final()
	if err != nil {
		panic(fmt.Sprintf("Encrypt Final failure: %s", err.Error()))
	}
	copy(ciphertext[dataSize:], cipherbytes)
}

func (s *sm4Cipher) Decrypt(plaintext, ciphertext []byte) {
	decCtx, err := s.NewDecryptionCipher(nil, s.key, nil)
	if err != nil {
		panic(fmt.Sprintf("Could not create decryption context: %s", err.Error()))
	}

	plainbytes, err := decCtx.Update(ciphertext)
	if err != nil {
		panic(fmt.Sprintf("Decrypt Update ciphertext failure: %s", err.Error()))
	}
	dataSize := len(plainbytes)
	copy(plaintext[:dataSize], plainbytes)

	plainbytes, err = decCtx.Final()
	if err != nil {
		panic(fmt.Sprintf("Decrypt Final failure: %s", err.Error()))
	}
	copy(plaintext[dataSize:], plainbytes)
}
