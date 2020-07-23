/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_ossl

import (
	"bytes"

	"github.com/pkg/errors"
)

type SM4Cipher interface {
	Cipher
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
}

type sm4Cipher struct {
	Cipher
	key []byte
}

func NewSM4Cipher(cipherName string, key []byte) (SM4Cipher, error) {
	if cipherName == "" {
		cipherName = "sm4-cbc"
	}
	cipher, err := GetCipherByName(cipherName)
	if err != nil {
		return nil, errors.Errorf("Could not get cipher: %s", err.Error())
	}
	return &sm4Cipher{cipher, key}, nil
}

func (s *sm4Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	encCtx, err := s.NewEncryptionCipher(nil, s.key, nil)
	if err != nil {
		return nil, errors.Errorf("Could not create encryption context: %s", err.Error())
	}

	cipherbuffer := new(bytes.Buffer)
	cipherbytes, err := encCtx.Update(plaintext)
	if err != nil {
		return nil, errors.Errorf("Encrypt Update plaintext: %s failure: %s", string(plaintext), err.Error())
	}
	cipherbuffer.Write(cipherbytes)

	cipherbytes, err = encCtx.Final()
	if err != nil {
		return nil, errors.Errorf("Encrypt Final failure: %s", err.Error())
	}
	cipherbuffer.Write(cipherbytes)

	return cipherbuffer.Bytes(), nil
}

func (s *sm4Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	decCtx, err := s.NewDecryptionCipher(nil, s.key, nil)
	if err != nil {
		return nil, errors.Errorf("Could not create decryption context: %s", err.Error())
	}
	plainbuffer := new(bytes.Buffer)
	plainbytes, err := decCtx.Update(ciphertext)
	if err != nil {
		return nil, errors.Errorf("Decrypt Update ciphertext failure: %s", err.Error())
	}
	plainbuffer.Write(plainbytes)

	plainbytes, err = decCtx.Final()
	if err != nil {
		return nil, errors.Errorf("Decrypt Final failure: %s", err.Error())
	}
	plainbuffer.Write(plainbytes)

	return plainbuffer.Bytes(), nil
}
