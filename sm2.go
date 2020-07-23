/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_ossl

type SM2Cipher struct{}

func (s *SM2Cipher) Sign(k PrivateKey, msg []byte, md MsgDigest) ([]byte, error) {
	if md == nil {
		var err error
		if md, err = GetDigestByName("SM3"); err != nil {
			return nil, err
		}
	}
	return k.Sign(msg, md)
}

func (s *SM2Cipher) Verify(k PrivateKey, msg, sig []byte, md MsgDigest) (bool, error) {
	var err error
	if md == nil {
		if md, err = GetDigestByName("SM3"); err != nil {
			return false, err
		}
	}
	if err = k.Verify(msg, sig, md); err != nil {
		return false, err
	}
	return true, nil
}

func (s *SM2Cipher) Encrypt() {

}

func (s *SM2Cipher) Decrypt() {

}
