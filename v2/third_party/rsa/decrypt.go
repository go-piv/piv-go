// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"math/big"
)

// Decrypt decodes the result of a raw RSA private-key operation using the
// crypto/rsa Decrypter options. It validates public inputs before rawDecrypt,
// which may require a PIN or touch. The callback must return a modulus-sized
// encoded message, including any leading zero byte.
func Decrypt(random io.Reader, pub *rsa.PublicKey, ciphertext []byte, opts crypto.DecrypterOpts, rawDecrypt func([]byte) ([]byte, error)) ([]byte, error) {
	if pub == nil || pub.N == nil || pub.N.Sign() <= 0 || pub.E < 2 || pub.E > 1<<31-1 {
		return nil, rsa.ErrDecryption
	}
	if rawDecrypt == nil {
		return nil, errors.New("crypto/rsa: missing raw RSA operation")
	}
	k := pub.Size()
	if len(ciphertext) != k || new(big.Int).SetBytes(ciphertext).Cmp(pub.N) >= 0 {
		return nil, rsa.ErrDecryption
	}

	var oaep *rsa.OAEPOptions
	var sessionKeyLen int
	switch o := opts.(type) {
	case nil:
	case *rsa.OAEPOptions:
		if o == nil || !o.Hash.Available() {
			return nil, errors.New("crypto/rsa: invalid OAEP hash")
		}
		mgfHash := o.MGFHash
		if mgfHash == 0 {
			mgfHash = o.Hash
		}
		if !mgfHash.Available() {
			return nil, errors.New("crypto/rsa: invalid OAEP MGF hash")
		}
		if k < 2*o.Hash.Size()+2 {
			return nil, rsa.ErrDecryption
		}
		oaep = &rsa.OAEPOptions{Hash: o.Hash, MGFHash: mgfHash, Label: o.Label}
	case *rsa.PKCS1v15DecryptOptions:
		if o == nil || o.SessionKeyLen < 0 {
			return nil, errors.New("crypto/rsa: invalid PKCS1v15 options")
		}
		sessionKeyLen = o.SessionKeyLen
	default:
		return nil, errors.New("crypto/rsa: invalid options for Decrypt")
	}
	if oaep == nil && (k < 11 || sessionKeyLen > k-11) {
		return nil, rsa.ErrDecryption
	}

	var sessionKey []byte
	if sessionKeyLen > 0 {
		if random == nil {
			return nil, errors.New("crypto/rsa: session key requires randomness")
		}
		sessionKey = make([]byte, sessionKeyLen)
		if _, err := io.ReadFull(random, sessionKey); err != nil {
			return nil, err
		}
	}
	em, err := rawDecrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	if len(em) != k {
		return nil, rsa.ErrDecryption
	}
	if oaep != nil {
		return decodeOAEP(oaep.Hash.New(), oaep.MGFHash.New(), em, oaep.Label)
	}
	valid, index := decodePKCS1v15(em)
	if sessionKeyLen > 0 {
		// Adapted from crypto/rsa.DecryptPKCS1v15SessionKey. A malformed
		// block or wrong message length leaves the random key unchanged.
		valid &= subtle.ConstantTimeEq(int32(len(em)-index), int32(len(sessionKey)))
		subtle.ConstantTimeCopy(valid, sessionKey, em[len(em)-len(sessionKey):])
		return sessionKey, nil
	}
	if valid == 0 {
		return nil, rsa.ErrDecryption
	}
	return em[index:], nil
}

// decodeOAEP is the software decoding portion of crypto/rsa.decryptOAEP from
// Go 1.20.14, with the private-key operation performed by the caller.
// The caller validates the encoded message length before invoking this function.
func decodeOAEP(hash, mgfHash hash.Hash, em, label []byte) ([]byte, error) {
	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)

	seed := em[1 : hash.Size()+1]
	db := em[hash.Size()+1:]

	mgf1XOR(seed, mgfHash, db)
	mgf1XOR(db, mgfHash, seed)

	lHash2 := db[0:hash.Size()]

	// We have to validate the plaintext in constant time in order to avoid
	// attacks like: J. Manger. A Chosen Ciphertext Attack on RSA Optimal
	// Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1
	// v2.0. In J. Kilian, editor, Advances in Cryptology.
	lHash2Good := subtle.ConstantTimeCompare(lHash, lHash2)

	// The remainder of the plaintext must be zero or more 0x00, followed
	// by 0x01, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the 0x01
	//   index: the offset of the first 0x01 byte
	//   invalid: 1 iff we saw a non-zero byte before the 0x01.
	var lookingForIndex, index, invalid int
	lookingForIndex = 1
	rest := db[hash.Size():]

	for i := 0; i < len(rest); i++ {
		equals0 := subtle.ConstantTimeByteEq(rest[i], 0)
		equals1 := subtle.ConstantTimeByteEq(rest[i], 1)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals1, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals1, 0, lookingForIndex)
		invalid = subtle.ConstantTimeSelect(lookingForIndex&^equals0, 1, invalid)
	}

	if firstByteIsZero&lHash2Good&^invalid&^lookingForIndex != 1 {
		return nil, rsa.ErrDecryption
	}

	return rest[index+1:], nil
}

// decodePKCS1v15 is the software decoding portion of crypto/rsa.decryptPKCS1v15
// from Go 1.20.14. The caller validates the encoded message length.
func decodePKCS1v15(em []byte) (valid, index int) {
	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)
	secondByteIsTwo := subtle.ConstantTimeByteEq(em[1], 2)

	// The remainder of the plaintext must be a string of non-zero random
	// octets, followed by a 0, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the zero.
	//   index: the offset of the first zero byte.
	lookingForIndex := 1

	for i := 2; i < len(em); i++ {
		equals0 := subtle.ConstantTimeByteEq(em[i], 0)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals0, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals0, 0, lookingForIndex)
	}

	// The PS padding must be at least 8 bytes long, and it starts two
	// bytes into em.
	validPS := subtle.ConstantTimeLessOrEq(2+8, index)

	valid = firstByteIsZero & secondByteIsTwo & (^lookingForIndex & 1) & validPS
	index = subtle.ConstantTimeSelect(valid, index+1, 0)
	return valid, index
}
