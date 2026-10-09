package piv

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/hex"
	"testing"
)

// Fixed valid PKCS #1 v1.5 ciphertext under rsaKnownAnswerKey, computed with
// public RSA from EM = 00 02 || 123 copies of 42 || 00 || 01 0a.
// Its first ciphertext byte is zero. No probabilistic runtime search is used.
func TestRSADecryptValidLeadingZeroCiphertext(t *testing.T) {
	priv, key := rsaKnownAnswerKey(t)
	ciphertext, err := hex.DecodeString("0062bed3392c811d0f732d91d72972d0459c872090dae5815daaa4646b2670ce1d9d6430228980821bc642f2d7ad1c933a0f18e35fe75894a984cf06f61618b6279bf139f3bfb171ae7e14b0c1556d2e91e54d4320d5004335b168f0a9043a96fff2018ca9edcee944220e8c98aed68c1054ef51172fdaf2fe72000fe6a477de")
	if err != nil || len(ciphertext) != priv.Size() || ciphertext[0] != 0 {
		t.Fatal("invalid test fixture")
	}
	message := []byte{1, 10}
	raw := key.rawDecrypt
	key.rawDecrypt = func(ct []byte) ([]byte, error) {
		if len(ct) != priv.Size() || !bytes.Equal(ct, ciphertext) {
			t.Fatal("wrapper changed modulus-sized ciphertext")
		}
		tx := rsaAPDUFunc(func(cmd apdu) ([]byte, error) {
			expected := marshalASN1(0x7c, append([]byte{0x82, 0}, marshalASN1(0x81, ciphertext)...))
			if cmd.instruction != insAuthenticate || cmd.param1 != algRSA1024 || cmd.param2 != 0x9d || !bytes.Equal(cmd.data, expected) {
				t.Fatal("APDU changed ciphertext or selected wrong algorithm/slot")
			}
			em, err := raw(ct)
			if err != nil {
				return nil, err
			}
			return marshalASN1(0x7c, marshalASN1(0x82, em)), nil
		})
		return ykDecryptRSA(tx, SlotKeyManagement, &priv.PublicKey, ct)
	}
	for _, opts := range []crypto.DecrypterOpts{nil, &rsa.PKCS1v15DecryptOptions{}} {
		control, controlErr := priv.Decrypt(nil, ciphertext, opts)
		got, err := key.Decrypt(nil, ciphertext, opts)
		if err != nil || controlErr != nil || !bytes.Equal(got, message) || !bytes.Equal(control, message) {
			t.Fatalf("got %x/%v, control %x/%v", got, err, control, controlErr)
		}
	}
}
