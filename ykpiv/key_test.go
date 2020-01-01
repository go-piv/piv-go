package ykpiv

import "testing"

func TestYubikeyGenerateKey(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
		bits int
		long bool // Does the key generation take a long time?
	}{
		{
			name: "ec_256",
			alg:  AlgorithmEC256,
		},
		{
			name: "ec_384",
			alg:  AlgorithmEC384,
		},
		{
			name: "rsa_1024",
			alg:  AlgorithmRSA1024,
		},
		{
			name: "rsa_2048",
			alg:  AlgorithmRSA2048,
			long: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.long && testing.Short() {
				t.Skip("skipping test in short mode")
			}
			yk, close := newTestYubikey(t)
			defer close()
			tx, err := yk.begin()
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer tx.Close()

			if err := ykAuthenticate(tx, DefaultManagementKey); err != nil {
				t.Fatalf("authenticating: %v", err)
			}

			key := keyOptions{alg: test.alg}
			if _, err := ykGenerateKey(tx, SlotAuthentication, key); err != nil {
				t.Errorf("generating key: %v", err)
			}
		})
	}
}
