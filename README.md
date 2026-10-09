This is not an officially supported Google product

# A Go YubiKey PIV implementation

[![Go Reference](https://pkg.go.dev/badge/github.com/go-piv/piv-go/v2/piv.svg)](https://pkg.go.dev/github.com/go-piv/piv-go/v2/piv)

YubiKeys implement the PIV specification for managing smart card certificates.
This applet is a simpler alternative to GPG for managing asymmetric keys on a
YubiKey.

This package is an alternative to Paul Tagliamonte's [go-ykpiv](https://github.com/paultag/go-ykpiv),
a wrapper for YubiKey's ykpiv.h C library. This package aims to provide:

* Better error messages
* Idiomatic Go APIs
* Modern features such as PIN protected management keys

V2 of this package was released in 2024 to support newer kinds of management
keys, and is now the default branch for new features. The import path is:

```
import "github.com/go-piv/piv-go/v2/piv"
```

## Examples

* [Signing](#signing)
* [PINs](#pins)
* [Certificates](#certificates)
* [Attestation](#attestation)

### Signing

The piv-go package can be used to generate keys and store certificates on a
YubiKey. This uses a management key to generate new keys on the applet, and a
PIN for signing operations. The package provides default PIN values. If the PIV
credentials on the YubiKey haven't been modified, the follow code generates a
new EC key on the smartcard, and provides a signing interface:

```go
// List all smartcards connected to the system.
cards, err := piv.Cards()
if err != nil {
	// ...
}

// Find a YubiKey and open the reader.
var yk *piv.YubiKey
for _, card := range cards {
	if strings.Contains(strings.ToLower(card), "yubikey") {
		if yk, err = piv.Open(card); err != nil {
			// ...
		}
		break
	}
}
if yk == nil {
	// ...
}

// Generate a private key on the YubiKey.
key := piv.Key{
	Algorithm:   piv.AlgorithmEC256,
	PINPolicy:   piv.PINPolicyAlways,
	TouchPolicy: piv.TouchPolicyAlways,
}
pub, err := yk.GenerateKey(piv.DefaultManagementKey, piv.SlotAuthentication, key)
if err != nil {
	// ...
}

auth := piv.KeyAuth{PIN: piv.DefaultPIN}
priv, err := yk.PrivateKey(piv.SlotAuthentication, pub, auth)
if err != nil {
	// ...
}
// Use private key to sign or decrypt.
```

### PINs

The PIV applet has three unique credentials:

* Management key (3DES key) used to generate new keys on the YubiKey.
	* YubiKey firmware 5.4.0+ adds support for AES128/192/256 keys
* PIN (up to 8 digits, usually 6) used to access signing operations.
* PUK (up to 8 digits) used to unblock the PIN. Usually set once and thrown
  away or managed by an administrator.

piv-go implements PIN protected management keys to store the management key on
the YubiKey. This allows users to only provide a PIN and still access management
capabilities.

The following code generates new, random credentials for a YubiKey:

```go
newPINInt, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
if err != nil {
	// ...
}
newPUKInt, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
if err != nil {
	// ...
}
newKey := make([]byte, 24)
if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
	// ...
}
// Format with leading zeros.
newPIN := fmt.Sprintf("%06d", newPINInt)
newPUK := fmt.Sprintf("%08d", newPUKInt)

// If you want to change PIN/PUK retries, it's recommended to do it BEFORE changing
// the PIN/PUK, as SetRetries will reset PIN/PUK to their default values.
if err := yk.SetRetries(piv.DefaultManagementKey, piv.DefaultPIN, 5, 4); err != nil {
	// ...
}

// Set all values to a new value. 
if err := yk.SetManagementKey(piv.DefaultManagementKey, newKey); err != nil {
	// ...
}
if err := yk.SetPUK(piv.DefaultPUK, newPUK); err != nil {
	// ...
}
if err := yk.SetPIN(piv.DefaultPIN, newPIN); err != nil {
	// ...
}
// Store management key on the YubiKey.
m := piv.Metadata{ManagementKey: &newKey}
if err := yk.SetMetadata(newKey, m); err != nil {
	// ...
}

fmt.Println("Credentials set. Your PIN is: %s", newPIN)
```

The user can use the PIN later to fetch the management key:

```go
m, err := yk.Metadata(pin)
if err != nil {
	// ...
}
if m.ManagementKey == nil {
	// ...
}
key := *m.ManagementKey
```

### Certificates

The PIV applet can also store X.509 certificates on the YubiKey:

```go
cert, err := x509.ParseCertificate(certDER)
if err != nil {
	// ...
}
if err := yk.SetCertificate(managementKey, piv.SlotAuthentication, cert); err != nil {
	// ...
}
```

The certificate can later be used in combination with the private key. For
example, to serve TLS traffic: 

```go
cert, err := yk.Certificate(piv.SlotAuthentication)
if err != nil {
	// ...
}
priv, err := yk.PrivateKey(piv.SlotAuthentication, cert.PublicKey, auth)
if err != nil {
	// ...
}
s := &http.Server{
	TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  priv,
			},
		},
	},
	Handler: myHandler,
}
```

### Attestation

YubiKeys can attest that a particular key was generated on the smartcard, and
that it was set with specific PIN and touch policies. The client generates a
key, then asks the YubiKey to sign an attestation certificate:

```go
// Get the YubiKey's attestation certificate, which is signed by Yubico.
yubiKeyAttestationCert, err := yk.AttestationCertificate()
if err != nil {
	// ...
}

// Generate a key on the YubiKey and generate an attestation certificate for
// that key. This will be signed by the YubiKey's attestation certificate.
key := piv.Key{
	Algorithm:   piv.AlgorithmEC256,
	PINPolicy:   piv.PINPolicyAlways,
	TouchPolicy: piv.TouchPolicyAlways,
}
if _, err := yk.GenerateKey(managementKey, piv.SlotAuthentication, key); err != nil {
	// ...
}
slotAttestationCertificate, err := yk.Attest(piv.SlotAuthentication)
if err != nil {
	// ...
}

// Send certificates to server.
```

A CA can then verify the attestation, proving a key was generated on the card
and enforce policy:

```go
// Server receives both certificates, then proves a key was generated on the
// YubiKey.
a, err := piv.Verify(yubiKeyAttestationCert, slotAttestationCertificate)
if err != nil {
	// ...
}
if a.TouchPolicy != piv.TouchPolicyAlways {
	// ...
}

// Record YubiKey's serial number and public key.
pub := slotAttestationCertificate.PublicKey
serial := a.Serial
```

## Installation

On MacOS, piv-go doesn't require any additional packages.

To build on Linux, piv-go requires PCSC lite. To install on Debian-based
distros, run:

```
sudo apt-get install libpcsclite-dev
```

On Fedora:

```
sudo yum install pcsc-lite-devel
```

On CentOS:

```
sudo yum install 'dnf-command(config-manager)'
sudo yum config-manager --set-enabled PowerTools
sudo yum install pcsc-lite-devel
```

On FreeBSD:

```
sudo pkg install pcsc-lite
```

On Windows:

No prerequisites are needed. The default driver by Microsoft supports all functionalities
which get tested by unittests. However if you run into problems try the official
[YubiKey Smart Card Minidriver](https://www.yubico.com/products/services-software/download/smart-card-drivers-tools/). Yubico states on their website the driver adds [_additional
smart functionality_](https://www.yubico.com/authentication-standards/smart-card/).

Please notice the following:

>Windows support is best effort due to lack of test hardware. This means the maintainers will take patches for Windows, but if you encounter a bug or the build is broken, you may be asked to fix it.

## Non-YubiKey smartcards

Non-YubiKey smartcards that implement the PIV standard are not officially supported due to a lack of test hardware. However, PRs that fix integrations with other smartcards are welcome, and piv-go will attempt to not break that support.  

## Testing

Tests automatically find connected available YubiKeys, but won't modify the
smart card without the `--wipe-yubikey` flag. To let the tests modify your
YubiKey's PIV applet, run:

```
go test -v ./piv --wipe-yubikey
```

Longer tests can be skipped with the `--test.short` flag.

```
go test -v --short ./piv --wipe-yubikey
```

## Why?

YubiKey's C PIV library, ykpiv, is brittle. The error messages aren't terrific,
and while it has debug options, plumbing them through isn't idiomatic or
convenient.

ykpiv wraps PC/SC APIs available on Windows, Mac, and Linux. There's no
requirement for it to be written in any particular langauge. As an alternative
to [pault.ag/go/ykpiv][go-ykpiv] this package re-implements ykpiv in Go instead
of calling it.

## Alternatives

OpenSSH has experimental support for U2F keys ([announcement][openssh-u2f]) that
directly use browser U2F challenges for smart cards.

[go-ykpiv]: https://github.com/paultag/go-ykpiv
[openssh-u2f]: https://marc.info/?l=openssh-unix-dev&m=157259802529972&w=2


### RSA decryption options and compatibility

RSA keys returned by `YubiKey.PrivateKey` implement `crypto.Decrypter`.
For new protocols, use explicit OAEP options and matching encryption parameters:

```go
ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)
// Handle err before using ciphertext.
plaintext, err = decrypter.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{
    Hash: crypto.SHA256, MGFHash: crypto.SHA256,
})
```

Choose the algorithm from trusted protocol metadata. Never retry failed OAEP
ciphertext with PKCS #1 v1.5. Existing exported APIs and valid historical ciphertext
remain supported; reencryption is not required to read existing data.

`Hash`, `MGFHash` (zero defaults to `Hash`), and
`Label` are honored. The selected hashes must be linked into the caller's
binary, as required by `crypto.Hash.Available`.

Valid PKCS #1 v1.5 ciphertext remains supported with nil options or
`&rsa.PKCS1v15DecryptOptions{SessionKeyLen: 0}`. This legacy decryption mode
is deprecated and should be restricted to trusted historical migration. Go 1.26
also deprecates PKCS #1 v1.5 session-key decryption because protocol behavior is
fragile. Applications that expose padding failures can still form a decryption
oracle; normalizing errors alone does not remove that risk. Avoid sharing an RSA
key between an exposed legacy decryptor and OAEP.

This changes behavior that previously ignored options and scanned for a zero
delimiter without fully validating PKCS #1 v1.5 padding:

- Malformed padding returns `rsa.ErrDecryption` with nil plaintext instead of
  returning a suffix from an invalid block. Error strings/sentinels therefore
  change. Valid empty plaintext is now accepted.
- Ciphertext must contain exactly the modulus-size number of bytes, retaining
  leading zero bytes, and its integer value must be less than the modulus.
- Unsupported or typed-nil options, invalid/unavailable hashes, bad public
  inputs, and impossible padding/session sizes fail before authentication.
  Rejected inputs can consequently change whether a PIN prompt occurs.
- A positive `SessionKeyLen` now consumes exactly that many bytes from the
  supplied random reader before authentication. Invalid padding or a different
  plaintext length produces a random fallback of that length; random-reader and
  transport failures return nil plaintext and an error. Callers must follow
  `crypto/rsa.DecryptPKCS1v15SessionKey` protocol requirements and avoid revealing
  whether the recovered session key is correct.

Public method signatures, RSA signing, and non-RSA key behavior are unchanged.
Software regression tests cover decoding, factory preflight, and logical APDU
construction/parsing. They do not validate physical card behavior, PIN/touch
handling, PC/SC command chaining, device timing, or FIPS compliance.

Historical regression fixtures come from the actual pinned `go-utils/v6 v6.2.1`
RSA encryptor used by `go-yubikey`. They cover valid single-block RSA-1024/2048
ciphertext (including leading zero bytes) with both nil and explicit legacy
options. Empty and concatenated helper output remains outside the one-block
PIV contract. The fixtures contain only generated software keys and public test
data; see `v2/piv/testdata/README.md`.
