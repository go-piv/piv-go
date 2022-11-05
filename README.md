This is not an officially supported Google product

# A Go YubiKey PIV implementation

[![GoDoc](https://godoc.org/github.com/go-piv/piv-go/piv?status.svg)](https://godoc.org/github.com/go-piv/piv-go/piv)

YubiKeys implement the PIV specification for managing smart card certificates.
This applet is a simpler alternative to GPG for managing asymmetric keys on a
YubiKey.

This package is an alternative to Paul Tagliamonte's [go-ykpiv](https://github.com/paultag/go-ykpiv),
a wrapper for YubiKey's ykpiv.h C library. This package aims to provide:

* Better error messages
* Idiomatic Go APIs
* Modern features such as PIN protected management keys

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
	if yk, err := piv.Open(card); err == nil {
		status := yk.Status()
		if !strings.Contains(strings.ToLower(string(status.Atr())), "ubike") {
			continue
		}
		// ..
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
var newKey [24]byte
if _, err := io.ReadFull(rand.Reader, newKey[:]); err != nil {
	// ...
}
// Format with leading zeros.
newPIN := fmt.Sprintf("%06d", newPINInt)
newPUK := fmt.Sprintf("%08d", newPUKInt)

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
