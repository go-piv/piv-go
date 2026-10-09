# Historical RSA ciphertext fixtures

These synthetic keys and binary plaintexts were generated solely for public regression tests. They are not user keys or data.

The actual historical encryptor is github.com/Laisky/go-utils/v6 v6.2.1, function RSAEncrypt, as pinned by go-yubikey at 3ad2190406e4fc8c205e1a72728c2b3d2b36a1d7. It produces PKCS #1 v1.5 ciphertext without algorithm/version metadata. Fixture provenance: 53b28f12b65126083d406d6d23588347e609168288e39a0d6d845acfd5388607

Both RSA-1024/2048 include one-byte and binary plaintext, the maximum single-block size k-11, and fixed-width ciphertext beginning with zero. Only modulus-sized single-block output is asserted decryptable through the historical public API. The encryptor also emits empty output and concatenated blocks; these are retained as unsupported-format controls, not presented as previously supported by the device wrapper. A successful software/APDU-seam test does not validate a physical device.

Do not replace these fixtures with newly generated ciphertext during ordinary test runs.
