This is not an officially supported Google product

# A pure Go YubiKey PIV implementation

YubiKeys implement the PIV specification for managing smart card certificates.
This is a simpler alternative to GPG for managing asymmetric keys on a YubiKey,
which can be used for use cases such as SSH, TLS, etc.

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
