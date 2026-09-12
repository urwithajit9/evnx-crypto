# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub's
[private vulnerability reporting](https://github.com/urwithajit9/evnx-crypto/security/advisories/new)
rather than a public issue.

Include what you can: affected version, a description, and ideally a reproducing
test. A proof-of-concept in the style of `tests/attacks.rs` is ideal.

## Scope

This crate performs all cryptography for evnx cloud sync. In scope:

- key derivation, encryption, key wrapping, key agreement and the SRP-6a client
- anything that would let an untrusted server read plaintext, substitute a key,
  replay old ciphertext, or learn a password
- key material reaching logs, `Debug` output, or surviving in memory after use

Out of scope:

- a compromised client. If an attacker executes code on the user's machine while
  they are logged in, they can read plaintext. This crate protects data at rest
  and in transit.
- denial of service through pathological input sizes
- vulnerabilities in upstream crates, unless our usage is what makes them
  exploitable — report those upstream, and tell us too

## Threat model

The server is untrusted and may be breached, compelled, or hostile. It can return
any bytes it likes. Every value arriving from the network is treated as
attacker-controlled. See the crate-level documentation for details.

## Supported versions

Until 1.0, only the latest 0.x release receives fixes.
