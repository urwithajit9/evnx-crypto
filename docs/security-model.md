# evnx-crypto — Security Model

What this library defends against, what it does not, and where it stands against
a quantum adversary. Written to be read by someone deciding whether to trust it.

---

## 1. What the server can see

evnx is zero-knowledge for **secret values**. It is not zero-knowledge for
everything, and the difference matters.

| Stored on the server | Encrypted? |
|---|---|
| `.env` values | ✅ AES-256-GCM under a key the server never has |
| Encrypted private key | ✅ XChaCha20-Poly1305 under an Argon2id-derived key |
| Wrapped vault keys | ✅ XChaCha20-Poly1305 under a master key or ECDH secret |
| SRP verifier | ✅ never the password — but see §4.1 |
| **Variable names** (`key_names[]`) | ❌ **plaintext** |
| Vault names, environments | ❌ plaintext |
| Member lists, who pushed what, when | ❌ plaintext |
| Blob sizes, version counts | ❌ plaintext |

**The variable names are the notable one.** `vault_versions.key_names` stores
`STRIPE_SECRET_KEY`, `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL` in the clear. The
*values* are encrypted; the *shape of your infrastructure* is not. A breach tells
an attacker which vendors you use and which of your systems hold what kind of
credential — useful targeting information, and for some threat models
unacceptable.

This is a deliberate trade: it lets the dashboard and `evnx vault list` show which
keys exist without decrypting anything. If that trade is wrong for your users,
`key_names` should be dropped or encrypted separately. **It is a product decision,
not a cryptographic limitation.**

---

## 2. What a server breach actually yields

Assume total compromise: database, object storage, application memory at rest.

The attacker holds, per user: `srp_verifier`, `srp_salt`, `argon2_salt`,
`encrypted_private_key`, every wrapped vault key, and every ciphertext blob.

**None of it decrypts without the user's password.** There is no server-side key
to steal, because there isn't one. What the attacker gets is the ability to run an
**offline attack against each user's password** — and the whole security of the
system at that point reduces to one number: the cost of a single Argon2id guess.

Two offline oracles exist:

1. **Against `encrypted_private_key`** — guess password → Argon2id → HKDF → attempt
   XChaCha20-Poly1305 decrypt. The Poly1305 tag says pass/fail with certainty.
2. **Against `srp_verifier`** — guess password → Argon2id → derive `x` → compute
   `g^x mod N` → compare with the stored verifier.

Both cost **one full Argon2id evaluation per guess**: 64 MiB of memory, 3
iterations, 4 lanes. Memory-hardness is the point — it denies the attacker the
GPU and ASIC parallelism that makes fast hashes worthless, because every parallel
guess needs its own 64 MiB.

### What that means in practice

| Password | Survives an offline attack? |
|---|---|
| 4-word diceware passphrase (~51 bits) | Yes, comfortably |
| 3-word passphrase (~38 bits) | Marginal — years, not centuries |
| 12 random chars, mixed (~71 bits) | Yes |
| 8 chars from a leaked-password wordlist | **No — hours** |
| Reused from a previous breach | **No — immediately** |

**Argon2id raises the cost of guessing. It does not make a bad password good.**
Any honest description of this system says so. The single highest-leverage
security control evnx has is refusing weak and known-breached passwords at
registration — and that belongs in the CLI, not in this crate.

---

## 3. Post-quantum posture

### The short version

**Both solo and shared vaults are post-quantum safe as of 0.2.0.**

> Updated 2026-09-18. Before 0.2.0 shared vaults were **not**: the vault key was
> wrapped under X25519 ECDH alone, so every secret ever shared was exposed to
> harvest-now-decrypt-later. 0.2.0 replaces that with a hybrid
> X25519 + ML-KEM-768 wrap. The rest of this section is kept as written because
> the reasoning is what justifies the change — the ❌ rows below are the state it
> fixed.

### Component by component

| Primitive | Quantum attack | Status |
|---|---|---|
| Argon2id | Grover only; memory-hardness resists quantum parallelism | ✅ Safe |
| AES-256-GCM | Grover halves it: 256 → ~128-bit effective | ✅ Safe |
| XChaCha20-Poly1305 | Grover: 256 → ~128-bit | ✅ Safe |
| SHA-256 / BLAKE3 | Grover; still ≥128-bit | ✅ Safe |
| **X25519 ECDH, alone** | **Shor breaks it outright** | ❌ was vulnerable |
| **X25519 + ML-KEM-768 hybrid** | Shor breaks the X25519 half; the ML-KEM half is a lattice scheme with no known quantum attack | ✅ **Safe as of 0.2.0** |
| **SRP-6a (2048-bit group)** | **Shor solves the discrete log** | ❌ Vulnerable |
| Ed25519 | Shor breaks it — but nothing is signed yet | ⚠️ Latent |

### Harvest now, decrypt later — the real risk

The threat is not a quantum computer today. It is an adversary recording
ciphertext **today** and decrypting it once a cryptographically relevant quantum
computer exists. Secrets have long lives: a database password or a cloud API key
set today may still be valid in five or ten years.

Trace the two paths a vault key can travel:

```
Solo vault:    VaultKey ── XChaCha20 under Argon2id(MasterKey) ──▶ server
               Breaking this needs the password. Quantum does not help.   ✅

Shared vault,  VaultKey ── XChaCha20 under HKDF(X25519 ECDH) ──▶ server
before 0.2.0:  The server also holds eph_pub_key and the recipient's
               X25519 public key. Shor recovers the private key from the
               public one, reconstructs the shared secret, unwraps the
               vault key, decrypts every blob.                            ❌

Shared vault,  VaultKey ── XChaCha20 under HKDF(ML-KEM ‖ X25519 ‖ …) ──▶ server
0.2.0 onward:  Shor still recovers the X25519 half. It contributes 32 of
               the HKDF's input bytes and the other 32 come from ML-KEM,
               which Shor does not touch. The wrap key is unrecoverable
               unless BOTH primitives fall.                               ✅
```

Before 0.2.0: **every secret ever shared with a teammate was exposed to
harvest-now-decrypt-later.** The vault contents themselves are AES-256 and fine —
it was the *wrapping* that failed, and that was enough.

⚠️ **This is why the hybrid landed before `evnx vault share` shipped, not after.**
A vault key wrapped under X25519 alone stays wrapped that way for as long as the
row exists; an adversary who recorded it does not care that a later version fixed
the algorithm. There was no version of this that could be safely retrofitted, so
sharing was held back until the wrap was right.

SRP is a smaller problem. Shor against the verifier yields `x`, which permits
impersonation but not password recovery (`x` is downstream of Argon2id). And
compromising authentication does not decrypt anything: the data key is
independent. Fix it after the wrapping.

### The fix, and why it is not in 0.1.0

The standard answer is a **hybrid KEM**: run X25519 and ML-KEM-768 (FIPS 203,
Kyber) side by side and feed both shared secrets into the same HKDF. The result is
secure if *either* survives — classical security is never reduced, and quantum
security is gained. This is what TLS deployed as `X25519MLKEM768`.

### What shipped in 0.2.0

The combiner takes more than the two secrets:

```text
ikm      = ss_mlkem ‖ ss_x25519 ‖ ct_mlkem ‖ eph_pub ‖ recipient_x25519_pub
wrap_key = HKDF-SHA256(ikm, "evnx-vault-key-wrap-v2")
```

**Why the transcript is in there.** A shared secret does not bind the message
that produced it. X25519 is not ciphertext-collision-resistant: distinct
ephemeral keys can produce the same secret against a chosen static key, so
without the transcript an attacker able to substitute one half could steer two
different wraps onto one key. ML-KEM already binds its own ciphertext and public
key through the FO transform, but including them costs nothing and makes the
combiner robust by construction rather than by appeal to one primitive's
internals. This is the shape X-Wing and the TLS hybrid drafts settled on.

**Why the info string went to v2.** v1 derived the wrap key from the X25519
secret alone. Reusing it would mean a v1 and a v2 wrap could derive the same key
from the same ECDH secret — so stripping the ML-KEM ciphertext and presenting the
blob as v1 would produce a *working* wrap key instead of a failure. The version
is what makes the hybrid non-optional.

**The ML-KEM keypair is derived, not stored.** It comes from the same Ed25519
seed that already yields the X25519 key, via HKDF under `evnx/mlkem768/v1`. So
`users.encrypted_private_key` is unchanged — still a sealed 32-byte seed — and no
existing user is ever asked to re-enter their master password so a second private
key can be sealed. The cost is that the derivation can never change: a KAT pins
it, and the test suite documents why.

**What it cost on the wire.** `vault_members` grows a 1088-byte ML-KEM ciphertext
per member row, `users` grows a 1184-byte ML-KEM public key, and the browser
bundle grew ~8 KB gzipped. Nothing else changed.

⚠️ **SRP-6a is still Shor-vulnerable** and is deliberately out of scope. Shor
against the verifier yields `x`, which permits impersonation but not password
recovery (`x` is downstream of Argon2id), and compromising authentication does
not decrypt anything — the data key is independent. Fixing the wrapping first was
the right order.

---

## 4. Attack-by-attack

### 4.1 Database dump / credential-leak dataset
The server holds no decryption key, so a dump yields only material for an offline
password attack, throttled by Argon2id (§2). Compare with a service that stores
plaintext or a fast hash, where a dump is instant total loss. **The password is
never transmitted at all** — SRP proves knowledge of it without sending it — so an
evnx breach also cannot hand attackers a password to reuse on other services,
except through that offline attack.

### 4.2 Credential stuffing / password reuse
Out of this crate's hands, and the honest answer is that reuse defeats it: if the
password already appears in a breach corpus, the offline attack in §2 succeeds
immediately. **Mitigation belongs in the CLI:** check candidate passwords against
Have I Been Pwned's k-anonymity range API at registration, and enforce a minimum
entropy. This is the single most valuable security feature evnx could add.

### 4.3 Malicious or compelled server
The core design case. The server can withhold data or refuse service; it cannot
read it. Two specific attacks are explicitly defended:
- **Key substitution** via a low-order ECDH point — rejected by the contributory
  check (`CryptoError::InvalidPublicKey`).
- **Version rollback**, serving an old blob as current — rejected by AAD binding
  through `vault_aad`.

### 4.4 Man in the middle
SRP-6a authenticates **mutually**. The client verifies the server's proof M2, which
only a party holding the verifier can produce. A rogue TLS certificate is not
enough to impersonate the server. This is stronger than a bearer-token login over
TLS, where certificate compromise is complete compromise.

### 4.5 Stolen laptop / memory scraping
Key material is `ZeroizeOnDrop` and cleared when it leaves scope, which narrows the
window. It cannot eliminate it: keys must exist in memory while in use, and Rust
may move values before they are zeroized. A compromised client running while the
user is logged in is **out of scope** — no client-side library can fix that.

### 4.6 Tampering with stored ciphertext
Every ciphertext is AEAD. Any modification to ciphertext, nonce, tag, or associated
data fails authentication. Errors deliberately do not distinguish which, to avoid
offering a decryption oracle.

---

## 5. Honest limitations

1. **A weak password defeats everything.** Argon2id buys cost, not immunity.
2. **Variable names are plaintext** (§1).
3. ~~**Shared vaults are not post-quantum safe** (§3).~~ **Fixed in 0.2.0** —
   hybrid X25519 + ML-KEM-768 wrap. SRP-6a remains Shor-vulnerable, which is an
   authentication problem rather than a confidentiality one; see §3.
4. **A compromised client is game over** — as with every client-side encryption tool.
5. **No forward secrecy for stored data.** Wrapped vault keys are long-lived; an
   attacker who obtains a master key can decrypt every past version that key wrapped.
   Key rotation is a Phase 3 feature.
6. **Ed25519 keys are generated and stored but never used to sign anything.** They
   exist as the derivation root for X25519 and as reserved identity. No integrity
   claim rests on them today.
7. **Nothing here has been externally audited.** The code is MIT-licensed and open
   precisely so it can be. Treat it as carefully reviewed, not as certified.
