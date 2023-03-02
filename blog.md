# Oca, oca y tiro porque me toca
A basic security property of digital signature algorithms is that they are existentially
unforgeable under chose message attacks (EU-CMA). In layman's terms, what this means
is that regardless of what message the adversary requests the signer to produce
a signature for, it is impossible to forge a valid signature for a message that 
has not yet been signed. Cryptosystems that are used in Cardano are proven to
be CPA-secure, such as [ed25519]() or [ECVRF](). However, these properties are 
proven in isolation, i.e. ed25519 is CPA-secure assuming one uses the secret key
explicitly as defined in the analysed protocol. 

Very often we (cryptography engineers) get asked whether one can use the same 
secret key for different algorithms. This is clearly bad practice - one should
only use the secret key for its intended purpose. My common answer, specifically
if replied generically, is 'no'. However, sometimes the arguments used (formal
security is studied in isolation, it is not well understood what happens if we
use a secret key for different purposes, etc) are too abstract for engineers.

In this blogpost we show how using the same key for ed25519 and 
ECVRF completely breaks the security of both algorithms, and allows an adversary 
to practically extract the signing key and forge signatures and VRF proofs. 

**NOTE**: this does not imply that using the same 32 secret bytes for two 
distinct cryptosystems discloses the secret. However, it should serve as an 
example that if you are not certain, then you should not do it.

## Schnorr signatures
[Schnorr]() signatures have been around for quite some years, and they are
deployed and used in many contexts. In Cardano, following our valentine 
upgrade, we introduced native support for Schnorr signatures over curve SECP256k1 
in Plutus. Schnorr signatures are simply [sigma protocols]() that are 
tied to a message. In particular, let $(sk, pk)$ be a key-pair such that 
$pk = sk \cdot G$ with $G$ being the elliptic curve base point[^1]. Then, 
the signature algorithm is defined interactively (between the prover and 
the verifier) as follows:

- [P] selects a random scalar $k$, computes $R = k \cdot G$, and sends $R$ to the verifier
- [V] selects a random scalar $c$, and sends it to the prover
- [P] computes $s = k + c * sk$, and sends it to the verifier
- [V] accepts if and only if $s * G = R + c * pk$. 

If one extends $s, R$ and $pk$, it is easy to see that if the protocol is followed,
the verifier will accept the signature. However, we've just described an interactive
protocol. How can that be a signature algorithm? Indeed, a signature algorithm would
be extremely impractical if the signer and verifier would have to interact. To
that end, the first step of the verifier (computing the random challenge) is 
replaced by a hash function, which is assumed to provide random, unpredictable 
outputs. Formally, this is called the [Fiat-Shamir]() heuristic, and is used in more
modern Zero Knowledge Proofs (yes! Schnorr signatures are very simple ZKPs) to make
them non-interactive.

These signatures guarantee the following three (informal) security properties:
* Completeness: If the signer follows the protocol, the verifier accepts
* Soundness: If the prover is able to create a valid signature, then it knows the
secret key.
* Zero Knowledge: The signature does not disclose anything other than the fact that
the signer knows/owns the secret key.
* EU-CMA: 

However, these properties are proven secure if the secret material is used exactly
as described in the protocol. As a matter of fact, producing two signatures that 
share the same value $R$ but a different value $s$ completely breaks the system. With 
high-school level algebra knowledge, it is easy to see why. Assume we have two valid
signatures, $(R, s)$ and $(R, s')$ with $s != s'$. Recall that the value $c$ and $c'$
are known to the verifier, and the latter knows that $s = k + c * sk$. Given that the
value of $R$ is equal in both proofs, then the verifier can compute the secret key as
$$sk = (s - s') * (c - c')^{-1}$$

Fortunately the above happens with probability $1 / 2^{256}$, which is negligible. 

## Ed25519
The signature scheme, ed25519, was introduced by Bernstein, Duif, Lange, Schwabe and Yang.
Essentially, this signature scheme is a Schnorr signature scheme but defined specifically 
over curve Edwards25519 for efficiency and security considerations. We don't need to cover 
the details of this curve or the benefits it brings. However, one important detail introduced
in ed25519 which differs with Schnorr is that signatures are deterministic, i.e. the 
randomness used in the announcement (first step of the prover), is computed using a hash
function, rather than sampling the value $k$ uniformly at random. The motivation behind that
choice was that in the past lack of secure sources of randomness resulted in the [disclosure - don't like it]
of the secret keys. Hence, by computing this value pseudorandomly, one relies on the security
of the pseudorandom generator (which is in control by the developers) instead of a secure source
of randomness (which is not under the control of the developers). In particular, ed25519
is defined as follows:

* $ \keygen(1^\secparam) $ takes as input the security parameter $ \secparam $ and returns a key-pair $
  (\secretkey, \vk)$. First, it chooses $ \secretkey\leftarrow\{0,1\}^b $. Next, let $ (h_0, h_1, \ldots, h_{2b - 1})\gets\hash(\secretkey) $,
  and compute the signing key, $ \signingkey \gets 2^{b-2} + \sum_{3\leq i\leq b-3}2^i h_i $
  . Finally, compute $ \vk \gets \signingkey \cdot \generator $, and return $ (\secretkey, \vk) $.
* $ \sign(\secretkey, \vk, m) $ takes as input a keypair $ (\secretkey, \vk) $ and a message $ m $, and returns a
  signature $ \signature $. Let $ r \gets H(h_b, \ldots, h_{2b-1}, m) $, and interpret the result as a little-endian
  integer in $ \{0,1,\ldots, 2^{2b}-1\} $. Let $ R \gets r\cdot\generator $, and $ S \gets (r + H(R, A, M)\cdot
  \signingkey) \mod \order $. Return $ \signature \gets (R, S) $.
* $ \verify(m, \vk, \signature) $ takes as input a message $ m $, a verification key $ \vk $ and a signature
  $ \signature $, and returns $ r\in\{\accept, \reject\} $ depending on whether the signature is valid or not. The algorithm
  returns $ \accept $ if the following equation holds and $ \reject $ otherwise:
  $$ S\cdot\generator = R + H(R, \vk, m)\cdot \vk. $$

Note that in this secret key generation, the secret key is not used to multiply the elliptic curve base point, 
but instead to compute a hash and use the output to perform these operations.

## ECVRF
The ECVRF is yet another protocol that is highly inspired from Schnorr in general, and ed25519 in particular. The
concrete scheme that we look into is ECVRF-EDWARDS25519-SHA512-ELL2, from the VRF [irtf draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-14#name-ecvrf-ciphersuites).
A VRF, namely a Verifiable Random Function, allows a prover to create some pseudorandom value associated with
its private key, and prove that it did so correctly. The details of why that is useful or how it is used is not 
relevant here. However, let's have a look at how it works:

* Key generation happens exactly as with ed25519. i.e. we have the same key-pair.
* $\vrfgenerateproof(\secretkey, \vrfvk, m)$ takes as input a keypair $(\secretkey, \vrfvk)$ and a message
  $m$, and returns the $\vrf$ randomness $\vrfoutput$ together with a proof $\vrfproof$. Use $\secretkey$ to
  derive $\vrfsk$. Let $H \gets \hash_{s2c}(\vrfvk, m)$. Let $\Gamma \gets \vrfsk\cdot H$. Compute $r$ as
  defined in procedure $\sign$ as in [ed25519](./ed25519.md#generalised-specification). Let $c \gets \hash
  (H\parallelsep\Gamma\parallelsep k\cdot\generator\parallelsep k\cdot H)[..128]$. Compute $s \gets (r +
  c\cdot\vrfsk)\mod\order$. Finally, return the proof $\vrfproof \gets (\Gamma, c, s)$ and the randomness
  $\vrfoutput \gets \hash(\texttt{suite\_string}\parallelsep 0x03\parallelsep\cofvar\cdot\Gamma\parallelsep
  0x00)$.
* $\verify(m, \vrfvk, \vrfproof)$ takes as input a message $m$, a verification key $\vrfvk$ and a vrf proof
  $\vrfproof$, and returns $\vrfoutput$ or $ \false $. It parses the proof as $(\Gamma, c, s) = \vrfproof$, and
  computes $H\gets\hash_{s2c}(\vrfvk, m)$. Let $U \gets s\cdot\generator - c\cdot\vrfvk$ and $V \gets s\cdot
  H - c\cdot\Gamma$. Compute the challenge $c'\gets\hash(H\parallelsep\Gamma\parallelsep U\parallelsep V)[..128]$.
  If $c'=c$, then return $\vrfoutput \gets  \hash(\texttt{suite\_string}\parallelsep
  0x03\parallelsep\cofvar\cdot\Gamma\parallelsep 0x00)$, otherwise, return $ \false $.

Ahá! seeing this we can conclude that for a given secret key $sk$, both algorithms ed25519 and ECVRF share the 
same public key. Well, this is convenient. We can prove ownership of a VRF key using an ed25519 signature, which
turns out to be smaller and cheaper to verify. Or can we?

## Share your love, not your secret keys
If you are reading this blogpost I guess that you know what is coming next. Indeed, if we share the secret keys for
these two algorithms, an adversary could trick an ed25519 signer to basically expose its private key. The way we
can do this came in a spoiler early on! What is essentially happening here is that we could have the same value
of $R$ for two distinct values of $s$. In ed25519, the random nonce that the signer commits to is computed via
$ r \gets H(h_b, \ldots, h_{2b-1}, m) $. In VRF, the value is computed via $ r \gets H(h_b, \ldots, h_{2b-1}, H) $
**(THIS IS NOT THE CASE CURRENTLY, CHANGE THE DESCRIPTION OF THE VRF)**. However, the challenge is computed via
$H(R, A, M)$ and $\hash
(H\parallelsep\Gamma\parallelsep k\cdot\generator\parallelsep k\cdot H)[..128]$ respectively.


Here is where the devil lies. We can trick the ed25519 signer to create the same value of $r$, but we will get a
different value of $c$. If the adversary manages to do this, then the cryptosystems are broken! Worst of all is 
that it is not an attack hard to pull-off. Given a VRF proof for public key $pk$, the adversary simply needs to 
request an ed25519 signature from $pk$'s owner to sign $H$, which is a public value. To showcase the simplicity of
the attack, we've implemented a simple script that, given a VRF proof for any message, requests the key owner to
sign a particular message with ed25519, and this results in an extraction of the secret key.

[^1] A non-expert reader should not be concerned of what this really means. Simply
one should trust that extracting $sk$ from $pk$ is computationally hard and that
operations over elliptic curve points are associative and cyclic..