# Insecurity of secret key re-usage
_[tl;dr]: In this blogpost we show how to extract the key of an ed25519 keypair if its secret is
also used to generate a Verifiable Random Function proof. We create a script that performs such 
an extraction over libsodium._

In the pre-blockchain era, the typical advise from cryptographers was ``Don't roll your own crypto!''. 
The intention behind this advice is to avoid security pitfalls, which are less likely to exist in 
rigorously researched inventions. However, this advice is muffled by the accelerated advancement 
of the blockchain space, where new cryptography is invented and rolled out every now and then. In 
this article, we re-emphasize the need for rigorous security analysis of every new crypto, by 
demonstrating how a natural shortcut can lead to a catastrophic consequence.

Specifically, ed25519 signatures and VRFs (verifiable random functions) are used in Cardano. 
Given their similarly structured public keys, one may be tempted to use the same secret key 
for both the primitives. However, doing so can allow an adversary to easily extract the secret 
key. Cryptosystems that are used in Cardano are proven to
be secure, such as [ed25519](https://datatracker.ietf.org/doc/rfc8032/) or 
[ECVRF](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-14). However, these properties are 
proven in isolation, i.e. ed25519 is secure assuming one uses the secret key
explicitly as defined in the analysed protocol. 

Very often cryptography engineers get asked whether one can use the same 
secret key for different algorithms. This natural shortcut is bad practice - one should
only use the secret key for its intended purpose, even if it's 'only' 32 bytes. 
The common answer, specifically
if replied generically, is 'no'. However, sometimes the arguments used (formal
security is studied in isolation, it is not well understood what happens if we
use a secret key for different purposes, etc) are too abstract for engineers.

In this blogpost we show how using the same key for ed25519 and 
ECVRF completely breaks the security of both algorithms, and allows an adversary 
to practically extract the signing key and forge signatures and VRF proofs. 

**NOTE**: this does not imply that using the same 32 secret bytes for any two 
distinct cryptosystems discloses the secret. However, it should serve as an 
example that if one is not certain of whether using the same key for two 
algorithms is secure or not, then the assumption should be that it is not.

## Schnorr Signatures, the Predecessor of Ed25519 and ECVRF
We will begin by explaining [Schnorr](https://en.wikipedia.org/wiki/Schnorr_signature) signatures, which was the basis of Ed25519 and ECVRF designs. 
Schnorr signatures have been around for quite some years, and they are
deployed widely in many applications. In Cardano, following our [valentine](https://docs.cardano.org/cardano-testnet/about/secp) 
upgrade, we introduced native support for Schnorr signatures over curve SECP256k1 
in Plutus. Schnorr signatures are simply 
[sigma protocols](https://en.wikipedia.org/wiki/Proof_of_knowledge#Sigma_protocols) that are 
tied to a message. In particular, let $(sk, vk)$ be a key-pair such that 
$vk = sk \cdot G$ with $G$ being the elliptic curve base point[^1] which is the 
generator of a prime order group with prime order $p$. Then, 
the signature algorithm is defined interactively (between the prover [P] and 
the verifier [V]) as follows:

- [P] selects a random scalar $k$, computes $R = k \cdot G$, and sends $R$ to the verifier
- [V] selects a random scalar $c$, and sends it to the prover
- [P] computes $s = k + c * sk$, and sends it to the verifier
- [V] accepts if and only if $s * G = R + c * vk$. 

Note that we have just described an interactive
protocol, where there is no message involved. We will now describe how it is transformed into a message signing non-interactive version. A typical method used in Cryptography is the so-called [Fiat-Shamir](https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic) transformation that replaces the random challenges with outputs of a random oralce, where the input to the random oracle is the transcript thus far. Furthermore, in order to link a signature
(as described above) to a message, the latter is inlcuded when computing the hash that 
defines the challenge. 

For readability, in this blogpost we describe all algorithms in their interactive version and note that any of them can be made non-interactive via the Fiat-Shamir 
heuristic. Furthermore, for simplicity, we omit specifying the message from the Schnorr-like signature schemes 
descriptions.

Subtle deviations from the protocol can be catastrophic. One such example is producing two signatures 
that share the same value $R$ but a different value $s$, this completely breaks the system (for 
example by using an incorrect source of randomness that  returns the same value of k). With 
high-school level algebra knowledge, it is easy to see why. Assume we have two valid
signatures, $(R, s)$ and $(R, s')$ with $s \neq s'$. Recall that the value $c$ and $c'$
are known to the verifier, and the latter knows that $s = k + c * sk$. Given that the
value of $R$ (and therefore $k$) is equal in both proofs, then the verifier can compute
the secret key as $$sk = (s - s') * (c - c')^{-1}$$

Fortunately, if the value $k$ is chosen uniformly at random, the above happens with probability 
$1 / 2^{256}$, which is negligible over the security parameter. 

### Ed25519
The signature scheme, ed25519, was introduced by Bernstein, Duif, Lange, Schwabe and Yang.
Essentially, this signature scheme is a Schnorr signature scheme but defined specifically 
over curve Edwards25519 for efficiency and security considerations. We don't need to cover 
the details of this curve or the benefits it brings. However, one important detail introduced
in ed25519 which differs with Schnorr is that signatures are deterministic, i.e. the 
randomness used in the announcement (first step of the prover), is computed using a hash
function, rather than sampling the value $k$ uniformly at random. The motivation behind that
choice was that in the past lack of secure sources of randomness resulted in the 
[security flaw](https://fahrplan.events.ccc.de/congress/2010/Fahrplan/attachments/1780_27c3_console_hacking_2010.pdf)
of the secret keys for ECDSA. Hence, by computing this value pseudorandomly, one relies on the security
of the pseudorandom generator (which is in control of the developers) instead of a secure source
of randomness (which is not in control of the developers). Below, we present a simplified version
of ed25519, it differs from the standard, but not in any meaningful way for the attack described
in this blogpost. Let $\texttt{KDF}$ be a key derivation function[^2] that takes as input a key and an index, and
returns an integer modulo $p$. Let $(sk, vk)$ be a key-pair such that $vk = \texttt{KDF}(sk, 0) \cdot G$. The 
protocol proceeds as follows:

- [P] selects a (pseudo)random scalar $k = \texttt{KDF}(sk || m, 1)$, computes $R = k \cdot G$, and sends $R$ to the verifier
- [V] selects a random scalar $c$, and sends it to the prover
- [P] computes $s = k + c * \texttt{KDF}(sk, 0)$, and sends it to the verifier
- [V] accepts if and only if $s * G = R + c * vk$.

One can see how closely related both algorithms (Schnorr and ed25519) are. Note that in this secret key generation, 
the secret key is not used to multiply the elliptic curve base point, 
but instead to derive two scalars. As noted above, this algorithm can be made non-interactive via the Fiat-Shamir
heuristic. 

### ECVRF
The ECVRF is yet another protocol that is highly inspired from Schnorr in general, and ed25519 in particular. The
concrete scheme that we look into is ECVRF-EDWARDS25519-SHA512-ELL2, from the VRF [irtf draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-14#name-ecvrf-ciphersuites).
A VRF, namely a Verifiable Random Function, allows a prover to create some pseudorandom value associated with
its private key, and prove that it did so correctly. The details of why that is useful or how it is used are not 
relevant here. However, let's have a look at how it works. In this algorithm we use a different hash function, 
$H_{s2c}$, that takes as input an array of bytes and returns a point in the elliptic curve. Again, we simplify
the protocol for this blogpost core goal (breaking both VRF and Ed25519).
Let $(sk, vk)$ be a key-pair such that $vk = \texttt{KDF}(sk, 0) \cdot G$. The
protocol proceeds as follows:

- [P] computes $L \gets H _ {s2c}(vk, m)$ and $\Gamma \gets \texttt{KDF}(sk, 0)\cdot L$.
  Next, it selects a (pseudo)random scalar $k = \texttt{KDF}(sk || L, 1)$, and computes $R = k \cdot G$,
  and $P\gets k \cdot L$. It sends $R, \Gamma, P$ to the verifier.
- [V] selects a random scalar $c$, and sends it to the prover
- [P] computes $s = k + c * \texttt{KDF}(sk, 0)$, and sends it to the verifier
- [V] computes $L \gets H _ {s2c}(vk, m)$, and accepts if and only if $s * G = R + c * vk$ and 
  $s * L = P + c * \Gamma$.

Ahá! seeing this we can conclude that for a given secret key $sk$, both algorithms ed25519 and ECVRF share the 
same public key. Well, this is convenient. We can prove ownership of a VRF key using an ed25519 signature, which
turns out to be smaller and cheaper to verify. Or can we?

## Don't share your secrets!
If you are reading this blogpost you know what is coming next. Indeed, if we share the secret keys for
these two algorithms, an adversary could trick an ed25519 signer to basically expose its private key. The way we
can do this came in a spoiler early on! What is essentially happening here is both VRF and ed25519 use the
same key derivation function. On the one hand this results in the same $pk$ for a given $sk$. However, this also means
that one can trick an ed25519 signer produce the same value of $k$ (and consequently $R$) as the VRF counterpart, while
having different values of the challenge $c$. If the adversary manages to do this, then the secret key can be extracted! 
Worst of all is that it is not an attack hard to pull-off. Given a VRF proof for public key $pk$, the adversary simply 
needs to request an ed25519 signature from $pk$'s owner to sign $L$, which is a public value. Then both nonces $k$ will 
be identical, and the adversary can recover the key.

To showcase the simplicity of the attack, we've implemented a simple script that, given a VRF proof for any message, requests 
the key owner to sign a particular message with ed25519, and this results in an extraction of the secret key. We show how 
the forged signature is accepted by libsodium's ed25519 verifier.

We begin by defining the message we'll use for the VRF proof, and initialising some variables.
```C
#define MESSAGE (const unsigned char *) "yup"
#define MESSAGE_LEN 3
// The message that we need to craft in order to extract the key is a value 
// publicly available. However, libsodium does not export the functions to 
// compute it. Nonetheless, it is computed internally. To simplify our lives, 
// we slightly modify libsodium VRF verifier to return the crafted message.
unsigned char crafted_msg[32], proof[80], sig[crypto_sign_BYTES], pk[crypto_sign_PUBLICKEYBYTES];
```
Next, we create the scope of the signer, over which we have no access when faking
the signature.

```C
{
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    // Now let's use these keys for vrf generation.
    crypto_vrf_ietfdraft03_prove(proof, sk, MESSAGE, MESSAGE_LEN);

    // Now, we have a proof that consists of 80 bytes that correspond to:
    // * 32 bytes of an EC point that we can ignore
    // * 16 bytes of a challenge C = H(pk, H, Gamma, U, V), where the values
    // of H, Gamma, U and V are irrelevant.
    // * 32 bytes of a scalar s' = k + C' * az
    // where k = H(z || m), with z = H(sk)[32..], and az = H(sk)[..32].

    unsigned char random_output[64];
    if (crypto_vrf_ietfdraft03_verify(random_output, crafted_msg, pk, proof, MESSAGE, MESSAGE_LEN))
        printf("failed VRF\n \n");

    // Now we use the same key to create an ed25519 signature for the crafted message. Note
    // that the only 'trick' we are doing is asking the signer to sign a particular message, after
    // she has used the key to create a VRF proof. We do not access the secret key in any other way.
    crypto_sign_detached(sig, NULL, crafted_msg, 32, sk);

    if (crypto_sign_verify_detached(sig, crafted_msg, 32, pk))
        printf("failed on ed25519 generation");

    // Now we should have a 64 bytes signature that corresponds to:
    // * first 32 bytes represent the point R = k * G, where k = H(z || m)
    // where z = H(sk)[32..]
    // * second 32 bytes represent a scalar s = k + az * HRAM
    // where HRAM = H(R || pk || m), and az = H(sk)[..32]
}
```
As we said above, the problem is that the two challenges are different. What does this mean?
That we can extract the secret key. Mainly, we have that:
`s - s' = (c - c') * az <=> az = (s - s') / (c - c')`

Let's try to break it:
```C
unsigned char c[64], cprime[32];
// First we need to compute c, as it is not given in the ed25519 signature. This is done
// using public values.
crypto_hash_sha512_state hs;

crypto_hash_sha512_init(&hs);
crypto_hash_sha512_update(&hs, sig, 32);
crypto_hash_sha512_update(&hs, pk, 32);
crypto_hash_sha512_update(&hs, crafted_msg, 32);
crypto_hash_sha512_final(&hs, c);

crypto_core_ed25519_scalar_reduce(c, c);

// Now we simply copy the challenge into a 16 byte string
memcpy(cprime, proof + 32, 16);
memset(cprime + 16, 0, 16); // Just for sanity.


// Now we have all we need, let's extract the secret.
unsigned char cminuscprimeinv[32], extracted_skey[32], extracted_pkey[32];
crypto_core_ed25519_scalar_sub(extracted_skey, sig + 32, proof + 48);
crypto_core_ed25519_scalar_sub(cminuscprimeinv, c, cprime);
crypto_core_ed25519_scalar_invert(cminuscprimeinv, cminuscprimeinv);

crypto_core_ed25519_scalar_mul(extracted_skey, extracted_skey, cminuscprimeinv);

crypto_scalarmult_ed25519_base_noclamp(extracted_pkey, extracted_skey);
```

So now, let's create a fake ed25519 signature for message `{0}` not signed before.
We cannot use the normal API because the algorithm uses the preimage of an extension
of the key we have extracted. With the algorithm described above, we cannot access this
pre-image that the API expects. However, the 'missing' data is not necessary to forge
a signature. Goes without saying that the adversary now can create invalid VRF proofs.
```C
unsigned char nonce_fake[32], challenge[64], sig_fake[64], reduced_c[32];
crypto_hash_sha512_state hs_f;
unsigned char msg[32] = {0};

// commitment
crypto_core_ed25519_scalar_random(nonce_fake);
crypto_scalarmult_ed25519_base_noclamp(sig_fake, nonce_fake);

// challenge
crypto_hash_sha512_init(&hs_f);
crypto_hash_sha512_update(&hs_f, sig_fake, 32);
crypto_hash_sha512_update(&hs_f, extracted_pkey, 32);
crypto_hash_sha512_update(&hs_f, msg, 32);
crypto_hash_sha512_final(&hs_f, challenge);

crypto_core_ed25519_scalar_reduce(reduced_c, challenge);

// response
crypto_core_ed25519_scalar_mul(sig_fake + 32, reduced_c, extracted_skey);
crypto_core_ed25519_scalar_add(sig_fake + 32, sig_fake + 32, nonce_fake);
```

While we didn't use the exposed API to generate the fake proof, we can use the usual API
to verify it, i.e. there is no need to modify the verification algorithm in order to 
accept crafted signatures.
```C
if (crypto_sign_verify_detached(sig_fake, msg, 32, pk))
    printf("Failed to fake ed25519\n");
else
    printf("Successfully faked an ed25519 sig\n");
```

And if one runs the script (see the details in the README.md file), we can see that we successfully 
faked an ed25519 signature!
                     

## A simple way to resolve this
While we should not design cryptographic algorithms to be able to share their secret keys, we 
should acknowledge that unfortunately that is something that highly attracts engineers. One
existing proposal to solve the problem of deterministic generation of the nonce (that also caused
[problems](https://www.reddit.com/r/cryptography/comments/vextlk/40_unsafe_ed25519_libs_where_private_key_can_be/) 
in some libraries that had an incorrect API) was to combine determinism and secure
source of randomness, so that the algorithm would have a flaw only if both sources somehow 
failed.

Another very simple solution is to use a domain separation when computing the value of `k`, i.e.
using some sort of padding in the hash function (the same way it is done with the `suite_string` in
the output computation of the VRF) to ensure that there is no match between the randomness
used in VRF and that of ed25519.

Of course, the best solution, and the one suggested in this blogpost, is to not share the secret 
keys among different cryptosystems.

Thanks to my wonderful colleagues, Gamze Kilic, David Nevado and Vanishree Rao for comments and review! 

[^1]: A non-expert reader should not be concerned of what this really means. Simply
one should trust that extracting sk from pk is computationally hard and that
operations over elliptic curve points are associative and cyclic.

[^2]: A key derivation function can simply be seen as a function that, given a secret seed, derives some 
secret value in a deterministic way.
