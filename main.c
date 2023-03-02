#include <stdio.h>
#include <string.h>
#include <sodium.h>

int main() {
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    const unsigned char seed[32] = {0};
    crypto_sign_seed_keypair(pk, sk, seed);

#define MESSAGE (const unsigned char *) "yup"
#define MESSAGE_LEN 3
    const unsigned char crafted_msg[32] = {151, 29, 3, 237, 140, 141, 180, 68, 126, 104, 194, 24, 227, 99, 6, 107, 249, 58, 71, 1, 5, 251, 110, 97, 245, 246, 79, 160, 87, 196, 222, 197};
    const unsigned char nonce[32] = {192, 120, 101, 190, 122, 145, 135, 203, 206, 241, 255, 71, 69, 183, 34, 147, 23, 215, 237, 82, 85, 205, 242, 82, 247, 44, 49, 58, 98, 176, 187, 13};

    unsigned char sig[crypto_sign_BYTES];

    crypto_sign_detached(sig, NULL, crafted_msg, 32, sk);

    if (crypto_sign_verify_detached(sig, crafted_msg, 32, pk))
        printf("failed on ed25519 generation");

    // Now we should have a 64 bytes signature that corresponds to:
    // * first 32 bytes represent the point R = k * G, where k = H(z || m)
    // where z = H(sk)[32..]
    // * second 32 bytes represent a scalar s = k + az * HRAM
    // where HRAM = H(R || pk || m), and az = H(sk)[..32]


    // Now let's use the same keys for vrf generation
    unsigned char proof[80];
    crypto_vrf_ietfdraft03_prove(proof, sk, MESSAGE, MESSAGE_LEN);
    // Now, we have a proof that consists of 80 bytes that correspond to:
    // * 32 bytes of an EC point that we can ignore
    // * 16 bytes of a challenge C = H(pk, H, Gamma, U, V), where the values
    // of H, Gamma, U and V are irrelevant.
    // * 32 bytes of a scalar s' = k + C' * az
    // where k = H(z || m), with z equal to above, and az as well.

    unsigned char random_output[64];
    if (crypto_vrf_ietfdraft03_verify(random_output, pk, proof, MESSAGE, MESSAGE_LEN))
        printf("failed VRF\n \n");


    // What is the problem here? That the two challenges are different. What does this mean?
    // That we can extract the secret key. Mainly, we have that:
    // s - s' = (c - c') * az <=> az = (s - s') / (c - c')

    // Let's try to break it:

    unsigned char c[64], cprime[64], s[32], sprime[32];
    // First we need to compute c.
    crypto_hash_sha512_state hs;

    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, sig, 32);
    crypto_hash_sha512_update(&hs, pk, 32);
    crypto_hash_sha512_update(&hs, crafted_msg, 32);
    crypto_hash_sha512_final(&hs, c);

    crypto_core_ed25519_scalar_reduce(c, c);

    memcpy(s, sig + 32, 32);
    memcpy(cprime, proof + 32, 16);
    memset(cprime + 16, 0, 48); // Just for sanity, probably they're still zeroes.
    memcpy(sprime, proof + 48, 32);

    // Now we have all we need, let's extract the secret.
    unsigned char sminussprime[32], cminuscprime[32], cminuscprimeinv[32], extracted_skey[32], extracted_pkey[32];
    crypto_core_ed25519_scalar_sub(sminussprime, s, sprime);
    crypto_core_ed25519_scalar_sub(cminuscprime, c, cprime);
    crypto_core_ed25519_scalar_invert(cminuscprimeinv, cminuscprime);

    crypto_core_ed25519_scalar_mul(extracted_skey, cminuscprimeinv, sminussprime);

    printf("extr_skey: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", extracted_skey[i]);
    }
    printf("\n");

    crypto_scalarmult_ed25519_base_noclamp(extracted_pkey, extracted_skey);

    printf("extr_pkey: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", extracted_pkey[i]);
    }
    printf("\n");


    // So now, let's create a fake ed25519 signature for message {0} [not signed before]
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
        printf("failed to fake ed25519\n");
    else
        printf("successfully faked an ed25519 sig\n");

    printf("Hello, World!\n");
    return 0;
}