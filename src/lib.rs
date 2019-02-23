#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!("./bindings.rs");

extern crate libc;

#[test]
fn example1() {
    // This means to emulate https://github.com/Microsoft/SEAL/blob/master/examples/examples.cpp
    unsafe {
        let mut x: libc::c_int = 1;
        let mut y: libc::c_int = 2;
        // Building the EncryptionParameters object
        let mut ep = bindings_EncryptionParameters_Create(1);
        bindings_EncryptionParameters_set_poly_modulus_degree(ep, 2048);
        bindings_EncryptionParameters_set_coeff_modulus(ep, 128, 2048);
        bindings_EncryptionParameters_set_plain_modulus(ep, 256);

        // Construct the context
        let mut ctx = bindings_SEALContext_Create(ep, false);

        // Construct the IntegerEncoder
        let mut ie = bindings_IntegerEncoder_Create(2);

        // Construct the KeyGenerator to generate the public and private keys
        let mut kg = bindings_KeyGenerator_Create(ctx);

        let mut pk = bindings_KeyGenerator_public_key(kg);

        let mut sk = bindings_KeyGenerator_secret_key(kg);

        let mut enc = bindings_Encryptor_Create(ctx, pk);

        let mut ev = bindings_Evaluator_Create(ctx);

        let mut dec = bindings_Decryptor_Create(ctx, sk);

        let mut p1 = bindings_IntegerEncoder_encode(ie, x);
        let mut p2 = bindings_IntegerEncoder_encode(ie, y);

        let mut ct1 = bindings_Encryptor_encrypt(enc, p1);
        let mut ct2 = bindings_Encryptor_encrypt(enc, p2);

        let nb1 = bindings_Decryptor_invariant_noise_budget(dec, ct1);
        let nb2 = bindings_Decryptor_invariant_noise_budget(dec, ct2);

    }
}
