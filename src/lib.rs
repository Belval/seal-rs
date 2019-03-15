#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!("./bindings.rs");

extern crate libc;

use std::ffi::CStr;

#[test]
fn example_bfv_basics_i() {
    // This means to emulate https://github.com/Microsoft/SEAL/blob/master/examples/examples.cpp
    unsafe {
        let mut x: libc::c_int = 5;
        let mut y: libc::c_int = -7;
        // Building the EncryptionParameters object
        let mut ep = bindings_EncryptionParameters_Create(1);
        bindings_EncryptionParameters_set_poly_modulus_degree(ep, 2048);
        bindings_EncryptionParameters_set_coeff_modulus(ep, 128, 2048);
        bindings_EncryptionParameters_set_plain_modulus(ep, 256);

        // Construct the context
        let mut ctx = bindings_SEALContext_Create(ep, false);

        // Construct the IntegerEncoder
        let mut ie = bindings_IntegerEncoder_Create(ctx);

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

        println!("{}", nb1);

        bindings_Evaluator_negate_inplace(ev, ct1);

        let mut p4 = bindings_Decryptor_decrypt(dec, ct1);

        println!("{}", bindings_IntegerEncoder_decode_int32(ie, p4));

        println!("{}", bindings_Decryptor_invariant_noise_budget(dec, ct1));

        bindings_Evaluator_add_inplace(ev, ct1, ct2);

        let mut p5 = bindings_Decryptor_decrypt(dec, ct1);

        println!("{}", bindings_IntegerEncoder_decode_int32(ie, p5));

        println!("{}", bindings_Decryptor_invariant_noise_budget(dec, ct1));

        bindings_Evaluator_multiply_inplace(ev, ct1, ct2);

        println!("{}", bindings_Decryptor_invariant_noise_budget(dec, ct1));

        let mut p3 = bindings_Decryptor_decrypt(dec, ct1);

        //println!("{}", CStr::from_ptr(bindings_Plaintext_to_string(p3)).to_str().unwrap());

        println!("{}", bindings_IntegerEncoder_decode_int32(ie, p3));
    }
}

#[test]
fn example_bfv_basics_ii() {
    unsafe {
        // Building the EncryptionParameters object
        let mut ep = bindings_EncryptionParameters_Create(1);
        bindings_EncryptionParameters_set_poly_modulus_degree(ep, 8192);
        bindings_EncryptionParameters_set_coeff_modulus(ep, 128, 8192);
        bindings_EncryptionParameters_set_plain_modulus(ep, 1024);

        // Construct the context
        let mut ctx = bindings_SEALContext_Create(ep, false);

        // Construct the KeyGenerator to generate the public and private keys
        let mut kg = bindings_KeyGenerator_Create(ctx);

        let mut pk = bindings_KeyGenerator_public_key(kg);

        let mut sk = bindings_KeyGenerator_secret_key(kg);

        let mut enc = bindings_Encryptor_Create(ctx, pk);

        let mut ev = bindings_Evaluator_Create(ctx);

        let mut dec = bindings_Decryptor_Create(ctx, sk);

        let mut pt1 = bindings_Plaintext_Create(ctx, "1x^2 + 2x^1 + 3");
        let mut ct1 = bindings_Encryptor_encrypt(enc, pt1);

        println!("{}", bindings_Decryptor_invariant_noise_budget(dec, ct1));

        bindings_Evaluator_square_inplace(ev, ct1);

        println!("{}", bindings_Decryptor_invariant_noise_budget(dec, ct1));

        bindings_Evaluator_square_inplace(ev, ct1);

        println!("{}", bindings_Decryptor_invariant_noise_budget(dec, ct1));

        let mut pt2 = bindings_Decryptor_decrypt(dec, ct1);

        println!("{}", CStr::from_ptr(bindings_Plaintext_to_string(pt2)).to_str().unwrap());

        let mut rk60 = bindings_KeyGenerator_relin_keys(kg, 60);

        let mut ct2 = bindings_Encryptor_encrypt(enc, pt1);

        println!("{}", bindings_Decryptor_invariant_noise_budget(dec, ct2));

        bindings_Evaluator_square_inplace(ev, ct2);

        println!("{}", bindings_Decryptor_invariant_noise_budget(dec, ct2));

        bindings_Evaluator_relinearize_inplace(ev, ct2, rk60);

        println!("{}", bindings_Decryptor_invariant_noise_budget(dec, ct2));

        let mut pt3 = bindings_Decryptor_decrypt(dev, ct2);

        println!("{}", CStr::from_ptr(bindings_Plaintext_to_string(pt3)).to_str().unwrap());

        bindings_Evaluator_square_inplace(ev, ct2);

        println!("{}", bindings_Decryptor_invariant_noise_budget(dec, ct2));

        bindings_Evaluator_relinearize_inplace(ev, ct2, rk60);

        println!("{}", bindings_Decryptor_invariant_noise_budget(dec, ct2));
    }
}
