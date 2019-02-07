#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!("./bindings.rs");


#[test]
fn example1() {
    // This means to emulate https://github.com/Microsoft/SEAL/blob/master/examples/examples.cpp
    unsafe {
        // Building the EncryptionParameters object
        let mut ep = bindings_EncryptionParameters_Create(1);
        bindings_EncryptionParameters_set_poly_modulus_degree(ep, 2048);
        bindings_EncryptionParameters_set_coeff_modulus(ep, 128, 2048);
        bindings_EncryptionParameters_set_plain_modulus(ep, 256);

        // Construct the context
        let mut ctx = bindings_SEALContext_Create(ep, false);

        // Construct the IntegerEncoder
        //let mut ie: seal_IntegerEncoder = Default::default();
        //seal_IntegerEncoder_IntegerEncoder(&mut ie, ep.plain_modulus(), 2);

        // Construct the KeyGenerator to generate the public and private keys
        //let mut kg: seal_KeyGenerator = Default::default();
        //let mut kg = bindings_KeyGenerator_Create(&mut kg, &mut ctx);

        //let mut pk = (&*kg).public_key();

        //let mut sk = (&*kg).secret_key();
    }
}
