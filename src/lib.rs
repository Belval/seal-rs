#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!("./bindings.rs");

    
#[test]
fn example1() {
    // This means to emulate https://github.com/Microsoft/SEAL/blob/master/examples/examples.cpp
    unsafe {
        // Building the EncryptionParameters object
        let mut ep: seal_EncryptionParameters = Default::default();
        seal_EncryptionParameters_EncryptionParameters(&mut ep, seal_scheme_type_BFV);
        // ep.set_poly_modulus_degree(2048);
        // ep.set_coeff_modulus(coeff_modulus_128(2048));
        // ep.set_plain_modulus(1 << 8);

        // // Construct the context
        // let mut ctx = seal_SEALContext_Create(ep);

        // // Construct the IntegerEncoder
        // let mut ie = seal_IntegerEncoder::Default();
        // seal_IntegerEncoder_IntegerEncoder(&mut ie, ep.plain_modulus());

        // // Construct the KeyGenerator to generate the public and private keys
        // let mut kg = seal_KeyGenerator::Default();
        // seal_KeyGenerator_KeyGenerator(&mut kg, &mut ctx);

        // let mut pk = kg.public_key();

        // let mut sk = kg.secret_key();
    }
}
