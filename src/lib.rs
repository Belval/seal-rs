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
        ep.set_poly_modulus_degree(2048);
        ep.set_coeff_modulus(&seal_coeff_modulus_128(2048));
        let mut sm: seal_util_global_variables_internal_mods_SmallModulus = Default::default();
        seal_util_global_variables_internal_mods_SmallModulus_SmallModulus(&mut sm, 1 << 8);
        ep.set_plain_modulus(&mut sm);
        
        // Construct the context
        let mut ctx = bindings_SEALContext_Create(&mut ep, false);

        // Construct the IntegerEncoder
        let mut ie: seal_IntegerEncoder = Default::default();
        seal_IntegerEncoder_IntegerEncoder(&mut ie, ep.plain_modulus(), 2);

        // Construct the KeyGenerator to generate the public and private keys
        let mut kg = bindings_KeyGenerator_Create(ctx);

        let mut pk = (&*kg).public_key();

        let mut sk = (&*kg).secret_key();
    }
}
