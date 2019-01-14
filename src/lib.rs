#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!("./bindings.rs");

mod tests {
    #[test]
    fn example1() {
        // This means to emulate https://github.com/Microsoft/SEAL/blob/master/examples/examples.cpp
        seal_EncryptionParameters parms(seal_scheme_type_BFV);
    }
}
