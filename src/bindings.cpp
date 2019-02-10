#include "bindings.h"

#include <seal/seal.h>

using namespace seal;

namespace bindings
{
    // EncryptionParameters functions
    EncryptionParameters* EncryptionParameters_Create(int scheme) {
        return new EncryptionParameters((scheme_type)scheme);
    }
    void EncryptionParameters_set_poly_modulus_degree(EncryptionParameters* ep, int degree) {
        ep->set_poly_modulus_degree(degree);
    }
    void EncryptionParameters_set_coeff_modulus(EncryptionParameters* ep, int coeff, int degree) {
        ep->set_coeff_modulus(coeff_modulus_128(degree));
    }
    void EncryptionParameters_set_plain_modulus(EncryptionParameters* ep, int modulus) {
        ep->set_plain_modulus(modulus);
    }
    const SmallModulus* EncryptionParameters_plain_modulus(EncryptionParameters* ep) {
        return &ep->plain_modulus();
    }


    // SEALContext functions
    SEALContext* SEALContext_Create(const EncryptionParameters* parms, bool expand_mod_chain) {
        return SEALContext::Create(*parms, expand_mod_chain).get();
    }

    bool SEALContext_parameters_set(SEALContext* ctx) {
        return ctx->context_data()->qualifiers().parameters_set;
    }

    // IntegerEncoder functions
    IntegerEncoder* IntegerEncoder_Create(uint64_t sm) {
        return new IntegerEncoder(sm);
    }

    // KeyGenerator functions
    void KeyGenerator_Create(KeyGenerator* kg, SEALContext* ctx) {
        kg = new KeyGenerator(std::shared_ptr<SEALContext>(ctx));
    }

    const PublicKey* KeyGenerator_public_key(KeyGenerator* kg) {
        return &kg->public_key();
    }

    const SecretKey* KeyGenerator_private_key(KeyGenerator* kg) {
        return &kg->secret_key();
    }
}

