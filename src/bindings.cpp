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
    void* SEALContext_Create(const EncryptionParameters* parms, bool expand_mod_chain) {
        void* ctx = SEALContext::Create(*parms, expand_mod_chain).get();
        return ctx;
    }

    //bool SEALContext_parameters_set(SEALContext* ctx) {
    //    return ctx->context_data()->qualifiers().parameters_set;
    //}

    // IntegerEncoder functions
    IntegerEncoder* IntegerEncoder_Create(uint64_t sm) {
        return new IntegerEncoder(sm);
    }

    // KeyGenerator functions
    void* KeyGenerator_Create(void* ctx) {
        std::shared_ptr<SEALContext> sp_ctx(static_cast<SEALContext*>(ctx));
        bool blah = sp_ctx->parameters_set();
        return new KeyGenerator(sp_ctx);
    }

    const PublicKey* KeyGenerator_public_key(void* kg) {
        return &static_cast<KeyGenerator*>(kg)->public_key();
    }

    const SecretKey* KeyGenerator_secret_key(void* kg) {
        return &static_cast<KeyGenerator*>(kg)->secret_key();
    }
}

