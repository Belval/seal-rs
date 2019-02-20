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
        return SEALContext::Create(*parms, expand_mod_chain);
    }

    bool SEALContext_parameters_set(SEALContext* ctx) {
        return ctx->context_data()->qualifiers().parameters_set;
    }

    // IntegerEncoder functions
    IntegerEncoder* IntegerEncoder_Create(uint64_t sm) {
        return new IntegerEncoder(sm);
    }

    Plaintext* IntegerEncoder_encode(IntegerEncoder* ie, uint64_t value) {
        Plaintext* pt;
        ie->encode(value, *pt);
        return pt;
    }

    // KeyGenerator functions
    KeyGenerator* KeyGenerator_Create(SEALContext* ctx) {
        std::shared_ptr<SEALContext> sp_ctx(static_cast<SEALContext*>(ctx));
        return new KeyGenerator(sp_ctx);
    }

    const PublicKey* KeyGenerator_public_key(KeyGenerator* kg) {
        return &kg->public_key();
    }

    const SecretKey* KeyGenerator_secret_key(KeyGenerator* kg) {
        return &kg->secret_key();
    }

    // Evaluator functions
    Evaluator* Evaluator_Create(SEALContext* ctx) {
        std::shared_ptr<SEALContext> sp_ctx(static_cast<SEALContext*>(ctx));
        return new Evaluator(sp_ctx);
    }

    // Encryptor functions
    Encryptor* Encryptor_Create(SEALContext* ctx, const PublicKey* pk) {
        std::shared_ptr<SEALContext> sp_ctx(static_cast<SEALContext*>(ctx));
        return new Encryptor(sp_ctx, *pk);
    }

    // Decryptor functions
    Decryptor* Decryptor_Create(SEALContext* ctx, const SecretKey* sk) {
        std::shared_ptr<SEALContext> sp_ctx(static_cast<SEALContext*>(ctx));
        return new Decryptor(sp_ctx, *sk);
    }
}

