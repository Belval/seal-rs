#include "bindings.h"
#include <stdexcept>
#include <algorithm>
#include <cmath>
#include "seal/seal.h"

using namespace seal;
using namespace seal::util;

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
        ep->set_coeff_modulus(DefaultParams::coeff_modulus_128(degree));
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
    IntegerEncoder* IntegerEncoder_Create(SEALContext* ctx) {
        std::shared_ptr<SEALContext> sp_ctx(static_cast<SEALContext*>(ctx));
        return new IntegerEncoder(sp_ctx);
    }

    Plaintext* IntegerEncoder_encode(IntegerEncoder* ie, int value) {
        Plaintext* pt = new Plaintext();
        ie->encode(value, *pt);
        return pt;
    }

    int IntegerEncoder_decode_int32(IntegerEncoder* ie, const Plaintext* pt) {
        return ie->decode_int32(*pt);
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

    RelinKeys* KeyGenerator_relin_keys(KeyGenerator* kg, int decomposition_bit_count, int count = 1) {
        return &kg->relin_keys(decomposition_bit_count, count);
    }

    // Evaluator functions
    Evaluator* Evaluator_Create(SEALContext* ctx) {
        std::shared_ptr<SEALContext> sp_ctx(static_cast<SEALContext*>(ctx));
        return new Evaluator(sp_ctx);
    }

    void Evaluator_negate_inplace(Evaluator* evr, Ciphertext* c1) {
        evr->negate_inplace(*c1);
    }

    void Evaluator_add_inplace(Evaluator* evr, Ciphertext* c1, Ciphertext* c2) {
        evr->add_inplace(*c1, *c2);
    }

    void Evaluator_multiply_inplace(Evaluator* evr, Ciphertext* c1, Ciphertext* c2) {
        evr->multiply_inplace(*c1, *c2);
    }

    void Evaluator_square_inplace(Evaluator* evr, Ciphertext* c1) {
        evr->square_inplace(*c1);
    }

    // Encryptor functions
    Encryptor* Encryptor_Create(SEALContext* ctx, const PublicKey* pk) {
        std::shared_ptr<SEALContext> sp_ctx(static_cast<SEALContext*>(ctx));
        return new Encryptor(sp_ctx, *pk);
    }

    Ciphertext* Encryptor_encrypt(Encryptor* enc, Plaintext* pt) {
        Ciphertext* ct = new Ciphertext();
        enc->encrypt(*pt, *ct);
        return ct;
    }

    // Decryptor functions
    Decryptor* Decryptor_Create(SEALContext* ctx, const SecretKey* sk) {
        std::shared_ptr<SEALContext> sp_ctx(static_cast<SEALContext*>(ctx));
        return new Decryptor(sp_ctx, *sk);
    }

    Plaintext* Decryptor_decrypt(Decryptor* dec, Ciphertext* c1) {
        Plaintext* pt = new Plaintext();
        dec->decrypt(*c1, *pt);
        return pt;
    }

    int Decryptor_invariant_noise_budget(Decryptor* dec, Ciphertext* ct) {
        return dec->invariant_noise_budget(*ct);
    }

    // Plaintext functions
    Plaintext* Plaintext_Create(const char* hex_poly) {
        std::string str_hex_poly(hex_poly);
        return new Plaintext(str_hex_poly);
    }

    const char* Plaintext_to_string(Plaintext* pt) {
        return pt->to_string().c_str();
    }
}

