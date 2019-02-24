#include <seal/seal.h>

using namespace seal;

namespace bindings
{
  // EncryptionParameters functions
  extern "C" EncryptionParameters* EncryptionParameters_Create(int scheme);
  extern "C" void EncryptionParameters_set_poly_modulus_degree(EncryptionParameters* ep, int degree);
  extern "C" void EncryptionParameters_set_coeff_modulus(EncryptionParameters* ep, int coeff, int degree);
  extern "C" void EncryptionParameters_set_plain_modulus(EncryptionParameters* ep, int modulus);
  extern "C" const SmallModulus* EncryptionParameters_plain_modulus(EncryptionParameters* ep);

  // SEALContext functions
  extern "C" SEALContext* SEALContext_Create(const EncryptionParameters* parms, bool expand_mod_chain);
  extern "C" bool SEALContext_parameters_set(void* ctx);

  // IntegerEncoder functions
  extern "C" IntegerEncoder* IntegerEncoder_Create(SEALContext* ctx);
  extern "C" Plaintext* IntegerEncoder_encode(IntegerEncoder* ie, int value);
  extern "C" int IntegerEncoder_decode_int32(IntegerEncoder* ie, const Plaintext* pt);

  // KeyGenerator function
  extern "C" KeyGenerator* KeyGenerator_Create(SEALContext* ctx);
  extern "C" const PublicKey* KeyGenerator_public_key(KeyGenerator* kg);
  extern "C" const SecretKey* KeyGenerator_secret_key(KeyGenerator* kg);

  // Evaluator function
  extern "C" Evaluator* Evaluator_Create(SEALContext* ctx);
  extern "C" void Evaluator_negate_inplace(Evaluator* evr, Ciphertext* c1);
  extern "C" void Evaluator_add_inplace(Evaluator* evr, Ciphertext* c1, Ciphertext* c2);
  extern "C" void Evaluator_multiply_inplace(Evaluator* evr, Ciphertext* c1, Ciphertext* c2);

  // Encryptor function
  extern "C" Encryptor* Encryptor_Create(SEALContext* ctx, const PublicKey* pk);
  extern "C" Ciphertext* Encryptor_encrypt(Encryptor* enc, Plaintext* pt);

  // Decryptor function
  extern "C" Decryptor* Decryptor_Create(SEALContext* ctx, const SecretKey* sk);
  extern "C" Plaintext* Decryptor_decrypt(Decryptor* dec, Ciphertext* c1);
  extern "C" int Decryptor_invariant_noise_budget(Decryptor* dec, Ciphertext* ct);

  // Plaintext function
  extern "C" const char* Plaintext_to_string(Plaintext* pt);
}
