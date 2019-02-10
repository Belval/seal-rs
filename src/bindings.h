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
  extern "C" void KeyGenerator_Create(KeyGenerator* kg, SEALContext* ctx);
  extern "C" bool SEALContext_parameters_set(SEALContext* ctx);

  // IntegerEncoder functions
  extern "C" IntegerEncoder* IntegerEncoder_Create(uint64_t sm);

  // KeyGenerator function
  extern "C" KeyGenerator* KeyGenerator_Create(SEALContext* ctx);
  extern "C" const PublicKey* KeyGenerator_public_key(KeyGenerator* kg);
  extern "C" const SecretKey* KeyGenerator_secret_key(KeyGenerator* kg);
}
