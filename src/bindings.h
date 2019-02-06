#include <seal/seal.h>

using namespace seal;

namespace bindings 
{
  extern "C" SEALContext* SEALContext_Create(const EncryptionParameters* parms, bool expand_mod_chain);
  extern "C" KeyGenerator* KeyGenerator_Create(SEALContext* ctx);
}
