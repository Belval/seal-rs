#include <seal/seal.h>

using namespace seal;

namespace bindings 
{
  extern "C" SEALContext* SEALContext_Create(const EncryptionParameters* parms, bool expand_mod_chain) {
    return SEALContext::Create(*parms, expand_mod_chain).get();
  }
}