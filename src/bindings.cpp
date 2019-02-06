#include "bindings.h"

#include <seal/seal.h>

using namespace seal;

namespace bindings 
{
    SEALContext* SEALContext_Create(const EncryptionParameters* parms, bool expand_mod_chain) {
        return SEALContext::Create(*parms, expand_mod_chain).get();
    }

    KeyGenerator* KeyGenerator_Create(SEALContext* ctx) {
        return new KeyGenerator(std::shared_ptr<SEALContext>(ctx));
    }
}

