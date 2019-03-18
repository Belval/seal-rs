#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!("./bindings.rs");

extern crate libc;

use std::ffi::CStr;
use std::ffi::CString;

#[test]
fn example_bfv_basics_i() {
    // This means to emulate https://github.com/Microsoft/SEAL/blob/master/examples/examples.cpp
    unsafe {
        println!("Example: BFV Basics I");

        /*
        In this example we demonstrate setting up encryption parameters and other 
        relevant objects for performing simple computations on encrypted integers.
        Microsoft SEAL implements two encryption schemes: the Brakerski/Fan-Vercauteren (BFV) 
        scheme and the Cheon-Kim-Kim-Song (CKKS) scheme. In the first examples we 
        use the BFV scheme as it is far easier to understand and use than CKKS. For 
        more details on the basics of the BFV scheme, we refer the reader to the
        original paper https://eprint.iacr.org/2012/144. In truth, to achieve good 
        performance Microsoft SEAL implements the "FullRNS" optimization as described in 
        https://eprint.iacr.org/2016/510, but this optimization is invisible to 
        the user and has no security implications. We will discuss the CKKS scheme
        in later examples.
        The first task is to set up an instance of the EncryptionParameters class.
        It is critical to understand how these different parameters behave, how they
        affect the encryption scheme, performance, and the security level. There are 
        three encryption parameters that are necessary to set: 
            - poly_modulus_degree (degree of polynomial modulus);
            - coeff_modulus ([ciphertext] coefficient modulus);
            - plain_modulus (plaintext modulus).
        A fourth parameter -- noise_standard_deviation -- has a default value 3.20 
        and should not be necessary to modify unless the user has a specific reason 
        to do so and has an in-depth understanding of the security implications.
        A fifth parameter -- random_generator -- can be set to use customized random
        number generators. By default, Microsoft SEAL uses hardware-based AES in counter mode
        for pseudo-randomness with key generated using std::random_device. If the 
        AES-NI instruction set is not available, all randomness is generated from 
        std::random_device. Most academic users in particular should have little 
        reason to change this.
        The BFV scheme cannot perform arbitrary computations on encrypted data. 
        Instead, each ciphertext has a specific quantity called the `invariant noise 
        budget' -- or `noise budget' for short -- measured in bits. The noise budget 
        in a freshly encrypted ciphertext (initial noise budget) is determined by 
        the encryption parameters. Homomorphic operations consume the noise budget 
        at a rate also determined by the encryption parameters. In BFV the two basic 
        operations allowed on encrypted data are additions and multiplications, of 
        which additions can generally be thought of as being nearly free in terms of 
        noise budget consumption compared to multiplications. Since noise budget 
        consumption compounds in sequential multiplications, the most significant 
        factor in choosing appropriate encryption parameters is the multiplicative 
        depth of the arithmetic circuit that the user wants to evaluate on encrypted
        data. Once the noise budget of a ciphertext reaches zero it becomes too 
        corrupted to be decrypted. Thus, it is essential to choose the parameters to 
        be large enough to support the desired computation; otherwise the result is 
        impossible to make sense of even with the secret key.
        */
        let mut ep = bindings_EncryptionParameters_Create(1);

        /*
        The first parameter we set is the degree of the polynomial modulus. This must
        be a positive power of 2, representing the degree of a power-of-2 cyclotomic 
        polynomial; it is not necessary to understand what this means. The polynomial 
        modulus degree should be thought of mainly affecting the security level of the 
        scheme: larger degree makes the scheme more secure. Larger degree also makes 
        ciphertext sizes larger, and consequently all operations slower. Recommended 
        degrees are 1024, 2048, 4096, 8192, 16384, 32768, but it is also possible to 
        go beyond this. In this example we use a relatively small polynomial modulus.
        */
        bindings_EncryptionParameters_set_poly_modulus_degree(ep, 2048);

        /*
        Next we set the [ciphertext] coefficient modulus (coeff_modulus). The size 
        of the coefficient modulus should be thought of as the most significant 
        factor in determining the noise budget in a freshly encrypted ciphertext: 
        bigger means more noise budget, which is desirable. On the other hand, 
        a larger coefficient modulus lowers the security level of the scheme. Thus, 
        if a large noise budget is required for complicated computations, a large 
        coefficient modulus needs to be used, and the reduction in the security 
        level must be countered by simultaneously increasing the polynomial modulus. 
        Overall, this will result in worse performance.
        
        To make parameter selection easier for the user, we have constructed sets 
        of largest safe coefficient moduli for 128-bit and 192-bit security levels
        for different choices of the polynomial modulus. These default parameters 
        follow the recommendations in the Security Standard Draft available at 
        http://HomomorphicEncryption.org. The security estimates are a complicated
        topic and we highly recommend consulting with experts in the field when 
        selecting parameters. 
        Our recommended values for the coefficient modulus can be easily accessed 
        through the functions 
            
            DefaultParams::coeff_modulus_128(int)
            DefaultParams::coeff_modulus_192(int)
            DefaultParams::coeff_modulus_256(int)
        for 128-bit, 192-bit, and 256-bit security levels. The integer parameter is 
        the degree of the polynomial modulus used.
        
        In Microsoft SEAL the coefficient modulus is a positive composite number -- 
        a product of distinct primes of size up to 60 bits. When we talk about the size 
        of the coefficient modulus we mean the bit length of the product of the primes. 
        The small primes are represented by instances of the SmallModulus class so for
        example DefaultParams::coeff_modulus_128(int) returns a vector of SmallModulus 
        instances. 
        
        It is possible for the user to select their own small primes. Since Microsoft 
        SEAL uses the Number Theoretic Transform (NTT) for polynomial multiplications 
        modulo the factors of the coefficient modulus, the factors need to be prime 
        numbers congruent to 1 modulo 2*poly_modulus_degree. We have generated a list 
        of such prime numbers of various sizes that the user can easily access through 
        the functions 
        
            DefaultParams::small_mods_60bit(int)
            DefaultParams::small_mods_50bit(int)
            DefaultParams::small_mods_40bit(int)
            DefaultParams::small_mods_30bit(int)
        
        each of which gives access to an array of primes of the denoted size. These 
        primes are located in the source file util/globals.cpp. Again, please keep 
        in mind that the choice of coeff_modulus has a dramatic effect on security 
        and should almost always be obtained through coeff_modulus_xxx(int).
        Performance is mainly affected by the size of the polynomial modulus, and 
        the number of prime factors in the coefficient modulus; hence in some cases
        it can be important to use as few prime factors in the coefficient modulus 
        as possible.
        In this example we use the default coefficient modulus for a 128-bit security
        level. Concretely, this coefficient modulus consists of only one 54-bit prime 
        factor: 0x3fffffff000001.
        */
        bindings_EncryptionParameters_set_coeff_modulus(ep, 128, 2048);

        /*
        The plaintext modulus can be any positive integer, even though here we take 
        it to be a power of two. In fact, in many cases one might instead want it 
        to be a prime number; we will see this in later examples. The plaintext 
        modulus determines the size of the plaintext data type but it also affects 
        the noise budget in a freshly encrypted ciphertext and the consumption of
        noise budget in homomorphic (encrypted) multiplications. Thus, it is 
        essential to try to keep the plaintext data type as small as possible for 
        best performance. The noise budget in a freshly encrypted ciphertext is 
        
            ~ log2(coeff_modulus/plain_modulus) (bits)
        and the noise budget consumption in a homomorphic multiplication is of the 
        form log2(plain_modulus) + (other terms).
        */
        bindings_EncryptionParameters_set_plain_modulus(ep, 256);

        /*
        Now that all parameters are set, we are ready to construct a SEALContext 
        object. This is a heavy class that checks the validity and properties of the 
        parameters we just set and performs several important pre-computations.
        */
        let mut ctx = bindings_SEALContext_Create(ep, false);

        /*
        Plaintexts in the BFV scheme are polynomials with coefficients integers 
        modulo plain_modulus. This is not a very practical object to encrypt: much
        more useful would be encrypting integers or floating point numbers. For this
        we need an `encoding scheme' to convert data from integer representation to
        an appropriate plaintext polynomial representation than can subsequently be 
        encrypted. Microsoft SEAL comes with a few basic encoders for the BFV scheme:
        [IntegerEncoder]
        The IntegerEncoder encodes integers to plaintext polynomials as follows. 
        First, a binary expansion of the integer is computed. Next, a polynomial is
        created with the bits as coefficients. For example, the integer 
        
            26 = 2^4 + 2^3 + 2^1
        
        is encoded as the polynomial 1x^4 + 1x^3 + 1x^1. Conversely, plaintext
        polynomials are decoded by evaluating them at x=2. For negative numbers the
        IntegerEncoder simply stores all coefficients as either 0 or -1, where -1 is
        represented by the unsigned integer plain_modulus - 1 in memory.
        Since encrypted computations operate on the polynomials rather than on the
        encoded integers themselves, the polynomial coefficients will grow in the
        course of such computations. For example, computing the sum of the encrypted
        encoded integer 26 with itself will result in an encrypted polynomial with
        larger coefficients: 2x^4 + 2x^3 + 2x^1. Squaring the encrypted encoded
        integer 26 results also in increased coefficients due to cross-terms, namely,
        
            (1x^4 + 1x^3 + 1x^1)^2 = 1x^8 + 2x^7 + 1x^6 + 2x^5 + 2x^4 + 1x^2; 
        
        further computations will quickly increase the coefficients much more. 
        Decoding will still work correctly in this case (evaluating the polynomial 
        at x=2), but since the coefficients of plaintext polynomials are really 
        integers modulo plain_modulus, implicit reduction modulo plain_modulus may 
        yield unexpected results. For example, adding 1x^4 + 1x^3 + 1x^1 to itself 
        plain_modulus many times will result in the constant polynomial 0, which is 
        clearly not equal to 26 * plain_modulus. It can be difficult to predict when 
        such overflow will take place especially when computing several sequential
        multiplications. BatchEncoder (discussed later) makes it easier to predict 
        encoding overflow conditions but has a stronger restriction on the size of 
        the numbers it can encode. 
        The IntegerEncoder is easy to understand and use for simple computations, 
        and can be a good starting point to learning Microsoft SEAL. However, 
        advanced users will probably prefer more efficient approaches, such as the 
        BatchEncoder or the CKKSEncoder (discussed later).
        [BatchEncoder]
        If plain_modulus is a prime congruent to 1 modulo 2*poly_modulus_degree, the 
        plaintext elements can be viewed as 2-by-(poly_modulus_degree / 2) matrices
        with elements integers modulo plain_modulus. When a desired computation can 
        be vectorized, using BatchEncoder can result in a massive performance boost
        over naively encrypting and operating on each input number separately. Thus, 
        in more complicated computations this is likely to be by far the most 
        important and useful encoder. In example_bfv_basics_iii() we show how to
        operate on encrypted matrix plaintexts.
        In this example we use the IntegerEncoder due to its simplicity. 
        */
        let mut ie = bindings_IntegerEncoder_Create(ctx);

        /*
        We are now ready to generate the secret and public keys. For this purpose 
        we need an instance of the KeyGenerator class. Constructing a KeyGenerator 
        automatically generates the public and secret key, which can then be read to 
        local variables.
        */
        let mut kg = bindings_KeyGenerator_Create(ctx);
        let mut pk = bindings_KeyGenerator_public_key(kg);
        let mut sk = bindings_KeyGenerator_secret_key(kg);

        /*
        To be able to encrypt we need to construct an instance of Encryptor. Note 
        that the Encryptor only requires the public key, as expected.
        */
        let mut enc = bindings_Encryptor_Create(ctx, pk);

        /*
        Computations on the ciphertexts are performed with the Evaluator class. In
        a real use-case the Evaluator would not be constructed by the same party 
        that holds the secret key.
        */
        let mut ev = bindings_Evaluator_Create(ctx);

        /*
        We will of course want to decrypt our results to verify that everything worked,
        so we need to also construct an instance of Decryptor. Note that the Decryptor
        requires the secret key.
        */
        let mut dec = bindings_Decryptor_Create(ctx, sk);

        /*
        We start by encoding two integers as plaintext polynomials.
        */
        let mut x: libc::c_int = 5;
        let mut p1 = bindings_IntegerEncoder_encode(ie, x);

        let mut y: libc::c_int = -7;
        let mut p2 = bindings_IntegerEncoder_encode(ie, y);

        /*
        Encrypting the encoded values is easy.
        */
        let mut ct1 = bindings_Encryptor_encrypt(enc, p1);
        let mut ct2 = bindings_Encryptor_encrypt(enc, p2);

        /*
        To illustrate the concept of noise budget, we print the budgets in the fresh 
        encryptions.
        */
        println!("Noise budget in ct1: {} bits",
                 bindings_Decryptor_invariant_noise_budget(dec, ct1));
        println!("Noise budget in ct2: {} bits",
                 bindings_Decryptor_invariant_noise_budget(dec, ct2));

        /*
        As a simple example, we compute (-encrypted1 + encrypted2) * encrypted2. Most 
        basic arithmetic operations come as in-place two-argument versions that
        overwrite the first argument with the result, and as three-argument versions
        taking as separate destination parameter. In most cases the in-place variants
        are slightly faster.
        */

        /*
        Negation is a unary operation and does not consume any noise budget.
        */
        bindings_Evaluator_negate_inplace(ev, ct1);
        println!("Noise budget in -ct1: {} bits",
                 bindings_Decryptor_invariant_noise_budget(dec, ct1));

        /*
        Compute the sum of ct1 and ct2; the sum overwrites ct1.
        */
        bindings_Evaluator_add_inplace(ev, ct1, ct2);

        /*
        Addition sets the noise budget to the minimum of the input noise budgets. 
        In this case both inputs had roughly the same budget going in, so the output 
        (in encrypted1) has just a slightly lower budget. Depending on probabilistic 
        effects the noise growth consumption may or may not be visible when measured 
        in whole bits.
        */
        println!("Noise bugdget in -ct1 + ct2: {} bits",
                 bindings_Decryptor_invariant_noise_budget(dec, ct1));

        /*
        Finally multiply with encrypted2. Again, we use the in-place version of the
        function, overwriting encrypted1 with the product.
        */
        bindings_Evaluator_multiply_inplace(ev, ct1, ct2);

        /*
        Multiplication consumes a lot of noise budget. This is clearly seen in the
        print-out. The user can change the plain_modulus to see its effect on the
        rate of noise budget consumption.
        */
        println!("Noise budget in (-ct1 + ct2) * ct2: {} bits",
                 bindings_Decryptor_invariant_noise_budget(dec, ct1));

        /*
        Now we decrypt and decode our result.
        */
        let mut p3 = bindings_Decryptor_decrypt(dec, ct1);

        /*
        Decode to obtain an integer result.
        */
        println!("Decoded integer: {}", bindings_IntegerEncoder_decode_int32(ie, p3));
    }
}

#[test]
fn example_bfv_basics_ii() {
    unsafe {
        println!("Example: BFV Basics II");

        /*
        In this example we explain what relinearization is, how to use it, and how 
        it affects noise budget consumption. Relinearization is used both in the BFV
        and the CKKS schemes but in this example (for the sake of simplicity) we 
        again focus on BFV.
        First we set the parameters, create a SEALContext, and generate the public
        and secret keys. We use slightly larger parameters than before to be able to 
        do more homomorphic multiplications.
        */
        let mut ep = bindings_EncryptionParameters_Create(1);
        bindings_EncryptionParameters_set_poly_modulus_degree(ep, 8192);

        /*
        The default coefficient modulus consists of the following primes:
            0x7fffffff380001,  0x7ffffffef00001,
            0x3fffffff000001,  0x3ffffffef40001
        The total size is 218 bits.
        */
        bindings_EncryptionParameters_set_coeff_modulus(ep, 128, 8192);
        bindings_EncryptionParameters_set_plain_modulus(ep, 1024);

        let mut ctx = bindings_SEALContext_Create(ep, false);

        /*
        We generate the public and secret keys as before. 
        There are actually two more types of keys in Microsoft SEAL: `relinearization keys' 
        and `Galois keys'. In this example we will discuss relinearization keys, and 
        Galois keys will be discussed later in example_bfv_basics_iii().
        */
        let mut kg = bindings_KeyGenerator_Create(ctx);
        let mut pk = bindings_KeyGenerator_public_key(kg);
        let mut sk = bindings_KeyGenerator_secret_key(kg);

        /*
        We also set up an Encryptor, Evaluator, and Decryptor here. We will
        encrypt polynomials directly in this example, so there is no need for
        an encoder.
        */
        let mut enc = bindings_Encryptor_Create(ctx, pk);
        let mut ev = bindings_Evaluator_Create(ctx);
        let mut dec = bindings_Decryptor_Create(ctx, sk);

        /*
        We can easily construct a plaintext polynomial from a string. Again, note 
        how there is no need for encoding since the BFV scheme natively encrypts
        polynomials.
        */
        let mut pt1 = bindings_Plaintext_Create(CString::new("1x^2 + 2x^1 + 3").expect("Something happened").as_ptr());
        let mut ct1 = bindings_Encryptor_encrypt(enc, pt1);

        /*
        In Microsoft SEAL, a valid ciphertext consists of two or more polynomials whose 
        coefficients are integers modulo the product of the primes in coeff_modulus. 
        The current size of a ciphertext can be found using Ciphertext::size().
        A freshly encrypted ciphertext always has size 2.
        */
        println!("Size of fresh encryption: {}", bindings_Ciphertext_size(ct1));
        println!("Noise budget in fresh encryption: {} bits", bindings_Decryptor_invariant_noise_budget(dec, ct1));

        /*
        Homomorphic multiplication results in the output ciphertext growing in size. 
        More precisely, if the input ciphertexts have size M and N, then the output 
        ciphertext after homomorphic multiplication will have size M+N-1. In this
        case we square encrypted twice to observe this growth (also observe noise
        budget consumption).
        */
        bindings_Evaluator_square_inplace(ev, ct1);

        println!("Size after squaring: {}", bindings_Ciphertext_size(ct1));
        println!("Noise budget after squaring: {}", bindings_Decryptor_invariant_noise_budget(dec, ct1));

        bindings_Evaluator_square_inplace(ev, ct1);

        println!("Size after second squaring: {}", bindings_Ciphertext_size(ct1));
        println!("Noise budget after second squaring: {}", bindings_Decryptor_invariant_noise_budget(dec, ct1));

        /*
        It does not matter that the size has grown -- decryption works as usual.
        Observe from the print-out that the coefficients in the plaintext have grown 
        quite large. One more squaring would cause some of them to wrap around the
        plain_modulus (0x400) and as a result we would no longer obtain the expected 
        result as an integer-coefficient polynomial. We can fix this problem to some 
        extent by increasing plain_modulus. This makes sense since we still have 
        plenty of noise budget left.
        */
        let mut pt2 = bindings_Decryptor_decrypt(dec, ct1);

        println!("Fourth power: {}", CStr::from_ptr(bindings_Plaintext_to_string(pt2)).to_str().unwrap());

        /*
        The problem here is that homomorphic operations on large ciphertexts are
        computationally much more costly than on small ciphertexts. Specifically,
        homomorphic multiplication on input ciphertexts of size M and N will require 
        O(M*N) polynomial multiplications to be performed, and an addition will
        require O(M+N) additions. Relinearization reduces the size of ciphertexts
        after multiplication back to the initial size (2). Thus, relinearizing one
        or both inputs before the next multiplication or e.g. before serializing the
        ciphertexts, can have a huge positive impact on performance.
        Another problem is that the noise budget consumption in multiplication is
        bigger when the input ciphertexts sizes are bigger. In a complicated
        computation the contribution of the sizes to the noise budget consumption
        can actually become the dominant term. We will point this out again below
        once we get to our example.
        Relinearization itself has both a computational cost and a noise budget cost.
        These both depend on a parameter called `decomposition bit count', which can
        be any integer at least 1 [dbc_min()] and at most 60 [dbc_max()]. A large
        decomposition bit count makes relinearization fast, but consumes more noise
        budget. A small decomposition bit count can make relinearization slower, but 
        might not change the noise budget by any observable amount.
        Relinearization requires a special type of key called `relinearization keys'.
        These can be created by the KeyGenerator for any decomposition bit count.
        To relinearize a ciphertext of size M >= 2 back to size 2, we actually need 
        M-2 relinearization keys. Attempting to relinearize a too large ciphertext 
        with too few relinearization keys will result in an exception being thrown.
        We repeat our computation, but this time relinearize after both squarings.
        Since our ciphertext never grows past size 3 (we relinearize after every
        multiplication), it suffices to generate only one relinearization key. This
        (relinearizing after every multiplication) should be the preferred approach 
        in almost all cases.
        First, we need to create relinearization keys. We use a decomposition bit 
        count of 16 here, which should be thought of as very small.
        This function generates one single relinearization key. Another overload 
        of KeyGenerator::relin_keys takes the number of keys to be generated as an 
        argument, but one is all we need in this example (see above).
        */
        let mut rk16 = bindings_KeyGenerator_relin_keys(kg, 16, 1);

        let mut ct2 = bindings_Encryptor_encrypt(enc, pt1);

        println!("Size of fresh encryption: {}", bindings_Ciphertext_size(ct2));
        println!("Noise budget in fresh encryption: {} bits", bindings_Decryptor_invariant_noise_budget(dec, ct2));

        bindings_Evaluator_square_inplace(ev, ct2);

        println!("Size after squaring: {}", bindings_Ciphertext_size(ct2));
        println!("Noise budget after squaring: {}", bindings_Decryptor_invariant_noise_budget(dec, ct2));

        bindings_Evaluator_relinearize_inplace(ev, ct2, rk16);

        println!("Size after relinearization: {}", bindings_Ciphertext_size(ct2));
        println!("Noise budget after relinearization (dbc = 16): {}", bindings_Decryptor_invariant_noise_budget(dec, ct2));

        bindings_Evaluator_square_inplace(ev, ct2);

        println!("Size after second squaring: {}", bindings_Ciphertext_size(ct2));
        println!("Noise budget after second squaring: {}", bindings_Decryptor_invariant_noise_budget(dec, ct2));

        bindings_Evaluator_relinearize_inplace(ev, ct2, rk16);
        
        println!("Size after relinearization: {}", bindings_Ciphertext_size(ct2));
        println!("Noise budget after relinearization (dbc = 16): {}", bindings_Decryptor_invariant_noise_budget(dec, ct2));

        let mut pt3 = bindings_Decryptor_decrypt(dec, ct2);

        println!("Fourth power: {}", CStr::from_ptr(bindings_Plaintext_to_string(pt3)).to_str().unwrap());

        /*
        Of course the result is still the same, but this time we actually used less 
        of our noise budget. This is not surprising for two reasons:
        
            - We used a very small decomposition bit count, which is why
            relinearization itself did not consume the noise budget by any
            observable amount;
            - Since our ciphertext sizes remain small throughout the two
            squarings, the noise budget consumption rate in multiplication
            remains as small as possible. Recall from above that operations
            on larger ciphertexts actually cause more noise growth.
        To make things more clear, we repeat the computation a third time, now using 
        the largest possible decomposition bit count (60). We are not measuring
        running time here, but relinearization with relin_keys60 (below) is much 
        faster than with relin_keys16.
        */
        let mut rk60 = bindings_KeyGenerator_relin_keys(kg, 60, 1);

        let mut ct3 = bindings_Encryptor_encrypt(enc, pt1);

        println!("Size of fresh encryption: {}", bindings_Ciphertext_size(ct3));
        println!("Noise budget in fresh encryption: {} bits", bindings_Decryptor_invariant_noise_budget(dec, ct3));

        bindings_Evaluator_square_inplace(ev, ct3);

        println!("Size after squaring: {}", bindings_Ciphertext_size(ct3));
        println!("Noise budget after squaring: {}", bindings_Decryptor_invariant_noise_budget(dec, ct3));

        bindings_Evaluator_relinearize_inplace(ev, ct3, rk60);

        println!("Size after relinearization: {}", bindings_Ciphertext_size(ct3));
        println!("Noise budget after relinearization (dbc = 60): {}", bindings_Decryptor_invariant_noise_budget(dec, ct3));

        bindings_Evaluator_square_inplace(ev, ct3);

        println!("Size after second squaring: {}", bindings_Ciphertext_size(ct3));
        println!("Noise budget after second squaring: {}", bindings_Decryptor_invariant_noise_budget(dec, ct3));

        bindings_Evaluator_relinearize_inplace(ev, ct3, rk60);
        
        println!("Size after relinearization: {}", bindings_Ciphertext_size(ct3));
        println!("Noise budget after relinearization (dbc = 60): {}", bindings_Decryptor_invariant_noise_budget(dec, ct3));

        let mut pt3 = bindings_Decryptor_decrypt(dec, ct3);

        println!("Fourth power: {}", CStr::from_ptr(bindings_Plaintext_to_string(pt3)).to_str().unwrap());

        /*
        Observe from the print-out that we have now used significantly more of our
        noise budget than in the two previous runs. This is again not surprising, 
        since the first relinearization chops off a huge part of the noise budget.

        However, note that the second relinearization does not change the noise
        budget by any observable amount. This is very important to understand when
        optimal performance is desired: relinearization always drops the noise
        budget from the maximum (freshly encrypted ciphertext) down to a fixed 
        amount depending on the encryption parameters and the decomposition bit 
        count. On the other hand, homomorphic multiplication always consumes the
        noise budget from its current level. This is why the second relinearization
        does not change the noise budget anymore: it is already consumed past the
        fixed amount determinted by the decomposition bit count and the encryption
        parameters. 

        We now perform a third squaring and observe an even further compounded
        decrease in the noise budget. Again, relinearization does not consume the
        noise budget at this point by any observable amount, even with the largest
        possible decomposition bit count.
        */

        bindings_Evaluator_square_inplace(ev, ct3);

        println!("Size after third squaring: {}", bindings_Ciphertext_size(ct3));
        println!("Noise budget after third squaring: {}", bindings_Decryptor_invariant_noise_budget(dec, ct3));

        bindings_Evaluator_relinearize_inplace(ev, ct3, rk60);
        
        println!("Size after relinearization: {}", bindings_Ciphertext_size(ct3));
        println!("Noise budget after relinearization (dbc = 60): {}", bindings_Decryptor_invariant_noise_budget(dec, ct3));

        let mut pt3 = bindings_Decryptor_decrypt(dec, ct3);

        println!("Eighth power: {}", CStr::from_ptr(bindings_Plaintext_to_string(pt3)).to_str().unwrap());

        /*
        Observe from the print-out that the polynomial coefficients are no longer
        correct as integers: they have been reduced modulo plain_modulus, and there
        was no warning sign about this. It might be necessary to carefully analyze
        the computation to make sure such overflow does not occur unexpectedly.
        These experiments suggest that an optimal strategy might be to relinearize
        first with relinearization keys with a small decomposition bit count, and 
        later with relinearization keys with a larger decomposition bit count (for 
        performance) when noise budget has already been consumed past the bound 
        determined by the larger decomposition bit count. For example, the best 
        strategy might have been to use relin_keys16 in the first relinearization 
        and relin_keys60 in the next two relinearizations for optimal noise budget 
        consumption/performance trade-off. Luckily, in most use-cases it is not so 
        critical to squeeze out every last bit of performance, especially when 
        larger parameters are used.
        */
    }
}
