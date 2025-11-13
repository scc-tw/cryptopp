// Focused ASan/UBSan test to exercise ESIGN's memcpy into seed + 4
// Verifies there is no out-of-bounds write when 'Seed' is provided.

#include "esign.h"
#include "osrng.h"
#include "algparam.h"
#include "secblock.h"

#include <iostream>
#include <vector>
#include <stdexcept>

using namespace CryptoPP;

static void run_one(size_t seed_len, unsigned int modulus_bits) {
    AutoSeededRandomPool rng;

    // Deterministic seed buffer of length seed_len
    SecByteBlock seedParam(seed_len);
    for (size_t i = 0; i < seed_len; ++i) {
        seedParam[i] = static_cast<byte>((i * 131u + 17u) & 0xFFu);
    }

    // modulus_bits must be divisible by 3 and >= 24
    AlgorithmParameters params =
        MakeParameters("ModulusSize", static_cast<int>(modulus_bits))(
            "Seed", ConstByteArrayParameter(seedParam));

    InvertibleESIGNFunction key;
    key.GenerateRandom(rng, params);

    // If we get here, ASan/UBSan found no overflow/UB on the memcpy path.
}

int main() {
    try {
        // Exercise a range of seed lengths
        const std::vector<size_t> lengths = {
            0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 128
        };

        // Multiple modulus sizes to cover code paths; all divisible by 3
        const std::vector<unsigned int> moduli = { 96, 192, 384 };

        for (unsigned int m : moduli) {
            for (size_t len : lengths) {
                run_one(len, m);
            }
        }

        std::cout << "ESIGN memcpy ASan test passed for all seeds and moduli." << std::endl;
        return 0;
    } catch (const Exception& ex) {
        std::cerr << "Crypto++ exception: " << ex.what() << std::endl;
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "std::exception: " << ex.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown exception" << std::endl;
        return 1;
    }
}
