#include "Drbg.h"

#include "MbedTlsError.h"

namespace {

// Personalization data for mbedtls_ctr_drbg_seed()
const std::string CUSTOM_DATA("node-mbed-dtls");

} // namespace

Drbg::Drbg() :
        drbg_(),
        entropy_() {
    mbedtls_entropy_init(&entropy_);
    mbedtls_ctr_drbg_init(&drbg_);
    try {
        MBEDTLS_CHECK_RESULT(mbedtls_ctr_drbg_seed(&drbg_, mbedtls_entropy_func, &entropy_,
                (const unsigned char*)CUSTOM_DATA.data(), CUSTOM_DATA.size()));
    } catch (const std::exception&) {
        mbedtls_ctr_drbg_free(&drbg_);
        mbedtls_entropy_free(&entropy_);
        throw;
    }
}

Drbg::~Drbg() {
    mbedtls_ctr_drbg_free(&drbg_);
    mbedtls_entropy_free(&entropy_);
}

Drbg* Drbg::instance() {
    static Drbg drbg;
    return &drbg;
}
