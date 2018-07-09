#pragma once

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

class Drbg {
public:
    typedef int (*Fn)(void*, unsigned char*, size_t);

    Drbg();
    ~Drbg();

    Fn fn();
    void* arg();

    static Drbg* instance();

private:
    mbedtls_ctr_drbg_context drbg_;
    mbedtls_entropy_context entropy_;
};

inline Drbg::Fn Drbg::fn() {
    return &mbedtls_ctr_drbg_random;
}

inline void* Drbg::arg() {
    return &drbg_;
}
