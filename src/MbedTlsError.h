#pragma once

#include <stdexcept>
#include <string>

#define MBEDTLS_CHECK_RESULT(_expr) \
        do { \
            const int ret = _expr; \
            if (ret != 0) { \
                throw MbedTlsError(ret); \
            } \
        } while (false)

class MbedTlsError: public std::runtime_error {
public:
    explicit MbedTlsError(int code);
    MbedTlsError(int code, std::string msg);

    int code() const;

private:
    int code_;

    static std::string defaultErrorMsg(int code);
};

inline MbedTlsError::MbedTlsError(int code) :
        MbedTlsError(code, defaultErrorMsg(code)) {
}

inline MbedTlsError::MbedTlsError(int code, std::string msg) :
        std::runtime_error(std::move(msg)),
        code_(code) {
}

inline int MbedTlsError::code() const {
    return code_;
}
