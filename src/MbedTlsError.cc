#include "MbedTlsError.h"

#include "mbedtls/error.h"

#include <memory>

namespace {

const size_t MAX_MESSAGE_SIZE = 128;

} // namespace

std::string MbedTlsError::defaultErrorMsg(int code) {
    const std::unique_ptr<char[]> buf(new char[MAX_MESSAGE_SIZE]);
    mbedtls_strerror(code, buf.get(), MAX_MESSAGE_SIZE);
    return std::string(buf.get());
}
