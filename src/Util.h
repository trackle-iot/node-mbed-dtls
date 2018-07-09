#pragma once

#include <stdexcept>
#include <string>

#define CHECK_ARG(_expr) \
        do { \
            if (!(_expr)) { \
                throw std::invalid_argument("Invalid arguments"); \
            } \
        } while (false)

namespace util {

std::string toLowerCase(const std::string& str);
std::string toUpperCase(const std::string& str);

} // util
