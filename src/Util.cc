#include "Util.h"

#include <cctype>

namespace util {

std::string toLowerCase(const std::string& str) {
    std::string s(str);
    for (size_t i = 0; i < s.size(); ++i) {
        s[i] = std::tolower((unsigned char)s[i]);
    }
    return s;
}

std::string toUpperCase(const std::string& str) {
    std::string s(str);
    for (size_t i = 0; i < s.size(); ++i) {
        s[i] = std::toupper((unsigned char)s[i]);
    }
    return s;
}

} // util
