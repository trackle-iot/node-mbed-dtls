#pragma once

#include "mbedtls/ccm.h"

#include <memory>

#include <node.h>
#include <nan.h>

class AesCcmImpl {
public:
    AesCcmImpl(const char* key, size_t keyBits);
    ~AesCcmImpl();

    void encrypt(const char* src, size_t srcSize, const char* nonce, size_t nonceSize, const char* add,
            size_t addSize, char* dest, char* tag, size_t tagSize);

    void decrypt(const char* src, size_t srcSize, const char* nonce, size_t nonceSize, const char* add,
            size_t addSize, char* dest, const char* tag, size_t tagSize);

    size_t defaultTagSize() const;

private:
    mbedtls_ccm_context ctx_;
};

class AesCcm: public Nan::ObjectWrap {
public:
    static void Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target);

    static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void Encrypt(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void Decrypt(const Nan::FunctionCallbackInfo<v8::Value>& info);

private:
    std::unique_ptr<AesCcmImpl> p_;
};
