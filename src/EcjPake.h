#pragma once

#include "mbedtls/ecjpake.h"

#include <memory>

#include <node.h>
#include <nan.h>

class EcjPakeImpl {
public:
    EcjPakeImpl(mbedtls_ecjpake_role role, mbedtls_md_type_t hash, mbedtls_ecp_group_id curve, const char* secret,
            size_t secretSize);
    ~EcjPakeImpl();

    void readRoundOne(const char* buf, size_t bufSize);
    void writeRoundOne(char* buf, size_t* bufSize);

    void readRoundTwo(const char* buf, size_t bufSize);
    void writeRoundTwo(char* buf, size_t* bufSize);

    void deriveSecret(char* buf, size_t* bufSize);
    
private:
    mbedtls_ecjpake_context ctx_;
};

class EcjPake: public Nan::ObjectWrap {
public:
    static void Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target);

    static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void ReadRoundOne(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void WriteRoundOne(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void ReadRoundTwo(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void WriteRoundTwo(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void DeriveSecret(const Nan::FunctionCallbackInfo<v8::Value>& info);

private:
    std::unique_ptr<EcjPakeImpl> p_;
};
