#include "AesCcm.h"

#include "MbedTlsError.h"
#include "Util.h"

namespace {

using namespace node;

Nan::Persistent<v8::Function> g_ccmCtor;

} // namespace

AesCcmImpl::AesCcmImpl(const char* key, size_t keyBits) :
        ctx_() {
    CHECK_ARG(key);
    mbedtls_ccm_init(&ctx_);
    try {
        MBEDTLS_CHECK_RESULT(mbedtls_ccm_setkey(&ctx_, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key, keyBits));
    } catch (const std::exception&) {
        mbedtls_ccm_free(&ctx_);
        throw;
    }
}

AesCcmImpl::~AesCcmImpl() {
    mbedtls_ccm_free(&ctx_);
}

void AesCcmImpl::encrypt(const char* src, size_t srcSize, const char* nonce, size_t nonceSize, const char* add,
        size_t addSize, char* dest, char* tag, size_t tagSize) {
    MBEDTLS_CHECK_RESULT(mbedtls_ccm_encrypt_and_tag(&ctx_, srcSize, (const unsigned char*)nonce, nonceSize,
            (const unsigned char*)add, addSize, (const unsigned char*)src, (unsigned char*)dest, (unsigned char*)tag,
            tagSize));
}

void AesCcmImpl::decrypt(const char* src, size_t srcSize, const char* nonce, size_t nonceSize, const char* add,
        size_t addSize, char* dest, const char* tag, size_t tagSize) {
    MBEDTLS_CHECK_RESULT(mbedtls_ccm_auth_decrypt(&ctx_, srcSize, (const unsigned char*)nonce, nonceSize,
        (const unsigned char*)add, addSize, (const unsigned char*)src, (unsigned char*)dest, (const unsigned char*)tag,
        tagSize));
}

size_t AesCcmImpl::defaultTagSize() const {
    return ctx_.cipher_ctx.cipher_info->block_size;
}

void AesCcm::Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target) {
    Nan::HandleScope scope;
    v8::Local<v8::FunctionTemplate> ctor = Nan::New<v8::FunctionTemplate>(AesCcm::New);
    ctor->SetClassName(Nan::New("AesCcm").ToLocalChecked());
    Nan::SetPrototypeMethod(ctor, "encrypt", AesCcm::Encrypt);
    Nan::SetPrototypeMethod(ctor, "decrypt", AesCcm::Decrypt);
    v8::Local<v8::ObjectTemplate> ctorInst = ctor->InstanceTemplate();
    ctorInst->SetInternalFieldCount(1);
    g_ccmCtor.Reset(ctor->GetFunction());
    Nan::Set(target, Nan::New("AesCcm").ToLocalChecked(), ctor->GetFunction());
}

void AesCcm::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    try {
        CHECK_ARG(info.Length() >= 1 && info[0]->IsObject());
        v8::Local<v8::Object> param = info[0]->ToObject();
        // Key (mandatory)
        v8::Local<v8::String> keyPropName = Nan::New("key").ToLocalChecked();
        v8::Local<v8::Value> keyVal = Nan::Get(param, keyPropName).ToLocalChecked();
        if (!Buffer::HasInstance(keyVal)) {
            throw std::invalid_argument("'key' is not a buffer");
        }
        const char* key = Buffer::Data(keyVal);
        const size_t keyBits = Buffer::Length(keyVal) * 8;
        std::unique_ptr<AesCcm> that(new AesCcm());
        that->p_.reset(new AesCcmImpl(key, keyBits));
        that->Wrap(info.This());
        info.GetReturnValue().Set(info.This());
        that.release();
    } catch (const std::exception& e) {
        Nan::ThrowError(e.what());
    }
}

void AesCcm::Encrypt(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    try {
        const auto that = Nan::ObjectWrap::Unwrap<AesCcm>(info.This());
        CHECK_ARG(info.Length() >= 1 && info[0]->IsObject());
        v8::Local<v8::Object> param = info[0]->ToObject();
        // Source data (mandatory)
        v8::Local<v8::String> srcPropName = Nan::New("data").ToLocalChecked();
        v8::Local<v8::Value> srcVal = Nan::Get(param, srcPropName).ToLocalChecked();
        if (!Buffer::HasInstance(srcVal)) {
            throw std::invalid_argument("'data' is not a buffer");
        }
        const char* src = Buffer::Data(srcVal);
        const size_t srcSize = Buffer::Length(srcVal);
        // Nonce (mandatory)
        v8::Local<v8::String> noncePropName = Nan::New("nonce").ToLocalChecked();
        v8::Local<v8::Value> nonceVal = Nan::Get(param, noncePropName).ToLocalChecked();
        if (!Buffer::HasInstance(nonceVal)) {
            throw std::invalid_argument("'nonce' is not a buffer");
        }
        const char* nonce = Buffer::Data(nonceVal);
        const size_t nonceSize = Buffer::Length(nonceVal);
        // Additional data (optional)
        const char* add = nullptr;
        size_t addSize = 0;
        v8::Local<v8::String> addPropName = Nan::New("additionalData").ToLocalChecked();
        v8::Local<v8::Value> addVal = Nan::Get(param, addPropName).ToLocalChecked();
        if (Nan::Has(param, addPropName).FromJust()) {
            if (!Buffer::HasInstance(addVal)) {
                throw std::invalid_argument("'additionalData' is not a buffer");
            }
            add = Buffer::Data(addVal);
            addSize = Buffer::Length(addVal);
        }
        // Tag size (optional)
        size_t tagSize = that->p_->defaultTagSize();
        v8::Local<v8::String> tagSizePropName = Nan::New("tagLength").ToLocalChecked();
        v8::Local<v8::Value> tagSizeVal = Nan::Get(param, tagSizePropName).ToLocalChecked();
        if (Nan::Has(param, tagSizePropName).FromJust()) {
            const int n = Nan::To<int>(tagSizeVal).FromJust();
            if (n <= 0) {
                throw std::invalid_argument("Invalid size of the authentication tag");
            }
            tagSize = n;
        }
        std::unique_ptr<char[]> dest(new char[srcSize]);
        std::unique_ptr<char[]> tag(new char[tagSize]);
        that->p_->encrypt(src, srcSize, nonce, nonceSize, add, addSize, dest.get(), tag.get(), tagSize);
        auto destBuf = Nan::CopyBuffer(dest.get(), srcSize).ToLocalChecked();
        auto tagBuf = Nan::CopyBuffer(tag.get(), tagSize).ToLocalChecked();
        auto retObj = Nan::New<v8::Object>();
        Nan::Set(retObj, Nan::New("data").ToLocalChecked(), destBuf);
        Nan::Set(retObj, Nan::New("tag").ToLocalChecked(), tagBuf);
        info.GetReturnValue().Set(retObj);
    } catch (const std::exception& e) {
        Nan::ThrowError(e.what());
    }
}

void AesCcm::Decrypt(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    try {
        const auto that = Nan::ObjectWrap::Unwrap<AesCcm>(info.This());
        CHECK_ARG(info.Length() >= 1 && info[0]->IsObject());
        v8::Local<v8::Object> param = info[0]->ToObject();
        // Source data (mandatory)
        v8::Local<v8::String> srcPropName = Nan::New("data").ToLocalChecked();
        v8::Local<v8::Value> srcVal = Nan::Get(param, srcPropName).ToLocalChecked();
        if (!Buffer::HasInstance(srcVal)) {
            throw std::invalid_argument("'data' is not a buffer");
        }
        const char* src = Buffer::Data(srcVal);
        const size_t srcSize = Buffer::Length(srcVal);
        // Nonce (mandatory)
        v8::Local<v8::String> noncePropName = Nan::New("nonce").ToLocalChecked();
        v8::Local<v8::Value> nonceVal = Nan::Get(param, noncePropName).ToLocalChecked();
        if (!Buffer::HasInstance(nonceVal)) {
            throw std::invalid_argument("'nonce' is not a buffer");
        }
        const char* nonce = Buffer::Data(nonceVal);
        const size_t nonceSize = Buffer::Length(nonceVal);
        // Authentication tag (mandatory)
        v8::Local<v8::String> tagPropName = Nan::New("tag").ToLocalChecked();
        v8::Local<v8::Value> tagVal = Nan::Get(param, tagPropName).ToLocalChecked();
        if (!Buffer::HasInstance(tagVal)) {
            throw std::invalid_argument("'tag' is not a buffer");
        }
        const char* tag = Buffer::Data(tagVal);
        const size_t tagSize = Buffer::Length(tagVal);
        // Additional data (optional)
        const char* add = nullptr;
        size_t addSize = 0;
        v8::Local<v8::String> addPropName = Nan::New("additionalData").ToLocalChecked();
        v8::Local<v8::Value> addVal = Nan::Get(param, addPropName).ToLocalChecked();
        if (Nan::Has(param, addPropName).FromJust()) {
            if (!Buffer::HasInstance(addVal)) {
                throw std::invalid_argument("'additionalData' is not a buffer");
            }
            add = Buffer::Data(addVal);
            addSize = Buffer::Length(addVal);
        }
        std::unique_ptr<char[]> dest(new char[srcSize]);
        that->p_->decrypt(src, srcSize, nonce, nonceSize, add, addSize, dest.get(), tag, tagSize);
        auto destBuf = Nan::CopyBuffer(dest.get(), srcSize).ToLocalChecked();
        auto retObj = Nan::New<v8::Object>();
        Nan::Set(retObj, Nan::New("data").ToLocalChecked(), destBuf);
        info.GetReturnValue().Set(retObj);
    } catch (const std::exception& e) {
        Nan::ThrowError(e.what());
    }
}
