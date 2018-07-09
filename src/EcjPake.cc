#include "EcjPake.h"

#include "Drbg.h"
#include "MbedTlsError.h"
#include "Util.h"

namespace {

using namespace node;

const auto DEFAULT_CURVE_TYPE = MBEDTLS_ECP_DP_SECP256R1;
const auto DEFAULT_HASH_TYPE = MBEDTLS_MD_SHA256;

const size_t MAX_BUFFER_SIZE = MBEDTLS_SSL_MAX_CONTENT_LEN; // FIXME: Use smaller temporary buffers

Nan::Persistent<v8::Function> g_ecjPakeCtor;

mbedtls_ecjpake_role roleTypeFromString(const std::string& str) {
    const std::string s(util::toLowerCase(str));
    if (s == "client") {
        return MBEDTLS_ECJPAKE_CLIENT;
    } else if (s == "server") {
        return MBEDTLS_ECJPAKE_SERVER;
    } else {
        throw std::invalid_argument("Invalid role name");
    }
}

mbedtls_ecp_group_id curveTypeFromString(const std::string& str) {
    const std::string s(util::toLowerCase(str));
    const auto info = mbedtls_ecp_curve_info_from_name(s.data());
    if (!info) {
        throw std::invalid_argument("Invalid curve type");
    }
    return info->grp_id;
}

mbedtls_md_type_t hashTypeFromString(const std::string& str) {
    const std::string s(util::toUpperCase(str));
    const auto info = mbedtls_md_info_from_string(s.data());
    if (!info) {
        throw std::invalid_argument("Invalid hash type");
    }
    return mbedtls_md_get_type(info);
}

} // namespace

EcjPakeImpl::EcjPakeImpl(mbedtls_ecjpake_role role, mbedtls_md_type_t hash, mbedtls_ecp_group_id curve,
        const char* secret, size_t secretSize) :
        ctx_() {
    CHECK_ARG(secret);
    mbedtls_ecjpake_init(&ctx_);
    try {
        MBEDTLS_CHECK_RESULT(mbedtls_ecjpake_setup(&ctx_, role, hash, curve, (const unsigned char*)secret, secretSize));
    } catch (const std::exception&) {
        mbedtls_ecjpake_free(&ctx_);
        throw;
    }
}

EcjPakeImpl::~EcjPakeImpl() {
    mbedtls_ecjpake_free(&ctx_);
}

void EcjPakeImpl::readRoundOne(const char* buf, size_t bufSize) {
    CHECK_ARG(buf);
    MBEDTLS_CHECK_RESULT(mbedtls_ecjpake_read_round_one(&ctx_, (const unsigned char*)buf, bufSize));
}

void EcjPakeImpl::writeRoundOne(char* buf, size_t* bufSize) {
    CHECK_ARG(buf && bufSize);
    size_t n = 0;
    const auto rand = Drbg::instance();
    MBEDTLS_CHECK_RESULT(mbedtls_ecjpake_write_round_one(&ctx_, (unsigned char*)buf, *bufSize, &n, rand->fn(), rand->arg()));
    *bufSize = n;
}

void EcjPakeImpl::readRoundTwo(const char* buf, size_t bufSize) {
    CHECK_ARG(buf);
    MBEDTLS_CHECK_RESULT(mbedtls_ecjpake_read_round_two(&ctx_, (const unsigned char*)buf, bufSize));
}

void EcjPakeImpl::writeRoundTwo(char* buf, size_t* bufSize) {
    CHECK_ARG(buf && bufSize);
    size_t n = 0;
    const auto rand = Drbg::instance();
    MBEDTLS_CHECK_RESULT(mbedtls_ecjpake_write_round_two(&ctx_, (unsigned char*)buf, *bufSize, &n, rand->fn(), rand->arg()));
    *bufSize = n;
}

void EcjPakeImpl::deriveSecret(char* buf, size_t* bufSize) {
    CHECK_ARG(buf && bufSize);
    size_t n = 0;
    const auto rand = Drbg::instance();
    MBEDTLS_CHECK_RESULT(mbedtls_ecjpake_derive_secret(&ctx_, (unsigned char*)buf, *bufSize, &n, rand->fn(), rand->arg()));
    *bufSize = n;
}

void EcjPake::Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target) {
    Nan::HandleScope scope;
    v8::Local<v8::FunctionTemplate> ctor = Nan::New<v8::FunctionTemplate>(EcjPake::New);
    ctor->SetClassName(Nan::New("EcjPake").ToLocalChecked());
    Nan::SetPrototypeMethod(ctor, "readRoundOne", EcjPake::ReadRoundOne);
    Nan::SetPrototypeMethod(ctor, "writeRoundOne", EcjPake::WriteRoundOne);
    Nan::SetPrototypeMethod(ctor, "readRoundTwo", EcjPake::ReadRoundTwo);
    Nan::SetPrototypeMethod(ctor, "writeRoundTwo", EcjPake::WriteRoundTwo);
    Nan::SetPrototypeMethod(ctor, "deriveSecret", EcjPake::DeriveSecret);
    v8::Local<v8::ObjectTemplate> ctorInst = ctor->InstanceTemplate();
    ctorInst->SetInternalFieldCount(1);
    g_ecjPakeCtor.Reset(ctor->GetFunction());
    Nan::Set(target, Nan::New("EcjPake").ToLocalChecked(), ctor->GetFunction());
}

void EcjPake::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    try {
        CHECK_ARG(info.Length() >= 1 && info[0]->IsObject());
        v8::Local<v8::Object> param = info[0]->ToObject();
        // Role (mandatory)
        v8::Local<v8::String> rolePropName = Nan::New("role").ToLocalChecked();
        v8::Local<v8::Value> roleVal = Nan::Get(param, rolePropName).ToLocalChecked();
        if (!roleVal->IsString() && !roleVal->IsStringObject()) {
            throw std::invalid_argument("'role' is not a string");
        }
        Nan::Utf8String roleStr(roleVal);
        const auto role = roleTypeFromString(std::string(*roleStr, roleStr.length()));
        // Pre-shared secret (mandatory)
        v8::Local<v8::String> secretPropName = Nan::New("secret").ToLocalChecked();
        v8::Local<v8::Value> secretVal = Nan::Get(param, secretPropName).ToLocalChecked();
        if (!Buffer::HasInstance(secretVal)) {
            throw std::invalid_argument("'secret' is not a buffer");
        }
        const char* secret = Buffer::Data(secretVal);
        const size_t secretSize = Buffer::Length(secretVal);
        // Curve type (optional)
        auto curve = DEFAULT_CURVE_TYPE;
        v8::Local<v8::String> curvePropName = Nan::New("curve").ToLocalChecked();
        v8::Local<v8::Value> curveVal = Nan::Get(param, curvePropName).ToLocalChecked();
        if (curveVal->IsString() || curveVal->IsStringObject()) {
            const Nan::Utf8String str(curveVal);
            curve = curveTypeFromString(std::string(*str, str.length()));
        }
        // Hash type (optional)
        auto hash = DEFAULT_HASH_TYPE;
        v8::Local<v8::String> hashPropName = Nan::New("hash").ToLocalChecked();
        v8::Local<v8::Value> hashVal = Nan::Get(param, hashPropName).ToLocalChecked();
        if (hashVal->IsString() || hashVal->IsStringObject()) {
            const Nan::Utf8String str(hashVal);
            hash = hashTypeFromString(std::string(*str, str.length()));
        }
        std::unique_ptr<EcjPake> that(new EcjPake());
        that->p_.reset(new EcjPakeImpl(role, hash, curve, secret, secretSize));
        that->Wrap(info.This());
        info.GetReturnValue().Set(info.This());
        that.release();
    } catch (const std::exception& e) {
        Nan::ThrowError(e.what());
    }
}

void EcjPake::ReadRoundOne(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    try {
        const auto that = Nan::ObjectWrap::Unwrap<EcjPake>(info.This());
        CHECK_ARG(info.Length() >= 1 && Buffer::HasInstance(info[0]));
        v8::Local<v8::Value> bufVal(info[0]);
        that->p_->readRoundOne(Buffer::Data(bufVal), Buffer::Length(bufVal));
    } catch (const std::exception& e) {
        Nan::ThrowError(e.what());
    }
}

void EcjPake::WriteRoundOne(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    try {
        const auto that = Nan::ObjectWrap::Unwrap<EcjPake>(info.This());
        std::unique_ptr<char[]> buf(new char[MAX_BUFFER_SIZE]);
        size_t n = MAX_BUFFER_SIZE;
        that->p_->writeRoundOne(buf.get(), &n);
        auto bufVal = Nan::CopyBuffer(buf.get(), n);
        info.GetReturnValue().Set(bufVal.ToLocalChecked());
    } catch (const std::exception& e) {
        Nan::ThrowError(e.what());
    }
}

void EcjPake::ReadRoundTwo(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    try {
        const auto that = Nan::ObjectWrap::Unwrap<EcjPake>(info.This());
        CHECK_ARG(info.Length() >= 1 && Buffer::HasInstance(info[0]));
        v8::Local<v8::Value> bufVal(info[0]);
        that->p_->readRoundTwo(Buffer::Data(bufVal), Buffer::Length(bufVal));
    } catch (const std::exception& e) {
        Nan::ThrowError(e.what());
    }
}

void EcjPake::WriteRoundTwo(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    try {
        const auto that = Nan::ObjectWrap::Unwrap<EcjPake>(info.This());
        std::unique_ptr<char[]> buf(new char[MAX_BUFFER_SIZE]);
        size_t n = MAX_BUFFER_SIZE;
        that->p_->writeRoundTwo(buf.get(), &n);
        auto bufVal = Nan::CopyBuffer(buf.get(), n);
        info.GetReturnValue().Set(bufVal.ToLocalChecked());
    } catch (const std::exception& e) {
        Nan::ThrowError(e.what());
    }
}

void EcjPake::DeriveSecret(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    try {
        const auto that = Nan::ObjectWrap::Unwrap<EcjPake>(info.This());
        std::unique_ptr<char[]> buf(new char[MAX_BUFFER_SIZE]);
        size_t n = MAX_BUFFER_SIZE;
        that->p_->deriveSecret(buf.get(), &n);
        auto bufVal = Nan::CopyBuffer(buf.get(), n);
        info.GetReturnValue().Set(bufVal.ToLocalChecked());
    } catch (const std::exception& e) {
        Nan::ThrowError(e.what());
    }
}
