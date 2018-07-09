
#include "DtlsServer.h"
#include "DtlsSocket.h"
#include "SessionWrap.h"
#include "EcjPake.h"
#include "AesCcm.h"

NAN_MODULE_INIT(init) {
	DtlsServer::Initialize(target);
	DtlsSocket::Initialize(target);
	SessionWrap::Initialize(target);
    EcjPake::Initialize(target);
    AesCcm::Initialize(target);
}

NODE_MODULE(node_mbed_dtls, init);
