'use strict';

var DtlsServer = require('./server');
var EcjPake = require('./build/Release/node_mbed_dtls').EcjPake;

function createServer(options, secureConnectionListener) {
	options = options || {};
	const server = new DtlsServer(options);

	if (secureConnectionListener) {
		server.on('secureConnection', secureConnectionListener);
	}

	return server;
}

module.exports = { createServer, EcjPake };
