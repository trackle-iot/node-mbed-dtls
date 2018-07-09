'use strict';

var DtlsServer = require('./server');

var mbed = require('./build/Release/node_mbed_dtls');
var EcjPake = mbed.EcjPake;
var AesCcm = mbed.AesCcm;

function createServer(options, secureConnectionListener) {
	options = options || {};
	const server = new DtlsServer(options);

	if (secureConnectionListener) {
		server.on('secureConnection', secureConnectionListener);
	}

	return server;
}

module.exports = { createServer, EcjPake, AesCcm };
