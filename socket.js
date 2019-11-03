'use strict';

const stream = require('stream');

var mbed = require('bindings')('node_mbed_dtls.node');

const MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY = -0x7880;
const MBEDTLS_ERR_SSL_CLIENT_RECONNECT = -0x6780;

/**
 * Implements a socket with a similar interface to other Duplex sockets. Note that the Readable interface
 * of this implementation does not support paused mode, and consequently should be put in flowing mode by adding a
 * "data" event listener.
 *
 *
 * Emits:
 *       "send", message.length: the length of the encrypted message sent
 *       "secureConnect": secure connection has been established (handshake complete)
 *       "sessionResumed": when a client indicates it has reconnected (via a movesession packet.)
 *       "error": only if a callback wasn't passed to write() (contrary to the node docs.) After the error event is emitted
 *          the socket is torn down.
 *       "closing": emitted when the connection is being torn down.
 *       "close", hadError: the socket is finally torn down. First parameter indicates if the closure was due to an error
 */
class DtlsSocket extends stream.Duplex {
	/**
	 *
	 * @param {DtlsServer} server   The server this client is bound to
	 * @param {String} address      The remote ip address of the destination device
	 * @param {Number} port         The remote port of the destination device
	 */
	constructor(server, address, port) {
		// todo - when is the remote address and port updated when a Move Session is handled?
		super({ allowHalfOpen: false });
		this.server = server;
		this.dgramSocket = server.dgramSocket;
		this.remoteAddress = address;
		this.remotePort = port;
		this._hadError = false;
		this._sendClose = true;
		// this._clientEnd = false;     // flag to indicate the socket is being ended by the local client
		// this._ending = false;        // flag set when the socket is being torn down. Used to prevent re-entrant calls.
		const key = `${address}:${port}`;

		this.mbedSocket = new mbed.DtlsSocket(server.mbedServer, key,
			this._sendEncrypted.bind(this),
			this._handshakeComplete.bind(this),
			this._error.bind(this),
			this._renegotiate.bind(this));
	}

	get publicKey() {
		return (this.mbedSocket && this.mbedSocket.publicKey) || new Buffer(0);
	}
	get publicKeyPEM() {
		return (this.mbedSocket && this.mbedSocket.publicKeyPEM) || new Buffer(0);
	}
	get outCounter() {
		return this.mbedSocket && this.mbedSocket.outCounter;
	}
	get session() {
		return this.mbedSocket && this.mbedSocket.session;
	}

	get sendClose() {
		return this._sendClose;
	}
	set sendClose(value) {
		this._sendClose = value;
	}

	/**
	 * Resume the mbedtls session state for this connection.
	 * If the session is successfully resumed, the socket is considered connected (handshake complete) and resumed.
	 * @param session
	 * @returns {boolean}
	 */
	resumeSession(session) {
		if (!session || !this.mbedSocket) {
			return false;
		}

		const s = new mbed.SessionWrap();
		s.restore(session);

		const success = this.mbedSocket.resumeSession(s);
		if (success) {
			this.connected = true;
			this.resumed = true;
		}
		return success;
	}

	/**
	 * Read data from the underlying stream. This presently does nothing since the data is delivered via the
	 * {@link #receive} function. The stream only operates in flowing mode.
	 * @private
	 */
	_read() {
		// TODO implement way to stop/start reading?
		// do nothing since chunk pushing is async
	}

	/**
	 * Override the stream.Duplex `_write` method to write data to the stream.
	 * This encodes the data via mbedSocket.send() method.
	 * @param chunk
	 * @param encoding
	 * @param callback
	 * @returns {*}
	 * @private
	 */
	_write(chunk, encoding, callback) {
		if (!this.mbedSocket) {
			return callback(new Error('no mbed socket'));
		}

		this._sendCallback = callback;  // save the callback temporarily, it's picked up in _sendEncrypted
		this.mbedSocket.send(chunk);
	}

	/**
	 * Callback from the mbedtls library to send data to the network. This happens either intrinsically or in
	 * response to sending application data via the `write` method.
	 * @param {Buffer|Array} msg    The packet to send
	 * @private
	 */
	_sendEncrypted(msg) {
		// store the callback here because '_write' might be called
		// again before the underlying socket finishes sending
		const sendCb = this._sendCallback;
		this._sendCallback = null;
		const sendFinished = (err) => {
			if (sendCb) {
				sendCb(err);
			}
			// todo - what does this mean and why isit necessary?
			//  _clientEnd is only set in end() which also calls _end().
			// but it may not call _finishEnd(), but there appears to be a bug in that logic anyhow...
			// maybe this was a quick fix for some strange behavior?
			if (this._clientEnd) {
				this._finishEnd();
			}
		};

		// make absolutely sure the socket will let us send
		if (!this.dgramSocket || !this.dgramSocket._handle) {
			process.nextTick(() => {
				sendFinished(new Error('no underlying socket'));
			});
			return;
		}

		this.emit('send', msg.length);
		this.dgramSocket.send(msg, 0, msg.length, this.remotePort, this.remoteAddress, sendFinished);
	}

	_handshakeComplete() {
		this.connected = true;
		this.emit('secureConnect');
	}

	_error(code, msg) {
		if (code === MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			this._end();
			return;
		}

		if (code === MBEDTLS_ERR_SSL_CLIENT_RECONNECT) {
			this.emit('reconnect', this);
			process.nextTick(() => {
				this.receive();
			});
			return;
		}

		this._hadError = true;
		if (this._sendCallback) {
			this._sendCallback(code);
			this._sendCallback = null;
		} else {
			// todo - why not emit the error event even with a callback for general metrics gathering?
			// The node docs say this (at https://nodejs.org/api/stream.html#stream_writable_write_chunk_encoding_callback)
			// >> If an error occurs, the callback may or may not be called with the error as its first argument.
			// >> To reliably detect write errors, add a listener for the 'error' event. If callback is called with
			// >> an error, it will be called before the 'error' event is emitted.
			this.emit('error', code, msg);
		}
		this._end();
	}

	_renegotiate(sessionId) {
		const done = this._renegotiateCallback.bind(this);
		if (!this.server.emit('renegotiate', sessionId.toString('hex'), this, done)) {
			process.nextTick(done);
		}
	}

	_renegotiateCallback(err, data) {
		if (err) {
			this._end();
			return;
		}

		let s;
		if (data) {
			s = new mbed.SessionWrap();
			s.restore(data);
		}
		this.mbedSocket.renegotiate(s || undefined);
		this.resumed = true;
	}

	/**
	 * Accept an encrypted packet coming from the network and attempt to decode it.
	 * Publishes the `receive` event with the incoming message length.
	 * The decoded data (if any) is pushed to the Duplex stream's read buffer.
	 * @param {Buffer|Array} msg The incoming message to decrypt
	 * @returns {boolean}
	 */
	receive(msg) {
		if (!this.mbedSocket) {
			return false;
		}
		if (msg && msg.length < 4) {
			return false;
		}

		this.emit('receive', (msg && msg.length) || 0);
		const data = this.mbedSocket.receiveData(msg);
		if (data) {
			this.push(data);
			return true;
		}
		return false;
	}

	end() {
		if (this._resetting) {
			return;
		}
		this._clientEnd = true;
		this._end();
	}

	reset() {
		this._resetting = true;
		this.emit('close', false);
		this.removeAllListeners();
		this._resetting = false;
		this.resumed = false;
		this.connected = false;
	}

	/**
	 * Tear down this connection.
	 * @private
	 */
	_end() {
		if (this._ending) {
			return;
		}
		this._ending = true;    // prevent re-entrant calls

		super.end();            // signal that no more data will be written
		this.push(null);        // signal that no more data can be read (EOF)
		const noSend = !this._sendClose || this.mbedSocket.close(); // don't send the event if _sendClose is false or there was an error closing the socket.
		this.emit('closing');
		this.mbedSocket = null;

		// todo - this seems wrong - shouldn't the condition be !noSend ?
		if (noSend || !this._clientEnd) {   // always finish if the connection was terminated by the remote client
			this._finishEnd();
		}
		// todo - when _finishEnd() is not called, don't we end up with a bunch of listeners from _attachToSocket
		// the spec says a Writable stream will always emit the close event even with the emitClose option
	}

	/**
	 * Clean up this connection and emit the close event.
	 *
	 * @private
	 */
	_finishEnd() {
		this.dgramSocket = null;
		this.server = null;
		this.emit('close', this._hadError);
		this.removeAllListeners();
	}
}

module.exports = DtlsSocket;
