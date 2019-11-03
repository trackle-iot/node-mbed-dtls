'use strict';

var dgram = require('dgram');
var fs = require('fs');
var EventEmitter = require('events').EventEmitter;

var DtlsSocket = require('./socket');
var mbed = require('bindings')('node_mbed_dtls.node');

const APPLICATION_DATA_CONTENT_TYPE = 23;
const IP_CHANGE_CONTENT_TYPE = 254;

/**
 * Emits:
 *  "listening"     when the server is ready to accept incoming connections
 *  "connection"    when a unverified client connects
 *  "secureConnection" client, [session] when a client has connected and completed a handshake (session is undefined) or
 *      when a session was resumed (session is non-null)
 *  "clientError"   when an error occurs during the handshake
 *  "error"         when an error occurs on the UDP socket. The socket is automatically closed after an error.
 */
class DtlsServer extends EventEmitter {
	/**
	 *
	 * @param {object} options
	 * @property sendClose - set to false when session resumption is required.
	 *  todo - exactly why is it necessary to suppress the close event? Possibly so that when a server shuts down it can
	 *  close each client connection without
	 */
	constructor(options) {
		super();
		this.options = options = Object.assign({
			sendClose: true
		}, options);

		/**
		 * Maps string keys to a DtlsClient instance
		 * @type {object}
		 * @see _createSocket
		 */
		this.sockets = {};

		/**
		 * The underlying networking socket that receives data for this server.
		 */
		this.dgramSocket = dgram.createSocket('udp4');
		this._onMessage = this._onMessage.bind(this);
		this.listening = false;
		this._closing = false;
		/**
		 * The number of MoveSession packets received consecutively.
		 * @type {number}
		 * @private
		 */
		this._moveSessionCount = 0;
		this.dgramSocket.on('message', this._onMessage);
		this.dgramSocket.once('listening', () => {
			this.listening = true;
			this.emit('listening');
		});
		this.dgramSocket.once('error', err => {
			this.emit('error', err);
			this._closeSocket();
		});
		this.dgramSocket.once('close', () => {
			this._socketClosed();
		});

		let key = Buffer.isBuffer(options.key) ? options.key : fs.readFileSync(options.key);
		// likely a PEM encoded key, add null terminating byte
		// 0x2d = '-'
		if (key[0] === 0x2d && key[key.length - 1] !== 0) {
			key = Buffer.concat([key, Buffer.from([0])]);
		}

		this.mbedServer = new mbed.DtlsServer(key, options.debug);
		if (options.handshakeTimeoutMin) {
			this.mbedServer.handshakeTimeoutMin = options.handshakeTimeoutMin;
		}
	}

	/**
	 * Begin listening on the specified port and interface.
	 * @param {Number} port
	 * @param {String} hostname
	 * @param callback
	 */
	listen(port, hostname, callback) {
		this.dgramSocket.bind(port, hostname, callback);
	}

	/**
	 * Close this server socket and all clients.
	 * @param callback  That is invoked once the socket is closed.
	 */
	close(callback) {
		if (callback) {
			this.once('close', callback);
		}
		this._closing = true;
		this._closeSocket();
	}

	address() {
		return this.dgramSocket.address();
	}

	getConnections(callback) {
		var numConnections = Object.keys(this.sockets).filter(skey => {
			return this.sockets[skey] && this.sockets[skey].connected;
		}).length;
		process.nextTick(() => callback(numConnections));
	}

	/**
	 * Reinstates and resumes the session on a client socket based on the source address and session.
	 * @param rinfo
	 * @param session
	 * @returns {boolean} false if there was already an existing client matching the same source
	 */
	resumeSocket(rinfo, session) {
		const key = this._makeKey(rinfo);
		let client = this.sockets[key];
		if (client) {
			return false;
		}

		this.sockets[key] = client = this._createSocket(rinfo, key, true);
		if (client.resumeSession(session)) {
			// todo - in many ways it makes more sense to defer the secureConnection event until the first
			// data is received and decoded from the peer
			//
			this.emit('secureConnection', client, session);
			return true;
		}
		return false;
	}

	_debug() {
		if (this.options.debug) {
			console.log(...arguments);
		}
	}

	_makeKey(rinfo) {
		return `${rinfo.address}:${rinfo.port}`;
	}

	/**
	 * Handles the message extracted from a MoveSession request.
	 * The deviceId is used to look up the last known source of the device, and from that the session is retrieved.
	 * An attempt is made to decode the message using the session retrieved. If it is successful then the deviceId
	 * was previously associated with that session and the session relocated to the new source address.
	 *
	 * The first moveSession packet to be received in a run of moveSession packets causes the sessionResumed event to be fired.
	 *
	 * @param {Uint8Array|Buffer} msg The application dtls message (encrypted)
	 * @param {string} key  A key for the client the message came from
	 * @param {object} rinfo The network source of the message
	 * @param {string} deviceId The deviceId that claims to have made the request
	 * @returns {boolean} true if the lookupKey event had listeners. This says nothing about whether the packet was
	 *  successfully decoded or not.
	 * @private
	 *
	 * @see _receiveMessage
	 */
	_handleIpChange(msg, key, rinfo, deviceId) {
		// this would be better named fetchSourceInfo and not exposed as an event but as a callback.
		const lookedUp = this.emit('lookupKey', deviceId, (err, oldRinfo) => {
			if (!err && oldRinfo) {
				// Handle the message using the previous source details
				const oldKey = this._makeKey(oldRinfo);
				this._receiveMessage(msg, oldKey, oldRinfo, (client, received) => {
					// if the message went through OK. (The stream is corked, so the data hasn't been delivered yet.)
					if (received) {
						if (rinfo.address === oldRinfo.address &&
							rinfo.port === oldRinfo.port) {
							this._debug(`ignoring ip change because address did not change ip=${key}, deviceID=${deviceId}`);
						}
						else {
							this._debug(`message successfully received, changing ip address fromip=${oldKey}, toip=${key}, deviceID=${deviceId}`);
							// change IP
							client.remoteAddress = rinfo.address;
							client.remotePort = rinfo.port;
							// move in lookup table - todo the _attachClient function should also be updated or the callbacks will remove the wrong socket when
							// the socket close event is called?
							delete this.sockets[oldKey];
							this.sockets[key] = client;

							// tell the world
							client.emit('ipChanged', oldRinfo);
						}
						if (!this._moveSessionCount) {
							client.emit('sessionResumed');
						}
						this._moveSessionCount++;
					} else {
						// the session does not match the given device ID
						// Do we need to jump out of lock state here too .. TBC (adding logging)?
						this._debug(`message NOT successfully received NOT changing ip address fromip=${oldKey}, toip=${key}, deviceID=${deviceId}`);
					}
				});
			} else {
				// In May 2019 some devices were stuck with bad sessions, never handshaking.
				// https://app.clubhouse.io/particle/milestone/32301/manage-next-steps-associated-with-device-connectivity-issues-starting-may-2nd-2019
				// This cloud-side solution was discovered by Eli Thomas which caused
				// mbedTLS to fail a socket read and initiate a handshake.
				this._debug(`Device in 'move session' lock state attempting to force it to re-handshake deviceID=${deviceId}`);

				//Always EMIT this event instead of calling _forceDeviceRehandshake internally this allows the DS to device whether to send the packet or not to the device
				this.emit('forceDeviceRehandshake', rinfo, deviceId);
			}
		});
		return lookedUp;
	}

	_forceDeviceRehandshake(rinfo, deviceId){
		this._debug(`Attemting force re-handshake by sending malformed hello request packet to deviceID=${deviceId}`);

		// Construct the 'session killing' Avada Kedavra packet
		const malformedHelloRequest = Buffer.from([
			0x16,                                 // Handshake message type 22
			0xfe, 0xfd,                           // DTLS 1.2
			0x00, 0x01,                           // Epoch
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Sequence number, works when set to anything, therefore chose 0x00
			0x00, 0x10,                           // Data length, this has to be >= 16 (minumum) (deliberatly set to 0x10 (16) which is > the data length (2) that follows to force an mbed error on the device
			0x00,                                 // HandshakeType hello_request
			0x00                                  // Handshake body, intentionally too short at a single byte
		]);

		// Sending the malformed hello request back over the raw UDP socket
		this.dgramSocket.send(malformedHelloRequest, rinfo.port, rinfo.address);
	}

	/**
	 * Try resuming the session based on the source of the packet. The `resumeSession` event (really a callback)
	 * is invoked to attempt to fetch the corresponding session for the source. If the session was successfully applied
	 * to the mbedtls layer, the message is then attempted to be decoded. Only when this is successful is the "secureConnection"
	 * event emitted.
	 * @param client
	 * @param msg
	 * @param key
	 * @param cb
	 * @returns {boolean}
	 * @private
	 */
	_attemptResume(client, msg, key, cb) {
		const lcb = cb || (() => {});
		// todo - this shouldn't be called resumeSession since it's more of a lookup and creates confusion with
		// the other uses of resumeSession where a session is actually resumed.
		// lookupSessionBySource would be more appropriate.
		const called = this.emit('resumeSession', key, client, (err, session) => {
			if (!err && session) {
				const resumed = client.resumeSession(session);
				if (resumed) {
					client.cork();

					const received = client.receive(msg);
					// callback before secureConnection so
					// IP can be changed
					lcb(client, received);
					if (received) {
						this.emit('secureConnection', client, session);
					}

					client.uncork();
					return;
				}
			}
			client.receive(msg);
			lcb(null, false);
		});

		// if somebody was listening, session will attempt to be resumed
		// do not process with receive until resume finishes
		return called;
	}

	/**
	 * Handle a packet from the socket.
	 * @param {Uint8Array|Buffer} msg       The message data
	 * @param {object} rinfo     The source address info
	 * @private
	 */
	_onMessage(msg, rinfo) {
		const key = this._makeKey(rinfo);

		if (!this._handleMoveSession(msg, key, rinfo)) {
			this._receiveMessage(msg, key, rinfo);
		}
	}

	/**
	 * Determines if the received packet is a "MoveSession" packet and if so, reworks the packet back to a regular
	 * DTLS application packet, after extracting the deviceID and then handles the packet.
	 * @param {Uint8Array|Buffer} msg   The packet to check
	 * @param {string} key              The key identifying the network source of the packet
	 * @param {object} rinfo            The network source of the packet
	 * @returns {boolean} true when the packet was handled and no further processing is necessary. false if the packet
	 *  could not be handled.
	 * @private
	 */
	_handleMoveSession(msg, key, rinfo) {
		// special IP changed content type
		let unpacked;
		if ((unpacked=this._unpackMoveSessionPacket(msg))) {
			const { msg, deviceId } = unpacked;
			this._debug(`received ip change ip=${key}, deviceID=${deviceId}`);
			if (this._handleIpChange(msg, key, rinfo, deviceId)) {
				// no more processing needed
				return true;
			}
		}
		this._moveSessionCount = 0;
		return false;
	}

	/**
	 * Determines if a packet is a move session packet, and if it is, unpacks it.
	 * @param {(Uint8Array|Buffer)} msg
	 * @returns {{msg: (Uint8Array|Buffer), deviceId: string}} result The unpacked message and the deviceId
	 * @private
	 */
	_unpackMoveSessionPacket(msg) {
		if (msg.length > 0 && msg[0] === IP_CHANGE_CONTENT_TYPE) {
			const idLen = msg[msg.length - 1];
			const idStartIndex = msg.length - idLen - 1;
			const deviceId = msg.slice(idStartIndex, idStartIndex + idLen).toString('hex').toLowerCase();

			// slice off id and length, return content type to ApplicationData
			msg = msg.slice(0, idStartIndex);
			msg[0] = APPLICATION_DATA_CONTENT_TYPE;
			return { msg, deviceId };
		}
	}

	/**
	 * Callback to handle error and delivery of application data.
	 * @callback DtlsServer~receiveCallback
	 * @param {number} err  When defined, indicates the error that occurred trying to decode the packet
	 * @param {bool} received   when set to true, application data was successfully decoded. Otherwise no data was decoded.
	 */

	/**
	 * Handled a dtls message.
	 * @param {(Buffer|Uint8Array)} msg   The packet to decode
	 * @param {String} key      The key of the client that sent the packet
	 * @param {Object} rinfo    The source of the packet
	 * @param {DtlsServer~receiveCallback} [cb]
	 *
	 * @private
	 */
	_receiveMessage(msg, key, rinfo, cb) {
		let client = this.sockets[key];
		if (!client) {
			// a device is sending data to this instance but we don't yet have a dtls socket for it
			this.sockets[key] = client = this._createSocket(rinfo, key);
			// the device is sending application data, meaning it considers the handshake done
			// the session needs to be resumed before we can decode the application data.
			if (msg.length > 0 && msg[0] === APPLICATION_DATA_CONTENT_TYPE) {
				if (this._attemptResume(client, msg, key, cb)) {
					return;
				}
				// else we are unable to resume. Attempt to just decode the message anyway by dropping through
			}
			// else it is a non-application message (alert, handshake etc..) attempt to decode
		}

		if (cb) {
			// we cork because we want the callback to happen
			// before the implications of the message data being delivered to clients
			client.cork();
			const received = client.receive(msg);
			cb(client, received);
			client.uncork();
		} else {
			client.receive(msg);
		}
	}

	/**
	 * Creates a new dtls socket representing a dtls connection with an endpoint
	 * @param {object} rinfo     The address of the endpoint
	 * @param {string} key       The unique identifier for the client
	 * @param {boolean} selfRestored Set to `true` to indicate the socket was created by the server from a previously stored
	 *  session. `false` when the socket is created as a result of a client connecting.
	 *  Available as the `selfRestored` property on the returned object.
	 * @returns {DtlsSocket}
	 * @private
	 */
	_createSocket(rinfo, key, selfRestored) {
		var client = new DtlsSocket(this, rinfo.address, rinfo.port);
		client.sendClose = this.options.sendClose;
		client.selfRestored = selfRestored;
		this._attachToSocket(client, key);
		return client;
	}

	/**
	 * Attaches the necessary event listeners to the given DtlsSocket.
	 * @param {DtlsSocket} client
	 * @param key The key used to uniquely identify this client.
	 * @private
	 */
	_attachToSocket(client, key) {
		// todo - shouldn't the key be part of the socket rather than using the key bound to the outer scope?
		// How is the correct key used after move session?
		client.once('error', (code, err) => {
			delete this.sockets[key];
			if (!client.connected) {
				this.emit('clientError', err, client);
			}
			// todo - don't we need to close the client
		});
		client.once('close', () => {
			delete this.sockets[key];
			client = null;
			// once all keys have been deleted, close the server socket if it was being closed
			if (this._closing && Object.keys(this.sockets).length === 0) {
				this._closeSocket();
			}
		});
		client.once('reconnect', socket => {
			// treat like a brand new connection
			socket.reset();
			this._attachToSocket(socket, key);
			// todo - shouldn't we also post an event like sessionResumed or secureConnect?
			this.sockets[key] = socket;
		});

		client.once('secureConnect', () => {    // after the handshake notify server listeners that this socket is available for use
			this.emit('secureConnection', client);
		});

		this.emit('connection', client);    // notify an unsecured connection is available
	}

	/**
	 * Calls DtlsClient.end() on all client sockets.
	 * @private
	 */
	_endSockets() {
		if (this.dgramSocket) {
			this.dgramSocket.removeListener('message', this._onMessage);
		}
		const sockets = Object.keys(this.sockets);
		sockets.forEach(skey => {
			const s = this.sockets[skey];
			if (s) {
				s.end();
			}
		});
	}

	/**
	 * Handler for the closed event from the underlying network socket.
	 * This method cleans up socket listeners, closes all client sockets and emits the "close" event and then
	 * removes all listeners from this socket.
	 * @private
	 */
	_socketClosed() {
		this.listening = false;
		// todo - why not call _endSockets() first and avoid the removeListener duplication?
		if (this.dgramSocket) {
			this.dgramSocket.removeListener('message', this._onMessage);
		}
		this.dgramSocket = null;
		this._endSockets();
		this.sockets = {};

		this.emit('close');
		this.removeAllListeners();
	}

	_closeSocket() {
		if (!this.listening) {
			// simulate the socket closure when the socket has not started binding.
			process.nextTick(() => {
				this._socketClosed();
			});
			return;
		}

		if (this.dgramSocket) {
			this.dgramSocket.close();
		}
	}
}

module.exports = DtlsServer;
