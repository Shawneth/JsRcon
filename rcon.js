var buffertools = require('buffertools');
var crypto = require('crypto');
var dgram = require('dgram');
var dns = require('dns');
var events = require('events');
var util = require('util');

var huffman = require('./huffman');
var proto = require('./proto');

// RCON protocol uses MD5
var md5 = crypto.createHash('md5');

// Initialize huffman table with proper Zandronum frequencies.	
var huf = new huffman.Huffman(proto.huffmanFreqs);

// Read a string from a buffer
function readString(buf, offset, encoding) {
	if (offset === undefined) {
		offset = 0;
	}

	if (encoding === undefined) {
		encoding = 'utf8';
	}

	var z = buffertools.indexOf(buf, "\0", offset);
	if (z === -1) {
		throw new TypeError("Null-terminator not found in buffer");
	}

	return buf.toString(encoding, offset, z);
}

// Write a string into a buffer
function writeString(buf, str, offset, encoding) {
	if (offset === undefined) {
		offset = 0;
	}

	if (encoding === undefined) {
		encoding = 'utf8';
	}

	var string = new Buffer(str, encoding);
	string.copy(buf, offset);
	buf.writeUInt8(0, offset + string.length);
}

function connectServer(options, callback) {
	var rcon = new RCONSocket();
	rcon.connect(options.password, options.port, options.host, callback);
	return rcon;
}

/**
 * RCONSocket
 *
 * An abstraction over a Zandronum RCON connection.
 */

// Constructor

class RCONSocket extends events.EventEmitter {

	constructor() {
		super();
		this._connected = false;
		this._connecting = false;

		this._dgram = dgram.createSocket('udp4');
		this._dgram.on('message', this.router.bind(this));
		this._dgram.bind();

		events.EventEmitter.call(this);
	}

	// Router, which handles all incoming messages
	router(msg, rinfo) {
		if (this._connected === false && this._connecting === false) {
			// What are we doing listening without being connected?
			return;
		}

		if (rinfo.address !== this._address || rinfo.port !== this._port) {
			// Traffic does not belong to this RCONSocket.
			return;
		}

		var decoded = huf.decode(msg);
		var type = decoded.readUInt8(0);

		switch (type) {
			case proto.SVRC_OLDPROTOCOL:
				if (this._connecting === false) {
					this.emit("error", new Error("SVRC_OLDPROTOCOL response while not connecting."));
				} else {
					this.emit("error", new Error("RCON protocol is out of date."));
				}
				break;
			case proto.SVRC_BANNED:
				if (this._connecting === false) {
					this.emit("error", new Error("SVRC_BANNED response while not connecting."));
				} else {
					this.emit("error", new Error("You are banned from the server."));
				}
				break;
			case proto.SVRC_SALT:
				if (this._connecting === false) {
					this.emit("error", new Error("SVRC_SALT response while not connecting."));
					return;
				}
				if (decoded.length !== 34) {
					this.emit("error", new Error("SVRC_SALT response does not include a 32-byte salt."));
					return;
				}

				// Hash the password with the salt to send back
				var saltbuff = readString(decoded, 1, 'ascii');
				var passbuff = new Buffer(this._password, 'ascii');
				md5.update(buffertools.concat(saltbuff, passbuff));
				var hashed = md5.digest();

				// Server response requires hex string representation of md5 digest.
				var hexhash = hashed.toString('hex');
				var response = new Buffer(hexhash.length + 2);
				response.writeUInt8(proto.CLRC_PASSWORD, 0);
				writeString(response, hexhash, 1, 'ascii');

				// Send the response
				var encoded = huf.encode(response);
				this._dgram.send(encoded, 0, encoded.length, this._port, this._address);
				break;
			case proto.SVRC_LOGGEDIN:
				if (this._connecting === false) {
					this.emit("error", new Error("SVRC_LOGGEDIN response while not connecting."));
					return;
				}

				// Connection state is now connected.
				this._connecting = false;
				this._connected = true;

				// Pong the server every five seconds so we stay connected.
				var self = this;
				var pongbuf = new Buffer(1);
				pongbuf.writeUInt8(proto.CLRC_PONG, 0);
				var pong = huf.encode(pongbuf);
				this._pongTimer = setInterval(function () {
					console.log("Sending ping...");
					self._dgram.send(pong, 0, pong.length, self._port, self._address);
				}, 5000);

				this.emit("connect");
				break;
			case proto.SVRC_INVALIDPASSWORD:
				if (this._connecting === false) {
					this.emit("error", new Error("SVRC_INVALIDPASSWORD response while not connecting."));
				} else {
					this.emit("error", new Error("Invalid password."));
				}
				break;
			case proto.SVRC_MESSAGE:
				if (this._connected === false) {
					this.emit("error", new Error("SVRC_MESSAGE response while not connected."));
					return;
				}
				var msg = readString(decoded, 1, 'ascii');
				this.emit("message", msg);
				break;
			case proto.SVRC_UPDATE:
				if (this._connected === false) {
					this.emit("error", new Error("SVRC_UPDATE response while not connected."));
					return;
				}

				// Updates have their own subtype
				var updateType = decoded.readUInt8(1);
				switch (updateType) {
					case proto.SVRCU_PLAYERDATA:
						var index = 3;
						var players = [];
						var playercount = decoded.readUInt8(2);
						for (var i = 0; i < playercount; i++) {
							var name = readString(decoded, index, 'ascii');
							players.push(name);
							index += 1 + name.length;
						}
						this.emit("players", players);
						break;
					case proto.SVRCU_ADMINCOUNT:
						var admins = decoded.readUInt8(2);
						this.emit("admins", admins);
						break;
					case proto.SVRCU_MAP:
						var map = readString(decoded, 2, 'ascii');
						this.emit("map", map);
						break;
					default:
						this.emit("error", new Error("Unrecognized update."));
						break;
				}
				break;
			default:
				this.emit("error", new Error("Unrecognized response."));
				break;
		}
	}

	// Connect to the RCON endpoint.
	connect(password, port, host, callback) {
		var self = this;

		this._connecting = true;
		this._password = password;
		this._port = port;

		dns.lookup(host, 4, function (err, address, family) {
			self._address = address;

			// Attempt to connect with protocol version 3
			var buf = new Buffer(2);
			buf.writeUInt8(proto.CLRC_BEGINCONNECTION, 0);
			buf.writeUInt8(3, 1);
			var encoded = huf.encode(buf);

			self._dgram.send(encoded, 0, encoded.length, port, host);
		});
	}
	disconnect() {
		// We're not connected.
		if (this._connected === false) {
			return;
		}

		var buf = new Buffer(1);
		buf.writeUInt8(proto.CLRC_DISCONNECT, 0);
		var encoded = huf.encode(buf);

		this._dgram.send(encoded, 0, encoded.length, port, host);
	}

	sendCommand(text) {
		// We're not connected.
		if (this._connected === false) {
			return;
		}

		var buf = new Buffer(text.length + 2);
		buf.writeUInt8(proto.CLRC_COMMAND, 0);
		writeString(buf, text, 1);
		var encoded = huf.encode(buf);

		this._dgram.send(encoded, 0, encoded.length, 10666, "localhost");
	}

}

exports.connectServer = connectServer;
exports.RCONSocket = RCONSocket;
