"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var net = require("net");
// Define valid username and password
var VALID_USERNAME = 'user';
var VALID_PASSWORD = 'pass';
// Constants
var DEBUG = true;
function random(min, max) {
    return Math.floor((Math.random()) * (max - min + 1)) + min;
}
var proxy = net.createServer(function (c) {
    var id = random(10000, 99999).toString();
    //  crypto.createHash('md5').update(<string>c.remoteAddress).update((<number>c.remotePort).toString()).digest("hex")
    c.on('end', function () {
        console.log('[%s] client disconnected', id);
    });
    c.on('close', function () {
        console.log('[%s] client disconnected', id);
    });
    c.on("error", function (err) {
        console.error('[%s] Remote connection error: %s', id, err.message);
        c.end();
    });
    c.once('data', function (data) {
        console.log("[%s] Connection from %s:%s", id, c.remoteAddress, c.remotePort);
        var version = data[0];
        if (DEBUG)
            console.log("[%s] Provided version: %s", id, version);
        if (version !== 0x05) {
            console.error('[%s] Only SOCKS5 is supported', id);
            c.end();
            return;
        }
        var nMethods = data[1];
        var methods = data.subarray(2, 2 + nMethods);
        if (!methods.includes(0x02)) {
            // No supported authentication method
            c.write(Buffer.from([0x05, 0xFF]));
            c.end();
            return;
        }
        // Send response to choose username/password authentication
        c.write(Buffer.from([0x05, 0x02]));
        c.once('data', function (authData) {
            var version = authData[0];
            if (version !== 0x01) {
                console.error('[%s] Unsupported authentication version: %s', id, version);
                c.end();
                return;
            }
            var usernameLength = authData[1];
            var username = authData.subarray(2, 2 + usernameLength).toString();
            var passwordLength = authData[2 + usernameLength];
            var password = authData
                .subarray(3 + usernameLength, 3 + usernameLength + passwordLength)
                .toString();
            if (username === VALID_USERNAME && password === VALID_PASSWORD) {
                // Send success response
                c.write(Buffer.from([0x01, 0x00]));
                handleSocksRequest(c, id);
            }
            else {
                // Send failure response
                c.write(Buffer.from([0x01, 0x01]));
                c.end();
            }
        });
    });
});
function handleSocksRequest(c, id) {
    c.once('data', function (data) {
        var version = data[0];
        var command = data[1];
        var addressType = data[3];
        var host;
        var port;
        if (command !== 0x01) {
            console.error('[%s] Only CONNECT command is supported: ', id, command);
            c.end();
            return;
        }
        if (addressType === 0x01) {
            // IPv4 address
            host = data.subarray(4, 8).join('.');
            port = data.readUInt16BE(8);
        }
        else if (addressType === 0x03) {
            // Domain name
            var length_1 = data[4];
            host = data.subarray(5, 5 + length_1).toString();
            port = data.readUInt16BE(5 + length_1);
        }
        else {
            console.error('[%s] Address type not supported: ', id, addressType);
            c.end();
            return;
        }
        var remoteSocket = net.createConnection(port, String(host), function () {
            // Send success response
            c.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
            // Pipe the data
            remoteSocket.pipe(c);
            c.pipe(remoteSocket);
        });
        remoteSocket.on('error', function (err) {
            console.error('[%s] Remote connection error: %s', id, err.message);
            c.end();
        });
    });
}
proxy.listen(1080, function () {
    console.log('SOCKS5 proxy server with authentication is running on port 1080');
});
