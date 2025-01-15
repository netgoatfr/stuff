import * as net from 'net';
import * as crypto from 'crypto';


// Define valid username and password
const VALID_USERNAME = 'user';
const VALID_PASSWORD = 'pass';

// Constants
const DEBUG = true;

function random(min: number, max: number) {
    return Math.floor((Math.random()) * (max - min + 1)) + min;
}

const proxy = net.createServer((c) => {
    var id = random(10000, 99999).toString()
    //  crypto.createHash('md5').update(<string>c.remoteAddress).update((<number>c.remotePort).toString()).digest("hex")
    c.on('end', () => {
        console.log('[%s] client disconnected', id);
    });
    c.on('close', () => {
        console.log('[%s] client disconnected', id);
    });
    c.on("error", (err) => {
        console.error('[%s] Remote connection error: %s', id, err.message);
        c.end();
    })
    c.once('data', (data) => {
        console.log("[%s] Connection from %s:%s", id, c.remoteAddress, c.remotePort)
        const version = data[0];
        if (DEBUG) console.log("[%s] Provided version: %s", id, version)
        if (version !== 0x05) {
            console.error('[%s] Only SOCKS5 is supported', id);
            c.end();
            return;
        }

        const nMethods = data[1];
        const methods = data.subarray(2, 2 + nMethods);

        if (!methods.includes(0x02)) {
            // No supported authentication method
            c.write(Buffer.from([0x05, 0xFF]));
            c.end();
            return;
        }

        // Send response to choose username/password authentication
        c.write(Buffer.from([0x05, 0x02]));

        c.once('data', (authData) => {
            const version = authData[0];
            if (version !== 0x01) {
                console.error('[%s] Unsupported authentication version: %s', id, version);
                c.end();
                return;
            }

            const usernameLength = authData[1];
            const username = authData.subarray(2, 2 + usernameLength).toString();

            const passwordLength = authData[2 + usernameLength];
            const password = authData
                .subarray(3 + usernameLength, 3 + usernameLength + passwordLength)
                .toString();

            if (username === VALID_USERNAME && password === VALID_PASSWORD) {
                // Send success response
                c.write(Buffer.from([0x01, 0x00]));
                handleSocksRequest(c, id);
            } else {
                // Send failure response
                c.write(Buffer.from([0x01, 0x01]));
                c.end();
            }
        });
    });
});

function handleSocksRequest(c: net.Socket, id: String) {
    c.once('data', (data) => {
        const version = data[0];
        const command = data[1];
        const addressType = data[3];
        let host: String;
        let port: number;

        if (command !== 0x01) {
            console.error('[%s] Only CONNECT command is supported: ', id, command);
            c.end();
            return;
        }

        if (addressType === 0x01) {
            // IPv4 address
            host = data.subarray(4, 8).join('.');
            port = data.readUInt16BE(8);
        } else if (addressType === 0x03) {
            // Domain name
            const length = data[4];
            host = data.subarray(5, 5 + length).toString();
            port = data.readUInt16BE(5 + length);
        } else {
            console.error('[%s] Address type not supported: ', id, addressType);
            c.end();
            return;
        }

        const remoteSocket = net.createConnection(port, String(host), () => {
            // Send success response
            c.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));

            // Pipe the data
            remoteSocket.pipe(c);
            c.pipe(remoteSocket);
        });

        remoteSocket.on('error', (err) => {
            console.error('[%s] Remote connection error: %s', id, err.message);
            c.end();
        });
    });
}

proxy.listen(1080, () => {
    console.log('SOCKS5 proxy server with authentication is running on port 1080');
});

