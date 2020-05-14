const http = require('http');
const static = require('node-static');
const file = new static.Server('./');
const crypto = require('crypto');
const server = http.createServer((req, res) => {
    req.addListener('end', () => {
        file.serve(req, res)
    }).resume();
});
server.on('upgrade', (req, socket) => {
    if (req.headers['upgrade'] !== 'websocket') {
        socket.end('HTTP/1.1 400 Bad Request');
        return;
    }
    // // Read the websocket key provided by the client: 
    const acceptKey = req.headers['sec-websocket-key'];
    const hash = generateAcceptValue(acceptKey);
    const responseHeaders = ['HTTP/1.1 101 Web Socket Protocol Handshake', 'Upgrade: WebSocket', 'Connection: Upgrade', `Sec-WebSocket-Accept: ${hash}`];
    // // If client has provided subprotocols and that the server doesn't support any of them, send error response and close the connection 
    const protocol = req.headers['sec-websocket-protocol'];
    const protocols = !protocol ? [] : protocol.split(',').map(s => s.trim());
    if (protocols.includes('json')) {
        // Tell the client that we agree to communicate with JSON data
        responseHeaders.push(`Sec-WebSocket-Protocol: json`);
    }
    // Write the response back to the client socket, the 2 additional newlines are mandatory
    socket.write(responseHeaders.join('\r\n') + '\r\n\r\n');
    socket.on('data', (buffer) => {
        const message = parseMessage(buffer);
        if (message) {
            // For our convenience, so we can see what the client sent
            console.log(message);
            // We'll just send a hardcoded message in this example 
            socket.write(constructReply({ message: 'Hello from the server!' }));
        } else if (message === null) {
            console.log('WebSocket connection closed by the client.');
        }
    });
});

function generateAcceptValue(acceptKey) {
    return crypto
        .createHash('sha1')
        .update(acceptKey + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', 'binary')
        .digest('base64');
}

function parseMessage(buffer) {
    var firstByte = buffer.readUInt8();
    const isFinalFrame = Boolean((firstByte >>> 7) & 0x1);
    const [reserved1, reserved2, reserved3] = [Boolean((firstByte >>> 6) & 0x1), Boolean((firstByte >>> 5) & 0x1), Boolean((firstByte >>> 4) & 0x1)];
    const opCode = firstByte & 0xF;
    // We can return null to signify that this is a connection termination frame 
    if (opCode === 0x8) {
        return null;
    }
    // We only care about text frames from this point onward 
    if (opCode !== 0x1) {
        return;
    }
    const secondByte = buffer.readUInt8(1);
    const isMasked = Boolean((secondByte >>> 7) & 0x1);
    let currentOffset = 2;
    let payloadLength = secondByte & 0x7F;
    if (payloadLength > 125) {
        if (payloadLength === 126) {
            payloadLength = buffer.readUInt16BE(currentOffset);
            currentOffset += 2;
        } else {
            // 127 
            // If this has a value, the frame size is ridiculously huge! 
            const leftPart = buffer.readUInt32BE(currentOffset);
            const rightPart = buffer.readUInt32BE(currentOffset += 4);
            // Not currently supported, and if get to this point, something is probably wrong
            throw new Error('Large payloads not currently implemented');
        }
    }

    let maskingKey;
    if (isMasked) {
        maskingKey = buffer.readUInt32BE(currentOffset);
        var masking = Buffer.from(buffer.buffer, currentOffset, 32 / 8);
        currentOffset += 4;
    }

    const data = Buffer.alloc(payloadLength);

    if (isMasked) {
        for (let i = 0; i < payloadLength; ++i) {
            var maskingByteIndex = masking.readUInt8(i % 4);
            const source = buffer.readUInt8(currentOffset++);
            data.writeUInt8(maskingByteIndex ^ source, i);
        }
    } else {
        buffer.copy(data, 0, currentOffset++);
    }

    return data.toString('utf8');
}

function constructReply(data) {
    // Convert the data to JSON and copy it into a buffer
    const json = JSON.stringify(data);
    const jsonByteLength = Buffer.byteLength(json);
    // Note: we're not supporting > 65535 byte payloads at this stage 
    const lengthByteCount = jsonByteLength < 126 ? 0 : 2;
    const payloadLength = lengthByteCount === 0 ? jsonByteLength : 126;
    const buffer = Buffer.alloc(2 + lengthByteCount + jsonByteLength);
    buffer.writeUInt8(0b10000001, 0);
    buffer.writeUInt8(payloadLength, 1);
    // Write the length of the JSON payload to the second byte 
    let payloadOffset = 2;
    if (lengthByteCount > 0) {
        buffer.writeUInt16BE(jsonByteLength, 2);
        payloadOffset += lengthByteCount;
    }
    // Write the JSON data to the data buffer 
    buffer.write(json, payloadOffset);
    parseMessage(buffer);
    return buffer;
}
const port = 3210;
server.listen(port, () => console.log(`Server running at http://localhost:${port}`));