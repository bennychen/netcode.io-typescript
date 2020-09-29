var { Netcode } = require('../dist/node/netcode');
var { createUdpConn } = require('./nodeUdpConn');

var PROTOCOL_ID = 0x1122334455667788;

// obviously you'd generate this outside of both web server and game server and store it in something
// like hashicorp vault to securely retrieve
var serverKey = new Uint8Array([
  0x60,
  0x6a,
  0xbe,
  0x6e,
  0xc9,
  0x19,
  0x10,
  0xea,
  0x9a,
  0x65,
  0x62,
  0xf6,
  0x6f,
  0x2b,
  0x30,
  0xe4,
  0x43,
  0x71,
  0xd6,
  0x2c,
  0xd1,
  0x99,
  0x27,
  0x26,
  0x6b,
  0x3c,
  0x60,
  0xf4,
  0xb7,
  0x15,
  0xab,
  0xa1,
]);

function main() {
  const server = new Netcode.Server(
    { ip: Netcode.Utils.stringToIPV4Address('127.0.0.1').ip, port: 40000 },
    serverKey,
    PROTOCOL_ID,
    255
  );
  server.listen(createUdpConn);

  var serverTime = 0;
  var delta = 10;
  setInterval(() => {
    server.update(serverTime);
    for (var i = 0; i < server.getMaxClients(); i += 1) {
      while (true) {
        var responsePayload = server.recvPayload(i);
        if (!responsePayload) {
          break;
        }
        console.log(
          'server got payload',
          responsePayload.data,
          'with sequence',
          responsePayload.sequence
        );
      }
    }
    // do simulation/process payload packets
    // send payloads to clients
    server.sendPayloads(new Uint8Array([0, 0]));
    serverTime += delta / 1000;
  }, delta);
}

main();
