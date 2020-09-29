var http = require('http');
var { Netcode } = require('../dist/node/netcode');
var { createUdpConn } = require('./nodeUdpConn');

function getConnectToken() {
  return new Promise((resolve, reject) => {
    var options = {
      host: 'localhost',
      path: '/token',
      port: '8880',
      method: 'GET',
    };

    var webtoken;
    callback = function (response) {
      response.on('data', function (chunk) {
        webtoken = JSON.parse(chunk);
        // console.log(webtoken);
        let buff = Buffer.alloc(2048, webtoken.connect_token, 'base64');
        const token = new Netcode.ConnectToken();
        var err = token.read(buff);
        if (err === Netcode.Errors.none) {
          resolve({ token, clientID: webtoken.client_id });
        } else {
          console.error('read token faile', Netcode.Errors[err]);
          reject();
        }
      });
    };

    var req = http.request(options, callback);
    req.end();
  });
}

var time = 0;
pingPayloadBytes = new Uint8Array(2);

function startClientLoop(clientID, token) {
  var client = new Netcode.Client(token);
  client.id = clientID;
  client.debug = true;
  console.log(client._connectToken.sharedTokenData.serverAddrs);
  var err = client.connect(createUdpConn);
  if (err !== Netcode.Errors.none) {
    console.error('error connecting', err);
  }
  console.log('client start connecting to server');
  setInterval(fakeGameLoop, 17, client);
}

var printed = false;
var lastSendPingTime = 0;
function fakeGameLoop(client) {
  // if (time > 5) {
  //   clearInterval(fakeGameLoop);
  // }

  if (client.state == Netcode.ClientState.connected) {
    if (!printed) {
      console.log('client connected to server');
      printed = true;
    }
    const now = Date.now();
    if (now - lastSendPingTime > 1000) {
      client.sendPayload(pingPayloadBytes);
      lastSendPingTime = now;
    }
  }

  client.tick(time);

  while (true) {
    var r = client.recvPayload();
    if (r && r.data) {
      console.log('recv pong payload', r.data);
      const rtt = Date.now() - lastSendPingTime;
      console.log('rtt', rtt);
    } else {
      break;
    }
  }

  time += 1 / 60;
}

getConnectToken().then(ret => {
  startClientLoop(ret.clientID, ret.token);
});
