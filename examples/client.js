var udp = require('dgram');
var http = require('http');
var buffer = require('buffer');
var { ConnectToken } = require('../bin/Token');
const { Errors } = require('../bin/Errors');
const { Client } = require('../bin/Client');

// // creating a client socket
// var client = udp.createSocket('udp4');

// //buffer msg
// var data = Buffer.from('siddheshrane');

// client.on('message', function (msg, info) {
//   console.log('Data received from server : ' + msg.toString());
//   console.log(
//     'Received %d bytes from %s:%d\n',
//     msg.length,
//     info.address,
//     info.port
//   );
// });

// //sending msg
// client.send(data, 2222, 'localhost', function (error) {
//   if (error) {
//     client.close();
//   } else {
//     console.log('Data sent !!!');
//   }
// });

// var data1 = Buffer.from('hello');
// var data2 = Buffer.from('world');

// //sending multiple msg
// client.send([data1, data2], 2222, 'localhost', function (error) {
//   if (error) {
//     client.close();
//   } else {
//     console.log('Data sent !!!');
//   }
// });

class NodeUDPConn {
  constructor() {
    this._socket = udp.createSocket('udp4');
  }
  connect(addr) {
    this._socket.connect(addr.)
  }
  bind(addr) {}
  send(b) {}
  sendTo(b, to) {}
  close() {}
  setReadBuffer(size) {}
  setWriteBuffer(size) {}
  onMessage(callback) {}
}

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
        let buff = Buffer.alloc(2048, webtoken.connect_token, 'base64');
        const token = new ConnectToken();
        var err = token.read(buff);
        if (err === Errors.none) {
          resolve({ token, clientID: webtoken.client_id });
        } else {
          rejects();
        }
      });
    };

    var req = http.request(options, callback);
    req.end();
  });
}

function dial(addr) {}

function clientLoop(clientID, token) {
  var time = 0;
  var delta = 1 / 60;

  var client = new Client();
  client.id = clientID;
  console.log(client);
  client.connect();
}

getConnectToken().then(ret => {
  clientLoop(ret.clientID, ret.token);
});
