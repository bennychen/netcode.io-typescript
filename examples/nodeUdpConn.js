var udp = require('dgram');
var ipaddr = require('./ipaddr');

class NodeUDPConn {
  constructor() {
    this._socket = udp.createSocket('udp4');
  }
  connect(addr) {
    var ipAddr = ipaddr.fromByteArray(addr.ip);
    var ip = ipAddr.toString();
    // var ip = Utils.IPV4AddressToString(addr);
    console.log('ip address', ip);
    this._socket.connect(addr.port, ip);
  }
  bind(addr) {
    var ipAddr = ipaddr.fromByteArray(addr.ip);
    var ip = ipAddr.toString();
    console.log('bind to', ip, addr.port);
    this._socket.bind(addr.port, ip);
    this._binded = true;
  }
  send(b) {
    this._socket.send(b);
  }
  sendTo(b, to) {
    var ipAddr = ipaddr.fromByteArray(addr.ip);
    var ip = ipAddr.toString();
    this._socket.send(b, 0, b.length, to.port, ip);
  }
  close() {
    this._socket.close;
  }
  setReadBuffer(size) {
    if (this._binded && this._socket) {
      // this._socket.setRecvBufferSize(size);
    }
  }
  setWriteBuffer(size) {
    if (this._binded && this._socket) {
      // this._socket.setWriteBufferSize(size);
    }
  }
  onMessage(callback) {
    if (!this._strAddressToBytes) {
      this._strAddressToBytes = {};
    }
    this._socket.on('message', (msg, remote) => {
      const fullAddr = remote.address + ':' + remote.port;
      let addr = this._strAddressToBytes[fullAddr];
      if (!addr) {
        const ipAddr = ipaddr.parse(remote.address);
        addr = this._strAddressToBytes[fullAddr] = new Uint8Array(
          ipAddr.toByteArray()
        );
        // addr = this._strAddressToBytes[fullAddr] = Utils.stringToIPV4Address(fullAddr);
      }
      callback(msg, addr);
    });
  }
}

this.createUdpConn = function (addr) {
  return new NodeUDPConn();
};
