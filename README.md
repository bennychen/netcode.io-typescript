# netcode.io-typescript

TypeScript/JavaScript implementation of [netcode.io](http://netcode.io).

### Why TypeScript/JavaScript version of netcode?

JavsScript is mainly used for webs, I know we cannot send UDP packets from the browser ([Why can't I send UDP packets from a browser?](http://gafferongames.com/post/why_cant_i_send_udp_packets_from_a_browser/)) . These days, instant games (e.g. Facebook Instant Games) are quite popular, and face-paced multiplayer games are inevitably emerging on these platforms. These platforms are using typical web technologies, but mostly they also expose UDP APIs from the native side. So this is the reason that I want a JavaScript version of netcode mainly for the client-side.

### netcode version

1.0.1

### Build project

npm run-script build

### Test

mocha tests

### How to use

Implement Netcode.IUDPConn interface for netcode to use to send/receive UDP packets.

A sample class is as below.

```
class InstantGameUDPConn implements Netcode.IUDPConn {
  public static create() {
    return new InstantGameUDPConn();
  }

  public constructor() {
    this._socket = createUDPSocket(); // Replace with your platform UDP API
  }
  public connect(addr: Netcode.IUDPAddr) {
    const ip = Netcode.Utils.IPV4AddressToString(addr);
    this._connectedAddr = ip;
    this._connectedPort = addr.port;
  }
  public bind(addr: Netcode.IUDPAddr) {
    this._socket.bind(addr.port);
  }
  public send(b: Uint8Array) {
    if (this._connectedPort) {
      this._socket.send({
        address: this._connectedAddr,
        port: this._connectedPort,
        message: b.buffer,
      });
    }
  }
  public sendTo(b: Uint8Array, addr: Netcode.IUDPAddr) {
    const ip = Netcode.Utils.IPV4AddressToString(addr);
    this._socket.send({
      address: ip,
      port: addr.port,
      message: b.buffer,
    });
  }
  public close() {
    this._socket.close();
  }
  public setReadBuffer(size: number) {}
  public setWriteBuffer(size: number) {}

  public onMessage(callback: Netcode.onMessageHandler) {
    this._socket.onMessage(res => {
      const { message, remoteInfo } = res;
      if (!this._addr) {
        const fullAddr = remoteInfo.address + ':' + remoteInfo.port;
        this._addr = Netcode.Utils.stringToIPV4Address(fullAddr);
      }
      callback(new Uint8Array(message), this._addr);
    });
  }

  private _connectedAddr: string;
  private _connectedPort: number;
  private _socket: UDPSocket;
  private _addr: Netcode.IUDPAddr;
}
```

Pass your Netcode.IUDPConn class creator when connecting your client.

```
const client = new Netcode.Client(YOUR_CONNECT_TOKEN);
client.id = YOUR_CLINET_ID;
client.connect(InstantGameUDPConn.create);
```
