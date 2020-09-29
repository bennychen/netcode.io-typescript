namespace Netcode {
  export const SOCKET_RCVBUF_SIZE = 2048 * 1024;
  export const SOCKET_SNDBUF_SIZE = 2048 * 1024;

  export type NetcodeRecvHandler = (data: INetcodeData) => void;
  export type UDPConnCreator = () => IUDPConn;

  export interface INetcodeData {
    data: Uint8Array;
    from?: IUDPAddr;
  }

  export class NetcodeConn {
    public constructor() {
      this._isClosed = true;
      this._maxBytes = MAX_PACKET_BYTES;
      this._recvSize = SOCKET_RCVBUF_SIZE;
      this._sendSize = SOCKET_SNDBUF_SIZE;
    }

    public setRecvHandler(recvHandlerFn: NetcodeRecvHandler) {
      this._recvHandlerFn = recvHandlerFn;
    }

    public write(b: Uint8Array): boolean {
      if (this._isClosed) {
        return false;
      }
      this._conn.send(b);
      return true;
    }

    public writeTo(b: Uint8Array, addr: IUDPAddr): boolean {
      if (this._isClosed) {
        return false;
      }
      this._conn.sendTo(b, addr);
      return true;
    }

    public close() {
      if (!this._isClosed) {
        this._isClosed = true;
        if (this._conn) {
          this._conn.close();
        }
      }
    }

    public setReadBuffer(bytes: number) {
      if (bytes) {
        this._recvSize = bytes;
        if (this._conn) {
          this._conn.setReadBuffer(this._recvSize);
        }
      }
    }

    public setWriteBuffer(bytes: number) {
      if (bytes) {
        this._sendSize = bytes;
        if (this._conn) {
          this._conn.setWriteBuffer(this._recvSize);
        }
      }
    }

    public dial(createUdpConn: UDPConnCreator, addr: IUDPAddr): boolean {
      if (!this._recvHandlerFn) {
        return false;
      }

      this._conn = createUdpConn();
      if (this._conn !== undefined) {
        this.init();
        this._conn.connect(addr);
        return true;
      } else {
        return false;
      }
    }

    public listen(createUdpConn: UDPConnCreator, addr: IUDPAddr): boolean {
      if (!this._recvHandlerFn) {
        return false;
      }

      this._conn = createUdpConn();
      if (this._conn !== undefined) {
        this._conn.bind(addr);
        this.init();
        return true;
      } else {
        return false;
      }
    }

    private init() {
      this._isClosed = false;

      if (this._recvSize) {
        this._conn.setReadBuffer(this._recvSize);
      }
      if (this._sendSize) {
        this._conn.setWriteBuffer(this._sendSize);
      }
      this._conn.onMessage(this.onMessage.bind(this));
    }

    private onMessage(message: Uint8Array, remote: IUDPAddr) {
      if (!this._recvHandlerFn) {
        console.warn('no recv handler is set for connection');
        return;
      }
      if (message && message.length <= this._maxBytes) {
        if (PacketFactory.peekPacketType(message) >= PacketType.numPackets) {
          console.warn('invalid netcode packet is received');
        } else {
          this._recvHandlerFn({
            data: message,
            from: remote,
          });
        }
      }
    }

    private _conn: IUDPConn;
    private _isClosed: boolean;
    private _maxBytes: number;
    private _recvSize: number;
    private _sendSize: number;
    private _recvHandlerFn: NetcodeRecvHandler;
  }
}
