import * as Defines from './Defines';
import { IUDPAddr, IUDPConn } from './Defines';
import { PacketFactory, PacketType } from './Packet';

export const SOCKET_RCVBUF_SIZE = 2048 * 2048;
export const SOCKET_SNDBUF_SIZE = 2048 * 2048;

export type NetcodeRecvHandler = (data: INetcodeData) => void;
export type UDPConnCreator = () => IUDPConn;

export interface INetcodeData {
  data: Uint8Array;
  from?: IUDPAddr;
}

export class NetcodeConn {
  public constructor() {
    this._isClosed = true;
    this._maxBytes = Defines.MAX_PACKET_BYTES;
    this._recvSize = SOCKET_RCVBUF_SIZE;
    this._sendSize = SOCKET_SNDBUF_SIZE;
  }

  public setRecvHandler(recvHandlerFn: NetcodeRecvHandler) {
    this._recvHandlerFn = recvHandlerFn;
  }

  public write(b: Uint8Array): number {
    if (this._isClosed) {
      return -1;
    }
    return this._conn.send(b);
  }

  public writeTo(b: Uint8Array, addr: IUDPAddr): number {
    if (this._isClosed) {
      return -1;
    }
    return this._conn.sendTo(b, addr);
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
    this._recvSize = bytes;
  }

  public setWriteBuffer(bytes: number) {
    this._sendSize = bytes;
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

    this._conn.setReadBuffer(this._recvSize);
    this._conn.setWriteBuffer(this._sendSize);
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
