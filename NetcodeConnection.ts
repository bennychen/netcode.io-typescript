import * as Defines from './Defines';
import { IUDPAddr, IUDPConn } from './Defines';
import { Errors } from './Errors';
import { Queue } from './Utils';
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
    this._msgQueue = new Queue<INetcodeData>(128);
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

  public writeTo(b: Uint8Array, address: string, port: number): number {
    if (this._isClosed) {
      return -1;
    }
    return this._conn.sendTo(b, address, port);
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

  public dial(
    createUdpConn: UDPConnCreator,
    ip: string,
    port: number
  ): boolean {
    if (!this._recvHandlerFn) {
      return false;
    }

    this._conn = createUdpConn();
    if (this._conn !== undefined) {
      this.init();
      this._conn.connect(ip, port);
      return true;
    } else {
      return false;
    }
  }

  public listen(createUdpConn: UDPConnCreator, port: number): boolean {
    if (!this._recvHandlerFn) {
      return false;
    }

    this._conn = createUdpConn();
    if (this._conn !== undefined) {
      this._conn.bind(port);
      this.init();
      return true;
    } else {
      return false;
    }
  }

  public read(): Errors {
    if (!this._recvHandlerFn) {
      return Errors.invalidHandler;
    }
    const msg = this._msgQueue.pop();
    if (PacketFactory.peekPacketType(msg.data) >= PacketType.numPackets) {
      return Errors.invalidPacket;
    }
    this._recvHandlerFn(msg);
    return Errors.none;
  }

  private init() {
    this._isClosed = false;

    this._conn.setReadBuffer(this._recvSize);
    this._conn.setWriteBuffer(this._sendSize);
    this._conn.onMessage(this.onMessage.bind(this));
  }

  private onMessage(
    message: Uint8Array,
    messageSize: number,
    remote: IUDPAddr
  ) {
    if (message && messageSize > 0 && messageSize <= this._maxBytes) {
      this._msgQueue.push({
        data: message.subarray(0, messageSize),
        from: remote,
      });
    }
  }

  private _msgQueue: Queue<INetcodeData>;
  private _conn: IUDPConn;
  private _isClosed: boolean;
  private _maxBytes: number;
  private _recvSize: number;
  private _sendSize: number;
  private _recvHandlerFn: NetcodeRecvHandler;
}
