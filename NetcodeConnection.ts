import * as Defines from './Defines';
import { IUDPAddr, IUDPConn, INetcodeData } from './Defines';
import { Errors } from './Errors';
import { PacketFactory, PacketType } from './Packet';

export const SOCKET_RCVBUF_SIZE = 2048 * 2048;
export const SOCKET_SNDBUF_SIZE = 2048 * 2048;

export type NetcodeRecvHandler = (data: INetcodeData) => void;
export type UDPHandler = (data: IUDPAddr) => IUDPConn;

export class NetcodeConn {
  public constructor() {
    this._isClosed = true;
    this._maxBytes = Defines.MAX_PACKET_BYTES;
    this._recvSize = SOCKET_RCVBUF_SIZE;
    this._sendSize = SOCKET_SNDBUF_SIZE;
    this._buffer = new Uint8Array(this._maxBytes);
  }

  public setRecvHandler(recvHandlerFn: NetcodeRecvHandler) {
    this._recvHandlerFn = recvHandlerFn;
  }

  public write(b: Uint8Array): number {
    if (this._isClosed) {
      return -1;
    }
    return this._conn.write(b);
  }

  public writeTo(b: Uint8Array, to: IUDPAddr): number {
    if (this._isClosed) {
      return -1;
    }
    return this._conn.writeTo(b, to);
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

  public dial(dialFn: UDPHandler, address: IUDPAddr): boolean {
    if (!this._recvHandlerFn) {
      return false;
    }

    this._conn = dialFn(address);
    if (this._conn !== undefined) {
      this.init();
      return true;
    } else {
      return false;
    }
  }

  public listen(listenFn: UDPHandler, address: IUDPAddr): boolean {
    if (!this._recvHandlerFn) {
      return false;
    }

    this._conn = listenFn(address);
    if (this._conn !== undefined) {
      this.init();
      return true;
    } else {
      return false;
    }
  }

  // read does the actual connection read call, verifies we have a
  // buffer > 0 and < maxBytes and is of a valid packet type before
  // we bother to attempt to actually dispatch it to the recvHandlerFn.
  public read(): Errors {
    if (!this._recvHandlerFn) {
      return Errors.invalidHandler;
    }
    const { n, from, err } = this._conn.readFromUDP(this._buffer);
    if (err) {
      return Errors.readUDPError;
    }

    if (n === 0) {
      return Errors.socketZeroRecv;
    }
    if (n > this._maxBytes) {
      return Errors.overMaxReadSize;
    }

    if (
      PacketFactory.peekPacketType(this._buffer) >=
      PacketType.ConnectionNumPackets
    ) {
      return Errors.invalidPacket;
    }

    this._recvHandlerFn({
      data: this._buffer.subarray(0, n),
      from,
    });
    return Errors.none;
  }

  private init() {
    this._isClosed = false;
    this._conn.setReadBuffer(this._recvSize);
    this._conn.setWriteBuffer(this._sendSize);
  }

  private _buffer: Uint8Array;
  private _conn: IUDPConn;
  private _isClosed: boolean;
  private _maxBytes: number;
  private _recvSize: number;
  private _sendSize: number;
  private _recvHandlerFn: NetcodeRecvHandler;
}
