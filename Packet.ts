import * as Defines from './Defines';
import { ByteBuffer, Long } from './ByteBuffer';
import { ConnectTokenPrivate } from './ConnectToken';
import { Errors } from './Errors';
import { Utils } from './Utils';
import { ReplayProtection } from './ReplayProtection';

export enum PacketType {
  ConnectionRequest,
  ConnectionDenied,
  ConnectionChallenge,
  ConnectionResponse,
  ConnectionKeepAlive,
  ConnectionPayload,
  ConnectionDisconnect,

  ConnectionNumPackets,
}

export interface IReadParams {
  protocolId: Long;
  currentTimestamp: number;
  readPacketKey: Uint8Array;
  privateKey: Uint8Array;
  allowedPackets: Uint8Array;
  replayProtection: ReplayProtection;
}

export interface IPacket {
  getType(): PacketType;
  sequence(): number;
  write(
    buf: Uint8Array,
    protocolID: Long,
    sequence: number,
    writePacketKey: Uint8Array
  ): number;
  read(
    packetData: Uint8Array,
    packetLen: number,
    readParams: IReadParams
  ): Errors;
}

export class PacketQueue {
  public constructor(capacity: number) {
    this._capacity = capacity;
    this._packets = new Array<IPacket>(capacity);
  }

  public clear() {
    this._numPackets = 0;
    this._startIndex = 0;
    this._packets.fill(null);
  }

  public push(packet: IPacket): boolean {
    if (this._numPackets === this._capacity) {
      return false;
    }

    const index = (this._startIndex + this._numPackets) % this._capacity;
    this._packets[index] = packet;
    this._numPackets++;
    return true;
  }

  public pop(): IPacket {
    if (this._numPackets === 0) {
      return null;
    }
    const packet = this._packets[this._startIndex];
    this._startIndex = (this._startIndex + 1) % this._capacity;
    this._numPackets--;
    return packet;
  }

  private _numPackets: number;
  private _startIndex: number;
  private _packets: Array<IPacket>;
  private _capacity: number;
}

export class PacketFactory {
  public static peekPacketType(packetBuffer: Uint8Array): PacketType {
    const prefix = packetBuffer[0];
    return prefix & 0xf;
  }

  public static create(packetBuffer: Uint8Array): IPacket {
    const packetType = this.peekPacketType(packetBuffer);
    switch (packetType) {
      case PacketType.ConnectionRequest:
        return new RequestPacket();
      default:
        return null;
    }
  }
}

export class RequestPacket implements IPacket {
  public getType(): PacketType {
    return PacketType.ConnectionRequest;
  }

  public sequence(): number {
    return 0;
  }

  public setProperties(
    versionInfo: Uint8Array,
    protocolID: Long,
    expireTimeStamp: Long,
    sequence: Long,
    connectTokenData: Uint8Array
  ) {
    this._versionInfo = versionInfo;
    this._protocolID = protocolID;
    this._connectTokenExpireTimestamp = expireTimeStamp;
    this._connectTokenSequence = sequence;
    this._connectTokenData = connectTokenData;
  }

  public write(
    buf: Uint8Array,
    protocolID: Long,
    sequence: number,
    writePacketKey: Uint8Array
  ): number {
    const bb = new ByteBuffer(buf);
    bb.writeUint8(PacketType.ConnectionRequest);
    bb.writeBytes(this._versionInfo);
    bb.writeUint64(this._protocolID);
    bb.writeUint64(this._connectTokenExpireTimestamp);
    bb.writeUint64(this._connectTokenSequence);
    bb.writeBytes(this._connectTokenData);
    if (
      bb.position !==
      1 + 13 + 8 + 8 + 8 + Defines.CONNECT_TOKEN_PRIVATE_BYTES
    ) {
      return -1;
    }
    return bb.position;
  }

  public read(
    packetData: Uint8Array,
    packetLen: number,
    readParams: IReadParams
  ): Errors {
    const bb = new ByteBuffer(packetData);
    const packetType = bb.readUint8();
    if (
      packetType === undefined ||
      packetType !== PacketType.ConnectionRequest
    ) {
      return Errors.invalidPacket;
    }
    if (readParams.allowedPackets[0] === 0) {
      return Errors.packetTypeNotAllowed;
    }
    if (
      packetLen !==
      1 +
        Defines.VERSION_INFO_BYTES +
        8 +
        8 +
        8 +
        Defines.CONNECT_TOKEN_PRIVATE_BYTES
    ) {
      return Errors.badPacketLength;
    }
    if (!readParams.privateKey) {
      return Errors.noPrivateKey;
    }

    this._versionInfo = bb.readBytes(Defines.VERSION_INFO_BYTES);
    if (
      this._versionInfo === undefined ||
      !Utils.arrayEqual(this._versionInfo, Defines.VERSION_INFO_BYTES_ARRAY)
    ) {
      return Errors.badVersionInfo;
    }

    this._protocolID = bb.readUint64();
    if (
      this._protocolID === undefined ||
      !this._protocolID.equals(readParams.protocolId)
    ) {
      return Errors.badProtocolID;
    }

    this._connectTokenExpireTimestamp = bb.readUint64();
    if (
      this._connectTokenExpireTimestamp === undefined ||
      this._connectTokenExpireTimestamp.toNumber() <=
        readParams.currentTimestamp
    ) {
      return Errors.connectTokenExpired;
    }

    this._connectTokenSequence = bb.readUint64();
    if (this._connectTokenSequence === undefined) {
      return Errors.EOF;
    }

    if (bb.position !== 1 + Defines.VERSION_INFO_BYTES + 8 + 8 + 8) {
      return Errors.packetInvalidLength;
    }

    const tokenBuffer = bb.readBytes(Defines.CONNECT_TOKEN_PRIVATE_BYTES);
    if (tokenBuffer === undefined) {
      return Errors.EOF;
    }

    this._token = ConnectTokenPrivate.createEncrypted(tokenBuffer);
    if (
      !this._token.decrypt(
        this._protocolID,
        this._connectTokenExpireTimestamp,
        this._connectTokenSequence,
        readParams.privateKey
      )
    ) {
      return Errors.decryptPrivateTokenData;
    }

    if (!this._token.read()) {
      return Errors.decryptPrivateTokenData;
    }

    return Errors.none;
  }

  private _versionInfo: Uint8Array;
  private _protocolID: Long;
  private _connectTokenExpireTimestamp: Long;
  private _connectTokenSequence: Long;
  private _token: ConnectTokenPrivate;
  private _connectTokenData: Uint8Array;
}
