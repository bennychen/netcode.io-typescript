import * as Defines from './Defines';
import { ByteBuffer, Long } from './ByteBuffer';
import { ConnectTokenPrivate } from './ConnectToken';

enum PacketType {
  ConnectionRequest,
  ConnectionDenied,
  ConnectionChallenge,
  ConnectionResponse,
  ConnectionKeepAlive,
  ConnectionPayload,
  ConnectionDisconnect,

  ConnectionNumPackets,
}

enum PacketError {
  none,
  EOF,

  invalidPacket,

  requestPacketTypeNotAllowed,
  requestBadPacketLength,
  requestPacketNoPrivateKey,
  reqeustPacketBadVersionInfoBytes,
  reqeustPacketBadVersionInfo,
  reqeustPacketBadProtocolID,
  reqeustPacketConnectTokenExpired,
  reqeustPacketInvalidLength,
  reqeustPacketDecryptPrivateTokenData,
}

function peekPacketType(packetBuffer: Uint8Array): PacketType {
  const prefix = packetBuffer[0];
  return prefix & 0xf;
}

class ReplayProtection {
  MostRecentSequence: number;
  ReceivedPacket: number[];
}

interface IReadParams {
  protocolId: Long;
  currentTimestamp: number;
  readPacketKey: Uint8Array;
  privateKey: Uint8Array;
  allowedPackets: Uint8Array;
  replayProtection: ReplayProtection;
}

interface IPacket {
  GetType(): PacketType;
  Sequence(): number;
  Write(buf: Uint8Array, sequence: number, writePacketKey: Uint8Array): number;
  Read(
    packetData: Uint8Array,
    packetLen: number,
    readParams: IReadParams
  ): PacketError;
}

class PacketFactory {
  public static create(packetBuffer: Uint8Array): IPacket {
    const packetType = peekPacketType(packetBuffer);
    switch (packetType) {
      case PacketType.ConnectionRequest:
        return new RequestPacket();
      default:
        return null;
    }
  }
}

class RequestPacket implements IPacket {
  public GetType(): PacketType {
    return PacketType.ConnectionRequest;
  }

  public Sequence(): number {
    return 0;
  }

  public Write(
    buf: Uint8Array,
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

  public Read(
    packetData: Uint8Array,
    packetLen: number,
    readParams: IReadParams
  ): PacketError {
    const bb = new ByteBuffer(packetData);
    const packetType = bb.readUint8();
    if (
      packetType === undefined ||
      packetType !== PacketType.ConnectionRequest
    ) {
      return PacketError.invalidPacket;
    }
    if (readParams.allowedPackets[0] === 0) {
      return PacketError.requestPacketTypeNotAllowed;
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
      return PacketError.requestBadPacketLength;
    }
    if (!readParams.privateKey) {
      return PacketError.requestPacketNoPrivateKey;
    }

    this._versionInfo = bb.readBytes(Defines.VERSION_INFO_BYTES);
    if (this._versionInfo === undefined) {
      return PacketError.reqeustPacketBadVersionInfoBytes;
    }
    if (this._versionInfo.toString() !== Defines.VERSION_INFO) {
      return PacketError.reqeustPacketBadVersionInfo;
    }

    this._protocolID = bb.readUint64();
    if (
      this._protocolID === undefined ||
      !this._protocolID.equals(readParams.protocolId)
    ) {
      return PacketError.reqeustPacketBadProtocolID;
    }

    this._connectTokenExpireTimestamp = bb.readUint64();
    if (
      this._connectTokenExpireTimestamp === undefined ||
      this._connectTokenExpireTimestamp.toNumber() <=
        readParams.currentTimestamp
    ) {
      return PacketError.reqeustPacketConnectTokenExpired;
    }

    this._connectTokenSequence = bb.readUint64();
    if (this._connectTokenSequence === undefined) {
      return PacketError.EOF;
    }

    if (bb.position !== 1 + Defines.VERSION_INFO_BYTES + 8 + 8 + 8) {
      return PacketError.reqeustPacketInvalidLength;
    }

    const tokenBuffer = bb.readBytes(Defines.CONNECT_TOKEN_PRIVATE_BYTES);
    if (tokenBuffer === undefined) {
      return PacketError.EOF;
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
      return PacketError.reqeustPacketDecryptPrivateTokenData;
    }

    if (!this._token.read()) {
      return PacketError.reqeustPacketDecryptPrivateTokenData;
    }

    return PacketError.none;
  }

  private _versionInfo: Uint8Array;
  private _protocolID: Long;
  private _connectTokenExpireTimestamp: Long;
  private _connectTokenSequence: Long;
  private _token: ConnectTokenPrivate;
  private _connectTokenData: Uint8Array;
}
