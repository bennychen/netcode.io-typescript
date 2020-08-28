import * as Defines from './Defines';
import { ByteBuffer, Long } from './ByteBuffer';
import { ConnectTokenPrivate } from './Token';
import { Errors } from './Errors';
import { Utils } from './Utils';
import { ReplayProtection } from './ReplayProtection';
import * as chacha from './chacha20poly1305';

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
  sequence(): Long;
  write(
    buf: Uint8Array,
    protocolID: Long,
    sequence: Long,
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

  public sequence(): Long {
    return new Long(0, 0);
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
    sequence: Long,
    writePacketKey: Uint8Array
  ): number {
    const bb = new ByteBuffer(buf);
    bb.writeUint8(PacketType.ConnectionRequest);
    bb.writeBytes(this._versionInfo);
    bb.writeUint64(this._protocolID);
    bb.writeUint64(this._connectTokenExpireTimestamp);
    bb.writeUint64(this._connectTokenSequence);
    bb.writeBytes(this._connectTokenData);
    const correctPosition =
      1 + 13 + 8 + 8 + 8 + Defines.CONNECT_TOKEN_PRIVATE_BYTES;
    if (bb.position !== correctPosition) {
      console.error('wrong token bytes length', bb.position, correctPosition);
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
    const err = this._token.read();
    if (err !== Errors.none) {
      return err;
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

export class DeniedPacket implements IPacket {
  public getType(): PacketType {
    return PacketType.ConnectionDenied;
  }

  public sequence(): Long {
    return this._sequence;
  }

  public write(
    buf: Uint8Array,
    protocolID: Long,
    sequence: Long,
    writePacketKey: Uint8Array
  ): number {
    const bb = new ByteBuffer(buf);
    const prefixByte = PacketHelper.writePacketPrefix(this, bb, sequence);
    if (prefixByte < 0) {
      return -1;
    }

    return PacketHelper.encryptPacket(
      bb,
      bb.position,
      bb.position,
      prefixByte,
      protocolID,
      sequence,
      writePacketKey
    );
  }

  public read(
    packetData: Uint8Array,
    packetLen: number,
    readParams: IReadParams
  ): Errors {
    const bb = new ByteBuffer(packetData);
    const { sequence, decrypted, err } = PacketHelper.decryptPacket(
      bb,
      packetLen,
      readParams.protocolId,
      readParams.readPacketKey,
      readParams.allowedPackets,
      readParams.replayProtection
    );
    if (err !== Errors.none) {
      return err;
    }
    this._sequence = sequence;
    if (decrypted.bytes.length !== 0) {
      return Errors.invalidDenyPacketDataSize;
    }
    return Errors.none;
  }

  private _sequence: Long;
}

export class ChallengePacket implements IPacket {
  public getType(): PacketType {
    return PacketType.ConnectionChallenge;
  }

  public sequence(): Long {
    return this._sequence;
  }

  public get challengeTokenSequence(): number {
    return this._challengeTokenSequence;
  }

  public get tokenData(): Uint8Array {
    return this._tokenData;
  }

  public setProperties(tokenSequence: number, tokenData: Uint8Array) {
    this._challengeTokenSequence = tokenSequence;
    this._tokenData = tokenData;
  }

  public write(
    buf: Uint8Array,
    protocolID: Long,
    sequence: Long,
    writePacketKey: Uint8Array
  ): number {
    const bb = new ByteBuffer(buf);
    const prefixByte = PacketHelper.writePacketPrefix(this, bb, sequence);
    if (prefixByte < 0) {
      return -1;
    }

    const start = bb.position;
    bb.writeUint64(Long.fromNumber(this._challengeTokenSequence));
    bb.writeBytes(this._tokenData, Defines.CHALLENGE_TOKEN_BYTES);
    const end = bb.position;
    return PacketHelper.encryptPacket(
      bb,
      start,
      end,
      prefixByte,
      protocolID,
      sequence,
      writePacketKey
    );
  }

  public read(
    packetData: Uint8Array,
    packetLen: number,
    readParams: IReadParams
  ): Errors {
    const bb = new ByteBuffer(packetData);
    const { sequence, decrypted, err } = PacketHelper.decryptPacket(
      bb,
      packetLen,
      readParams.protocolId,
      readParams.readPacketKey,
      readParams.allowedPackets,
      readParams.replayProtection
    );
    if (err !== Errors.none) {
      return err;
    }
    this._sequence = sequence;
    if (decrypted.bytes.length !== 8 + Defines.CHALLENGE_TOKEN_BYTES) {
      return Errors.invalidChallengePacketDataSize;
    }

    const challengeTokenSequence = decrypted.readUint64();
    if (challengeTokenSequence === undefined) {
      return Errors.invalidChallengeTokenSequence;
    }
    this._challengeTokenSequence = challengeTokenSequence.toNumber();

    this._tokenData = decrypted.readBytes(Defines.CHALLENGE_TOKEN_BYTES);
    if (this._tokenData === undefined) {
      return Errors.invalidChallengeTokenData;
    }
    return Errors.none;
  }

  private _sequence: Long;
  private _challengeTokenSequence: number;
  private _tokenData: Uint8Array;
}

export class ResponsePacket implements IPacket {
  public getType(): PacketType {
    return PacketType.ConnectionResponse;
  }

  public sequence(): Long {
    return this._sequence;
  }

  public get challengeTokenSequence(): number {
    return this._challengeTokenSequence;
  }

  public get tokenData(): Uint8Array {
    return this._tokenData;
  }

  public setProperties(tokenSequence: number, tokenData: Uint8Array) {
    this._challengeTokenSequence = tokenSequence;
    this._tokenData = tokenData;
  }

  public write(
    buf: Uint8Array,
    protocolID: Long,
    sequence: Long,
    writePacketKey: Uint8Array
  ): number {
    const bb = new ByteBuffer(buf);
    const prefixByte = PacketHelper.writePacketPrefix(this, bb, sequence);
    if (prefixByte < 0) {
      return -1;
    }

    const start = bb.position;
    bb.writeUint64(Long.fromNumber(this._challengeTokenSequence));
    bb.writeBytes(this._tokenData, Defines.CHALLENGE_TOKEN_BYTES);
    const end = bb.position;
    return PacketHelper.encryptPacket(
      bb,
      start,
      end,
      prefixByte,
      protocolID,
      sequence,
      writePacketKey
    );
  }

  public read(
    packetData: Uint8Array,
    packetLen: number,
    readParams: IReadParams
  ): Errors {
    const bb = new ByteBuffer(packetData);
    const { sequence, decrypted, err } = PacketHelper.decryptPacket(
      bb,
      packetLen,
      readParams.protocolId,
      readParams.readPacketKey,
      readParams.allowedPackets,
      readParams.replayProtection
    );
    if (err !== Errors.none) {
      return err;
    }
    this._sequence = sequence;
    if (decrypted.bytes.length !== 8 + Defines.CHALLENGE_TOKEN_BYTES) {
      return Errors.invalidResponsePacketDataSize;
    }

    const challengeTokenSequence = decrypted.readUint64();
    if (challengeTokenSequence === undefined) {
      return Errors.invalidResponseTokenSequence;
    }
    this._challengeTokenSequence = challengeTokenSequence.toNumber();

    this._tokenData = decrypted.readBytes(Defines.CHALLENGE_TOKEN_BYTES);
    if (this._tokenData === undefined) {
      return Errors.invalidResponseTokenData;
    }
    return Errors.none;
  }

  private _sequence: Long;
  private _challengeTokenSequence: number;
  private _tokenData: Uint8Array;
}

export class KeepAlivePacket implements IPacket {
  public getType(): PacketType {
    return PacketType.ConnectionKeepAlive;
  }

  public sequence(): Long {
    return this._sequence;
  }

  public get clientIndex(): number {
    return this._clientIndex;
  }

  public get maxClients(): number {
    return this._maxClients;
  }

  public setProperties(clientIndex: number, maxClients: number) {
    this._clientIndex = clientIndex;
    this._maxClients = maxClients;
  }

  public write(
    buf: Uint8Array,
    protocolID: Long,
    sequence: Long,
    writePacketKey: Uint8Array
  ): number {
    const bb = new ByteBuffer(buf);
    const prefixByte = PacketHelper.writePacketPrefix(this, bb, sequence);
    if (prefixByte < 0) {
      return -1;
    }

    const start = bb.position;
    bb.writeUint32(this._clientIndex);
    bb.writeUint32(this._maxClients);
    const end = bb.position;
    return PacketHelper.encryptPacket(
      bb,
      start,
      end,
      prefixByte,
      protocolID,
      sequence,
      writePacketKey
    );
  }

  public read(
    packetData: Uint8Array,
    packetLen: number,
    readParams: IReadParams
  ): Errors {
    const bb = new ByteBuffer(packetData);
    const { sequence, decrypted, err } = PacketHelper.decryptPacket(
      bb,
      packetLen,
      readParams.protocolId,
      readParams.readPacketKey,
      readParams.allowedPackets,
      readParams.replayProtection
    );
    if (err !== Errors.none) {
      return err;
    }
    this._sequence = sequence;
    if (decrypted.bytes.length !== 8) {
      return Errors.invalidDisconnectPacketDataSize;
    }

    this._clientIndex = decrypted.readUint32();
    if (this._clientIndex === undefined) {
      return Errors.invalidKeepAliveClientIndex;
    }

    this._maxClients = decrypted.readUint32();
    if (this._maxClients === undefined) {
      return Errors.invalidKeepAliveMaxClients;
    }
    return Errors.none;
  }

  private _sequence: Long;
  private _clientIndex: number;
  private _maxClients: number;
}

export class PayloadPacket implements IPacket {
  public getType(): PacketType {
    return PacketType.ConnectionPayload;
  }

  public sequence(): Long {
    return this._sequence;
  }

  public get payloadData(): Uint8Array {
    return this._payloadData;
  }

  public constructor(payloadData?: Uint8Array) {
    if (payloadData) {
      this._payloadData = payloadData;
    }
  }

  public write(
    buf: Uint8Array,
    protocolID: Long,
    sequence: Long,
    writePacketKey: Uint8Array
  ): number {
    const bb = new ByteBuffer(buf);
    const prefixByte = PacketHelper.writePacketPrefix(this, bb, sequence);
    if (prefixByte < 0) {
      return -1;
    }

    const start = bb.position;
    bb.writeBytes(this._payloadData);
    const end = bb.position;
    return PacketHelper.encryptPacket(
      bb,
      start,
      end,
      prefixByte,
      protocolID,
      sequence,
      writePacketKey
    );
  }

  public read(
    packetData: Uint8Array,
    packetLen: number,
    readParams: IReadParams
  ): Errors {
    const bb = new ByteBuffer(packetData);
    const { sequence, decrypted, err } = PacketHelper.decryptPacket(
      bb,
      packetLen,
      readParams.protocolId,
      readParams.readPacketKey,
      readParams.allowedPackets,
      readParams.replayProtection
    );
    if (err !== Errors.none) {
      return err;
    }
    this._sequence = sequence;

    const decryptedSize = decrypted.bytes.length;
    if (decryptedSize < 1) {
      return Errors.payloadPacketTooSmall;
    }
    if (decryptedSize > Defines.MAX_PACKET_BYTES) {
      return Errors.payloadPacketTooLarge;
    }

    this._payloadData = decrypted.bytes;
    return Errors.none;
  }

  private _sequence: Long;
  private _payloadData: Uint8Array;
}

export class DisconnectPacket implements IPacket {
  public getType(): PacketType {
    return PacketType.ConnectionDisconnect;
  }

  public sequence(): Long {
    return this._sequence;
  }

  public write(
    buf: Uint8Array,
    protocolID: Long,
    sequence: Long,
    writePacketKey: Uint8Array
  ): number {
    const bb = new ByteBuffer(buf);
    const prefixByte = PacketHelper.writePacketPrefix(this, bb, sequence);
    if (prefixByte < 0) {
      return -1;
    }
    return PacketHelper.encryptPacket(
      bb,
      bb.position,
      bb.position,
      prefixByte,
      protocolID,
      sequence,
      writePacketKey
    );
  }

  public read(
    packetData: Uint8Array,
    packetLen: number,
    readParams: IReadParams
  ): Errors {
    const bb = new ByteBuffer(packetData);
    const { sequence, decrypted, err } = PacketHelper.decryptPacket(
      bb,
      packetLen,
      readParams.protocolId,
      readParams.readPacketKey,
      readParams.allowedPackets,
      readParams.replayProtection
    );
    if (err !== Errors.none) {
      return err;
    }
    this._sequence = sequence;
    if (decrypted.bytes.length !== 0) {
      return Errors.invalidDisconnectPacketDataSize;
    }
    return Errors.none;
  }

  private _sequence: Long;
}

export class PacketHelper {
  // Encrypts the packet data of the supplied buffer between encryptedStart and encrypedFinish.
  public static encryptPacket(
    buffer: ByteBuffer,
    encryptedStart: number,
    encryptedFinish: number,
    prefixByte: number,
    protocolId: Long,
    sequence: Long,
    writePacketKey: Uint8Array
  ) {
    // slice up the buffer for the bits we will encrypt
    const encryptedBuffer = buffer.bytes.subarray(
      encryptedStart,
      encryptedFinish
    );
    const { additionalData, nonce } = this.packetCryptData(
      prefixByte,
      protocolId,
      sequence
    );

    const encrypted = chacha.aead_encrypt(
      writePacketKey,
      nonce,
      encryptedBuffer,
      additionalData
    );
    buffer.bytes.set(encrypted[0], encryptedStart);
    buffer.bytes.set(encrypted[1], encryptedFinish);
    buffer.skipPosition(Defines.MAC_BYTES);
    return buffer.position;
  }

  // used for encrypting the per-packet packet written with the prefix byte,
  // protocol id and version as the associated data. this must match to decrypt.
  public static packetCryptData(
    prefixByte: number,
    protocolId: Long,
    sequence: Long
  ): { additionalData: Uint8Array; nonce: Uint8Array } {
    if (!this._addtionalDatabuffer) {
      this._addtionalDatabuffer = ByteBuffer.allocate(
        Defines.VERSION_INFO_BYTES + 8 + 1
      );
    }
    const additionalData = this._addtionalDatabuffer;
    additionalData.clearPosition();
    additionalData.writeBytes(Defines.VERSION_INFO_BYTES_ARRAY);
    additionalData.writeUint64(protocolId);
    additionalData.writeUint8(prefixByte);

    if (!this._nonceBuffer) {
      this._nonceBuffer = ByteBuffer.allocate(8 + 4);
    }
    const nonce = this._nonceBuffer;
    nonce.clearPosition();
    nonce.writeUint32(0);
    nonce.writeUint64(sequence);
    return { additionalData: additionalData.bytes, nonce: nonce.bytes };
  }

  // Decrypts the packet after reading in the prefix byte and sequence id. Used for all PacketTypes except RequestPacket. Returns a buffer containing the decrypted data
  public static decryptPacket(
    packetBuffer: ByteBuffer,
    packetLen: number,
    protocolId: Long,
    readPacketKey: Uint8Array,
    allowedPackets: Uint8Array,
    replayProtection: ReplayProtection
  ): { sequence?: Long; decrypted?: ByteBuffer; err: Errors } {
    const prefixByte = packetBuffer.readUint8();
    if (prefixByte === undefined) {
      return { err: Errors.invalidPacket };
    }

    const packetSequence = this.readSequence(
      packetBuffer,
      packetLen,
      prefixByte
    );
    if (!packetSequence) {
      return { err: Errors.badSequence };
    }

    const err = this.validateSequence(
      packetLen,
      prefixByte,
      packetSequence,
      readPacketKey,
      allowedPackets,
      replayProtection
    );
    if (err !== Errors.none) {
      return { err };
    }

    // decrypt the per-packet type data
    const { additionalData, nonce } = this.packetCryptData(
      prefixByte,
      protocolId,
      packetSequence
    );

    const encryptedSize = packetLen - packetBuffer.position;
    if (encryptedSize < Defines.MAC_BYTES) {
      return { err: Errors.badPacketLength };
    }

    const encryptedBuff = packetBuffer.readBytes(encryptedSize);
    if (encryptedBuff === undefined) {
      return { err: Errors.badPacketLength };
    }

    const decrypted = chacha.aead_decrypt(
      readPacketKey,
      nonce,
      encryptedBuff.subarray(0, encryptedBuff.length - Defines.MAC_BYTES),
      additionalData,
      encryptedBuff.subarray(encryptedBuff.length - Defines.MAC_BYTES)
    );
    if (!decrypted) {
      return { err: Errors.errDecryptData };
    }
    return {
      sequence: packetSequence,
      decrypted: new ByteBuffer(decrypted),
      err: Errors.none,
    };
  }

  // Reads and verifies the sequence id
  public static readSequence(
    packetBuffer: ByteBuffer,
    packetLen: number,
    prefixByte: number
  ): Long | undefined {
    const sequenceBytes = prefixByte >> 4;
    if (sequenceBytes < 1 || sequenceBytes > 8) {
      return;
    }
    if (packetLen < 1 + sequenceBytes + Defines.MAC_BYTES) {
      return;
    }

    let sequence: Long = new Long(0, 0);
    // read variable length sequence number [1,8]
    for (let i = 0; i < sequenceBytes; i += 1) {
      const val = packetBuffer.readUint8();
      if (val === undefined) {
        return;
      }
      if (i <= 3) {
        sequence.low |= val << (8 * i);
      } else {
        sequence.high |= val << (8 * (i - 4));
      }
    }
    return sequence;
  }

  // Validates the data prior to the encrypted segment before we bother attempting to decrypt.
  public static validateSequence(
    packetLen: number,
    prefixByte: number,
    sequence: Long,
    readPacketKey: Uint8Array,
    allowedPackets: Uint8Array,
    replayProtection: ReplayProtection
  ): Errors {
    if (!readPacketKey) {
      return Errors.emptyPacketKey;
    }

    if (packetLen < 1 + 1 + Defines.MAC_BYTES) {
      return Errors.badPacketLength;
    }

    const packetType: PacketType = prefixByte & 0xf;
    if (packetType >= PacketType.ConnectionNumPackets) {
      return Errors.invalidPacket;
    }

    if (!allowedPackets[packetType]) {
      return Errors.packetTypeNotAllowed;
    }

    // replay protection (optional)
    if (replayProtection && packetType >= PacketType.ConnectionKeepAlive) {
      if (replayProtection.checkAlreadyReceived(sequence.toNumber())) {
        return Errors.packetAlreadyReceived;
      }
    }
    return Errors.none;
  }

  // write the prefix byte
  // (this is a combination of the packet type and number of sequence bytes)
  public static writePacketPrefix(
    p: IPacket,
    buffer: ByteBuffer,
    sequence: Long
  ): number {
    const sequenceBytes = this.sequenceNumberBytesRequired(sequence);
    if (sequenceBytes < 1 || sequenceBytes > 8) {
      return -1;
    }

    const prefixByte = p.getType() | (0xff & (sequenceBytes << 4));
    buffer.writeUint8(prefixByte);

    this._sequenceTemp.low = sequence.low;
    this._sequenceTemp.high = sequence.high;
    for (let i = 0; i < sequenceBytes; i += 1) {
      buffer.writeUint8(this._sequenceTemp.low & 0xff);
      this._sequenceTemp.rightShiftSelf(8);
    }
    return prefixByte;
  }

  // Depending on size of sequence number, we need to reserve N bytes
  public static sequenceNumberBytesRequired(sequence: Long): number {
    this._mask.high = 0xff000000;
    this._mask.low = 0;
    let i = 0;
    for (; i < 7; i += 1) {
      if (
        (sequence.high & this._mask.high) !== 0 ||
        (sequence.low & this._mask.low) !== 0
      ) {
        break;
      }
      this._mask.rightShiftSelf(8);
    }
    return 8 - i;
  }

  private static _sequenceTemp: Long = new Long(0, 0);
  private static _mask: Long = new Long(0, 0);
  private static _addtionalDatabuffer: ByteBuffer;
  private static _nonceBuffer: ByteBuffer;
}
