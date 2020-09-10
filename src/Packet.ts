namespace Netcode {
  export enum PacketType {
    connectionRequest,
    connectionDenied,
    connectionChallenge,
    connectionResponse,
    connectionKeepAlive,
    connectionPayload,
    connectionDisconnect,

    numPackets,
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

  export class PacketFactory {
    public static peekPacketType(packetBuffer: Uint8Array): PacketType {
      const prefix = packetBuffer[0];
      return prefix & 0xf;
    }

    public static create(packetBuffer: Uint8Array): IPacket {
      const packetType = this.peekPacketType(packetBuffer);
      switch (packetType) {
        case PacketType.connectionRequest:
          return new RequestPacket();
        case PacketType.connectionChallenge:
          return new ChallengePacket();
        case PacketType.connectionResponse:
          return new ResponsePacket();
        case PacketType.connectionKeepAlive:
          return new KeepAlivePacket();
        case PacketType.connectionDenied:
          return new DeniedPacket();
        case PacketType.connectionPayload:
          return new PayloadPacket();
        case PacketType.connectionDisconnect:
          return new DisconnectPacket();
        default:
          console.error('unknown connection type', packetType);
          return null;
      }
    }
  }

  export class RequestPacket implements IPacket {
    public getType(): PacketType {
      return PacketType.connectionRequest;
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
      bb.writeUint8(PacketType.connectionRequest);
      bb.writeBytes(this._versionInfo);
      bb.writeUint64(this._protocolID);
      bb.writeUint64(this._connectTokenExpireTimestamp);
      bb.writeUint64(this._connectTokenSequence);
      bb.writeBytes(this._connectTokenData);
      const correctPosition = 1 + 13 + 8 + 8 + 8 + CONNECT_TOKEN_PRIVATE_BYTES;
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
        packetType !== PacketType.connectionRequest
      ) {
        return Errors.invalidPacket;
      }
      if (readParams.allowedPackets[0] === 0) {
        return Errors.packetTypeNotAllowed;
      }
      if (
        packetLen !==
        1 + VERSION_INFO_BYTES + 8 + 8 + 8 + CONNECT_TOKEN_PRIVATE_BYTES
      ) {
        return Errors.badPacketLength;
      }
      if (!readParams.privateKey) {
        return Errors.noPrivateKey;
      }

      this._versionInfo = bb.readBytes(VERSION_INFO_BYTES);
      if (
        this._versionInfo === undefined ||
        !Utils.arrayEqual(this._versionInfo, VERSION_INFO_BYTES_ARRAY)
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

      if (bb.position !== 1 + VERSION_INFO_BYTES + 8 + 8 + 8) {
        return Errors.packetInvalidLength;
      }

      const tokenBuffer = bb.readBytes(CONNECT_TOKEN_PRIVATE_BYTES);
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
      return PacketType.connectionDenied;
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
      return PacketType.connectionChallenge;
    }

    public sequence(): Long {
      return this._sequence;
    }

    public get challengeTokenSequence(): Long {
      return this._challengeTokenSequence;
    }

    public get tokenData(): Uint8Array {
      return this._tokenData;
    }

    public setProperties(tokenSequence: Long, tokenData: Uint8Array) {
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
      bb.writeUint64(this._challengeTokenSequence);
      bb.writeBytes(this._tokenData, CHALLENGE_TOKEN_BYTES);
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
      if (decrypted.bytes.length !== 8 + CHALLENGE_TOKEN_BYTES) {
        return Errors.invalidChallengePacketDataSize;
      }

      this._challengeTokenSequence = decrypted.readUint64();
      if (this._challengeTokenSequence === undefined) {
        return Errors.invalidResponseTokenSequence;
      }

      this._tokenData = decrypted.readBytes(CHALLENGE_TOKEN_BYTES);
      if (this._tokenData === undefined) {
        return Errors.invalidChallengeTokenData;
      }
      return Errors.none;
    }

    private _sequence: Long;
    private _challengeTokenSequence: Long;
    private _tokenData: Uint8Array;
  }

  export class ResponsePacket implements IPacket {
    public getType(): PacketType {
      return PacketType.connectionResponse;
    }

    public sequence(): Long {
      return this._sequence;
    }

    public get challengeTokenSequence(): Long {
      return this._challengeTokenSequence;
    }

    public get tokenData(): Uint8Array {
      return this._tokenData;
    }

    public setProperties(tokenSequence: Long, tokenData: Uint8Array) {
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
      bb.writeUint64(this._challengeTokenSequence);
      bb.writeBytes(this._tokenData, CHALLENGE_TOKEN_BYTES);
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
      if (decrypted.bytes.length !== 8 + CHALLENGE_TOKEN_BYTES) {
        return Errors.invalidResponsePacketDataSize;
      }

      this._challengeTokenSequence = decrypted.readUint64();
      if (this._challengeTokenSequence === undefined) {
        return Errors.invalidResponseTokenSequence;
      }

      this._tokenData = decrypted.readBytes(CHALLENGE_TOKEN_BYTES);
      if (this._tokenData === undefined) {
        return Errors.invalidResponseTokenData;
      }
      return Errors.none;
    }

    private _sequence: Long;
    private _challengeTokenSequence: Long;
    private _tokenData: Uint8Array;
  }

  export class KeepAlivePacket implements IPacket {
    public getType(): PacketType {
      return PacketType.connectionKeepAlive;
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
      return PacketType.connectionPayload;
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
      if (decryptedSize > MAX_PACKET_BYTES) {
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
      return PacketType.connectionDisconnect;
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

      const encrypted = Utils.aead_encrypt(
        writePacketKey,
        nonce,
        encryptedBuffer,
        additionalData
      );
      buffer.bytes.set(encrypted[0], encryptedStart);
      buffer.bytes.set(encrypted[1], encryptedFinish);
      buffer.skipPosition(MAC_BYTES);
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
          VERSION_INFO_BYTES + 8 + 1
        );
      }
      const additionalData = this._addtionalDatabuffer;
      additionalData.clearPosition();
      additionalData.writeBytes(VERSION_INFO_BYTES_ARRAY);
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
      if (encryptedSize < MAC_BYTES) {
        return { err: Errors.badPacketLength };
      }

      const encryptedBuff = packetBuffer.readBytes(encryptedSize);
      if (encryptedBuff === undefined) {
        return { err: Errors.badPacketLength };
      }

      const decrypted = Utils.aead_decrypt(
        readPacketKey,
        nonce,
        encryptedBuff.subarray(0, encryptedBuff.length - MAC_BYTES),
        additionalData,
        encryptedBuff.subarray(encryptedBuff.length - MAC_BYTES)
      );
      if (!decrypted) {
        return { err: Errors.errDecryptData };
      }
      return {
        sequence: packetSequence,
        decrypted: new ByteBuffer(decrypted as Uint8Array),
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
      if (packetLen < 1 + sequenceBytes + MAC_BYTES) {
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

      if (packetLen < 1 + 1 + MAC_BYTES) {
        return Errors.badPacketLength;
      }

      const packetType: PacketType = prefixByte & 0xf;
      if (packetType >= PacketType.numPackets) {
        return Errors.invalidPacket;
      }

      if (!allowedPackets[packetType]) {
        return Errors.packetTypeNotAllowed;
      }

      // replay protection (optional)
      if (replayProtection && packetType >= PacketType.connectionKeepAlive) {
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
}
