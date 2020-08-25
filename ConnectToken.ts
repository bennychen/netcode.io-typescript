import * as Defines from './Defines';
import { Utils } from './Utils';
import { Errors } from './Errors';
import { Long, ByteBuffer } from './ByteBuffer';
import * as chacha from './chacha20poly1305';

// This struct contains data that is shared in both public and private parts of the
// connect token.
export class SharedTokenData {
  public timeoutSeconds: number;
  public serverAddrs: Defines.IUDPAddr[];
  public clientKey: Uint8Array;
  public serverKey: Uint8Array;

  public generate() {
    this.clientKey = Utils.generateKey();
    this.serverKey = Utils.generateKey();
  }

  public read(buffer: ByteBuffer): Errors {
    this.timeoutSeconds = buffer.readInt32();
    if (this.timeoutSeconds === undefined) {
      return Errors.EOF;
    }
    const servers = buffer.readUint32();
    if (
      servers === undefined ||
      servers <= 0 ||
      servers > Defines.MAX_SERVERS_PER_CONNECT
    ) {
      return Errors.EOF;
    }
    if (servers <= 0) {
      return Errors.emptyServer;
    }
    if (servers > Defines.MAX_SERVERS_PER_CONNECT) {
      return Errors.tooManyServers;
    }

    this.serverAddrs = [];
    for (let i = 0; i < servers; i++) {
      const serverType = buffer.readUint8();
      if (serverType === undefined) {
        return Errors.EOF;
      }

      let ipBytes: Uint8Array;
      let isIPV6: boolean = false;
      if (serverType === Defines.AddressType.ADDRESS_IPV4) {
        ipBytes = buffer.readBytes(4);
        if (ipBytes === undefined) {
          return Errors.EOF;
        }
      } else if (serverType === Defines.AddressType.ADDRESS_IPV6) {
        ipBytes = new Uint8Array(16);
        for (let j = 0; j < 16; j += 2) {
          const n = buffer.readUint16();
          if (n === undefined) {
            return Errors.EOF;
          }
          // decode little endian -> big endian
          ipBytes[j] = 0xff & (n >> 8);
          ipBytes[j + 1] = 0xff & n;
        }
        isIPV6 = true;
      } else {
        return Errors.unknownIPAddressType;
      }
      const port = buffer.readUint16();
      if (port === undefined) {
        return Errors.invalidPort;
      }
      this.serverAddrs[i] = {
        ip: ipBytes,
        port: port,
        isIPV6,
      };
    }

    this.clientKey = buffer.readBytes(Defines.KEY_BYTES);
    if (!this.clientKey) {
      return Errors.EOF;
    }

    this.serverKey = buffer.readBytes(Defines.KEY_BYTES);
    if (!this.serverKey) {
      return Errors.EOF;
    }

    return Errors.none;
  }

  public write(buffer: ByteBuffer) {
    buffer.writeInt32(this.timeoutSeconds);
    buffer.writeUint32(this.serverAddrs.length);

    for (const addr of this.serverAddrs) {
      if (addr.isIPV6) {
        buffer.writeUint8(Defines.AddressType.ADDRESS_IPV6);
        for (let i = 0; i < addr.ip.length; i += 2) {
          let n = (0xffff & addr.ip[i]) << 8;
          n |= 0xffff & addr.ip[i + 1];
          // encode big endian -> little endian
          buffer.writeUint16(n);
        }
      } else {
        buffer.writeUint8(Defines.AddressType.ADDRESS_IPV4);
        buffer.writeBytes(addr.ip);
      }
      buffer.writeUint16(addr.port);
    }

    buffer.writeBytes(this.clientKey, Defines.KEY_BYTES);
    buffer.writeBytes(this.serverKey, Defines.KEY_BYTES);
  }
}

// The private parts of a connect token
export class ConnectTokenPrivate {
  public static createEncrypted(buffer: Uint8Array): ConnectTokenPrivate {
    const p = new ConnectTokenPrivate();
    p.tokenData = new ByteBuffer(buffer);
    return p;
  }

  public static create(
    clientID: Long,
    timeoutSeconds: number,
    serverAddrs: Defines.IUDPAddr[],
    userData: Uint8Array
  ): ConnectTokenPrivate {
    const p = new ConnectTokenPrivate();
    p.tokenData = new ByteBuffer(
      new Uint8Array(Defines.CONNECT_TOKEN_PRIVATE_BYTES)
    );
    p.clientId = clientID;
    p.userData = userData;
    p.sharedTokenData.timeoutSeconds = timeoutSeconds;
    p.sharedTokenData.serverAddrs = serverAddrs;
    return p;
  }

  public static buildTokenCryptData(
    protocolID: Long,
    expireTimestamp: Long,
    sequence: Long
  ): { additionalData: ByteBuffer; nonce: ByteBuffer } {
    this._sharedAdditionalBytes.clearPosition();
    this._sharedAdditionalBytes.writeBytes(Defines.VERSION_INFO_BYTES_ARRAY);
    this._sharedAdditionalBytes.writeUint64(protocolID);
    this._sharedAdditionalBytes.writeUint64(expireTimestamp);

    this._sharedNonce.clearPosition();
    this._sharedNonce.writeUint32(0);
    this._sharedNonce.writeUint64(sequence);
    return {
      additionalData: this._sharedAdditionalBytes,
      nonce: this._sharedNonce,
    };
  }
  private static _sharedAdditionalBytes: ByteBuffer = new ByteBuffer(
    new Uint8Array(Defines.VERSION_INFO_BYTES + 8 + 8)
  );
  private static _sharedNonce: ByteBuffer = new ByteBuffer(
    new Uint8Array(8 + 4)
  );

  public sharedTokenData: SharedTokenData;
  public clientId: Long;
  public userData: Uint8Array;
  public mac: Uint8Array;
  public tokenData: ByteBuffer;

  public constructor() {
    this.sharedTokenData = new SharedTokenData();
    this.mac = new Uint8Array(Defines.MAC_BYTES);
  }

  public get buffer(): Uint8Array {
    return this.tokenData.bytes;
  }

  public generate() {
    this.sharedTokenData.generate();
  }

  public read(): Errors {
    this.clientId = this.tokenData.readUint64();
    if (!this.clientId) {
      return Errors.EOF;
    }
    const err = this.sharedTokenData.read(this.tokenData);
    if (err !== Errors.none) {
      return err;
    }
    this.userData = this.tokenData.readBytes(Defines.USER_DATA_BYTES);
    if (!this.userData) {
      return Errors.badUserData;
    }
    return Errors.none;
  }

  public write(): Uint8Array {
    this.tokenData.writeUint64(this.clientId);
    this.sharedTokenData.write(this.tokenData);
    this.tokenData.writeBytes(this.userData, Defines.USER_DATA_BYTES);
    return this.tokenData.bytes;
  }

  public encrypt(
    protocolID: Long,
    expireTimestamp: Long,
    sequence: Long,
    privateKey: Uint8Array
  ): boolean {
    const { additionalData, nonce } = ConnectTokenPrivate.buildTokenCryptData(
      protocolID,
      expireTimestamp,
      sequence
    );
    const encBuf = this.tokenData.bytes.subarray(
      0,
      Defines.CONNECT_TOKEN_PRIVATE_BYTES - Defines.MAC_BYTES
    );
    const encrypted = chacha.aead_encrypt(
      privateKey,
      nonce.bytes,
      encBuf,
      additionalData.bytes
    );
    if (
      encrypted[0].length + encrypted[1].length !==
      Defines.CONNECT_TOKEN_PRIVATE_BYTES
    ) {
      console.error(
        'encrypted length not correct',
        encrypted[0].length,
        Defines.CONNECT_TOKEN_PRIVATE_BYTES
      );
      return false;
    }
    this.tokenData.bytes.set(encrypted[0], 0);
    this.tokenData.bytes.set(encrypted[1], encrypted[0].length);
    this.mac = encrypted[1];
    return true;
  }

  public decrypt(
    protocolID: Long,
    expireTimestamp: Long,
    sequence: Long,
    privateKey: Uint8Array
  ): Uint8Array {
    if (this.tokenData.bytes.length !== Defines.CONNECT_TOKEN_PRIVATE_BYTES) {
      console.error('wrong token data length');
      return;
    }
    this.mac.set(
      this.tokenData.bytes.subarray(
        Defines.CONNECT_TOKEN_PRIVATE_BYTES - Defines.MAC_BYTES
      ),
      0
    );
    const { additionalData, nonce } = ConnectTokenPrivate.buildTokenCryptData(
      protocolID,
      expireTimestamp,
      sequence
    );
    const decrypted = chacha.aead_decrypt(
      privateKey,
      nonce.bytes,
      this.tokenData.bytes.subarray(
        0,
        Defines.CONNECT_TOKEN_PRIVATE_BYTES - Defines.MAC_BYTES
      ),
      additionalData.bytes,
      this.mac
    );
    if (decrypted) {
      this.tokenData = new ByteBuffer(decrypted);
    } else {
      return;
    }
    this.tokenData.clearPosition();
    return this.tokenData.bytes;
  }
}

export class ConnectToken {
  public sharedTokenData: SharedTokenData;
  public versionInfo: Uint8Array;
  public protocolID: Long;
  public createTimestamp: Long;
  public expireTimestamp: Long;
  public sequence: Long;
  public privateData: ConnectTokenPrivate;

  public constructor() {
    this.sharedTokenData = new SharedTokenData();
    this.privateData = new ConnectTokenPrivate();
  }

  public generate(
    clientID: Long,
    serverAddrs: Defines.IUDPAddr[],
    protocoalID: Long,
    expireSeconds: number,
    timeoutSeconds: number,
    sequence: number,
    userData: Uint8Array,
    privateKey: Uint8Array
  ): boolean {
    const now = new Date().getTime();
    this.createTimestamp = Long.fromNumber(now);
    if (expireSeconds >= 0) {
      this.expireTimestamp = Long.fromNumber(now + expireSeconds);
    } else {
      this.expireTimestamp = Long.fromNumber(0xffffffffffffffff);
    }
    this.sharedTokenData.timeoutSeconds = timeoutSeconds;
    this.versionInfo = new Uint8Array(Defines.VERSION_INFO_BYTES_ARRAY);
    this.protocolID = protocoalID;
    this.sequence = Long.fromNumber(sequence);

    this.privateData = ConnectTokenPrivate.create(
      clientID,
      timeoutSeconds,
      serverAddrs,
      userData
    );
    this.privateData.generate();
    this.sharedTokenData.clientKey = this.privateData.sharedTokenData.clientKey;
    this.sharedTokenData.serverKey = this.privateData.sharedTokenData.serverKey;
    this.sharedTokenData.serverAddrs = serverAddrs;
    if (this.privateData.write() === undefined) {
      return false;
    }
    if (
      !this.privateData.encrypt(
        this.protocolID,
        this.expireTimestamp,
        this.sequence,
        privateKey
      )
    ) {
      return false;
    }
    return true;
  }

  public write(): Uint8Array {
    const bb = new ByteBuffer(new Uint8Array(Defines.CONNECT_TOKEN_BYTES));
    bb.writeBytes(this.versionInfo);
    bb.writeUint64(this.protocolID);
    bb.writeUint64(this.createTimestamp);
    bb.writeUint64(this.expireTimestamp);
    bb.writeUint64(this.sequence);

    bb.writeBytes(this.privateData.buffer);
    this.sharedTokenData.write(bb);
    return bb.bytes;
  }

  public read(buffer: Uint8Array): Errors {
    const bb = new ByteBuffer(buffer);
    this.versionInfo = bb.readBytes(Defines.VERSION_INFO_BYTES);
    if (
      this.versionInfo === undefined ||
      !Utils.arrayEqual(this.versionInfo, Defines.VERSION_INFO_BYTES_ARRAY)
    ) {
      return Errors.badVersionInfo;
    }
    this.protocolID = bb.readUint64();
    if (this.protocolID === undefined) {
      return Errors.badProtocolID;
    }
    this.createTimestamp = bb.readUint64();
    if (this.createTimestamp === undefined) {
      return Errors.badCreateTimestamp;
    }
    this.expireTimestamp = bb.readUint64();
    if (this.expireTimestamp === undefined) {
      return Errors.badExpireTimestamp;
    }
    if (this.createTimestamp.toNumber() > this.expireTimestamp.toNumber()) {
      return Errors.connectTokenExpired;
    }
    this.sequence = bb.readUint64();
    if (this.sequence === undefined) {
      return Errors.badSequence;
    }
    const privateData = bb.readBytes(Defines.CONNECT_TOKEN_PRIVATE_BYTES);
    if (privateData === undefined) {
      return Errors.badPrivateData;
    }
    this.privateData.tokenData = new ByteBuffer(privateData);
    const err = this.sharedTokenData.read(bb);
    if (err !== Errors.none) {
      return err;
    }
    return Errors.none;
  }
}
