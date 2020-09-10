namespace Netcode {
  // This struct contains data that is shared in both public and private parts of the
  // connect token.
  export class SharedTokenData {
    public timeoutSeconds: number;
    public serverAddrs: IUDPAddr[];
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
      if (servers === undefined) {
        return Errors.EOF;
      }
      if (servers <= 0) {
        return Errors.emptyServer;
      }
      if (servers > MAX_SERVERS_PER_CONNECT) {
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
        if (serverType === AddressType.ipv4) {
          ipBytes = buffer.readBytes(4);
          if (ipBytes === undefined) {
            return Errors.EOF;
          }
        } else if (serverType === AddressType.ipv6) {
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

      this.clientKey = buffer.readBytes(KEY_BYTES);
      if (!this.clientKey) {
        return Errors.EOF;
      }

      this.serverKey = buffer.readBytes(KEY_BYTES);
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
          buffer.writeUint8(AddressType.ipv6);
          for (let i = 0; i < addr.ip.length; i += 2) {
            let n = (0xffff & addr.ip[i]) << 8;
            n |= 0xffff & addr.ip[i + 1];
            // encode big endian -> little endian
            buffer.writeUint16(n);
          }
        } else {
          buffer.writeUint8(AddressType.ipv4);
          buffer.writeBytes(addr.ip);
        }
        buffer.writeUint16(addr.port);
      }

      buffer.writeBytes(this.clientKey, KEY_BYTES);
      buffer.writeBytes(this.serverKey, KEY_BYTES);
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
      serverAddrs: IUDPAddr[],
      userData: Uint8Array
    ): ConnectTokenPrivate {
      const p = new ConnectTokenPrivate();
      p.tokenData = ByteBuffer.allocate(CONNECT_TOKEN_PRIVATE_BYTES);
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
      this._sharedAdditionalBytes.writeBytes(VERSION_INFO_BYTES_ARRAY);
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
    private static _sharedAdditionalBytes: ByteBuffer = ByteBuffer.allocate(
      VERSION_INFO_BYTES + 8 + 8
    );
    private static _sharedNonce: ByteBuffer = ByteBuffer.allocate(8 + 4);

    public sharedTokenData: SharedTokenData;
    public clientId: Long;
    public userData: Uint8Array;
    public mac: Uint8Array;
    public tokenData: ByteBuffer;

    public constructor() {
      this.sharedTokenData = new SharedTokenData();
      this.mac = new Uint8Array(MAC_BYTES);
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
      this.userData = this.tokenData.readBytes(USER_DATA_BYTES);
      if (!this.userData) {
        return Errors.badUserData;
      }
      return Errors.none;
    }

    public write(): Uint8Array {
      this.tokenData.writeUint64(this.clientId);
      this.sharedTokenData.write(this.tokenData);
      this.tokenData.writeBytes(this.userData, USER_DATA_BYTES);
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
        CONNECT_TOKEN_PRIVATE_BYTES - MAC_BYTES
      );
      const encrypted = Utils.aead_encrypt(
        privateKey,
        nonce.bytes,
        encBuf,
        additionalData.bytes
      );
      if (
        encrypted[0].length + encrypted[1].length !==
        CONNECT_TOKEN_PRIVATE_BYTES
      ) {
        console.error(
          'encrypted length not correct',
          encrypted[0].length,
          CONNECT_TOKEN_PRIVATE_BYTES
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
      if (this.tokenData.bytes.length !== CONNECT_TOKEN_PRIVATE_BYTES) {
        console.error('wrong connect private token data length');
        return;
      }
      this.mac.set(
        this.tokenData.bytes.subarray(CONNECT_TOKEN_PRIVATE_BYTES - MAC_BYTES),
        0
      );
      const { additionalData, nonce } = ConnectTokenPrivate.buildTokenCryptData(
        protocolID,
        expireTimestamp,
        sequence
      );
      const decrypted = Utils.aead_decrypt(
        privateKey,
        nonce.bytes,
        this.tokenData.bytes.subarray(
          0,
          CONNECT_TOKEN_PRIVATE_BYTES - MAC_BYTES
        ),
        additionalData.bytes,
        this.mac
      );
      if (decrypted) {
        this.tokenData = new ByteBuffer(decrypted as Uint8Array);
      } else {
        console.error('decrypted connect private token failed');
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
      serverAddrs: IUDPAddr[],
      protocoalID: Long,
      expireSeconds: number,
      timeoutSeconds: number,
      sequence: Long,
      userData: Uint8Array,
      privateKey: Uint8Array
    ): boolean {
      const now = Date.now();
      this.createTimestamp = Long.fromNumber(now);
      if (expireSeconds >= 0) {
        this.expireTimestamp = Long.fromNumber(now + expireSeconds);
      } else {
        this.expireTimestamp = Long.fromNumber(0xffffffffffffffff);
      }
      this.sharedTokenData.timeoutSeconds = timeoutSeconds;
      this.versionInfo = new Uint8Array(VERSION_INFO_BYTES_ARRAY);
      this.protocolID = protocoalID;
      this.sequence = new Long(sequence.low, sequence.high);

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
      const bb = ByteBuffer.allocate(CONNECT_TOKEN_BYTES);
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
      this.versionInfo = bb.readBytes(VERSION_INFO_BYTES);
      if (
        this.versionInfo === undefined ||
        !Utils.arrayEqual(this.versionInfo, VERSION_INFO_BYTES_ARRAY)
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
      const privateData = bb.readBytes(CONNECT_TOKEN_PRIVATE_BYTES);
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

  export class ChallengeToken {
    public get clientID(): Long {
      return this._clientID;
    }

    public get userData(): Uint8Array {
      return this._userData.bytes;
    }

    public constructor(clientID?: Long) {
      this._userData = ByteBuffer.allocate(USER_DATA_BYTES);
      if (clientID) {
        this._clientID = clientID;
      }
    }

    public static encrypt(
      tokenBuffer: Uint8Array,
      sequance: Long,
      key: Uint8Array
    ) {
      this._nonceBuffer.clearPosition();
      this._nonceBuffer.writeUint32(0);
      this._nonceBuffer.writeUint64(sequance);
      const encrypted = Utils.aead_encrypt(
        key,
        this._nonceBuffer.bytes,
        tokenBuffer.subarray(0, CHALLENGE_TOKEN_BYTES - MAC_BYTES),
        []
      );
      tokenBuffer.set(encrypted[0], 0);
      tokenBuffer.set(encrypted[1], encrypted[0].length);
    }

    public static decrypt(
      tokenBuffer: Uint8Array,
      sequance: Long,
      key: Uint8Array
    ): Uint8Array {
      this._nonceBuffer.clearPosition();
      this._nonceBuffer.writeUint32(0);
      this._nonceBuffer.writeUint64(sequance);
      const decrypted = Utils.aead_decrypt(
        key,
        this._nonceBuffer.bytes,
        tokenBuffer.subarray(0, CHALLENGE_TOKEN_BYTES - MAC_BYTES),
        [],
        tokenBuffer.subarray(CHALLENGE_TOKEN_BYTES - MAC_BYTES)
      );
      if (decrypted) {
        return decrypted as Uint8Array;
      }
    }

    private static _nonceBuffer: ByteBuffer = ByteBuffer.allocate(8 + 4);

    public write(userData: Uint8Array): Uint8Array {
      this._userData.writeBytes(userData);

      const tokenData = ByteBuffer.allocate(CHALLENGE_TOKEN_BYTES);
      tokenData.writeUint64(this._clientID);
      tokenData.writeBytes(this._userData.bytes);
      return tokenData.bytes;
    }

    public read(buffer: Uint8Array): Errors {
      const bb = new ByteBuffer(buffer);
      this._clientID = bb.readUint64();
      if (this._clientID === undefined) {
        return Errors.invalidClientID;
      }

      const userData = bb.readBytes(USER_DATA_BYTES);
      if (userData === undefined) {
        return Errors.badUserData;
      }
      this._userData.writeBytes(userData);
      this._userData.clearPosition();
      return Errors.none;
    }

    private _clientID: Long;
    private _userData: ByteBuffer;
  }
}
