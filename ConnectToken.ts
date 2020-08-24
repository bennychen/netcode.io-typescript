import * as Defines from './Defines';
import * as BB from './ByteBuffer';
import * as chacha from './chacha20poly1305';

export enum AddressType {
  ADDRESS_NONE,
  ADDRESS_IPV4,
  ADDRESS_IPV6,
}

export interface IUDPAddr {
  ip: Uint8Array;
  port: number;
  isIPV6?: boolean;
}

// This struct contains data that is shared in both public and private parts of the
// connect token.
export class SharedTokenData {
  timeoutSeconds: number;
  serverAddrs: IUDPAddr[];
  clientKey: Uint8Array;
  serverKey: Uint8Array;

  public generate() {
    this.clientKey = Defines.generateKey();
    this.serverKey = Defines.generateKey();
  }

  public read(buffer: BB.ByteBuffer): boolean {
    this.timeoutSeconds = buffer.readInt32();
    if (this.timeoutSeconds === undefined) {
      return;
    }
    const servers = buffer.readUint32();
    if (
      servers === undefined ||
      servers <= 0 ||
      servers > Defines.MAX_SERVERS_PER_CONNECT
    ) {
      return false;
    }

    this.serverAddrs = [];
    for (let i = 0; i < servers; i++) {
      const serverType = buffer.readUint8();
      if (serverType === undefined) {
        return false;
      }

      let ipBytes: Uint8Array;
      let isIPV6: boolean = false;
      if (serverType === AddressType.ADDRESS_IPV4) {
        ipBytes = buffer.readBytes(4);
        if (ipBytes === undefined) {
          return false;
        }
      } else if (serverType === AddressType.ADDRESS_IPV6) {
        ipBytes = new Uint8Array(16);
        for (let j = 0; j < 16; j += 2) {
          const n = buffer.readUint16();
          if (n === undefined) {
            return false;
          }
          // decode little endian -> big endian
          ipBytes[j] = 0xff & (n >> 8);
          ipBytes[j + 1] = 0xff & n;
        }
        isIPV6 = true;
      } else {
        return false;
      }
      const port = buffer.readUint16();
      if (port === undefined) {
        return false;
      }
      this.serverAddrs[i] = {
        ip: ipBytes,
        port: port,
        isIPV6,
      };
    }

    this.clientKey = buffer.readBytes(Defines.KEY_BYTES);
    if (!this.clientKey) {
      return false;
    }

    this.serverKey = buffer.readBytes(Defines.KEY_BYTES);
    if (!this.serverKey) {
      return false;
    }

    return true;
  }

  public write(buffer: BB.ByteBuffer) {
    buffer.writeInt32(this.timeoutSeconds);
    buffer.writeUint32(this.serverAddrs.length);

    for (const addr of this.serverAddrs) {
      if (addr.isIPV6) {
        buffer.writeUint8(AddressType.ADDRESS_IPV6);
        for (let i = 0; i < addr.ip.length; i += 2) {
          let n = (0xffff & addr.ip[i]) << 8;
          n |= 0xffff & addr.ip[i + 1];
          // encode big endian -> little endian
          buffer.writeUint16(n);
        }
      } else {
        buffer.writeUint8(AddressType.ADDRESS_IPV4);
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
  sharedTokenData: SharedTokenData;
  clientId: BB.Long;
  userData: Uint8Array;
  mac: Uint8Array;
  tokenData: BB.ByteBuffer;

  public static createEncrypted(buffer: Uint8Array): ConnectTokenPrivate {
    const p = new ConnectTokenPrivate();
    p.mac = new Uint8Array(Defines.MAC_BYTES);
    p.tokenData = new BB.ByteBuffer(buffer);
    return p;
  }

  public static create(
    clientID: BB.Long,
    timeoutSeconds: number,
    serverAddrs: IUDPAddr[],
    userData: Uint8Array
  ): ConnectTokenPrivate {
    const p = new ConnectTokenPrivate();
    p.tokenData = new BB.ByteBuffer(
      new Uint8Array(Defines.CONNECT_TOKEN_PRIVATE_BYTES)
    );
    p.clientId = clientID;
    p.userData = userData;
    p.sharedTokenData.timeoutSeconds = timeoutSeconds;
    p.sharedTokenData.serverAddrs = serverAddrs;
    p.mac = new Uint8Array(Defines.MAC_BYTES);
    return p;
  }

  public constructor() {
    this.sharedTokenData = new SharedTokenData();
  }

  public get buffer(): Uint8Array {
    return this.tokenData.bytes;
  }

  public generate() {
    return this.sharedTokenData.generate();
  }

  public read(): boolean {
    this.clientId = this.tokenData.readUint64();
    if (!this.clientId) {
      console.error('client id error');
      return false;
    }
    if (!this.sharedTokenData.read(this.tokenData)) {
      console.error('read share token error');
      return false;
    }
    this.userData = this.tokenData.readBytes(Defines.USER_DATA_BYTES);
    if (!this.userData) {
      console.error('read user data error');
      return false;
    }
    return true;
  }

  public write(): Uint8Array {
    this.tokenData.writeUint64(this.clientId);
    this.sharedTokenData.write(this.tokenData);
    this.tokenData.writeBytes(this.userData, Defines.USER_DATA_BYTES);
    return this.tokenData.bytes;
  }

  public encrypt(
    protocolID: BB.Long,
    expireTimestamp: BB.Long,
    sequence: BB.Long,
    privateKey: Uint8Array
  ): boolean {
    const { additionalData, nonce } = this.buildTokenCryptData(
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
    Defines.blockCopy(
      encrypted[0],
      0,
      this.tokenData.bytes,
      0,
      encrypted[0].length
    );
    Defines.blockCopy(
      encrypted[1],
      0,
      this.tokenData.bytes,
      encrypted[0].length,
      encrypted[1].length
    );
    this.mac = encrypted[1];
    return true;
  }

  public decrypt(
    protocolID: BB.Long,
    expireTimestamp: BB.Long,
    sequence: BB.Long,
    privateKey: Uint8Array
  ): Uint8Array {
    if (this.tokenData.bytes.length !== Defines.CONNECT_TOKEN_PRIVATE_BYTES) {
      console.error('wrong token data length');
      return;
    }
    Defines.blockCopy(
      this.tokenData.bytes,
      Defines.CONNECT_TOKEN_PRIVATE_BYTES - Defines.MAC_BYTES,
      this.mac,
      0,
      Defines.MAC_BYTES
    );
    const { additionalData, nonce } = this.buildTokenCryptData(
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
      this.tokenData = new BB.ByteBuffer(decrypted);
    } else {
      return;
    }
    this.tokenData.clearPosition();
    return this.tokenData.bytes;
  }

  private buildTokenCryptData(
    protocolID: BB.Long,
    expireTimestamp: BB.Long,
    sequence: BB.Long
  ): { additionalData: BB.ByteBuffer; nonce: BB.ByteBuffer } {
    const additionalData = new BB.ByteBuffer(
      new Uint8Array(Defines.VERSION_INFO_BYTES + 8 + 8)
    );
    additionalData.writeBytes(Defines.VERSION_INFO_BYTES_ARRAY);
    additionalData.writeUint64(protocolID);
    additionalData.writeUint64(expireTimestamp);

    const nonce = new BB.ByteBuffer(new Uint8Array(8 + 4));
    nonce.writeUint32(0);
    nonce.writeUint64(sequence);
    return { additionalData, nonce };
  }
}

export class ConnectToken {}
