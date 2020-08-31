import * as chacha from '../libs/chacha20poly1305';
import * as Defines from './Defines';

export class Utils {
  public static generateKey(): Uint8Array {
    return this.getRandomBytes(Defines.KEY_BYTES);
  }

  public static getRandomBytes(num: number): Uint8Array {
    return chacha.getRandomBytes(num);
  }

  public static blockCopy(
    src: Uint8Array,
    srcOffset: number,
    dst: Uint8Array,
    dstOffset: number,
    count: number
  ) {
    if (
      dstOffset + count < 0 ||
      dstOffset + count > dst.length ||
      srcOffset + count < 0 ||
      srcOffset + count > src.length
    ) {
      throw new Error('blockCopy::array out of bounds');
    }
    for (let i = 0; i < count; i++) {
      dst[dstOffset + i] = src[srcOffset + i];
    }
  }

  public static arrayEqual(a1: Uint8Array, a2: Uint8Array) {
    a1.forEach(function (item, index) {
      if (a2[index] !== item) {
        return false;
      }
    });
    return true;
  }

  public static stringToIPV4Address(ip: string): Defines.IUDPAddr {
    const ipAndPort = ip.split(':');
    let port = 0;
    if (ipAndPort.length == 2) {
      port = parseInt(ipAndPort[1], 10);
      if (Number.isNaN(port) || port <= 0) {
        console.warn('port must be a valid number larger than 0');
      }
    }
    const octets = ip.split('.');
    if (octets.length !== 4) {
      console.error('only support ipv4');
      return;
    }
    const bytes = new Uint8Array(4);
    for (var i = 0; i < octets.length; ++i) {
      var octet = parseInt(octets[i], 10);
      if (Number.isNaN(octet) || octet < 0 || octet > 255) {
        throw new Error('Each octet must be between 0 and 255');
      }
      bytes[i] = octet;
    }
    return { ip: bytes, isIPV6: false, port };
  }

  public static IPV4AddressToString(
    address: Defines.IUDPAddr,
    appendPort?: boolean
  ): string {
    if (address.isIPV6) {
      console.error('only support ipv4');
      return '';
    } else {
      let str = `${address.ip[0]}.${address.ip[1]}.${address.ip[2]}.${address.ip[3]}`;
      if (appendPort && address.port > 0) {
        str += `:${address.port}`;
      }
      return str;
    }
  }
}

export class Queue<T> {
  public constructor(capacity: number) {
    this._capacity = capacity;
    this._elements = new Array<T>(capacity);
    this.clear();
  }

  public clear() {
    this._numElements = 0;
    this._startIndex = 0;
    this._elements.fill(null);
  }

  public push(element: T): boolean {
    if (this._numElements === this._capacity) {
      return false;
    }

    const index = (this._startIndex + this._numElements) % this._capacity;
    this._elements[index] = element;
    this._numElements++;
    return true;
  }

  public pop(): T {
    if (this._numElements === 0) {
      return null;
    }
    const element = this._elements[this._startIndex];
    this._startIndex = (this._startIndex + 1) % this._capacity;
    this._numElements--;
    return element;
  }

  private _numElements: number;
  private _startIndex: number;
  private _elements: Array<T>;
  private _capacity: number;
}
