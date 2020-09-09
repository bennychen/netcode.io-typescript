namespace Netcode {
  export class Long {
    public static readonly ZERO = new Long(0, 0);

    public static fromNumber(value: number): Long {
      if (value === 0) {
        return new Long(0, 0);
      }
      var sign = value < 0;
      if (sign) value = -value;
      var lo = value >>> 0,
        hi = ((value - lo) / 4294967296) >>> 0;
      if (sign) {
        hi = ~hi >>> 0;
        lo = ~lo >>> 0;
        if (++lo > 4294967295) {
          lo = 0;
          if (++hi > 4294967295) hi = 0;
        }
      }
      return new Long(lo, hi);
    }

    public get low(): number {
      return this._low;
    }

    public get high(): number {
      return this._high;
    }

    public set low(value: number) {
      this._low = value;
    }

    public set high(value: number) {
      this._high = value;
    }

    public constructor(low: number, high: number) {
      this._low = low | 0;
      this._high = high | 0;
    }

    public toNumber(): number {
      return (this._low >>> 0) + this._high * 0x100000000;
    }

    public equals(other: Long) {
      return this._low == other._low && this._high == other._high;
    }

    public plusOne() {
      if (this._low === 0xffffffff) {
        this._low = 0;
        this._high++;
      } else {
        this._low++;
      }
    }

    public leftShiftSelf(s: number) {
      const { low, high } = this.leftShift(s);
      this._low = low;
      this._high = high;
    }

    public leftShift(s: number): { low: number; high: number } {
      if (s === 0 || s >= 64) {
        return { high: this._high, low: this._low };
      } else if (s < 32) {
        return {
          high: (this._low >>> (32 - s)) | (this._high << s),
          low: (this._low << s) | 0,
        };
      } else if (s < 64) {
        return {
          high: (this._low << (s - 32)) | 0,
          low: 0,
        };
      }
    }

    public rightShiftSelf(s: number) {
      const { low, high } = this.rightShift(s);
      this._low = low;
      this._high = high;
    }

    public rightShift(s: number): { low: number; high: number } {
      if (s === 0 || s >= 64) {
        return { high: this._high, low: this._low };
      } else if (s < 32) {
        return {
          high: (this._high >>> s) | 0,
          low: (this._high << (32 - s)) | (this._low >>> s),
        };
      } else if (s < 64) {
        return {
          high: 0,
          low: (this._high >>> (s - 32)) | 0,
        };
      }
    }

    public setZero() {
      this._high = 0;
      this._low = 0;
    }

    private _low: number;
    private _high: number;
  }

  export class ByteBuffer {
    public static allocate(byte_size: number): ByteBuffer {
      return new ByteBuffer(new Uint8Array(byte_size));
    }

    public constructor(bytes: Uint8Array) {
      if (!(bytes instanceof Uint8Array)) {
        throw new Error('bytes must be a Uint8Array');
      }
      this._bytes = bytes;
      this._position = 0;
    }

    public get bytes(): Uint8Array {
      return this._bytes;
    }

    public get position(): number {
      return this._position;
    }

    public get capacity(): number {
      return this._bytes.length;
    }

    public skipPosition(value: number) {
      this._position += value;
    }

    public clearPosition() {
      this._position = 0;
    }

    public readInt8(): number | undefined {
      const n = this.readUint8();
      if (n !== undefined) {
        return (n << 24) >> 24;
      }
    }

    public readUint8(): number | undefined {
      if (this.assertPosition(1)) {
        return this._bytes[this._position++];
      }
    }

    public readInt16(): number | undefined {
      const n = this.readUint16();
      if (n !== undefined) {
        return (n << 16) >> 16;
      }
    }

    public readUint16(): number | undefined {
      if (this.assertPosition(2)) {
        const n =
          this._bytes[this._position] | (this._bytes[this._position + 1] << 8);
        this._position += 2;
        return n;
      }
    }

    public readInt32(): number | undefined {
      if (this.assertPosition(4)) {
        const n =
          this._bytes[this._position] |
          (this._bytes[this._position + 1] << 8) |
          (this._bytes[this._position + 2] << 16) |
          (this._bytes[this._position + 3] << 24);
        this._position += 4;
        return n;
      }
    }

    public readUint32(): number | undefined {
      const n = this.readInt32();
      if (n !== undefined) {
        return n >>> 0;
      }
    }

    public readInt64(): Long | undefined {
      const low = this.readInt32();
      const high = this.readInt32();
      if (low !== undefined && high !== undefined) {
        return new Long(low, high);
      }
    }

    public readUint64(): Long | undefined {
      const low = this.readUint32();
      const high = this.readUint32();
      if (low !== undefined && high !== undefined) {
        return new Long(low, high);
      }
    }

    public readBytes(length: number): Uint8Array | undefined {
      if (this.assertPosition(length)) {
        const ret = this._bytes.slice(this._position, this._position + length);
        this._position += length;
        return ret;
      }
    }

    public writeInt8(value: number) {
      this._bytes[this._position] = value;
      this._position += 1;
    }

    public writeUint8(value: number) {
      this._bytes[this._position] = value;
      this._position += 1;
    }

    public writeInt16(value: number) {
      this._bytes[this._position] = value;
      this._bytes[this._position + 1] = value >> 8;
      this._position += 2;
    }

    public writeUint16(value: number) {
      this._bytes[this._position] = value;
      this._bytes[this._position + 1] = value >> 8;
      this._position += 2;
    }

    public writeInt32(value: number) {
      this._bytes[this._position] = value;
      this._bytes[this._position + 1] = value >> 8;
      this._bytes[this._position + 2] = value >> 16;
      this._bytes[this._position + 3] = value >> 24;
      this._position += 4;
    }

    public writeUint32(value: number) {
      this._bytes[this._position] = value;
      this._bytes[this._position + 1] = value >> 8;
      this._bytes[this._position + 2] = value >> 16;
      this._bytes[this._position + 3] = value >> 24;
      this._position += 4;
    }

    public writeInt64(value: Long) {
      this.writeInt32(value.low);
      this.writeInt32(value.high);
    }

    public writeUint64(value: Long) {
      this.writeUint32(value.low);
      this.writeUint32(value.high);
    }

    public writeBytes(bytes: Uint8Array, length?: number) {
      if (length === undefined) {
        length = bytes.length;
      }
      for (let i = 0; i < length; i++) {
        this.writeUint8(bytes[i]);
      }
    }

    private assertPosition(length: number): boolean {
      const bufferLength = this._bytes.length;
      const bufferWindow = this._position + length;
      if (bufferWindow > bufferLength) {
        console.error('buffer out of bounds', bufferLength, bufferWindow);
        return false;
      }
      return true;
    }

    private _bytes: Uint8Array;
    private _position: number = 0;
  }
}
