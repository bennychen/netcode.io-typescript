import * as chacha from './chacha20poly1305';
import { ByteBuffer, Long } from './ByteBuffer';
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
}
