declare function aead_encrypt(
  key: Uint8Array | Array<number>,
  nonce: Uint8Array | Array<number>,
  plaintext: Uint8Array | Array<number>,
  data: Uint8Array | Array<number>
): Uint8Array[];
declare function aead_decrypt(
  key: Uint8Array | Array<number>,
  nonce: Uint8Array | Array<number>,
  ciphertext: Uint8Array | Array<number>,
  data: Uint8Array | Array<number>,
  mac: Uint8Array | Array<number>
): boolean | Uint8Array;
declare function getRandomBytes(n: number): Uint8Array;
