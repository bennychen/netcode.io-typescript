export declare function aead_encrypt(
  key: Uint8Array | Array,
  nonce: Uint8Array | Array,
  plaintext: Uint8Array | Array,
  data: Uint8Array | Array
): Uint8Array[];
export declare function aead_decrypt(
  key: Uint8Array | Array,
  nonce: Uint8Array | Array,
  ciphertext: Uint8Array | Array,
  data: Uint8Array | Array,
  mac: Uint8Array | Array
): boolean | Uint8Array;
export declare function getRandomBytes(n: number): Uint8Array;
