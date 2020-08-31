export const CONNECT_TOKEN_PRIVATE_BYTES = 1024;
export const CHALLENGE_TOKEN_BYTES = 300;
export const VERSION_INFO_BYTES = 13;
export const USER_DATA_BYTES = 256;
export const MAX_PACKET_BYTES = 1220;
export const MAX_PAYLOAD_BYTES = 1200;
export const MAX_ADDRESS_STRING_LENGTH = 256;

export const KEY_BYTES = 32;
export const MAC_BYTES = 16;
export const NONCE_BYTES = 8;
export const MAX_SERVERS_PER_CONNECT = 32;

export const VERSION_INFO = 'NETCODE 1.01\x00';
export const VERSION_INFO_BYTES_ARRAY = new Uint8Array([
  78,
  69,
  84,
  67,
  79,
  68,
  69,
  32,
  49,
  46,
  48,
  49,
  0,
]);

export const CONNECT_TOKEN_BYTES = 2048;

export const PACKET_QUEUE_SIZE = 256;

export enum AddressType {
  none,
  ipv4,
  ipv6,
}

export interface IUDPAddr {
  ip: Uint8Array;
  port: number;
  isIPV6?: boolean;
}

export type onMessageHandler = (message: Uint8Array, remote: IUDPAddr) => void;

export interface IUDPConn {
  connect(addr: IUDPAddr);
  bind(addr: IUDPAddr);
  send(b: Uint8Array): number;
  sendTo(b: Uint8Array, addr: IUDPAddr): number;
  close();
  setReadBuffer(size: number);
  setWriteBuffer(size: number);
  onMessage(callback: onMessageHandler);
}
