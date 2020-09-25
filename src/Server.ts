namespace Netcode {
  export const TIMEOUT_SECONDS = 5; // default timeout for clients
  export const MAX_SERVER_PACKETS = 64;

  export class Server {
    serverConn: NetcodeConn;
    serverAddr: IUDPAddr;
    // shutdownCh      :chan struct{}
    serverTime: number;
    running: boolean;
    maxClients: number;
    connectedClients: number;
    timeout: number;

    clientManager: ClientManager;
    globalSequence: Long;

    ignoreRequest: boolean;
    ignoreResponse: boolean;
    allowedPacket: Uint8Array;
    protocolId: Long;

    privateKey: Uint8Array;
    challengeKe: Uint8Array;

    challengeSequenc: Long;
    recvByte: number;
    // packetCh : chan *NetcodeData
  }
}
