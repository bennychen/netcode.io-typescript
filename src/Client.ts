import { Long } from './ByteBuffer';
import {
  IPacket,
  PacketType,
  PacketFactory,
  RequestPacket,
  ChallengePacket,
  KeepAlivePacket,
  ResponsePacket,
  PayloadPacket,
  DisconnectPacket,
} from './Packet';
import { ConnectToken } from './Token';
import * as Defines from './Defines';
import { Queue } from './Utils';
import { ReplayProtection } from './ReplayProtection';
import { Errors } from './Errors';
import { INetcodeData, NetcodeConn, UDPConnCreator } from './NetcodeConnection';

export enum ClientState {
  tokenExpired = -6,
  invalidConnectToken = -5,
  connectionTimeout = -4,
  connectionResponseTimeout = -3,
  connectionRequestTimeout = -2,
  connectionDenied = -1,
  disconnected = 0,
  sendingConnectionRequest = 1,
  sendingConnectionResponse = 2,
  connected = 3,
}

const PACKET_SEND_RATE = 10.0;
const NUM_DISCONNECT_PACKETS = 10; // number of disconnect packets the client/server should send when disconnecting

export interface IContext {
  writePacketKey: Uint8Array;
  readPacketKey: Uint8Array;
}

export class Client {
  public debug: boolean = false;

  public get id(): Long {
    return this._id;
  }

  public set id(value: Long) {
    this._id = value;
  }

  public get state(): ClientState {
    return this._state;
  }
  public set state(value: ClientState) {
    this._state = value;
  }

  public get clientIndex(): number {
    return this._clientIndex;
  }

  public get maxClients(): number {
    return this._maxClients;
  }

  public constructor(token: ConnectToken) {
    this._connectToken = token;
    this._lastPacketRecvTime = -1;
    this._lastPacketSendTime = -1;
    this._shouldDisconnect = false;
    this.state = ClientState.disconnected;
    this._challenTokenData = new Uint8Array(Defines.CHALLENGE_TOKEN_BYTES);
    this._replayProtection = new ReplayProtection();
    this._payloadPacketQueue = new Queue<IPacket>(Defines.PACKET_QUEUE_SIZE);
    this._allowedPackets = new Uint8Array(PacketType.numPackets);
    this._allowedPackets[PacketType.connectionDenied] = 1;
    this._allowedPackets[PacketType.connectionChallenge] = 1;
    this._allowedPackets[PacketType.connectionKeepAlive] = 1;
    this._allowedPackets[PacketType.connectionPayload] = 1;
    this._allowedPackets[PacketType.connectionDisconnect] = 1;
  }

  public connect(dial: UDPConnCreator): Errors {
    this._dialFn = dial;
    this._startTime = 0;
    if (
      this._serverIndex > this._connectToken.sharedTokenData.serverAddrs.length
    ) {
      return Errors.exceededServerNumber;
    }
    this._serverAddr = this._connectToken.sharedTokenData.serverAddrs[
      this._serverIndex
    ];

    this._conn = new NetcodeConn();
    this._conn.setRecvHandler(this.handleNetcodeData.bind(this));
    if (!this._conn.dial(dial, this._serverAddr)) {
      return Errors.dialServer;
    }

    this._context = {
      readPacketKey: this._connectToken.sharedTokenData.serverKey,
      writePacketKey: this._connectToken.sharedTokenData.clientKey,
    };
    this.state = ClientState.sendingConnectionRequest;
    return Errors.none;
  }

  public disconnect(reason: ClientState, sendDisconnect: boolean) {
    this.debugLog(`client[${this._id}] disconnected: ${ClientState[reason]}`);
    if (this._state <= ClientState.disconnected) {
      console.warn('state <= disconnected');
      return;
    }

    if (sendDisconnect && this._state > ClientState.disconnected) {
      for (let i = 0; i < NUM_DISCONNECT_PACKETS; i += 1) {
        const p = new DisconnectPacket();
        this.sendPacket(p);
      }
    }
    this.resetConectionData(reason);
  }

  public close() {
    if (this._conn) {
      this._conn.close();
    }
  }

  public reset() {
    this._lastPacketSendTime = this._time - 1;
    this._lastPacketRecvTime = this._time - 1;
    this._shouldDisconnect = false;
    this._shouldDisconnectState = ClientState.disconnected;
    this._challenTokenData.fill(0);
    this._challengeSequence.setZero();
    this._replayProtection.reset();
  }

  public tick(t: number) {
    this._time = t;
    for (const p of this._receivedPackets) {
      this.onPacketData(p.data, p.from);
    }
    this._receivedPackets = [];
    this.tickSend();
    const state = this._state;
    if (state > ClientState.disconnected && state < ClientState.connected) {
      const expire =
        this._connectToken.expireTimestamp.toNumber() -
        this._connectToken.createTimestamp.toNumber();
      if (this._startTime + expire <= this._time) {
        this.debugLog(`client${this.id} connect failed. connect token expired`);
        this.disconnect(ClientState.tokenExpired, false);
        return;
      }
    }
    if (this._shouldDisconnect) {
      this.debugLog(
        `client${this._id} should disconnect -> ${
          ClientState[this._shouldDisconnectState]
        }`
      );
      if (this.connectNextServer()) {
        return;
      }
      this.disconnect(this._shouldDisconnectState, false);
      return;
    }
    switch (this._state) {
      case ClientState.sendingConnectionRequest:
        {
          const timeout =
            this._lastPacketRecvTime +
            this._connectToken.sharedTokenData.timeoutSeconds * 1000;
          if (timeout < this._time) {
            this.debugLog(`client[${this._id}] connection request timed out`);
            if (this.connectNextServer()) {
              return;
            }
            this.disconnect(ClientState.connectionRequestTimeout, false);
          }
        }
        break;
      case ClientState.sendingConnectionResponse:
        {
          const timeout =
            this._lastPacketRecvTime +
            this._connectToken.sharedTokenData.timeoutSeconds * 1000;
          if (timeout < this._time) {
            this.debugLog(`client[${this._id}] connection response timed out`);
            if (this.connectNextServer()) {
              return;
            }
            this.disconnect(ClientState.connectionResponseTimeout, false);
          }
        }
        break;
      case ClientState.connected:
        {
          const timeout =
            this._lastPacketRecvTime +
            this._connectToken.sharedTokenData.timeoutSeconds * 1000;
          if (timeout < this._time) {
            this.debugLog(`client[${this._id}] connection timed out`);
            this.disconnect(ClientState.connectionTimeout, false);
          }
        }
        break;
    }
  }

  public sendPayload(payloadData: Uint8Array): boolean {
    if (this._state !== ClientState.connected) {
      return false;
    }
    const p = new PayloadPacket(payloadData);
    this.sendPacket(p);
  }

  public recvPayload(): { data: Uint8Array; sequence: Long } {
    const packet = this._payloadPacketQueue.pop();
    if (packet) {
      const p = packet as PayloadPacket;
      return { data: p.payloadData, sequence: p.sequence() };
    }
  }

  private connectNextServer(): boolean {
    if (
      this._serverIndex + 1 >=
      this._connectToken.sharedTokenData.serverAddrs.length
    ) {
      return false;
    }

    this._serverIndex++;
    this._serverAddr = this._connectToken.sharedTokenData.serverAddrs[
      this._serverIndex
    ];

    this.reset();

    this.debugLog(
      `client[${this._id}] connecting to next server %s (${this._serverAddr}`
    );
    const err = this.connect(this._dialFn);
    if (err != Errors.none) {
      this.debugLog('error connecting to next server: ' + Errors[err]);
      return false;
    }
    this.state = ClientState.sendingConnectionRequest;
    return true;
  }

  private tickSend() {
    // check our send rate prior to bother sending
    if (this._lastPacketSendTime + 1.0 / PACKET_SEND_RATE >= this._time) {
      return;
    }
    switch (this._state) {
      case ClientState.sendingConnectionRequest:
        {
          const p = new RequestPacket();
          p.setProperties(
            this._connectToken.versionInfo,
            this._connectToken.protocolID,
            this._connectToken.expireTimestamp,
            this._connectToken.sequence,
            this._connectToken.privateData.buffer
          );
          this.debugLog(
            `client ${this._id} sent connection request packet to server`
          );
          this.sendPacket(p);
        }
        break;
      case ClientState.sendingConnectionResponse:
        {
          const p = new ResponsePacket();
          p.setProperties(this._challengeSequence, this._challenTokenData);
          this.debugLog(
            `client ${this._id} sent connection response packet to server`
          );
          this.sendPacket(p);
        }
        break;
      case ClientState.connected:
        const p = new KeepAlivePacket();
        p.setProperties(0, 0);
        // sent connection keep-alive packet to server
        this.sendPacket(p);
        break;
    }
  }

  private sendPacket(packet: IPacket): boolean {
    const buffer = new Uint8Array(Defines.MAX_PACKET_BYTES);
    const bytesCount = packet.write(
      buffer,
      this._connectToken.protocolID,
      this._sequence,
      this._context.writePacketKey
    );
    if (bytesCount <= 0) {
      return false;
    }
    if (this._conn.write(buffer.subarray(0, bytesCount)) <= 0) {
      return false;
    }
    this._lastPacketSendTime = this._time;
    this._sequence.plusOne();
    return true;
  }

  private handleNetcodeData(data: INetcodeData) {
    this._receivedPackets.push(data);
  }

  private onPacketData(packetData: Uint8Array, from: Defines.IUDPAddr) {
    const size = packetData.length;
    const timestamp = Date.now();

    const packet = PacketFactory.create(packetData);
    const err = packet.read(packetData, size, {
      protocolId: this._connectToken.protocolID,
      currentTimestamp: timestamp,
      readPacketKey: this._context.readPacketKey,
      privateKey: null,
      allowedPackets: this._allowedPackets,
      replayProtection: this._replayProtection,
    });
    if (err === Errors.none) {
      this.processPacket(packet);
    } else {
      console.error(err);
    }
  }

  private processPacket(packet: IPacket) {
    switch (packet.getType()) {
      case PacketType.connectionDenied:
        if (
          this._state == ClientState.sendingConnectionRequest ||
          this._state == ClientState.sendingConnectionResponse
        ) {
          this.debugLog(
            `client ${this._id} got connection denied packet from server`
          );
          this._shouldDisconnect = true;
          this._shouldDisconnectState = ClientState.connectionDenied;
        }
        break;
      case PacketType.connectionChallenge:
        if (this._state !== ClientState.sendingConnectionRequest) {
          return;
        }
        this.debugLog(
          `client ${this._id} got connection challenge packet from server`
        );
        const challengePacket = packet as ChallengePacket;
        this._challengeSequence = challengePacket.challengeTokenSequence;
        this._challenTokenData = challengePacket.tokenData;
        this.state = ClientState.sendingConnectionResponse;
        break;
      case PacketType.connectionKeepAlive:
        const keepAlivePacket = packet as KeepAlivePacket;
        if (this._state === ClientState.sendingConnectionResponse) {
          this._clientIndex = keepAlivePacket.clientIndex;
          this._maxClients = keepAlivePacket.maxClients;
          this.state = ClientState.connected;
        }
        break;
      case PacketType.connectionPayload:
        if (this._state !== ClientState.connected) {
          return;
        }
        this.debugLog(
          `client ${
            this._id
          } got payload packet from server ${(packet as PayloadPacket)
            .sequence()
            .toNumber()}`
        );
        this._payloadPacketQueue.push(packet);
        break;
      case PacketType.connectionDisconnect:
        this.debugLog(
          `client ${this._id} got connection disconnect packet from server`
        );
        if (this._state !== ClientState.connected) {
          return;
        }
        this._shouldDisconnect = true;
        this._shouldDisconnectState = ClientState.disconnected;
        break;
      default:
        return;
    }
    this._lastPacketRecvTime = this._time;
  }

  private resetConectionData(newState: ClientState) {
    this._sequence.setZero();
    this._clientIndex = 0;
    this._maxClients = 0;
    this._startTime = 0;
    this._serverIndex = 0;
    this._serverAddr = null;
    this._connectToken = null;
    this._context = null;
    this.state = newState;
    this.reset();
    this._payloadPacketQueue.clear();
    this._conn.close();
  }

  private debugLog(str: string) {
    if (this.debug) {
      console.log(str);
    }
  }

  private _dialFn: UDPConnCreator;
  private _id: Long;
  private _connectToken: ConnectToken;
  private _clientIndex: number = 0;
  private _maxClients: number = 0;

  private _time: number = 0;
  private _startTime: number;
  private _serverIndex: number = 0;
  private _serverAddr: Defines.IUDPAddr;

  private _context: IContext;
  private _lastPacketRecvTime: number;
  private _lastPacketSendTime: number;
  private _shouldDisconnect: boolean;
  private _shouldDisconnectState: ClientState;

  private _sequence: Long = new Long(0, 0);
  private _challenTokenData: Uint8Array;
  private _challengeSequence: Long = new Long(0, 0);
  private _allowedPackets: Uint8Array;
  private _payloadPacketQueue: Queue<IPacket>;
  private _receivedPackets: INetcodeData[] = [];

  private _state: ClientState;
  private _replayProtection: ReplayProtection;
  private _conn: NetcodeConn;
}
