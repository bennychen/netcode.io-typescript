import { Long } from './ByteBuffer';
import {
  IPacket,
  PacketType,
  PacketQueue,
  PacketFactory,
  RequestPacket,
} from './Packet';
import { ConnectToken } from './ConnectToken';
import * as Defines from './Defines';
import { ReplayProtection } from './ReplayProtection';
import { Errors } from './Errors';
import { NetcodeConn, UDPHandler } from './NetcodeConnection';

namespace NetcodeIO {
  enum ClientState {
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

  const CLIENT_MAX_RECEIVE_PACKETS = 64;
  const PACKET_SEND_RATE = 10.0;
  const NUM_DISCONNECT_PACKETS = 10; // number of disconnect packets the client/server should send when disconnecting

  interface IContext {
    writePacketKey: Uint8Array;
    readPacketKey: Uint8Array;
  }

  export class Client {
    public set id(value: Long) {
      this._id = value;
    }

    public get state(): ClientState {
      return this._state;
    }
    public set state(value: ClientState) {
      this._state = value;
    }

    public constructor(token: ConnectToken) {
      this._connectToken = token;
      this._lastPacketRecvTime = -1;
      this._lastPacketSendTime = -1;
      this._shouldDisconnect = false;
      this.state = ClientState.disconnected;
      this._challenTokenData = new Uint8Array(Defines.CHALLENGE_TOKEN_BYTES);
      this._replayProtection = new ReplayProtection();
      this._packetQueue = new PacketQueue(Defines.PACKET_QUEUE_SIZE);
      this._allowedPackets = new Uint8Array(PacketType.ConnectionNumPackets);
      this._allowedPackets[PacketType.ConnectionDenied] = 1;
      this._allowedPackets[PacketType.ConnectionChallenge] = 1;
      this._allowedPackets[PacketType.ConnectionKeepAlive] = 1;
      this._allowedPackets[PacketType.ConnectionPayload] = 1;
      this._allowedPackets[PacketType.ConnectionDisconnect] = 1;
    }

    public connect(dial: UDPHandler): Errors {
      this._dialFn = dial;
      this._startTime = 0;
      if (
        this._serverIndex >
        this._connectToken.sharedTokenData.serverAddrs.length
      ) {
        return Errors.exceededServerNumber;
      }
      this._serverAddr = this._connectToken.sharedTokenData.serverAddrs[
        this._serverIndex
      ];

      this._conn = new NetcodeConn();
      this._conn.setRecvHandler(this.handleNetcodeData);
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
      console.log(`client[${this._id}] disconnected: ${ClientState[reason]}`);
      if (this._state <= ClientState.disconnected) {
        console.warn('state <= disconnected');
        return;
      }

      if (sendDisconnect && this._state > ClientState.disconnected) {
        for (let i = 0; i < NUM_DISCONNECT_PACKETS; i += 1) {
          // TODO
          // packet := &DisconnectPacket{}
          // c.sendPacket(packet)
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
      this.tickSend();
      const state = this._state;
      if (state > ClientState.disconnected && state < ClientState.connected) {
        const expire =
          this._connectToken.expireTimestamp.toNumber() -
          this._connectToken.createTimestamp.toNumber();
        if (this._startTime + expire <= this._time) {
          // 		log.Printf("client[%d] connect failed. connect token expired\n", this.id)
          this.disconnect(ClientState.tokenExpired, false);
          return;
        }
      }
      if (this._shouldDisconnect) {
        console.log(
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
              console.log(`client[${this._id}] connection request timed out`);
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
              console.log(`client[${this._id}] connection response timed out`);
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
              console.log(`client[${this._id}] connection timed out`);
              this.disconnect(ClientState.connectionTimeout, false);
            }
          }
          break;
      }
    }

    public sendPayload(payloadData: Uint8Array): boolean {
      if (this._state !== ClientState.connected) {
        return;
      }
      // p := NewPayloadPacket(payloadData)
      // this.sendPacket(p)
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

      console.log(
        `client[${this._id}] connecting to next server %s (${this._serverAddr}`
      );
      const err = this.connect(this._dialFn);
      if (err != Errors.none) {
        console.log('error connecting to next server: ', Errors[err]);
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
            console.log(
              `client ${this._id} sent connection request packet to server`
            );
            this.sendPacket(p);
          }
          break;
        case ClientState.sendingConnectionResponse:
          {
            // p := &ResponsePacket{}
            // p.ChallengeTokenSequence = c.challengeSequence
            // p.ChallengeTokenData = c.challengeData
            console.log(
              `client ${this._id} sent connection response packet to server`
            );
            // return c.sendPacket(p)
          }
          break;
        case ClientState.connected:
          // p := &KeepAlivePacket{}
          // p.ClientIndex = 0
          // p.MaxClients = 0
          // log.Printf("client[%d] sent connection keep-alive packet to server\n", c.id)
          // return c.sendPacket(p)
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
      this._sequence++;
      return true;
    }

    private handleNetcodeData(data: Defines.INetcodeData) {
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
      if (err !== Errors.none) {
        console.log(err);
      }
      this.processPacket(packet);
    }

    private processPacket(packet: IPacket) {
      switch (packet.getType()) {
        case PacketType.ConnectionDenied:
          if (
            this._state == ClientState.sendingConnectionRequest ||
            this._state == ClientState.sendingConnectionResponse
          ) {
            this._shouldDisconnect = true;
            this._shouldDisconnectState = ClientState.connectionDenied;
          }
          break;
        case PacketType.ConnectionChallenge:
          if (this._state !== ClientState.sendingConnectionResponse) {
            return;
          }
          // TODO
          break;
        case PacketType.ConnectionKeepAlive:
          // TODO
          break;
        case PacketType.ConnectionPayload:
          if (this._state != ClientState.connected) {
            return;
          }
          // TODO
          break;
        case PacketType.ConnectionDisconnect:
          if (this._state != ClientState.connected) {
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
      this._sequence = 0;
      this._clientIndex = 0;
      this._maxClients = 0;
      this._startTime = 0;
      this._serverIndex = 0;
      this._serverAddr = null;
      this._connectToken = null;
      this._context = null;
      this.state = newState;
      this.reset();
      this._packetQueue.clear();
      this._conn.close();
    }

    private _dialFn: UDPHandler;
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

    private _sequence: number;
    private _challenTokenData: Uint8Array;
    private _challengeSequence: Long;
    private _allowedPackets: Uint8Array;
    private _packetQueue: PacketQueue;
    private _receivedPackets: Defines.INetcodeData[];

    private _state: ClientState;
    private _replayProtection: ReplayProtection;
    private _conn: NetcodeConn;
  }
}
