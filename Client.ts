import { Long } from './ByteBuffer';
import { IPacket, PacketType } from './Packet';
import { ConnectToken } from './ConnectToken';
import * as Defines from './Defines';

enum ClientState {
  tokenExpired = -6,
  invalidConnectToken = -5,
  connectionTimeout = -4,
  connectionResponseTimeout = -3,
  connectionRequestTimeout = -2,
  connectionDenied = -1,
  disconnected = 0,
  connectionRequest = 1,
  connectionResponse = 2,
  connected = 3,
}

export class Client {
  public set id(value: Long) {
    this._id = value;
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
    this._allowedPackets = new Uint8Array(PacketType.ConnectionNumPackets);
    this._allowedPackets[PacketType.ConnectionDenied] = 1;
    this._allowedPackets[PacketType.ConnectionChallenge] = 1;
    this._allowedPackets[PacketType.ConnectionKeepAlive] = 1;
    this._allowedPackets[PacketType.ConnectionPayload] = 1;
    this._allowedPackets[PacketType.ConnectionDisconnect] = 1;
  }

  public _id: Long;
  public _connectToken: ConnectToken;

  private _time: number;
  private _startTime: number;

  private _lastPacketRecvTime: number;
  private _lastPacketSendTime: number;
  private _packets: IPacket[];
  private _shouldDisconnect: boolean;

  private _challenTokenData: Uint8Array;
  private _allowedPackets: Uint8Array;

  private _state: ClientState;
  // private _replayProtection: ReplayProtection;
}
