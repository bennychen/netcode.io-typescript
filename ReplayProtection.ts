import { REPLAY_PROTECTION_BUFFER_SIZE } from './Defines';

// Our type to hold replay protection of packet sequences
export class ReplayProtection {
  public constructor() {
    this._receivedPacket = new Array(REPLAY_PROTECTION_BUFFER_SIZE);
    this.reset();
  }

  public reset() {
    this._mostRecentSequence = 0;
    this._receivedPacket.fill(0xffffffffffffffff);
  }

  public checkAlreadyReceived(sequence: number): boolean {
    if ((sequence & (1 << 63)) !== 0) {
      return false;
    }
    if (sequence + REPLAY_PROTECTION_BUFFER_SIZE <= this._mostRecentSequence) {
      return true;
    }
    if (sequence > this._mostRecentSequence) {
      this._mostRecentSequence = sequence;
    }
    const index = sequence % REPLAY_PROTECTION_BUFFER_SIZE;
    if (this._receivedPacket[index] == 0xffffffffffffffff) {
      this._receivedPacket[index] = sequence;
      return false;
    }
    if (this._receivedPacket[index] >= sequence) {
      return true;
    }
    this._receivedPacket[index] = sequence;
    return false;
  }

  private _mostRecentSequence: number;
  private _receivedPacket: Array<number>;
}
