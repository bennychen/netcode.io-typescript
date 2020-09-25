namespace Netcode {
  export class ClientInstance {
    public clientId: Long;
    public clientIndex: number;
    public serverConn: NetcodeConn;
    public confirmed: boolean;
    public connected: boolean;

    public encryptionIndex: number;
    public sequence: Long;
    public lastSendTime: number;
    public lastRecvTime: number;
    public userData: Uint8Array;
    public protocolId: Long;
    public replayProtection: ReplayProtection;
    public address: IUDPAddr;
    public packetQueue: Queue<IPacket>;
    public packetData: Uint8Array;

    public constructor() {
      this.userData = new Uint8Array(USER_DATA_BYTES);
      this.packetQueue = new Queue(PACKET_QUEUE_SIZE);
      this.packetData = new Uint8Array(MAX_PACKET_BYTES);
      this.replayProtection = new ReplayProtection();
    }

    public clear() {
      this.replayProtection.reset();
      this.connected = false;
      this.confirmed = false;
      this.clientId.setZero();
      this.sequence.setZero();
      this.lastSendTime = 0.0;
      this.lastRecvTime = 0.0;
      this.address = null;
      this.clientIndex = -1;
      this.encryptionIndex = -1;
      this.packetQueue.clear();
      this.userData.fill(0);
      this.packetData.fill(0);
    }

    public sendPacket(
      packet: IPacket,
      writePacketKey: Uint8Array,
      serverTime: number
    ): boolean {
      let writeCount = packet.write(
        this.packetData,
        this.protocolId,
        this.sequence,
        writePacketKey
      );
      if (writeCount === 0) {
        return false;
      }

      if (
        !this.serverConn.writeTo(
          this.packetData.subarray(0, writeCount),
          this.address
        )
      ) {
        return false;
      }

      this.sequence.plusOne();
      this.lastSendTime = serverTime;
      return true;
    }
  }

  interface IConnectTokenEntry {
    mac: Uint8Array;
    address: IUDPAddr;
    time: number;
  }

  interface IEncryptionEntry {
    expireTime: number;
    lastAccess: number;
    timeout: number;
    address: IUDPAddr;
    sendKey: Uint8Array;
    recvKey: Uint8Array;
  }

  export type ClientConnectionHandler = (client: ClientInstance) => void;

  export class ClientManager {
    public constructor(timeout: number, maxClients: number) {
      this.maxClients = maxClients;
      this.maxEntries = maxClients * 8;
      this.timeout = timeout;
      this.emptyMac = new Uint8Array(MAC_BYTES);
      this.emptyWriteKey = new Uint8Array(KEY_BYTES);
      this.resetClientInstances();
      this.resetTokenEntries();
      this.resetCryptoEntries();
    }

    public set Timeout(value: number) {
      this.timeout = value;
    }

    public findFreeClientIndex(): number {
      for (let i = 0; i < this.maxClients; i += 1) {
        if (!this.instances[i].connected) {
          return i;
        }
      }
      return -1;
    }

    // Returns the clientIds of the connected clients. To avoid allocating a buffer everytime this is called
    // we simply re-add all connected clients to the connectedClientIds buffer and return the slice of how
    // many we were able to add.
    public getConnectedClients(): Long[] {
      const connectedClientIds = [];
      for (
        let clientIndex = 0;
        clientIndex < this.maxClients;
        clientIndex += 1
      ) {
        const client = this.instances[clientIndex];
        if (client.connected && client.address) {
          connectedClientIds.push(client.clientId);
        }
      }
      return connectedClientIds;
    }

    public getConnectedClientCount(): number {
      return this.getConnectedClients().length;
    }

    // Initializes the client with the clientId
    public connectClient(
      addr: IUDPAddr,
      challengeToken: ChallengeToken
    ): ClientInstance {
      const clientIndex = this.findFreeClientIndex();
      if (clientIndex == -1) {
        console.warn('failure to find free client index');
        return null;
      }
      const client = this.instances[clientIndex];
      client.clientIndex = clientIndex;
      client.connected = true;
      client.sequence.setZero();
      client.clientId = challengeToken.clientID;
      client.address = addr;
      client.userData.set(challengeToken.userData);
      if (this.clientConnectHandler) {
        this.clientConnectHandler(client);
      }
      return client;
    }

    // Disconnects the client referenced by the provided clientIndex.
    public disconnectClientByIndex(
      clientIndex: number,
      sendDisconnect: boolean,
      serverTime: number
    ) {
      const instance = this.instances[clientIndex];
      this.disconnectClient(instance, sendDisconnect, serverTime);
    }

    // Finds the client index referenced by the provided UDPAddr.
    public findClientIndexByAddress(addr: IUDPAddr): number {
      for (let i = 0; i < this.maxClients; i += 1) {
        const instance = this.instances[i];
        if (
          instance.address &&
          instance.connected &&
          Utils.addressEqual(instance.address, addr)
        ) {
          return i;
        }
      }
      return -1;
    }

    // Finds the client index via the provided clientId.
    public findClientIndexById(clientId: Long): number {
      for (let i = 0; i < this.maxClients; i += 1) {
        const instance = this.instances[i];
        if (
          instance.address &&
          instance.connected &&
          instance.clientId.equals(clientId)
        ) {
          return i;
        }
      }
      return -1;
    }

    // Finds the encryption index via the provided clientIndex, returns -1 if not found.
    public findEncryptionIndexByClientIndex(clientIndex: number): number {
      if (clientIndex < 0 || clientIndex > this.maxClients) {
        return -1;
      }

      return this.instances[clientIndex].encryptionIndex;
    }

    // Finds an encryption entry index via the provided UDPAddr.
    public findEncryptionEntryIndex(
      addr: IUDPAddr,
      serverTime: number
    ): number {
      for (let i = 0; i < this.numCryptoEntries; i += 1) {
        const entry = this.cryptoEntries[i];
        if (!entry || !entry.address) {
          continue;
        }

        const lastAccessTimeout = entry.lastAccess + this.timeout;
        if (
          Utils.addressEqual(entry.address, addr) &&
          this.serverTimedout(lastAccessTimeout, serverTime) &&
          (entry.expireTime < 0 || entry.expireTime >= serverTime)
        ) {
          entry.lastAccess = serverTime;
          return i;
        }
      }
      return -1;
    }

    // Finds or adds a token entry to our token entry slice.
    public findOrAddTokenEntry(
      connectTokenMac: Uint8Array,
      addr: IUDPAddr,
      serverTime: number
    ): boolean {
      let oldestTime: number;

      let tokenIndex = -1;
      let oldestIndex = -1;

      if (Utils.arrayEqual(connectTokenMac, this.emptyMac)) {
        return false;
      }

      // find the matching entry for the token mac and the oldest token entry.
      for (let i = 0; i < this.maxEntries; i += 1) {
        if (
          Utils.arrayEqual(this.connectTokensEntries[i].mac, connectTokenMac)
        ) {
          tokenIndex = i;
        }

        if (
          oldestIndex == -1 ||
          this.connectTokensEntries[i].time < oldestTime
        ) {
          oldestTime = this.connectTokensEntries[i].time;
          oldestIndex = i;
        }
      }

      // if no entry is found with the mac, this is a new connect token. replace the oldest token entry.
      if (tokenIndex == -1) {
        this.connectTokensEntries[oldestIndex].time = serverTime;
        this.connectTokensEntries[oldestIndex].address = addr;
        this.connectTokensEntries[oldestIndex].mac = connectTokenMac;
        console.log('new connect token added for %s', addr);
        return true;
      }

      // allow connect tokens we have already seen from the same address
      if (
        Utils.addressEqual(this.connectTokensEntries[tokenIndex].address, addr)
      ) {
        return true;
      }

      return false;
    }

    // Adds a new encryption mapping of client/server keys.
    public addEncryptionMapping(
      connectToken: ConnectTokenPrivate,
      addr: IUDPAddr,
      serverTime: number,
      expireTime: number
    ): boolean {
      // already list
      for (let i = 0; i < this.maxEntries; i += 1) {
        const entry = this.cryptoEntries[i];

        const lastAccessTimeout = entry.lastAccess + this.timeout;
        if (
          entry.address &&
          Utils.addressEqual(entry.address, addr) &&
          this.serverTimedout(lastAccessTimeout, serverTime)
        ) {
          entry.expireTime = expireTime;
          entry.lastAccess = serverTime;
          entry.sendKey.set(connectToken.sharedTokenData.serverKey);
          entry.recvKey.set(connectToken.sharedTokenData.clientKey);
          console.log('re-added encryption mapping for %s encIdx: %d', addr, i);
          return true;
        }
      }

      // not in our list.
      for (let i = 0; i < this.maxEntries; i += 1) {
        const entry = this.cryptoEntries[i];
        if (
          entry.lastAccess + this.timeout < serverTime ||
          (entry.expireTime >= 0 && entry.expireTime < serverTime)
        ) {
          entry.address = addr;
          entry.expireTime = expireTime;
          entry.lastAccess = serverTime;
          entry.sendKey.set(connectToken.sharedTokenData.serverKey);
          entry.recvKey.set(connectToken.sharedTokenData.clientKey);
          if (i + 1 > this.numCryptoEntries) {
            this.numCryptoEntries = i + 1;
          }
          return true;
        }
      }

      return false;
    }

    // Update the encryption entry for the  provided encryption index.
    public touchEncryptionEntry(
      encryptionIndex: number,
      addr: IUDPAddr,
      serverTime: number
    ): boolean {
      if (encryptionIndex < 0 || encryptionIndex > this.numCryptoEntries) {
        return false;
      }

      if (
        !Utils.addressEqual(this.cryptoEntries[encryptionIndex].address, addr)
      ) {
        return false;
      }

      this.cryptoEntries[encryptionIndex].lastAccess = serverTime;
      return true;
    }

    // Sets the expiration for this encryption entry.
    public setEncryptionEntryExpiration(
      encryptionIndex: number,
      expireTime: number
    ): boolean {
      if (encryptionIndex < 0 || encryptionIndex > this.numCryptoEntries) {
        return false;
      }
      this.cryptoEntries[encryptionIndex].expireTime = expireTime;
      return true;
    }

    // Removes the encryption entry for this UDPAddr.
    private removeEncryptionEntry(addr: IUDPAddr, serverTime: number): boolean {
      for (let i = 0; i < this.numCryptoEntries; i += 1) {
        const entry = this.cryptoEntries[i];
        if (!Utils.addressEqual(entry.address, addr)) {
          continue;
        }

        this.clearCryptoEntry(entry);

        if (i + 1 == this.numCryptoEntries) {
          let index = i - 1;
          while (index >= 0) {
            const lastAccessTimeout =
              this.cryptoEntries[index].lastAccess + this.timeout;
            if (
              this.serverTimedout(lastAccessTimeout, serverTime) &&
              (this.cryptoEntries[index].expireTime < 0 ||
                this.cryptoEntries[index].expireTime > serverTime)
            ) {
              break;
            }
            index--;
          }
          this.numCryptoEntries = index + 1;
        }

        return true;
      }

      return false;
    }

    private disconnectClient(
      client: ClientInstance,
      sendDisconnect: boolean,
      serverTime: number
    ) {
      if (!client.connected) {
        return;
      }

      if (sendDisconnect) {
        const packet = new DisconnectPacket();
        const writePacketKey = this.getEncryptionEntrySendKey(
          client.encryptionIndex
        );
        if (!writePacketKey) {
          console.error(
            'error: unable to retrieve encryption key for client for disconnect: %d\n',
            client.clientId
          );
        } else {
          for (let i = 0; i < NUM_DISCONNECT_PACKETS; i += 1) {
            client.sendPacket(packet, writePacketKey, serverTime);
          }
        }
      }
      console.log('removing encryption entry for: %s', client.address);
      this.removeEncryptionEntry(client.address, serverTime);
      if (this.clientDisconnectHandler) {
        this.clientDisconnectHandler(client);
      }
      client.clear();
    }

    private resetClientInstances() {
      this.instances = [];
      for (let i = 0; i < this.maxClients; i += 1) {
        const instance = new ClientInstance();
        this.instances[i] = instance;
      }
    }

    // preallocate the token buffers so we don't have to do nil checks
    private resetTokenEntries() {
      this.connectTokensEntries = [];
      for (let i = 0; i < this.maxEntries; i += 1) {
        const entry: any = {};
        this.clearTokenEntry(entry);
        this.connectTokensEntries[i] = entry;
      }
    }

    private clearTokenEntry(entry: IConnectTokenEntry) {
      entry.mac = new Uint8Array(MAC_BYTES);
      entry.address = null;
      entry.time = -1;
    }

    // preallocate the crypto entries so we don't have to do nil checks
    private resetCryptoEntries() {
      this.cryptoEntries = [];
      for (let i = 0; i < this.maxEntries; i += 1) {
        const entry: any = {};
        this.clearCryptoEntry(entry);
        this.cryptoEntries[i] = entry;
      }
    }

    private clearCryptoEntry(entry: IEncryptionEntry) {
      entry.expireTime = -1;
      entry.lastAccess = -1000;
      entry.address = null;
      entry.sendKey = new Uint8Array(KEY_BYTES);
      entry.recvKey = new Uint8Array(KEY_BYTES);
    }

    // Returns the encryption send key.
    private getEncryptionEntrySendKey(index: number): Uint8Array {
      return this.getEncryptionEntryKey(index, true);
    }

    // Returns the encryption recv key.
    private getEncryptionEntryRecvKey(index: number): Uint8Array {
      return this.getEncryptionEntryKey(index, false);
    }

    private getEncryptionEntryKey(index: number, sendKey: boolean): Uint8Array {
      if (index === -1 || index < 0 || index > this.numCryptoEntries) {
        return null;
      }

      if (sendKey) {
        return this.cryptoEntries[index].sendKey;
      }

      return this.cryptoEntries[index].recvKey;
    }

    // checks if last access + timeout is > or = to serverTime.
    private serverTimedout(
      lastAccessTimeout: number,
      serverTime: number
    ): boolean {
      return (
        lastAccessTimeout > serverTime ||
        Utils.floatEquals(lastAccessTimeout, serverTime)
      );
    }

    public sendPayloads(payloadData: Uint8Array, serverTime: number) {
      for (let i = 0; i < this.maxClients; i += 1) {
        this.sendPayloadToInstance(i, payloadData, serverTime);
      }
    }

    public sendPayloadToInstance(
      index: number,
      payloadData: Uint8Array,
      serverTime: number
    ) {
      const instance = this.instances[index];
      if (instance.encryptionIndex === -1) {
        return;
      }

      const writePacketKey = this.getEncryptionEntrySendKey(
        instance.encryptionIndex
      );
      if (
        Utils.arrayEqual(writePacketKey, this.emptyWriteKey) ||
        !instance.address
      ) {
        return;
      }

      if (!instance.confirmed) {
        const packet = new KeepAlivePacket();
        packet.setProperties(instance.clientIndex, this.maxClients);
        instance.sendPacket(packet, writePacketKey, serverTime);
      }

      if (instance.connected) {
        if (
          !this.touchEncryptionEntry(
            instance.encryptionIndex,
            instance.address,
            serverTime
          )
        ) {
          console.error(
            'error: encryption mapping is out of date for client %d',
            instance.clientIndex
          );
          return;
        }
        const packet = new PayloadPacket(payloadData);
        instance.sendPacket(packet, writePacketKey, serverTime);
      }
    }

    // Send keep alives to all connected clients.
    public sendKeepAlives(serverTime: number) {
      for (let i = 0; i < this.maxClients; i += 1) {
        const instance = this.instances[i];
        if (!instance.connected) {
          continue;
        }

        const writePacketKey = this.getEncryptionEntrySendKey(
          instance.encryptionIndex
        );
        if (
          Utils.arrayEqual(writePacketKey, this.emptyWriteKey) ||
          !instance.address
        ) {
          continue;
        }

        const shouldSendTime = instance.lastSendTime + 1.0 / PACKET_SEND_RATE;
        if (
          shouldSendTime < serverTime ||
          Utils.floatEquals(shouldSendTime, serverTime)
        ) {
          if (
            !this.touchEncryptionEntry(
              instance.encryptionIndex,
              instance.address,
              serverTime
            )
          ) {
            console.error(
              'error: encryption mapping is out of date for client %d',
              instance.clientIndex
            );
            continue;
          }

          const packet = new KeepAlivePacket();
          packet.setProperties(instance.clientIndex, this.maxClients);
          instance.sendPacket(packet, writePacketKey, serverTime);
        }
      }
    }

    // Checks and disconnects any clients that have timed out.
    public checkTimeouts(serverTime: number) {
      for (let i = 0; i < this.maxClients; i += 1) {
        const instance = this.instances[i];
        const timeout = instance.lastRecvTime + this.timeout;

        if (
          instance.connected &&
          (timeout < serverTime || Utils.floatEquals(timeout, serverTime))
        ) {
          console.log('server timed out client: %d', i);
          this.disconnectClient(instance, false, serverTime);
        }
      }
    }

    public disconnectClients(serverTime: number) {
      for (
        let clientIndex = 0;
        clientIndex < this.maxClients;
        clientIndex += 1
      ) {
        const instance = this.instances[clientIndex];
        this.disconnectClient(instance, true, serverTime);
      }
    }

    maxClients: number;
    maxEntries: number;
    timeout: number;

    instances: ClientInstance[];
    connectTokensEntries: IConnectTokenEntry[];
    cryptoEntries: IEncryptionEntry[];
    numCryptoEntries: number;

    emptyMac: Uint8Array; // used to ensure empty mac (all empty bytes) doesn't match
    emptyWriteKey: Uint8Array; // used to test for empty write key

    clientConnectHandler: ClientConnectionHandler;
    clientDisconnectHandler: ClientConnectionHandler;
  }
}
