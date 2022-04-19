namespace Netcode {
  export const TIMEOUT_SECONDS = 5; // default timeout for clients
  export const MAX_SERVER_PACKETS = 64;

  export class Server {
    public set timeout(durationSeconds: number) {
      this._timeout = durationSeconds;
      this.clientManager.timeout = this._timeout;
    }

    public constructor(
      serverAddress: IUDPAddr,
      privateKey: Uint8Array,
      protocolId: Long,
      maxClients: number
    ) {
      this.serverAddr = serverAddress;
      this.protocolId = protocolId;
      this.privateKey = privateKey;
      this.maxClients = maxClients;

      this.globalSequence = new Long(1 << 31, 0);
      this._timeout = TIMEOUT_SECONDS;
      this.clientManager = new ClientManager(this.timeout, maxClients);

      // set allowed packets for this server
      this.allowedPackets = new Uint8Array(PacketType.numPackets);
      this.allowedPackets[PacketType.connectionRequest] = 1;
      this.allowedPackets[PacketType.connectionResponse] = 1;
      this.allowedPackets[PacketType.connectionKeepAlive] = 1;
      this.allowedPackets[PacketType.connectionPayload] = 1;
      this.allowedPackets[PacketType.connectionDisconnect] = 1;

      this.challengeKey = Utils.generateKey();
      this.serverConn = new NetcodeConn();
      this.serverConn.setReadBuffer(SOCKET_RCVBUF_SIZE * this.maxClients);
      this.serverConn.setWriteBuffer(SOCKET_SNDBUF_SIZE * this.maxClients);
      this.serverConn.setRecvHandler(this.handleNetcodeData);

      this._tempBuffer = new Uint8Array(MAX_PACKET_BYTES);
    }

    public setClientConnectHandler(handler: ClientConnectionHandler) {
      this.clientManager.clientConnectHandler = handler;
    }

    public setClientDisconnectHandler(handler: ClientConnectionHandler) {
      this.clientManager.clientDisconnectHandler = handler;
    }

    public setAllowedPackets(allowedPackets: Uint8Array) {
      this.allowedPackets = allowedPackets;
    }

    public setIgnoreRequests(val: boolean) {
      this.ignoreRequests = val;
    }

    public setIgnoreResponses(val: boolean) {
      this.ignoreResponses = val;
    }

    // increments the challenge sequence and returns the un-incremented value
    public incChallengeSequence(): Long {
      const original = this.challengeSequence.clone();
      this.challengeSequence.plusOne();
      return original;
    }

    public incGlobalSequence(): Long {
      const original = this.globalSequence.clone();
      this.globalSequence.plusOne();
      return original;
    }

    public getConnectedClientIds(): Long[] {
      return this.clientManager.getConnectedClients();
    }

    public getMaxClients(): number {
      return this.maxClients;
    }

    public getConnectedClientCount(): number {
      return this.clientManager.getConnectedClientCount();
    }

    public getClientUserData(clientId: Long): Uint8Array {
      const i = this.getClientIndexByClientId(clientId);
      if (i > -1) {
        return this.clientManager.instances[i].userData;
      }
    }

    public listen(createUdpConn: UDPConnCreator) {
      this.running = true;
      this.serverConn.listen(createUdpConn, this.serverAddr);
    }

    public sendPayloads(payloadData: Uint8Array) {
      if (!this.running) {
        return;
      }
      this.clientManager.sendPayloads(payloadData, this.serverTime);
    }

    // Sends the payload to the client specified by their clientId.
    public sendPayloadToClient(clientId: Long, payloadData: Uint8Array) {
      const clientIndex = this.getClientIndexByClientId(clientId);
      if (clientIndex !== -1) {
        this.clientManager.sendPayloadToInstance(
          clientIndex,
          payloadData,
          this.serverTime
        );
      }
    }

    public getClientIndexByClientId(clientId: Long): number {
      if (!this.running) {
        return -1;
      }
      return this.clientManager.findClientIndexById(clientId);
    }

    public update(time: number) {
      if (!this.running) {
        return;
      }

      this.serverTime = time;

      for (const p of this.packets) {
        this.onPacketData(p.data, p.from);
      }
      this.clientManager.sendKeepAlives(this.serverTime);
      this.clientManager.checkTimeouts(this.serverTime);
    }

    public stop() {
      if (!this.running) {
        return;
      }
      this.clientManager.disconnectClients(this.serverTime);
      this.running = false;
      this.maxClients = 0;
      this.globalSequence.setZero();
      this.challengeSequence.setZero();
      this.challengeKey.fill(0);
      this.clientManager.resetCryptoEntries();
      this.clientManager.resetTokenEntries();
      this.running = false;
      this.serverConn.close();
    }

    public recvPayload(clientIndex: number): {
      data: Uint8Array;
      sequance: Long;
    } {
      const packet =
        this.clientManager.instances[clientIndex].packetQueue.pop();
      if (!packet) {
        return null;
      }
      const p = packet as PayloadPacket;
      if (p.getType() === PacketType.connectionPayload) {
        return { data: p.payloadData, sequance: p.getSequence() };
      } else {
        return null;
      }
    }

    // write the netcodeData to our buffered packet channel. The NetcodeConn verifies
    // that the recv'd data is > 0 < maxBytes and is of a valid packet type before
    // this is even called.
    // NOTE: we will block the netcodeConn from processing which is what we want since
    // we want to synchronize access from the Update call.
    private handleNetcodeData(packetData: INetcodeData) {
      this.packets.push(packetData);
    }

    private onPacketData(packetData: Uint8Array, addr: IUDPAddr) {
      let replayProtection: ReplayProtection;

      if (!this.running) {
        return;
      }

      const size = packetData.length;

      let encryptionIndex = -1;
      const clientIndex = this.clientManager.findClientIndexByAddress(addr);
      if (clientIndex != -1) {
        encryptionIndex =
          this.clientManager.findEncryptionIndexByClientIndex(clientIndex);
      } else {
        encryptionIndex = this.clientManager.findEncryptionEntryIndex(
          addr,
          this.serverTime
        );
      }
      const readPacketKey =
        this.clientManager.getEncryptionEntryRecvKey(encryptionIndex);

      const timestamp = Date.now();

      const packet = PacketFactory.create(packetData);
      if (clientIndex !== -1) {
        const client = this.clientManager.instances[clientIndex];
        replayProtection = client.replayProtection;
      }

      const err = packet.read(packetData, size, {
        protocolId: this.protocolId,
        currentTimestamp: timestamp,
        readPacketKey,
        privateKey: this.privateKey,
        allowedPackets: this.allowedPackets,
        replayProtection,
      });
      if (err !== Errors.none) {
        console.error('error reading packet: %s from %s', err, addr);
        return;
      }

      this.processPacket(clientIndex, encryptionIndex, packet, addr);
    }

    private processPacket(
      clientIndex: number,
      encryptionIndex: number,
      packet: IPacket,
      addr: IUDPAddr
    ) {
      switch (packet.getType()) {
        case PacketType.connectionRequest:
          {
            if (this.ignoreRequests) {
              return;
            }
            console.log('server received connection request from %s', addr);
            this.processConnectionRequest(packet as RequestPacket, addr);
          }
          break;
        case PacketType.connectionResponse: {
          if (this.ignoreResponses) {
            return;
          }
          console.log('server received connection response from %s', addr);
          this.processConnectionResponse(
            clientIndex,
            encryptionIndex,
            packet as ResponsePacket,
            addr
          );
          break;
        }
        case PacketType.connectionKeepAlive:
          {
            if (clientIndex == -1) {
              return;
            }
            const client = this.clientManager.instances[clientIndex];
            client.lastRecvTime = this.serverTime;

            if (!client.confirmed) {
              client.confirmed = true;
              console.log(
                'server confirmed connection to client %d',
                client.clientId
              );
            }
          }
          break;
        case PacketType.connectionPayload:
          {
            if (clientIndex == -1) {
              return;
            }
            const client = this.clientManager.instances[clientIndex];
            client.lastRecvTime = this.serverTime;

            if (!client.confirmed) {
              client.confirmed = true;
              console.log(
                'server confirmed connection to client %d',
                client.clientId
              );
            }

            client.packetQueue.push(packet);
          }
          break;
        case PacketType.connectionDisconnect:
          {
            if (clientIndex == -1) {
              return;
            }
            const client = this.clientManager.instances[clientIndex];
            console.log(
              'server received disconnect packet from client %d',
              client.clientId
            );
            this.clientManager.disconnectClient(client, false, this.serverTime);
          }
          break;
      }
    }

    private processConnectionRequest(packet: RequestPacket, addr: IUDPAddr) {
      if (packet.token.sharedTokenData.serverAddrs.length === 0) {
        console.log(
          'server ignored connection request.' +
            'server address not in connect token whitelist'
        );
        return;
      }

      let addrFound = false;
      for (const tokenAddr of packet.token.sharedTokenData.serverAddrs) {
        if (Utils.addressEqual(this.serverAddr, tokenAddr)) {
          addrFound = true;
          break;
        }
      }

      if (!addrFound) {
        console.log(
          'server ignored connection request. server address not in connect token whitelist'
        );
        return;
      }

      let clientIndex = this.clientManager.findClientIndexByAddress(addr);
      if (clientIndex !== -1) {
        console.log(
          'server ignored connection request. a client with this address is already connected'
        );
        return;
      }

      clientIndex = this.clientManager.findClientIndexById(
        packet.token.clientId
      );
      if (clientIndex !== -1) {
        console.log(
          'server ignored connection request. a client with this id has already been used'
        );
        return;
      }

      if (
        !this.clientManager.findOrAddTokenEntry(
          packet.token.mac,
          addr,
          this.serverTime
        )
      ) {
        console.log(
          'server ignored connection request. connect token has already been used'
        );
        return;
      }

      if (this.clientManager.getConnectedClientCount() === this.maxClients) {
        console.log('server denied connection request. server is full');
        this.sendDeniedPacket(packet.token.sharedTokenData.serverKey, addr);
        return;
      }

      if (
        !this.clientManager.addEncryptionMapping(
          packet.token,
          addr,
          this.serverTime,
          this.serverTime + this.timeout
        )
      ) {
        console.log(
          'server ignored connection request. failed to add encryption mapping'
        );
        return;
      }

      this.sendChallengePacket(packet, addr);
    }

    private sendChallengePacket(requestPacket: RequestPacket, addr: IUDPAddr) {
      const challenge = new ChallengeToken(requestPacket.token.clientId);
      const challengeBuf = challenge.write(requestPacket.token.userData);
      const challengeSequence = this.incChallengeSequence();

      ChallengeToken.encrypt(
        challengeBuf,
        challengeSequence,
        this.challengeKey
      );
      const challengePacket = new ChallengePacket();
      challengePacket.setProperties(challengeSequence, challengeBuf);

      const buffer = this._tempBuffer;
      const bytesWritten = challengePacket.write(
        buffer,
        this.protocolId,
        this.incGlobalSequence(),
        requestPacket.token.sharedTokenData.serverKey
      );
      if (bytesWritten <= 0) {
        console.log('server error while writing challenge packet');
        return;
      }
      this.sendGlobalPacket(buffer.subarray(0, bytesWritten), addr);
    }

    public sendGlobalPacket(packetBuffer: Uint8Array, addr: IUDPAddr) {
      this.serverConn.writeTo(packetBuffer, addr);
    }

    private sendDeniedPacket(sendKey: Uint8Array, addr: IUDPAddr) {
      const deniedPacket = new DeniedPacket();
      const packetBuffer = this._tempBuffer;
      const bytesWritten = deniedPacket.write(
        packetBuffer,
        this.protocolId,
        this.incGlobalSequence(),
        sendKey
      );
      if (bytesWritten <= 0) {
        console.log('error creating denied packet');
        return;
      }
      this.sendGlobalPacket(packetBuffer.subarray(0, bytesWritten), addr);
    }

    private processConnectionResponse(
      clientIndex: number,
      encryptionIndex: number,
      packet: ResponsePacket,
      addr: IUDPAddr
    ) {
      const tokenBuffer = ChallengeToken.decrypt(
        packet.tokenData,
        packet.challengeTokenSequence,
        this.challengeKey
      );
      if (!tokenBuffer) {
        console.log('failed to decrypt challenge token: %s');
        return;
      }
      const challengeToken = new ChallengeToken();
      const err = challengeToken.read(tokenBuffer);
      if (err !== Errors.none) {
        console.log('failed to read challenge token: %s', Errors[err]);
        return;
      }
      const sendKey =
        this.clientManager.getEncryptionEntrySendKey(encryptionIndex);
      if (!sendKey) {
        console.log('server ignored connection response. no packet send key');
        return;
      }
      if (this.clientManager.findClientIndexByAddress(addr) !== -1) {
        console.log(
          'server ignored connection response. a client with this address is already connected'
        );
        return;
      }
      if (
        this.clientManager.findClientIndexById(challengeToken.clientID) !== -1
      ) {
        console.log(
          'server ignored connection response. a client with this id is already connected'
        );
        return;
      }
      if (this.clientManager.getConnectedClientCount() === this.maxClients) {
        console.log('server denied connection response. server is full');
        this.sendDeniedPacket(sendKey, addr);
        return;
      }
      this.connectClient(encryptionIndex, challengeToken, addr);
    }

    private connectClient(
      encryptionIndex: number,
      challengeToken: ChallengeToken,
      addr: IUDPAddr
    ) {
      if (this.clientManager.getConnectedClientCount() > this.maxClients) {
        console.warn('maxium number of clients reached');
        return;
      }
      this.clientManager.setEncryptionEntryExpiration(encryptionIndex, -1);
      const client = this.clientManager.connectClient(addr, challengeToken);
      if (!client) {
        return;
      }
      client.serverConn = this.serverConn;
      client.encryptionIndex = encryptionIndex;
      client.protocolId = this.protocolId;
      client.lastSendTime = this.serverTime;
      client.lastRecvTime = this.serverTime;
      console.log(
        'server accepted client %d from %s in slot: %d',
        client.clientId,
        addr,
        client.clientIndex
      );
      this.sendKeepAlive(client);
    }

    private sendKeepAlive(client: ClientInstance) {
      const clientIndex = client.clientIndex;
      const packet = new KeepAlivePacket();
      packet.setProperties(clientIndex, this.maxClients);
      if (
        !this.clientManager.touchEncryptionEntry(
          client.encryptionIndex,
          client.address,
          this.serverTime
        )
      ) {
        console.warn(
          'error: encryption mapping is out of date for client %d encIndex: %d addr: %s',
          clientIndex,
          client.encryptionIndex,
          client.address
        );
        return;
      }
      const writePacketKey = this.clientManager.getEncryptionEntrySendKey(
        client.encryptionIndex
      );
      if (!writePacketKey) {
        console.error(
          'error: unable to retrieve encryption key for client: %d',
          clientIndex
        );
        return;
      }
      client.sendPacket(packet, writePacketKey, this.serverTime);
    }

    private serverConn: NetcodeConn;
    private serverAddr: IUDPAddr;

    private serverTime: number;
    private running: boolean;
    private maxClients: number;
    private connectedClients: number;
    private _timeout: number;

    private clientManager: ClientManager;
    private globalSequence: Long;

    private ignoreRequests: boolean;
    private ignoreResponses: boolean;
    private allowedPackets: Uint8Array;
    private protocolId: Long;

    private privateKey: Uint8Array;
    private challengeKey: Uint8Array;

    private challengeSequence: Long;
    private recvByte: number;

    private packets: INetcodeData[] = [];
    private _tempBuffer: Uint8Array;
  }
}
