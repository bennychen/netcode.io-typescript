namespace Netcode {
  export enum Errors {
    none,
    EOF,

    invalidPacket,
    packetTypeNotAllowed,
    badPacketLength,
    packetAlreadyReceived,

    emptyServer,
    tooManyServers,
    unknownIPAddressType,
    invalidPort,

    noPrivateKey,
    emptyPacketKey,
    badVersionInfo,
    badProtocolID,
    invalidClientID,
    connectTokenExpired,
    badCreateTimestamp,
    badExpireTimestamp,
    packetInvalidLength,
    decryptPrivateTokenData,
    readPrivateTokenData,
    badSequence,
    badPrivateData,
    badUserData,

    invalidHandler,
    readUDPError,
    socketZeroRecv,
    overMaxReadSize,
    exceededServerNumber,
    dialServer,
    errDecryptData,

    invalidDenyPacketDataSize,
    invalidChallengePacketDataSize,
    invalidChallengeTokenSequence,
    invalidChallengeTokenData,
    invalidResponseTokenData,
    invalidResponseTokenSequence,
    invalidResponsePacketDataSize,
    invalidDisconnectPacketDataSize,
    invalidKeepAliveClientIndex,
    invalidKeepAliveMaxClients,
    payloadPacketTooSmall,
    payloadPacketTooLarge,
  }
}