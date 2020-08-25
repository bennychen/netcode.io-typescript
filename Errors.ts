export enum Errors {
  none,
  EOF,

  invalidPacket,
  packetTypeNotAllowed,
  badPacketLength,

  emptyServer,
  tooManyServers,
  unknownIPAddressType,
  invalidPort,

  noPrivateKey,
  badVersionInfo,
  badProtocolID,
  connectTokenExpired,
  badCreateTimestamp,
  badExpireTimestamp,
  packetInvalidLength,
  decryptPrivateTokenData,
  badSequence,
  badPrivateData,
  badUserData,

  invalidHandler,
  readUDPError,
  socketZeroRecv,
  overMaxReadSize,
}
