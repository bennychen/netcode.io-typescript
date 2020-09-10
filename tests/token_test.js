var { Netcode } = require('../dist/node/Netcode');
var assert = require('assert');

var TEST_PROTOCOL_ID = Netcode.Long.fromNumber(0x1122334455667788);
var TEST_CONNECT_TOKEN_EXPIRY = 30;
var TEST_SERVER_PORT = 40000;
var TEST_CLIENT_ID = Netcode.Long.fromNumber(0x1);
var TEST_SEQUENCE_START = Netcode.Long.fromNumber(1000);
var TEST_TIMEOUT_SECONDS = 15;
var TEST_PRIVATE_KEY = new Uint8Array([
  0x60,
  0x6a,
  0xbe,
  0x6e,
  0xc9,
  0x19,
  0x10,
  0xea,
  0x9a,
  0x65,
  0x62,
  0xf6,
  0x6f,
  0x2b,
  0x30,
  0xe4,
  0x43,
  0x71,
  0xd6,
  0x2c,
  0xd1,
  0x99,
  0x27,
  0x26,
  0x6b,
  0x3c,
  0x60,
  0xf4,
  0xb7,
  0x15,
  0xab,
  0xa1,
]);

function assertBytesEqual(a1, a2, str) {
  assert.equal(Netcode.Utils.arrayEqual(a1, a2), true, str);
}

function ipStringToBytes(ip) {
  var addr = Netcode.Utils.stringToIPV4Address(ip);
  return addr.ip;
}

describe('ConnectToken tests', function () {
  it('read/write shared connect token', function () {
    var clientKey = Netcode.Utils.generateKey();
    assert.equal(clientKey.length, Netcode.KEY_BYTES, 'oh no');
    var serverKey = Netcode.Utils.generateKey();
    assert.equal(serverKey.length, Netcode.KEY_BYTES, 'oh no');

    var addr = {
      ip: ipStringToBytes('10.20.30.40'),
      port: TEST_SERVER_PORT,
    };
    var data = new Netcode.SharedTokenData();
    data.timeoutSeconds = 10;
    data.serverAddrs = [addr];
    data.clientKey = clientKey;
    data.serverKey = serverKey;

    var buffer = new Netcode.ByteBuffer(
      new Uint8Array(Netcode.CONNECT_TOKEN_BYTES)
    );
    data.write(buffer);
    buffer.clearPosition();

    var outData = new Netcode.SharedTokenData();
    var ret = outData.read(buffer);
    assert.equal(ret, Netcode.Errors.none, 'oh no');
    assertBytesEqual(clientKey, outData.clientKey, 'oh no');
    assertBytesEqual(serverKey, outData.serverKey, 'oh no');
    assert.equal(data.timeoutSeconds, outData.timeoutSeconds, 'oh no');
    assert.equal(outData.serverAddrs.length, 1, 'oh no');
    assertBytesEqual(outData.serverAddrs[0].ip, addr.ip, 'oh no');
    assert.equal(outData.serverAddrs[0].port, addr.port, 'oh no');
  });

  it('read/write private connect token', function () {
    var addr = {
      ip: ipStringToBytes('10.20.30.40'),
      port: TEST_SERVER_PORT,
    };
    var ts = Date.now();
    var expireTs = ts + TEST_CONNECT_TOKEN_EXPIRY;
    var timeoutSeconds = 10;
    var userData = Netcode.Utils.getRandomBytes(Netcode.USER_DATA_BYTES);

    var token1 = Netcode.ConnectTokenPrivate.create(
      TEST_CLIENT_ID,
      timeoutSeconds,
      [addr],
      userData
    );
    token1.generate();
    token1.write();
    var ret = token1.encrypt(
      TEST_PROTOCOL_ID,
      expireTs,
      TEST_SEQUENCE_START,
      TEST_PRIVATE_KEY
    );
    assert.equal(ret, true, 'oh no');

    var encryptedToken = new Uint8Array(token1.buffer);
    var token2 = Netcode.ConnectTokenPrivate.createEncrypted(encryptedToken);
    const decrypted = token2.decrypt(
      TEST_PROTOCOL_ID,
      expireTs,
      TEST_SEQUENCE_START,
      TEST_PRIVATE_KEY
    );
    assert.equal(decrypted !== undefined, true, 'decrypt failed');
    ret = token2.read();
    assert.equal(ret, Netcode.Errors.none, 'oh no');

    // compare tokens
    assert.equal(token1.clientId.equals(token2.clientId), true, 'oh no');
    assert.equal(
      token1.sharedTokenData.serverAddrs.length,
      token2.sharedTokenData.serverAddrs.length,
      'oh no'
    );
    assertBytesEqual(
      token1.sharedTokenData.serverAddrs[0].ip,
      token2.sharedTokenData.serverAddrs[0].ip,
      'oh no'
    );
    assert.equal(
      token1.sharedTokenData.serverAddrs[0].port,
      token2.sharedTokenData.serverAddrs[0].port,
      'oh no'
    );
    assertBytesEqual(
      token1.sharedTokenData.clientKey,
      token2.sharedTokenData.clientKey,
      'oh no'
    );
    assertBytesEqual(
      token1.sharedTokenData.serverKey,
      token2.sharedTokenData.serverKey,
      'oh no'
    );

    const buffer = new Uint8Array(Netcode.CONNECT_TOKEN_PRIVATE_BYTES);
    Netcode.Utils.blockCopy(token2.buffer, 0, buffer, 0, token2.buffer.length);
    token2.tokenData = new Netcode.ByteBuffer(buffer);
    token2.write();
    var ret = token2.encrypt(
      TEST_PROTOCOL_ID,
      expireTs,
      TEST_SEQUENCE_START,
      TEST_PRIVATE_KEY
    );
    assert.equal(ret, true, 'oh no');
    assert.equal(token1.buffer.length, token2.buffer.length, 'oh no');
    assertBytesEqual(token1.buffer, token2.buffer, 'oh no');
  });

  it('read/write connect token', function () {
    var addr = {
      ip: ipStringToBytes('10.20.30.40'),
      port: TEST_SERVER_PORT,
    };
    var key = Netcode.Utils.generateKey();
    var userData = Netcode.Utils.getRandomBytes(Netcode.USER_DATA_BYTES);
    var inToken = new Netcode.ConnectToken();
    var ret = inToken.generate(
      TEST_CLIENT_ID,
      [addr],
      TEST_PROTOCOL_ID,
      TEST_CONNECT_TOKEN_EXPIRY,
      TEST_TIMEOUT_SECONDS,
      TEST_SEQUENCE_START,
      userData,
      key
    );
    assertBytesEqual(
      inToken.versionInfo,
      Netcode.VERSION_INFO_BYTES_ARRAY,
      'oh no'
    );
    assert.equal(ret, true, 'oh no');
    var tokenBuffer = inToken.write();
    assert.equal(tokenBuffer !== undefined, true, 'oh no');

    var outToken = new Netcode.ConnectToken();
    var readRet = outToken.read(tokenBuffer);
    assert.equal(readRet, Netcode.Errors.none, 'oh no');
    assertBytesEqual(
      outToken.versionInfo,
      Netcode.VERSION_INFO_BYTES_ARRAY,
      'oh no'
    );
    assert.equal(outToken.protocolID.equals(TEST_PROTOCOL_ID), true, 'oh no');
    assert.equal(
      outToken.createTimestamp.equals(inToken.createTimestamp),
      true,
      'oh no'
    );
    assert.equal(
      outToken.expireTimestamp.equals(inToken.expireTimestamp),
      true,
      'oh no'
    );
    assert.equal(outToken.sequence.equals(inToken.sequence), true, 'oh no');

    assert.equal(outToken.sharedTokenData.serverAddrs.length, 1, 'oh no');
    assert.equal(
      outToken.sharedTokenData.serverAddrs[0].port,
      addr.port,
      'oh no'
    );
    assertBytesEqual(
      outToken.sharedTokenData.serverAddrs[0].ip,
      addr.ip,
      'oh no'
    );
    assertBytesEqual(
      outToken.sharedTokenData.clientKey,
      inToken.sharedTokenData.clientKey,
      'oh no'
    );
    assertBytesEqual(
      outToken.sharedTokenData.serverKey,
      inToken.sharedTokenData.serverKey,
      'oh no'
    );
    assertBytesEqual(
      outToken.privateData.buffer,
      inToken.privateData.buffer,
      'oh no'
    );

    assert.equal(
      outToken.privateData.decrypt(
        TEST_PROTOCOL_ID,
        outToken.expireTimestamp,
        outToken.sequence,
        key
      ) !== undefined,
      true,
      'oh no'
    );
    assert.equal(
      inToken.privateData.decrypt(
        TEST_PROTOCOL_ID,
        inToken.expireTimestamp,
        inToken.sequence,
        key
      ) !== undefined,
      true,
      'oh no'
    );
    assert.equal(outToken.privateData.read(), Netcode.Errors.none, 'oh no');

    assert.equal(outToken.sharedTokenData.serverAddrs.length, 1, 'oh no');
    assert.equal(
      outToken.sharedTokenData.serverAddrs[0].port,
      addr.port,
      'oh no'
    );
    assertBytesEqual(
      outToken.sharedTokenData.serverAddrs[0].ip,
      addr.ip,
      'oh no'
    );
    assertBytesEqual(
      outToken.sharedTokenData.clientKey,
      inToken.sharedTokenData.clientKey,
      'oh no'
    );
    assertBytesEqual(
      outToken.sharedTokenData.serverKey,
      inToken.sharedTokenData.serverKey,
      'oh no'
    );
  });
});

describe('ChallengeToken tests', function () {
  it('read/write challenge token', function () {
    var token = new Netcode.ChallengeToken(TEST_CLIENT_ID);
    var userData = Netcode.Utils.getRandomBytes(Netcode.USER_DATA_BYTES);
    var tokenBuffer = token.write(userData);

    var sequence = Netcode.Long.fromNumber(9999);
    var key = Netcode.Utils.generateKey();

    assert.equal(tokenBuffer.length, Netcode.CHALLENGE_TOKEN_BYTES, 'oh no');
    Netcode.ChallengeToken.encrypt(tokenBuffer, sequence, key);
    assert.equal(tokenBuffer.length, Netcode.CHALLENGE_TOKEN_BYTES, 'oh no');

    var decrypted = Netcode.ChallengeToken.decrypt(tokenBuffer, sequence, key);
    assert.equal(decrypted instanceof Uint8Array, true, 'oh no');
    assert.equal(
      decrypted.length,
      Netcode.CHALLENGE_TOKEN_BYTES - Netcode.MAC_BYTES,
      'oh no'
    );

    var token2 = new Netcode.ChallengeToken();
    var err = token2.read(decrypted);
    assert.equal(err, Netcode.Errors.none, 'oh no');
    assert.equal(token2.clientID.equals(token.clientID), true, 'oh no');
    assertBytesEqual(token2.userData, token.userData, 'oh no');
  });
});
