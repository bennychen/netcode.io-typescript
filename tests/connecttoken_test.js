var CT = require('../bin/ConnectToken');
var BB = require('../bin/ByteBuffer');
var { Utils } = require('../bin/Utils');
var Defines = require('../bin/Defines');
var chacha = require('../bin/chacha20poly1305');
var assert = require('assert');

var TEST_PROTOCOL_ID = 0x1122334455667788;
var TEST_CONNECT_TOKEN_EXPIRY = 30;
var TEST_SERVER_PORT = 40000;
var TEST_CLIENT_ID = BB.Long.fromNumber(0x1);
var TEST_SEQUENCE_START = 1000;
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

function arrayEqual(a1, a2) {
  a1.forEach(function (item, index) {
    if (a2[index] !== item) {
      return false;
    }
  });
  return true;
}

function assertBytesEqual(a1, a2, str) {
  assert.equal(arrayEqual(a1, a2), true, str);
}

function ipStringToBytes(ip) {
  var octets = ip.split('.');
  if (octets.length !== 4) {
    console.error('only support ipv4');
    return;
  }
  const bytes = new Uint8Array(4);
  for (var i = 0; i < octets.length; ++i) {
    var octet = parseInt(octets[i], 10);
    if (Number.isNaN(octet) || octet < 0 || octet > 255) {
      throw new Error('Each octet must be between 0 and 255');
    }
    bytes[i] = octet;
  }
  return bytes;
}

describe('ShareConnectToken tests', function () {
  it('read/write shared connect token', function () {
    var clientKey = Utils.generateKey();
    assert.equal(clientKey.length, Defines.KEY_BYTES, 'oh no');
    var serverKey = Utils.generateKey();
    assert.equal(serverKey.length, Defines.KEY_BYTES, 'oh no');

    var addr = {
      ip: ipStringToBytes('10.20.30.40'),
      port: 40000,
    };
    var data = new CT.SharedTokenData();
    data.timeoutSeconds = 10;
    data.serverAddrs = [addr];
    data.clientKey = clientKey;
    data.serverKey = serverKey;

    var buffer = new BB.ByteBuffer(new Uint8Array(Defines.CONNECT_TOKEN_BYTES));
    data.write(buffer);
    buffer.clearPosition();

    var outData = new CT.SharedTokenData();
    var ret = outData.read(buffer);
    assert.equal(ret, true, 'oh no');
    assertBytesEqual(clientKey, outData.clientKey, 'oh no');
    assertBytesEqual(serverKey, outData.serverKey, 'oh no');
    assert.equal(data.timeoutSeconds, outData.timeoutSeconds, 'oh no');
    assert.equal(outData.serverAddrs.length, 1, 'on no');
    assertBytesEqual(outData.serverAddrs[0].ip, addr.ip, 'on no');
    assert.equal(outData.serverAddrs[0].port, addr.port, 'on no');
  });

  it('read/write private connect token', function () {
    var addr = {
      ip: ipStringToBytes('10.20.30.40'),
      port: 40000,
    };
    var ts = new Date().getTime();
    var expireTs = ts + TEST_CONNECT_TOKEN_EXPIRY;
    var timeoutSeconds = 10;
    var userData = chacha.getRandomBytes(Defines.USER_DATA_BYTES);

    var token1 = CT.ConnectTokenPrivate.create(
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
    var token2 = CT.ConnectTokenPrivate.createEncrypted(encryptedToken);
    const decrypted = token2.decrypt(
      TEST_PROTOCOL_ID,
      expireTs,
      TEST_SEQUENCE_START,
      TEST_PRIVATE_KEY
    );
    assert.equal(decrypted !== undefined, true, 'decrypt failed');
    ret = token2.read();
    assert.equal(ret, true, 'on no');

    // compare tokens
    assert.equal(token1.clientId.equals(token2.clientId), true, 'on no');
    assert.equal(
      token1.sharedTokenData.serverAddrs.length,
      token2.sharedTokenData.serverAddrs.length,
      'on no'
    );
    assertBytesEqual(
      token1.sharedTokenData.serverAddrs[0].ip,
      token2.sharedTokenData.serverAddrs[0].ip,
      'on no'
    );
    assert.equal(
      token1.sharedTokenData.serverAddrs[0].port,
      token2.sharedTokenData.serverAddrs[0].port,
      'on no'
    );
    assertBytesEqual(
      token1.sharedTokenData.clientKey,
      token2.sharedTokenData.clientKey,
      'on no'
    );
    assertBytesEqual(
      token1.sharedTokenData.serverKey,
      token2.sharedTokenData.serverKey,
      'on no'
    );

    const buffer = new Uint8Array(Defines.CONNECT_TOKEN_PRIVATE_BYTES);
    Utils.blockCopy(token2.buffer, 0, buffer, 0, token2.buffer.length);
    token2.tokenData = new BB.ByteBuffer(buffer);
    token2.write();
    var ret = token2.encrypt(
      TEST_PROTOCOL_ID,
      expireTs,
      TEST_SEQUENCE_START,
      TEST_PRIVATE_KEY
    );
    assert.equal(ret, true, 'oh no');
    assert.equal(token1.buffer.length, token2.buffer.length, 'oh no');
    assertBytesEqual(token1.buffer, token2.buffer, 'on no');
  });
});
