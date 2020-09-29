var assert = require('assert');
var { Netcode } = require('../dist/node/netcode');

var TEST_PROTOCOL_ID = Netcode.Long.fromNumber(0x1122334455667788);
var TEST_CONNECT_TOKEN_EXPIRY = 30;
var TEST_SERVER_PORT = 40000;
var TEST_CLIENT_ID = Netcode.Long.fromNumber(0x1);
var TEST_SEQUENCE_START = Netcode.Long.fromNumber(1000);
var TEST_TIMEOUT_SECONDS = 15;

describe('ClientManager tests', function () {
  it('test new ClientManager', function () {
    var timeout = 4;
    var maxClient = 2;
    const mgr = new Netcode.ClientManager(timeout, maxClient);
    if (mgr.findFreeClientIndex() === -1) {
      assert.fail('free client index should not return -1 when empty');
    }
    var addr = {
      ip: new Uint8Array(),
      port: 0,
    };
    if (mgr.findClientIndexByAddress(addr) !== -1) {
      assert.fail('empty address should get no client');
    }
    if (mgr.findClientIndexById(0) !== -1) {
      assert.fail('should not have any clients');
    }
  });

  function ipStringToBytes(ip) {
    var addr = Netcode.Utils.stringToIPV4Address(ip);
    return addr.ip;
  }

  it('test add encryption mapping', function () {
    var timeout = 4;
    var maxClient = 2;
    var servers = [];
    const ip = ipStringToBytes('127.0.0.1');
    servers.push({
      ip,
      port: 40000,
    });
    var addr = { ip, port: 62424 };
    var addr2 = { ip, port: 62425 };
    var overAddrs = [];
    for (var i = 0; i < maxClient * 8; i++) {
      overAddrs.push({ ip, port: 6000 + i });
    }

    var key = Netcode.Utils.generateKey();
    var userData = Netcode.Utils.getRandomBytes(Netcode.USER_DATA_BYTES);
    var connectToken = new Netcode.ConnectToken();
    connectToken.generate(
      TEST_CLIENT_ID,
      servers,
      TEST_PROTOCOL_ID,
      TEST_CONNECT_TOKEN_EXPIRY,
      TEST_TIMEOUT_SECONDS,
      TEST_SEQUENCE_START,
      userData,
      key
    );

    var mgr = new Netcode.ClientManager(timeout, maxClient);

    var serverTime = 1;
    var expireTime = 1;
    if (
      !mgr.addEncryptionMapping(
        connectToken.privateData,
        addr,
        serverTime,
        expireTime
      )
    ) {
      assert.fail('error adding encryption mapping');
    }

    // add it again
    if (
      !mgr.addEncryptionMapping(
        connectToken.privateData,
        addr,
        serverTime,
        expireTime
      )
    ) {
      assert.fail('error re-adding encryption mapping');
    }
    if (
      !mgr.addEncryptionMapping(
        connectToken.privateData,
        addr2,
        serverTime,
        expireTime
      )
    ) {
      assert.fail('error adding 2nd encryption mapping');
    }
    var failed = false;
    for (var i = 0; i < overAddrs.length; i++) {
      if (
        mgr.addEncryptionMapping(
          connectToken.privateData,
          overAddrs[i],
          serverTime,
          expireTime
        )
      ) {
        failed = true;
      }
    }
    if (!failed) {
      assert.fail(
        'error we added more encryption mappings than should have been allowed'
      );
    }
  });

  it('test add encryption mapping time out', function () {
    var timeout = 4;
    var maxClient = 2;
    var servers = [];
    var ip = ipStringToBytes('127.0.0.1');
    servers.push({ ip, port: 40000 });
    var addr = { ip, port: 62424 };

    var key = Netcode.Utils.generateKey();
    var userData = Netcode.Utils.getRandomBytes(Netcode.USER_DATA_BYTES);
    var connectToken = new Netcode.ConnectToken();
    connectToken.generate(
      TEST_CLIENT_ID,
      servers,
      TEST_PROTOCOL_ID,
      TEST_CONNECT_TOKEN_EXPIRY,
      TEST_TIMEOUT_SECONDS,
      TEST_SEQUENCE_START,
      userData,
      key
    );

    var mgr = new Netcode.ClientManager(timeout, maxClient);

    var serverTime = 1;
    var expireTime = 1;
    if (
      !mgr.addEncryptionMapping(
        connectToken.privateData,
        addr,
        serverTime,
        expireTime
      )
    ) {
      assert.fail('error adding encryption mapping');
    }

    var idx = mgr.findEncryptionEntryIndex(addr, serverTime);
    if (idx === -1) {
      assert.fail('error getting encryption entry index');
    }
    if (!mgr.setEncryptionEntryExpiration(idx, 0.1)) {
      assert.fail('error setting entry expiration');
    }
    // remove the client.
    mgr.checkTimeouts(serverTime);
    idx = mgr.findEncryptionEntryIndex(addr, serverTime);
    if (idx !== -1) {
      assert.fail(
        'error got encryption entry index when it should have been removed'
      );
    }
  });

  it('test disconnect client', function () {
    var timeout = 4;
    var maxClient = 2;
    var servers = [];
    var ip = ipStringToBytes('127.0.0.1');
    servers.push({ ip, port: 40000 });
    var addr = { ip, port: 62424 };

    var key = Netcode.Utils.generateKey();
    var userData = Netcode.Utils.getRandomBytes(Netcode.USER_DATA_BYTES);
    var connectToken = new Netcode.ConnectToken();
    connectToken.generate(
      TEST_CLIENT_ID,
      servers,
      TEST_PROTOCOL_ID,
      TEST_CONNECT_TOKEN_EXPIRY,
      TEST_TIMEOUT_SECONDS,
      TEST_SEQUENCE_START,
      userData,
      key
    );

    var mgr = new Netcode.ClientManager(timeout, maxClient);

    var serverTime = 1;
    var expireTime = 1;
    if (
      !mgr.addEncryptionMapping(
        connectToken.privateData,
        addr,
        serverTime,
        expireTime
      )
    ) {
      assert.fail('error adding encryption mapping');
    }

    var token = new Netcode.ChallengeToken(TEST_CLIENT_ID);
    var client = mgr.connectClient(addr, token);
    if (!client.connected) {
      assert.fail('error client should be connected');
    }
    assert.equal(client.clientId, TEST_CLIENT_ID, 'client id should be same');
    var clientIndex = mgr.findClientIndexById(TEST_CLIENT_ID);
    if (clientIndex === -1) {
      assert.fail('error finding client index');
    }
    assert.equal(
      clientIndex,
      client.clientIndex,
      'client index should be same'
    );

    if (mgr.getConnectedClientCount() !== 1) {
      assert.fail('error client connected count should be 1');
    }

    mgr.disconnectClientByIndex(clientIndex, false, serverTime);
    if (client.connected) {
      assert.fail('error client should be disconnected');
    }
  });
});
