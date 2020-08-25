var { ReplayProtection } = require('../bin/ReplayProtection');
var Defines = require('../bin/Defines');
var assert = require('assert');

describe('ReplayProtection tests', function () {
  it('test reset', function () {
    const rp = new ReplayProtection();
    for (const p of rp._receivedPacket) {
      assert.equal(p, 0xffffffffffffffff, 'oh no');
    }
  });

  it('test replay protection', function () {
    const rp = new ReplayProtection();
    for (let i = 0; i < 2; i += 1) {
      rp.reset();
      if (rp._mostRecentSequence !== 0) {
        assert.fail('sequence not 0');
      }
    }

    var sequence = 1 << 63;
    if (rp.checkAlreadyReceived(sequence)) {
      assert.fail('sequence numbers with high bit set should be ignored');
    }

    if (rp._mostRecentSequence !== 0) {
      assert.fail(
        'sequence was not 0 after high-bit check got',
        rp._mostRecentSequence
      );
    }

    // the first time we receive packets, they should not be already received
    var maxSequence = Defines.REPLAY_PROTECTION_BUFFER_SIZE * 4;
    for (let sequence = 0; sequence < maxSequence; sequence += 1) {
      if (rp.checkAlreadyReceived(sequence)) {
        assert.fail(
          'the first time we receive packets, they should not be already received'
        );
      }
    }

    // old packets outside buffer should be considered already received
    if (!rp.checkAlreadyReceived(0)) {
      assert.fail(
        'old packets outside buffer should be considered already received'
      );
    }

    // packets received a second time should be flagged already received
    for (
      let sequence = maxSequence - 10;
      sequence < maxSequence;
      sequence += 1
    ) {
      if (!rp.checkAlreadyReceived(sequence)) {
        assert.fail(
          'packets received a second time should be flagged already received'
        );
      }
    }

    // jumping ahead to a much higher sequence should be considered not already received
    if (
      rp.checkAlreadyReceived(
        maxSequence + Defines.REPLAY_PROTECTION_BUFFER_SIZE
      )
    ) {
      assert.fail(
        'jumping ahead to a much higher sequence should be considered not already received'
      );
    }

    // old packets should be considered already received
    for (let sequence = 0; sequence < maxSequence; sequence += 1) {
      if (!rp.checkAlreadyReceived(sequence)) {
        assert.fail('old packets should be considered already received');
      }
    }
  });
});
