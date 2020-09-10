var assert = require('assert');
var { Netcode } = require('../dist/node/netcode');

describe('ByteBuffer tests', function () {
  it('correct write/read bytes', function () {
    var bb = new Netcode.ByteBuffer(new Uint8Array(64));
    var input = new Uint8Array(Netcode.VERSION_INFO_BYTES_ARRAY);
    assert.equal(bb.position, 0, 'oh no');
    bb.writeBytes(input);
    assert.equal(bb.position, 13, 'oh no');

    bb.clearPosition();
    assert.equal(bb.position, 0, 'oh no');
    var output = bb.readBytes(13);
    output.forEach(function (item, index) {
      if (Netcode.VERSION_INFO_BYTES_ARRAY[index] !== item) {
        assert(false, 'oh no');
      }
    });
    assert.equal(bb.position, 13, 'oh no');
  });

  it('correct write/read byte', function () {
    var array = new Uint8Array(1);
    let bb = new Netcode.ByteBuffer(array);
    bb.writeUint8(0xfe);
    assert.equal(bb.position, 1, 'oh no');

    bb.clearPosition();
    var out = bb.readUint8();
    assert.equal(bb.position, 1, 'oh no');
    assert.equal(out, 0xfe, 'oh no');
  });

  it('correct write/read int8', function () {
    var array = new Uint8Array(1);
    let bb = new Netcode.ByteBuffer(array);
    bb.writeInt8(-3);
    assert.equal(bb.position, 1, 'oh no');

    bb.clearPosition();
    var out = bb.readInt8();
    assert.equal(bb.position, 1, 'oh no');
    assert.equal(out, -3, 'oh no');
  });

  it('correct write/read uint16', function () {
    var array = new Uint8Array(2);
    let bb = new Netcode.ByteBuffer(array);
    bb.writeUint16(9999);
    assert.equal(bb.position, 2, 'oh no');

    bb.clearPosition();
    var out = bb.readUint16();
    assert.equal(bb.position, 2, 'oh no');
    assert.equal(out, 9999, 'oh no');
  });

  it('correct write/read int16', function () {
    var array = new Uint8Array(2);
    let bb = new Netcode.ByteBuffer(array);
    bb.writeInt16(-9999);
    assert.equal(bb.position, 2, 'oh no');

    bb.clearPosition();
    var out = bb.readInt16();
    assert.equal(bb.position, 2, 'oh no');
    assert.equal(out, -9999, 'oh no');
  });

  it('correct write/read uint32', function () {
    var array = new Uint8Array(4);
    let bb = new Netcode.ByteBuffer(array);
    bb.writeUint32(99999);
    assert.equal(bb.position, 4, 'oh no');

    bb.clearPosition();
    var out = bb.readUint32();
    assert.equal(bb.position, 4, 'oh no');
    assert.equal(out, 99999, 'oh no');
  });

  it('correct write/read int32', function () {
    var array = new Uint8Array(4);
    let bb = new Netcode.ByteBuffer(array);
    bb.writeUint32(-99999);
    assert.equal(bb.position, 4, 'oh no');

    bb.clearPosition();
    var out = bb.readInt32();
    assert.equal(bb.position, 4, 'oh no');
    assert.equal(out, -99999, 'oh no');
  });

  it('correct write/read uint64', function () {
    var array = new Uint8Array(8);
    let bb = new Netcode.ByteBuffer(array);
    const l = new Netcode.Long(65534, 99999);
    bb.writeUint64(l);
    assert.equal(bb.position, 8, 'oh no');

    bb.clearPosition();
    var out = bb.readUint64();
    assert.equal(bb.position, 8, 'oh no');
    assert.equal(out.equals(l), true, 'oh no');
  });

  it('test Long', function () {
    var n = 3293924239;
    var l = Netcode.Long.fromNumber(n);
    assert.equal(l.toNumber(), n, 'oh no');

    var l2 = new Netcode.Long(2432, 9923);
    var n2 = l2.toNumber();
    var l3 = Netcode.Long.fromNumber(n2);
    assert.equal(l2.equals(l3), true, 'on no');
  });
});
