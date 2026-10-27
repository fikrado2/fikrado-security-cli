'use strict';

/*
 * Fikrado Security — network engine tests
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'fikrado-home-'));
process.env.USERPROFILE = process.env.HOME;

const network = require('../lib/scanners/network');

test('parseCidr expands hosts and excludes network/broadcast', () => {
  assert.deepEqual(network.parseCidr('192.168.1.0/30'), ['192.168.1.1', '192.168.1.2']);
  assert.deepEqual(network.parseCidr('10.0.0.0/31'), []);
  assert.deepEqual(network.parseCidr('192.168.1.7/32'), ['192.168.1.7']);
});

test('parseCidr rejects garbage and oversized ranges', () => {
  assert.throws(() => network.parseCidr('not-a-cidr'), /Invalid CIDR/);
  assert.throws(() => network.parseCidr('10.0.0.0/7'), /Invalid prefix/);
  assert.throws(() => network.parseCidr('10.0.0.0/8'), /too large/);
});

test('getLocalNetworks returns well-formed IPv4 networks', () => {
  const nets = network.getLocalNetworks();
  assert.ok(Array.isArray(nets));
  for (const n of nets) {
    assert.match(n.cidr, /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/);
    assert.ok(n.prefix >= 0 && n.prefix <= 32);
    assert.ok(n.name);
  }
});

test('service and risk tables are consistent', () => {
  assert.equal(network.SERVICES[22], 'ssh');
  assert.equal(network.SERVICES[443], 'https');
  assert.equal(network.SERVICES[3389], 'rdp');
  for (const port of Object.keys(network.RISKS)) {
    assert.ok(network.SERVICES[Number(port)], `risk port ${port} must have a service name`);
    assert.ok(['high', 'med', 'low'].includes(network.RISKS[port][0]));
  }
});

test('checkPort detects a listener on an ephemeral port', async (t) => {
  const net = require('node:net');
  const server = net.createServer((s) => s.end());
  await new Promise((res) => server.listen(0, '127.0.0.1', res));
  const port = server.address().port;
  t.after(() => server.close());

  assert.equal(await network.checkPort('127.0.0.1', port, 1500), port);
  assert.equal(await network.checkPort('127.0.0.1', 1, 400), null);
});
