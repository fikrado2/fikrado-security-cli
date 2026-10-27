'use strict';

/*
 * Fikrado Security — host audit + AD + UI tests
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'fikrado-home-'));
process.env.USERPROFILE = process.env.HOME;
process.env.FIKRADO_NO_ANIM = '1';

const serverAudit = require('../lib/scanners/server');
const ad = require('../lib/scanners/ad');
const ui = require('../lib/ui');

test('host audit returns a coherent report', async () => {
  const res = await serverAudit.audit();
  assert.ok(res.checks.length >= 5);
  assert.equal(res.host, os.hostname());
  assert.match(res.platform, new RegExp(os.type()));

  const allowed = new Set(['pass', 'warn', 'fail', 'skip', 'info']);
  for (const ch of res.checks) {
    assert.ok(ch.id && ch.title, 'every check needs an id and title');
    assert.ok(allowed.has(ch.status), `unexpected status ${ch.status}`);
    assert.equal(typeof ch.detail, 'string');
  }

  const total = Object.values(res.counts).reduce((a, b) => a + b, 0);
  assert.equal(total, res.checks.length);
  assert.ok(res.durationMs >= 0);
});

test('linux audit includes SECURITY-relevant checks', async () => {
  const res = await serverAudit.audit();
  const ids = res.checks.map((c) => c.id);
  if (process.platform === 'linux') {
    for (const id of ['ssh-root-login', 'shadow-perms', 'uid0-accounts', 'firewall', 'ld-preload', 'cron-suspicious']) {
      assert.ok(ids.includes(id), `expected linux check ${id}`);
    }
  } else if (process.platform === 'darwin') {
    for (const id of ['mac-firewall', 'mac-filevault', 'mac-sip']) {
      assert.ok(ids.includes(id), `expected macos check ${id}`);
    }
  } else if (process.platform === 'win32') {
    for (const id of ['win-firewall', 'win-defender', 'win-uac']) {
      assert.ok(ids.includes(id), `expected windows check ${id}`);
    }
  }
});

test('AD domain validation rejects shell-ish input', async () => {
  await assert.rejects(() => ad.audit('bad domain; rm -rf /'), /Invalid or missing domain/);
  await assert.rejects(() => ad.audit(''), /Invalid or missing domain/);
});

test('AD audit of a non-existent domain returns an informational risk', async () => {
  const res = await ad.audit('definitely-not-a-real-domain.invalid');
  assert.equal(res.domain, 'definitely-not-a-real-domain.invalid');
  assert.ok(Array.isArray(res.risks));
  assert.equal(res.dcResults.length, 0);
  assert.ok(res.risks.length >= 1);
  assert.match(res.risks[0].msg, /No SRV records|No LDAP/i);
});

test('ANSI stripping and progress bar degrade safely', () => {
  assert.equal(ui.stripAnsi('\x1b[1;33mFIKRADO\x1b[0m'), 'FIKRADO');
  const bar = ui.progressBar(5, 10, 'half');
  assert.ok(bar.includes('50%'));
  assert.ok(ui.progressBar(0, 0, '').includes('0%'));
  assert.ok(ui.progressBar(10, 10, '').includes('100%'));
});

test('banner renders the full FIKRADO SECURITY wordmark', async () => {
  const chunks = [];
  const write = process.stdout.write.bind(process.stdout);
  process.stdout.write = (s) => { chunks.push(String(s)); return true; };
  try {
    await ui.showBanner({ anim: false, version: '9.9.9' });
  } finally {
    process.stdout.write = write;
  }
  const out = ui.stripAnsi(chunks.join(''));
  assert.match(out, /v9\.9\.9/);
  // each letter is drawn as a 5-row block glyph; count the wide glyph rows
  assert.ok(out.split('\n').filter((l) => l.includes('█')).length >= 10);
});
