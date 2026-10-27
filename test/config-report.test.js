'use strict';

/*
 * Fikrado Security — config + report store tests
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'fikrado-home-'));
process.env.USERPROFILE = process.env.HOME;

const cfg = require('../lib/config');
const report = require('../lib/report');

test('config defaults are safe and provider presets exist', () => {
  const c = cfg.load();
  assert.equal(c.activeProvider, null);
  assert.deepEqual(c.providers, {});
  for (const name of ['openrouter', 'openai', 'opencode', 'custom']) {
    assert.ok(cfg.PROVIDER_PRESETS[name], `${name} preset missing`);
  }
  assert.deepEqual(cfg.providerNames().sort(), ['custom', 'openai', 'opencode', 'openrouter']);
});

test('provider keys are saved, masked and only active with a key', () => {
  const c = cfg.load();
  cfg.setProvider(c, 'openrouter', { key: 'sk-or-v1-abcdefghijklmnop' });
  assert.equal(cfg.getActive(c), null, 'setting a key must not silently activate');

  cfg.setActive(c, 'openrouter');
  const active = cfg.getActive(cfg.load());
  assert.equal(active.name, 'openrouter');
  assert.equal(active.label, 'OpenRouter');
  assert.match(active.baseUrl, /^https:\/\/openrouter\.ai/);

  const masked = cfg.maskKey('sk-or-v1-abcdefghijklmnop');
  assert.ok(!masked.includes('abcdefghij'));
  assert.match(masked, /…/);
});

test('setProvider persists to ~/.fikrado/config.json with 0600 perms', () => {
  const c = cfg.load();
  cfg.setProvider(c, 'openai', { model: 'gpt-4o-mini' });
  const raw = fs.readFileSync(cfg.CONFIG_FILE, 'utf8');
  assert.match(raw, /gpt-4o-mini/);
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(cfg.CONFIG_FILE).mode & 0o077, 0, 'config must not be world-readable');
  }
});

test('saveReport writes both json and txt and listReports finds it', () => {
  const saved = report.saveReport('unit-test', {
    title: 'Unit test report',
    durationMs: 1234,
    summary: ['everything nominal'],
    checks: [
      { title: 'check one', status: 'pass', detail: 'ok' },
      { title: 'check two', status: 'fail', detail: 'boom', advice: 'fix it' },
    ],
  });

  assert.ok(fs.existsSync(saved.jsonPath));
  assert.ok(fs.existsSync(saved.txtPath));

  const parsed = JSON.parse(fs.readFileSync(saved.jsonPath, 'utf8'));
  assert.equal(parsed.tool, 'Fikrado Security');
  assert.equal(parsed.kind, 'unit-test');
  assert.equal(parsed.title, 'Unit test report');

  const txt = fs.readFileSync(saved.txtPath, 'utf8');
  assert.match(txt, /UNIT TEST REPORT/);
  assert.match(txt, /\[PASS\] check one/);
  assert.match(txt, /\[FAIL\] check two/);
  assert.match(txt, /fix: fix it/);

  const list = report.listReports();
  assert.ok(list.some((r) => r.title === 'Unit test report'));
  assert.match(report.readReportTxt(saved.name + '.json'), /everything nominal/);
});

test('reports folder is created on demand', () => {
  assert.ok(fs.existsSync(report.reportsDir()));
});
