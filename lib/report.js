'use strict';

/*
 * Fikrado Security — report store
 * Reports are written to ~/.fikrado/reports/ as both .json (machine) and .txt (human).
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { REPORTS_DIR, ensureDirs } = require('./config');
const { stripAnsi } = require('./ui');

const TOOL = 'Fikrado Security';

function stamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

function saveReport(kind, payload) {
  ensureDirs();
  const base = `fikrado-${kind}-${stamp()}`;
  const report = {
    tool: TOOL,
    createdAt: new Date().toISOString(),
    host: os.hostname(),
    platform: `${os.type()} ${os.release()} (${os.arch()})`,
    user: os.userInfo().username,
    kind,
    ...payload,
  };
  const jsonPath = path.join(REPORTS_DIR, base + '.json');
  const txtPath = path.join(REPORTS_DIR, base + '.txt');
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2) + '\n');
  fs.writeFileSync(txtPath, renderText(report) + '\n');
  return { jsonPath, txtPath, name: base, report };
}

function renderText(r) {
  const L = [];
  L.push('='.repeat(64));
  L.push(`  ${TOOL} — ${String(r.title || r.kind).toUpperCase()} REPORT`);
  L.push('='.repeat(64));
  L.push(`Created : ${r.createdAt}`);
  L.push(`Host    : ${r.host}  (${r.platform})`);
  L.push(`User    : ${r.user}`);
  if (r.durationMs !== undefined) L.push(`Duration: ${(r.durationMs / 1000).toFixed(1)}s`);
  L.push('-'.repeat(64));
  if (r.summary && Array.isArray(r.summary)) {
    for (const s of r.summary) L.push(`  ${s}`);
  }
  L.push('-'.repeat(64));
  if (Array.isArray(r.entries)) {
    for (const e of r.entries) L.push(`  ${stripAnsi(e)}`);
  }
  if (Array.isArray(r.checks)) {
    for (const ch of r.checks) {
      const tag = { pass: '[PASS]', warn: '[WARN]', fail: '[FAIL]', skip: '[SKIP]', info: '[INFO]' }[ch.status] || '[????]';
      L.push(`  ${tag} ${ch.title}${ch.detail ? ' — ' + ch.detail : ''}`);
      if (ch.advice && ch.status !== 'pass') L.push(`         ↳ fix: ${ch.advice}`);
    }
  }
  if (Array.isArray(r.hosts)) {
    for (const h of r.hosts) {
      if (!h.alive) continue;
      L.push(`  HOST ${h.ip}  ports: ${(h.openPorts || []).map((p) => p.port).join(', ') || 'none scanned open'}`);
      for (const risk of h.risks || []) L.push(`        [${risk.severity.toUpperCase()}] ${risk.msg}`);
    }
  }
  L.push('='.repeat(64));
  L.push('  Authorized use only. Fikrado Security — terminal security suite.');
  return L.join('\n');
}

function listReports() {
  ensureDirs();
  const files = fs
    .readdirSync(REPORTS_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .reverse();
  return files.map((f) => {
    try {
      const j = JSON.parse(fs.readFileSync(path.join(REPORTS_DIR, f), 'utf8'));
      return { file: f, createdAt: j.createdAt, kind: j.kind, title: j.title || j.kind };
    } catch {
      return { file: f, createdAt: null, kind: '?', title: f };
    }
  });
}

function readReportTxt(name) {
  const p = path.join(REPORTS_DIR, name.replace(/\.json$/, '.txt'));
  return fs.readFileSync(p, 'utf8');
}

function reportsDir() {
  return REPORTS_DIR;
}

module.exports = { saveReport, listReports, readReportTxt, reportsDir, stamp };
