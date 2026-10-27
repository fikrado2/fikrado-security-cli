'use strict';

/*
 * Fikrado Security — interactive menu + CLI entry
 */

const readline = require('readline');
const os = require('os');
const path = require('path');
const fs = require('fs');
const pkg = require('../package.json');
const ui = require('./ui');
const { c } = ui;
const cfgMod = require('./config');
const ai = require('./ai');
const reportMod = require('./report');
const malware = require('./scanners/malware');
const network = require('./scanners/network');
const serverAudit = require('./scanners/server');
const adScanner = require('./scanners/ad');

let rl = null;
let closed = false;
const lineQueue = [];
const lineWaiters = [];

function getRl() {
  if (!rl) {
    rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });
    rl.on('line', (l) => {
      const w = lineWaiters.shift();
      if (w) w(l);
      else lineQueue.push(l);
    });
    rl.on('close', () => {
      closed = true;
      while (lineWaiters.length) lineWaiters.shift()('');
    });
  }
  return rl;
}

function nextLine() {
  if (lineQueue.length) return Promise.resolve(lineQueue.shift());
  return new Promise((res) => lineWaiters.push(res));
}

process.on('SIGINT', () => {
  ui.showCursor();
  process.stdout.write('\n' + c.yellow('aborted by user') + '\n');
  process.exit(130);
});

async function ask(prompt) {
  getRl();
  if (prompt) process.stdout.write(prompt || '❯ ');
  if (closed && !lineQueue.length) return '';
  const line = await nextLine();
  return String(line).trim();
}

async function askInt(prompt, opts = {}) {
  for (;;) {
    const raw = await ask(prompt);
    if (raw === '' && opts.def !== undefined) return opts.def;
    // stdin exhausted / non-interactive: never spin forever on a closed pipe
    if (raw === '' && closed && !lineQueue.length) return opts.min !== undefined ? opts.min : 0;
    const n = Number(raw);
    if (Number.isInteger(n) && (opts.min === undefined || n >= opts.min) && (opts.max === undefined || n <= opts.max)) return n;
    console.log(c.dim(`  enter a number${opts.min !== undefined ? ` ${opts.min}-${opts.max}` : ''}`));
  }
}

async function askConfirm(prompt, defYes = true) {
  const raw = (await ask(prompt)).toLowerCase();
  if (raw === '') return defYes;
  return raw.startsWith('y');
}

function askHidden(prompt) {
  if (!process.stdin.isTTY) return ask(prompt);
  const main = getRl();
  main.pause();
  return new Promise((resolve) => {
    const r = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const W = r._writeToOutput.bind(r);
    r._writeToOutput = (s) => W(String(s).replace(/[^\r\n]/g, '*'));
    r.question(prompt, (ans) => {
      r.close();
      process.stdout.write('\n');
      main.resume();
      resolve(String(ans).trim());
    });
  });
}

process.on('exit', () => ui.showCursor());

/* ================================================================== */
/* Rendering helpers                                                   */
/* ================================================================== */

const sevColor = { high: c.lightRed, med: c.yellow, low: c.cyan, info: c.gray };

function printFindings(result) {
  console.log(`\n${c.bold('Scan complete')} ${c.dim(`· ${result.filesScanned} files scanned · ${result.signatureCount} signatures · ${(result.durationMs / 1000).toFixed(1)}s`)}`);
  if (!result.findings.length) {
    console.log(`  ${c.green('✔')} ${c.green('No threats detected.')}`);
    return;
  }
  const rows = result.findings.map((f) => [
    f.risk === 'high' ? c.lightRed('HIGH') : c.yellow('MED'),
    path.basename(f.path),
    f.matches.map((m) => m.id).slice(0, 3).join(', '),
    f.size + ' B',
  ]);
  console.log();
  ui.table(['RISK', 'FILE', 'SIGNATURES', 'SIZE'], rows);
  console.log(`\n  ${c.lightRed(result.findings.filter((f) => f.risk === 'high').length)} high-risk · ${c.yellow(result.findings.filter((f) => f.risk !== 'high').length)} medium files flagged`);
  for (const f of result.findings.filter((x) => x.risk === 'high').slice(0, 5)) {
    console.log(`  ${c.gray('›')} ${f.path}`);
  }
}

async function handleFindingsActions(result) {
  if (!result.findings.length) return { deleted: 0, quarantined: 0 };
  const act = (await ask(`\n${c.bold('Action:')} ${c.lightRed('[d]')}elete all · ${c.yellow('[q]')}uarantine all · ${c.lightCyan('[i]')}nteractive · ${c.gray('[k]')}eep ❯ `)).toLowerCase();
  const out = { deleted: 0, quarantined: 0 };

  const doDelete = async (f) => { await malware.deleteFinding(f); out.deleted++; };
  const doQuarantine = async (f) => { await malware.quarantineFinding(f, out.quarantined); out.quarantined++; };

  if (act === 'd') {
    if (!(await askConfirm(c.yellow('Permanently delete ALL flagged files? [y/N] '), false))) return out;
    for (const f of result.findings) { try { await doDelete(f); } catch (e) { console.log(`  ${c.lightRed('✗')} ${f.path}: ${e.message}`); } }
  } else if (act === 'q') {
    for (const f of result.findings) { try { await doQuarantine(f); } catch (e) { console.log(`  ${c.lightRed('✗')} ${f.path}: ${e.message}`); } }
  } else if (act === 'i') {
    for (const f of result.findings) {
      const a = (await ask(`  ${path.basename(f.path)} ${c.dim(`(${f.matches.map((m) => m.id).join(', ')})`)} — ${c.lightRed('[d]')}${c.yellow('el / [q]uarantine / [k]eep ❯ ')}`)).toLowerCase();
      if (a === 'd') { try { await doDelete(f); } catch (e) { console.log(`    ${c.lightRed('✗')} ${e.message}`); } }
      else if (a === 'q') { try { await doQuarantine(f); } catch (e) { console.log(`    ${c.lightRed('✗')} ${e.message}`); } }
    }
  }
  if (out.deleted || out.quarantined) {
    console.log(`  ${c.green('✔')} ${out.deleted} deleted · ${out.quarantined} quarantined`);
  }
  return out;
}

async function aiAnalyze(kind, data) {
  const cfg = cfgMod.load();
  const p = cfgMod.getActive(cfg);
  if (!p) {
    console.log(c.dim(`  AI detection not configured — open menu option 6 to add an OpenRouter / OpenAI / OpenCode key.`));
    return null;
  }
  const sp = new ui.Spinner(`asking ${p.label} (${p.model})…`).start();
  try {
    let text;
    if (kind === 'findings') text = await ai.analyzeFindings(p, data);
    else text = await ai.summarizeReport(p, data);
    sp.succeed('AI analysis');
    console.log('\n' + c.lightMagenta('┌─ AI verdict ' + '─'.repeat(Math.max(0, ui.width() - 14))));
    for (const line of String(text).split('\n')) console.log(c.lightMagenta('│') + ' ' + line);
    console.log(c.lightMagenta('└' + '─'.repeat(Math.max(0, ui.width() - 2))) + '\n');
    return text;
  } catch (e) {
    sp.fail(e.message);
    return null;
  }
}

async function maybeAiAnalyze(kind, data) {
  const cfg = cfgMod.load();
  const p = cfgMod.getActive(cfg);
  if (!p) {
    console.log(c.dim(`  AI detection not configured — open menu option 6 to add an OpenRouter / OpenAI / OpenCode key.`));
    return null;
  }
  if (!(await askConfirm(`${c.lightMagenta('✦')} Analyze with AI (${p.label})? [y/N] `, false))) return null;
  return aiAnalyze(kind, data);
}

function printServerResults(res) {
  console.log(`\n${c.bold('Host audit')} ${c.dim(`· ${res.checks.length} checks · ${(res.durationMs / 1000).toFixed(1)}s`)}`);
  for (const ch of res.checks) {
    console.log(`  ${ui.statusIcon(ch.status)} ${c.white(ch.title)} ${c.dim('— ' + ch.detail)}`);
    if (ch.advice && ch.status !== 'pass') console.log(`    ${c.gray('↳ fix:')} ${c.yellow(ch.advice)}`);
  }
  const k = res.counts;
  console.log(`\n  ${c.green(k.pass + ' pass')} · ${c.yellow(k.warn + ' warn')} · ${c.lightRed(k.fail + ' fail')} · ${c.gray(k.skip + k.info + ' info/skip')}`);
}

function printNetworkResults(res) {
  console.log(`\n${c.bold('Network scan')} ${c.dim(`· ${res.cidr} · ${res.hostsScanned} hosts · ${res.hostsAlive} alive · ${(res.durationMs / 1000).toFixed(1)}s`)}`);
  for (const h of res.hosts) {
    const ports = h.openPorts.map((p) => (network.RISKS[p.port] ? c.lightRed(String(p.port)) : c.green(String(p.port)))).join(' ') || c.gray('none open');
    console.log(`  ${c.green('●')} ${c.bold(h.ip)} ${c.dim(ports)}`);
    for (const r of h.risks) console.log(`      ${sevColor[r.severity](`[${r.severity.toUpperCase()}]`)} ${c.gray(r.msg)}`);
  }
  const s = res.summary;
  console.log(`\n  hosts alive ${c.bold(String(s.alive))} · open ports ${c.bold(String(s.openPorts))} · ${c.lightRed(s.highRisks + ' high-risk')} ${c.yellow(s.medRisks + ' medium')}`);
}

function printAdResults(res) {
  console.log(`\n${c.bold('Active Directory audit')} ${c.dim(`· ${res.domain} · ${(res.durationMs / 1000).toFixed(1)}s`)}`);
  for (const dc of res.dcResults) {
    console.log(`\n  ${c.cyan('▦')} ${c.bold(dc.host)} ${dc.anonymousBind && dc.anonymousBind.ok && dc.anonymousBind.code === 0 ? c.lightRed('(anonymous bind allowed!)') : c.green('(anonymous bind rejected)')}`);
    for (const p of dc.ports) {
      console.log(`      ${p.open ? c.green('●') : c.gray('○')} :${String(p.port).padEnd(5)} ${p.service}`);
    }
  }
  for (const r of res.risks) console.log(`  ${sevColor[r.severity](`[${(r.severity || '').toUpperCase() || 'INFO'}]`)} ${c.white(r.msg)}`);
  for (const i of res.info || []) console.log(`  ${c.gray('ℹ ' + i)}`);
}

function renderProgress(cur, tot, label) {
  if (ui.animOn) {
    process.stdout.write(`\r\x1b[2K  ${ui.progressBar(cur, tot, label)}`);
    if (cur >= tot) process.stdout.write('\n');
  } else if (tot && (cur % Math.max(1, Math.floor(tot / 8)) === 0 || cur === tot)) {
    console.log(`  ${ui.progressBar(cur, tot, label)}`);
  }
}

async function saveReportPrompt(kind, payload) {
  const { saveReport, reportsDir } = reportMod;
  const saved = saveReport(kind, payload);
  console.log(`  ${c.green('✔')} report saved ${c.gray(saved.txtPath)}`);
  return saved;
}

/* ================================================================== */
/* Flows                                                               */
/* ================================================================== */

async function runMalwareScan(rootPath, opts = {}) {
  const sp = new ui.Spinner('preparing scan…').start();
  const result = await malware.scan(rootPath, {
    onProgress: (a, b, lbl) => renderProgress(a, b, lbl || ''),
    onPhase: (t) => sp.update(t),
  });
  sp.stop();
  printFindings(result);
  if (result.findings.length && !opts.noPrompt) await handleFindingsActions(result);
  lastScan = result;
  return result;
}

let lastScan = null;
let lastNet = null;

async function malwareMenu() {
  for (;;) {
    ui.menuHeader('MALWARE SCAN');
    console.log(`  ${c.bold('[1]')} Quick scan      ${c.dim('(Downloads, Desktop, Documents, /tmp, web roots…)')}`);
    console.log(`  ${c.bold('[2]')} Full scan       ${c.dim('(custom path — every file under it)')}`);
    console.log(`  ${c.bold('[3]')} Quarantine      ${c.dim('(view / restore quarantined files)')}`);
    console.log(`  ${c.bold('[0]')} Back`);
    const choice = await ask('❯ ');
    if (choice === '0' || choice === '') return;
    if (choice === '1') {
      const paths = malware.quickScanPaths();
      if (!paths.length) { console.log(c.yellow('  no common locations found — use full scan')); continue; }
      console.log(c.dim('  scanning: ' + paths.join(', ')));
      for (const p of paths) {
        console.log(`\n${c.bold('▸ ' + p)}`);
        const res = await runMalwareScan(p);
        if (!(await askConfirm('Save report? [Y/n] ', true))) continue;
        await saveReportPrompt('malware', {
          title: `Malware scan — ${p}`,
          root: res.root,
          durationMs: res.durationMs,
          filesScanned: res.filesScanned,
          summary: [
            `files scanned: ${res.filesScanned}`,
            `threats found: ${res.findings.length} (${res.findings.filter((f) => f.risk === 'high').length} high)`,
          ],
          entries: res.findings.map((f) => `[${f.risk.toUpperCase()}] ${f.path} — ${f.matches.map((m) => m.id).join(', ')}`),
        });
      }
      await maybeAiAnalyze('findings', lastScan ? lastScan.findings : []);
    }
    if (choice === '2') {
      const p = await ask(`path to scan [${process.cwd()}] ❯ `);
      const target = p || process.cwd();
      if (!fs.existsSync(target)) { console.log(c.lightRed(`  path not found: ${target}`)); continue; }
      const res = await runMalwareScan(target);
      if (await askConfirm('Save report? [Y/n] ', true)) {
        await saveReportPrompt('malware', {
          title: `Malware scan — ${res.root}`,
          root: res.root,
          durationMs: res.durationMs,
          filesScanned: res.filesScanned,
          summary: [
            `files scanned: ${res.filesScanned}`,
            `threats found: ${res.findings.length} (${res.findings.filter((f) => f.risk === 'high').length} high)`,
          ],
          entries: res.findings.map((f) => `[${f.risk.toUpperCase()}] ${f.path} — ${f.matches.map((m) => m.id).join(', ')}`),
        });
      }
      await maybeAiAnalyze('findings', res.findings);
    }
    if (choice === '3') {
      const q = malware.listQuarantine();
      if (!q.length) { console.log(c.dim('  quarantine is empty')); continue; }
      q.forEach((e, i) => console.log(`  ${c.bold('[' + i + ']')} ${e.originalPath} ${c.dim('· ' + e.matches.join(', ') + ' · ' + e.quarantinedAt)}`));
      const idx = await askInt('restore number (Ctrl+C to cancel) ', { min: 0, max: q.length - 1 });
      try {
        const dest = await malware.restoreFromQuarantine(idx);
        console.log(`  ${c.green('✔')} restored to ${dest}`);
      } catch (e) { console.log(`  ${c.lightRed('✗ ' + e.message)}`); }
    }
  }
}

async function networkMenu() {
  const nets = network.getLocalNetworks();
  ui.menuHeader('NETWORK SCAN');
  for (const n of nets) console.log(`  ${c.cyan('◈')} ${n.name} ${c.dim(n.address)} → ${c.bold(n.cidr)}`);
  const gw = await network.defaultGateway();
  if (gw) console.log(`  ${c.gray('default gateway: ' + gw)}`);
  console.log();
  console.log(`  ${c.bold('[1]')} Scan detected subnet`);
  console.log(`  ${c.bold('[2]')} Custom CIDR       ${c.dim('(e.g. 10.0.0.0/24)')}`);
  console.log(`  ${c.bold('[3]')} Deep scan one host ${c.dim('(ports 1-1024 + common)')}`);
  console.log(`  ${c.bold('[0]')} Back`);
  const choice = await ask('❯ ');
  try {
    if (choice === '1' && nets.length) {
      const res = await doNetworkScan(nets[0].cidr);
      if (res && await askConfirm('Save report? [Y/n] ', true)) await saveNetReport(res);
    } else if (choice === '2') {
      const cidr = await ask('CIDR ❯ ');
      const res = await doNetworkScan(cidr);
      if (res && await askConfirm('Save report? [Y/n] ', true)) await saveNetReport(res);
    } else if (choice === '3') {
      const host = await ask('host (IP or hostname) ❯ ');
      if (!host) return;
      const sp = new ui.Spinner(`deep scanning ${host}…`).start();
      const res = await network.deepScanHost(host, { onProgress: (a, b, l) => renderProgress(a, b, l) });
      sp.succeed(`deep scan ${host}`);
      console.log(`  ${res.alive ? c.green('alive') : c.gray('no ping reply')}`);
      const ports = res.openPorts.map((p) => (network.RISKS[p.port] ? c.lightRed(String(p.port)) : c.green(String(p.port)))).join(' ') || c.gray('none');
      console.log(`  open ports: ${ports}`);
      for (const r of res.risks) console.log(`    ${sevColor[r.severity](`[${r.severity.toUpperCase()}]`)} ${c.gray(r.msg)}`);
      if (await askConfirm('Save report? [Y/n] ', true)) {
        await saveReportPrompt('network', {
          title: `Deep host scan — ${host}`,
          durationMs: res.durationMs,
          summary: [`host: ${host} (${res.alive ? 'alive' : 'no ping'})`, `open ports: ${res.openPorts.length}`],
          hosts: [{ ip: host, alive: res.alive, openPorts: res.openPorts, risks: res.risks }],
        });
      }
    }
  } catch (e) { console.log(c.lightRed('  ' + e.message)); }
}

async function doNetworkScan(cidr, opts = {}) {
  const hosts = network.parseCidr(cidr);
  if (hosts.length > 256 && !opts.assumeYes && !(await askConfirm(c.yellow(`${hosts.length} hosts — this can take a while. Continue? [y/N] `), false))) return null;
  const sp = new ui.Spinner('network scan…').start();
  const res = await network.scanNetwork(cidr, { onProgress: (a, b, l) => renderProgress(a, b, l) });
  sp.succeed(`network scan ${cidr}`);
  printNetworkResults(res);
  lastNet = res;
  if (opts.aiPrompt !== false) {
    await maybeAiAnalyze('report', JSON.stringify({ summary: res.summary, hosts: res.hosts.map((h) => ({ ip: h.ip, openPorts: h.openPorts.map((p) => p.port), risks: h.risks })) }, null, 2));
  }
  return res;
}

async function saveNetReport(res) {
  await saveReportPrompt('network', {
    title: `Network scan — ${res.cidr}`,
    durationMs: res.durationMs,
    summary: [
      `subnet: ${res.cidr}`,
      `hosts scanned: ${res.hostsScanned}, alive: ${res.hostsAlive}`,
      `open ports: ${res.summary.openPorts}, high risks: ${res.summary.highRisks}, medium: ${res.summary.medRisks}`,
    ],
    hosts: res.hosts,
  });
}

async function serverFlow(opts = {}) {
  const sp = new ui.Spinner('auditing host…').start();
  const res = await serverAudit.audit();
  sp.succeed('host audit');
  printServerResults(res);
  if (opts.saveReport !== false) {
    await saveReportPrompt('server', {
      title: `Server / host audit — ${res.host}`,
      durationMs: res.durationMs,
      summary: [`${res.checks.length} checks · ${res.counts.pass} pass / ${res.counts.warn} warn / ${res.counts.fail} fail`, res.platform],
      checks: res.checks,
    });
  }
  if (opts.aiPrompt !== false) await maybeAiAnalyze('report', JSON.stringify({ counts: res.counts, checks: res.checks }, null, 2));
  return res;
}

async function adFlow(domainArg, opts = {}) {
  let domain = domainArg;
  if (!domain) {
    const guess = adScanner.guessDomain();
    domain = await ask(`AD domain ${guess ? c.dim(`[${guess}] `) : '(e.g. corp.contoso.com) '}❯ `) || guess;
  }
  if (!domain) { console.log(c.yellow('  no domain given')); return null; }
  const sp = new ui.Spinner(`auditing ${domain}…`).start();
  let res;
  try {
    res = await adScanner.audit(domain, { onPhase: (t) => sp.update(t) });
  } catch (e) {
    sp.fail(e.message);
    return null;
  }
  sp.succeed(`AD audit ${domain}`);
  printAdResults(res);
  if (opts.saveReport !== false) {
    await saveReportPrompt('ad', {
      title: `Active Directory audit — ${res.domain}`,
      durationMs: res.durationMs,
      summary: [`domain: ${res.domain}`, `domain controllers probed: ${res.dcResults.length}`],
      entries: res.risks.map((r) => `[${(r.severity || 'info').toUpperCase()}] ${r.host ? r.host + ': ' : ''}${r.msg}`),
    });
  }
  if (opts.aiPrompt !== false) await maybeAiAnalyze('report', JSON.stringify({ domain: res.domain, risks: res.risks, dcResults: res.dcResults }, null, 2));
  return res;
}

async function fullSystemScan() {
  ui.menuHeader('FULL SYSTEM SCAN');
  console.log(c.dim('  runs: host audit → malware quick scan → network scan (detected subnet)\n'));
  const serverRes = await serverAudit.audit();
  printServerResults(serverRes);

  console.log(`\n${c.bold('▸')} malware quick scan`);
  const paths = malware.quickScanPaths();
  const allFindings = [];
  for (const p of paths) {
    const res = await runMalwareScan(p, { noPrompt: true });
    allFindings.push(...res.findings.map((f) => ({ ...f, path: f.path })));
  }
  if (allFindings.length) await handleFindingsActions({ findings: allFindings });

  let netRes = null;
  const nets = network.getLocalNetworks();
  if (nets.length && await askConfirm('\nscan local subnet too? [Y/n] ', true)) {
    netRes = await doNetworkScan(nets[0].cidr);
  }

  const entries = [
    ...serverRes.checks.map((ch) => `[${ch.status.toUpperCase()}] ${ch.title} — ${ch.detail}`),
    ...allFindings.map((f) => `[${f.risk.toUpperCase()}] ${f.path} — ${f.matches.map((m) => m.id).join(', ')}`),
  ];
  await saveReportPrompt('full', {
    title: 'Full system scan',
    durationMs: serverRes.durationMs,
    summary: [
      `server audit: ${serverRes.counts.pass} pass / ${serverRes.counts.warn} warn / ${serverRes.counts.fail} fail`,
      `malware: ${allFindings.length} findings (${paths.join(', ')})`,
      netRes ? `network: ${netRes.hostsAlive} hosts alive, ${netRes.summary.openPorts} open ports, ${netRes.summary.highRisks} high risks` : 'network: skipped',
    ],
    entries,
    hosts: netRes ? netRes.hosts : [],
    checks: serverRes.checks,
  });
  console.log(`\n${c.greenBold('✔ full scan complete')}`);
}

/* ------------------------------------------------------------------ */
/* AI provider menu                                                    */
/* ------------------------------------------------------------------ */

async function providerMenu(cfg, name) {
  const preset = cfgMod.PROVIDER_PRESETS[name];
  for (;;) {
    const p = cfgMod.getProvider(cfg, name);
    ui.menuHeader(`AI PROVIDER — ${preset.label.toUpperCase()}`);
    console.log(c.dim('  ' + preset.note));
    console.log(`  key      : ${p.key ? c.green(cfgMod.maskKey(p.key)) : c.gray('not set')}`);
    console.log(`  model    : ${c.bold(p.model)}`);
    console.log(`  base URL : ${c.bold(p.baseUrl)}`);
    if (cfg.activeProvider === name) console.log(`  ${c.lightGreen('★ ACTIVE — used for AI detection')}`);
    console.log();
    console.log(`  ${c.bold('[1]')} Set API key`);
    console.log(`  ${c.bold('[2]')} Set model`);
    console.log(`  ${c.bold('[3]')} Set base URL`);
    console.log(`  ${c.bold('[4]')} Clear key`);
    console.log(`  ${c.bold('[5]')} Test connection`);
    if (cfg.activeProvider !== name) console.log(`  ${c.bold('[6]')} Make ACTIVE provider`);
    console.log(`  ${c.bold('[0]')} Back`);
    const choice = await ask('❯ ');
    if (choice === '0' || choice === '') return;
    if (choice === '1') {
      const key = await askHidden('paste API key (input hidden) ❯ ');
      if (key) {
        cfgMod.setProvider(cfg, name, { key });
        if (!cfg.activeProvider) cfgMod.setActive(cfg, name);
        console.log(`  ${c.green('✔')} key saved to ~/.fikrado/config.json`);
      }
    } else if (choice === '2') {
      const m = await ask(`model [${p.model}] ❯ `);
      if (m) { cfgMod.setProvider(cfg, name, { model: m }); console.log(`  ${c.green('✔')} model = ${m}`); }
    } else if (choice === '3') {
      const u = await ask(`base URL [${p.baseUrl}] ❯ `);
      if (u) { cfgMod.setProvider(cfg, name, { baseUrl: u }); console.log(`  ${c.green('✔')} baseUrl = ${u}`); }
    } else if (choice === '4') {
      cfgMod.setProvider(cfg, name, { key: '' });
      console.log(`  ${c.green('✔')} key cleared`);
    } else if (choice === '5') {
      const sp = new ui.Spinner(`contacting ${preset.label}…`).start();
      try {
        const out = await ai.testConnection(cfgMod.getProvider(cfg, name));
        sp.succeed(`${preset.label} replied: ${out.slice(0, 60)}`);
      } catch (e) { sp.fail(e.message); }
    } else if (choice === '6' && cfg.activeProvider !== name) {
      cfgMod.setActive(cfg, name);
      console.log(`  ${c.green('✔')} ${preset.label} is now the active AI provider`);
    }
  }
}

async function aiMenu() {
  const cfg = cfgMod.load();
  for (;;) {
    ui.menuHeader('AI DETECTION SETTINGS');
    const names = cfgMod.providerNames();
    names.forEach((n, i) => {
      const p = cfgMod.getProvider(cfg, n);
      const active = cfg.activeProvider === n ? c.lightGreen(' ★') : '';
      const key = p.key ? c.green(cfgMod.maskKey(p.key)) : c.gray('no key');
      console.log(`  ${c.bold(`[${i + 1}]`)} ${p.label}${active} ${c.dim(p.model)} ${key}`);
    });
    console.log();
    console.log(`  ${c.bold('[t]')} Test active provider`);
    console.log(`  ${c.bold('[x]')} Deactivate AI`);
    console.log(`  ${c.bold('[0]')} Back`);
    console.log(c.dim('\n  keys are stored locally in ~/.fikrado/config.json (chmod 600)'));
    const choice = (await ask('❯ ')).toLowerCase();
    if (choice === '0' || choice === '') return;
    if (choice === 't') {
      const p = cfgMod.getActive(cfg);
      if (!p) { console.log(c.yellow('  no active provider with a key set')); continue; }
      const sp = new ui.Spinner(`contacting ${p.label}…`).start();
      try {
        const out = await ai.testConnection(p);
        sp.succeed(`${p.label} replied: ${out.slice(0, 60)}`);
      } catch (e) { sp.fail(e.message); }
      continue;
    }
    if (choice === 'x') { cfgMod.setActive(cfg, null); console.log(c.green('  ✔ AI detection off')); continue; }
    const idx = Number(choice) - 1;
    if (Number.isInteger(idx) && names[idx]) await providerMenu(cfg, names[idx]);
  }
}

/* ------------------------------------------------------------------ */
/* Reports & about                                                     */
/* ------------------------------------------------------------------ */

async function reportsMenu() {
  for (;;) {
    ui.menuHeader('REPORTS');
    const list = reportMod.listReports();
    if (!list.length) { console.log(c.dim('  no reports yet — run a scan first')); return; }
    list.slice(0, 15).forEach((r, i) => {
      console.log(`  ${c.bold(`[${i + 1}]`)} ${c.gray(r.createdAt || '')} ${c.white(r.title || r.kind)}`);
    });
    console.log(c.dim(`  folder: ${reportMod.reportsDir()}`));
    const choice = await ask(`view number (blank = back) ❯ `);
    if (choice === '' || choice === '0') return;
    const idx = Number(choice) - 1;
    if (!list[idx]) continue;
    try {
      const txt = reportMod.readReportTxt(list[idx].file);
      console.log('');
      for (const line of txt.split('\n')) {
        if (/^\s*\[PASS\]/.test(line)) console.log(c.green(line));
        else if (/^\s*\[WARN\]/.test(line)) console.log(c.yellow(line));
        else if (/^\s*\[FAIL\]/.test(line)) console.log(c.lightRed(line));
        else if (/^\s*\[HIGH\]/.test(line)) console.log(c.lightRed(line));
        else console.log(line);
      }
    } catch (e) { console.log(c.lightRed('  ' + e.message)); }
  }
}

async function aboutMenu() {
  ui.menuHeader('ABOUT');
  console.log(`
  ${c.yellowBold('FIKRADO')} ${c.greenBold('SECURITY')} ${c.dim('v' + pkg.version)}

  Cross-platform terminal security suite — pure Node.js, zero dependencies.

  ${c.bold('Engines')}
   ${c.red('☣')} Malware      signature scanner · quarantine · delete · restore
   ${c.cyan('◈')} Network     subnet discovery · ping sweep · port scan · risk flags
   ${c.green('▤')} Server      hardening audit (Linux / Windows / macOS)
   ${c.blue('▦')} Directory    Active Directory DC discovery · LDAP probes
   ${c.magenta('✦')} AI          OpenRouter · OpenAI · OpenCode Zen · custom endpoints

  ${c.bold('Data')}   ${c.dim('~/.fikrado/ (config.json, reports/, quarantine/)')}

  ${c.yellow('⚠')} Use only on systems you own or are authorized to test.
`);
}

/* ================================================================== */
/* Main                                                                */
/* ================================================================== */

async function interactive() {
  ui.clear();
  await ui.showBanner({ version: pkg.version });
  await ui.bootLines();
  console.log(c.dim(`  host ${os.hostname()} · ${os.type()} ${os.release()} · ${os.userInfo().username} · node ${process.version}`));
  for (;;) {
    console.log(`
${c.yellowBold('┌─ FIKRADO SECURITY ') + c.gray('─'.repeat(Math.max(0, ui.width() - 21))) + c.yellowBold('┐')}
 ${c.bold('[1]')} ${c.lightRed('☣')} Full system scan      ${c.bold('[5]')} ${c.blue('▦')} Active Directory audit
 ${c.bold('[2]')} ${c.lightRed('☣')} Malware scan          ${c.bold('[6]')} ${c.magenta('✦')} AI detection settings
 ${c.bold('[3]')} ${c.cyan('◈')} Network scan          ${c.bold('[7]')} ${c.gray('▤')} Reports
 ${c.bold('[4]')} ${c.green('▤')} Server / host audit   ${c.bold('[8]')} ${c.gray('?')} About
 ${c.bold('[0]')} ${c.gray('✕')} Exit
${c.yellowBold('└') + c.gray('─'.repeat(Math.max(0, ui.width() - 2))) + c.yellowBold('┘')}`);
    const choice = await ask(c.yellowBold('❯ '));
    try {
      if (choice === '0' || choice === 'q' || choice === '') break;
      else if (choice === '1') await fullSystemScan();
      else if (choice === '2') await malwareMenu();
      else if (choice === '3') await networkMenu();
      else if (choice === '4') await serverFlow();
      else if (choice === '5') await adFlow();
      else if (choice === '6') await aiMenu();
      else if (choice === '7') await reportsMenu();
      else if (choice === '8') await aboutMenu();
    } catch (e) {
      console.log(`\n  ${c.lightRed('✗ ' + (e && e.message ? e.message : String(e)))}`);
    }
  }
  console.log(`\n  ${c.greenBold('✔')} ${c.dim('stay secure — ')}${c.yellowBold('FIKRADO')} ${c.greenBold('SECURITY')}${c.dim(' out.')}\n`);
  process.exit(0);
}

/* ================================================================== */
/* Non-interactive CLI                                                 */
/* ================================================================== */

const USAGE = `
${c.yellowBold('FIKRADO')} ${c.greenBold('SECURITY')} v${pkg.version} — terminal security suite

${c.bold('Usage')}
  fikrado                          interactive menu (banner + animated UI)
  fikrado scan [path] [--delete|--quarantine] [--ai] [--no-report]
  fikrado net [cidr] [--deep <host>] [--ai] [--no-report] [--yes]
  fikrado server [--ai] [--no-report]
  fikrado ad <domain> [--ai] [--no-report]
  fikrado full                     host audit + malware + network
  fikrado quarantine [list|restore <n>]

  fikrado keys                     manage AI providers (interactive)
  fikrado keys list
  fikrado keys set <provider> [key]
  fikrado keys model <provider> <model>
  fikrado keys base <provider> <url>
  fikrado keys test [provider]
  fikrado keys off

  fikrado report [list|show <n>|folder]
  fikrado --banner | --help | --version

${c.bold('Providers')}  ${cfgMod.providerNames().join(' · ')}

${c.bold('Options')}
  --ai                          send results to the active AI provider for analysis
  --no-report                   do not write a report file
  --no-anim                     disable animations
  NO_COLOR=1                    disable colors

${c.bold('Examples')}
  fikrado scan /var/www --quarantine
  fikrado keys set openrouter sk-or-v1-...
  fikrado scan ~/Downloads --ai
  fikrado net 192.168.1.0/24
  fikrado net --deep 10.0.0.5
  fikrado ad corp.contoso.com
`;

function providerOrThrow(name) {
  const preset = cfgMod.PROVIDER_PRESETS[name];
  if (!preset) {
    throw new Error(`unknown provider "${name}" — choose one of: ${cfgMod.providerNames().join(', ')}`);
  }
  return preset;
}

async function aiForCli(kind, data) {
  const cfg = cfgMod.load();
  if (!cfgMod.getActive(cfg)) {
    console.log(c.yellow('  --ai: no provider configured — run "fikrado keys set openrouter [key]" first'));
    return;
  }
  await aiAnalyze(kind, data);
}

async function keysCmd(args) {
  const cfg = cfgMod.load();
  const names = cfgMod.providerNames();
  const sub = (args[0] || 'menu').toLowerCase();

  if (sub === 'menu' || sub === 'interactive') return aiMenu();

  if (sub === 'list' || sub === 'ls') {
    console.log(`\n${c.yellowBold('AI PROVIDERS')}`);
    for (const n of names) {
      const p = cfgMod.getProvider(cfg, n);
      const star = cfg.activeProvider === n ? c.lightGreen('★ active') : c.gray('—');
      const key = p.key ? c.green(cfgMod.maskKey(p.key)) : c.gray('no key');
      console.log(`  ${c.bold(n.padEnd(11))} ${key.padEnd(28)} ${c.dim(p.model)}  ${star}`);
    }
    console.log(c.dim(`\n  config: ${cfgMod.CONFIG_FILE}\n`));
    return;
  }

  if (sub === 'off' || sub === 'disable' || sub === 'deactivate') {
    cfgMod.setActive(cfg, null);
    console.log(`  ${c.green('✔')} AI detection disabled`);
    return;
  }

  if (sub === 'test') {
    const name = args[1] || cfg.activeProvider;
    if (!name) throw new Error('no active provider — run: fikrado keys set <provider> [key]');
    providerOrThrow(name);
    const p = cfgMod.getProvider(cfg, name);
    if (!p.key) throw new Error(`no API key set for ${p.label}`);
    const sp = new ui.Spinner(`contacting ${p.label} (${p.model})…`).start();
    const out = await ai.testConnection(p);
    sp.succeed(`${p.label} replied: ${String(out).replace(/\s+/g, ' ').slice(0, 70)}`);
    return;
  }

  if (sub === 'set' || sub === 'add') {
    const name = args[1];
    if (!name) throw new Error(`usage: fikrado keys set <${names.join('|')}> [key]`);
    const preset = providerOrThrow(name);
    let key = args[2];
    if (!key) key = await askHidden(`paste ${preset.label} API key (hidden) ❯ `);
    if (!key) throw new Error('no key entered');
    cfgMod.setProvider(cfg, name, { key });
    if (!cfg.activeProvider) cfgMod.setActive(cfg, name);
    console.log(`  ${c.green('✔')} ${preset.label} key saved (${cfgMod.maskKey(key)}) → ${cfgMod.CONFIG_FILE}`);
    return;
  }

  if (sub === 'model') {
    const name = args[1];
    if (!name || !args[2]) throw new Error('usage: fikrado keys model <provider> <model>');
    providerOrThrow(name);
    cfgMod.setProvider(cfg, name, { model: args[2] });
    console.log(`  ${c.green('✔')} ${name} model = ${args[2]}`);
    return;
  }

  if (sub === 'base' || sub === 'url') {
    const name = args[1];
    if (!name || !args[2]) throw new Error('usage: fikrado keys base <provider> <url>');
    providerOrThrow(name);
    cfgMod.setProvider(cfg, name, { baseUrl: args[2] });
    console.log(`  ${c.green('✔')} ${name} baseUrl = ${args[2]}`);
    return;
  }

  if (sub === 'clear' || sub === 'remove' || sub === 'unset') {
    const name = args[1];
    if (!name) throw new Error('usage: fikrado keys clear <provider>');
    providerOrThrow(name);
    cfgMod.setProvider(cfg, name, { key: '' });
    console.log(`  ${c.green('✔')} ${name} key cleared`);
    return;
  }

  throw new Error(`unknown keys subcommand "${sub}" — try: list | set | model | base | test | off`);
}

async function runCli(argv) {
  const [cmd, ...rest] = argv;
  const flags = rest.filter((a) => a.startsWith('--'));
  const args = rest.filter((a) => !a.startsWith('--'));
  const has = (f) => flags.includes(f);

  if (has('--no-anim') || has('--no-animation')) process.env.FIKRADO_NO_ANIM = '1';

  if (!cmd || cmd === 'menu' || cmd === 'interactive') return interactive();

  if (cmd === '-h' || cmd === '--help' || cmd === 'help') { console.log(USAGE); return; }
  if (cmd === '-V' || cmd === '--version' || cmd === 'version') { console.log(pkg.version); return; }

  if (cmd === '--banner') {
    await ui.showBanner({ version: pkg.version, anim: !has('--static') });
    return;
  }

  if (cmd === 'scan') {
    await ui.showBanner({ version: pkg.version, anim: false });
    const target = args[0] || process.cwd();
    if (!fs.existsSync(target)) throw new Error(`path not found: ${target}`);
    const res = await runMalwareScan(target, { noPrompt: true });
    if (res.findings.length && (has('--delete') || has('--quarantine'))) {
      const sp = new ui.Spinner('removing threats…').start();
      let i = 0;
      for (const f of res.findings) {
        try {
          if (has('--delete')) await malware.deleteFinding(f);
          else await malware.quarantineFinding(f, i++);
        } catch (e) { console.log(c.lightRed(`  ✗ ${f.path}: ${e.message}`)); }
      }
      sp.succeed(`threats ${has('--delete') ? 'deleted' : 'quarantined'}: ${res.findings.length}`);
    }
    if (!has('--no-report')) {
      await saveReportPrompt('malware', {
        title: `Malware scan — ${res.root}`,
        root: res.root,
        durationMs: res.durationMs,
        filesScanned: res.filesScanned,
        summary: [`files scanned: ${res.filesScanned}`, `threats: ${res.findings.length}`],
        entries: res.findings.map((f) => `[${f.risk.toUpperCase()}] ${f.path} — ${f.matches.map((m) => m.id).join(', ')}`),
      });
    }
    if (has('--ai')) await aiForCli('findings', res.findings);
    if (res.findings.length) process.exitCode = 2;
    return;
  }

  if (cmd === 'net') {
    await ui.showBanner({ version: pkg.version, anim: false });
    if (has('--deep')) {
      const host = args[0];
      if (!host) throw new Error('net --deep needs a host, e.g. fikrado net --deep 10.0.0.5');
      const sp = new ui.Spinner(`deep scanning ${host}…`).start();
      const res = await network.deepScanHost(host, { onProgress: (a, b, l) => renderProgress(a, b, l) });
      sp.succeed(`deep scan ${host}`);
      console.log(`  ${res.alive ? c.green('alive') : c.gray('no ping reply')}`);
      console.log(`  open ports: ${res.openPorts.map((p) => p.port).join(' ') || c.gray('none')}`);
      for (const r of res.risks) console.log(`    ${sevColor[r.severity](`[${r.severity.toUpperCase()}]`)} ${c.gray(r.msg)}`);
      if (!has('--no-report')) {
        await saveReportPrompt('network', {
          title: `Deep host scan — ${host}`,
          durationMs: res.durationMs,
          summary: [`host: ${host} (${res.alive ? 'alive' : 'no ping'})`, `open ports: ${res.openPorts.length}`],
          hosts: [{ ip: host, alive: res.alive, openPorts: res.openPorts, risks: res.risks }],
        });
      }
      if (has('--ai')) await aiForCli('report', JSON.stringify({ host, alive: res.alive, openPorts: res.openPorts, risks: res.risks }, null, 2));
      return;
    }
    const cidr = args[0] || (network.getLocalNetworks()[0] || {}).cidr;
    if (!cidr) throw new Error('could not auto-detect a subnet — pass a CIDR, e.g. fikrado net 192.168.1.0/24');
    const res = await doNetworkScan(cidr, { aiPrompt: false, assumeYes: has('--yes') });
    if (!res) { console.log(c.yellow('  scan cancelled')); return; }
    if (!has('--no-report')) await saveNetReport(res);
    if (has('--ai')) {
      await aiForCli('report', JSON.stringify({ summary: res.summary, hosts: res.hosts.map((h) => ({ ip: h.ip, openPorts: h.openPorts.map((p) => p.port), risks: h.risks })) }, null, 2));
    }
    return;
  }

  if (cmd === 'server') {
    await ui.showBanner({ version: pkg.version, anim: false });
    const res = await serverFlow({ saveReport: !has('--no-report'), aiPrompt: false });
    if (has('--ai')) await aiForCli('report', JSON.stringify({ counts: res.counts, checks: res.checks }, null, 2));
    if (res.counts.fail) process.exitCode = 2;
    return;
  }

  if (cmd === 'ad') {
    await ui.showBanner({ version: pkg.version, anim: false });
    if (!args[0]) throw new Error('usage: fikrado ad <domain>   (e.g. fikrado ad corp.contoso.com)');
    const res = await adFlow(args[0], { saveReport: !has('--no-report'), aiPrompt: false });
    if (has('--ai') && res) await aiForCli('report', JSON.stringify({ domain: res.domain, risks: res.risks, dcResults: res.dcResults }, null, 2));
    return;
  }

  if (cmd === 'full') {
    await ui.showBanner({ version: pkg.version, anim: false });
    await fullSystemScan();
    return;
  }

  if (cmd === 'keys' || cmd === 'ai') {
    return keysCmd(args);
  }

  if (cmd === 'quarantine') {
    const sub = (args[0] || 'list').toLowerCase();
    const q = malware.listQuarantine();
    if (sub === 'list' || sub === 'ls') {
      if (!q.length) { console.log(c.dim('  quarantine is empty')); return; }
      q.forEach((e, i) => console.log(`  ${c.bold('[' + (i + 1) + ']')} ${e.originalPath} ${c.dim('· ' + e.matches.join(', ') + ' · ' + e.quarantinedAt)}`));
      console.log(c.dim(`  folder: ${cfgMod.QUARANTINE_DIR}`));
      return;
    }
    if (sub === 'restore') {
      const idx = Number(args[1]) - 1;
      if (!Number.isInteger(idx) || !q[idx]) throw new Error('usage: fikrado quarantine restore <number>   (see "fikrado quarantine list")');
      const dest = await malware.restoreFromQuarantine(idx);
      console.log(`  ${c.green('✔')} restored to ${dest}`);
      return;
    }
    throw new Error('usage: fikrado quarantine [list|restore <n>]');
  }

  if (cmd === 'report' || cmd === 'reports') {
    const list = reportMod.listReports();
    if (args[0] === 'list' || !args[0]) {
      if (!list.length) { console.log(c.dim('  no reports yet — run a scan first')); return; }
      list.forEach((r, i) => console.log(`  [${i + 1}] ${r.createdAt || ''}  ${r.title || r.kind}`));
      console.log(c.dim(`  folder: ${reportMod.reportsDir()}`));
      return;
    }
    if (args[0] === 'folder' || args[0] === 'dir') { console.log(reportMod.reportsDir()); return; }
    if (args[0] === 'show') {
      const idx = Number(args[1]) - 1;
      if (!list[idx]) throw new Error('no such report number — run "fikrado report list"');
      console.log(reportMod.readReportTxt(list[idx].file));
      return;
    }
  }

  console.log(USAGE);
  process.exitCode = 1;
}

module.exports = { runCli, interactive };

if (require.main === module) {
  runCli(process.argv.slice(2)).catch((e) => {
    process.stderr.write(String((e && e.stack) || e) + '\n');
    process.exit(1);
  });
}
