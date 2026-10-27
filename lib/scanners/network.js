'use strict';

/*
 * Fikrado Security — network scanner engine
 * Subnet discovery, cross-platform ping sweep, TCP port scan, risk flags.
 */

const os = require('os');
const net = require('net');
const dns = require('dns').promises;
const { execFile } = require('child_process');

const SERVICES = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 67: 'dhcp',
  69: 'tftp', 80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
  139: 'netbios-ssn', 143: 'imap', 389: 'ldap', 443: 'https', 445: 'microsoft-ds',
  465: 'smtps', 500: 'isakmp', 514: 'syslog', 587: 'submission', 636: 'ldaps',
  993: 'imaps', 995: 'pop3s', 1080: 'socks', 1433: 'mssql', 1723: 'pptp',
  1900: 'upnp', 2049: 'nfs', 2375: 'docker-api', 2376: 'docker-tls',
  3306: 'mysql', 3389: 'rdp', 5432: 'postgres', 5601: 'kibana', 5900: 'vnc',
  5985: 'winrm-http', 5986: 'winrm-https', 6379: 'redis', 7547: 'tr069',
  8080: 'http-alt', 8443: 'https-alt', 8888: 'http-alt2', 9200: 'elasticsearch',
  11211: 'memcached', 27017: 'mongodb', 27018: 'mongodb',
  873: 'rsync', 3128: 'squid',
};

const RISKS = {
  21:    ['med',   'FTP exposed — plaintext protocol'],
  23:    ['high',  'Telnet exposed — plaintext credentials'],
  69:    ['high',  'TFTP exposed — often unauthenticated'],
  135:   ['med',   'MSRPC exposed to the network'],
  139:   ['med',   'NetBIOS exposed'],
  445:   ['med',   'SMB exposed — verify patching & sharing rules'],
  873:   ['med',   'rsync exposed'],
  1433:  ['med',   'MSSQL exposed'],
  1723:  ['med',   'PPTP VPN exposed — legacy protocol'],
  2375:  ['high',  'Docker API exposed unauthenticated — full host takeover risk'],
  3128:  ['med',  'Proxy (squid) exposed'],
  3306:  ['high',  'MySQL exposed to the network'],
  3389:  ['med',   'RDP exposed — require NLA & strong passwords'],
  5432:  ['high',  'PostgreSQL exposed to the network'],
  5601:  ['med',   'Kibana exposed'],
  5900:  ['high',  'VNC exposed — often weakly authenticated'],
  5985:  ['med',   'WinRM over plaintext HTTP'],
  6379:  ['high',  'Redis exposed — commonly unauthenticated'],
  7547:  ['high',  'TR-069 CWMP exposed — router compromise vector'],
  8080:  ['low',   'HTTP-alt open — verify what serves this'],
  9200:  ['high',  'Elasticsearch exposed — commonly unauthenticated'],
  11211: ['high',  'Memcached exposed — amplification DDoS risk'],
  27017: ['high',  'MongoDB exposed — commonly unauthenticated'],
};

const TOP_PORTS = Object.keys(SERVICES).map(Number).sort((a, b) => a - b);

/* ------------------------------------------------------------------ */

function exec(cmd, args, timeoutMs = 6000) {
  return new Promise((resolve) => {
    try {
      execFile(cmd, args, { timeout: timeoutMs, windowsHide: true }, (err, stdout, stderr) => {
        resolve({ code: err ? (err.code === undefined ? 1 : err.code) : 0, stdout: String(stdout || ''), stderr: String(stderr || '') });
      });
    } catch {
      resolve({ code: 1, stdout: '', stderr: 'exec failed' });
    }
  });
}

async function ping(host) {
  const plat = process.platform;
  let args;
  if (plat === 'win32') args = ['-n', '1', '-w', '1200', host];
  else if (plat === 'darwin') args = ['-c', '1', '-W', '1200', host];
  else args = ['-c', '1', '-W', '1', host];
  const { code } = await exec('ping', args, 4000);
  return code === 0;
}

function checkPort(host, port, timeoutMs = 900) {
  return new Promise((resolve) => {
    const s = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      s.destroy();
      resolve(open ? port : null);
    };
    s.setTimeout(timeoutMs);
    s.once('connect', () => finish(true));
    s.once('timeout', () => finish(false));
    s.once('error', () => finish(false));
    try { s.connect(port, host); } catch { finish(false); }
  });
}

async function pool(items, limit, worker) {
  return new Promise((resolve, reject) => {
    const results = new Array(items.length);
    let i = 0, active = 0, finished = false;
    const next = () => {
      if (finished) return;
      if (i >= items.length && active === 0) {
        finished = true;
        resolve(results);
        return;
      }
      while (active < limit && i < items.length) {
        const idx = i++;
        active++;
        Promise.resolve(worker(items[idx], idx))
          .then((r) => { results[idx] = r; })
          .catch((e) => { results[idx] = { error: String((e && e.message) || e) }; })
          .finally(() => { active--; next(); });
      }
    };
    next();
  });
}

/* ------------------------------------------------------------------ */
/* CIDR / subnet helpers                                               */
/* ------------------------------------------------------------------ */

function ipToInt(ip) {
  return ip.split('.').reduce((a, o) => ((a << 8) + Number(o)) >>> 0, 0);
}
function intToIp(n) {
  return [24, 16, 8, 0].map((sh) => (n >>> sh) & 255).join('.');
}

function parseCidr(cidr) {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(String(cidr).trim());
  if (!m) throw new Error(`Invalid CIDR: ${cidr} (expected e.g. 192.168.1.0/24)`);
  const prefix = Number(m[2]);
  if (prefix < 8 || prefix > 32) throw new Error(`Invalid prefix /${prefix}`);
  const base = ipToInt(m[1]);
  const size = 2 ** (32 - prefix);
  // reject oversized ranges *before* allocating anything
  const count = prefix === 32 ? 1 : Math.max(0, size - 2);
  if (count > 4096) throw new Error(`Subnet /${prefix} is too large (${count} hosts). Max 4096.`);
  const hosts = [];
  const start = prefix === 32 ? base : base + 1;
  const end = prefix === 32 ? base : base + size - 2;
  for (let n = start; n <= end; n++) hosts.push(intToIp(n));
  return hosts;
}

function maskToPrefix(mask) {
  return mask
    .split('.')
    .map((o) => (Number(o) >>> 0).toString(2).replace(/0/g, '').length)
    .reduce((a, b) => a + b, 0);
}

function getLocalNetworks() {
  const out = [];
  const ifaces = os.networkInterfaces();
  for (const [name, addrs] of Object.entries(ifaces)) {
    for (const a of addrs || []) {
      if (a.family !== 'IPv4' || a.internal || !a.address) continue;
      const prefix = a.netmask ? maskToPrefix(a.netmask) : 24;
      out.push({
        name,
        address: a.address,
        netmask: a.netmask,
        prefix,
        cidr: `${intToIp(ipToInt(a.address) & (0xffffffff << (32 - prefix)))}/${prefix}`,
      });
    }
  }
  return out;
}

async function defaultGateway() {
  if (process.platform === 'linux') {
    const { stdout } = await exec('ip', ['route', 'show', 'default']);
    const m = /via (\d+\.\d+\.\d+\.\d+)/.exec(stdout);
    if (m) return m[1];
  }
  if (process.platform === 'darwin') {
    const { stdout } = await exec('netstat', ['-rn']);
    const m = /^default\s+(\d+\.\d+\.\d+\.\d+)/m.exec(stdout);
    if (m) return m[1];
  }
  if (process.platform === 'win32') {
    // Windows netstat prints:  0.0.0.0   0.0.0.0   <gateway>   <iface-ip>   <metric>
    const { stdout } = await exec('netstat', ['-rn']);
    for (const line of stdout.split('\n')) {
      const m = /^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)/.exec(line);
      if (m) return m[1];
    }
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* Scans                                                               */
/* ------------------------------------------------------------------ */

async function scanNetwork(cidr, opts = {}) {
  const started = Date.now();
  const onProgress = opts.onProgress || (() => {});
  const hosts = parseCidr(cidr);

  onProgress(0, hosts.length, 'discovering hosts (ping sweep)');
  let done = 0;
  const aliveResults = await pool(hosts, 64, async (ip) => {
    const alive = await ping(ip);
    done++;
    onProgress(done, hosts.length, `ping ${ip}`);
    return { ip, alive };
  });

  const live = aliveResults.filter((h) => h && h.alive).map((h) => h.ip);

  const results = [];
  let hostIdx = 0;
  await pool(live, 8, async (ip) => {
    const ports = await pool(TOP_PORTS, 24, (p) => checkPort(ip, p, 800));
    const openPorts = ports.filter(Boolean).map((p) => ({ port: p, service: SERVICES[p] || '?' }));
    const risks = openPorts
      .map((p) => (RISKS[p.port] ? { port: p.port, severity: RISKS[p.port][0], msg: `${p.service} (:${p.port}) — ${RISKS[p.port][1]}` } : null))
      .filter(Boolean);
    let names = [];
    if (opts.resolveNames) {
      try { names = await dns.reverse(ip); } catch { names = []; }
    }
    hostIdx++;
    onProgress(hostIdx, live.length, `port scan ${ip}`);
    results.push({
      ip,
      alive: true,
      names,
      openPorts,
      risks,
    });
  });

  results.sort((a, b) => ipToInt(a.ip) - ipToInt(b.ip));
  return {
    cidr,
    startedAt: new Date(started).toISOString(),
    durationMs: Date.now() - started,
    hostsScanned: hosts.length,
    hostsAlive: live.length,
    hosts: results,
    summary: {
      scanned: hosts.length,
      alive: live.length,
      openPorts: results.reduce((a, h) => a + h.openPorts.length, 0),
      highRisks: results.reduce((a, h) => a + h.risks.filter((r) => r.severity === 'high').length, 0),
      medRisks: results.reduce((a, h) => a + h.risks.filter((r) => r.severity === 'med').length, 0),
    },
  };
}

async function deepScanHost(host, opts = {}) {
  const started = Date.now();
  const onProgress = opts.onProgress || (() => {});
  const alive = await ping(host);
  let ports = [];
  if (alive) {
    const full = [];
    for (let p = 1; p <= 1024; p++) full.push(p);
    for (const p of TOP_PORTS) if (p > 1024) full.push(p);
    let done = 0;
    const open = await pool(full, 128, async (p) => {
      const r = await checkPort(host, p, 500);
      done++;
      if (done % 64 === 0) onProgress(done, full.length, `port ${p}`);
      return r;
    });
    ports = open.filter(Boolean).map((p) => ({ port: p, service: SERVICES[p] || '?' }));
  }
  const risks = ports
    .map((p) => (RISKS[p.port] ? { port: p.port, severity: RISKS[p.port][0], msg: `${p.service} (:${p.port}) — ${RISKS[p.port][1]}` } : null))
    .filter(Boolean);
  return {
    host,
    alive,
    durationMs: Date.now() - started,
    openPorts: ports,
    risks,
  };
}

module.exports = {
  parseCidr, getLocalNetworks, defaultGateway, ping, checkPort,
  scanNetwork, deepScanHost, TOP_PORTS, SERVICES, RISKS,
};
