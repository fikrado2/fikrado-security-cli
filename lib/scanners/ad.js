'use strict';

/*
 * Fikrado Security — Active Directory audit engine
 * Domain-controllers discovery via DNS SRV records, service-port posture
 * (Kerberos/LDAP/LDAPS/SMB/GC), and an anonymous LDAP-bind probe built on
 * a raw BER-encoded LDAP bind (zero dependencies).
 */

const net = require('net');
const dns = require('dns').promises;
const os = require('os');

const DC_PORTS = [
  { port: 88,   name: 'Kerberos' },
  { port: 389,  name: 'LDAP' },
  { port: 636,  name: 'LDAPS (LDAP over TLS)' },
  { port: 445,  name: 'SMB' },
  { port: 464,  name: 'Kerberos password change' },
  { port: 3268, name: 'Global Catalog' },
  { port: 3269, name: 'Global Catalog over TLS' },
];

const LDAP_RESULT_NAMES = {
  0: 'success',
  1: 'operationsError',
  8: 'insufficientAccessRights',
  14: 'saslBindInProgress',
  48: 'invalidCredentials',
  49: 'invalidCredentials',
  53: 'unwillingToPerform',
  7: 'authMethodNotSupported',
};

function checkPort(host, port, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const s = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      s.destroy();
      resolve(open);
    };
    s.setTimeout(timeoutMs);
    s.once('connect', () => finish(true));
    s.once('timeout', () => finish(false));
    s.once('error', () => finish(false));
    try { s.connect(port, host); } catch { finish(false); }
  });
}

/* Minimal BER: LDAPMessage ::= SEQUENCE { messageID, bindRequest }
 * bindRequest ::= [APPLICATION 0] SEQUENCE { version INTEGER 3,
 *   name LDAPDN "", authentication [0] OCTET STRING "" }  (anonymous)   */
const ANON_BIND = Buffer.from([
  0x30, 0x0c,       // SEQUENCE, len 12
  0x02, 0x01, 0x01, // messageID = 1
  0x60, 0x07,       // bindRequest [APPLICATION 0], len 7
  0x02, 0x01, 0x03, // version = 3
  0x04, 0x00,       // name = ""
  0x80, 0x00,       // simple auth = ""
]);

function parseLdapBindResponse(buf) {
  try {
    if (!buf || buf.length < 10 || buf[0] !== 0x30) return null;
    let pos = 2;                       // skip SEQUENCE header (len < 128 assumed)
    if (buf[pos] !== 0x02) return null;
    pos += 3;                          // messageID
    if (buf[pos] !== 0x61) return null; // bindResponse [APPLICATION 1]
    pos += 2;                          // tag + len
    if (buf[pos] !== 0x0a) return null; // resultCode ENUMERATED
    pos += 1;
    const l = buf[pos];
    pos += 1;
    let code = 0;
    for (let i = 0; i < l && pos + i < buf.length; i++) code = (code << 8) | buf[pos + i];
    return code;
  } catch {
    return null;
  }
}

function ldapAnonymousBind(host, timeoutMs = 4000) {
  return new Promise((resolve) => {
    const s = new net.Socket();
    let buf = Buffer.alloc(0);
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      s.destroy();
      resolve(result);
    };
    s.setTimeout(timeoutMs);
    s.once('connect', () => s.write(ANON_BIND));
    s.once('data', (d) => {
      buf = Buffer.concat([buf, d]);
      const code = parseLdapBindResponse(buf);
      if (code !== null) finish({ ok: true, code, name: LDAP_RESULT_NAMES[code] || `code ${code}` });
    });
    s.once('timeout', () => finish({ ok: false, error: 'timeout' }));
    s.once('error', (e) => finish({ ok: false, error: e.code || e.message }));
    try { s.connect(389, host); } catch (e) { finish({ ok: false, error: String(e) }); }
  });
}

async function discoverDcs(domain, log = () => {}) {
  const attempts = [
    `_ldap._tcp.dc._msdcs.${domain}`,
    `_ldap._tcp.${domain}`,
  ];
  for (const q of attempts) {
    try {
      log(`DNS SRV lookup ${q}`);
      const srv = await dns.resolveSrv(q);
      if (srv && srv.length) {
        return srv.map((r) => ({ host: r.name, priority: r.priority, weight: r.weight }));
      }
    } catch { /* try next */ }
  }
  // Fallback: does the domain at least resolve?
  try {
    const addrs = await dns.resolve4(domain);
    if (addrs.length) return [{ host: domain, priority: 0, weight: 0, fallback: true }];
  } catch { /* nothing */ }
  return [];
}

function guessDomain() {
  if (process.platform === 'win32' && process.env.USERDOMAIN && !/^WORKGROUP$/i.test(process.env.USERDOMAIN)) {
    return process.env.USERDOMAIN;
  }
  if (process.platform === 'win32' && process.env.USERDNSDOMAIN) return process.env.USERDNSDOMAIN;
  const host = os.hostname();
  if (host && host.includes('.') && !host.endsWith('.local') && !/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    return host.split('.').slice(1).join('.');
  }
  return null;
}

async function audit(domain, opts = {}) {
  const started = Date.now();
  const log = opts.onPhase || (() => {});
  const risks = [];
  const info = [];

  if (!domain || !/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(domain)) {
    throw new Error('Invalid or missing domain name (e.g. corp.example.com)');
  }

  log(`discovering domain controllers for ${domain}`);
  const dcs = await discoverDcs(domain, log);
  if (!dcs.length) {
    return {
      domain,
      durationMs: Date.now() - started,
      dcs: [],
      dcResults: [],
      risks: [{ severity: 'info', msg: `No SRV records or A records found for ${domain} — is this the right domain, and are you on a network that hosts it?` }],
      info,
    };
  }
  if (dcs.some((d) => d.fallback)) {
    info.push(`${domain} resolves via A record but no _ldap SRV records — may not be an Active Directory domain.`);
  }

  const dcResults = [];
  for (const dc of dcs.slice(0, 5)) {
    log(`probing ${dc.host}`);
    const ports = [];
    for (const p of DC_PORTS) {
      const open = await checkPort(dc.host, p.port);
      ports.push({ port: p.port, service: p.name, open });
    }
    const anon = await ldapAnonymousBind(dc.host);
    dcResults.push({ host: dc.host, ports, anonymousBind: anon });

    if (!ports.find((p) => p.port === 389).open && !ports.find((p) => p.port === 636).open) {
      risks.push({ severity: 'warn', host: dc.host, msg: 'No LDAP/LDAPS reachable — not acting as a DC from here (or firewalled).' });
    }
    const ldaps = ports.find((p) => p.port === 636);
    if (!ldaps.open) {
      risks.push({ severity: 'med', host: dc.host, msg: 'LDAPS (636) closed — directory traffic may travel unencrypted on 389.' });
    }
    if (anon.ok && anon.code === 0) {
      risks.push({ severity: 'high', host: dc.host, msg: 'Anonymous LDAP bind ACCEPTED — anyone can connect without credentials (enumerate users/groups depending on dSHeuristics).' });
    } else if (anon.ok) {
      info.push(`${dc.host}: anonymous bind rejected (${anon.name}) — good.`);
    }
    if (ports.find((p) => p.port === 445).open) {
      risks.push({ severity: 'info', host: dc.host, msg: 'SMB (445) reachable — normal for a DC; keep it patched (EternalBlue, SMBGhost).' });
    }
    if (!ports.find((p) => p.port === 88).open) {
      risks.push({ severity: 'warn', host: dc.host, msg: 'Kerberos (88) not reachable from this host.' });
    }
  }

  return {
    domain,
    durationMs: Date.now() - started,
    dcs,
    dcResults,
    risks,
    info,
  };
}

module.exports = { audit, guessDomain, discoverDcs, ldapAnonymousBind };
