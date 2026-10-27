'use strict';

/*
 * Fikrado Security — server / host audit engine
 * Cross-platform hardening checks: Linux, Windows, macOS.
 * Every check is defensive (read-only) and fails soft ("skip") if a
 * command or file is unavailable on this platform.
 */

const os = require('os');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { execFile } = require('child_process');

function exec(cmd, args, timeoutMs = 12000) {
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

function safeRead(p) {
  try { return fs.readFileSync(p, 'utf8'); } catch { return null; }
}

function check(id, title, platform, run) {
  return { id, title, platform, run };
}

/* ------------------------------------------------------------------ */
/* Check definitions                                                   */
/* ------------------------------------------------------------------ */

const CHECKS = [

  /* ---------------- Linux ---------------- */
  check('ssh-root-login', 'SSH: root login', 'linux', async () => {
    const txt = safeRead('/etc/ssh/sshd_config');
    if (txt === null) return { status: 'skip', detail: 'sshd_config not present (no SSH server?)' };
    const m = /^PermitRootLogin\s+(\S+)/mi.exec(txt);
    if (!m) return { status: 'pass', detail: 'not set (default prohibit-password on modern distros)' };
    const v = m[1].toLowerCase();
    if (v === 'yes') return { status: 'fail', detail: 'PermitRootLogin yes — root can SSH directly', advice: 'Set "PermitRootLogin no" (or prohibit-password) in /etc/ssh/sshd_config and restart sshd.' };
    return { status: 'pass', detail: `PermitRootLogin ${v}` };
  }),

  check('ssh-password-auth', 'SSH: password authentication', 'linux', async () => {
    const txt = safeRead('/etc/ssh/sshd_config');
    if (txt === null) return { status: 'skip', detail: 'sshd_config not present' };
    const m = /^PasswordAuthentication\s+(\S+)/mi.exec(txt);
    if (!m) return { status: 'warn', detail: 'not set — most distros default to yes', advice: 'Set "PasswordAuthentication no" and use SSH keys.' };
    if (m[1].toLowerCase() === 'no') return { status: 'pass', detail: 'key-based only' };
    return { status: 'warn', detail: 'PasswordAuthentication yes — brute-forceable', advice: 'Switch to key-based auth; at minimum install fail2ban.' };
  }),

  check('shadow-perms', '/etc/shadow permissions', 'linux', async () => {
    try {
      const st = fs.statSync('/etc/shadow');
      const others = st.mode & 0o007;
      if (st.uid !== 0) return { status: 'fail', detail: 'owned by non-root user', advice: 'chown root:root /etc/shadow && chmod 600 /etc/shadow (or 640 shadow-group).' };
      if (others !== 0) return { status: 'fail', detail: `readable by others (mode ${st.mode.toString(8)})`, advice: 'chmod 600 /etc/shadow.' };
      return { status: 'pass', detail: `mode ${st.mode.toString(8)} root-owned` };
    } catch { return { status: 'skip', detail: 'cannot stat /etc/shadow' }; }
  }),

  check('uid0-accounts', 'Accounts with UID 0', 'linux', async () => {
    const txt = safeRead('/etc/passwd');
    if (!txt) return { status: 'skip', detail: 'no /etc/passwd' };
    const roots = txt.split('\n').filter(Boolean).map((l) => l.split(':')).filter((f) => f[2] === '0').map((f) => f[0]);
    if (roots.length > 1) return { status: 'fail', detail: `UID-0 accounts: ${roots.join(', ')}`, advice: 'Only "root" should have UID 0 — investigate the others.' };
    return { status: 'pass', detail: 'only root' };
  }),

  check('empty-passwords', 'Accounts with empty passwords', 'linux', async () => {
    const txt = safeRead('/etc/shadow');
    if (!txt) return { status: 'info', detail: 'run as root/sudo to check password hashes' };
    const bad = txt.split('\n').filter(Boolean).map((l) => l.split(':')).filter((f) => f[1] === '').map((f) => f[0]);
    if (bad.length) return { status: 'fail', detail: `empty passwords: ${bad.join(', ')}`, advice: 'Lock them: usermod -L <user> or set a password.' };
    return { status: 'pass', detail: 'none' };
  }),

  check('world-writable-etc', 'World-writable files in /etc', 'linux', async () => {
    const found = [];
    async function walkDir(dir, depth) {
      if (depth > 3 || found.length >= 50) return;
      let entries;
      try { entries = await fsp.readdir(dir, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        const p = `${dir}/${e.name}`;
        if (e.isDirectory()) await walkDir(p, depth + 1);
        else if (e.isFile()) {
          try {
            const st = await fsp.stat(p);
            if (st.mode & 0o002) found.push(p);
          } catch { /* ignore */ }
        }
      }
    }
    await walkDir('/etc', 0);
    if (found.length) return { status: 'warn', detail: `${found.length} world-writable (showing up to 5): ${found.slice(0, 5).join(', ')}`, advice: 'Remove write bits: chmod o-w <file>.' };
    return { status: 'pass', detail: 'none' };
  }),

  check('suid-binaries', 'SUID binaries (informational)', 'linux', async () => {
    const { stdout } = await exec('find', ['/usr/bin', '/usr/sbin', '/usr/local/bin', '-maxdepth', '1', '-perm', '-4000', '-type', 'f'], 8000);
    const list = stdout.split('\n').filter(Boolean);
    return { status: 'info', detail: `${list.length} SUID binaries: ${list.slice(0, 6).map((l) => l.split('/').pop()).join(', ')}${list.length > 6 ? '…' : ''}` };
  }),

  check('firewall', 'Firewall status', 'linux', async () => {
    const ufw = await exec('systemctl', ['is-active', 'ufw'], 6000);
    if (ufw.code === 0) {
      const st = await exec('ufw', ['status'], 6000);
      if (/Status:\s+active/i.test(st.stdout)) return { status: 'pass', detail: 'ufw active' };
      return { status: 'fail', detail: 'ufw service running but firewall reports inactive', advice: 'sudo ufw enable' };
    }
    const fwd = await exec('firewall-cmd', ['--state'], 6000);
    if (/running/i.test(fwd.stdout)) return { status: 'pass', detail: 'firewalld running' };
    const ipt = await exec('sh', ['-c', 'iptables -S 2>/dev/null | head -5'], 6000);
    if (ipt.stdout.trim().length > 20) return { status: 'pass', detail: 'iptables rules present' };
    return { status: 'fail', detail: 'no firewall detected (ufw/firewalld/iptables)', advice: 'Enable ufw (sudo ufw enable) or firewalld.' };
  }),

  check('fail2ban', 'Brute-force protection (fail2ban)', 'linux', async () => {
    const r = await exec('systemctl', ['is-active', 'fail2ban'], 6000);
    if (r.code === 0) return { status: 'pass', detail: 'fail2ban active' };
    if (/inactive|failed/i.test(r.stdout)) return { status: 'warn', detail: 'fail2ban not running', advice: 'Install & start fail2ban if this host is reachable over SSH.' };
    return { status: 'info', detail: 'fail2ban not installed' };
  }),

  check('auto-updates', 'Automatic security updates', 'linux', async () => {
    try { fs.accessSync('/etc/apt/apt.conf.d/20auto-upgrades'); return { status: 'pass', detail: 'unattended-upgrades configured' }; } catch { /* next */ }
    const dnf = await exec('systemctl', ['is-enabled', 'dnf-automatic.timer', '--quiet'], 5000);
    if (dnf.code === 0 && /enabled/.test(dnf.stdout)) return { status: 'pass', detail: 'dnf-automatic enabled' };
    return { status: 'warn', detail: 'no automatic updates detected', advice: 'Enable unattended-upgrades / dnf-automatic for security patches.' };
  }),

  check('reboot-required', 'Pending reboot / restart', 'linux', async () => {
    const needed = fs.existsSync('/var/run/reboot-required');
    return needed
      ? { status: 'warn', detail: 'reboot required (kernel/libs updated)', advice: 'Schedule a reboot.' }
      : { status: 'pass', detail: 'no reboot pending' };
  }),

  check('ld-preload', 'LD_PRELOAD hijack (/etc/ld.so.preload)', 'linux', async () => {
    const txt = safeRead('/etc/ld.so.preload');
    if (txt === null) return { status: 'pass', detail: 'not present (default)' };
    const libs = txt.split('\n').map((l) => l.trim()).filter(Boolean);
    if (!libs.length) return { status: 'pass', detail: 'present but empty' };
    return {
      status: 'fail',
      detail: `preloaded libraries: ${libs.join(', ')}`,
      advice: 'A non-empty /etc/ld.so.preload is a classic Linux rootkit persistence vector. Verify each library, then empty the file if unexplained.',
    };
  }),

  check('cron-suspicious', 'Suspicious cron entries', 'linux', async () => {
    const dirs = ['/etc/crontab', '/etc/cron.d', '/var/spool/cron', '/var/spool/cron/crontabs'];
    const bad = [];
    const scanText = (file, text) => {
      for (const line of text.split('\n')) {
        if (!line || /^\s*#/.test(line)) continue;
        if (/(curl|wget)[^\n]{0,80}\|\s*(ba)?sh|base64\s+-d[^\n]{0,80}\|\s*(ba)?sh|\/dev\/tcp\/|\bnc\b[^\n]{0,40}-e\s/i.test(line)) {
          bad.push(`${file}: ${line.trim().slice(0, 90)}`);
        }
      }
    };
    for (const p of dirs) {
      try {
        const st = await fsp.stat(p);
        if (st.isFile()) scanText(p, safeRead(p) || '');
        else {
          const ents = await fsp.readdir(p);
          for (const e of ents) {
            const f = p + '/' + e;
            const t = safeRead(f);
            if (t) scanText(f, t);
          }
        }
      } catch { /* not present */ }
    }
    if (bad.length) return { status: 'fail', detail: `${bad.length} suspicious cron line(s)`, advice: 'Review and remove: ' + bad.slice(0, 2).join(' | ') };
    return { status: 'pass', detail: 'no download-and-execute cron patterns' };
  }),

  check('authorized-keys', 'SSH authorized_keys', 'linux', async () => {
    const p = path.join(os.homedir(), '.ssh', 'authorized_keys');
    const txt = safeRead(p);
    if (txt === null) return { status: 'info', detail: 'no authorized_keys for this user' };
    const keys = txt.split('\n').filter((l) => l.trim() && !/^\s*#/.test(l));
    if (!keys.length) return { status: 'info', detail: 'authorized_keys is empty' };
    const odd = keys.filter((l) => /command=|from="/.test(l));
    if (odd.length) return { status: 'warn', detail: `${keys.length} key(s), ${odd.length} with forced-command/from restrictions`, advice: 'Verify restricted keys were added intentionally.' };
    return { status: 'info', detail: `${keys.length} key(s) authorized for this account` };
  }),

  /* ---------------- Windows ---------------- */

  check('win-firewall', 'Windows Firewall profiles', 'win32', async () => {
    const r = await exec('netsh', ['advfirewall', 'show', 'allprofiles', 'state'], 15000);
    const off = (r.stdout.match(/OFF/gi) || []).length;
    const on = (r.stdout.match(/ON/gi) || []).length;
    if (!on && !off) return { status: 'skip', detail: 'netsh not available or denied' };
    if (off > 0) return { status: 'fail', detail: `${off} firewall profile(s) OFF`, advice: 'netsh advfirewall set allprofiles state on' };
    return { status: 'pass', detail: 'all profiles ON' };
  }),

  check('win-defender', 'Antivirus (Defender)', 'win32', async () => {
    const r = await exec('powershell', ['-NoProfile', '-Command', '(Get-MpComputerStatus).AntivirusEnabled'], 20000);
    if (/true/i.test(r.stdout)) return { status: 'pass', detail: 'Defender enabled' };
    if (/false/i.test(r.stdout)) return { status: 'fail', detail: 'Defender disabled', advice: 'Re-enable Microsoft Defender real-time protection.' };
    return { status: 'skip', detail: 'could not query Defender' };
  }),

  check('win-uac', 'UAC (EnableLUA)', 'win32', async () => {
    const r = await exec('reg', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', '/v', 'EnableLUA'], 10000);
    if (/0x1\b/.test(r.stdout)) return { status: 'pass', detail: 'UAC enabled' };
    if (/0x0\b/.test(r.stdout)) return { status: 'fail', detail: 'UAC disabled', advice: 'Set EnableLUA=1 — UAC blocks silent elevation.' };
    return { status: 'skip', detail: 'registry key not found' };
  }),

  check('win-rdp', 'RDP exposure', 'win32', async () => {
    const r = await exec('reg', ['query', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server', '/v', 'fDenyTSConnections'], 10000);
    if (/0x1\b/.test(r.stdout)) return { status: 'pass', detail: 'RDP disabled' };
    if (/0x0\b/.test(r.stdout)) return { status: 'warn', detail: 'RDP enabled', advice: 'Require NLA and restrict RDP to a VPN/Jump-host if possible.' };
    return { status: 'skip', detail: 'could not read RDP state' };
  }),

  check('win-guest', 'Guest account', 'win32', async () => {
    const r = await exec('net', ['user', 'guest'], 10000);
    if (/Account active\s+Yes/i.test(r.stdout)) return { status: 'fail', detail: 'Guest account active', advice: 'net user guest /active:no' };
    if (/Account active\s+No/i.test(r.stdout)) return { status: 'pass', detail: 'Guest disabled' };
    return { status: 'skip', detail: 'could not query guest account' };
  }),

  check('win-smb1', 'SMBv1 protocol', 'win32', async () => {
    const r = await exec('reg', ['query', 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters', '/v', 'SMB1'], 10000);
    if (/0x0\b/.test(r.stdout)) return { status: 'pass', detail: 'SMB1 disabled' };
    if (/0x1\b/.test(r.stdout)) return { status: 'fail', detail: 'SMB1 enabled (EternalBlue/WannaCry risk)', advice: 'Disable SMBv1: Remove-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' };
    return { status: 'pass', detail: 'SMB1 not configured (disabled by default on modern Windows)' };
  }),

  check('win-powershell-policy', 'PowerShell execution policy', 'win32', async () => {
    const r = await exec('powershell', ['-NoProfile', '-Command', 'Get-ExecutionPolicy'], 15000);
    const pol = r.stdout.trim();
    if (/unrestricted|bypass/i.test(pol)) return { status: 'fail', detail: `policy: ${pol}`, advice: 'Set-ExecutionPolicy RemoteSigned' };
    return { status: 'pass', detail: `policy: ${pol || 'default'}` };
  }),

  /* ---------------- macOS ---------------- */

  check('mac-firewall', 'Application firewall', 'darwin', async () => {
    const r = await exec('/usr/libexec/ApplicationFirewall/socketfilterfw', ['--getglobalstatus'], 8000);
    if (/enabled/i.test(r.stdout)) return { status: 'pass', detail: 'firewall enabled' };
    if (/disabled/i.test(r.stdout)) return { status: 'fail', detail: 'firewall disabled', advice: 'System Settings → Network → Firewall → ON (or socketfilterfw --setglobalstate on).' };
    return { status: 'skip', detail: 'could not query (may need sudo)' };
  }),

  check('mac-filevault', 'FileVault disk encryption', 'darwin', async () => {
    const r = await exec('fdesetup', ['status'], 8000);
    if (/On\b/.test(r.stdout)) return { status: 'pass', detail: 'FileVault on' };
    if (/Off\b/.test(r.stdout)) return { status: 'warn', detail: 'FileVault off', advice: 'Enable FileVault to encrypt the disk.' };
    return { status: 'skip', detail: 'could not query' };
  }),

  check('mac-sip', 'System Integrity Protection', 'darwin', async () => {
    const r = await exec('csrutil', ['status'], 8000);
    if (/enabled/i.test(r.stdout)) return { status: 'pass', detail: 'SIP enabled' };
    if (/disabled/i.test(r.stdout)) return { status: 'fail', detail: 'SIP disabled', advice: 'Re-enable SIP from Recovery OS (csrutil enable).' };
    return { status: 'skip', detail: 'could not query' };
  }),

  check('mac-gatekeeper', 'Gatekeeper', 'darwin', async () => {
    const r = await exec('spctl', ['--status'], 8000);
    if (/assessments enabled/i.test(r.stdout)) return { status: 'pass', detail: 'Gatekeeper enforcing' };
    return { status: 'warn', detail: 'Gatekeeper assessments disabled', advice: 'spctl --master-enable' };
  }),

  check('mac-remote-login', 'Remote login (SSH)', 'darwin', async () => {
    const r = await exec('systemsetup', ['-getremotelogin'], 8000);
    if (/Off/i.test(r.stdout)) return { status: 'pass', detail: 'SSH off' };
    if (/On/i.test(r.stdout)) return { status: 'info', detail: 'SSH on — ensure only key auth for remote users' };
    return { status: 'skip', detail: 'could not query' };
  }),

  /* ---------------- Common ---------------- */

  check('listening-ports', 'Listening network services', 'any', async () => {
    let lines = [];
    if (process.platform !== 'win32') {
      const ss = await exec('ss', ['-tln'], 8000);
      if (ss.code === 0 && ss.stdout) lines = ss.stdout.split('\n');
      else {
        const ns = await exec('netstat', ['-an'], 8000);
        lines = (ns.stdout || '').split('\n').filter((l) => /LISTEN/i.test(l));
      }
    } else {
      const ns = await exec('netstat', ['-ano'], 15000);
      lines = (ns.stdout || '').split('\n').filter((l) => /LISTENING/i.test(l));
    }
    const exposed = [];
    const seen = new Set();
    for (const l of lines) {
      const m = /(?:^|\s)(?:([\d.]+)|\*|\[?::]?)(?::|\.)(\d{2,5})\s/i.exec(l) || /([\d.]+|\*):(\d+)\s+.*LISTEN/i.exec(l);
      if (!m) continue;
      const bind = m[1] || '*';
      const port = m[2];
      const key = `${bind}:${port}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (bind === '0.0.0.0' || bind === '::' || bind === '*' || bind === '') exposed.push(key);
    }
    if (exposed.some((e) => e.endsWith(':23'))) return { status: 'fail', detail: `telnet (23) listening: ${exposed.join(', ')}`, advice: 'Disable telnet; use SSH.' };
    if (exposed.length) return { status: 'info', detail: `${exposed.length} services on all interfaces: ${exposed.slice(0, 8).join(', ')}${exposed.length > 8 ? '…' : ''}` };
    return { status: 'pass', detail: 'nothing listening on all interfaces' };
  }),

  check('updates-info', 'System information', 'any', async () => {
    let distro = '';
    if (process.platform === 'linux') {
      const txt = safeRead('/etc/os-release');
      const m = txt && /^PRETTY_NAME="?([^"\n]+)"?/m.exec(txt);
      if (m) distro = m[1];
    }
    const up = os.uptime();
    const days = Math.floor(up / 86400);
    return {
      status: 'info',
      detail: `${distro || os.type()} ${os.release()} · ${os.arch()} · uptime ${days}d ${Math.floor((up % 86400) / 3600)}h · ${Object.keys(os.cpus()).length} CPUs · ${Math.round(os.totalmem() / 1e9)}GB RAM`,
    };
  }),
];

/* ------------------------------------------------------------------ */

async function audit(opts = {}) {
  const started = Date.now();
  const onCheck = opts.onCheck || (() => {});
  const results = [];
  for (const chk of CHECKS) {
    if (chk.platform !== 'any' && chk.platform !== process.platform) continue;
    let r;
    try {
      r = await chk.run();
    } catch (e) {
      r = { status: 'skip', detail: `check error: ${(e && e.message) || e}` };
    }
    const entry = { id: chk.id, title: chk.title, status: r.status || 'info', detail: r.detail || '', advice: r.advice || '' };
    results.push(entry);
    onCheck(entry);
  }
  const counts = { pass: 0, warn: 0, fail: 0, skip: 0, info: 0 };
  for (const r of results) counts[r.status] = (counts[r.status] || 0) + 1;
  return {
    startedAt: new Date(started).toISOString(),
    durationMs: Date.now() - started,
    checks: results,
    counts,
    host: os.hostname(),
    platform: `${os.type()} ${os.release()}`,
  };
}

module.exports = { audit, CHECKS };
