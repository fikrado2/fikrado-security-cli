```
██████  ██████  ██  ██  █████     ██    █████    ████        ████   ██████   ████   ██  ██  █████   ██████  ██████  ██  ██
██        ██    ██ ██   ██  ██   ████   ██  ██  ██  ██      ██      ██      ██      ██  ██  ██  ██    ██      ██    ██  ██
██████    ██    ████    █████   ██  ██  ██  ██  ██  ██       ████   █████   ██      ██  ██  █████     ██      ██     ████
██        ██    ██ ██   ██  ██  ██████  ██  ██  ██  ██          ██  ██      ██      ██  ██  ██  ██    ██      ██      ██
██      ██████  ██  ██  ██  ██  ██  ██  █████    ████       █████   ██████   ████    ████   ██  ██  ██████    ██      ██
```

# Fikrado Security

**Cross-platform terminal security suite — malware removal, network discovery, server hardening and Active Directory checks, with optional AI-assisted analysis.**

Pure Node.js. **Zero runtime dependencies.** Runs on Linux, macOS and Windows, with prebuilt standalone binaries and an npm package.

> This is the **terminal (CLI) edition**. The Windows desktop GUI edition lives at [fikrado2/fikrado-security](https://github.com/fikrado2/fikrado-security).

```
┌─ FIKRADO SECURITY ───────────────────────────────────────────────────┐
 [1] ☣ Full system scan      [5] ▦ Active Directory audit
 [2] ☣ Malware scan          [6] ✦ AI detection settings
 [3] ◈ Network scan          [7] ▤ Reports
 [4] ▤ Server / host audit   [8] ? About
 [0] ✕ Exit
└──────────────────────────────────────────────────────────────────────┘
```

---

## Contents

- [What it does](#what-it-does)
- [Install](#install)
- [Quick start](#quick-start)
- [CLI reference](#cli-reference)
- [AI detection](#ai-detection)
- [Reports, quarantine & data](#reports-quarantine--data)
- [Exit codes](#exit-codes)
- [Build standalone binaries](#build-standalone-binaries)
- [Development](#development)
- [Safety & legal](#safety--legal)
- [License](#license)

---

## What it does

| Engine | What it checks | Typical use |
|---|---|---|
| **Malware** | 19 built-in signature families + filename heuristics: EICAR, obfuscated PHP/ASP/JSP webshells, reverse shells, encoded PowerShell, Mimikatz/Meterpreter artifacts, crypto-miners, `.htaccess` auto-prepend, autorun worms, obfuscated JS. Quarantine, restore or permanently delete findings. | Compromised web servers, shared hosting, suspicious downloads |
| **Network** | Local subnet discovery, cross-platform ping sweep (64 parallel probes), TCP scan of ~44 service ports, severity-ranked risk flags (Telnet, SMB, RDP, Redis, MongoDB, Elasticsearch, Docker API, memcached, TR-069…), deep scan of a single host (ports 1–1024 + services). | Network hygiene, exposed service discovery |
| **Server / host** | Linux: SSH root/password login, `/etc/shadow` perms, UID-0 accounts, empty passwords, world-writable `/etc`, SUID inventory, firewall, fail2ban, auto-updates, reboot pending, **`/etc/ld.so.preload` rootkit check**, **suspicious cron download-and-execute**, SSH `authorized_keys`.<br>Windows: Defender, firewall profiles, UAC, RDP, Guest, SMBv1, PowerShell policy.<br>macOS: application firewall, FileVault, SIP, Gatekeeper, remote login. | Server hardening baseline, PCI/CIS-style triage |
| **Active Directory** | DC discovery via DNS SRV (`_ldap._tcp.dc._msdcs`), Kerberos/LDAP/LDAPS/GC/SMB posture, and a **real anonymous LDAP bind probe** (raw BER, no libraries) to detect anonymous directory access. | AD hygiene, DC exposure review |
| **AI detection** | Sends findings/reports to any OpenAI-compatible endpoint — **OpenRouter, OpenAI, OpenCode Zen, or custom** (Groq, Together, Ollama, LM Studio) — and returns classification, risk, and recommended action. | Second opinion on false positives, executive summaries |

Everything is **read-only** except the malware actions you explicitly request (quarantine or delete).

---

## Install

### Option A — prebuilt binary (no Node.js needed)

**One-line install (Linux / macOS):**

```bash
curl -fsSL https://raw.githubusercontent.com/fikrado2/fikrado-security-cli/main/install.sh | bash
```

Or download the file for your OS from the [Releases](https://github.com/fikrado2/fikrado-security-cli/releases) page:

| Platform | File |
|---|---|
| Linux x86_64 | `fikrado-linux-x64` |
| Linux ARM64 | `fikrado-linux-arm64` |
| macOS Intel | `fikrado-macos-x64` |
| macOS Apple Silicon | `fikrado-macos-arm64` |
| Windows x64 | `fikrado-win-x64.exe` |

```bash
# Linux / macOS
chmod +x fikrado-linux-x64
sudo mv fikrado-linux-x64 /usr/local/bin/fikrado
fikrado
```

```powershell
# Windows (PowerShell)
.\fikrado-win-x64.exe
```

> macOS may refuse an unsigned binary downloaded from the internet. Clear the quarantine flag once:
> `xattr -d com.apple.quarantine ./fikrado-macos-arm64 && chmod +x ./fikrado-macos-arm64`
>
> Windows SmartScreen may warn about an unsigned binary — choose **More info → Run anyway**.

### Option B — npm (requires Node.js ≥ 16)

```bash
npm install -g fikrado-security
fikrado
```

### Option C — from source

```bash
git clone https://github.com/fikrado2/fikrado-security-cli.git
cd fikrado-security
node bin/fikrado.js          # no npm install needed to run
```

---

## Quick start

Run it with no arguments for the animated menu:

```bash
fikrado
```

On start you get the animated **FIKRADO SECURITY** banner (yellow + light green), a short boot sequence, then the menu. Colors, spinners and the banner animation are disabled automatically when output is piped or `NO_COLOR` is set.

Common one-liners:

```bash
fikrado scan ~/Downloads                      # scan a folder, report only
fikrado scan /var/www --quarantine            # move threats to ~/.fikrado/quarantine
fikrado scan /var/www --delete                # permanently delete detected threats
fikrado net 192.168.1.0/24                    # subnet + port scan
fikrado net --deep 10.0.0.5                   # full port scan of one host
fikrado server                                # host hardening audit
fikrado ad corp.example.com                   # Active Directory audit
fikrado full                                  # host audit + malware + network
fikrado quarantine list                       # inspect quarantined files
fikrado quarantine restore 1                  # put item 1 back
fikrado report list                           # list saved reports
fikrado report show 1                         # print a report
```

---

## CLI reference

```
fikrado                          interactive menu
fikrado scan [path] [--delete|--quarantine] [--ai] [--no-report]
fikrado net [cidr] [--deep <host>] [--ai] [--no-report] [--yes]
fikrado server [--ai] [--no-report]
fikrado ad <domain> [--ai] [--no-report]
fikrado full
fikrado quarantine [list|restore <n>]

fikrado keys                     interactive AI settings
fikrado keys list
fikrado keys set <provider> [key]
fikrado keys model <provider> <model>
fikrado keys base <provider> <url>
fikrado keys test [provider]
fikrado keys off

fikrado report [list|show <n>|folder]
fikrado --banner [--static] | --help | --version
```

**Flags**

| Flag | Meaning |
|---|---|
| `--ai` | Send the results to the active AI provider for analysis |
| `--delete` | Permanently delete detected malware (scan only) |
| `--quarantine` | Move detected malware into quarantine (scan only) |
| `--no-report` | Do not write a report file |
| `--deep <host>` | Full port scan of one host (net only) |
| `--yes` | Skip the confirmation for subnets larger than /24 |
| `--no-anim` | Disable animations |
| `NO_COLOR=1` | Disable colors |

Providers: `openrouter` · `openai` · `opencode` · `custom`

---

## AI detection

AI analysis is optional and entirely local-first: results are only sent to the provider you configure, and only when you ask for it (`--ai` or the `Analyze with AI?` prompt).

### Add a key

```bash
fikrado keys set openrouter sk-or-v1-...      # https://openrouter.ai/keys
fikrado keys set openai sk-...                # https://platform.openai.com/api-keys
fikrado keys set opencode <your-zen-key>      # OpenCode Zen
fikrado keys set custom <key>                 # any OpenAI-compatible endpoint
```

Or use the interactive menu: **6 → provider → Set API key** (input is hidden).

The first provider you configure becomes active. Manage it with:

```bash
fikrado keys list
fikrado keys test
fikrado keys model openai gpt-4o-mini
fikrado keys base custom http://localhost:11434/v1
fikrado keys off                              # disable AI completely
```

### Notes per provider

- **OpenRouter** — default model `openrouter/auto`, extra `HTTP-Referer`/`X-Title` headers are sent.
- **OpenAI** — default model `gpt-4o-mini`.
- **OpenCode Zen** — the preset points at `https://opencode.ai/zen/v1` with model `codeshell`. Depending on your account, set the exact model/base URL with `fikrado keys model` / `fikrado keys base`.
- **Custom** — anything that speaks `POST /chat/completions` (Ollama: `http://localhost:11434/v1`, LM Studio, Groq, Together…). A local Ollama needs no real key but the field must be non-empty.

Keys are stored **only** on your machine in `~/.fikrado/config.json` with mode `0600`. They are never sent anywhere except the provider you configured.

---

## Reports, quarantine & data

Everything lives under `~/.fikrado/`:

```
~/.fikrado/
├── config.json          # AI providers + settings (chmod 600)
├── signatures.json      # optional custom signatures
├── quarantine/          # quarantined files + manifest.json
└── reports/             # fikrado-<kind>-<timestamp>.json and .txt
```

**Custom signatures** — drop a JSON array into `~/.fikrado/signatures.json`:

```json
[
  { "id": "MY.RULE", "name": "My rule", "severity": "high", "pattern": "eval\\s*\\(\\s*base64_decode", "flags": "i" }
]
```

**Quarantine** — files are moved (not copied) into `~/.fikrado/quarantine/` and recorded in `manifest.json` with original path, matched signatures and timestamp. Restore with `fikrado quarantine restore <n>` or from the menu. Quarantined files are **not** executed or scanned again.

**Reports** — every scan writes a human-readable `.txt` and a machine-readable `.json` with host, platform, user, duration and findings. Use `--no-report` to skip.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, nothing wrong found |
| `1` | Usage error / runtime failure |
| `2` | Findings: malware detected (`scan`) or failing checks (`server`) |
| `130` | Interrupted (Ctrl+C) |

Useful for cron/CI:

```bash
fikrado scan /var/www --delete --no-report || echo "FIKRADO: threats handled"
```

---

## Build standalone binaries

```bash
npm install                 # dev dependency: @yao-pkg/pkg
npm run build               # all platforms → dist/
npm run build:linux
npm run build:mac
npm run build:win
```

Output (plus `dist/SHA256SUMS.txt`):

```
dist/fikrado-linux-x64
dist/fikrado-linux-arm64
dist/fikrado-macos-x64
dist/fikrado-macos-arm64
dist/fikrado-win-x64.exe
```

Binaries are self-contained (Node runtime embedded) and need nothing installed on the target machine. Building all targets from one machine works because pkg downloads the official Node base binaries for each platform.

The repository also ships a GitHub Actions workflow that builds and attaches all binaries to a release when you push a tag:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

---

## Development

```bash
npm test              # 23 tests, Node's built-in runner, no test dependencies
npm start             # run from source
npm run banner        # render the banner only
```

```
bin/fikrado.js            CLI entry
lib/menu.js               interactive UI + argument parsing
lib/ui.js                 colors, banner animation, spinner, progress bar, tables
lib/config.js             ~/.fikrado config, providers, custom signatures
lib/ai.js                 OpenAI-compatible chat client
lib/report.js             report store (json + txt)
lib/scanners/malware.js   signature engine + quarantine/delete/restore
lib/scanners/network.js   CIDR/ping/port scanning + risk table
lib/scanners/server.js    cross-platform hardening checks
lib/scanners/ad.js        AD discovery + raw LDAP anonymous bind probe
test/                     unit + integration tests
scripts/build-binaries.js standalone binary builder
```

Adding a signature is one object in `BUILT_IN_SIGNATURES` (`lib/scanners/malware.js`) or a line in `~/.fikrado/signatures.json`. Adding a host check is one `check(...)` entry in `lib/scanners/server.js`.

---

## Safety & legal

- Use Fikrado Security **only on systems you own or are explicitly authorized to test**. Port-scanning or auditing networks without permission can be illegal.
- The malware engine is **signature-based**, not a replacement for a full antivirus/EDR. It is tuned for webshells, droppers, reverse shells, miners and common post-exploitation artifacts.
- `--delete` is irreversible. Prefer `--quarantine` (default in the interactive menu) when unsure.
- Some host checks need root/administrator to read `/etc/shadow`, firewall state or registry keys; without it they report `info`/`skip` instead of failing.
- AI analysis sends finding metadata (file names, signature IDs, short snippets) to your chosen provider. Do not enable it on data you cannot share.

---

## License

MIT — see [LICENSE](LICENSE).

Built by [fikrado2](https://github.com/fikrado2). Stay secure. 🟡🟢
