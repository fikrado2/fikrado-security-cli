#!/usr/bin/env node
'use strict';

/*
 * Fikrado Security — standalone binary builder
 *
 * Produces real self-contained executables (no Node.js required on the target)
 * using @yao-pkg/pkg, which cross-compiles from any host OS.
 *
 *   node scripts/build-binaries.js            # every platform
 *   node scripts/build-binaries.js linux      # linux only
 *   node scripts/build-binaries.js macos win  # selected groups
 *
 * Output: dist/fikrado-<os>-<arch>[.exe] + dist/SHA256SUMS.txt
 */

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const DIST = path.join(ROOT, 'dist');
const ENTRY = path.join(ROOT, 'bin', 'fikrado.js');

const GROUPS = {
  linux: [
    { target: 'node22-linux-x64', out: 'fikrado-linux-x64' },
    { target: 'node22-linux-arm64', out: 'fikrado-linux-arm64' },
  ],
  macos: [
    { target: 'node22-macos-x64', out: 'fikrado-macos-x64' },
    { target: 'node22-macos-arm64', out: 'fikrado-macos-arm64' },
  ],
  win: [
    { target: 'node22-win-x64', out: 'fikrado-win-x64.exe' },
  ],
};

function selectedGroups(argv) {
  const names = argv.filter((a) => !a.startsWith('-'));
  if (!names.length) return Object.keys(GROUPS);
  const out = [];
  for (const raw of names) {
    const n = raw.toLowerCase();
    const key = n === 'windows' ? 'win' : n === 'mac' || n === 'darwin' || n === 'osx' ? 'macos' : n;
    if (!GROUPS[key]) {
      console.error(`unknown group "${raw}" — choose from: ${Object.keys(GROUPS).join(', ')}`);
      process.exit(1);
    }
    out.push(key);
  }
  return [...new Set(out)];
}

async function main() {
  let pkg;
  try {
    pkg = require('@yao-pkg/pkg');
  } catch {
    console.error('Missing dev dependency. Run:  npm install');
    process.exit(1);
  }

  const groups = selectedGroups(process.argv.slice(2));
  fs.mkdirSync(DIST, { recursive: true });

  const built = [];
  for (const group of groups) {
    for (const job of GROUPS[group]) {
      const outFile = path.join(DIST, job.out);
      console.log(`\n▸ building ${job.out}  (${job.target})`);
      const started = Date.now();
      try {
        fs.rmSync(outFile, { force: true });
        await pkg.exec([
          ENTRY,
          '--target', job.target,
          '--output', outFile,
          '--compress', 'GZip',
        ]);
        if (process.platform !== 'win32') fs.chmodSync(outFile, 0o755);
        const size = fs.statSync(outFile).size;
        console.log(`  ✔ ${job.out} — ${(size / 1024 / 1024).toFixed(1)} MB in ${((Date.now() - started) / 1000).toFixed(0)}s`);
        built.push({ file: job.out, size });
      } catch (e) {
        console.error(`  ✗ ${job.out}: ${(e && e.message) || e}`);
        process.exitCode = 1;
      }
    }
  }

  if (built.length) {
    const lines = built
      .map((b) => {
        const hash = crypto.createHash('sha256').update(fs.readFileSync(path.join(DIST, b.file))).digest('hex');
        return `${hash}  ${b.file}`;
      })
      .join('\n');
    fs.writeFileSync(path.join(DIST, 'SHA256SUMS.txt'), lines + '\n');
    console.log('\nSHA256SUMS.txt');
    console.log(lines);
  }
}

main().catch((e) => {
  console.error((e && e.stack) || e);
  process.exit(1);
});
