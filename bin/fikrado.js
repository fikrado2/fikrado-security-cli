#!/usr/bin/env node
'use strict';

/*
 * Fikrado Security — CLI entry point
 *
 *   node bin/fikrado.js              (any OS with Node >= 16)
 *   fikrado / fikrado-security       (npm install -g .)
 */

process.title = 'fikrado-security';

const { runCli } = require('../lib/menu');

runCli(process.argv.slice(2)).then(
  () => {
    // keep the process alive only when interactive UI is still running
  },
  (e) => {
    const msg = (e && e.message) || String(e);
    process.stderr.write('\n  ✗ ' + msg + '\n');
    if (process.env.FIKRADO_DEBUG) process.stderr.write(String((e && e.stack) || '') + '\n');
    process.stderr.write('  run "fikrado --help" for usage\n\n');
    process.exit(1);
  }
);
