'use strict';

/*
 * Fikrado Security — UI kit (zero dependencies)
 * Colors, ASCII banner with animation, spinners, progress bars, tables.
 * Degrades gracefully: NO_COLOR / non-TTY / FIKRADO_NO_ANIM all supported.
 */

const ttyOut = !!process.stdout.isTTY;
const ttyIn = !!process.stdin.isTTY;
const NO_COLOR = !!process.env.NO_COLOR || !!process.env.FIKRADO_NO_COLOR;
const colorOn = ttyOut && !NO_COLOR;
const animOn = colorOn && ttyIn && !process.env.FIKRADO_NO_ANIM;

const wrap = (...codes) => (s) =>
  colorOn ? `\x1b[${codes.join(';')}m${String(s)}\x1b[0m` : String(s);

const c = {
  bold: wrap(1),
  dim: wrap(2),
  underline: wrap(4),
  inverse: wrap(7),
  red: wrap(31),
  green: wrap(32),
  yellow: wrap(33),
  blue: wrap(34),
  magenta: wrap(35),
  cyan: wrap(36),
  white: wrap(37),
  gray: wrap(90),
  lightRed: wrap(91),
  lightGreen: wrap(92),
  lightYellow: wrap(93),
  lightBlue: wrap(94),
  lightMagenta: wrap(95),
  lightCyan: wrap(96),
  lightWhite: wrap(97),
  yellowBold: wrap(1, 33),
  greenBold: wrap(1, 92),
};

function stripAnsi(s) {
  return String(s).replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '');
}

function width() {
  return Math.max(40, Math.min(process.stdout.columns || 72, 100));
}

function hr(ch) {
  return c.gray((ch || '─').repeat(width()));
}

function clear() {
  if (ttyOut) process.stdout.write('\x1b[2J\x1b[3J\x1b[H');
}

function showCursor() {
  if (ttyOut) process.stdout.write('\x1b[?25h');
}
function hideCursor() {
  if (ttyOut) process.stdout.write('\x1b[?25l');
}

/* ------------------------------------------------------------------ */
/* Status icons                                                        */
/* ------------------------------------------------------------------ */

function statusIcon(status) {
  switch (status) {
    case 'pass': return c.green('✔');
    case 'warn': return c.yellow('⚠');
    case 'fail': return c.lightRed('✗');
    case 'skip': return c.gray('–');
    default:     return c.cyan('ℹ');
  }
}

/* ------------------------------------------------------------------ */
/* ASCII banner — "FIKRADO SECURITY" in yellow + light green           */
/* ------------------------------------------------------------------ */

const FONT = {
  F: ['██████', '██    ', '██████', '██    ', '██    '],
  I: ['██████', '  ██  ', '  ██  ', '  ██  ', '██████'],
  K: ['██  ██', '██ ██ ', '████  ', '██ ██ ', '██  ██'],
  R: ['█████ ', '██  ██', '█████ ', '██  ██', '██  ██'],
  A: ['  ██  ', ' ████ ', '██  ██', '██████', '██  ██'],
  D: ['█████ ', '██  ██', '██  ██', '██  ██', '█████ '],
  O: [' ████ ', '██  ██', '██  ██', '██  ██', ' ████ '],
  S: [' ████ ', '██    ', ' ████ ', '    ██', '█████ '],
  E: ['██████', '██    ', '█████ ', '██    ', '██████'],
  C: [' ████ ', '██    ', '██    ', '██    ', ' ████ '],
  U: ['██  ██', '██  ██', '██  ██', '██  ██', ' ████ '],
  T: ['██████', '  ██  ', '  ██  ', '  ██  ', '  ██  '],
  Y: ['██  ██', '██  ██', ' ████ ', '  ██  ', '  ██  '],
  ' ': ['      ', '      ', '      ', '      ', '      '],
};

const HL = colorOn ? (s) => `\x1b[1;97m${s}\x1b[0m` : (s) => s; // sweep highlight: bold white

function bannerRow(glyphs, row, visible, hlIndex) {
  let out = '';
  for (let i = 0; i < glyphs.length; i++) {
    const g = glyphs[i];
    let txt = g[row];
    if (i >= visible) txt = txt.replace(/█/g, ' ');
    out += (i === hlIndex ? HL(txt) : txt) + '  ';
  }
  return out;
}

async function showBanner(opts = {}) {
  const anim = opts.anim !== undefined ? !!opts.anim && colorOn : animOn;
  const tagline = opts.tagline || `cross-platform terminal security suite · v${opts.version || '1.0.0'}`;

  const g1 = 'FIKRADO'.split('').map((ch) => FONT[ch]);
  const g2 = 'SECURITY'.split('').map((ch) => FONT[ch]);

  const blank = '';
  const tag = c.lightCyan('  ➤  ' + tagline);
  const rule = c.lightGreen('  ' + '═'.repeat(Math.max(g1.length, g2.length) * 8 + 2));

  const buildLines = (visible1, visible2, hl) => {
    const lines = [];
    lines.push(blank);
    for (let r = 0; r < 5; r++) lines.push(c.yellowBold(bannerRow(g1, r, visible1, hl < g1.length ? hl : -1)));
    lines.push(blank);
    for (let r = 0; r < 5; r++) lines.push(c.greenBold(bannerRow(g2, r, visible2, hl)));
    lines.push(blank);
    lines.push(tag);
    lines.push(rule);
    lines.push(blank);
    return lines;
  };

  if (!anim) {
    const lines = buildLines(g1.length, g2.length, -1);
    process.stdout.write(lines.join('\n') + '\n');
    return;
  }

  const totalGlyphs = g1.length + g2.length;
  const frames = [];
  // Phase 1: reveal glyphs left → right
  for (let k = 0; k <= totalGlyphs; k++) {
    const v1 = Math.min(k, g1.length);
    const v2 = Math.max(0, Math.min(k - g1.length, g2.length));
    frames.push(buildLines(v1, v2, -1));
  }
  // Phase 2: light-beam sweep (two passes, both words highlighted at same glyph index)
  for (let pass = 0; pass < 2; pass++) {
    for (let p = 0; p < Math.max(g1.length, g2.length); p++) {
      frames.push(buildLines(g1.length, g2.length, p));
    }
  }
  frames.push(buildLines(g1.length, g2.length, -1));

  const n = frames[0].length;
  const up = `\x1b[${n}A`;
  const down = `\x1b[${n}B`;

  hideCursor();
  try {
    process.stdout.write('\n'.repeat(n));
    const delay = (ms) => new Promise((r) => setTimeout(r, ms));
    for (const f of frames) {
      let out = up + '\r';
      for (const l of f) out += '\x1b[2K' + l + '\n';
      process.stdout.write(out + up);
      await delay(frames.length > 40 ? 38 : 45);
    }
    process.stdout.write(down + '\r');
  } catch { /* ignore animation errors */ } finally {
    showCursor();
  }
}

async function bootLines() {
  if (!animOn) return;
  const items = [
    'signature database',
    'scan engines (malware · network · server · AD)',
    'AI detection providers',
    'config & report store',
  ];
  const delay = (ms) => new Promise((r) => setTimeout(r, ms));
  process.stdout.write('\n');
  for (const it of items) {
    process.stdout.write(`  ${c.gray('›')} initializing ${it} `);
    await delay(90 + Math.floor(Math.random() * 80));
    process.stdout.write(`${c.green('ready')}\n`);
  }
}

/* ------------------------------------------------------------------ */
/* Spinner                                                             */
/* ------------------------------------------------------------------ */

const FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

class Spinner {
  constructor(label) {
    this.label = label || '';
    this.frame = 0;
    this.timer = null;
    this.active = false;
    this.logged = false;
  }

  start(label) {
    if (label !== undefined) this.label = label;
    this.active = true;
    if (!animOn) {
      if (!this.logged) { process.stdout.write(`  ${c.gray('·')} ${this.label}\n`); this.logged = true; }
      return this;
    }
    const tick = () => {
      if (!this.active) return;
      const f = FRAMES[this.frame++ % FRAMES.length];
      process.stdout.write(`\r\x1b[2K${c.lightCyan(f)} ${c.white(this.label)}`);
      this.timer = setTimeout(tick, 80);
    };
    tick();
    return this;
  }

  update(label) {
    this.label = label;
    if (!animOn && !this.logged) { process.stdout.write(`  ${c.gray('·')} ${label}\n`); this.logged = true; }
    return this;
  }

  _stop(icon, text, colorFn) {
    this.active = false;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    if (animOn) {
      process.stdout.write(`\r\x1b[2K${icon} ${text}\n`);
    } else if (text && text !== this.label) {
      process.stdout.write(`  ${icon} ${colorFn ? colorFn(text) : text}\n`);
    }
  }

  succeed(msg) { this._stop(c.green('✔'), c.green(msg || this.label)); }
  fail(msg)    { this._stop(c.lightRed('✗'), c.lightRed(msg || this.label)); }
  warn(msg)    { this._stop(c.yellow('⚠'), c.yellow(msg || this.label)); }
  info(msg)    { this._stop(c.cyan('ℹ'), c.cyan(msg || this.label)); }
  stop()       { this._stop('', ''); }
}

/* ------------------------------------------------------------------ */
/* Progress bar                                                        */
/* ------------------------------------------------------------------ */

function progressBar(cur, tot, label) {
  const W = 26;
  const frac = tot > 0 ? Math.min(1, cur / tot) : 0;
  const f = Math.round(frac * W);
  const bar = c.lightGreen('█'.repeat(f)) + c.gray('░'.repeat(W - f));
  const pct = String(Math.round(frac * 100)).padStart(3) + '%';
  return `${bar} ${c.bold(pct)} ${c.gray(label || '')}`;
}

/* ------------------------------------------------------------------ */
/* Layout helpers                                                      */
/* ------------------------------------------------------------------ */

function menuHeader(title) {
  console.log(`\n${c.yellowBold('▸ ' + title.toUpperCase())}`);
  console.log(hr('─'));
}

function box(title, lines) {
  const w = Math.max(
    stripAnsi(title).length + 4,
    ...lines.map((l) => stripAnsi(l).length)
  ) + 4;
  const top = c.yellow('╭─ ' + title + ' ' + '─'.repeat(Math.max(0, w - stripAnsi(title).length - 4)) + '╮');
  const bot = c.yellow('╰' + '─'.repeat(w - 2) + '╯');
  console.log(top);
  for (const l of lines) console.log(c.yellow('│') + '  ' + l + ' '.repeat(Math.max(0, w - 4 - stripAnsi(l).length)) + c.yellow('│'));
  console.log(bot);
}

function table(headers, rows, colorCell) {
  const widths = headers.map((h, i) =>
    Math.max(
      stripAnsi(h).length,
      ...rows.map((r) => stripAnsi(String(r[i] !== undefined ? r[i] : '')).length)
    )
  );
  const line = (cells, isHeader) =>
    cells
      .map((cell, i) => {
        const s = String(cell !== undefined && cell !== null ? cell : '');
        const pad = ' '.repeat(Math.max(0, widths[i] - stripAnsi(s).length));
        return isHeader ? c.bold(c.white(s)) + pad : s + pad;
      })
      .join('  ');
  console.log(line(headers, true));
  console.log(c.gray('─'.repeat(widths.reduce((a, b) => a + b + 2, 0))));
  rows.forEach((r, ri) => {
    const plain = line(r, false);
    if (colorCell) {
      const colored = r.map((cell, ci) => {
        const s = String(cell !== undefined && cell !== null ? cell : '');
        const pad = ' '.repeat(Math.max(0, widths[ci] - stripAnsi(s).length));
        return colorCell(ri, ci, s) + pad;
      }).join('  ');
      console.log(colored);
    } else {
      console.log(plain);
    }
  });
}

module.exports = {
  c, stripAnsi, width, hr, clear, showCursor, hideCursor,
  statusIcon, showBanner, bootLines, Spinner, progressBar,
  menuHeader, box, table, colorOn, animOn, ttyOut,
};
