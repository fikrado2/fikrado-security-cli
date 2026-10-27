'use strict';

/*
 * Fikrado Security — configuration & persistence
 * Everything lives under ~/.fikrado/
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const DIR = path.join(os.homedir(), '.fikrado');
const QUARANTINE_DIR = path.join(DIR, 'quarantine');
const REPORTS_DIR = path.join(DIR, 'reports');
const CONFIG_FILE = path.join(DIR, 'config.json');
const MANIFEST_FILE = path.join(QUARANTINE_DIR, 'manifest.json');
const CUSTOM_SIGS_FILE = path.join(DIR, 'signatures.json');

const PROVIDER_PRESETS = {
  openrouter: {
    label: 'OpenRouter',
    baseUrl: 'https://openrouter.ai/api/v1',
    model: 'openrouter/auto',
    note: 'Get a key at https://openrouter.ai/keys',
  },
  openai: {
    label: 'OpenAI',
    baseUrl: 'https://api.openai.com/v1',
    model: 'gpt-4o-mini',
    note: 'Get a key at https://platform.openai.com/api-keys',
  },
  opencode: {
    label: 'OpenCode Zen',
    baseUrl: 'https://opencode.ai/zen/v1',
    model: 'codeshell',
    note: 'OpenCode Zen gateway — set your key, model & base URL per your account',
  },
  custom: {
    label: 'Custom (OpenAI-compatible)',
    baseUrl: 'http://localhost:11434/v1',
    model: 'llama3',
    note: 'Any OpenAI-compatible endpoint: Groq, Together, Ollama, LM Studio…',
  },
};

function defaults() {
  return {
    version: 1,
    activeProvider: null,
    providers: {},
    settings: { confirmDelete: true },
  };
}

function ensureDirs() {
  for (const d of [DIR, QUARANTINE_DIR, REPORTS_DIR]) {
    fs.mkdirSync(d, { recursive: true });
  }
}

function load() {
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    return { ...defaults(), ...raw };
  } catch {
    return defaults();
  }
}

function save(cfg) {
  ensureDirs();
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
}

function providerNames() {
  return Object.keys(PROVIDER_PRESETS);
}

function getProvider(cfg, name) {
  const preset = PROVIDER_PRESETS[name];
  if (!preset) return null;
  const saved = cfg.providers[name] || {};
  return {
    name,
    label: preset.label,
    note: preset.note || '',
    baseUrl: saved.baseUrl || preset.baseUrl,
    model: saved.model || preset.model,
    key: saved.key || '',
  };
}

function setProvider(cfg, name, patch) {
  const cur = cfg.providers[name] || {};
  cfg.providers[name] = { ...cur, ...patch };
  save(cfg);
}

function setActive(cfg, name) {
  cfg.activeProvider = name || null;
  save(cfg);
}

function getActive(cfg) {
  if (!cfg.activeProvider) return null;
  const p = getProvider(cfg, cfg.activeProvider);
  return p && p.key ? p : null;
}

function maskKey(k) {
  if (!k) return '(not set)';
  if (k.length <= 10) return k.slice(0, 2) + '…';
  return k.slice(0, 7) + '…' + k.slice(-4);
}

/* Quarantine manifest ------------------------------------------------ */

function readManifest() {
  try {
    return JSON.parse(fs.readFileSync(MANIFEST_FILE, 'utf8'));
  } catch {
    return [];
  }
}

function writeManifest(entries) {
  ensureDirs();
  fs.writeFileSync(MANIFEST_FILE, JSON.stringify(entries, null, 2));
}

/* Custom user signatures --------------------------------------------- */

function loadCustomSignatures() {
  try {
    const arr = JSON.parse(fs.readFileSync(CUSTOM_SIGS_FILE, 'utf8'));
    if (!Array.isArray(arr)) return [];
    return arr
      .filter((s) => s && s.id && s.pattern)
      .map((s) => ({
        id: String(s.id),
        name: String(s.name || s.id),
        severity: s.severity === 'high' || s.severity === 'med' || s.severity === 'low' ? s.severity : 'med',
        re: new RegExp(s.pattern, s.flags || 'i'),
        custom: true,
      }));
  } catch {
    return [];
  }
}

module.exports = {
  DIR, QUARANTINE_DIR, REPORTS_DIR, CONFIG_FILE, MANIFEST_FILE, CUSTOM_SIGS_FILE,
  PROVIDER_PRESETS,
  ensureDirs, load, save, providerNames, getProvider, setProvider,
  setActive, getActive, maskKey,
  readManifest, writeManifest, loadCustomSignatures,
};
