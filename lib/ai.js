'use strict';

/*
 * Fikrado Security — AI-assisted detection
 * Talks to any OpenAI-compatible /chat/completions endpoint:
 *   OpenRouter · OpenAI · OpenCode Zen · custom (Groq, Ollama, …)
 * Pure Node https — zero dependencies.
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

async function chatCompletion(p, messages, opts = {}) {
  if (!p) throw new Error('No AI provider selected. Open the AI menu to configure one.');
  if (!p.key) throw new Error(`No API key set for ${p.label}. Open the AI menu to add one.`);

  const base = String(p.baseUrl || '').replace(/\/+$/, '');
  if (!/^https?:\/\//.test(base)) throw new Error(`Invalid base URL for ${p.label}: ${p.baseUrl}`);
  const url = new URL(base + '/chat/completions');
  const mod = url.protocol === 'http:' ? http : https;

  const body = JSON.stringify({
    model: p.model,
    messages,
    max_tokens: opts.maxTokens || 1024,
    temperature: opts.temperature !== undefined ? opts.temperature : 0.2,
  });

  const headers = {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    Authorization: `Bearer ${p.key}`,
  };
  if (p.name === 'openrouter') {
    headers['HTTP-Referer'] = 'https://fikrado.security.local';
    headers['X-Title'] = 'Fikrado Security';
  }

  return new Promise((resolve, reject) => {
    const req = mod.request(url, { method: 'POST', headers, timeout: opts.timeoutMs || 60000 }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (d) => (data += d));
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            const json = JSON.parse(data);
            const content =
              (json.choices && json.choices[0] && json.choices[0].message && json.choices[0].message.content) ||
              json.content ||
              '(empty response)';
            resolve(String(content).trim());
          } catch {
            reject(new Error(`${p.label} returned invalid JSON (first 200 chars): ${data.slice(0, 200)}`));
          }
        } else {
          let msg = `${p.label} API error ${res.statusCode}`;
          try {
            const j = JSON.parse(data);
            msg += `: ${(j.error && (j.error.message || j.error.code)) || j.message || data.slice(0, 200)}`;
          } catch {
            msg += `: ${data.slice(0, 200)}`;
          }
          if (res.statusCode === 401 || res.statusCode === 403) msg += ' — check your API key.';
          if (res.statusCode === 429) msg += ' — rate limited, try again shortly.';
          reject(new Error(msg));
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error(`${p.label} request timed out`)));
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function testConnection(p) {
  const out = await chatCompletion(
    p,
    [{ role: 'user', content: 'Reply with the single word: OK' }],
    { maxTokens: 8, timeoutMs: 25000 }
  );
  return out;
}

function sanitizeSnippet(s) {
  return String(s)
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '')
    .slice(0, 120);
}

async function analyzeFindings(p, findings) {
  const items = findings.slice(0, 25).map((f, i) => ({
    n: i + 1,
    file: f.path.split(/[\\/]/).pop(),
    size: f.size,
    modified: f.modified,
    matched: (f.matches || []).map((m) => `${m.id} (${m.severity})`),
    snippet: sanitizeSnippet(f.snippet || ''),
  }));
  const extra = findings.length > 25 ? `\n(+ ${findings.length - 25} more findings not listed)` : '';

  const messages = [
    {
      role: 'system',
      content:
        'You are a senior malware analyst and incident responder for "Fikrado Security". ' +
        'You receive scanner findings (matched signature IDs, file metadata, short snippets). ' +
        'Classify each finding: MALICIOUS / SUSPICIOUS / LIKELY-BENIGN, give a risk level (high/medium/low), ' +
        'one-line reasoning, and a recommended action (delete/quarantine/investigate/keep). ' +
        'End with a 3-line incident summary. Be concise. Format with a numbered list.',
    },
    {
      role: 'user',
      content:
        'Analyze these malware scanner findings:\n\n' +
        JSON.stringify(items, null, 2) +
        extra,
    },
  ];
  return chatCompletion(p, messages, { maxTokens: 1400 });
}

async function summarizeReport(p, reportText) {
  const messages = [
    {
      role: 'system',
      content:
        'You are a security auditor. Summarize the scan report into a crisp executive brief: ' +
        'overall risk rating (LOW/MEDIUM/HIGH/CRITICAL), top 5 issues, and prioritized fixes. Max ~250 words.',
    },
    { role: 'user', content: String(reportText).slice(0, 12000) },
  ];
  return chatCompletion(p, messages, { maxTokens: 900 });
}

module.exports = { chatCompletion, testConnection, analyzeFindings, summarizeReport };
