// Fingerprint/bot-detection matrix: mb configurations vs. default Playwright launches.
// Usage: node bench/stealth-test.mjs            (all configs)
//        node bench/stealth-test.mjs mb-headful  (one config)
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const TESTS = [
  { name: 'sannysoft', url: 'https://bot.sannysoft.com', wait: 3000,
    expr: `(() => { const f = [...document.querySelectorAll('td')].filter(td => /failed|warn/.test(td.className)).map(td => td.parentElement.cells[0].innerText.replace(/\\s+/g, ' ').trim()); return f.length ? 'FAIL: ' + f.join(', ') : 'pass'; })()` },
  { name: 'deviceandbrowserinfo', url: 'https://deviceandbrowserinfo.com/are_you_a_bot', wait: 4000,
    expr: `(() => { const m = /\\{[\\s\\S]*?"isBot"[\\s\\S]*?\\n\\}/.exec(document.body.innerText); if (!m) return 'n/a'; const j = JSON.parse(m[0]); const flags = Object.entries(j.details).filter(([, v]) => v).map(([k]) => k); return (j.isBot ? 'BOT: ' : 'human') + flags.join(', '); })()` },
  { name: 'browserscan', url: 'https://www.browserscan.net/bot-detection', wait: 7000,
    expr: `(() => { const t = document.body.innerText; const r = /Test Results:\\s*\\n\\s*(\\w+)/.exec(t)?.[1]; const bad = [...t.matchAll(/\\n([^\\n]+)\\n\\s*Robot\\b/g)].map(m => m[1].trim()); return (r || 'n/a') + (bad.length ? ' (' + bad.join(', ') + ')' : ''); })()` },
  { name: 'creepjs', url: 'https://abrahamjuliot.github.io/creepjs/', wait: 14000,
    expr: `(() => { const t = document.body.innerText; const g = (re) => re.exec(t)?.[1] ?? '?'; return 'headless ' + g(/(\\d+)% headless/) + '%, like-headless ' + g(/(\\d+)% like headless/) + '%, stealth ' + g(/(\\d+)% stealth/) + '%'; })()` },
];

// mb is driven through its CLI, like an agent would.
import { execFileSync } from 'node:child_process';
async function runMb(name, startOpts) {
  const env = { ...process.env, MB_SESSION: 'st-' + name };
  const mb = (...a) => execFileSync('mb', a, { encoding: 'utf8', env }).trim();
  try { mb('stop'); } catch {}
  mb('start', ...(startOpts.headless ? ['--headless'] : []), ...(startOpts.webgl ? ['--webgl'] : []));
  const out = {};
  for (const t of TESTS) {
    try { mb('goto', t.url, '--quiet'); await sleep(t.wait); out[t.name] = mb('eval', t.expr); }
    catch (e) { out[t.name] = 'error: ' + e.message.split('\n')[0]; }
  }
  mb('stop');
  return out;
}

async function runPlaywright(headless) {
  const { chromium } = require('playwright');
  const proxy = process.env.HTTPS_PROXY ? { server: process.env.HTTPS_PROXY } : undefined;
  const browser = await chromium.launch({ headless, proxy });
  const page = await browser.newPage();
  const out = {};
  for (const t of TESTS) {
    try { await page.goto(t.url, { waitUntil: 'load', timeout: 45000 }); await sleep(t.wait); out[t.name] = await page.evaluate(t.expr); }
    catch (e) { out[t.name] = 'error: ' + e.message.split('\n')[0]; }
  }
  await browser.close();
  return out;
}

const CONFIGS = {
  'playwright-headless': () => runPlaywright(true),
  'playwright-headful': () => runPlaywright(false),
  'mb-headful': () => runMb('headful', {}),
  'mb-headful-webgl': () => runMb('headful-webgl', { webgl: true }),
  'mb-headless': () => runMb('headless', { headless: true }),
};

const only = process.argv[2];
for (const [name, fn] of Object.entries(CONFIGS)) {
  if (only && name !== only) continue;
  const r = await fn();
  console.log(`\n## ${name}`);
  for (const [k, v] of Object.entries(r)) console.log(`  ${k.padEnd(22)} ${v}`);
}
process.exit(0);
