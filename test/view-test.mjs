// A "human" (Playwright, separate browser) uses mb's live view: clicks, types, and finishes a handoff.
import { execFileSync, spawn } from 'node:child_process';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const mb = (...a) => execFileSync('mb', a, { encoding: 'utf8', env: { ...process.env, MB_SESSION: 'viewtest' } }).trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

mb('goto', 'https://todomvc.com/examples/react/dist/');
const ho = spawn('mb', ['handoff', 'Add a todo called "from the human", then click Done', '--timeout', '60'], { env: { ...process.env, MB_SESSION: 'viewtest' } });
let hoOut = '', hoErr = '';
ho.stdout.on('data', (d) => (hoOut += d)); ho.stderr.on('data', (d) => (hoErr += d));
import fs from 'node:fs';
const hf = `${process.env.HOME}/.mb/viewtest/handoff.json`;
for (let i = 0; i < 100 && !fs.existsSync(hf); i++) await sleep(100);
if (/\?t=/.test(hoErr)) throw new Error('the handoff URL leaked to the agent');
const url = JSON.parse(fs.readFileSync(hf, 'utf8')).url;
console.log('handoff url:', url.replace(/t=\w+/, 't=…'));

const browser = await chromium.launch();
const human = await browser.newPage({ viewport: { width: 1400, height: 900 } });
await human.goto(url);
await human.waitForFunction(() => document.getElementById('s').src.startsWith('data:image'), null, { timeout: 15000 });
console.log('banner:', await human.locator('#msg').innerText());
// click where the input is: find it via mb's own coordinates, map to the image
const box = await human.locator('#s').boundingBox();
const r = mb('eval', '(() => { const b = document.querySelector(".new-todo").getBoundingClientRect(); return JSON.stringify([b.x + b.width / 2, b.y + b.height / 2, innerWidth, innerHeight]); })()');
const [cx, cy, vw, vh] = JSON.parse(r);
await human.mouse.click(box.x + (cx / vw) * box.width, box.y + (cy / vh) * box.height);
await sleep(300);
await human.keyboard.type('from the human', { delay: 40 });
await human.keyboard.press('Enter');
await sleep(800);
await human.screenshot({ path: new URL('./live-view.png', import.meta.url).pathname });
await human.click('#done');
for (let i = 0; i < 40 && ho.exitCode === null; i++) await sleep(250);
console.log('handoff returned:', hoOut.trim());
console.log('page now:', mb('find', 'from the human'));
await browser.close();
mb('stop');
