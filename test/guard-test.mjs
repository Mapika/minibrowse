// Tests for guard.mjs. Run: node test/guard-test.mjs   (exit 0 = all passed)
import net from 'node:net';
import http from 'node:http';
import tls from 'node:tls';
import fs from 'node:fs';
import dns from 'node:dns/promises';
import { startGuard, hostMatches, isPrivateAddress } from '../guard.mjs';

let passed = 0, failed = 0, skipped = 0;
const check = (name, cond, extra = '') => {
  if (cond) { passed++; console.log(`ok   ${name}`); }
  else { failed++; console.log(`FAIL ${name}${extra ? ' -- ' + extra : ''}`); }
};
const skip = (name, why) => { skipped++; console.log(`skip ${name} (${why})`); };

// Raw CONNECT through the guard; resolves { status, headers, body, socket }.
function rawConnect(guardPort, target, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const s = net.connect(guardPort, '127.0.0.1');
    let buf = Buffer.alloc(0);
    const t = setTimeout(() => { s.destroy(); reject(new Error('timeout')); }, timeoutMs);
    s.on('error', (e) => { clearTimeout(t); reject(e); });
    s.on('connect', () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      const i = buf.indexOf('\r\n\r\n');
      if (i < 0) return;
      s.off('data', onData); clearTimeout(t);
      const head = buf.subarray(0, i).toString();
      const rest = buf.subarray(i + 4);
      const status = +head.split(' ')[1];
      if (status !== 200) {
        // read the short body until close
        let body = rest.toString();
        s.on('data', (x) => { body += x; });
        s.on('close', () => resolve({ status, head, body, socket: s }));
      } else {
        if (rest.length) s.unshift(rest);
        resolve({ status, head, body: '', socket: s });
      }
    };
    s.on('data', onData);
  });
}

// Absolute-form GET through the guard.
function proxyGet(guardPort, url, agent) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: guardPort, path: url, method: 'GET',
      headers: { host: new URL(url).host }, agent: agent ?? false });
    req.setTimeout(15000, () => req.destroy(new Error('timeout')));
    req.on('response', (res) => { let b = ''; res.on('data', (d) => (b += d)); res.on('end', () => resolve({ status: res.statusCode, body: b })); });
    req.on('error', reject);
    req.end();
  });
}

const listen = (srv) => new Promise((r) => srv.listen(0, '127.0.0.1', () => r(srv.address().port)));

// ---- local test servers ----
const echo = net.createServer((s) => { s.on('error', () => {}); s.pipe(s); });
const echoPort = await listen(echo);
let lastHostHeader = null;
const web = http.createServer((req, res) => { lastHostHeader = req.headers.host; res.end('hello from local'); });
const webPort = await listen(web);

// ---- 1. pure-function tests ----
const pm = [
  ['example.com', 'example.com', 443, true], ['example.com', 'a.b.example.com', 443, true],
  ['example.com', 'notexample.com', 443, false], ['example.com', 'example.com.evil.net', 443, false],
  ['*.example.com', 'example.com', 443, false], ['*.example.com', 'www.example.com', 443, true],
  ['example.com:443', 'example.com', 443, true], ['example.com:443', 'example.com', 80, false],
  ['EXAMPLE.com.', 'www.Example.COM.', 80, true], ['[::1]:8080', '[::1]', 8080, true],
  ['*.example.com:8443', 'x.example.com', 8443, true], ['*.example.com:8443', 'x.example.com', 443, false],
];
for (const [p, h, port, want] of pm) check(`hostMatches(${p}, ${h}, ${port}) = ${want}`, hostMatches(p, h, port) === want);
for (const [ip, want] of [['127.0.0.1', true], ['10.1.2.3', true], ['100.64.0.1', true], ['172.31.255.255', true],
  ['172.32.0.1', false], ['169.254.169.254', true], ['198.19.0.1', true], ['8.8.8.8', false], ['::1', true], ['::', true],
  ['fd00::1', true], ['fe80::1%eth0', true], ['ff02::1', true], ['2001:db8::1', true], ['::ffff:127.0.0.1', true],
  ['::ffff:7f00:1', true], ['64:ff9b::a00:1', true], ['64:ff9b::808:808', false], ['2002:7f00:1::', true],
  ['::ffff:8.8.8.8', false], ['2606:4700::1111', false]])
  check(`isPrivateAddress(${ip}) = ${want}`, isPrivateAddress(ip) === want);

// ---- 2. default guard blocks private targets ----
const blocks = [];
const g = await startGuard({ onBlock: (b) => blocks.push(b) });
for (const target of [`127.0.0.1:${echoPort}`, `localhost:${echoPort}`, '169.254.169.254:80', '10.0.0.1:443',
  `[::1]:${echoPort}`, `[::ffff:127.0.0.1]:${echoPort}`, `[64:ff9b::7f00:1]:${echoPort}`, `0x7f000001:${echoPort}`,
  `2130706433:${echoPort}`, `0177.0.0.1:${echoPort}`, `LOCALHOST.:${echoPort}`]) {
  const r = await rawConnect(g.port, target);
  check(`CONNECT ${target} blocked with 403`, r.status === 403 && /Blocked by mb egress guard/.test(r.body), r.head);
}
const loopName = blocks.find((b) => b.host === 'localhost');
check('hostname resolving to loopback blocked as private address', loopName?.reason === 'private address', JSON.stringify(loopName));
try {
  const a = await dns.lookup('127.0.0.1.nip.io', { all: true });
  if (!a.some((x) => x.address === '127.0.0.1')) throw new Error('unexpected answer');
  const r = await rawConnect(g.port, `127.0.0.1.nip.io:${echoPort}`);
  check('CONNECT 127.0.0.1.nip.io blocked (DNS -> loopback)', r.status === 403 && /private address/.test(r.body), r.body);
} catch (e) { skip('CONNECT 127.0.0.1.nip.io', `DNS unavailable: ${e.code || e.message}`); }

let r = await proxyGet(g.port, `http://localhost:${webPort}/`);
check('GET http://localhost:<port>/ blocked by default', r.status === 403 && /Blocked by mb egress guard: private address/.test(r.body), `${r.status} ${r.body}`);
r = await proxyGet(g.port, `http://169.254.169.254/latest/meta-data/`);
check('GET metadata endpoint blocked', r.status === 403, `${r.status}`);
check('onBlock called for every block', blocks.length === g.stats.blocked && blocks.every((b) => b.at && b.reason && 'port' in b),
  `${blocks.length} vs ${g.stats.blocked}`);
check('stats counted (blocked > 0, allowed == 0)', g.stats.blocked >= 13 && g.stats.allowed === 0, JSON.stringify(g.stats));
await g.close();

// ---- 3. allowPrivate lets exact host:port through, bytes flow ----
const g2 = await startGuard({ allowPrivate: [`localhost:${echoPort}`, `localhost:${webPort}`] });
r = await rawConnect(g2.port, `localhost:${echoPort}`);
check('allowPrivate localhost:<echo> CONNECT -> 200', r.status === 200, r.head);
if (r.status === 200) {
  const got = await new Promise((resolve) => {
    let b = ''; r.socket.on('data', (d) => { b += d; if (b.includes('ping-pong')) resolve(b); });
    setTimeout(() => resolve(b), 3000);
    r.socket.write('ping-pong');
  });
  check('bytes flow through allowed tunnel (echo)', got === 'ping-pong', JSON.stringify(got));
  r.socket.destroy();
}
r = await rawConnect(g2.port, `127.0.0.1:${echoPort}`);
check('allowPrivate is exact: 127.0.0.1:<echo> still blocked', r.status === 403, r.head);
r = await rawConnect(g2.port, `localhost:1`);
check('allowPrivate is exact: localhost:1 still blocked', r.status === 403, r.head);
r = await proxyGet(g2.port, `http://localhost:${webPort}/`);
check('GET http://localhost:<port>/ allowed with allowPrivate', r.status === 200 && r.body === 'hello from local', `${r.status} ${r.body}`);
check('original Host header forwarded', lastHostHeader === `localhost:${webPort}`, lastHostHeader);
// One keep-alive proxy connection used for two different targets (Chrome does this).
const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
const a1 = await proxyGet(g2.port, `http://localhost:${webPort}/one`, agent);
const a2 = await proxyGet(g2.port, `http://10.0.0.1/two`, agent);
const a3 = await proxyGet(g2.port, `http://localhost:${webPort}/three`, agent);
check('reused proxy connection judges each request separately', a1.status === 200 && a2.status === 403 && a3.status === 200,
  `${a1.status} ${a2.status} ${a3.status}`);
agent.destroy();
check('stats on allowPrivate guard', g2.stats.allowed >= 4 && g2.stats.blocked >= 3, JSON.stringify(g2.stats));
await g2.close();

// ---- 4. allow/deny lists enforced by the server (decided before DNS) ----
const g3 = await startGuard({ allow: ['example.com', '*.allowed.test:443'], deny: ['bad.example.com'] });
for (const [t, want] of [['evil.com:443', 'not in allow list'], ['bad.example.com:443', 'denied by pattern'],
  ['x.bad.example.com:443', 'denied by pattern'], ['allowed.test:443', 'not in allow list'],
  ['a.allowed.test:80', 'not in allow list']]) {
  const x = await rawConnect(g3.port, t);
  check(`allow/deny: CONNECT ${t} -> 403 ${want}`, x.status === 403 && x.body.includes(want), x.body.trim());
}
await g3.close();

// ---- 5. close() really closes ----
const g4 = await startGuard({ allowPrivate: [`localhost:${echoPort}`] });
const open = await rawConnect(g4.port, `localhost:${echoPort}`);
const closedP = new Promise((res) => open.socket.on('close', res));
await g4.close();
await Promise.race([closedP, new Promise((res) => setTimeout(res, 2000))]);
check('close() destroys open tunnels', open.socket.destroyed);
const refused = await new Promise((res) => { const s = net.connect(g4.port, '127.0.0.1'); s.on('error', () => res(true)); s.on('connect', () => { s.destroy(); res(false); }); });
check('close() stops listening', refused);

// ---- 6. public host via the environment's upstream proxy ----
const up = process.env.HTTPS_PROXY || process.env.https_proxy;
if (!up) skip('upstream proxy checks', 'HTTPS_PROXY not set');
else {
  const g5 = await startGuard({ upstream: up });
  const x = await rawConnect(g5.port, 'example.com:443', 30000).catch((e) => ({ status: 0, head: e.message }));
  check('CONNECT example.com:443 via upstream -> 200', x.status === 200 && /^HTTP\/1\.[01] 200/.test(x.head), x.head);
  if (x.status === 200) {
    const caPath = '/root/.ccr/ca-bundle.crt';
    const ca = fs.existsSync(caPath) ? fs.readFileSync(caPath) : undefined;
    const resp = await new Promise((resolve) => {
      const t = tls.connect({ socket: x.socket, servername: 'example.com', ca });
      let b = '';
      t.on('secureConnect', () => t.write('GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'));
      t.on('data', (d) => (b += d));
      t.on('end', () => resolve(b)); t.on('close', () => resolve(b));
      t.on('error', (e) => resolve('TLS ERROR ' + e.message));
      setTimeout(() => { t.destroy(); resolve(b); }, 20000);
    });
    check('TLS handshake + GET through guard+upstream returns HTTP/1.1', resp.startsWith('HTTP/1.1'), resp.slice(0, 80));
  }
  const y = await rawConnect(g5.port, `localhost:${echoPort}`);
  check('upstream mode still blocks loopback', y.status === 403, y.head);
  const z = await proxyGet(g5.port, 'http://169.254.169.254/').catch((e) => ({ status: 0, body: e.message }));
  check('upstream mode still blocks metadata over plain HTTP', z.status === 403, `${z.status}`);
  // Plain HTTP via an upstream tunnel to :80. The sandbox proxy may refuse port 80; informational only.
  const p = await proxyGet(g5.port, 'http://example.com/').catch((e) => ({ status: 0, body: e.message }));
  if (p.status === 200) check('plain GET http://example.com/ via upstream tunnel', true);
  else skip('plain GET http://example.com/ via upstream tunnel', `got ${p.status}: ${p.body.trim().slice(0, 80)}`);
  await g5.close();
}

echo.close(); web.close();
console.log(`\n${passed} passed, ${failed} failed, ${skipped} skipped`);
process.exit(failed ? 1 : 0);
