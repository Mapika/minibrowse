// guard.mjs - egress guard for mb. Chrome runs with --proxy-server pointing here
// (and --proxy-bypass-list=<-loopback>), so every request, localhost included,
// passes through this proxy. It keeps pages from reaching the sandbox's own
// network: cloud metadata, internal services, loopback (CDP, live view), LANs.
// Zero dependencies; node: built-ins only.
import http from 'node:http';
import net from 'node:net';
import dns from 'node:dns/promises';

// ---- Address classification -------------------------------------------------
const PRIVATE = new net.BlockList();
for (const c of ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15',
  '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4']) {
  const [a, p] = c.split('/'); PRIVATE.addSubnet(a, +p, 'ipv4');
}
for (const c of ['::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8', '2001:db8::/32',
  '100::/64', 'fec0::/10']) {
  const [a, p] = c.split('/'); PRIVATE.addSubnet(a, +p, 'ipv6');
}

// Expand an IPv6 literal to 16 bytes (handles "::" and a trailing dotted quad).
function v6bytes(ip) {
  let s = ip.split('%')[0], tail = [];
  const m = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (m) { tail = m[1].split('.').map(Number); s = s.slice(0, -m[1].length) + '0:0'; }
  const [l, r] = s.split('::');
  const L = l ? l.split(':') : [], R = r !== undefined && r ? r.split(':') : [];
  const groups = r === undefined ? L : [...L, ...Array(8 - L.length - R.length).fill('0'), ...R];
  const b = groups.flatMap((g) => { const n = parseInt(g || '0', 16); return [n >> 8, n & 255]; });
  if (tail.length) b.splice(12, 4, ...tail);
  return b;
}

// IPv4 embedded in an IPv6 address via IPv4-mapped/compatible (::ffff:a.b.c.d, ::a.b.c.d),
// NAT64 (64:ff9b::/96) or 6to4 (2002:AABB:CCDD::). These forms reach the IPv4 host,
// so they must be judged by the IPv4 rules.
function embeddedV4(ip) {
  const b = v6bytes(ip), zero = (from, to) => b.slice(from, to).every((x) => x === 0);
  if (zero(0, 10) && ((b[10] === 0xff && b[11] === 0xff) || (b[10] === 0 && b[11] === 0)))
    return b.slice(12).join('.');
  if (b[0] === 0 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && zero(4, 12)) return b.slice(12).join('.');
  if (b[0] === 0x20 && b[1] === 0x02) return b.slice(2, 6).join('.');
  return null;
}

export function isPrivateAddress(ip) {
  const fam = net.isIP(ip);
  if (fam === 4) return PRIVATE.check(ip, 'ipv4');
  if (fam !== 6) return true; // unparseable: fail closed
  const bare = ip.split('%')[0];
  if (PRIVATE.check(bare, 'ipv6')) return true;
  const v4 = embeddedV4(bare);
  return v4 !== null && PRIVATE.check(v4, 'ipv4');
}

// Hostnames like "2130706433", "0x7f.1", "0177.0.0.1" are IPv4 in disguise
// (inet_aton accepts them). No legitimate site needs them, so block outright.
const looksNumeric = (h) => /^(0x[0-9a-f]*|\d+)(\.(0x[0-9a-f]*|\d+)){0,3}\.?$/i.test(h);

// ---- Host patterns ----------------------------------------------------------
const norm = (h) => String(h).toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');

// "example.com" = apex + subdomains; "*.example.com" = subdomains only;
// optional ":port" restricts the port. IPv6 patterns may be written "[::1]:443".
export function hostMatches(pattern, host, port) {
  let p = String(pattern).trim().toLowerCase(), pport = null;
  const m = p.match(/^(\[[^\]]+\]|[^:]+):(\d+)$/);
  if (m) { p = m[1]; pport = +m[2]; }
  if (pport !== null && +port !== pport) return false;
  p = norm(p); const h = norm(host);
  if (p.startsWith('*.')) return h.endsWith(p.slice(1));
  return h === p || h.endsWith('.' + p);
}

// ---- Upstream CONNECT tunnel -----------------------------------------------
function openTunnel(upstream, host, port) {
  const u = new URL(upstream);
  const target = `${net.isIP(host) === 6 ? `[${host}]` : host}:${port}`;
  const headers = { host: target };
  if (u.username) headers['proxy-authorization'] = 'Basic ' +
    Buffer.from(`${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`).toString('base64');
  return new Promise((resolve, reject) => {
    const req = http.request({ host: u.hostname.replace(/^\[|\]$/g, ''), port: u.port || 80,
      method: 'CONNECT', path: target, headers, agent: false });
    req.setTimeout(30000, () => req.destroy(new Error('upstream timeout')));
    req.on('connect', (res, sock, head) => {
      if (res.statusCode !== 200) { sock.destroy(); return reject(new Error(`upstream answered ${res.statusCode}`)); }
      if (head?.length) sock.unshift(head);
      resolve(sock);
    });
    req.on('response', (res) => { res.resume(); reject(new Error(`upstream answered ${res.statusCode}`)); });
    req.on('error', reject);
    req.end();
  });
}

const HOP = new Set(['connection', 'proxy-connection', 'keep-alive', 'proxy-authorization',
  'proxy-authenticate', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
const stripHop = (h) => Object.fromEntries(Object.entries(h).filter(([k]) => !HOP.has(k.toLowerCase())));

// ---- Server -----------------------------------------------------------------
export async function startGuard({ allow = [], deny = [], allowPrivate = [], upstream = null,
  onBlock = () => {}, host = '127.0.0.1' } = {}) {
  const stats = { allowed: 0, blocked: 0 };
  const sockets = new Set();
  const track = (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)); s.on('error', () => {}); return s; };
  const privOK = new Set(allowPrivate.map((e) => String(e).toLowerCase().replace(/\.(?=:\d+$|$)/, '')));

  // Returns { address } for a direct connection, { tunnel: true } for upstream, or { reason }.
  async function decide(rawHost, port) {
    const h = norm(rawHost);
    if (!h) return { reason: 'empty host' };
    if (!(port >= 1 && port <= 65535)) return { reason: 'bad port' };
    if (deny.some((p) => hostMatches(p, h, port))) return { reason: 'denied by pattern' };
    if (allow.length && !allow.some((p) => hostMatches(p, h, port))) return { reason: 'not in allow list' };
    const fam = net.isIP(h);
    if (!fam && looksNumeric(h)) return { reason: 'numeric host encoding' };
    let addrs;
    try { addrs = fam ? [{ address: h, family: fam }] : await dns.lookup(h, { all: true, verbatim: true }); }
    catch (e) { return { reason: `dns lookup failed (${e.code || e.message})` }; }
    if (!addrs.length) return { reason: 'no addresses' };
    // ANY private answer blocks: a hostile DNS server can mix public and private
    // records and we must not let the connect step pick the private one.
    if (addrs.some((a) => isPrivateAddress(a.address))) {
      const hp = fam === 6 ? `[${h}]:${port}` : `${h}:${port}`;
      if (!privOK.has(h) && !privOK.has(hp) && !privOK.has(`${h}:${port}`)) return { reason: 'private address' };
      return { addresses: addrs.map((a) => a.address) }; // allowed private target: always direct
    }
    // Public. Connect to the exact IPs we vetted (never re-resolve: DNS rebinding).
    // With an upstream we must hand it the hostname instead (see limitations).
    return upstream ? { tunnel: true, host: h } : { addresses: addrs.map((a) => a.address) };
  }

  function block(hostName, port, reason) {
    stats.blocked++;
    try { onBlock({ host: hostName, port, reason, at: new Date().toISOString() }); } catch {}
  }

  const connectOne = (address, port) => new Promise((resolve, reject) => {
    const s = net.connect({ host: address, port });
    s.setTimeout(30000, () => s.destroy(new Error('connect timeout')));
    s.once('connect', () => { s.setTimeout(0); s.off('error', reject); resolve(s); });
    s.once('error', reject);
  });
  // Try each vetted address in order (e.g. localhost -> ::1 then 127.0.0.1), like a normal client.
  async function connectTo(d, port) {
    if (d.tunnel) return openTunnel(upstream, d.host, port);
    let err;
    for (const a of d.addresses) {
      try { return await connectOne(a, port); } catch (e) { err = e; }
    }
    throw err;
  }

  const server = http.createServer();
  server.on('connection', track);
  server.on('clientError', (err, s) => { if (s.writable) s.end('HTTP/1.1 400 Bad Request\r\n\r\n'); else s.destroy(); });

  // CONNECT host:port (HTTPS, wss). Each CONNECT takes over its own client socket.
  server.on('connect', async (req, client, head) => {
    track(client);
    const m = String(req.url).match(/^(\[[^\]]+\]|[^:/]+):(\d+)$/);
    const hostName = m ? norm(m[1]) : String(req.url), port = m ? +m[2] : 0;
    const d = m ? await decide(hostName, port) : { reason: 'malformed CONNECT target' };
    if (d.reason) {
      block(hostName, port, d.reason);
      const body = `Blocked by mb egress guard: ${d.reason}\n`;
      return client.end(`HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
    }
    try {
      const remote = track(await connectTo(d, port));
      if (client.destroyed) return remote.destroy();
      stats.allowed++;
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head?.length) remote.write(head);
      remote.pipe(client).on('error', () => {}); client.pipe(remote);
      remote.on('close', () => client.destroy()); client.on('close', () => remote.destroy());
    } catch (e) {
      client.end(`HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nmb egress guard: ${e.message}\n`);
    }
  });

  // Absolute-form plain HTTP: GET http://host[:port]/path.
  server.on('request', async (req, res) => {
    const fail = (code, msg) => { if (!res.headersSent) res.writeHead(code, { 'content-type': 'text/plain' }); res.end(msg + '\n'); };
    let url;
    try { url = new URL(req.url); } catch { return fail(400, 'mb egress guard: absolute-form URL required'); }
    if (url.protocol !== 'http:') return fail(400, 'mb egress guard: only http:// is proxied in absolute form');
    const hostName = norm(url.hostname), port = +(url.port || 80);
    const d = await decide(hostName, port);
    if (d.reason) { block(hostName, port, d.reason); req.resume(); return fail(403, `Blocked by mb egress guard: ${d.reason}`); }
    let sock;
    try { sock = track(await connectTo(d, port)); } catch (e) { req.resume(); return fail(502, `mb egress guard: ${e.message}`); }
    stats.allowed++;
    const headers = stripHop(req.headers);
    headers.host = url.host; // original Host header, even though we dial an IP
    headers.connection = 'close';
    const out = http.request({ createConnection: () => sock, method: req.method,
      path: url.pathname + url.search, headers, setHost: false });
    out.on('response', (pres) => { res.writeHead(pres.statusCode, pres.statusMessage, stripHop(pres.headers)); pres.pipe(res); });
    out.on('error', (e) => { fail(502, `mb egress guard: ${e.message}`); res.destroy(); });
    res.on('close', () => out.destroy());
    req.pipe(out);
  });

  // Upgrade over absolute-form HTTP is not supported (Chrome uses CONNECT for ws via proxies).
  server.on('upgrade', (req, s) => { track(s); s.end('HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n'); });

  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, host, resolve); });
  server.on('error', () => {});
  return {
    port: server.address().port,
    stats,
    close: () => new Promise((resolve) => {
      server.close(() => resolve());
      for (const s of sockets) s.destroy();
      server.closeAllConnections?.();
    }),
  };
}
