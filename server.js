import { createServer } from 'node:http';
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from 'node:crypto';
import mqtt from 'mqtt';

const here = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(here, 'public');
const port = Number(process.env.PORT || 3000);
const brokerUrl = process.env.MQTT_URL || 'mqtt://192.168.1.11:1883';
const healthTimeoutMs = Number(process.env.HEALTH_ONLINE_TIMEOUT_MS || 30000);
const credentialsFile = process.env.CREDENTIALS_FILE || '';
const sessionStorePath = path.resolve(here, process.env.SESSION_STORE_FILE || 'data/sessions.json');
const sessionLifetimeMs = 30 * 24 * 60 * 60 * 1000;
const passwordIterations = 310000;
const authSalt = randomBytes(16);
const hasEnvCredentials = Boolean(process.env.APP_USERNAME || process.env.APP_PASSWORD);

if (hasEnvCredentials && (!process.env.APP_USERNAME || !process.env.APP_PASSWORD)) {
  throw new Error('Set both APP_USERNAME and APP_PASSWORD.');
}
if (hasEnvCredentials && credentialsFile) {
  throw new Error('Configure credentials with either APP_USERNAME/APP_PASSWORD or CREDENTIALS_FILE, not both.');
}
if (!hasEnvCredentials && !credentialsFile) {
  throw new Error('Set APP_USERNAME and APP_PASSWORD, or set CREDENTIALS_FILE.');
}
if (!Number.isFinite(healthTimeoutMs) || healthTimeoutMs < 1000) {
  throw new Error('HEALTH_ONLINE_TIMEOUT_MS must be at least 1000.');
}

let credentials;
if (credentialsFile) {
  const file = path.isAbsolute(credentialsFile) ? credentialsFile : path.resolve(here, credentialsFile);
  credentials = JSON.parse(await readFile(file, 'utf8'));
} else {
  credentials = { username: process.env.APP_USERNAME, password: process.env.APP_PASSWORD };
}
if (!credentials || typeof credentials !== 'object' ||
    typeof credentials.username !== 'string' || !credentials.username ||
    typeof credentials.password !== 'string' || !credentials.password) {
  throw new Error('Credentials must contain non-empty username and password strings.');
}

const passwordVerifier = pbkdf2Sync(credentials.password, authSalt, passwordIterations, 32, 'sha256');
await mkdir(path.dirname(sessionStorePath), { recursive: true, mode: 0o700 });
await chmod(path.dirname(sessionStorePath), 0o700);
let savedSessions = {};
try {
  savedSessions = JSON.parse(await readFile(sessionStorePath, 'utf8'));
  await chmod(sessionStorePath, 0o600);
  if (!savedSessions || typeof savedSessions !== 'object' || Array.isArray(savedSessions)) savedSessions = {};
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}
const sessions = new Map(Object.entries(savedSessions).filter(([, expires]) => Number.isFinite(expires) && expires > Date.now()));
let persistQueue = Promise.resolve();
const loginChallenges = new Map();
const loginFailures = new Map();
const states = { switch1: null, switch2: null };
let lastHealthMessageAt = 0;
const eventClients = new Map();
const contentTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8'
};
const mqttOptions = {
  clientId: process.env.MQTT_CLIENT_ID || `esp32_web_${randomBytes(5).toString('hex')}`,
  clean: true,
  connectTimeout: 10000,
  reconnectPeriod: 3000
};
if (process.env.MQTT_USERNAME) mqttOptions.username = process.env.MQTT_USERNAME;
if (process.env.MQTT_PASSWORD) mqttOptions.password = process.env.MQTT_PASSWORD;
const mqttClient = mqtt.connect(brokerUrl, mqttOptions);

function healthOnline() {
  return lastHealthMessageAt > 0 && Date.now() - lastHealthMessageAt <= healthTimeoutMs;
}

function currentStatus() {
  return { states, healthOnline: healthOnline(), mqttConnected: mqttClient.connected };
}

function broadcast(event, data) {
  const line = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const [response, request] of eventClients) {
    if (!sessionFor(request)) { response.end(); eventClients.delete(response); }
    else response.write(line);
  }
}

function broadcastStatus() {
  broadcast('status', currentStatus());
}

mqttClient.on('connect', () => {
  mqttClient.subscribe(['esp32/health', 'esp32/switch1', 'esp32/switch2'], { qos: 1 }, (error) => {
    if (error) console.error('MQTT subscription failed:', error.message);
  });
  broadcastStatus();
});

mqttClient.on('message', (topic, payload) => {
  const value = payload.toString().trim().toUpperCase();
  if (topic === 'esp32/health') {
    lastHealthMessageAt = Date.now();
    broadcastStatus();
    return;
  }
  const id = topic === 'esp32/switch1' ? 'switch1' : topic === 'esp32/switch2' ? 'switch2' : null;
  if (!id) return;
  if (value === 'ON') states[id] = true;
  else if (value === 'OFF') states[id] = false;
  else return;
  broadcastStatus();
});

mqttClient.on('error', (error) => console.error('MQTT connection error:', error.message));
mqttClient.on('close', broadcastStatus);
setInterval(broadcastStatus, Math.min(healthTimeoutMs, 5000)).unref();

function parseCookies(header = '') {
  return Object.fromEntries(header.split(';').map((part) => {
    const index = part.indexOf('=');
    return index < 0 ? ['', ''] : [part.slice(0, index).trim(), part.slice(index + 1).trim()];
  }).filter(([key]) => key));
}

function secureEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function tokenHash(token) {
  return createHash('sha256').update(token).digest('hex');
}

function persistSessions() {
  persistQueue = persistQueue.catch(() => {}).then(async () => {
    const temporary = `${sessionStorePath}.${randomBytes(4).toString('hex')}.tmp`;
    await writeFile(temporary, JSON.stringify(Object.fromEntries(sessions)), { mode: 0o600 });
    await rename(temporary, sessionStorePath);
  });
  return persistQueue;
}

function sessionFor(request) {
  const token = parseCookies(request.headers.cookie).esp32_session;
  if (!token) return null;
  const hash = tokenHash(token);
  const expires = sessions.get(hash);
  if (!expires) return null;
  if (expires <= Date.now()) {
    sessions.delete(hash);
    persistSessions().catch((error) => console.error('Could not update session store:', error.message));
    return null;
  }
  return hash;
}

function loginRateLimited(request) {
  const key = clientAddress(request);
  const entry = loginFailures.get(key);
  if (!entry || entry.resetAt <= Date.now()) {
    loginFailures.delete(key);
    return false;
  }
  return entry.count >= 8;
}

function recordLoginFailure(request) {
  const key = clientAddress(request);
  const entry = loginFailures.get(key);
  if (!entry || entry.resetAt <= Date.now()) loginFailures.set(key, { count: 1, resetAt: Date.now() + 15 * 60 * 1000 });
  else entry.count += 1;
}

function clientAddress(request) {
  if (process.env.TRUST_PROXY === 'true') {
    const forwarded = request.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim();
  }
  return request.socket.remoteAddress || 'unknown';
}

setInterval(() => {
  const now = Date.now();
  let sessionsChanged = false;
  for (const [hash, expires] of sessions) {
    if (expires <= now) { sessions.delete(hash); sessionsChanged = true; }
  }
  for (const [id, challenge] of loginChallenges) {
    if (now - challenge.createdAt > 90000) loginChallenges.delete(id);
  }
  for (const [address, failure] of loginFailures) {
    if (failure.resetAt <= now) loginFailures.delete(address);
  }
  if (sessionsChanged) persistSessions().catch((error) => console.error('Could not update session store:', error.message));
}, 60000).unref();

function sameOrigin(request) {
  const origin = request.headers.origin;
  if (typeof origin !== 'string') return false;
  try { return new URL(origin).host === request.headers.host; }
  catch { return false; }
}

function json(response, status, body) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Referrer-Policy': 'no-referrer'
  });
  response.end(JSON.stringify(body));
}

async function readJson(request) {
  let body = '';
  for await (const chunk of request) {
    body += chunk;
    if (body.length > 4096) throw new Error('Request body too large.');
  }
  return JSON.parse(body || '{}');
}

async function serveStatic(request, response, pathname) {
  const name = pathname === '/' ? 'index.html' : decodeURIComponent(pathname.slice(1));
  const filePath = path.resolve(publicDir, name);
  if (!filePath.startsWith(`${publicDir}${path.sep}`)) {
    response.writeHead(404).end();
    return;
  }
  try {
    const file = await readFile(filePath);
    const headers = {
      'Content-Type': contentTypes[path.extname(filePath)] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
    };
    if (process.env.NODE_ENV === 'production' && request.headers['x-forwarded-proto'] === 'https') {
      headers['Strict-Transport-Security'] = 'max-age=31536000';
    }
    response.writeHead(200, headers);
    response.end(file);
  } catch {
    response.writeHead(404).end();
  }
}

const server = createServer(async (request, response) => {
  let url;
  try { url = new URL(request.url, `http://${request.headers.host}`); }
  catch { response.writeHead(400).end(); return; }

  if (request.method === 'POST' && url.pathname === '/api/login/challenge') {
    if (!sameOrigin(request)) { json(response, 403, { error: 'Same-origin request required.' }); return; }
    try { await readJson(request); }
    catch { json(response, 400, { error: 'Invalid request.' }); return; }
    const now = Date.now();
    for (const [id, challenge] of loginChallenges) {
      if (now - challenge.createdAt > 90000) loginChallenges.delete(id);
    }
    if (loginChallenges.size > 10000) { json(response, 503, { error: 'Login service busy.' }); return; }
    const challengeId = randomBytes(24).toString('hex');
    const nonce = randomBytes(32);
    loginChallenges.set(challengeId, { nonce, createdAt: now });
    json(response, 200, {
      challengeId,
      nonce: nonce.toString('hex'),
      salt: authSalt.toString('hex'),
      iterations: passwordIterations
    });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/login') {
    if (!sameOrigin(request)) { json(response, 403, { error: 'Same-origin request required.' }); return; }
    if (loginRateLimited(request)) { json(response, 429, { error: 'Too many login attempts. Try again in 15 minutes.' }); return; }
    let body;
    try { body = await readJson(request); }
    catch { json(response, 400, { error: 'Invalid request.' }); return; }
    const challenge = typeof body?.challengeId === 'string' ? loginChallenges.get(body.challengeId) : null;
    if (body?.challengeId) loginChallenges.delete(body.challengeId);
    if (!challenge || Date.now() - challenge.createdAt > 90000 ||
        typeof body.username !== 'string' || typeof body.proof !== 'string' || !/^[a-f0-9]{64}$/i.test(body.proof)) {
      recordLoginFailure(request);
      json(response, 401, { error: 'Incorrect username or password.' });
      return;
    }
    const expectedProof = createHmac('sha256', passwordVerifier)
      .update(challenge.nonce).update('\0').update(body.username).digest();
    const suppliedProof = Buffer.from(body.proof, 'hex');
    const proofValid = suppliedProof.length === expectedProof.length && timingSafeEqual(expectedProof, suppliedProof);
    const usernameValid = secureEqual(body.username, credentials.username);
    if (!proofValid || !usernameValid) {
      recordLoginFailure(request);
      json(response, 401, { error: 'Incorrect username or password.' });
      return;
    }
    if (process.env.NODE_ENV === 'production' && request.headers['x-forwarded-proto'] !== 'https') {
      json(response, 400, { error: 'HTTPS is required for login in production.' });
      return;
    }
    loginFailures.delete(clientAddress(request));
    const token = randomBytes(32).toString('hex');
    sessions.set(tokenHash(token), Date.now() + sessionLifetimeMs);
    try { await persistSessions(); }
    catch (error) {
      sessions.delete(tokenHash(token));
      console.error('Could not persist login session:', error.message);
      json(response, 500, { error: 'Could not save login session.' });
      return;
    }
    const secure = process.env.NODE_ENV === 'production' || request.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
    response.setHeader('Set-Cookie', `esp32_session=${token}; HttpOnly${secure}; SameSite=Strict; Path=/; Max-Age=${Math.floor(sessionLifetimeMs / 1000)}`);
    json(response, 200, { authenticated: true });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/logout') {
    if (!sameOrigin(request)) { json(response, 403, { error: 'Same-origin request required.' }); return; }
    const sessionHash = sessionFor(request);
    if (sessionHash) {
      sessions.delete(sessionHash);
      await persistSessions();
    }
    const secure = process.env.NODE_ENV === 'production' || request.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
    response.setHeader('Set-Cookie', `esp32_session=; HttpOnly${secure}; SameSite=Strict; Path=/; Max-Age=0`);
    json(response, 200, { authenticated: false });
    return;
  }

  if (url.pathname.startsWith('/api/')) {
    if (!sessionFor(request)) { json(response, 401, { error: 'Login required.' }); return; }
    if (request.method === 'GET' && url.pathname === '/api/status') {
      json(response, 200, currentStatus());
      return;
    }
    if (request.method === 'GET' && url.pathname === '/api/events') {
      response.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
      });
      response.write(': connected\n\n');
      eventClients.set(response, request);
      response.write(`event: status\ndata: ${JSON.stringify(currentStatus())}\n\n`);
      const heartbeat = setInterval(() => {
        if (!sessionFor(request)) response.end();
        else response.write(': keep-alive\n\n');
      }, 20000);
      response.on('close', () => { clearInterval(heartbeat); eventClients.delete(response); });
      return;
    }
    const match = url.pathname.match(/^\/api\/(switch1|switch2)$/);
    if (request.method === 'POST' && match) {
      if (!sameOrigin(request)) { json(response, 403, { error: 'Same-origin request required.' }); return; }
      let body;
      try { body = await readJson(request); }
      catch { json(response, 400, { error: 'Invalid request.' }); return; }
      if (typeof body?.on !== 'boolean') { json(response, 400, { error: 'Expected an on value.' }); return; }
      if (!mqttClient.connected) { json(response, 503, { error: 'MQTT broker is not connected.' }); return; }
      mqttClient.publish(`esp32/${match[1]}`, body.on ? 'ON' : 'OFF', { qos: 1, retain: false }, (error) => {
        if (error) json(response, 502, { error: 'Could not publish switch command.' });
        else json(response, 202, { accepted: true });
      });
      return;
    }
    json(response, 404, { error: 'Not found.' });
    return;
  }

  if (request.method === 'GET') await serveStatic(request, response, url.pathname);
  else response.writeHead(404).end();
});

server.listen(port, '0.0.0.0', () => console.log(`ESP32 Switch app listening on port ${port}; MQTT broker ${brokerUrl}`));

function shutdown() {
  for (const response of eventClients.keys()) response.end();
  mqttClient.end(true);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
