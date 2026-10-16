(() => {
  const loginPanel = document.getElementById('login-panel');
  const dashboard = document.getElementById('dashboard');
  const form = document.getElementById('login-form');
  const passwordInput = document.getElementById('password');
  const loginError = document.getElementById('login-error');
  const notice = document.getElementById('notice');
  const ids = ['switch1', 'switch2'];
  const toggles = Object.fromEntries(ids.map((id) => [id, document.getElementById(`toggle-${id}`)]));
  const pending = new Set();
  let states = { switch1: null, switch2: null };
  let requestedStates = { switch1: null, switch2: null };
  let mqttConnected = false;
  let events;

  function showLogin() {
    dashboard.hidden = true;
    loginPanel.hidden = false;
    document.getElementById('username').focus();
  }

  function showDashboard() {
    loginPanel.hidden = true;
    dashboard.hidden = false;
  }

  function renderControls() {
    for (const id of ids) {
      const value = states[id];
      const shownValue = value ?? requestedStates[id];
      toggles[id].setAttribute('aria-checked', String(shownValue === true));
      toggles[id].disabled = !mqttConnected || pending.has(id);
      document.getElementById(`state-${id}`).textContent = value !== null
        ? value ? 'On' : 'Off'
        : requestedStates[id] !== null ? 'Command sent · waiting for state' : 'No state yet · tap to turn on';
    }
  }

  function renderStatus(data) {
    if (data.states) {
      for (const id of ids) {
        if (typeof data.states[id] === 'boolean') {
          states[id] = data.states[id];
          requestedStates[id] = null;
        }
      }
    }
    mqttConnected = data.mqttConnected === true;
    renderControls();
    const healthLight = document.getElementById('health-light');
    healthLight.classList.toggle('online', data.healthOnline === true);
    document.getElementById('health-title').textContent = data.healthOnline ? 'ESP32 online' : 'ESP32 offline';
    document.getElementById('health-detail').textContent = data.healthOnline
      ? 'Health messages are arriving'
      : 'No recent message on esp32/health';
    const broker = document.getElementById('broker-state');
    broker.textContent = mqttConnected ? 'Broker connected' : 'Broker disconnected';
    broker.classList.toggle('connected', mqttConnected);
  }

  function bytesFromHex(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i += 1) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return bytes;
  }

  function toHex(bytes) {
    return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  async function makeProof(password, username, challenge) {
    if (!globalThis.crypto?.subtle) throw new Error('Secure browser cryptography is unavailable. Open this app over HTTPS.');
    const encoder = new TextEncoder();
    const baseKey = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const verifier = await crypto.subtle.deriveBits({
      name: 'PBKDF2', hash: 'SHA-256', salt: bytesFromHex(challenge.salt), iterations: challenge.iterations
    }, baseKey, 256);
    const hmacKey = await crypto.subtle.importKey('raw', verifier, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const nameBytes = encoder.encode(username);
    const nonce = bytesFromHex(challenge.nonce);
    const message = new Uint8Array(nonce.length + 1 + nameBytes.length);
    message.set(nonce);
    message.set(nameBytes, nonce.length + 1);
    return toHex(await crypto.subtle.sign('HMAC', hmacKey, message));
  }

  async function checkSession() {
    try {
      const response = await fetch('/api/status', { cache: 'no-store' });
      if (response.status === 401) { showLogin(); return; }
      if (!response.ok) throw new Error('Could not read app status.');
      renderStatus(await response.json());
      showDashboard();
      if (events) events.close();
      events = new EventSource('/api/events');
      events.addEventListener('status', (event) => renderStatus(JSON.parse(event.data)));
      events.onerror = () => { notice.textContent = 'Live updates disconnected. Reconnecting…'; };
      events.onopen = () => { notice.textContent = ''; };
    } catch (error) {
      showLogin();
      loginError.textContent = error.message;
    }
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    loginError.textContent = '';
    const username = document.getElementById('username').value;
    const password = passwordInput.value;
    passwordInput.value = '';
    try {
      const challengeResponse = await fetch('/api/login/challenge', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}'
      });
      const challenge = await challengeResponse.json();
      if (!challengeResponse.ok) throw new Error(challenge.error || 'Could not start login.');
      const proof = await makeProof(password, username, challenge);
      const response = await fetch('/api/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, challengeId: challenge.challengeId, proof })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Login failed.');
      await checkSession();
    } catch (error) { loginError.textContent = error.message; }
  });

  document.getElementById('logout').addEventListener('click', async () => {
    if (events) events.close();
    try { await fetch('/api/logout', { method: 'POST' }); }
    finally {
      states = { switch1: null, switch2: null };
      requestedStates = { switch1: null, switch2: null };
      renderControls();
      showLogin();
    }
  });

  async function setSwitch(id) {
    if (pending.has(id)) return;
    const currentValue = states[id] ?? requestedStates[id] ?? false;
    const requestedValue = !currentValue;
    pending.add(id);
    renderControls();
    notice.textContent = '';
    try {
      const response = await fetch(`/api/${id}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ on: requestedValue })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Command failed.');
      if (states[id] === null) requestedStates[id] = requestedValue;
      notice.textContent = `Command sent to esp32/${id}. Waiting for the reported state…`;
    } catch (error) { notice.textContent = error.message; }
    finally { pending.delete(id); renderControls(); }
  }

  for (const id of ids) toggles[id].addEventListener('click', () => setSwitch(id));
  checkSession();
})();
