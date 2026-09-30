/* SafeReach API layer — matches Thuso-SafeReach-Backend routes.
 * Online: talks to the Express API. Offline/unreachable: SOS, check-ins and
 * incident reports are queued in localStorage and re-sent when back online.
 */
const DEFAULT_BASE = 'http://localhost:4000/api'; // change to your hosted URL
const TIMEOUT_MS = 8000;

const base = () => localStorage.getItem('sr_api_base') || DEFAULT_BASE;
export const setApiBase = (url) => localStorage.setItem('sr_api_base', url);

/* ---------- storage helpers ---------- */
const store = {
  get: (k, d) => { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } },
  set: (k, v) => localStorage.setItem(k, JSON.stringify(v)),
};
export const getToken = () => localStorage.getItem('sr_token');
export const setToken = (t) => (t ? localStorage.setItem('sr_token', t) : localStorage.removeItem('sr_token'));
export const getUser = () => store.get('sr_user', null);

/* Backend validator needs lat/lng as "-26.204100" (must contain a decimal
 * point, max 10 decimals). Raw geolocation numbers would be rejected. */
export const fmtCoord = (n) => (Number.isFinite(Number(n)) ? Number(n).toFixed(6) : undefined);

/* ---------- core request ---------- */
async function request(path, { method = 'GET', body } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(base() + path, {
      method,
      signal: ctrl.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      if (res.status === 401 && getToken()) {
        // Token expired (backend default is 1h) — force re-login in the UI.
        setToken(null);
        window.dispatchEvent(new CustomEvent('sr:session-expired'));
      }
      const err = new Error(data.error || `HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return data;
  } finally {
    clearTimeout(timer);
  }
}

const isOffline = (e) => e.name === 'AbortError' || e instanceof TypeError;

/* ---------- offline queue (SOS + incidents + check-ins) ---------- */
const QUEUE_KEY = 'sr_queue';

function enqueue(path, body) {
  const q = store.get(QUEUE_KEY, []);
  q.push({ path, body, at: Date.now() });
  store.set(QUEUE_KEY, q);
}

export async function flushQueue() {
  if (!getToken()) return 0;
  const q = store.get(QUEUE_KEY, []);
  if (!q.length) return 0;
  const remaining = [];
  for (const item of q) {
    try {
      await request(item.path, { method: 'POST', body: item.body });
    } catch (e) {
      if (isOffline(e)) remaining.push(item); // keep for next attempt
      // 4xx (bad data / 409 already active) are dropped so they don't block the queue
    }
  }
  store.set(QUEUE_KEY, remaining);
  return q.length - remaining.length;
}

async function postOrQueue(path, body) {
  try {
    return { queued: false, data: await request(path, { method: 'POST', body }) };
  } catch (e) {
    if (isOffline(e)) { enqueue(path, body); return { queued: true }; }
    throw e;
  }
}

/* ---------- auth (members log in with phone number) ---------- */
export async function register({ fullName, phoneNumber, password }) {
  const data = await request('/auth/register', { method: 'POST', body: { fullName, phoneNumber, password } });
  setToken(data.token); store.set('sr_user', data.user);
  return data;
}

export async function login(phoneNumber, password) {
  const data = await request('/auth/login', { method: 'POST', body: { phoneNumber, password } });
  setToken(data.token); store.set('sr_user', data.user);
  flushQueue();
  return data;
}

export function logout() { setToken(null); localStorage.removeItem('sr_user'); }

/* ---------- check-in ---------- */
export const startCheckIn = ({ durationMinutes, destination, lat, lng }) =>
  postOrQueue('/checkin', {
    durationMinutes, destination,
    lat: fmtCoord(lat), lng: fmtCoord(lng),
  });

export const getActiveCheckIn = async () => (await request('/checkin/active')).checkIn;
export const extendCheckIn = (id, minutes = 15) => request(`/checkin/${id}/extend`, { method: 'PATCH', body: { minutes } });
export const markSafe = (id) => request(`/checkin/${id}/safe`, { method: 'PATCH' });

/* ---------- SOS ---------- */
// triggerSource: 'manual' | 'shake' | 'checkin_timeout'
export const sendSOS = ({ checkInId, lat, lng, triggerSource = 'manual' }) =>
  postOrQueue('/sos', { checkInId, triggerSource, lat: fmtCoord(lat), lng: fmtCoord(lng) });

/* ---------- incidents ---------- */
// type: theft|assault|accident|fire|medical|checkin|other   severity: low|medium|high
export const reportIncident = ({ type, description, severity, location, lat, lng }) =>
  postOrQueue('/incidents', { type, description, severity, location, lat: fmtCoord(lat), lng: fmtCoord(lng) });

export async function getMyIncidents() {
  try {
    const data = await request('/incidents/mine');
    store.set('sr_incidents_cache', data);
    return data;
  } catch (e) {
    if (isOffline(e)) return store.get('sr_incidents_cache', []);
    throw e;
  }
}

export async function isBackendUp() {
  try { await request('/health'); return true; } catch { return false; }
}

window.addEventListener('online', () => { flushQueue(); });
