// ============================================================
//  auth.js  v4  –  Shared authentication & access helpers
//  Adds cross-domain session handoff so users only need to
//  log in once and can access all apps on any subdomain.
//
//  Depends on: config.js  +  Supabase JS v2 (CDN)
//
//  DEPLOY THIS FILE TO EVERY REPO THAT USES THE AUTH SYSTEM.
// ============================================================

const { createClient } = supabase;
const sb = createClient(SUPABASE_URL, SUPABASE_ANON);

// ── Constants ─────────────────────────────────────────────────
const SESSION_TOKEN_KEY = 'sb_device_token';

// The full URL of your login page on your auth domain.
// Every app uses this to redirect unauthenticated users.
const LOGIN_URL = 'https://quiz-bizz.learnwithcole.com/index.html';

// ── Step 1: Absorb a session handoff from the URL ────────────
//
//  When index.html redirects back to a gated app after login,
//  it appends ?_at=<access_token>&_rt=<refresh_token> to the URL.
//  This function detects those params, establishes a local
//  Supabase session from them, then cleans the URL.
//
async function absorbSessionFromUrl() {
  const params = new URLSearchParams(location.search);
  const at = params.get('_at');
  const rt = params.get('_rt');
  const dt = params.get('_dt'); // device token

  if (!at || !rt) return; // nothing to absorb

  // Set the session in this domain's localStorage
  const { error } = await sb.auth.setSession({
    access_token:  at,
    refresh_token: rt
  });

  if (!error && dt) {
    // Restore the device token so the single-device check passes
    localStorage.setItem(SESSION_TOKEN_KEY, dt);
  }

  // Clean the tokens out of the URL immediately
  // (they should not sit in the address bar or browser history)
  params.delete('_at');
  params.delete('_rt');
  params.delete('_dt');
  params.delete('_next');
  const cleanSearch = params.toString() ? '?' + params.toString() : '';
  const cleanUrl = location.pathname + cleanSearch + location.hash;
  history.replaceState(null, '', cleanUrl);
}

// ── Get current session + profile ────────────────────────────
async function getSessionAndProfile() {
  // Always try to absorb a handoff first
  await absorbSessionFromUrl();

  const { data: { session } } = await sb.auth.getSession();
  if (!session) return { session: null, profile: null };

  const { data: profile, error } = await sb
    .from('profiles')
    .select('*, plans(id, name)')
    .eq('id', session.user.id)
    .single();

  return { session, profile: error ? null : profile };
}

// ── Build the login redirect URL ──────────────────────────────
//  Appends ?next=<current url> so index.html can send the user
//  back here after a successful login.
function buildLoginUrl() {
  return LOGIN_URL + '?next=' + encodeURIComponent(location.href);
}

// ── Guard: must be logged in, active, AND on this device ─────
async function requireAuth() {
  const { session, profile } = await getSessionAndProfile();

  // Not logged in → go to login, passing current URL as ?next
  if (!session) {
    location.href = buildLoginUrl();
    return null;
  }

  // Account not active
  if (!profile || !profile.is_active) {
    await sb.auth.signOut();
    localStorage.removeItem(SESSION_TOKEN_KEY);
    location.href = LOGIN_URL + '?reason=inactive';
    return null;
  }

  // Single-device check
  if (profile.session_token) {
    const localToken = localStorage.getItem(SESSION_TOKEN_KEY);
    if (localToken !== profile.session_token) {
      await sb.auth.signOut();
      localStorage.removeItem(SESSION_TOKEN_KEY);
      location.href = LOGIN_URL + '?reason=session_invalid';
      return null;
    }
  }

  return { session, profile };
}

// ── Guard: must be admin ──────────────────────────────────────
async function requireAdmin() {
  const result = await requireAuth();
  if (!result) return null;

  if (result.profile.role !== 'admin') {
    location.href = LOGIN_URL + '?reason=forbidden';
    return null;
  }
  return result;
}

// ── Guard: must have access to a specific app by slug ────────
//
//  Usage in any gated app:
//    const result = await requireAppAccess('myslug');
//    if (!result) return;
//
async function requireAppAccess(appSlug, noAccessPage = null) {
  // Default no-access page is on the auth domain
  const noAccess = noAccessPage ||
    'https://quiz-bizz.learnwithcole.com/no-access.html';

  const result = await requireAuth();
  if (!result) return null;

  const { session, profile } = result;

  // Admins bypass app-level checks entirely
  if (profile.role === 'admin') return result;

  // No plan assigned
  if (!profile.plan_id) {
    location.href = noAccess + '?reason=no_plan';
    return null;
  }

  // Look up the app by slug
  const { data: app, error: appErr } = await sb
    .from('apps')
    .select('id, name')
    .eq('slug', appSlug)
    .eq('is_active', true)
    .single();

  if (appErr || !app) {
    location.href = noAccess + '?reason=app_unavailable';
    return null;
  }

  // Check if user's plan includes this app
  const { data: access } = await sb
    .from('plan_apps')
    .select('app_id')
    .eq('plan_id', profile.plan_id)
    .eq('app_id', app.id)
    .maybeSingle();

  if (!access) {
    const p = new URLSearchParams({ reason: 'no_access', app: app.name });
    location.href = noAccess + '?' + p.toString();
    return null;
  }

  return result;
}

// ── Sign out ──────────────────────────────────────────────────
async function signOut() {
  localStorage.removeItem(SESSION_TOKEN_KEY);
  await sb.auth.signOut();
  location.href = LOGIN_URL;
}

// ── Toast notification helper ─────────────────────────────────
function showToast(message, type = 'info') {
  const existing = document.querySelector('.sb-toast');
  if (existing) existing.remove();

  const t = document.createElement('div');
  t.className = `sb-toast sb-toast-${type}`;
  t.textContent = message;
  document.body.appendChild(t);

  requestAnimationFrame(() => t.classList.add('sb-toast-show'));
  setTimeout(() => {
    t.classList.remove('sb-toast-show');
    setTimeout(() => t.remove(), 400);
  }, 3500);
}

// ── Shared styles ─────────────────────────────────────────────
(function injectSharedStyles() {
  if (document.getElementById('sb-shared-styles')) return;
  const s = document.createElement('style');
  s.id = 'sb-shared-styles';
  s.textContent = `
    .sb-toast {
      position: fixed; bottom: 1.5rem; right: 1.5rem; z-index: 9999;
      padding: .75rem 1.25rem; border-radius: 8px; font-size: .875rem;
      font-family: inherit; max-width: 320px;
      opacity: 0; transform: translateY(8px);
      transition: opacity .3s, transform .3s;
    }
    .sb-toast-show { opacity: 1; transform: translateY(0); }
    .sb-toast-info    { background: rgba(20,184,166,.15); border:1px solid #14b8a6; color:#5eead4; }
    .sb-toast-success { background: rgba(34,197,94,.15);  border:1px solid #22c55e; color:#86efac; }
    .sb-toast-error   { background: rgba(239,68,68,.15);  border:1px solid #ef4444; color:#fca5a5; }
    .sb-toast-warn    { background: rgba(234,179,8,.15);  border:1px solid #eab308; color:#fde047; }
    .sb-spinner {
      width: 20px; height: 20px;
      border: 2px solid rgba(255,255,255,.15);
      border-top-color: var(--accent, #14b8a6);
      border-radius: 50%;
      animation: sb-spin .7s linear infinite;
      display: inline-block;
    }
    @keyframes sb-spin { to { transform: rotate(360deg); } }
  `;
  document.head.appendChild(s);
})();
