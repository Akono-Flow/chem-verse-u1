// ─────────────────────────────────────────────────────────────────────────────
// auth.js — SCQ Auth System v2.0
//
// Exposes:
//   requireAuth()                          → use on launcher.html, admin.html
//   requireAppAccess(slug, noAccessPage)   → use on every gated app page
//   scqLogout()                            → sign-out button handler
//   getMyApps()                            → fetch apps for current user
//   _scqSupabase                           → raw Supabase client (advanced use)
//   _scqRegisterDevice(uid)                → called internally on login
//
// Depends on: supabase-js v2 (CDN), config.js  (must both load before this)
// ─────────────────────────────────────────────────────────────────────────────

(function (global) {
  'use strict';

  // ── Dependency guard ───────────────────────────────────────────────────────
  if (typeof supabase === 'undefined') {
    console.error('[SCQ] supabase-js not loaded. Add CDN script before auth.js.');
    return;
  }
  if (typeof SUPABASE_URL === 'undefined' || typeof SUPABASE_ANON_KEY === 'undefined') {
    console.error('[SCQ] config.js not loaded. Add it before auth.js.');
    return;
  }

  // ── Supabase client ────────────────────────────────────────────────────────
  var _sb = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: {
      autoRefreshToken: true,
      persistSession:   true,
      storageKey:       'scq_sb_session',
      detectSessionInUrl: true,
    }
  });

  global._scqSupabase = _sb;

  // ── Storage key constants ──────────────────────────────────────────────────
  var DEVICE_TOKEN_KEY = 'scq_device_token';

  // ── URL helpers ───────────────────────────────────────────────────────────
  function _base() {
    return (typeof AUTH_BASE_URL !== 'undefined')
      ? AUTH_BASE_URL.replace(/\/$/, '')
      : '';
  }

  function _authUrl(page) {
    var b = _base();
    return b ? (b + '/' + page) : page;
  }

  function _goLogin(reason) {
    var url = _authUrl('index.html');
    if (reason) url += '?reason=' + encodeURIComponent(reason);
    window.location.href = url;
  }

  function _goNoAccess(reason, override) {
    var page = override || _authUrl('no-access.html');
    if (reason) page += '?reason=' + encodeURIComponent(reason);
    window.location.href = page;
  }

  // ── UUID generator (with old-browser fallback) ─────────────────────────────
  function _uuid() {
    if (global.crypto && global.crypto.randomUUID) {
      return global.crypto.randomUUID();
    }
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = Math.random() * 16 | 0;
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
  }

  // ── getSession ─────────────────────────────────────────────────────────────
  async function _getSession() {
  try {
    var r = await _sb.auth.getSession();
    if (r && r.data && r.data.session) return r.data.session;

    // No session found — wait for URL hash to be processed (cross-subdomain launch)
    return new Promise(function (resolve) {
      var sub = _sb.auth.onAuthStateChange(function (event, session) {
        sub.data.subscription.unsubscribe();
        resolve(session || null);
      });
      // Timeout after 4 seconds to avoid hanging forever
      setTimeout(function () {
        try { sub.data.subscription.unsubscribe(); } catch (_) {}
        resolve(null);
      }, 4000);
    });
  } catch (_) { return null; }
}

  // ── getProfile ─────────────────────────────────────────────────────────────
  async function _getProfile(uid) {
    try {
      var r = await _sb.from('profiles')
        .select('id, email, full_name, role, is_active, plan_id, device_token, device_last_seen')
        .eq('id', uid)
        .single();
      return (r && r.data) ? r.data : null;
    } catch (_) { return null; }
  }

  // ── Device token status ────────────────────────────────────────────────────
  // Returns: 'ok' | 'conflict' | 'fresh'
  function _deviceStatus(profile) {
    var local  = localStorage.getItem(DEVICE_TOKEN_KEY);
    var remote = profile.device_token;

    if (!local && !remote) return 'fresh';    // Brand new: no device registered yet
    if (local === remote)   return 'ok';       // Same device, all good
    return 'conflict';                         // Mismatch: another device took over, or admin revoked
  }

  // ── Register this device ───────────────────────────────────────────────────
  async function _registerDevice(uid) {
    var token = _uuid();
    var info  = JSON.stringify({
      ua:   (navigator.userAgent || '').substring(0, 200),
      lang: navigator.language || '',
      tz:   (Intl && Intl.DateTimeFormat ? Intl.DateTimeFormat().resolvedOptions().timeZone : ''),
      ts:   new Date().toISOString()
    });

    localStorage.setItem(DEVICE_TOKEN_KEY, token);

    await _sb.from('profiles').update({
      device_token:     token,
      device_info:      info,
      device_last_seen: new Date().toISOString()
    }).eq('id', uid);

    return token;
  }

  // Expose so the login page (index.html) can call it after a successful sign-in
  global._scqRegisterDevice = _registerDevice;

  // ── Update last-seen timestamp (non-critical) ─────────────────────────────
  async function _touch(uid) {
    try {
      await _sb.from('profiles')
        .update({ device_last_seen: new Date().toISOString() })
        .eq('id', uid);
    } catch (_) {}
  }

  // ── Handle device conflict: sign out + redirect ───────────────────────────
  async function _ejectDevice(reason) {
    try { await _sb.auth.signOut(); } catch (_) {}
    localStorage.removeItem(DEVICE_TOKEN_KEY);
    _goLogin(reason || 'session_conflict');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PUBLIC API
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * requireAuth()
   *
   * Use on pages that need a logged-in + active user but don't gate a specific
   * app (e.g. launcher.html, admin.html).
   *
   * Checks:  session exists → profile exists → is_active → device token
   * Returns: { session, profile }  if all pass
   *          null                  (and redirects) if any check fails
   */
  global.requireAuth = async function () {
    var session = await _getSession();
    if (!session) { _goLogin('not_logged_in'); return null; }

    var profile = await _getProfile(session.user.id);
    if (!profile) { _goLogin('no_profile'); return null; }

    if (!profile.is_active) {
      try { await _sb.auth.signOut(); } catch (_) {}
      _goLogin('inactive');
      return null;
    }

    var status = _deviceStatus(profile);
    if (status === 'conflict') { await _ejectDevice('session_conflict'); return null; }
    if (status === 'fresh')    { await _registerDevice(session.user.id); }
    else                       { await _touch(session.user.id); }

    return { session: session, profile: profile };
  };

  /**
   * requireAppAccess(slug, noAccessPageOverride)
   *
   * Use as the FIRST CALL inside DOMContentLoaded on every gated app page.
   *
   * @param {string} slug                 App slug matching admin registry (e.g. 'mcq')
   * @param {string} [noAccessPageOverride]  Local path to no-access.html for cross-repo apps
   *
   * Checks:  session → profile → is_active → device token → plan includes slug → app is_active
   * Returns: { session, profile } or null (and redirects)
   *
   * Usage:
   *   document.addEventListener('DOMContentLoaded', async () => {
   *     const auth = await requireAppAccess('my-app-slug', 'no-access.html');
   *     if (!auth) return;
   *     document.getElementById('page-loader').remove();
   *     init(); // your existing init
   *   });
   */
  global.requireAppAccess = async function (slug, noAccessPageOverride) {
    var session = await _getSession();
    if (!session) { _goLogin('not_logged_in'); return null; }

    var profile = await _getProfile(session.user.id);
    if (!profile) { _goLogin('no_profile'); return null; }

    if (!profile.is_active) {
      try { await _sb.auth.signOut(); } catch (_) {}
      _goLogin('inactive');
      return null;
    }

     // App-level access check — admins bypass entirely
    if (profile.role === 'admin') {
      return { session: session, profile: profile };
    }

    var status = _deviceStatus(profile);
    if (status === 'conflict') { await _ejectDevice('session_conflict'); return null; }
    if (status === 'fresh')    { await _registerDevice(session.user.id); }
    else                       { await _touch(session.user.id); }

    var reason = 'plan_denied';
    try {
      var r = await _sb.rpc('check_app_access', { app_slug: slug });
      var result = (r && r.data) ? r.data : 'plan_denied';
      if (result === 'ok') {
        return { session: session, profile: profile };
      }
      reason = result;
    } catch (_) {
      reason = 'plan_denied';
    }

    _goNoAccess(reason, noAccessPageOverride || null);
    return null;
  };

  /**
   * scqLogout()
   *
   * Sign out the current user, clear device token, redirect to login.
   * Attach to any logout button: onclick="scqLogout()"
   */
  global.scqLogout = async function () {
    try { await _sb.auth.signOut(); } catch (_) {}
    localStorage.removeItem(DEVICE_TOKEN_KEY);
    _goLogin('logged_out');
  };

  /**
   * getMyApps()
   *
   * Returns the array of app objects the current user's plan grants access to.
   * Used by launcher.html to render the app grid.
   * @returns {Array<{id, name, slug, url, description, icon, is_active}>}
   */
   global.getMyApps = async function () {
    try {
      var session = await _getSession();
      if (session) {
        var profile = await _getProfile(session.user.id);
        if (profile && profile.role === 'admin') {
          var r = await _sb.from('apps').select('*').eq('is_active', true);
          return (r && r.data) ? r.data : [];
        }
      }
      var r = await _sb.rpc('get_my_apps');
      return (r && r.data) ? r.data : [];
    } catch (_) { return []; }
  };

})(window);
