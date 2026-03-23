// ─────────────────────────────────────────────────────────────────────────────
// config.js — Portal Configuration
//
// SETUP INSTRUCTIONS:
//   1. Replace SUPABASE_URL with your project URL
//      → Supabase Dashboard → Settings → API → Project URL
//   2. Replace SUPABASE_ANON_KEY with your anon/public key
//      → Supabase Dashboard → Settings → API → anon public
//   3. Replace AUTH_BASE_URL with the GitHub Pages URL of THIS auth repo
//      → e.g. https://yourusername.github.io/auth-repo
//      → If using a custom domain: https://portal.yourdomain.com
//   4. Customise PORTAL_CONFIG with your institution name and details
// ─────────────────────────────────────────────────────────────────────────────

// ── Supabase Connection ────────────────────────────────────────────────────────
const SUPABASE_URL      = 'https://pcyismgmyotxialalkro.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBjeWlzbWdteW90eGlhbGFsa3JvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQyMjUxOTQsImV4cCI6MjA4OTgwMTE5NH0.GYyfNVAfGmsejI1MiWfCzZo2UJ-fa3f9zJbkwb0wWW4';

// ── Auth Repo Base URL ─────────────────────────────────────────────────────────
// The URL where index.html, launcher.html, and no-access.html live.
// No trailing slash. Cross-repo apps use this to redirect to the login page.
const AUTH_BASE_URL = 'https://akono-flow.github.io/akono-app-gate';

// ── Portal Branding ────────────────────────────────────────────────────────────
const PORTAL_CONFIG = {
  institutionName  : 'Akono Learning Portal',   // Full name shown in headings
  institutionShort : 'AF',                    // Abbreviation shown in badges/nav
  tagline          : 'Science & Competition Excellence',
  supportEmail     : 'colem3846@gmail.com',
  logoInitials     : 'AF',                    // 2–4 letters for the circular emblem
  footerText       : 'Akono Flow Educational Technology Platform',
  // Theme override (optional — leave as-is for the default academic blue)
  accentColor      : '#2563eb',
};
