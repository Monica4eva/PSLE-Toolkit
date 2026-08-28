// ============================================================
// PSLE Prep Toolkit — Supabase connection details
//
// Fill in the two values below, then save. Nothing else in the site
// needs editing.
//
// Where to find them:
//   Supabase dashboard → your project → Settings → API
//     • "Project URL"        → SUPABASE_URL
//     • "anon public" key    → SUPABASE_ANON_KEY
//
// The anon key is MEANT to be public — it is in every visitor's browser
// by design. It grants nothing on its own: the database policies in
// supabase-setup.sql decide what any request is allowed to do.
//
// NEVER paste the "service_role" key here. That one bypasses all
// policies and must stay secret.
//
// Leave these blank to keep working offline: the site falls back to
// browser-only storage, exactly as it behaved before.
// ============================================================

export const SUPABASE_URL = 'https://ovoioaarepuiczsprvlx.supabase.co';
export const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im92b2lvYWFyZXB1aWN6c3Bydmx4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODc5MDgyNjQsImV4cCI6MjEwMzQ4NDI2NH0.CVEv1DBhjvsSpbKzTRaLBWIODKlaExVURBYAYOxWFOU';

// How many devices one access code may be used on.
// Change this in the database (orders.device_limit) for existing codes.
export const DEVICE_LIMIT = 3;
