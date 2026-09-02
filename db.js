// ============================================================
// PSLE Prep Toolkit — data layer
//
// Every page talks to the database through this one file. If
// supabase-config.js is left blank it falls back to browser-only
// storage, so the site keeps working while you set Supabase up.
//
// Nothing here trusts the browser for permission. Sign-in, code
// redemption and payment verification are all decided by the database
// (see supabase-setup.sql).
// ============================================================

import { SUPABASE_URL, SUPABASE_ANON_KEY, DEVICE_LIMIT } from './supabase-config.js';

const GRANTS_KEY = 'psle-access-grants';
const ACCOUNTS_KEY = 'psle-accounts';
const FP_KEY = 'psle-device-id';
const LOCAL_SESSION = 'psle-local-session';

let clientPromise = null;

export function isLive(){
  return !!(SUPABASE_URL && SUPABASE_ANON_KEY);
}

async function client(){
  if(!isLive()) return null;
  if(!clientPromise){
    clientPromise = import('https://esm.sh/@supabase/supabase-js@2')
      .then(m => m.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
        auth: { persistSession: true, autoRefreshToken: true }
      }))
      .catch(e => { console.warn('[db] Supabase failed to load, using offline mode', e); return null; });
  }
  return clientPromise;
}

// A stable-ish id for this browser, used for the device limit.
export function deviceFingerprint(){
  try{
    let fp = localStorage.getItem(FP_KEY);
    if(!fp){
      fp = 'd-' + Math.random().toString(36).slice(2) + '-' + Date.now().toString(36);
      localStorage.setItem(FP_KEY, fp);
    }
    return fp;
  }catch(e){ return 'no-storage'; }
}

function readLocal(key){
  try{ const raw = localStorage.getItem(key); return raw ? JSON.parse(raw) : []; }catch(e){ return []; }
}
function writeLocal(key, val){
  try{ localStorage.setItem(key, JSON.stringify(val)); }catch(e){}
}

export function makeCode(){
  const set = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const pick = n => Array.from({length:n}, () => set[Math.floor(Math.random()*set.length)]).join('');
  return 'PSLE-' + pick(4) + '-' + pick(4);
}

// ---------- ORDERS ----------

// Creates an order. Always unpaid — the database refuses anything else.
export async function createOrder(o){
  const code = o.code || makeCode();
  const db = await client();

  if(db){
    const { data: { user } } = await db.auth.getUser();
    const { error } = await db.from('orders').insert({
      account_id: user ? user.id : null,
      parent_name: o.parent, phone: o.phone, email: o.email,
      learner_name: o.learner, standard: o.std,
      plan: o.plan, plan_name: o.planName, price: o.price,
      subjects: o.subjects || [],
      method: o.method, reference: o.reference,
      code, status: 'pending-verification',
      device_limit: DEVICE_LIMIT
    });
    if(error) throw new Error(error.message);
    return { code, live: true };
  }

  const list = readLocal(GRANTS_KEY);
  list.push(Object.assign({}, o, {
    code, status: 'pending-verification',
    created: new Date().toISOString(), expires: '2026-10-31'
  }));
  writeLocal(GRANTS_KEY, list);

  // Offline: remember which account this code belongs to, so the
  // parent's email sign-in can find it again.
  if(o.email){
    const accts = readLocal(ACCOUNTS_KEY);
    const key = String(o.email).toLowerCase();
    const i = accts.findIndex(a => (a.email||'').toLowerCase() === key);
    if(i >= 0) accts[i].codes = (accts[i].codes || []).concat([code]);
    else accts.push({ email:key, password:null, provider:'password', parent:o.parent || '', codes:[code] });
    writeLocal(ACCOUNTS_KEY, accts);
  }
  return { code, live: false };
}

// The security boundary. Returns {authorised, reason, subjects, learner…}
export async function redeemCode(code){
  const entered = String(code || '').trim().toUpperCase();
  const db = await client();

  if(db){
    const { data, error } = await db.rpc('redeem_code', {
      p_code: entered, p_fingerprint: deviceFingerprint()
    });
    if(error) throw new Error(error.message);
    return data;
  }

  const g = readLocal(GRANTS_KEY).find(x => (x.code||'').toUpperCase() === entered);
  if(!g) return { authorised:false, reason:'not-found' };
  if(g.status === 'revoked') return { authorised:false, reason:'revoked' };
  if(g.status !== 'verified') return { authorised:false, reason:'pending' };
  return {
    authorised:true, reason:'ok', code:g.code, learner:g.learner || '',
    standard:g.std || '', planName:g.planName || '', price:g.price || 0,
    subjects: (Array.isArray(g.subjects) && g.subjects.length && g.subjects.length < 6) ? g.subjects : null
  };
}

// Turns a redeem reason into words a parent understands.
export function reasonMessage(reason, extra){
  switch(reason){
    case 'pending':
      return 'This code is not active yet — we still need to confirm your payment. Send your proof of payment to WhatsApp 74310425 and we will switch it on, usually within a few hours.';
    case 'revoked':
      return 'This code is no longer active. Please WhatsApp 74310425 so we can sort it out.';
    case 'expired':
      return 'This code has expired. WhatsApp 74310425 if you think that is wrong.';
    case 'device-limit':
      return 'This code is already in use on ' + ((extra && extra.limit) || DEVICE_LIMIT) + ' devices. WhatsApp 74310425 if you need it moved to a new phone or tablet.';
    default:
      return 'That code was not recognised. Check for typos, or WhatsApp 74310425 for help.';
  }
}

// ---------- ADMIN ----------

export async function listOrders(){
  const db = await client();
  if(db){
    const { data, error } = await db.from('orders')
      .select('*').order('created_at', { ascending:false });
    if(error) throw new Error(error.message);
    return (data || []).map(r => ({
      code:r.code, status:r.status, learner:r.learner_name, std:r.standard,
      parent:r.parent_name, phone:r.phone, email:r.email,
      plan:r.plan, planName:r.plan_name, price:r.price,
      subjects:r.subjects || [], method:r.method, reference:r.reference,
      created:r.created_at, verifiedAt:r.verified_at, expires:r.expires_at
    }));
  }
  return readLocal(GRANTS_KEY).slice().reverse();
}

// Admin: how many device slots each code has used.
export async function deviceCounts(){
  const db = await client();
  if(!db) return {};
  const { data, error } = await db.from('devices').select('code');
  if(error) return {};
  const out = {};
  (data || []).forEach(d => {
    const k = String(d.code || '').toUpperCase();
    out[k] = (out[k] || 0) + 1;
  });
  return out;
}

// Admin: free every device slot on a code.
export async function resetDevices(code){
  const db = await client();
  if(!db) return 0;
  const { data, error } = await db.rpc('reset_devices', { p_code: code });
  if(error) throw new Error(error.message);
  return data || 0;
}

// Admin: who has signed up, and how many orders each holds.
export async function listAccounts(){
  const db = await client();
  if(!db) return [];
  const { data, error } = await db.rpc('list_accounts');
  if(error) throw new Error(error.message);
  return data || [];
}

// Admin: remove someone's ability to sign in. Orders are kept.
export async function deleteAccount(email){
  const db = await client();
  if(!db) return false;
  const { error } = await db.rpc('delete_account', { p_email: email });
  if(error) throw new Error(error.message);
  return true;
}

// Admin: permanently remove an order, its devices and its progress.
export async function deleteOrder(code){
  const db = await client();
  if(db){
    const { error } = await db.rpc('delete_order', { p_code: code });
    if(error) throw new Error(error.message);
    return true;
  }
  const keep = readLocal(GRANTS_KEY)
    .filter(g => String(g.code||'').toUpperCase() !== String(code).toUpperCase());
  writeLocal(GRANTS_KEY, keep);
  return true;
}

export async function setOrderStatus(code, status){
  const db = await client();
  if(db){
    const { error } = await db.rpc('set_order_status', { p_code: code, p_status: status });
    if(error) throw new Error(error.message);
    return true;
  }
  const list = readLocal(GRANTS_KEY).map(g => {
    if((g.code||'').toUpperCase() !== String(code).toUpperCase()) return g;
    const next = Object.assign({}, g, { status });
    if(status === 'verified'){
      next.verifiedAt = new Date().toISOString();
      next.upgrades = (g.upgrades || []).map(u => Object.assign({}, u, { status:'verified' }));
    }
    return next;
  });
  writeLocal(GRANTS_KEY, list);
  return true;
}

// ---------- AUTH ----------

export async function signUp(email, password, meta){
  const db = await client();
  if(db){
    const { error } = await db.auth.signUp({
      email, password, options: { data: meta || {} }
    });
    if(error) throw new Error(error.message);
    return true;
  }
  const accts = readLocal(ACCOUNTS_KEY);
  const key = String(email).toLowerCase();
  const i = accts.findIndex(a => (a.email||'').toLowerCase() === key);
  const rec = { email:key, password, provider:'password', parent:(meta||{}).parent_name || '', codes:[] };
  if(i >= 0) accts[i] = Object.assign({}, accts[i], rec, { codes:accts[i].codes || [] });
  else accts.push(rec);
  writeLocal(ACCOUNTS_KEY, accts);
  return true;
}

export async function signIn(email, password){
  const db = await client();
  if(db){
    const { error } = await db.auth.signInWithPassword({ email, password });
    if(error) throw new Error('That email and password do not match.');
    // Attach any orders placed before this account had a session.
    try{ await db.rpc('claim_my_orders'); }catch(e){}
    return true;
  }
  const found = readLocal(ACCOUNTS_KEY)
    .find(a => (a.email||'').toLowerCase() === String(email).toLowerCase());
  if(!found) throw new Error('No account found for that email.');
  if(found.password !== password) throw new Error('That password is not right.');
  try{ localStorage.setItem(LOCAL_SESSION, String(email).toLowerCase()); }catch(e){}
  return true;
}

export async function signInWithGoogle(){
  const db = await client();
  if(!db) throw new Error('Google sign-in needs the database connected first.');
  const { error } = await db.auth.signInWithOAuth({
    provider:'google',
    options:{ redirectTo: window.location.href }
  });
  if(error) throw new Error(error.message);
  return true;
}

// Is Google actually switched on for this project? The button hides itself
// until it is, so nobody clicks a control that cannot work.
let googleCheck = null;
export async function googleAvailable(){
  if(!isLive()) return false;
  if(googleCheck) return googleCheck;
  googleCheck = fetch(SUPABASE_URL + '/auth/v1/settings', {
      headers: { apikey: SUPABASE_ANON_KEY }
    })
    .then(r => r.json())
    .then(s => !!(s && s.external && s.external.google))
    .catch(() => false);
  return googleCheck;
}

export async function signOut(){
  const db = await client();
  if(db) await db.auth.signOut();
  try{ localStorage.removeItem(LOCAL_SESSION); }catch(e){}
  return true;
}

export async function currentUser(){
  const db = await client();
  if(!db) return null;
  const { data } = await db.auth.getUser();
  return data ? data.user : null;
}

export async function isAdmin(){
  const db = await client();
  if(!db) return null;                       // offline: PIN gate decides
  const { data, error } = await db.rpc('is_admin');
  if(error) return false;
  return data === true;
}

// A signed-in parent's own orders, so they can see verification status.
export async function myOrders(){
  const db = await client();

  if(db){
    const { data, error } = await db.from('orders')
      .select('code,status,learner_name,subjects,plan_name,price')
      .order('created_at', { ascending:false });
    if(error) return [];
    return data || [];
  }

  // Offline: use the email remembered at sign-in.
  let email = '';
  try{ email = localStorage.getItem(LOCAL_SESSION) || ''; }catch(e){}
  if(!email) return [];
  const acct = readLocal(ACCOUNTS_KEY)
    .find(a => (a.email||'').toLowerCase() === email);
  if(!acct) return [];
  const codes = (acct.codes || []).map(c => String(c).toUpperCase());
  return readLocal(GRANTS_KEY)
    .filter(g => codes.indexOf(String(g.code||'').toUpperCase()) >= 0)
    .map(g => ({
      code:g.code, status:g.status, learner_name:g.learner,
      subjects:g.subjects || [], plan_name:g.planName, price:g.price
    }));
}

// ---------- PROGRESS ----------

export async function saveProgress(code, subject, answered, correct, stars){
  const db = await client();
  if(!db) return false;
  const { error } = await db.rpc('save_progress', {
    p_code:code, p_subject:subject,
    p_answered:answered|0, p_correct:correct|0, p_stars:stars|0
  });
  return !error;
}

// Anonymous standing — a band only, never a name or a position.
export async function myStanding(code){
  const db = await client();
  if(!db) return null;
  const { data, error } = await db.rpc('my_standing', { p_code: code });
  if(error) return null;
  return data;
}

// Wipe one subject's saved progress.
export async function clearSubject(code, subject){
  const db = await client();
  if(!db) return false;
  const { error } = await db.rpc('clear_subject', { p_code: code, p_subject: subject });
  return !error;
}

// Wipe a learner's saved progress so they can start from zero.
export async function clearProgress(code){
  const db = await client();
  if(!db) return false;
  const { error } = await db.rpc('clear_progress', { p_code: code });
  return !error;
}

export async function loadProgress(code){
  const db = await client();
  if(!db) return [];
  const { data, error } = await db.rpc('load_progress', { p_code:code });
  if(error) return [];
  return data || [];
}
