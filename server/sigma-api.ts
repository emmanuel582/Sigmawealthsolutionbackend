import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import {
  isFlutterwaveConfigured,
  isSandboxMode,
  initiateDirectCharge,
  getCharge,
  getBanks,
  resolveBankAccount,
  createDirectTransfer,
  completeSandboxCharge,
} from './lib/flutterwaveV4.js';
import { applySecurityMiddleware, productionErrorHandler } from './lib/security.js';
import { sanitizeRequestBody } from './lib/sanitize.js';
import { hashPassword, verifyPassword } from './lib/passwords.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || process.env.SIGMA_API_PORT || 4000);

applySecurityMiddleware(app);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(sanitizeRequestBody);

// Health check endpoints for hosting (Render, Vercel, monitoring)
app.get('/', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    service: 'SigmawealthSolution API',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ---------------- ENVIRONMENT & SUPABASE SETUP ----------------
const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.VITE_SUPABASE_URL || '';
// Never fall back to the public anon key for admin operations
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const FLUTTERWAVE_ENCRYPTION_KEY = process.env.FLUTTERWAVE_ENCRYPTION_KEY || '';
const FLUTTERWAVE_WEBHOOK_SECRET = process.env.FLUTTERWAVE_WEBHOOK_SECRET || process.env.FLUTTERWAVE_SECRET_HASH || '';

const OPAY_ACCOUNT_NAME = process.env.OPAY_ACCOUNT_NAME || '';
const OPAY_ACCOUNT_NUMBER = process.env.OPAY_ACCOUNT_NUMBER || '';
const OPAY_BANK_NAME = process.env.OPAY_BANK_NAME || '';

const isLiveSupabase = Boolean(
  SUPABASE_URL &&
    SUPABASE_SERVICE_ROLE_KEY &&
    !SUPABASE_URL.includes('your-project') &&
    SUPABASE_SERVICE_ROLE_KEY.length > 40
);
const supabaseAdmin = isLiveSupabase
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false },
    })
  : null;

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isValidUUID(id: unknown): id is string {
  return typeof id === 'string' && UUID_REGEX.test(id.trim());
}

// ---------------- LOCAL IN-MEMORY / POSTGRES DATA LAYER ----------------
// When live Supabase is connected, live SQL is queried. 
// When in sandbox mode, state is maintained with empty/clean initial state as required.
interface LocalStore {
  profiles: Map<string, any>;
  user_roles: Map<string, 'investor' | 'admin'>;
  admin_allowlist: Set<string>;
  bank_details: Map<string, any>;
  card_details: Map<string, any>;
  investments: Map<string, any>;
  payments: any[];
  payouts: any[];
  opay_receipts: any[];
  notifications: any[];
  activity_log: any[];
  platform_settings: { payout_mode: 'automatic' | 'manual'; updated_by: string; updated_at: string };
  payout_batches: any[];
  current_session: any | null;
  referrals: any[];
  auto_debit_plans: Map<string, any>;
  auth_credentials: Map<string, string>;
}

const pendingCharges = new Map<
  string,
  {
    chargeId: string;
    userId: string;
    amount: number;
    phase: string;
    isRecurringPlan: boolean;
    email: string;
    name: string;
  }
>();

const store: LocalStore = {
  profiles: new Map(),
  user_roles: new Map(),
  admin_allowlist: new Set(),
  bank_details: new Map(),
  card_details: new Map(),
  investments: new Map(),
  payments: [],
  payouts: [],
  opay_receipts: [],
  notifications: [],
  activity_log: [],
  platform_settings: {
    payout_mode: 'manual',
    updated_by: 'system',
    updated_at: new Date().toISOString(),
  },
  payout_batches: [],
  current_session: null,
  referrals: [],
  auto_debit_plans: new Map(),
  auth_credentials: new Map(),
};

function makeReferralCode(userId: string): string {
  const seed = String(userId).replace(/[^a-zA-Z0-9]/g, '').slice(-8).toUpperCase() || 'SIGMA';
  return `SW${seed}`;
}

function ensureReferralCode(profile: any): string {
  if (!profile.referral_code) {
    profile.referral_code = makeReferralCode(profile.id);
    store.profiles.set(profile.id, profile);
  }
  return profile.referral_code;
}

function findProfileByReferralCode(code: string): any | null {
  const clean = String(code || '').trim().toUpperCase();
  if (!clean) return null;
  for (const p of store.profiles.values()) {
    if (String(p.referral_code || '').toUpperCase() === clean) return p;
  }
  return null;
}

function attachReferral(newProfile: any, referralCode?: string | null) {
  if (!referralCode || newProfile.referred_by) return;
  const referrer = findProfileByReferralCode(referralCode);
  if (!referrer || referrer.id === newProfile.id) return;
  newProfile.referred_by = referrer.id;
  store.profiles.set(newProfile.id, newProfile);
  const existing = store.referrals.find(
    (r) => r.referred_id === newProfile.id || (r.referred_email && r.referred_email === newProfile.email)
  );
  if (!existing) {
    store.referrals.unshift({
      id: `ref-${Date.now()}`,
      referrer_id: referrer.id,
      referred_id: newProfile.id,
      referred_name: newProfile.name,
      referred_email: newProfile.email,
      earned_total: 0,
      created_at: new Date().toISOString(),
    });
  }
  logActivity(
    referrer.name || referrer.email,
    'REFERRAL_SIGNUP',
    `${newProfile.name || newProfile.email} joined via invite link`
  );
}

function buildReferralPayload(userId: string, profile: any) {
  ensureReferralCode(profile);
  const myReferrals = store.referrals.filter((r) => r.referrer_id === userId || r.referrer_id === profile.id);
  return {
    referralCode: profile.referral_code,
    referralEarnings: Number(profile.referral_earnings || 0),
    referralCount: myReferrals.length,
    referrals: myReferrals,
    autoDebitPlan: store.auto_debit_plans.get(userId) || store.auto_debit_plans.get(profile.id) || null,
  };
}

function creditReferralCommission(payerProfile: any, paymentAmount: number) {
  if (!payerProfile?.referred_by || !paymentAmount) return;
  const commission = Math.round(Number(paymentAmount) * 0.1);
  if (commission <= 0) return;
  const referrer = store.profiles.get(payerProfile.referred_by);
  if (!referrer) return;
  referrer.referral_earnings = Number(referrer.referral_earnings || 0) + commission;
  store.profiles.set(referrer.id, referrer);
  const link = store.referrals.find((r) => r.referred_id === payerProfile.id);
  if (link) {
    link.earned_total = Number(link.earned_total || 0) + commission;
    link.last_earn_at = new Date().toISOString();
  }
  store.notifications.unshift({
    id: `notif-ref-${Date.now()}`,
    title: 'Referral reward credited',
    body: `You earned ${commission.toLocaleString('en-NG', { style: 'currency', currency: 'NGN' })} (10%) from ${payerProfile.name || payerProfile.email}'s investment.`,
    audience: 'single',
    target_user_id: referrer.id,
    icon: 'gift',
    image_url: null,
    sent_at: new Date().toISOString(),
    delivery_status: 'delivered',
  });
  logActivity(
    referrer.name || referrer.email,
    'REFERRAL_EARNING',
    `Earned ₦${commission.toLocaleString()} referral commission`,
    commission
  );
}

// Helper: Retrieve canonical investor profile by ID or email
function findCanonicalProfile(userId?: string | null, email?: string | null): any | null {
  if (userId && store.profiles.has(userId)) {
    return store.profiles.get(userId);
  }
  const cleanEmail = (email || '').toLowerCase().trim();
  if (cleanEmail) {
    for (const [_, p] of store.profiles.entries()) {
      if (p.email && p.email.toLowerCase().trim() === cleanEmail) {
        return p;
      }
    }
  }
  return null;
}

// Helper: Ensure single canonical profile per user, merging duplicates
function linkCanonicalProfile(canonicalId: string, profileData: Partial<any>): any {
  const cleanEmail = (profileData.email || '').toLowerCase().trim();
  let existing = findCanonicalProfile(canonicalId, cleanEmail);

  if (existing) {
    // Merge properties
    Object.assign(existing, {
      ...profileData,
      id: canonicalId || existing.id,
      email: cleanEmail || existing.email,
      name: profileData.name || existing.name,
      phone: profileData.phone || existing.phone,
      total_invested: Math.max(Number(existing.total_invested || 0), Number(profileData.total_invested || 0)),
      current_phase: (profileData.current_phase && profileData.current_phase !== 'None') ? profileData.current_phase : existing.current_phase,
    });
    // Remove obsolete keys for the same email
    for (const [key, p] of Array.from(store.profiles.entries())) {
      if (key !== existing.id && p.email && p.email.toLowerCase().trim() === cleanEmail) {
        store.profiles.delete(key);
      }
    }
    store.profiles.set(existing.id, existing);
    return existing;
  }

  const newProfile = {
    id: canonicalId,
    name: profileData.name || cleanEmail.split('@')[0] || 'Investor',
    email: cleanEmail,
    phone: profileData.phone || null,
    total_invested: Number(profileData.total_invested || 0),
    current_phase: profileData.current_phase || 'None',
    payment_plan_id: profileData.payment_plan_id || null,
    created_at: profileData.created_at || new Date().toISOString(),
  };

  store.profiles.set(canonicalId, newProfile);
  return newProfile;
}

// Helper: Get distinct human investors (excluding administrators)
function getDistinctInvestors(): any[] {
  const distinctMap = new Map<string, any>();

  for (const [_, profile] of store.profiles.entries()) {
    const cleanEmail = (profile.email || '').toLowerCase().trim();
    if (!cleanEmail) continue;

    // Filter out administrator accounts
    const isAdmin = store.admin_allowlist.has(cleanEmail) ||
      store.user_roles.get(profile.id) === 'admin';

    if (isAdmin) continue;

    if (!distinctMap.has(cleanEmail)) {
      distinctMap.set(cleanEmail, profile);
    } else {
      // Merge with existing record if duplicate found
      const existing = distinctMap.get(cleanEmail);
      existing.total_invested = Math.max(Number(existing.total_invested || 0), Number(profile.total_invested || 0));
      if (profile.current_phase && profile.current_phase !== 'None') {
        existing.current_phase = profile.current_phase;
      }
    }
  }

  return Array.from(distinctMap.values());
}

// Helper: Log activity
async function logActivity(actor: string, action: string, details: string, amount: number | null = null) {
  const item = {
    id: `act-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    actor: actor || 'System',
    action,
    details,
    amount,
    created_at: new Date().toISOString(),
  };
  store.activity_log.unshift(item);
  if (store.activity_log.length > 500) store.activity_log.pop();

  if (isLiveSupabase && supabaseAdmin) {
    try {
      await supabaseAdmin.from('activity_log').insert({
        actor: actor || 'System',
        action,
        details,
        amount,
        created_at: item.created_at,
      });
    } catch (err) {
      console.warn('Failed to insert activity log in Supabase:', err);
    }
  }

  return item;
}

// ---------------- PUBLIC & CONFIG API ----------------

app.get('/api/config', (req: Request, res: Response) => {
  res.json({
    flutterwaveConfigured: isFlutterwaveConfigured(),
    flutterwaveSandbox: isSandboxMode(),
    opayAccountName: OPAY_ACCOUNT_NAME,
    opayAccountNumber: OPAY_ACCOUNT_NUMBER,
    opayBankName: OPAY_BANK_NAME,
    isSupabaseLive: isLiveSupabase,
  });
});

const FALLBACK_BANKS = [
  { id: '1', code: '044', name: 'Access Bank' },
  { id: '2', code: '023', name: 'Citibank Nigeria' },
  { id: '3', code: '050', name: 'Ecobank Nigeria' },
  { id: '4', code: '070', name: 'Fidelity Bank' },
  { id: '5', code: '011', name: 'First Bank of Nigeria' },
  { id: '6', code: '214', name: 'First City Monument Bank' },
  { id: '7', code: '058', name: 'Guaranty Trust Bank (GTBank)' },
  { id: '8', code: '030', name: 'Heritage Bank' },
  { id: '9', code: '301', name: 'Jaiz Bank' },
  { id: '10', code: '082', name: 'Keystone Bank' },
  { id: '11', code: '50211', name: 'Kuda Bank' },
  { id: '12', code: '999992', name: 'OPay' },
  { id: '13', code: '999991', name: 'PalmPay' },
  { id: '14', code: '50515', name: 'Moniepoint MFB' },
  { id: '15', code: '076', name: 'Polaris Bank' },
  { id: '16', code: '101', name: 'Providus Bank' },
  { id: '17', code: '221', name: 'Stanbic IBTC Bank' },
  { id: '18', code: '068', name: 'Standard Chartered Bank' },
  { id: '19', code: '232', name: 'Sterling Bank' },
  { id: '20', code: '100', name: 'Suntrust Bank' },
  { id: '21', code: '032', name: 'Union Bank of Nigeria' },
  { id: '22', code: '033', name: 'United Bank for Africa (UBA)' },
  { id: '23', code: '215', name: 'Unity Bank' },
  { id: '24', code: '035', name: 'Wema Bank' },
  { id: '25', code: '057', name: 'Zenith Bank' },
];

let cachedBanksList: any[] | null = null;

app.get('/api/banks', async (req: Request, res: Response) => {
  if (cachedBanksList && cachedBanksList.length > 0) {
    return res.json({ status: 'success', message: 'Banks fetched successfully (cached)', data: cachedBanksList });
  }

  if (isFlutterwaveConfigured()) {
    try {
      const result: any = await Promise.race([
        getBanks('NG'),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Banks fetch timed out')), 3000)),
      ]);
      const banks = (result?.data || []).map((b: any, i: number) => ({
        id: String(b.id || i + 1),
        code: String(b.code || b.bank_code || ''),
        name: b.name || b.bank_name || 'Bank',
      }));
      if (banks.length > 0) {
        cachedBanksList = banks;
        return res.json({ status: 'success', message: 'Banks fetched successfully', data: banks });
      }
    } catch {
      // Fallback silently without throwing unhandled network errors
    }
  }

  cachedBanksList = FALLBACK_BANKS;
  return res.json({ status: 'success', message: 'Banks fetched successfully', data: FALLBACK_BANKS });
});

app.post('/api/verify-account', async (req: Request, res: Response) => {
  const { account_number, account_bank } = req.body;
  if (!account_number || !account_bank) {
    return res.status(400).json({ status: 'error', message: 'Account number and bank code are required' });
  }

  const cleanNuban = String(account_number).trim();
  if (cleanNuban.length !== 10 || !/^\d+$/.test(cleanNuban)) {
    return res.status(400).json({ status: 'error', message: 'Invalid 10-digit NUBAN account number format' });
  }

  if (!isFlutterwaveConfigured()) {
    return res.status(503).json({ status: 'error', message: 'Bank account verification is not configured.' });
  }

  try {
    const result = await resolveBankAccount(cleanNuban, String(account_bank));
    const resolved = result.data || result;
    return res.json({
      status: 'success',
      message: 'Account details verified',
      data: {
        account_number: resolved.account_number || cleanNuban,
        account_name: resolved.account_name || resolved.account_holder_name,
      },
    });
  } catch (err: any) {
    return res.status(400).json({
      status: 'error',
      message: err.message || 'Unable to resolve account. Please check the account number and bank.',
    });
  }
});

// ---------------- AUTH FALLBACK API ----------------

app.get('/api/auth/current-session', (req: Request, res: Response) => {
  res.json({ user: store.current_session });
});

app.post('/api/auth/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' });
  }

  const cleanEmail = email.toLowerCase().trim();
  const storedHash = store.auth_credentials.get(cleanEmail);
  if (!storedHash || !verifyPassword(password, storedHash)) {
    return res.status(401).json({ message: 'Invalid email or password.' });
  }

  let profile = findCanonicalProfile(null, cleanEmail);
  
  if (!profile) {
    return res.status(401).json({ message: 'Invalid email or password. Please sign up first.' });
  }

  ensureReferralCode(profile);

  const { isAdmin } = await verifyIsAdmin(profile.id, profile.email);
  const role = isAdmin ? 'admin' : (store.user_roles.get(profile.id) || 'investor');
  const user = {
    id: profile.id,
    email: profile.email,
    name: profile.name,
  };
  store.current_session = user;

  logActivity(profile.name || profile.email, 'LOGIN', `User signed in as ${role}`);

  res.json({ user, role });
});

app.post('/api/auth/signup', (req: Request, res: Response) => {
  const { email, password, fullName, phone, agreedToTerms, referralCode, supabaseUserId } = req.body;
  if (!agreedToTerms) {
    return res.status(400).json({ message: 'Terms and Conditions agreement is mandatory' });
  }
  if (!email || !password || !fullName) {
    return res.status(400).json({ message: 'All registration fields are required' });
  }

  const cleanEmail = email.toLowerCase().trim();
  const existing = findCanonicalProfile(null, cleanEmail);
  if (existing && !supabaseUserId) {
    return res.status(400).json({ message: 'An account with this email address already exists. Please sign in.' });
  }

  const newId = supabaseUserId || existing?.id || `usr-${Date.now()}`;
  const profile = linkCanonicalProfile(newId, {
    id: newId,
    name: fullName,
    email: cleanEmail,
    phone: phone || null,
    total_invested: existing?.total_invested || 0,
    current_phase: 'None',
    payment_plan_id: null,
    referral_earnings: existing?.referral_earnings || 0,
    created_at: existing?.created_at || new Date().toISOString(),
  });

  ensureReferralCode(profile);
  attachReferral(profile, referralCode);
  store.auth_credentials.set(cleanEmail, hashPassword(password));
  store.user_roles.set(profile.id, 'investor');

  const user = { id: profile.id, email: cleanEmail, name: fullName };
  store.current_session = user;

  logActivity(fullName, 'SIGNUP', 'New investor account registered with ₦0 initial balance');

  res.json({ user, role: 'investor' });
});

app.post('/api/auth/logout', (req: Request, res: Response) => {
  store.current_session = null;
  res.json({ success: true });
});

// Dedicated Admin Email Authentication Endpoint
app.post('/api/auth/admin-login', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Administrator email and password required' });
  }

  const cleanEmail = email.toLowerCase().trim();
  const isAllowlisted = store.admin_allowlist.has(cleanEmail);
  
  if (!isAllowlisted) {
    return res.status(403).json({ 
      success: false, 
      message: `The account ${cleanEmail} is not on the administrator allowlist. Please verify the approved admin email address.` 
    });
  }

  const storedHash = store.auth_credentials.get(cleanEmail);
  if (storedHash && !verifyPassword(password, storedHash)) {
    return res.status(401).json({ success: false, message: 'Invalid admin credentials.' });
  }
  if (!storedHash) {
    // First local login after allowlist seed — require register first
    return res.status(401).json({
      success: false,
      message: 'Admin account not initialized. Use Register on the admin gate first.',
    });
  }

  let profile = findCanonicalProfile(null, cleanEmail);
  if (!profile) {
    profile = linkCanonicalProfile(`usr-admin-${Date.now()}`, {
      id: `usr-admin-${Date.now()}`,
      name: cleanEmail.split('@')[0] || 'System Administrator',
      email: cleanEmail,
      phone: null,
      total_invested: 0,
      current_phase: 'None',
      payment_plan_id: null,
      created_at: new Date().toISOString(),
    });
  }

  store.user_roles.set(profile.id, 'admin');
  const user = {
    id: profile.id,
    email: profile.email,
    name: profile.name || 'System Administrator',
  };
  store.current_session = user;

  logActivity(profile.name || cleanEmail, 'ADMIN_LOGIN', 'Administrator authenticated via Operations Gate');

  res.json({ success: true, user, role: 'admin' });
});

// Dedicated Admin Email Registration / Setup Endpoint
app.post('/api/auth/admin-register', async (req: Request, res: Response) => {
  const { email, password, fullName } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Administrator email and password required' });
  }
  if (String(password).length < 8) {
    return res.status(400).json({ success: false, message: 'Password must be at least 8 characters.' });
  }

  const cleanEmail = email.toLowerCase().trim();
  const isAllowlisted = store.admin_allowlist.has(cleanEmail);
  
  if (!isAllowlisted) {
    return res.status(403).json({ 
      success: false, 
      message: `The email ${cleanEmail} is not authorized for administrative registration. Only approved administrative emails can register here.` 
    });
  }

  let profile = findCanonicalProfile(null, cleanEmail);
  if (!profile) {
    const newId = `usr-admin-${Date.now()}`;
    profile = linkCanonicalProfile(newId, {
      id: newId,
      name: fullName || cleanEmail.split('@')[0] || 'System Administrator',
      email: cleanEmail,
      phone: null,
      total_invested: 0,
      current_phase: 'None',
      payment_plan_id: null,
      created_at: new Date().toISOString(),
    });
  } else if (fullName) {
    profile.name = fullName;
    store.profiles.set(profile.id, profile);
  }

  store.auth_credentials.set(cleanEmail, hashPassword(password));
  store.user_roles.set(profile.id, 'admin');
  const user = {
    id: profile.id,
    email: profile.email,
    name: profile.name,
  };
  store.current_session = user;

  logActivity(profile.name || cleanEmail, 'ADMIN_REGISTRATION', 'Administrator account initialized via Operations Gate');

  res.json({ success: true, user, role: 'admin' });
});

// ---------------- INVESTOR DASHBOARD API ----------------

app.get('/api/investor/profile/:id', async (req: Request, res: Response) => {
  const userId = req.params.id;
  const queryEmail = (req.query.email as string || '').toLowerCase().trim();
  const queryName = (req.query.name as string || '').trim();

  if (isLiveSupabase && supabaseAdmin && isValidUUID(userId)) {
    try {
      const { data, error } = await supabaseAdmin
        .from('profiles')
        .select('*')
        .eq('id', userId)
        .maybeSingle();

      if (!error && data) {
        // Keep in sync with memory
        linkCanonicalProfile(userId, data);
        return res.json(data);
      }

      // Profile row doesn't exist yet — auto-provision from Supabase Auth
      try {
        const { data: userData } = await supabaseAdmin.auth.admin.getUserById(userId);
        if (userData?.user) {
          const newProfile = {
            id: userId,
            name: userData.user.user_metadata?.full_name || userData.user.user_metadata?.name || queryName || userData.user.email?.split('@')[0] || 'Investor',
            email: (userData.user.email || queryEmail || '').toLowerCase().trim(),
            phone: userData.user.user_metadata?.phone || '',
            total_invested: 0,
            current_phase: 'None',
            payment_plan_id: null,
            created_at: new Date().toISOString(),
          };
          await supabaseAdmin.from('profiles').upsert(newProfile);
          await supabaseAdmin.from('user_roles').upsert({ user_id: userId, role: 'investor' });
          linkCanonicalProfile(userId, newProfile);
          return res.json(newProfile);
        }
      } catch (authErr) {
        console.warn('Could not auto-provision profile from Supabase Auth:', authErr);
      }
    } catch (err) {
      console.warn('Error fetching Supabase profile, falling back to store:', err);
    }
  }

  // Find canonical profile by ID or email
  let profile = findCanonicalProfile(userId, queryEmail || store.current_session?.email);
  if (profile) {
    // If found by email but key differs, alias it
    if (!store.profiles.has(userId)) {
      store.profiles.set(userId, profile);
    }
    return res.json(profile);
  }

  if (store.current_session && (store.current_session.id === userId || (queryEmail && store.current_session.email === queryEmail))) {
    profile = linkCanonicalProfile(userId, {
      id: userId,
      name: store.current_session.name || 'Investor',
      email: store.current_session.email || queryEmail || '',
      phone: '',
      total_invested: 0,
      current_phase: 'None',
      payment_plan_id: null,
      created_at: new Date().toISOString(),
    });
    return res.json(profile);
  }

  // Last resort: auto-create profile from query params if email is provided
  if (queryEmail) {
    profile = linkCanonicalProfile(userId, {
      id: userId,
      name: queryName || queryEmail.split('@')[0] || 'Investor',
      email: queryEmail,
      phone: '',
      total_invested: 0,
      current_phase: 'None',
      payment_plan_id: null,
      created_at: new Date().toISOString(),
    });

    if (isLiveSupabase && supabaseAdmin && isValidUUID(userId)) {
      (async () => {
        try {
          await supabaseAdmin.from('profiles').upsert(profile);
          await supabaseAdmin.from('user_roles').upsert({ user_id: userId, role: 'investor' });
        } catch (err) {}
      })();
    }

    return res.json(profile);
  }

  return res.status(404).json({ message: 'Profile not found' });
});

app.post('/api/investor/register-profile', async (req: Request, res: Response) => {
  const { id, email, name, phone, referralCode } = req.body;
  const cleanEmail = (email || '').toLowerCase().trim();

  // Find existing profile by email first
  let profile = findCanonicalProfile(id, cleanEmail);

  if (profile) {
    // Update existing profile with new ID and metadata
    profile.id = id;
    if (name && name !== 'Investor') profile.name = name;
    if (phone) profile.phone = phone;
    store.profiles.set(id, profile);
  } else {
    profile = {
      id,
      name: name || (cleanEmail ? cleanEmail.split('@')[0] : 'Investor'),
      email: cleanEmail,
      phone: phone || '',
      total_invested: 0,
      current_phase: 'None',
      payment_plan_id: null,
      referral_earnings: 0,
      created_at: new Date().toISOString(),
    };
    linkCanonicalProfile(id, profile);
  }

  ensureReferralCode(profile);
  attachReferral(profile, referralCode);

  if (isLiveSupabase && supabaseAdmin && isValidUUID(id)) {
    try {
      await supabaseAdmin.from('profiles').upsert(profile);
      await supabaseAdmin.from('user_roles').upsert({ user_id: id, role: 'investor' });
    } catch (err) {
      console.error('Error registering profile to Supabase:', err);
    }
  }

  if (!store.user_roles.has(id)) {
    store.user_roles.set(id, 'investor');
  }
  res.json(profile);
});

app.get('/api/investor/dashboard/:id', async (req: Request, res: Response) => {
  const userId = req.params.id;
  const queryEmail = (req.query.email as string || '').toLowerCase().trim();

  // Find canonical profile from memory or session first
  let canonicalProfile = findCanonicalProfile(userId, queryEmail || store.current_session?.email);
  const effectiveEmail = (canonicalProfile?.email || queryEmail || store.current_session?.email || '').toLowerCase().trim();

  if (isLiveSupabase && supabaseAdmin && isValidUUID(userId)) {
    try {
      const [
        { data: profData },
        { data: bankData },
        { data: cardData },
        { data: investData },
        { data: payData },
        { data: payoutData },
        { data: receiptData },
        { data: notifData }
      ] = await Promise.all([
        supabaseAdmin.from('profiles').select('*').eq('id', userId).maybeSingle(),
        supabaseAdmin.from('bank_details').select('*').eq('user_id', userId).maybeSingle(),
        supabaseAdmin.from('card_details').select('*').eq('user_id', userId).maybeSingle(),
        supabaseAdmin.from('investments').select('*').eq('user_id', userId).maybeSingle(),
        supabaseAdmin.from('payments').select('*').eq('user_id', userId).order('created_at', { ascending: false }),
        supabaseAdmin.from('payouts').select('*').eq('user_id', userId).order('scheduled_date', { ascending: false }),
        supabaseAdmin.from('opay_receipts').select('*').eq('user_id', userId).order('uploaded_at', { ascending: false }),
        supabaseAdmin.from('notifications').select('*').or(`audience.eq.all,target_user_id.eq.${userId}`).order('sent_at', { ascending: false }),
      ]);

      let finalProfile = profData || canonicalProfile;
      if (!finalProfile) {
        // Automatically provision investor profile if user exists in auth
        try {
          const { data: userData } = await supabaseAdmin.auth.admin.getUserById(userId);
          if (userData?.user) {
            finalProfile = {
              id: userId,
              name: userData.user.user_metadata?.full_name || userData.user.email?.split('@')[0] || 'Investor',
              email: userData.user.email,
              phone: userData.user.user_metadata?.phone || '',
              total_invested: 0,
              current_phase: 'None',
              payment_plan_id: null,
              created_at: new Date().toISOString(),
            };
            await supabaseAdmin.from('profiles').upsert(finalProfile);
          }
        } catch (_) {}
      }

      if (finalProfile) {
        linkCanonicalProfile(userId, finalProfile);
      }

      // Merge Supabase and in-memory payments to ensure zero data loss
      const localPayments = store.payments.filter((p) => 
        p.user_id === userId || (finalProfile?.id && p.user_id === finalProfile.id) || (effectiveEmail && p.user_email?.toLowerCase() === effectiveEmail)
      );
      const localReceipts = store.opay_receipts.filter((r) => 
        r.user_id === userId || (finalProfile?.id && r.user_id === finalProfile.id) || (effectiveEmail && r.user_email?.toLowerCase() === effectiveEmail)
      );
      const localInvestment = store.investments.get(userId) || (finalProfile?.id ? store.investments.get(finalProfile.id) : null);

      const mergedPayments = [...(payData || []), ...localPayments.filter(lp => !(payData || []).some((p: any) => p.id === lp.id || (p.flutterwave_tx_ref && p.flutterwave_tx_ref === lp.flutterwave_tx_ref)))];
      const mergedReceipts = [...(receiptData || []), ...localReceipts.filter(lr => !(receiptData || []).some((r: any) => r.id === lr.id))];

      const approvedReceiptsTotal = mergedReceipts
        .filter((r: any) => r.status === 'approved')
        .reduce((sum: number, r: any) => sum + (Number(r.amount) || 0), 0);
      const successfulPaymentsTotal = mergedPayments
        .filter((p: any) => p.status === 'successful')
        .reduce((sum: number, p: any) => sum + (Number(p.amount) || 0), 0);

      const totalInvested = Math.max(
        Number(finalProfile?.total_invested || 0),
        Number(investData?.amount || 0),
        Number(localInvestment?.amount || 0),
        approvedReceiptsTotal + successfulPaymentsTotal
      );

      let finalInvestment = investData || localInvestment || null;
      if (totalInvested > 0) {
        if (finalProfile) {
          finalProfile.total_invested = totalInvested;
        }
        if (!finalInvestment) {
          const now = new Date();
          const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, now.getDate()).toISOString().split('T')[0];
          finalInvestment = {
            id: `inv-${Date.now()}`,
            user_id: userId,
            amount: totalInvested,
            phase: 'Phase 1: Seed Accumulation',
            type: 'opay',
            status: 'active',
            start_date: new Date().toISOString(),
            next_payment_date: nextMonth,
            cycle_count: 1,
            created_at: new Date().toISOString(),
          };
        } else {
          finalInvestment.amount = totalInvested;
          finalInvestment.status = 'active';
        }
      }

      return res.json({
        profile: finalProfile || null,
        bankDetails: bankData || store.bank_details.get(userId) || (finalProfile?.id ? store.bank_details.get(finalProfile.id) : null) || null,
        cardDetails: cardData || store.card_details.get(userId) || (finalProfile?.id ? store.card_details.get(finalProfile.id) : null) || null,
        investment: finalInvestment,
        payments: mergedPayments,
        payouts: payoutData || store.payouts.filter((p) => p.user_id === userId || (finalProfile?.id && p.user_id === finalProfile.id)),
        opayReceipts: mergedReceipts,
        notifications: (() => {
          const localNotifs = store.notifications.filter(
            (n) =>
              n.audience === 'all' ||
              n.target_user_id === userId ||
              (finalProfile?.id && n.target_user_id === finalProfile.id)
          );
          const dbNotifs = notifData || [];
          const ids = new Set(dbNotifs.map((n: any) => n.id));
          return [...localNotifs.filter((n) => !ids.has(n.id)), ...dbNotifs];
        })(),
        ...(finalProfile ? buildReferralPayload(userId, finalProfile) : {}),
      });
    } catch (err) {
      console.warn('Error fetching Supabase dashboard data, using local store fallback:', err);
    }
  }

  let profile = canonicalProfile;
  if (!profile) {
    profile = linkCanonicalProfile(userId, {
      id: userId,
      name: (store.current_session?.id === userId ? store.current_session?.name : undefined) || 'Investor',
      email: effectiveEmail || '',
      phone: '',
      total_invested: 0,
      current_phase: 'None',
      payment_plan_id: null,
      created_at: new Date().toISOString(),
    });
  }

  const userEmail = (profile?.email || effectiveEmail).toLowerCase().trim();
  const profileId = profile?.id || userId;

  const bankDetails = store.bank_details.get(userId) || store.bank_details.get(profileId) || null;
  const cardDetails = store.card_details.get(userId) || store.card_details.get(profileId) || null;
  
  // Find payments, receipts, payouts matching user_id or email
  const payments = store.payments.filter((p) => 
    p.user_id === userId || p.user_id === profileId || (userEmail && p.user_email?.toLowerCase() === userEmail)
  );
  const payouts = store.payouts.filter((p) => 
    p.user_id === userId || p.user_id === profileId || (userEmail && p.user_email?.toLowerCase() === userEmail)
  );
  const opayReceipts = store.opay_receipts.filter((r) => 
    r.user_id === userId || r.user_id === profileId || (userEmail && r.user_email?.toLowerCase() === userEmail)
  );
  const notifications = store.notifications.filter(
    (n) => n.audience === 'all' || n.target_user_id === userId || n.target_user_id === profileId
  );

  let investment = store.investments.get(userId) || store.investments.get(profileId) || null;

  const approvedReceiptsTotal = opayReceipts
    .filter((r) => r.status === 'approved')
    .reduce((sum, r) => sum + (Number(r.amount) || 0), 0);
  const successfulPaymentsTotal = payments
    .filter((p) => p.status === 'successful')
    .reduce((sum, p) => sum + (Number(p.amount) || 0), 0);

  const calculatedTotalInvested = Math.max(
    Number(profile.total_invested || 0),
    Number(investment?.amount || 0),
    approvedReceiptsTotal + successfulPaymentsTotal
  );

  if (calculatedTotalInvested > 0) {
    profile.total_invested = calculatedTotalInvested;
    const latestApprovedReceipt = opayReceipts.find((r) => r.status === 'approved');
    const phaseToUse = (investment?.phase && investment.phase !== 'None')
      ? investment.phase
      : latestApprovedReceipt?.target_phase || (profile.current_phase !== 'None' ? profile.current_phase : 'Phase 1: Seed Accumulation');

    profile.current_phase = phaseToUse;

    if (!investment) {
      const now = new Date();
      const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, now.getDate()).toISOString().split('T')[0];
      investment = {
        id: `inv-${Date.now()}`,
        user_id: profileId,
        amount: calculatedTotalInvested,
        phase: phaseToUse,
        type: latestApprovedReceipt ? 'opay' : 'auto',
        status: 'active',
        start_date: new Date().toISOString(),
        next_payment_date: nextMonth,
        cycle_count: 1,
        created_at: new Date().toISOString(),
      };
      store.investments.set(userId, investment);
      store.investments.set(profileId, investment);
    } else {
      investment.amount = calculatedTotalInvested;
      investment.phase = phaseToUse;
      investment.status = 'active';
    }
  }

  res.json({
    profile,
    bankDetails,
    cardDetails,
    investment,
    payments,
    payouts,
    opayReceipts,
    notifications,
    ...buildReferralPayload(userId, profile),
  });
});

app.post('/api/investor/auto-debit-plan', (req: Request, res: Response) => {
  const { userId, amount } = req.body;
  if (!userId || !amount || Number(amount) <= 0) {
    return res.status(400).json({ message: 'userId and a positive monthly amount are required' });
  }
  const card = store.card_details.get(userId);
  if (!card?.flutterwave_card_token) {
    return res.status(400).json({
      message: 'Save a debit card first via a Flutterwave payment, then set your monthly auto-debit amount.',
    });
  }
  const now = new Date();
  const nextCharge = new Date(now.getFullYear(), now.getMonth() + 1, now.getDate()).toISOString().split('T')[0];
  const reminder = new Date(now.getFullYear(), now.getMonth() + 1, now.getDate() - 1).toISOString().split('T')[0];
  const plan = {
    user_id: userId,
    amount: Number(amount),
    active: true,
    next_charge_date: nextCharge,
    reminder_date: reminder,
    last_reminder_sent: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
  store.auto_debit_plans.set(userId, plan);

  const profile = store.profiles.get(userId);
  if (profile) {
    profile.payment_plan_id = `plan_auto_${Date.now()}`;
    store.profiles.set(userId, profile);
  }

  store.notifications.unshift({
    id: `notif-ad-${Date.now()}`,
    title: 'Monthly auto-debit activated',
    body: `Your card will be charged ₦${Number(amount).toLocaleString()} each month. We’ll remind you a day before.`,
    audience: 'single',
    target_user_id: userId,
    icon: 'bell',
    image_url: null,
    sent_at: new Date().toISOString(),
    delivery_status: 'delivered',
  });

  logActivity(profile?.name || userId, 'AUTO_DEBIT_SET', `Monthly auto-debit set to ₦${Number(amount).toLocaleString()}`);
  res.json(plan);
});

/** Send day-before auto-debit reminders (callable by admin cron / refresh) */
app.post('/api/investor/auto-debit-reminders', (_req: Request, res: Response) => {
  const today = new Date().toISOString().split('T')[0];
  let sent = 0;
  for (const plan of store.auto_debit_plans.values()) {
    if (!plan.active) continue;
    if (plan.reminder_date === today && plan.last_reminder_sent !== today) {
      store.notifications.unshift({
        id: `notif-adr-${Date.now()}-${sent}`,
        title: 'Auto-debit tomorrow',
        body: `Reminder: ₦${Number(plan.amount).toLocaleString()} will be charged to your saved card tomorrow.`,
        audience: 'single',
        target_user_id: plan.user_id,
        icon: 'calendar',
        image_url: null,
        sent_at: new Date().toISOString(),
        delivery_status: 'delivered',
      });
      plan.last_reminder_sent = today;
      sent += 1;
    }
  }
  res.json({ success: true, sent });
});

app.post('/api/investor/bank-details', (req: Request, res: Response) => {
  const { userId, accountNumber, bankCode, bankName, accountName } = req.body;
  if (!userId || !accountNumber || !bankCode || !accountName) {
    return res.status(400).json({ message: 'Missing required bank parameters' });
  }

  const record = {
    user_id: userId,
    account_number: accountNumber,
    bank_code: bankCode,
    bank_name: bankName,
    account_name: accountName,
    flutterwave_beneficiary_id: `bene_${Date.now()}`,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  store.bank_details.set(userId, record);
  logActivity(accountName, 'BANK_DETAILS_SAVED', `Updated payout destination to ${bankName} (${accountNumber.slice(-4)})`);

  res.json(record);
});

app.post('/api/investor/cancel-subscription', (req: Request, res: Response) => {
  const { userId } = req.body;
  const investment = store.investments.get(userId);
  const profile = store.profiles.get(userId);

  if (investment) {
    investment.type = 'one-time';
    investment.status = 'paused';
    store.investments.set(userId, investment);
  }

  if (profile) {
    profile.payment_plan_id = null;
    store.profiles.set(userId, profile);
  }

  logActivity(profile?.name || userId, 'CANCEL_AUTO_DEBIT', 'Cancelled monthly auto-debit subscription plan');

  res.json({ success: true, message: 'Auto-debit subscription successfully cancelled' });
});

// ---------------- FLUTTERWAVE PAYMENTS & WEBHOOK API (v4) ----------------

function isChargeSucceeded(status?: string): boolean {
  return status === 'succeeded' || status === 'successful';
}

async function creditVerifiedPayment(params: {
  userId?: string;
  email?: string;
  name?: string;
  verifiedAmount: number;
  phase?: string;
  isRecurringPlan?: boolean;
  txRef: string;
  flwRef: string;
  cardLast4?: string;
  cardBrand?: string;
  cardToken?: string | null;
}) {
  const {
    userId,
    email,
    name,
    verifiedAmount,
    phase,
    isRecurringPlan,
    txRef,
    flwRef,
    cardLast4 = '****',
    cardBrand = 'Card',
    cardToken = null,
  } = params;

  const verifiedCustomerEmail = (email || '').toLowerCase().trim();
  const verifiedCustomerName = name || 'Investor';

  let profile: any = userId ? store.profiles.get(userId) : null;
  if (!profile && verifiedCustomerEmail) {
    for (const [_, p] of store.profiles.entries()) {
      if (p.email && p.email.toLowerCase() === verifiedCustomerEmail) {
        profile = p;
        break;
      }
    }
  }

  if (!profile) {
    profile = linkCanonicalProfile(userId || `usr-${Date.now()}`, {
      id: userId || `usr-${Date.now()}`,
      name: verifiedCustomerName,
      email: verifiedCustomerEmail,
      phone: '',
      total_invested: 0,
      current_phase: phase || 'None',
      payment_plan_id: null,
      created_at: new Date().toISOString(),
    });
  }

  const effectiveUserId = profile.id;
  const targetPhase = phase || profile.current_phase || 'None';

  const existingPayment = store.payments.find(
    (p) => (txRef && p.flutterwave_tx_ref === txRef) || (flwRef && (p.flutterwave_ref === flwRef || p.reference === flwRef))
  );

  let payment: any = existingPayment;

  if (!existingPayment) {
    payment = {
      id: `pay-${Date.now()}`,
      user_id: effectiveUserId,
      user_email: profile.email || verifiedCustomerEmail,
      amount: verifiedAmount,
      method: isRecurringPlan ? 'auto_debit' : 'card',
      flutterwave_tx_ref: txRef,
      flutterwave_ref: flwRef,
      reference: txRef || flwRef,
      status: 'successful',
      notes: `Flutterwave payment (${targetPhase})`,
      created_at: new Date().toISOString(),
    };
    store.payments.unshift(payment);

    profile.total_invested = Number(profile.total_invested || 0) + verifiedAmount;
    profile.current_phase = targetPhase;
    if (isRecurringPlan) {
      profile.payment_plan_id = `plan_flw_${Date.now()}`;
    }
    store.profiles.set(profile.id, profile);
    if (userId && userId !== profile.id) {
      store.profiles.set(userId, profile);
    }
    creditReferralCommission(profile, verifiedAmount);
  }

  if (cardToken) {
    const cardRecord = {
      user_id: effectiveUserId,
      flutterwave_card_token: cardToken,
      card_last4: cardLast4,
      card_brand: cardBrand,
      card_exp_month: '12',
      card_exp_year: '28',
      created_at: new Date().toISOString(),
    };
    store.card_details.set(effectiveUserId, cardRecord);
    if (userId && userId !== effectiveUserId) {
      store.card_details.set(userId, cardRecord);
    }
  }

  let investment = store.investments.get(effectiveUserId) || (userId ? store.investments.get(userId) : null);
  const now = new Date();
  const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, now.getDate()).toISOString().split('T')[0];

  if (investment) {
    if (!existingPayment) {
      investment.amount = Number(investment.amount) + verifiedAmount;
      investment.cycle_count = (investment.cycle_count || 0) + 1;
    }
    investment.phase = targetPhase;
    investment.type = isRecurringPlan ? 'auto' : investment.type;
    investment.status = 'active';
    investment.next_payment_date = nextMonth;
  } else {
    investment = {
      id: `inv-${Date.now()}`,
      user_id: effectiveUserId,
      amount: profile.total_invested > 0 ? profile.total_invested : verifiedAmount,
      phase: targetPhase,
      type: isRecurringPlan ? 'auto' : 'one-time',
      status: 'active',
      start_date: new Date().toISOString(),
      next_payment_date: nextMonth,
      cycle_count: 1,
      created_at: new Date().toISOString(),
    };
  }
  store.investments.set(effectiveUserId, investment);
  if (userId && userId !== effectiveUserId) {
    store.investments.set(userId, investment);
  }

  if (isLiveSupabase && supabaseAdmin && isValidUUID(effectiveUserId)) {
    try {
      await supabaseAdmin.from('profiles').upsert({
        id: effectiveUserId,
        name: profile.name,
        email: profile.email,
        phone: profile.phone,
        total_invested: profile.total_invested,
        current_phase: profile.current_phase,
      });

      const invPayload: any = {
        user_id: effectiveUserId,
        amount: investment.amount,
        phase: investment.phase,
        type: investment.type,
        status: 'active',
        start_date: investment.start_date,
        next_payment_date: investment.next_payment_date,
        cycle_count: investment.cycle_count || 1,
      };
      if (isValidUUID(investment.id)) {
        invPayload.id = investment.id;
      }
      await supabaseAdmin.from('investments').upsert(invPayload, { onConflict: 'user_id' });

      if (!existingPayment) {
        const payPayload: any = {
          user_id: effectiveUserId,
          amount: verifiedAmount,
          method: payment.method || 'card',
          flutterwave_tx_ref: payment.flutterwave_tx_ref,
          status: 'successful',
          notes: payment.notes,
          created_at: payment.created_at,
        };
        if (isValidUUID(payment.id)) {
          payPayload.id = payment.id;
        }
        await supabaseAdmin.from('payments').insert(payPayload);

        // Also add a database notification
        await supabaseAdmin.from('notifications').insert({
          id: crypto.randomUUID(),
          title: 'Payment Received',
          body: `Congratulations! Your payment of ₦${verifiedAmount.toLocaleString()} has been successfully credited to ${targetPhase}.`,
          audience: effectiveUserId,
          target_user_id: effectiveUserId,
          delivery_status: 'delivered'
        });
      }
    } catch (dbErr) {
      console.warn('Supabase sync warning on payment credit:', dbErr);
    }
  }

  if (!existingPayment) {
    logActivity(
      profile?.name || verifiedCustomerEmail || effectiveUserId,
      'PAYMENT_RECEIVED',
      `Received payment of ₦${verifiedAmount.toLocaleString()} via Flutterwave`,
      verifiedAmount
    );

    // Push local notification for RAM state
    store.notifications.unshift({
      id: crypto.randomUUID(),
      title: 'Payment Received',
      body: `Congratulations! Your payment of ₦${verifiedAmount.toLocaleString()} has been successfully credited to ${targetPhase}.`,
      audience: effectiveUserId,
      target_user_id: effectiveUserId,
      sent_at: new Date().toISOString(),
      delivery_status: 'delivered',
    });
  }

  pendingCharges.delete(txRef);
  return { payment, investment, profile, existingPayment: Boolean(existingPayment) };
}

app.post('/api/flutterwave/initiate', async (req: Request, res: Response) => {
  const { userId, email, name, phone, amount, phase, isRecurringPlan, paymentType } = req.body;

  if (!email || !amount || Number(amount) <= 0) {
    return res.status(400).json({ message: 'Valid email and amount are required.' });
  }
  if (!isFlutterwaveConfigured()) {
    return res.status(503).json({ message: 'Flutterwave is not configured.' });
  }
  if (!FLUTTERWAVE_ENCRYPTION_KEY) {
    return res.status(503).json({ message: 'FLUTTERWAVE_ENCRYPTION_KEY is required for card payments.' });
  }

  const reference = `SIGMA${Date.now()}${crypto.randomUUID().replace(/[^a-zA-Z0-9]/g, '').slice(0, 8)}`;
  const frontendUrl = (process.env.FRONTEND_URL || process.env.APP_URL || 'https://sigmawealthsolution.vercel.app').replace(/\/$/, '');
  const redirectUrl = `${frontendUrl}/api/flutterwave/callback?reference=${encodeURIComponent(reference)}`;

  try {
    const result = await initiateDirectCharge({
      amount: Number(amount),
      reference,
      email: String(email).trim(),
      name,
      phone,
      redirectUrl,
      paymentType: paymentType === 'opay' ? 'opay' : 'card',
      meta: { userId, phase, isRecurringPlan: !!isRecurringPlan },
    });

    let charge = result.data || result;
    const chargeId = charge.id;
    if (!chargeId) {
      return res.status(502).json({ message: 'Flutterwave did not return a charge ID.' });
    }

    pendingCharges.set(reference, {
      chargeId,
      userId: userId || '',
      amount: Number(amount),
      phase: phase || 'None',
      isRecurringPlan: !!isRecurringPlan,
      email: String(email).trim(),
      name: name || 'Investor',
    });

    let redirectTo: string | null = null;
    if (isSandboxMode() && charge.status === 'pending') {
      const completed = await completeSandboxCharge(chargeId);
      charge = completed.charge;
      redirectTo = completed.redirectUrl;
    } else if (charge.next_action?.type === 'redirect_url') {
      redirectTo = charge.next_action.redirect_url?.url || charge.next_action.redirect_url || null;
    }

    if (isChargeSucceeded(charge.status)) {
      return res.json({
        success: true,
        chargeId,
        reference,
        status: charge.status,
        redirectUrl: null,
        completed: true,
      });
    }

    return res.json({
      success: true,
      chargeId,
      reference,
      status: charge.status,
      redirectUrl: redirectTo,
      completed: false,
      nextAction: charge.next_action || null,
    });
  } catch (err: any) {
    console.error('Flutterwave initiate error:', err);
    return res.status(500).json({ message: err.message || 'Failed to initiate payment.', payload: err.payload });
  }
});

app.get('/api/flutterwave/callback', (req: Request, res: Response) => {
  const reference = req.query.reference || req.query.tx_ref || '';
  res.redirect(`/dashboard?flw_return=1&reference=${encodeURIComponent(String(reference))}`);
});

app.post('/api/flutterwave/webhook', async (req: Request, res: Response) => {
  try {
    const payload = req.body;
    if (!payload || !payload.data) {
      return res.status(200).json({ status: 'ignored', message: 'No payload data' });
    }

    const eventType = payload.type || payload.event;
    const data = payload.data;
    if (!data) {
      return res.status(200).json({ status: 'ignored', message: 'No payload data' });
    }

    if (eventType === 'transfer.completed') {
      const transferId = data.id;
      const status = isChargeSucceeded(data.status) ? 'successful' : 'failed';
      const payout = store.payouts.find((p) => p.flutterwave_transfer_id === String(transferId));
      if (payout) {
        payout.status = status;
        payout.processed_at = new Date().toISOString();
        logActivity(
          'Flutterwave Webhook',
          'PAYOUT_WEBHOOK_STATUS',
          `Transfer #${transferId} completed with status: ${status}`
        );
      }
    } else if (eventType === 'charge.completed' && isChargeSucceeded(data.status)) {
      const txRef = data.reference || data.tx_ref;
      const flwRef = data.id || data.flw_ref;
      const amount = Number(data.amount) || 0;
      const customerEmail = (data.customer?.email || '').toLowerCase().trim();
      const customerName = data.customer?.name?.first
        ? `${data.customer.name.first} ${data.customer.name.last || ''}`.trim()
        : data.customer?.name || 'Investor';
      const pending = txRef ? pendingCharges.get(txRef) : undefined;
      const card = data.payment_method?.card;
      const cardLast4 = card?.last4 || '****';
      const cardBrand = card?.network || card?.brand || 'Card';

      await creditVerifiedPayment({
        userId: pending?.userId,
        email: customerEmail || pending?.email,
        name: customerName || pending?.name,
        verifiedAmount: amount,
        phase: pending?.phase,
        isRecurringPlan: pending?.isRecurringPlan,
        txRef: txRef || `FLW_${flwRef}`,
        flwRef: String(flwRef),
        cardLast4,
        cardBrand,
        cardToken: data.payment_method?.id || null,
      });
    }

    return res.status(200).json({ status: 'success' });
  } catch (err: any) {
    console.error('Flutterwave webhook processing error:', err);
    return res.status(200).json({ status: 'error', message: err.message });
  }
});

app.post('/api/flutterwave/sync', async (req: Request, res: Response) => {
  res.json({
    success: true,
    syncedCount: 0,
    totalPayments: store.payments.length,
    message: 'Payments are synchronized via webhooks and charge verification in Flutterwave v4.',
  });
});

app.post('/api/flutterwave/verify', async (req: Request, res: Response) => {
  const { chargeId, transactionId, txRef, flwRef, userId, email, name, amount, phase, isRecurringPlan } = req.body;

  if (!userId && !email) {
    return res.status(400).json({ message: 'Missing user identification parameters' });
  }

  const pending = txRef ? pendingCharges.get(txRef) : undefined;
  const resolvedChargeId = chargeId || transactionId || pending?.chargeId;
  let verifiedAmount = Number(amount) || pending?.amount || 0;
  let resolvedTxRef = txRef || '';
  let resolvedFlwRef = flwRef || '';
  let cardLast4 = '****';
  let cardBrand = 'Card';
  let cardToken: string | null = null;

  if (!isFlutterwaveConfigured()) {
    return res.status(503).json({ message: 'Flutterwave is not configured.' });
  }

  if (!resolvedChargeId) {
    return res.status(400).json({ message: 'Charge ID is required to verify payment.' });
  }

  try {
    const chargeRes = await getCharge(String(resolvedChargeId));
    const charge = chargeRes.data;
    if (!isChargeSucceeded(charge?.status)) {
      return res.status(400).json({ message: `Payment not completed. Current status: ${charge?.status || 'unknown'}` });
    }

    verifiedAmount = Number(charge.amount) || verifiedAmount;
    resolvedTxRef = charge.reference || resolvedTxRef || `APEX_${resolvedChargeId}`;
    resolvedFlwRef = charge.id || resolvedFlwRef;
    const pmCard = charge.payment_method?.card;
    if (pmCard) {
      cardLast4 = pmCard.last4 || cardLast4;
      cardBrand = pmCard.network || pmCard.brand || cardBrand;
    }
    cardToken = charge.payment_method?.id || null;
  } catch (err: any) {
    return res.status(502).json({ message: err.message || 'Failed to verify charge with Flutterwave.' });
  }

  const result = await creditVerifiedPayment({
    userId: userId || pending?.userId,
    email: email || pending?.email,
    name: name || pending?.name,
    verifiedAmount,
    phase: phase || pending?.phase,
    isRecurringPlan: isRecurringPlan ?? pending?.isRecurringPlan,
    txRef: resolvedTxRef,
    flwRef: String(resolvedFlwRef),
    cardLast4,
    cardBrand,
    cardToken,
  });

  res.json({
    success: true,
    message: result.existingPayment ? 'Payment already recorded' : 'Payment verified and investment credited successfully',
    payment: result.payment,
    investment: result.investment,
    profile: result.profile,
  });
});

// ---------------- OPAY RECEIPTS API ----------------

app.post('/api/opay/submit-receipt', async (req: Request, res: Response) => {
  const { userId, receiptImageUrl, amount, phase, userEmail } = req.body;
  if (!userId || !receiptImageUrl || !amount) {
    return res.status(400).json({ message: 'Receipt image and claimed amount are required' });
  }

  let prof = store.profiles.get(userId);
  if (!prof && userEmail) {
    for (const [_, p] of store.profiles.entries()) {
      if (p.email && p.email.toLowerCase() === userEmail.toLowerCase()) {
        prof = p;
        break;
      }
    }
  }

  const targetPhase = phase || 'Phase 1: Seed Accumulation';
  const emailToUse = userEmail || prof?.email || store.current_session?.email || '';

  const receipt = {
    id: `opay-${Date.now()}`,
    user_id: userId,
    user_email: emailToUse,
    receipt_image_url: receiptImageUrl,
    amount: Number(amount),
    target_phase: targetPhase,
    status: 'pending',
    reviewed_by: null,
    admin_notes: null,
    created_at: new Date().toISOString(),
    reviewed_at: null,
  };

  store.opay_receipts.unshift(receipt);

  if (isLiveSupabase && supabaseAdmin && isValidUUID(userId)) {
    try {
      await supabaseAdmin.from('opay_receipts').upsert({
        id: receipt.id,
        user_id: userId,
        receipt_image_url: receiptImageUrl,
        amount: Number(amount),
        target_phase: targetPhase,
        status: 'pending',
        uploaded_at: receipt.created_at,
      });
    } catch (err) {
      console.warn('Supabase opay receipt upload notice:', err);
    }
  }

  logActivity(
    prof?.name || emailToUse || userId,
    'OPAY_RECEIPT_UPLOAD',
    `Uploaded OPay transfer proof for ₦${Number(amount).toLocaleString()} (${targetPhase})`,
    Number(amount)
  );

  res.json(receipt);
});

// Helper: Server-side check for both admin role AND admin allowlist
async function verifyIsAdmin(userId: string, userEmail?: string): Promise<{ isAdmin: boolean; reason?: string }> {
  // If Live Supabase client is connected, query Postgres tables
  if (isLiveSupabase && supabaseAdmin) {
    try {
      // 1. Resolve email
      let emailToCheck = (userEmail || '').toLowerCase().trim();
      if (!emailToCheck && isValidUUID(userId)) {
        const { data: profileData } = await supabaseAdmin
          .from('profiles')
          .select('email')
          .eq('id', userId)
          .maybeSingle();
        emailToCheck = profileData?.email?.toLowerCase()?.trim() || '';
      }

      if (!emailToCheck && isValidUUID(userId)) {
        // Try getting from Supabase auth admin
        try {
          const { data: authUserData } = await supabaseAdmin.auth.admin.getUserById(userId);
          emailToCheck = authUserData?.user?.email?.toLowerCase()?.trim() || '';
        } catch (_) {}
      }

      if (!emailToCheck) {
        const localProf = store.profiles.get(userId);
        emailToCheck = (localProf?.email || (store.current_session?.id === userId ? store.current_session?.email : '') || '').toLowerCase().trim();
      }

      if (!emailToCheck) {
        return { isAdmin: false, reason: 'EMAIL_UNRESOLVED' };
      }

      // 2. Check admin_allowlist table (Hard backstop check)
      const { data: allowData, error: allowError } = await supabaseAdmin
        .from('admin_allowlist')
        .select('email')
        .ilike('email', emailToCheck)
        .maybeSingle();

      // Check fallback allowlist in case table is freshly created
      const isLocallyAllowlisted = store.admin_allowlist.has(emailToCheck);

      if ((allowError || !allowData) && !isLocallyAllowlisted) {
        return { isAdmin: false, reason: 'NOT_ON_ALLOWLIST' };
      }

      // 3. User is verified in allowlist! Ensure user_roles has admin role if userId is UUID
      if (isValidUUID(userId)) {
        const { data: roleData } = await supabaseAdmin
          .from('user_roles')
          .select('role')
          .eq('user_id', userId)
          .maybeSingle();

        if (!roleData || roleData.role !== 'admin') {
          try {
            await supabaseAdmin.from('user_roles').upsert({ user_id: userId, role: 'admin' });
          } catch (_) {}
        }
      }

      store.user_roles.set(userId, 'admin');
      return { isAdmin: true };
    } catch (err) {
      console.error('Error during Supabase admin verification:', err);
      // Fallback check against local store allowlist
      const fallbackEmail = (userEmail || '').toLowerCase().trim();
      if (fallbackEmail && store.admin_allowlist.has(fallbackEmail)) {
        store.user_roles.set(userId, 'admin');
        return { isAdmin: true };
      }
      return { isAdmin: false, reason: 'VERIFICATION_ERROR' };
    }
  }

  // Local/Sandbox data layer
  const profile = store.profiles.get(userId);
  const email = (userEmail || profile?.email || (store.current_session?.id === userId ? store.current_session?.email : '') || '').toLowerCase().trim();

  const isAllowlisted = Boolean(email && store.admin_allowlist.has(email));
  if (!isAllowlisted) {
    return { isAdmin: false, reason: 'NOT_ON_ALLOWLIST' };
  }

  // If email is in allowlist, ensure user_roles has admin
  store.user_roles.set(userId, 'admin');

  return { isAdmin: true };
}

// ---------------- ADMIN API (SECURED / ROLE & ALLOWLIST CHECKED) ----------------

app.get('/api/admin/check-role/:id', async (req: Request, res: Response) => {
  const userId = req.params.id;
  const userEmail = (req.query.email as string) || '';
  const result = await verifyIsAdmin(userId, userEmail);

  res.json({ 
    isAdmin: result.isAdmin, 
    role: result.isAdmin ? 'admin' : 'investor' 
  });
});

// Overview tab: Attention items, KPIs, and Live Activity Feed
app.get('/api/admin/overview', async (req: Request, res: Response) => {
  // Sync platform settings from Supabase if live
  if (isLiveSupabase && supabaseAdmin) {
    try {
      const { data: settingsData } = await supabaseAdmin
        .from('platform_settings')
        .select('*')
        .eq('key', 'payout_mode')
        .maybeSingle();
      if (settingsData?.value?.mode) {
        store.platform_settings.payout_mode = settingsData.value.mode;
        if (settingsData.updated_at) {
          store.platform_settings.updated_at = settingsData.updated_at;
        }
      }
    } catch (err) {
      console.warn('Failed to load platform_settings from Supabase for overview:', err);
    }
  }

  const pendingOPayCount = store.opay_receipts.filter((r) => r.status === 'pending').length;
  
  const todayStr = new Date().toISOString().split('T')[0];
  const activeInvestments = Array.from(store.investments.values()).filter(
    (inv) => inv.status === 'active' && inv.next_payment_date
  );
  const payoutsDueTodayCount = activeInvestments.filter(
    (inv) => inv.next_payment_date && inv.next_payment_date <= todayStr
  ).length;
  const scheduledPayoutsCount = activeInvestments.length;

  const failedPayoutsCount = store.payouts.filter((p) => p.status === 'failed').length;

  // Use distinct non-admin investors
  const distinctInvestors = getDistinctInvestors();
  const totalInvestors = distinctInvestors.length;
  const totalAUM = distinctInvestors.reduce((sum, p) => sum + Number(p.total_invested || 0), 0);
  const totalPayoutsDisbursed = store.payouts
    .filter((p) => p.status === 'successful')
    .reduce((sum, p) => sum + Number(p.amount || 0), 0);

  const successfulPayments = store.payments.filter((p) => p.status === 'successful');
  const totalPaymentsVolume = successfulPayments.reduce((sum, p) => sum + Number(p.amount || 0), 0);

  // Last 14 days payment chart
  const dayKeys: string[] = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date();
    d.setHours(0, 0, 0, 0);
    d.setDate(d.getDate() - i);
    dayKeys.push(d.toISOString().split('T')[0]);
  }
  const byDayMap = new Map(dayKeys.map((k) => [k, { date: k, amount: 0, count: 0 }]));
  for (const p of store.payments) {
    const day = String(p.created_at || '').slice(0, 10);
    if (!byDayMap.has(day)) continue;
    const row = byDayMap.get(day)!;
    row.count += 1;
    if (p.status === 'successful') row.amount += Number(p.amount || 0);
  }
  const paymentsByDay = Array.from(byDayMap.values());

  const statusBuckets = ['successful', 'pending', 'failed'] as const;
  const paymentsByStatus = statusBuckets.map((status) => {
    const rows = store.payments.filter((p) => p.status === status);
    return {
      status,
      count: rows.length,
      amount: rows.reduce((s, p) => s + Number(p.amount || 0), 0),
    };
  });

  const scheduledPayouts = activeInvestments
    .map((inv) => {
      const profile = store.profiles.get(inv.user_id);
      const bankDetails = store.bank_details.get(inv.user_id) || null;
      return {
        userId: inv.user_id,
        investorName: profile?.name || profile?.email || 'Investor',
        investorEmail: profile?.email || '—',
        amount: Math.round(Number(inv.amount) * 0.15) || 0,
        nextPaymentDate: inv.next_payment_date as string,
        hasBeneficiary: Boolean(bankDetails?.account_number),
      };
    })
    .sort((a, b) => a.nextPaymentDate.localeCompare(b.nextPaymentDate));

  res.json({
    attention: {
      pendingOPayCount,
      payoutsDueTodayCount,
      failedPayoutsCount,
      scheduledPayoutsCount,
    },
    kpis: {
      totalInvestors,
      investorWeeklyDelta: Math.max(0, totalInvestors),
      totalAUM,
      payoutMode: store.platform_settings.payout_mode,
      totalPayoutsDisbursed,
      totalPaymentsVolume,
      successfulPaymentsCount: successfulPayments.length,
    },
    charts: {
      paymentsByDay,
      paymentsByStatus,
    },
    scheduledPayouts,
    activityFeed: store.activity_log,
  });
});

// Investors tab: Data table & detail
app.get('/api/admin/investors', async (req: Request, res: Response) => {
  const { q, phase } = req.query;

  // If live Supabase, sync all profiles into local store
  if (isLiveSupabase && supabaseAdmin) {
    try {
      const { data: dbProfiles } = await supabaseAdmin.from('profiles').select('*');
      if (dbProfiles && dbProfiles.length > 0) {
        for (const p of dbProfiles) {
          linkCanonicalProfile(p.id, p);
        }
      }
      const { data: dbInvestments } = await supabaseAdmin.from('investments').select('*');
      if (dbInvestments) {
        for (const inv of dbInvestments) {
          store.investments.set(inv.user_id, inv);
        }
      }
      const { data: dbBank } = await supabaseAdmin.from('bank_details').select('*');
      if (dbBank) {
        for (const b of dbBank) {
          store.bank_details.set(b.user_id, b);
        }
      }
      const { data: dbCard } = await supabaseAdmin.from('card_details').select('*');
      if (dbCard) {
        for (const c of dbCard) {
          store.card_details.set(c.user_id, c);
        }
      }
    } catch (err) {
      console.warn('Failed to sync investors dataset from Supabase:', err);
    }
  }

  // Get distinct human investors (strictly non-admin)
  const distinctInvestors = getDistinctInvestors();

  let investorsList = distinctInvestors.map((prof) => {
    const bankDetails = store.bank_details.get(prof.id) || null;
    const cardDetails = store.card_details.get(prof.id) || null;
    const investment = store.investments.get(prof.id) || null;
    
    const profEmail = (prof.email || '').toLowerCase().trim();
    const userPayments = store.payments.filter((p) => p.user_id === prof.id || (profEmail && p.user_email?.toLowerCase() === profEmail));
    const userPayouts = store.payouts.filter((p) => p.user_id === prof.id || (profEmail && p.user_email?.toLowerCase() === profEmail));
    const userReceipts = store.opay_receipts.filter((r) => r.user_id === prof.id || (profEmail && r.user_email?.toLowerCase() === profEmail));

    const approvedReceiptsTotal = userReceipts
      .filter((r) => r.status === 'approved')
      .reduce((sum, r) => sum + (Number(r.amount) || 0), 0);
    const successfulPaymentsTotal = userPayments
      .filter((p) => p.status === 'successful')
      .reduce((sum, p) => sum + (Number(p.amount) || 0), 0);

    const calculatedTotalInvested = Math.max(
      Number(prof.total_invested || 0),
      Number(investment?.amount || 0),
      approvedReceiptsTotal + successfulPaymentsTotal
    );

    const updatedProfile = {
      ...prof,
      total_invested: calculatedTotalInvested,
      current_phase: investment?.phase || prof.current_phase || (calculatedTotalInvested > 0 ? 'Phase 1: Seed Accumulation' : 'None'),
    };

    return {
      profile: updatedProfile,
      bankDetails,
      cardDetails,
      investment: investment ? { ...investment, amount: calculatedTotalInvested } : null,
      paymentsCount: userPayments.length,
      payoutsCount: userPayouts.length,
    };
  });

  if (q && typeof q === 'string') {
    const search = q.toLowerCase();
    investorsList = investorsList.filter(
      (item) =>
        item.profile.name?.toLowerCase().includes(search) ||
        item.profile.email.toLowerCase().includes(search) ||
        item.profile.phone?.toLowerCase().includes(search)
    );
  }

  if (phase && typeof phase === 'string' && phase !== 'all') {
    investorsList = investorsList.filter((item) => item.profile.current_phase === phase);
  }

  res.json({ investors: investorsList });
});

// Delete investor account with mandatory cascade and activity logging
app.delete('/api/admin/investors/:id', async (req: Request, res: Response) => {
  const userId = req.params.id;
  const { adminName } = req.body;

  let investorName = userId;
  const localProfile = store.profiles.get(userId);
  if (localProfile?.name || localProfile?.email) {
    investorName = localProfile.name || localProfile.email;
  }

  // 1. Supabase Database Cascade Deletion
  if (isLiveSupabase && supabaseAdmin && isValidUUID(userId)) {
    try {
      const { data: dbProf } = await supabaseAdmin
        .from('profiles')
        .select('*')
        .eq('id', userId)
        .maybeSingle();

      if (dbProf?.name || dbProf?.email) {
        investorName = dbProf.name || dbProf.email;
      }

      // Explicitly delete all child records
      await supabaseAdmin.from('bank_details').delete().eq('user_id', userId);
      await supabaseAdmin.from('card_details').delete().eq('user_id', userId);
      await supabaseAdmin.from('investments').delete().eq('user_id', userId);
      await supabaseAdmin.from('payments').delete().eq('user_id', userId);
      await supabaseAdmin.from('payouts').delete().eq('user_id', userId);
      await supabaseAdmin.from('opay_receipts').delete().eq('user_id', userId);
      await supabaseAdmin.from('user_roles').delete().eq('user_id', userId);
      await supabaseAdmin.from('notifications').delete().eq('target_user_id', userId);
      
      // Delete profile record
      const { error: deleteProfErr } = await supabaseAdmin.from('profiles').delete().eq('id', userId);
      if (deleteProfErr) {
        console.error('Error deleting profile in Supabase:', deleteProfErr);
      }

      // Delete Auth user account
      try {
        await supabaseAdmin.auth.admin.deleteUser(userId);
      } catch (authErr) {
        console.warn('Note: Auth user deletion notice:', authErr);
      }
    } catch (dbErr) {
      console.error('Failed to perform Supabase cascade delete:', dbErr);
    }
  }

  // 2. Local In-Memory Cascade Delete
  store.profiles.delete(userId);
  store.user_roles.delete(userId);
  store.bank_details.delete(userId);
  store.card_details.delete(userId);
  store.investments.delete(userId);
  store.payments = store.payments.filter((p) => p.user_id !== userId);
  store.payouts = store.payouts.filter((p) => p.user_id !== userId);
  store.opay_receipts = store.opay_receipts.filter((r) => r.user_id !== userId);
  store.notifications = store.notifications.filter((n) => n.target_user_id !== userId);

  // 3. Write Activity Log entry
  await logActivity(
    adminName || 'Admin',
    'INVESTOR_ACCOUNT_DELETED',
    `Permanently deleted investor profile (${investorName}) and all associated payment/payout history`
  );

  res.json({ success: true, message: `Investor ${investorName} permanently deleted` });
});

// Update investor record
app.patch('/api/admin/investors/:id', async (req: Request, res: Response) => {
  const userId = req.params.id;
  const { updates, adminName } = req.body;

  const profile = store.profiles.get(userId) || { id: userId, email: 'investor@example.com' };
  Object.assign(profile, updates);
  store.profiles.set(userId, profile);

  if (isLiveSupabase && supabaseAdmin && isValidUUID(userId)) {
    try {
      await supabaseAdmin.from('profiles').update(updates).eq('id', userId);
    } catch (err) {
      console.error('Failed to update profile in Supabase:', err);
    }
  }

  await logActivity(
    adminName || 'Admin',
    'INVESTOR_RECORD_UPDATED',
    `Adjusted record for ${profile.name || profile.email}: ${JSON.stringify(updates)}`
  );

  res.json({ success: true, profile });
});

// Payments tab: Transaction table across all investors
app.get('/api/admin/payments', async (req: Request, res: Response) => {
  if (isLiveSupabase && supabaseAdmin) {
    try {
      const { data: dbPayments } = await supabaseAdmin.from('payments').select('*').order('created_at', { ascending: false });
      if (dbPayments && dbPayments.length > 0) {
        store.payments = dbPayments;
      }
    } catch (err) {
      console.warn('Failed to sync payments from Supabase:', err);
    }
  }

  const enrichedPayments = store.payments.map((p) => {
    let profile = store.profiles.get(p.user_id);
    if (!profile && p.user_email) {
      for (const [_, pr] of store.profiles.entries()) {
        if (pr.email && pr.email.toLowerCase() === p.user_email.toLowerCase()) {
          profile = pr;
          break;
        }
      }
    }
    return {
      ...p,
      reference: p.flutterwave_tx_ref || p.reference || p.id,
      payment_method: p.method || p.payment_method || 'card',
      investor_name: profile?.name || p.user_email || 'Investor',
      investor_email: profile?.email || p.user_email || '—',
    };
  });
  res.json(enrichedPayments);
});

// Payouts tab: Automation engine, Due Today, Upcoming, Mode toggle
app.get('/api/admin/payouts', async (req: Request, res: Response) => {
  // Sync platform settings (payout_mode) from Supabase if live
  if (isLiveSupabase && supabaseAdmin) {
    try {
      const { data: settingsData } = await supabaseAdmin
        .from('platform_settings')
        .select('*')
        .eq('key', 'payout_mode')
        .maybeSingle();

      if (settingsData?.value?.mode) {
        store.platform_settings.payout_mode = settingsData.value.mode;
        if (settingsData.updated_at) {
          store.platform_settings.updated_at = settingsData.updated_at;
        }
      }

      const { data: dbPayouts } = await supabaseAdmin.from('payouts').select('*').order('processed_at', { ascending: false });
      if (dbPayouts && dbPayouts.length > 0) {
        store.payouts = dbPayouts;
      }
    } catch (err) {
      console.warn('Failed to sync payouts dataset from Supabase:', err);
    }
  }

  const todayStr = new Date().toISOString().split('T')[0];
  
  const dueToday: any[] = [];
  const upcoming: any[] = [];

  Array.from(store.investments.values()).forEach((inv) => {
    if (inv.status !== 'active' || !inv.next_payment_date) return;

    const profile = store.profiles.get(inv.user_id);
    const bankDetails = store.bank_details.get(inv.user_id) || null;
    
    // Check if investor made confirmed payment in current cycle
    const userPayments = store.payments.filter((p) => p.user_id === inv.user_id && p.status === 'successful');
    const hasPaidIn = userPayments.length > 0;

    const payoutItem = {
      userId: inv.user_id,
      investorName: profile?.name || profile?.email || 'Investor',
      investorEmail: profile?.email || '—',
      amount: Math.round(Number(inv.amount) * 0.15) || 0,
      nextPaymentDate: inv.next_payment_date || todayStr,
      hasBeneficiary: Boolean(bankDetails?.account_number),
      bankDetails,
      hasPaidIn,
    };

    if (inv.next_payment_date <= todayStr) {
      dueToday.push(payoutItem);
    } else {
      upcoming.push(payoutItem);
    }
  });

  const enrichedPayouts = store.payouts.map((po) => {
    const prof = store.profiles.get(po.user_id);
    return {
      ...po,
      investor_name: prof?.name || 'Investor',
      investor_email: prof?.email || '—',
    };
  });

  res.json({
    payouts: enrichedPayouts,
    dueToday,
    upcoming,
    payoutMode: store.platform_settings.payout_mode,
    lastRunTimestamp: store.platform_settings.updated_at,
    batchHistory: store.payout_batches,
  });
});

// Toggle payout mode (Automatic vs Manual)
app.post('/api/admin/payout-mode', async (req: Request, res: Response) => {
  const { mode, adminName } = req.body;
  if (mode !== 'automatic' && mode !== 'manual') {
    return res.status(400).json({ message: 'Invalid payout mode. Must be "automatic" or "manual".' });
  }

  const prevMode = store.platform_settings.payout_mode;
  const timestamp = new Date().toISOString();

  // 1. Update in-memory state
  store.platform_settings.payout_mode = mode;
  store.platform_settings.updated_by = adminName || 'Admin';
  store.platform_settings.updated_at = timestamp;

  // 2. Persist to Supabase platform_settings table
  if (isLiveSupabase && supabaseAdmin) {
    try {
      const { error: dbError } = await supabaseAdmin.from('platform_settings').upsert(
        {
          key: 'payout_mode',
          value: { mode, updated_by: adminName || 'Admin' },
          updated_at: timestamp,
        },
        { onConflict: 'key' }
      );
      if (dbError) console.warn('payout_mode upsert notice:', dbError.message);
    } catch (err) {
      console.warn('Failed to persist payout_mode:', err);
    }
  }

  // Keep memory as source of truth after an explicit admin toggle
  store.platform_settings.payout_mode = mode;

  // 3. Write to Activity Feed
  await logActivity(
    adminName || 'Admin',
    'PAYOUT_MODE_SWITCHED',
    `Switched platform payout mode from ${prevMode.toUpperCase()} to ${mode.toUpperCase()}`
  );

  res.json({ success: true, mode });
});

// Manual Payout Execution (Admin Mark As Paid with reference note)
app.post('/api/admin/payouts/manual-pay', async (req: Request, res: Response) => {
  const { userId, amount, adminName, referenceNote } = req.body;
  if (!userId || !amount || !referenceNote) {
    return res.status(400).json({ message: 'User, amount, and reference note are required' });
  }

  const payout = {
    id: `po-${Date.now()}`,
    user_id: userId,
    amount: Number(amount),
    mode: 'manual',
    status: 'successful',
    flutterwave_transfer_id: `MANUAL_REF_${Date.now()}`,
    processed_at: new Date().toISOString(),
    processed_by: adminName || 'Admin Ops',
    notes: referenceNote,
  };

  store.payouts.unshift(payout);

  // Advance investor next payment date by 30 days
  const investment = store.investments.get(userId);
  let updatedNextPaymentDate: string | null = null;
  if (investment) {
    const currentNext = investment.next_payment_date ? new Date(investment.next_payment_date) : new Date();
    currentNext.setDate(currentNext.getDate() + 30);
    updatedNextPaymentDate = currentNext.toISOString().split('T')[0];
    investment.next_payment_date = updatedNextPaymentDate;
    store.investments.set(userId, investment);
  }

  if (isLiveSupabase && supabaseAdmin && isValidUUID(userId)) {
    try {
      await supabaseAdmin.from('payouts').insert({
        user_id: userId,
        amount: Number(amount),
        mode: 'manual',
        status: 'successful',
        flutterwave_transfer_id: payout.flutterwave_transfer_id,
        processed_at: payout.processed_at,
        notes: referenceNote,
      });

      if (updatedNextPaymentDate) {
        await supabaseAdmin.from('investments').update({
          next_payment_date: updatedNextPaymentDate,
        }).eq('user_id', userId);
      }
    } catch (err) {
      console.error('Failed to record manual payout in Supabase:', err);
    }
  }

  const profile = store.profiles.get(userId);
  await logActivity(
    adminName || 'Admin',
    'MANUAL_PAYOUT_DISBURSED',
    `Disbursed manual payout of ₦${Number(amount).toLocaleString()} to ${profile?.name || userId}. Note: ${referenceNote}`,
    Number(amount)
  );

  res.json(payout);
});

// Automated Daily Cron / Edge Function Payout Runner
app.post('/api/payouts/run-cron', async (req: Request, res: Response) => {
  const { triggeredBy } = req.body;
  const todayStr = new Date().toISOString().split('T')[0];
  const logs: string[] = [];
  const currentMode = store.platform_settings.payout_mode;

  logs.push(`[${new Date().toISOString()}] Initiating payout cycle. Mode: ${currentMode.toUpperCase()}`);

  const activeInvestments = Array.from(store.investments.values()).filter(
    (inv) => inv.status === 'active' && inv.next_payment_date && inv.next_payment_date <= todayStr
  );

  let eligibleCount = 0;
  let successfulTransfers = 0;
  let failedTransfers = 0;
  let queuedForManual = 0;

  for (const inv of activeInvestments) {
    const profile = store.profiles.get(inv.user_id);
    const investorName = profile?.name || profile?.email || inv.user_id;

    // Check contribution requirement: investor must have confirmed payment
    const userPayments = store.payments.filter((p) => p.user_id === inv.user_id && p.status === 'successful');
    if (userPayments.length === 0) {
      logs.push(`Skipping ${investorName}: No verified contribution found in current cycle.`);
      logActivity('Payout Automation', 'PAYOUT_SKIPPED', `Skipped ${investorName} — no confirmed contribution record`);
      continue;
    }

    eligibleCount++;
    const payoutAmount = Math.round(Number(inv.amount) * 0.15) || 50000;

    if (currentMode === 'manual') {
      queuedForManual++;
      logs.push(`Queued ${investorName} for manual admin disbursement (₦${payoutAmount.toLocaleString()}).`);
      continue;
    }

    // Automatic mode
    const bankDetails = store.bank_details.get(inv.user_id);
    if (!bankDetails || !bankDetails.account_number || !bankDetails.bank_code) {
      failedTransfers++;
      logs.push(`[FAILED] ${investorName}: No bank account on file. Skipping transfer.`);
      logActivity('Payout Automation', 'PAYOUT_FAILED', `No bank account on file for ${investorName}`);
      continue;
    }

    let transferSuccessful = false;
    let transferId = `flw_trf_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;

    if (isFlutterwaveConfigured()) {
      try {
        const trfRef = `APEX_TRF_${Date.now()}_${inv.user_id.slice(-4)}`;
        const trfData = await createDirectTransfer({
          amount: payoutAmount,
          reference: trfRef,
          narration: `Apex Capital Monthly Yield — ${investorName}`,
          accountNumber: bankDetails.account_number,
          bankCode: bankDetails.bank_code,
        });
        if (trfData?.data?.id) {
          transferSuccessful = true;
          transferId = trfData.data.id;
        } else {
          logs.push(`Flutterwave transfer rejected: ${trfData?.message || 'Unknown error'}`);
        }
      } catch (err: any) {
        logs.push(`Transfers API network error: ${err.message}`);
      }
    } else if (isSandboxMode()) {
      transferSuccessful = true;
    }

    if (transferSuccessful) {
      successfulTransfers++;
      const payout = {
        id: `po-${Date.now()}-${Math.random().toString(36).substring(2, 5)}`,
        user_id: inv.user_id,
        amount: payoutAmount,
        mode: 'automatic',
        status: 'successful',
        flutterwave_transfer_id: String(transferId),
        processed_at: new Date().toISOString(),
        processed_by: 'Automated Supabase Cron Engine',
        notes: `Automated Flutterwave transfer to ${bankDetails.bank_name} (${bankDetails.account_number.slice(-4)})`,
      };
      store.payouts.unshift(payout);

      // Advance next_payment_date by 30 days ONLY on success
      const currentNext = new Date(inv.next_payment_date);
      currentNext.setDate(currentNext.getDate() + 30);
      inv.next_payment_date = currentNext.toISOString().split('T')[0];
      store.investments.set(inv.user_id, inv);

      logActivity(
        'Payout Automation',
        'AUTOMATIC_PAYOUT_SUCCESS',
        `Disbursed ₦${payoutAmount.toLocaleString()} to ${investorName} (${bankDetails.bank_name}) via Flutterwave Transfer #${transferId}`,
        payoutAmount
      );
      logs.push(`[SUCCESS] Transferred ₦${payoutAmount.toLocaleString()} to ${investorName}. Next payout: ${inv.next_payment_date}`);
    } else {
      failedTransfers++;
      const payout = {
        id: `po-${Date.now()}-${Math.random().toString(36).substring(2, 5)}`,
        user_id: inv.user_id,
        amount: payoutAmount,
        mode: 'automatic',
        status: 'failed',
        flutterwave_transfer_id: null,
        processed_at: new Date().toISOString(),
        processed_by: 'Automated Supabase Cron Engine',
        notes: 'Flutterwave Transfers API declined the transaction. Flagged for admin resolution.',
      };
      store.payouts.unshift(payout);
      logActivity(
        'Payout Automation',
        'AUTOMATIC_PAYOUT_FAILED',
        `Failed automated transfer of ₦${payoutAmount.toLocaleString()} to ${investorName}. Flagged for manual action.`,
        payoutAmount
      );
      logs.push(`[FAILED] Automatic payout failed for ${investorName}.`);
    }
  }

  const batchRecord = {
    id: `batch-${Date.now()}`,
    timestamp: new Date().toISOString(),
    total: eligibleCount,
    success: successfulTransfers,
    failed: failedTransfers,
  };
  store.payout_batches.unshift(batchRecord);
  if (store.payout_batches.length > 30) store.payout_batches.pop();

  logActivity(
    triggeredBy || 'Scheduled Cron',
    'PAYOUT_BATCH_COMPLETED',
    `Payout cycle finished. Eligible: ${eligibleCount}, Success: ${successfulTransfers}, Failed: ${failedTransfers}, Queued Manual: ${queuedForManual}`
  );

  res.json({
    runTimestamp: new Date().toISOString(),
    payoutMode: currentMode,
    totalChecked: activeInvestments.length,
    eligibleCount,
    successfulTransfers,
    failedTransfers,
    queuedForManual,
    logs,
  });
});

// OPay Receipts Review tab
app.get('/api/admin/opay-receipts', (req: Request, res: Response) => {
  const enriched = store.opay_receipts.map((r) => {
    let prof = store.profiles.get(r.user_id);
    if (!prof && r.user_email) {
      for (const [_, p] of store.profiles.entries()) {
        if (p.email && p.email.toLowerCase() === r.user_email.toLowerCase()) {
          prof = p;
          break;
        }
      }
    }
    return {
      ...r,
      target_phase: r.target_phase || 'Phase 1: Seed Accumulation',
      investor_name: prof?.name || r.user_email || 'Investor',
      investor_email: prof?.email || r.user_email || '—',
    };
  });
  res.json(enriched);
});

app.post('/api/admin/opay-receipts/review', async (req: Request, res: Response) => {
  const { receiptId, decision, adminName, adminNotes } = req.body;
  if (!receiptId || !decision) {
    return res.status(400).json({ message: 'Receipt ID and review decision required' });
  }

  const receipt = store.opay_receipts.find((r) => r.id === receiptId);
  if (!receipt) {
    return res.status(404).json({ message: 'Receipt record not found' });
  }

  if (decision === 'rejected' && !adminNotes) {
    return res.status(400).json({ message: 'A rejection note explaining the reason is required.' });
  }

  receipt.status = decision;
  receipt.reviewed_by = adminName || 'Admin';
  receipt.admin_notes = adminNotes || null;
  receipt.reviewed_at = new Date().toISOString();

  // Find profile by ID or by email
  let profile = store.profiles.get(receipt.user_id);
  if (!profile && receipt.user_email) {
    for (const [_, p] of store.profiles.entries()) {
      if (p.email && p.email.toLowerCase() === receipt.user_email.toLowerCase()) {
        profile = p;
        break;
      }
    }
  }
  if (!profile) {
    for (const [_, p] of store.profiles.entries()) {
      if (p.id === receipt.user_id) {
        profile = p;
        break;
      }
    }
  }

  const targetPhase = receipt.target_phase || 'Phase 1: Seed Accumulation';
  const investorName = profile?.name || receipt.user_email || receipt.user_id;

  if (decision === 'approved') {
    const verifiedAmount = Number(receipt.amount);

    // 1. Record verified payment
    const payment = {
      id: `pay-${Date.now()}`,
      user_id: receipt.user_id,
      user_email: receipt.user_email || profile?.email || '',
      amount: verifiedAmount,
      method: 'opay_transfer',
      flutterwave_tx_ref: `OPAY_MANUAL_${receipt.id}`,
      status: 'successful',
      notes: `Verified OPay Transfer (${targetPhase}) by ${adminName || 'Admin'}`,
      created_at: new Date().toISOString(),
    };
    store.payments.unshift(payment);

    // 2. Update or create investment
    let investment = store.investments.get(receipt.user_id);
    if (!investment && profile?.id) {
      investment = store.investments.get(profile.id);
    }
    const now = new Date();
    const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, now.getDate()).toISOString().split('T')[0];

    if (investment) {
      investment.amount = Number(investment.amount) + verifiedAmount;
      investment.phase = targetPhase;
      investment.status = 'active';
      investment.next_payment_date = nextMonth;
      investment.cycle_count = (investment.cycle_count || 0) + 1;
    } else {
      investment = {
        id: `inv-${Date.now()}`,
        user_id: receipt.user_id,
        amount: verifiedAmount,
        phase: targetPhase,
        type: 'opay',
        status: 'active',
        start_date: new Date().toISOString(),
        next_payment_date: nextMonth,
        cycle_count: 1,
        created_at: new Date().toISOString(),
      };
    }
    store.investments.set(receipt.user_id, investment);
    if (profile?.id && profile.id !== receipt.user_id) {
      store.investments.set(profile.id, investment);
    }

    // 3. Update profile
    if (!profile) {
      profile = {
        id: receipt.user_id,
        name: investorName,
        email: receipt.user_email || '',
        phone: '',
        total_invested: verifiedAmount,
        current_phase: targetPhase,
        payment_plan_id: null,
        created_at: new Date().toISOString(),
      };
      store.profiles.set(receipt.user_id, profile);
    } else {
      profile.total_invested = Number(profile.total_invested || 0) + verifiedAmount;
      profile.current_phase = targetPhase;
      store.profiles.set(profile.id, profile);
      if (receipt.user_id !== profile.id) {
        store.profiles.set(receipt.user_id, profile);
      }
    }

    // 4. If Supabase is connected, sync to database
    if (isLiveSupabase && supabaseAdmin) {
      try {
        const dbUserId = isValidUUID(receipt.user_id) ? receipt.user_id : (profile?.id && isValidUUID(profile.id) ? profile.id : null);
        if (dbUserId) {
          await supabaseAdmin.from('profiles').upsert({
            id: dbUserId,
            name: profile.name,
            email: profile.email,
            phone: profile.phone,
            total_invested: profile.total_invested,
            current_phase: targetPhase,
          });
          await supabaseAdmin.from('investments').upsert({
            id: investment.id,
            user_id: dbUserId,
            amount: investment.amount,
            phase: targetPhase,
            type: 'opay',
            status: 'active',
            start_date: investment.start_date,
            next_payment_date: investment.next_payment_date,
            cycle_count: investment.cycle_count || 1,
          });
          await supabaseAdmin.from('payments').insert({
            id: payment.id,
            user_id: dbUserId,
            amount: verifiedAmount,
            method: 'opay_transfer',
            flutterwave_tx_ref: payment.flutterwave_tx_ref,
            status: 'successful',
            notes: payment.notes,
            created_at: payment.created_at,
          });
          await supabaseAdmin.from('opay_receipts').update({
            status: 'approved',
            reviewed_by: adminName || 'Admin',
            reviewed_at: new Date().toISOString(),
          }).eq('id', receipt.id);
        }
      } catch (dbErr) {
        console.warn('Supabase sync error on OPay review:', dbErr);
      }
    }

    logActivity(
      adminName || 'Admin',
      'OPAY_RECEIPT_APPROVED',
      `Approved OPay receipt of ₦${verifiedAmount.toLocaleString()} for ${investorName} (${targetPhase})`,
      verifiedAmount
    );
  } else {
    logActivity(
      adminName || 'Admin',
      'OPAY_RECEIPT_REJECTED',
      `Rejected OPay receipt for ${investorName}. Reason: ${adminNotes}`
    );
  }

  res.json({ success: true, receipt });
});

app.get('/api/admin/notifications', async (req: Request, res: Response) => {
  if (isLiveSupabase && supabaseAdmin) {
    try {
      const { data } = await supabaseAdmin
        .from('notifications')
        .select('*')
        .order('sent_at', { ascending: false })
        .limit(200);
      if (data && data.length > 0) {
        const ids = new Set(data.map((n: any) => n.id));
        const localOnly = store.notifications.filter((n) => !ids.has(n.id));
        return res.json([...localOnly, ...data]);
      }
    } catch (err) {
      console.warn('Failed to load notifications from Supabase:', err);
    }
  }
  res.json(store.notifications);
});

app.post('/api/admin/notifications/send', async (req: Request, res: Response) => {
  const { title, body, audience, targetUserId, adminName, icon, imageUrl } = req.body;
  if (!title || !body) {
    return res.status(400).json({ message: 'Title and message body are required' });
  }

  const resolvedAudience = audience || 'all';
  if (resolvedAudience === 'single' && !targetUserId) {
    return res.status(400).json({ message: 'Select an investor for single alerts.' });
  }

  // Cap base64 images (~5MB) to keep memory safe
  if (imageUrl && typeof imageUrl === 'string' && imageUrl.length > 6_000_000) {
    return res.status(400).json({ message: 'Image is too large. Use a smaller picture.' });
  }

  const notification = {
    id: crypto.randomUUID(),
    title: String(title).trim(),
    body: String(body).trim(),
    audience: resolvedAudience,
    target_user_id: resolvedAudience === 'single' ? targetUserId : null,
    icon: icon || 'bell',
    image_url: imageUrl || null,
    sent_at: new Date().toISOString(),
    delivery_status: 'delivered',
  };

  store.notifications.unshift(notification);

  if (isLiveSupabase && supabaseAdmin) {
    try {
      await supabaseAdmin.from('notifications').insert({
        id: isValidUUID(notification.id) ? notification.id : undefined,
        title: notification.title,
        body: notification.body,
        audience: notification.audience,
        target_user_id: notification.target_user_id && isValidUUID(notification.target_user_id)
          ? notification.target_user_id
          : null,
        icon: notification.icon,
        image_url: notification.image_url,
        sent_at: notification.sent_at,
        delivery_status: notification.delivery_status,
      });
    } catch (err) {
      console.warn('Supabase notification insert notice:', err);
    }
  }

  logActivity(
    adminName || 'Admin',
    'NOTIFICATION_DISPATCHED',
    `Sent alert "${notification.title}" to ${resolvedAudience === 'all' ? 'all investors' : `user ${targetUserId}`}`
  );

  res.json(notification);
});

// ---------------- VITE MIDDLEWARE & STATIC SERVE ----------------

async function hydrateAdminAllowlist(): Promise<void> {
  if (!isLiveSupabase || !supabaseAdmin) return;
  try {
    const { data } = await supabaseAdmin.from('admin_allowlist').select('email');
    if (data) {
      for (const row of data) {
        if (row.email) {
          store.admin_allowlist.add(String(row.email).toLowerCase().trim());
        }
      }
    }
  } catch (err) {
    console.warn('Could not load admin allowlist from Supabase:', err);
  }
}

async function startServer() {
  await hydrateAdminAllowlist();

  // Local/dev fallback when Supabase allowlist is empty (matches supabase/schema.sql seed)
  if (store.admin_allowlist.size === 0) {
    store.admin_allowlist.add('cmyrachrist72@gmail.com');
  }

  app.use(productionErrorHandler);

  if (process.env.SIGMA_API_NO_LISTEN === '1') {
    return;
  }

  // API-only server — Next.js serves the frontend on :3000
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SigmaWealth API running at http://localhost:${PORT}`);
  });
}

if (process.env.SIGMA_API_NO_LISTEN !== '1') {
  startServer();
}

export { app, store, startServer };
