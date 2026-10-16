import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import { payoutAmount } from './lib/exactMoney.js';
import { safeProfileUpdates } from './lib/profileUpdates.js';
import { mountBachsRoutes } from './lib/bachsRoutes.js';
import { mountAuthorization, isApprovedAdmin } from './lib/authorization.js';
import { FUNDING_PLAN_AMOUNTS } from '../lib/sigma/fundingPlans.js';
import { normalizeCurrency } from './lib/money.js';
const PAYMENT_CURRENCY = 'ngn';
const MIN_DEPOSIT_NGN = FUNDING_PLAN_AMOUNTS[0];
import { applySecurityMiddleware, productionErrorHandler } from './lib/security.js';
import { sanitizeRequestBody } from './lib/sanitize.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || process.env.SIGMA_API_PORT || 4000);

applySecurityMiddleware(app);

// Preserve exact Bachs webhook bytes before JSON parsing and sanitization.

app.use(express.json({
  limit: '256kb',
  verify: (req: any, _res, buf) => {
    if (req.originalUrl?.startsWith('/api/bachs/webhook')) {
      req.rawBody = buf;
    }
  },
}));
app.use(express.urlencoded({ extended: false, limit: '64kb', parameterLimit:100 }));
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
  platform_settings: { payout_mode: 'automatic' | 'manual'; interest_rate: number; updated_by: string; updated_at: string };
  payout_batches: any[];
  current_session: any | null;
  referrals: any[];
  auto_debit_plans: Map<string, any>;
  support_conversations: Map<string, any>;
  support_messages: any[];
  support_typing: Map<string, { role: string; name: string; at: number }>;
}

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
    interest_rate: 0.15,
    updated_by: 'system',
    updated_at: new Date().toISOString(),
  },
  payout_batches: [],
  current_session: null,
  referrals: [],
  auto_debit_plans: new Map(),
  support_conversations: new Map(),
  support_messages: [],
  support_typing: new Map(),
};

mountAuthorization(app, supabaseAdmin, store.support_conversations);
mountBachsRoutes(app, supabaseAdmin, store);

function hasValidPayoutDestination(bank: any): boolean {
  return Boolean(bank?.bachs_account_id && bank?.payouts_enabled && bank?.bachs_destination_id);
}

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

function parsePayoutModeValue(raw: unknown): 'automatic' | 'manual' | null {
  if (!raw) return null;
  if (typeof raw === 'string') {
    const cleaned = raw.trim().toLowerCase();
    if (cleaned === 'automatic' || cleaned === 'manual') return cleaned;
    try {
      const parsed = JSON.parse(raw);
      return parsePayoutModeValue(parsed);
    } catch {
      return null;
    }
  }
  if (typeof raw === 'object' && raw !== null) {
    const mode = String((raw as any).mode || '').toLowerCase();
    if (mode === 'automatic' || mode === 'manual') return mode;
  }
  return null;
}

function getBankDetailsForUser(userId: string) {
  const direct = store.bank_details.get(userId);
  if (direct && hasValidPayoutDestination(direct)) return direct;
  const profile = store.profiles.get(userId);
  if (profile?.id && profile.id !== userId) {
    const byProfile = store.bank_details.get(profile.id);
    if (byProfile && hasValidPayoutDestination(byProfile)) return byProfile;
  }
  if (profile?.email) {
    const email = String(profile.email).toLowerCase();
    for (const [uid, p] of store.profiles.entries()) {
      if (p?.email && String(p.email).toLowerCase() === email) {
        const bank = store.bank_details.get(uid) || (p.id ? store.bank_details.get(p.id) : null);
        if (bank && hasValidPayoutDestination(bank)) return bank;
      }
    }
  }
  return direct || null;
}

function normalizeDateOnly(value: unknown): string | null {
  if (!value) return null;
  const raw = String(value).trim();
  if (!raw) return null;
  // Accept YYYY-MM-DD or full ISO
  const slice = raw.slice(0, 10);
  if (/^\d{4}-\d{2}-\d{2}$/.test(slice)) return slice;
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 10);
}

function isPayoutDue(nextPaymentDate: unknown, today = new Date()): boolean {
  const due = normalizeDateOnly(nextPaymentDate);
  if (!due) return false;
  return due <= today.toISOString().slice(0, 10);
}

/** Deduplicate Map values that may be stored under both auth id and profile id. */
function uniqueActiveInvestments(): any[] {
  const byUser = new Map<string, any>();
  for (const inv of store.investments.values()) {
    if (!inv || inv.status !== 'active') continue;
    const key = String(inv.user_id);
    const prev = byUser.get(key);
    if (!prev || Number(inv.amount || 0) >= Number(prev.amount || 0)) {
      byUser.set(key, inv);
    }
  }
  return Array.from(byUser.values());
}

function investorHasSuccessfulPayment(userId: string): boolean {
  const ids = new Set<string>([String(userId)]);
  const profile = store.profiles.get(userId);
  if (profile?.id) ids.add(String(profile.id));
  if (profile?.email) {
    const email = String(profile.email).toLowerCase();
    for (const [uid, p] of store.profiles.entries()) {
      if (p?.email && String(p.email).toLowerCase() === email) ids.add(String(uid));
    }
  }
  return store.payments.some(
    (p) => ids.has(String(p.user_id)) && String(p.status).toLowerCase() === 'successful'
  );
}

function notifyInvestor(userId: string, title: string, body: string, icon = 'alert') {
  const notification = {
    id: `notif-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    title,
    body,
    audience: 'single',
    target_user_id: userId,
    icon,
    image_url: null,
    sent_at: new Date().toISOString(),
    delivery_status: 'delivered',
  };
  store.notifications.unshift(notification);
  return notification;
}

/** Weekly payouts: 25% of deposit each week for 4 weeks; week 4 also includes interest. */
export { MIN_DEPOSIT_NGN };
const WEEKLY_SHARE = 0.25;
type PayoutWeek = 1 | 2 | 3 | 4;

function getInterestRate(): number {
  const rate = Number(store.platform_settings.interest_rate);
  return Number.isFinite(rate) && rate >= 0 && rate <= 1 ? rate : 0.15;
}

function normalizePayoutWeek(raw: unknown): PayoutWeek {
  const v = String(raw || '').toLowerCase();
  if (v === 'week2' || v === '2') return 2;
  if (v === 'week3' || v === '3') return 3;
  if (v === 'week4' || v === 'final' || v === '4') return 4;
  // legacy mid → treat as week 1
  return 1;
}

function ensureInvestmentPayoutSchedule(inv: any) {
  if (!inv) return inv;
  const week = normalizePayoutWeek(inv.payout_phase);
  inv.payout_phase = `week${week}`;
  if (!inv.cycle_start_date) {
    inv.cycle_start_date = inv.start_date || inv.created_at || new Date().toISOString();
  }
  return inv;
}

function computePayoutForInvestment(inv: any): {
  amount: number;
  currency: string;
  phase: `week${PayoutWeek}`;
  week: PayoutWeek;
  label: string;
  interestComponent: number;
  principalComponent: number;
} {
  ensureInvestmentPayoutSchedule(inv);
  const principal = Math.max(0, Number(inv.amount) || 0);
  const currency = normalizeCurrency(inv.currency || PAYMENT_CURRENCY);
  const week = normalizePayoutWeek(inv.payout_phase);
  const interestRate = getInterestRate();
  const principalComponent = principal>0 ? Number(payoutAmount(inv.amount,false,'0')) : 0;

  if (week < 4) {
    return {
      amount: principalComponent,
      currency,
      phase: `week${week}`,
      week,
      label: `Week ${week} · 25% payout`,
      interestComponent: 0,
      principalComponent,
    };
  }

  const finalAmount=principal>0 ? Number(payoutAmount(inv.amount,true,interestRate)) : 0;
  const interest = finalAmount-principalComponent;
  return {
    amount: finalAmount,
    currency,
    phase: 'week4',
    week: 4,
    label: `Week 4 · 25% + ${(interestRate * 100).toFixed(0)}% interest`,
    interestComponent: interest,
    principalComponent,
  };
}

function addDaysIso(base: Date | string, days: number): string {
  const d = new Date(base);
  d.setDate(d.getDate() + days);
  return d.toISOString().split('T')[0];
}

// ---------------- AUTH FALLBACK API ----------------

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
        supabaseAdmin.from('payouts').select('*').eq('user_id', userId).order('processed_at', { ascending: false }),
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

      const mergedPayments = [...(payData || []), ...localPayments.filter(lp => !(payData || []).some((p: any) => p.id === lp.id || (p.provider_reference && p.provider_reference === lp.provider_reference)))];
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
          finalInvestment = {
            id: `inv-${Date.now()}`,
            user_id: userId,
            amount: totalInvested,
            phase: 'Phase 1: Seed Accumulation',
            type: 'opay',
            status: 'active',
            start_date: now.toISOString(),
            cycle_start_date: now.toISOString(),
            payout_phase: 'week1',
            next_payment_date: addDaysIso(now, 7),
            cycle_count: 1,
            created_at: now.toISOString(),
          };
        } else {
          finalInvestment.amount = totalInvested;
          finalInvestment.status = 'active';
          ensureInvestmentPayoutSchedule(finalInvestment);
        }
      }

      return res.json({
        profile: finalProfile || null,
        bankDetails: bankData || store.bank_details.get(userId) || (finalProfile?.id ? store.bank_details.get(finalProfile.id) : null) || null,
        cardDetails: store.card_details.get(userId) || (finalProfile?.id ? store.card_details.get(finalProfile.id) : null) || cardData || null,
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
      investment = {
        id: `inv-${Date.now()}`,
        user_id: profileId,
        amount: calculatedTotalInvested,
        phase: phaseToUse,
        type: latestApprovedReceipt ? 'opay' : 'auto',
        status: 'active',
        start_date: now.toISOString(),
        cycle_start_date: now.toISOString(),
        payout_phase: 'week1',
        next_payment_date: addDaysIso(now, 7),
        cycle_count: 1,
        created_at: now.toISOString(),
      };
      store.investments.set(userId, investment);
      store.investments.set(profileId, investment);
    } else {
      investment.amount = calculatedTotalInvested;
      investment.phase = phaseToUse;
      investment.status = 'active';
      ensureInvestmentPayoutSchedule(investment);
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

// ---------------- ADMIN API (SECURED / ROLE & ALLOWLIST CHECKED) ----------------

app.get('/api/admin/check-role/:id', async (req: Request, res: Response) => {
  const approved = supabaseAdmin && await isApprovedAdmin(supabaseAdmin, res.locals.authUser);

  res.json({
    isAdmin: Boolean(approved),
    role: approved ? 'admin' : 'investor'
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
      if (settingsData?.value) {
        const parsed = parsePayoutModeValue(settingsData.value);
        if (parsed) {
          store.platform_settings.payout_mode = parsed;
        }
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
  const activeInvestments = uniqueActiveInvestments().filter((inv) => {
    ensureInvestmentPayoutSchedule(inv);
    return Boolean(normalizeDateOnly(inv.next_payment_date));
  });
  const payoutsDueTodayCount = activeInvestments.filter((inv) => isPayoutDue(inv.next_payment_date)).length;
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
      const bankDetails = getBankDetailsForUser(inv.user_id);
      const due = computePayoutForInvestment(inv);
      return {
        userId: inv.user_id,
        investorName: profile?.name || profile?.email || 'Investor',
        investorEmail: profile?.email || '—',
        amount: due.amount,
        payoutPhase: due.phase,
        payoutLabel: due.label,
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
  const updates=safeProfileUpdates(req.body.updates);
  if(!updates)return res.status(400).json({message:'Only name and phone can be edited. Financial balances require verified ledger transactions.'});
  const adminName=res.locals.authUser?.email || 'Admin';

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
      reference: p.provider_reference || p.reference || p.id,
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

      if (settingsData?.value) {
        const parsed = parsePayoutModeValue(settingsData.value);
        if (parsed) {
          store.platform_settings.payout_mode = parsed;
        }
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

  uniqueActiveInvestments().forEach((inv) => {
    ensureInvestmentPayoutSchedule(inv);
    if (!inv.next_payment_date) {
      inv.next_payment_date = addDaysIso(inv.cycle_start_date || new Date(), 7);
      store.investments.set(inv.user_id, inv);
    }

    const profile = store.profiles.get(inv.user_id);
    const bankDetails = getBankDetailsForUser(inv.user_id);
    const due = computePayoutForInvestment(inv);
    const hasPaidIn = investorHasSuccessfulPayment(inv.user_id);

    const payoutItem = {
      userId: inv.user_id,
      investorName: profile?.name || profile?.email || 'Investor',
      investorEmail: profile?.email || '—',
      amount: due.amount,
      suggestedAmount: due.amount,
      amountInvested: Number(inv.amount || profile?.total_invested || 0),
      payoutPhase: due.phase,
      payoutLabel: due.label,
      interestComponent: due.interestComponent,
      principalComponent: due.principalComponent,
      nextPaymentDate: normalizeDateOnly(inv.next_payment_date) || todayStr,
      hasBeneficiary: hasValidPayoutDestination(bankDetails),
      bankName: bankDetails?.bank_name || bankDetails?.iban || null,
      bankCountry: bankDetails?.country || 'NG',
      bankAccountLast4: String(bankDetails?.account_number || bankDetails?.iban || '').slice(-4) || null,
      bankDetails,
      hasPaidIn,
    };

    if (isPayoutDue(inv.next_payment_date)) {
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

// ---------------- LIVE SUPPORT CHAT API ----------------

const SUPPORT_STORE_PATH = path.join(process.cwd(), 'data', 'support-store.json');

function persistSupportToDisk() {
  try {
    const dir = path.dirname(SUPPORT_STORE_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const payload = {
      conversations: Array.from(store.support_conversations.values()),
      messages: store.support_messages,
      saved_at: new Date().toISOString(),
    };
    fs.writeFileSync(SUPPORT_STORE_PATH, JSON.stringify(payload), 'utf8');
  } catch (err) {
    console.warn('Failed to persist support chat to disk:', err);
  }
}

function loadSupportFromDisk() {
  try {
    if (!fs.existsSync(SUPPORT_STORE_PATH)) return;
    const raw = fs.readFileSync(SUPPORT_STORE_PATH, 'utf8');
    const data = JSON.parse(raw);
    if (Array.isArray(data.conversations)) {
      for (const c of data.conversations) {
        if (c?.id) store.support_conversations.set(c.id, c);
      }
    }
    if (Array.isArray(data.messages)) {
      store.support_messages = data.messages;
    }
    console.log(
      `Restored support chat: ${store.support_conversations.size} conversations, ${store.support_messages.length} messages`
    );
  } catch (err) {
    console.warn('Failed to load support chat from disk:', err);
  }
}

async function hydrateSupportFromSupabase() {
  if (!isLiveSupabase || !supabaseAdmin) return;
  try {
    const { data: conversations, error: cErr } = await supabaseAdmin
      .from('support_conversations')
      .select('*')
      .order('updated_at', { ascending: false })
      .limit(500);
    if (cErr) {
      // Table may not exist yet — disk fallback still works
      console.warn('support_conversations hydrate skipped:', cErr.message);
      return;
    }
    const { data: messages, error: mErr } = await supabaseAdmin
      .from('support_messages')
      .select('*')
      .order('created_at', { ascending: true })
      .limit(5000);
    if (mErr) {
      console.warn('support_messages hydrate skipped:', mErr.message);
      return;
    }
    for (const c of conversations || []) {
      if (c?.id) store.support_conversations.set(c.id, c);
    }
    if (messages?.length) {
      const byId = new Map(store.support_messages.map((m) => [m.id, m]));
      for (const m of messages) {
        if (m?.id) byId.set(m.id, m);
      }
      store.support_messages = Array.from(byId.values());
    }
    persistSupportToDisk();
  } catch (err) {
    console.warn('Could not hydrate support chat from Supabase:', err);
  }
}

async function persistSupportConversation(conversation: any) {
  persistSupportToDisk();
  if (!isLiveSupabase || !supabaseAdmin || !conversation?.id) return;
  try {
    await supabaseAdmin.from('support_conversations').upsert(
      {
        id: conversation.id,
        guest_id: conversation.guest_id,
        user_id: conversation.user_id,
        visitor_name: conversation.visitor_name,
        visitor_email: conversation.visitor_email,
        status: conversation.status,
        unread_admin: conversation.unread_admin || 0,
        unread_user: conversation.unread_user || 0,
        last_message_at: conversation.last_message_at,
        last_message_preview: conversation.last_message_preview,
        created_at: conversation.created_at,
        updated_at: conversation.updated_at || new Date().toISOString(),
      },
      { onConflict: 'id' }
    );
  } catch (err) {
    console.warn('Failed to upsert support conversation:', err);
  }
}

async function persistSupportMessage(message: any) {
  persistSupportToDisk();
  if (!isLiveSupabase || !supabaseAdmin || !message?.id) return;
  try {
    await supabaseAdmin.from('support_messages').upsert(
      {
        id: message.id,
        conversation_id: message.conversation_id,
        sender: message.sender,
        sender_name: message.sender_name,
        content: message.content,
        status: message.status || 'delivered',
        created_at: message.created_at,
      },
      { onConflict: 'id' }
    );
  } catch (err) {
    console.warn('Failed to upsert support message:', err);
  }
}

function supportConversationMessages(conversationId: string) {
  return store.support_messages
    .filter((m) => m.conversation_id === conversationId)
    .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
}

function touchConversation(conversation: any, preview: string, from: 'user' | 'admin') {
  conversation.last_message_at = new Date().toISOString();
  conversation.last_message_preview = preview.slice(0, 140);
  conversation.updated_at = conversation.last_message_at;
  if (from === 'user') {
    conversation.status = 'pending';
    conversation.unread_admin = (conversation.unread_admin || 0) + 1;
  } else {
    conversation.status = 'active';
    conversation.unread_user = (conversation.unread_user || 0) + 1;
  }
  store.support_conversations.set(conversation.id, conversation);
  void persistSupportConversation(conversation);
}

app.post('/api/support/conversations', (req: Request, res: Response) => {
  const { guestId, userId, name, email, conversationId } = req.body || {};
  const clientKey = String(userId || guestId || '').trim();
  const requestedId = conversationId ? String(conversationId).trim() : '';

  let conversation =
    (requestedId && store.support_conversations.get(requestedId)) ||
    (clientKey
      ? Array.from(store.support_conversations.values()).find(
          (c) => c.guest_id === clientKey || c.user_id === clientKey
        )
      : null);

  if (!conversation && !clientKey) {
    return res.status(400).json({ message: 'guestId or userId is required' });
  }

  if (!conversation) {
    conversation = {
      id: `sup-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`,
      guest_id: userId ? null : clientKey,
      user_id: userId || null,
      visitor_name: name || 'Guest Investor',
      visitor_email: email || null,
      status: 'open',
      unread_admin: 0,
      unread_user: 0,
      last_message_at: new Date().toISOString(),
      last_message_preview: 'Conversation started',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    store.support_conversations.set(conversation.id, conversation);

    const welcome = {
      id: `msg-${Date.now()}-welcome`,
      conversation_id: conversation.id,
      sender: 'admin',
      sender_name: 'Sigma Wealth Support',
      content:
        'Hello! Welcome to SigmawealthSolution support. How can we assist you with your investments, payouts, or account today?',
      status: 'delivered',
      created_at: new Date().toISOString(),
    };
    store.support_messages.push(welcome);
    void persistSupportConversation(conversation);
    void persistSupportMessage(welcome);
  } else if (name || email) {
    if (name) conversation.visitor_name = name;
    if (email) conversation.visitor_email = email;
    store.support_conversations.set(conversation.id, conversation);
    void persistSupportConversation(conversation);
  }

  res.json({
    conversation,
    messages: supportConversationMessages(conversation.id),
  });
});

app.get('/api/support/conversations/:id', (req: Request, res: Response) => {
  const conversation = store.support_conversations.get(String(req.params.id));
  if (!conversation) return res.status(404).json({ message: 'Conversation not found' });

  const since = req.query.since ? String(req.query.since) : null;
  let messages = supportConversationMessages(conversation.id);
  if (since) {
    const sinceTs = new Date(since).getTime();
    messages = messages.filter((m) => new Date(m.created_at).getTime() > sinceTs);
  }

  const typing = store.support_typing.get(conversation.id);
  const typingActive = typing && Date.now() - typing.at < 4000 ? typing : null;

  if (req.query.as === 'admin') {
    conversation.unread_admin = 0;
  } else if (req.query.as === 'user') {
    conversation.unread_user = 0;
  }
  store.support_conversations.set(conversation.id, conversation);
  void persistSupportConversation(conversation);

  res.json({
    conversation,
    messages: since ? messages : supportConversationMessages(conversation.id),
    typing: typingActive,
  });
});

app.get('/api/support/admin/conversations', (_req: Request, res: Response) => {
  const list = Array.from(store.support_conversations.values()).sort(
    (a, b) => new Date(b.last_message_at || 0).getTime() - new Date(a.last_message_at || 0).getTime()
  );
  res.json({
    conversations: list,
    pendingCount: list.filter((c) => c.status === 'pending' || (c.unread_admin || 0) > 0).length,
  });
});

app.post('/api/support/conversations/:id/messages', (req: Request, res: Response) => {
  const conversation = store.support_conversations.get(String(req.params.id));
  if (!conversation) return res.status(404).json({ message: 'Conversation not found' });

  const { content, sender, senderName } = req.body || {};
  const text = String(content || '').trim().slice(0, 4000);
  if (!text) return res.status(400).json({ message: 'Message content is required' });

  const role: 'user' | 'admin' = sender === 'admin' ? 'admin' : 'user';
  const safeName = String(
    role === 'admin'
      ? senderName || 'Sigma Wealth Support'
      : senderName || conversation.visitor_name || 'Guest'
  )
    .replace(/[<>]/g, '')
    .slice(0, 80);

  const message = {
    id: `msg-${Date.now()}-${crypto.randomUUID().slice(0, 6)}`,
    conversation_id: conversation.id,
    sender: role,
    sender_name: safeName,
    content: text,
    status: role === 'user' ? 'pending' : 'delivered',
    created_at: new Date().toISOString(),
  };

  store.support_messages.push(message);
  touchConversation(conversation, text, role);
  store.support_typing.delete(conversation.id);

  if (role === 'admin') {
    for (const m of store.support_messages) {
      if (m.conversation_id === conversation.id && m.sender === 'user' && m.status === 'pending') {
        m.status = 'delivered';
      }
    }
    persistSupportToDisk();
  }

  void persistSupportMessage(message);

  res.json({ message, conversation });
});

app.post('/api/support/conversations/:id/typing', (req: Request, res: Response) => {
  const conversation = store.support_conversations.get(String(req.params.id));
  if (!conversation) return res.status(404).json({ message: 'Conversation not found' });

  const role = req.body?.role === 'admin' ? 'admin' : 'user';
  const name =
    req.body?.name ||
    (role === 'admin' ? 'Sigma Wealth Support' : conversation.visitor_name || 'Guest');

  if (req.body?.typing === false) {
    store.support_typing.delete(conversation.id);
  } else {
    store.support_typing.set(conversation.id, { role, name, at: Date.now() });
  }

  res.json({ success: true });
});

app.patch('/api/support/conversations/:id', (req: Request, res: Response) => {
  const conversation = store.support_conversations.get(String(req.params.id));
  if (!conversation) return res.status(404).json({ message: 'Conversation not found' });

  if (req.body?.status) {
    conversation.status = String(req.body.status);
  }
  conversation.updated_at = new Date().toISOString();
  store.support_conversations.set(conversation.id, conversation);
  void persistSupportConversation(conversation);
  res.json({ conversation });
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
  loadSupportFromDisk();
  await hydrateAdminAllowlist();
  await hydrateSupportFromSupabase();

  // Local/dev fallback when Supabase allowlist is empty (matches supabase/schema.sql seed)
  if (store.admin_allowlist.size === 0) {
    store.admin_allowlist.add('cmyrachrist72@gmail.com');
  }

  app.use(productionErrorHandler);

  if (process.env.SIGMA_API_NO_LISTEN === '1') {
    return;
  }

  // API-only server — Next.js serves the frontend on :3000
  const server=app.listen(PORT, '0.0.0.0', () => {
    console.log('SigmaWealth API listening on port '+PORT);
  });
  server.requestTimeout=30_000;
  server.headersTimeout=15_000;
  server.keepAliveTimeout=5_000;
  process.once('SIGTERM',()=>{
    server.close(()=>process.exit(0));
    setTimeout(()=>{server.closeAllConnections();process.exit(0);},25_000).unref();
  });
}

if (process.env.SIGMA_API_NO_LISTEN !== '1') {
  startServer();
}

export { app, store, startServer };
