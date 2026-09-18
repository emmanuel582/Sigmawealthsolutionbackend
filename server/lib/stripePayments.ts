import Stripe from 'stripe';
import {
  formatMoney,
  currencyForCountry,
  isSupportedPaymentCurrency,
  normalizeCurrency,
} from './money.js';

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';

/** Platform default — frontend sticks to Naira (₦100,000 min). Override via STRIPE_CURRENCY. */
export const STRIPE_CURRENCY = normalizeCurrency(process.env.STRIPE_CURRENCY || 'ngn');

/**
 * Minimum top-up / monthly auto-debit floor ≈ ₦100,000 (~USD 72).
 * Override any rate via STRIPE_FX_<CURRENCY>=rate_to_ngn (how many NGN per 1 unit).
 */
export const MIN_DEPOSIT_NGN = 100_000;
export const MIN_DEPOSIT_USD = Number(process.env.MIN_DEPOSIT_USD || 72);

/** Tiny auto-debit setup fee when investor already funded (avoid double 100k). NGN major units. */
export const AUTO_DEBIT_SETUP_FEE_NGN = Number(process.env.AUTO_DEBIT_SETUP_FEE_NGN || 1);

const DEFAULT_FX_TO_NGN: Record<string, number> = {
  ngn: 1,
  usd: MIN_DEPOSIT_NGN / MIN_DEPOSIT_USD, // ~1388.89
  eur: Number(process.env.STRIPE_FX_EUR || 1500),
  gbp: Number(process.env.STRIPE_FX_GBP || 1750),
  cad: Number(process.env.STRIPE_FX_CAD || 1000),
  aud: Number(process.env.STRIPE_FX_AUD || 900),
  zar: Number(process.env.STRIPE_FX_ZAR || 75),
  ghs: Number(process.env.STRIPE_FX_GHS || 90),
  kes: Number(process.env.STRIPE_FX_KES || 10),
};

let stripeSingleton: Stripe | null = null;

export function isStripeConfigured(): boolean {
  return Boolean(STRIPE_SECRET_KEY && STRIPE_SECRET_KEY.startsWith('sk_'));
}

export function isStripeLiveMode(): boolean {
  return Boolean(STRIPE_SECRET_KEY.startsWith('sk_live_'));
}

export function isStripeTestMode(): boolean {
  return STRIPE_SECRET_KEY.includes('_test_') || process.env.STRIPE_MODE === 'test';
}

/** Simulation is OFF unless explicitly allowed (never auto-on when keys missing). */
export function isStripeSimulateMode(): boolean {
  return process.env.STRIPE_ALLOW_SIMULATE === '1' && process.env.NODE_ENV !== 'production';
}

export function getStripe(): Stripe {
  if (!isStripeConfigured()) {
    throw new Error('Stripe is not configured. Set STRIPE_SECRET_KEY (sk_live_… for production).');
  }
  if (!stripeSingleton) {
    stripeSingleton = new Stripe(STRIPE_SECRET_KEY, {
      apiVersion: '2025-02-24.acacia' as Stripe.LatestApiVersion,
      typescript: true,
    });
  }
  return stripeSingleton;
}

export function getStripePublishableKey(): string {
  return process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY || process.env.STRIPE_PUBLISHABLE_KEY || '';
}

export function getFrontendBaseUrl(): string {
  return (
    process.env.FRONTEND_URL ||
    process.env.APP_URL ||
    process.env.NEXT_PUBLIC_APP_URL ||
    'https://sigmawealthsolution.vercel.app'
  ).replace(/\/$/, '');
}

export function getApiBaseUrl(): string {
  return (
    process.env.PUBLIC_API_URL ||
    process.env.SIGMA_API_PUBLIC_URL ||
    process.env.RENDER_EXTERNAL_URL ||
    'https://sigmawealthsolutionbackend.onrender.com'
  ).replace(/\/$/, '');
}

/** Stripe Dashboard → Developers → Webhooks → endpoint URL (served on Vercel) */
export function getStripeWebhookUrl(): string {
  const base = (
    process.env.STRIPE_WEBHOOK_BASE_URL ||
    process.env.FRONTEND_URL ||
    process.env.APP_URL ||
    process.env.NEXT_PUBLIC_APP_URL ||
    'https://sigmawealthsolution.vercel.app'
  ).replace(/\/$/, '');
  return `${base}/api/stripe/webhook`;
}

export function getStripeSuccessUrl(reference: string): string {
  return `${getFrontendBaseUrl()}/dashboard?stripe_return=1&reference=${encodeURIComponent(reference)}&session_id={CHECKOUT_SESSION_ID}`;
}

export function getStripeCancelUrl(): string {
  return `${getFrontendBaseUrl()}/dashboard?stripe_cancel=1`;
}

export function fxToNgn(currency: string): number {
  const c = (currency || 'ngn').toLowerCase();
  const envKey = `STRIPE_FX_${c.toUpperCase()}`;
  if (process.env[envKey]) return Number(process.env[envKey]);
  return DEFAULT_FX_TO_NGN[c] || DEFAULT_FX_TO_NGN.usd;
}

export function minDepositMajor(currency: string): number {
  const c = (currency || STRIPE_CURRENCY).toLowerCase();
  if (c === 'ngn') return MIN_DEPOSIT_NGN;
  if (c === 'usd') return MIN_DEPOSIT_USD;
  const rate = fxToNgn(c);
  return Math.max(1, Math.ceil(MIN_DEPOSIT_NGN / rate));
}

export function assertMinDepositMajor(amountMajor: number, currency: string): string | null {
  const c = normalizeCurrency(currency);
  if (!isSupportedPaymentCurrency(c)) {
    return `Currency ${c.toUpperCase()} is not supported. Use: USD, EUR, GBP, NGN, CAD, AUD, and others.`;
  }
  const min = minDepositMajor(c);
  if (!Number.isFinite(amountMajor) || amountMajor < min) {
    return `Minimum deposit is ${formatMoney(min, c)} (≈ ${formatMoney(MIN_DEPOSIT_NGN, 'ngn')} / ${formatMoney(MIN_DEPOSIT_USD, 'usd')}).`;
  }
  return null;
}

/** Zero-decimal currencies (Stripe) — amount already in major units as smallest */
const ZERO_DECIMAL = new Set(['jpy', 'krw', 'vnd', 'clp', 'ugx', 'xaf', 'xof']);

export function toMinorUnits(amountMajor: number, currency = STRIPE_CURRENCY): number {
  const c = currency.toLowerCase();
  if (ZERO_DECIMAL.has(c)) return Math.round(Number(amountMajor));
  return Math.round(Number(amountMajor) * 100);
}

export function fromMinorUnits(amountMinor: number, currency = STRIPE_CURRENCY): number {
  const c = currency.toLowerCase();
  if (ZERO_DECIMAL.has(c)) return Math.round(Number(amountMinor));
  return Math.round(Number(amountMinor)) / 100;
}

export function setupFeeMajor(currency: string): number {
  const c = (currency || STRIPE_CURRENCY).toLowerCase();
  if (c === 'ngn') return Math.max(1, AUTO_DEBIT_SETUP_FEE_NGN);
  // ~1 NGN equivalent in other currencies (at least Stripe-friendly floor of 1 minor unit major)
  const ngnFee = Math.max(1, AUTO_DEBIT_SETUP_FEE_NGN);
  const major = ngnFee / fxToNgn(c);
  // Stripe often needs at least 0.5 USD equivalent; keep tiny but chargeable — use 1 minor unit as 0.01
  if (c === 'usd' || c === 'eur' || c === 'gbp') return Math.max(0.5, Number(major.toFixed(2)));
  return Math.max(1 / 100, Number(major.toFixed(2)));
}

export async function ensureStripeCustomer(params: {
  customerId?: string | null;
  email: string;
  name?: string;
  metadata?: Record<string, string>;
}): Promise<string> {
  const stripe = getStripe();
  if (params.customerId) {
    try {
      const existing = await stripe.customers.retrieve(params.customerId);
      if (!('deleted' in existing) || !existing.deleted) return existing.id;
    } catch {
      /* create new */
    }
  }
  const customer = await stripe.customers.create({
    email: params.email,
    name: params.name || undefined,
    metadata: params.metadata || {},
  });
  return customer.id;
}

export async function createFundPaymentIntent(params: {
  amountMajor: number;
  currency?: string;
  customerId: string;
  email: string;
  metadata: Record<string, string>;
  saveCard?: boolean;
}): Promise<{ clientSecret: string; paymentIntentId: string }> {
  const currency = (params.currency || STRIPE_CURRENCY).toLowerCase();
  const stripe = getStripe();
  const intent = await stripe.paymentIntents.create({
    amount: toMinorUnits(params.amountMajor, currency),
    currency,
    customer: params.customerId,
    receipt_email: params.email,
    automatic_payment_methods: { enabled: true },
    setup_future_usage: params.saveCard ? 'off_session' : undefined,
    metadata: params.metadata,
  });
  if (!intent.client_secret) throw new Error('Stripe did not return a client secret');
  return { clientSecret: intent.client_secret, paymentIntentId: intent.id };
}

/**
 * Hosted Checkout — payment mode (fund / setup fee).
 */
export async function createCheckoutSession(params: {
  amountMajor: number;
  currency?: string;
  customerId: string;
  email: string;
  successUrl: string;
  cancelUrl: string;
  metadata: Record<string, string>;
  saveCard?: boolean;
  productName?: string;
}): Promise<{ sessionId: string; url: string | null; mode: 'payment' }> {
  const currency = (params.currency || STRIPE_CURRENCY).toLowerCase();
  const stripe = getStripe();
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    customer: params.customerId,
    // Explicit card PM — required for NGN and other non-default currencies on this account
    payment_method_types: ['card'],
    line_items: [
      {
        quantity: 1,
        price_data: {
          currency,
          unit_amount: toMinorUnits(params.amountMajor, currency),
          product_data: {
            name: params.productName || 'Sigma Wealth investment',
          },
        },
      },
    ],
    success_url: params.successUrl,
    cancel_url: params.cancelUrl,
    payment_intent_data: {
      setup_future_usage: params.saveCard ? 'off_session' : undefined,
      metadata: params.metadata,
      receipt_email: params.email,
    },
    metadata: params.metadata,
  });

  if (!session.url) throw new Error('Stripe Checkout did not return a URL');
  return { sessionId: session.id, url: session.url, mode: 'payment' };
}

/**
 * Save card for auto-debit with $0 charge (Setup mode) — use when investor already funded.
 */
export async function createSetupCheckoutSession(params: {
  customerId: string;
  email: string;
  successUrl: string;
  cancelUrl: string;
  metadata: Record<string, string>;
  currency?: string;
}): Promise<{ sessionId: string; url: string | null; mode: 'setup' }> {
  const currency = (params.currency || STRIPE_CURRENCY).toLowerCase();
  const stripe = getStripe();
  const session = await stripe.checkout.sessions.create({
    mode: 'setup',
    customer: params.customerId,
    currency,
    payment_method_types: ['card'],
    success_url: params.successUrl,
    cancel_url: params.cancelUrl,
    metadata: params.metadata,
    setup_intent_data: {
      metadata: params.metadata,
    },
  });
  if (!session.url) throw new Error('Stripe Setup Checkout did not return a URL');
  return { sessionId: session.id, url: session.url, mode: 'setup' };
}

export async function retrievePaymentIntent(paymentIntentId: string) {
  return getStripe().paymentIntents.retrieve(paymentIntentId, {
    expand: ['payment_method', 'latest_charge'],
  });
}

export async function retrieveCheckoutSession(sessionId: string) {
  return getStripe().checkout.sessions.retrieve(sessionId, {
    expand: ['payment_intent', 'payment_intent.payment_method', 'setup_intent', 'setup_intent.payment_method'],
  });
}

export async function retrieveSetupIntent(setupIntentId: string) {
  return getStripe().setupIntents.retrieve(setupIntentId, {
    expand: ['payment_method'],
  });
}

export async function chargeSavedPaymentMethodOffSession(params: {
  amountMajor: number;
  currency?: string;
  customerId: string;
  paymentMethodId: string;
  metadata: Record<string, string>;
}): Promise<Stripe.PaymentIntent> {
  const currency = (params.currency || STRIPE_CURRENCY).toLowerCase();
  const stripe = getStripe();
  return stripe.paymentIntents.create({
    amount: toMinorUnits(params.amountMajor, currency),
    currency,
    customer: params.customerId,
    payment_method: params.paymentMethodId,
    off_session: true,
    confirm: true,
    metadata: params.metadata,
  });
}

export function constructStripeWebhookEvent(rawBody: Buffer | string, signature: string): Stripe.Event {
  const stripe = getStripe();
  if (!STRIPE_WEBHOOK_SECRET) {
    throw new Error('STRIPE_WEBHOOK_SECRET is not set');
  }
  return stripe.webhooks.constructEvent(rawBody, signature, STRIPE_WEBHOOK_SECRET);
}

export function cardBrandLast4FromPaymentMethod(pm: Stripe.PaymentMethod | string | null | undefined): {
  brand: string;
  last4: string;
  paymentMethodId: string | null;
} {
  if (!pm || typeof pm === 'string') {
    return { brand: 'Card', last4: '****', paymentMethodId: typeof pm === 'string' ? pm : null };
  }
  return {
    brand: pm.card?.brand || 'Card',
    last4: pm.card?.last4 || '****',
    paymentMethodId: pm.id,
  };
}

/**
 * Create a Connect account so investors receive payouts to their local bank worldwide.
 *
 * - Same-region (EEA) Express with full agreement when possible
 * - Cross-border (e.g. FI platform → NG/US/GB/…) uses recipient service agreement
 *   so Stripe can collect local bank details during hosted onboarding
 *
 * Docs: https://docs.stripe.com/connect/service-agreement-types
 *       https://docs.stripe.com/connect/express-accounts
 */
const EEA_COUNTRIES = new Set([
  'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU',
  'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE',
]);

function needsRecipientAgreement(investorCountry: string, platformCountry?: string | null): boolean {
  const c = investorCountry.toUpperCase();
  const platform = (platformCountry || 'FI').toUpperCase();
  if (c === platform) return false;
  // Cross-border outside shared EEA acquiring usually needs recipient agreement
  if (EEA_COUNTRIES.has(c) && EEA_COUNTRIES.has(platform)) return false;
  return true;
}

export async function createConnectExpressAccount(params: {
  email: string;
  country: string;
  userId: string;
}): Promise<string> {
  const stripe = getStripe();
  const country = String(params.country || 'US').toUpperCase();

  const platform = await stripe.accounts.retrieve();
  if (!platform.charges_enabled) {
    throw new Error(
      'Your Stripe platform must finish Activate Payments before investors can connect payout banks. Open https://dashboard.stripe.com/account/onboarding'
    );
  }

  const recipient = needsRecipientAgreement(country, platform.country);
  const common = {
    country,
    email: params.email,
    business_type: 'individual' as const,
    capabilities: {
      transfers: { requested: true as const },
    },
    metadata: {
      userId: params.userId,
      purpose: 'investor_local_bank_payout',
      country,
    },
    settings: {
      payouts: {
        schedule: { interval: 'manual' as const },
      },
    },
    business_profile: {
      product_description: 'Weekly investment return payouts from SigmawealthSolution',
      url: getFrontendBaseUrl(),
    },
  };

  try {
    if (recipient) {
      // Cross-border payouts (NG, US, UK, Africa, Asia, …) from an EEA platform
      const account = await stripe.accounts.create({
        ...common,
        tos_acceptance: { service_agreement: 'recipient' },
        controller: {
          fees: { payer: 'application' },
          losses: { payments: 'application' },
          requirement_collection: 'stripe',
          stripe_dashboard: { type: 'express' },
        },
      });
      return account.id;
    }

    const account = await stripe.accounts.create({
      ...common,
      type: 'express',
    });
    return account.id;
  } catch (primaryErr: any) {
    const msg = String(primaryErr?.message || primaryErr || '');
    // Fallback: let Stripe hosted onboarding pick country (still Express)
    if (/country|not supported|invalid/i.test(msg)) {
      try {
        const account = await stripe.accounts.create({
          type: 'express',
          email: params.email,
          business_type: 'individual',
          capabilities: { transfers: { requested: true } },
          metadata: {
            userId: params.userId,
            purpose: 'investor_local_bank_payout',
            preferred_country: country,
          },
          settings: { payouts: { schedule: { interval: 'manual' } } },
          business_profile: {
            product_description: 'Weekly investment return payouts from SigmawealthSolution',
            url: getFrontendBaseUrl(),
          },
        });
        return account.id;
      } catch (fallbackErr: any) {
        throw new Error(
          fallbackErr?.message ||
            msg ||
            `Stripe could not create a payout account for ${country}. In Stripe Dashboard → Settings → Connect, enable that country for Express/recipient onboarding.`
        );
      }
    }
    throw new Error(
      msg ||
        `Stripe could not create a payout account for ${country}. Enable the country under Connect settings, then retry.`
    );
  }
}

export async function createConnectOnboardingLink(params: {
  accountId: string;
  refreshUrl: string;
  returnUrl: string;
}): Promise<string> {
  const stripe = getStripe();
  const link = await stripe.accountLinks.create({
    account: params.accountId,
    refresh_url: params.refreshUrl,
    return_url: params.returnUrl,
    type: 'account_onboarding',
  });
  return link.url;
}

/** Resolve payout currency from Connect account (matches investor's linked bank country). */
export async function resolveConnectPayoutCurrency(
  stripeAccountId: string,
  hint?: string
): Promise<string> {
  try {
    const acct = await getStripe().accounts.retrieve(stripeAccountId);
    return normalizeCurrency(hint || acct.default_currency || STRIPE_CURRENCY);
  } catch {
    return normalizeCurrency(hint || STRIPE_CURRENCY);
  }
}

/**
 * Pay investor via Stripe Connect Transfer to their connected account.
 * Connected account pays out to their local bank (ACH, IBAN, SEPA, etc.).
 */
export async function sendInvestorPayout(params: {
  amountMajor: number;
  currency?: string;
  stripeAccountId?: string | null;
  description: string;
  metadata?: Record<string, string>;
}): Promise<{
  success: boolean;
  transferId: string;
  simulated: boolean;
  currency?: string;
  message?: string;
}> {
  if (!isStripeConfigured()) {
    return {
      success: false,
      transferId: '',
      simulated: false,
      message: 'Stripe is not configured for payouts.',
    };
  }

  if (!params.stripeAccountId) {
    return {
      success: false,
      transferId: '',
      simulated: false,
      message:
        'Investor must connect a Stripe payout account (Connect Express). Complete bank onboarding in the dashboard.',
    };
  }

  try {
    const currency = await resolveConnectPayoutCurrency(params.stripeAccountId, params.currency);
    const transfer = await getStripe().transfers.create({
      amount: toMinorUnits(params.amountMajor, currency),
      currency,
      destination: params.stripeAccountId,
      description: params.description.slice(0, 500),
      metadata: params.metadata || {},
    });
    return { success: true, transferId: transfer.id, simulated: false, currency };
  } catch (err: any) {
    return {
      success: false,
      transferId: '',
      simulated: false,
      message: err.message || 'Stripe transfer failed',
    };
  }
}

export type PayoutDestinationInput = {
  country: string;
  currency: string;
  accountHolderName: string;
  routingNumber?: string;
  accountNumber?: string;
  bankCode?: string;
  bankName?: string;
  iban?: string;
  bic?: string;
  stripeAccountId?: string | null;
};

export function validatePayoutDestination(d: PayoutDestinationInput): string | null {
  // Prefer Connect account — bank fields optional once connected
  if (d.stripeAccountId) return null;

  const country = String(d.country || '').toUpperCase();
  if (!d.accountHolderName?.trim()) return 'Account holder name is required';
  if (!country || country.length !== 2) return 'Select a valid country (ISO-2, e.g. NG, US, GB)';

  if (country === 'US') {
    if (!d.routingNumber || !/^\d{9}$/.test(d.routingNumber)) return 'US routing number must be 9 digits';
    if (!d.accountNumber || d.accountNumber.replace(/\D/g, '').length < 4) return 'US account number is required';
    return null;
  }
  if (country === 'NG') {
    if (!d.accountNumber || !/^\d{10}$/.test(d.accountNumber)) return 'Nigerian NUBAN must be 10 digits';
    if (!d.bankCode && !d.bankName) return 'Select a Nigerian bank';
    return null;
  }
  if (d.iban && d.iban.replace(/\s/g, '').length >= 15) return null;
  if (d.accountNumber && d.bic) return null;
  return 'Connect Stripe payouts, or provide IBAN / account+BIC for this country';
}

/** Payouts run through Stripe Connect — connected account required for manual + automatic + referral. */
export function hasValidPayoutDestination(bank: any): boolean {
  return Boolean(bank?.stripe_account_id);
}

export { currencyForCountry, formatMoney, isSupportedPaymentCurrency, normalizeCurrency };

export function productionStripeHints() {
  return {
    webhookUrl: getStripeWebhookUrl(),
    successUrlExample: getStripeSuccessUrl('REFERENCE'),
    cancelUrl: getStripeCancelUrl(),
    connectReturnUrl: `${getFrontendBaseUrl()}/dashboard?connect_return=1`,
    connectRefreshUrl: `${getFrontendBaseUrl()}/dashboard?connect_refresh=1`,
    note:
      'In Stripe Dashboard → Developers → Webhooks, add the webhookUrl and listen for checkout.session.completed, payment_intent.succeeded, setup_intent.succeeded, account.updated. Use live keys (sk_live / pk_live) for production.',
  };
}
