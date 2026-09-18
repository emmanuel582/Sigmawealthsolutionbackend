/** Shared money / currency helpers — used by frontend and API server. */

export const SUPPORTED_PAYMENT_CURRENCIES = [
  'usd',
  'eur',
  'gbp',
  'ngn',
  'cad',
  'aud',
  'zar',
  'ghs',
  'kes',
  'chf',
  'sek',
  'nok',
  'dkk',
  'pln',
  'jpy',
  'sgd',
  'hkd',
  'inr',
  'brl',
  'mxn',
] as const;

export type PaymentCurrency = (typeof SUPPORTED_PAYMENT_CURRENCIES)[number];

/** ISO-3166 alpha-2 → default settlement currency (Stripe Connect / Checkout). */
export const COUNTRY_CURRENCY: Record<string, string> = {
  NG: 'NGN',
  US: 'USD',
  GB: 'GBP',
  DE: 'EUR',
  FR: 'EUR',
  IT: 'EUR',
  ES: 'EUR',
  NL: 'EUR',
  BE: 'EUR',
  AT: 'EUR',
  IE: 'EUR',
  PT: 'EUR',
  FI: 'EUR',
  CA: 'CAD',
  AU: 'AUD',
  NZ: 'NZD',
  ZA: 'ZAR',
  GH: 'GHS',
  KE: 'KES',
  AE: 'AED',
  SA: 'SAR',
  IN: 'INR',
  SG: 'SGD',
  HK: 'HKD',
  JP: 'JPY',
  CH: 'CHF',
  SE: 'SEK',
  NO: 'NOK',
  DK: 'DKK',
  PL: 'PLN',
  BR: 'BRL',
  MX: 'MXN',
};

export function normalizeCurrency(code?: string | null): string {
  return String(code || 'usd').trim().toLowerCase();
}

export function currencyForCountry(country?: string | null): string {
  const cc = String(country || 'US').trim().toUpperCase();
  return (COUNTRY_CURRENCY[cc] || 'USD').toLowerCase();
}

export function isSupportedPaymentCurrency(code: string): boolean {
  return SUPPORTED_PAYMENT_CURRENCIES.includes(normalizeCurrency(code) as PaymentCurrency);
}

export function localeForCurrency(currency: string): string {
  const c = normalizeCurrency(currency);
  const map: Record<string, string> = {
    usd: 'en-US',
    gbp: 'en-GB',
    eur: 'de-DE',
    ngn: 'en-NG',
    cad: 'en-CA',
    aud: 'en-AU',
    zar: 'en-ZA',
    jpy: 'ja-JP',
    inr: 'en-IN',
    brl: 'pt-BR',
    mxn: 'es-MX',
  };
  return map[c] || 'en-US';
}

export function formatMoney(
  amount: number | string | undefined | null,
  currency = 'usd',
  includeDecimals = false
): string {
  if (amount === undefined || amount === null || Number.isNaN(Number(amount))) {
    return formatMoney(0, currency, includeDecimals);
  }
  const numeric = Number(amount);
  const cur = normalizeCurrency(currency).toUpperCase();
  const zeroDecimal = new Set(['JPY', 'KRW', 'VND', 'CLP', 'UGX', 'XAF', 'XOF']);
  const decimals = zeroDecimal.has(cur) ? 0 : includeDecimals ? 2 : 0;
  try {
    return new Intl.NumberFormat(localeForCurrency(cur), {
      style: 'currency',
      currency: cur,
      minimumFractionDigits: decimals,
      maximumFractionDigits: decimals,
    }).format(numeric);
  } catch {
    return `${cur} ${numeric.toLocaleString()}`;
  }
}

export function payoutCountryOptions(): Array<{ code: string; label: string }> {
  return [
    { code: 'NG', label: 'Nigeria' },
    { code: 'US', label: 'United States' },
    { code: 'GB', label: 'United Kingdom' },
    { code: 'CA', label: 'Canada' },
    { code: 'AU', label: 'Australia' },
    { code: 'DE', label: 'Germany' },
    { code: 'FR', label: 'France' },
    { code: 'IE', label: 'Ireland' },
    { code: 'NL', label: 'Netherlands' },
    { code: 'ES', label: 'Spain' },
    { code: 'IT', label: 'Italy' },
    { code: 'PT', label: 'Portugal' },
    { code: 'BE', label: 'Belgium' },
    { code: 'AT', label: 'Austria' },
    { code: 'SE', label: 'Sweden' },
    { code: 'NO', label: 'Norway' },
    { code: 'DK', label: 'Denmark' },
    { code: 'FI', label: 'Finland' },
    { code: 'CH', label: 'Switzerland' },
    { code: 'PL', label: 'Poland' },
    { code: 'GH', label: 'Ghana' },
    { code: 'KE', label: 'Kenya' },
    { code: 'ZA', label: 'South Africa' },
    { code: 'EG', label: 'Egypt' },
    { code: 'AE', label: 'United Arab Emirates' },
    { code: 'SA', label: 'Saudi Arabia' },
    { code: 'IN', label: 'India' },
    { code: 'SG', label: 'Singapore' },
    { code: 'HK', label: 'Hong Kong' },
    { code: 'JP', label: 'Japan' },
    { code: 'KR', label: 'South Korea' },
    { code: 'BR', label: 'Brazil' },
    { code: 'MX', label: 'Mexico' },
    { code: 'PH', label: 'Philippines' },
    { code: 'MY', label: 'Malaysia' },
    { code: 'NZ', label: 'New Zealand' },
  ];
}
