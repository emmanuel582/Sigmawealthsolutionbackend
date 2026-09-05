import crypto from "crypto";
const TOKEN_URL = "https://idp.flutterwave.com/realms/flutterwave/protocol/openid-connect/token";
const SANDBOX_API = "https://developersandbox-api.flutterwave.com";
const LIVE_API = "https://api.flutterwave.com";
let cachedToken = null;
function getApiBase() {
  const mode = (process.env.FLUTTERWAVE_ENV || "sandbox").toLowerCase();
  return mode === "live" ? LIVE_API : SANDBOX_API;
}
function getClientId() {
  return (process.env.FLUTTERWAVE_CLIENT_ID || process.env.VITE_FLUTTERWAVE_PUBLIC_KEY || "").trim();
}
function getClientSecret() {
  return (process.env.FLUTTERWAVE_CLIENT_SECRET || process.env.FLUTTERWAVE_SECRET_KEY || "").trim();
}
function isFlutterwaveConfigured() {
  return Boolean(getClientId() && getClientSecret());
}
function isSandboxMode() {
  return (process.env.FLUTTERWAVE_ENV || "sandbox").toLowerCase() !== "live";
}
async function getAccessToken() {
  const clientId = getClientId();
  const clientSecret = getClientSecret();
  if (!clientId || !clientSecret) {
    throw new Error("Flutterwave credentials are not configured.");
  }
  const now = Date.now();
  if (cachedToken && cachedToken.expiresAt > now + 6e4) {
    return cachedToken.token;
  }
  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "client_credentials"
  });
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const data = await res.json();
  if (!res.ok || !data.access_token) {
    throw new Error(data.error_description || data.message || "Failed to obtain Flutterwave access token.");
  }
  cachedToken = {
    token: data.access_token,
    expiresAt: now + (data.expires_in || 600) * 1e3
  };
  return data.access_token;
}
function generateNonce(length = 12) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  for (let i = 0; i < length; i++) {
    out += chars[crypto.randomInt(0, chars.length)];
  }
  return out;
}
function encryptAesGcm(plainText, nonce) {
  const keyB64 = process.env.FLUTTERWAVE_ENCRYPTION_KEY || "";
  if (!keyB64) throw new Error("FLUTTERWAVE_ENCRYPTION_KEY is not configured.");
  if (nonce.length !== 12) throw new Error("Nonce must be 12 characters.");
  const key = Buffer.from(keyB64, "base64");
  const iv = Buffer.from(nonce, "utf8");
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([encrypted, tag]).toString("base64");
}
function splitName(fullName) {
  const parts = (fullName || "Investor").trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return { first: "Investor", last: "User" };
  if (parts.length === 1) return { first: parts[0], last: parts[0] };
  return {
    first: parts[0],
    ...parts.length > 2 ? { middle: parts.slice(1, -1).join(" ") } : {},
    last: parts[parts.length - 1]
  };
}
async function flwRequest(path, options = {}) {
  const token = await getAccessToken();
  const headers = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    "X-Trace-Id": crypto.randomUUID()
  };
  if (options.scenarioKey) headers["X-Scenario-Key"] = options.scenarioKey;
  if (options.idempotencyKey) headers["X-Idempotency-Key"] = options.idempotencyKey;
  const res = await fetch(`${getApiBase()}${path}`, {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : void 0
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    console.error("Flutterwave API Error Payload:", JSON.stringify(data, null, 2));
    const msg = data?.error?.message || data?.message || `Flutterwave API error (${res.status})`;
    const error = new Error(msg);
    error.payload = data;
    throw error;
  }
  return data;
}
const SANDBOX_TEST_CARD = {
  number: "1234120000002222",
  expiryMonth: "08",
  expiryYear: "32",
  cvv: "123",
  pin: "12345"
};
function buildEncryptedCardPayload(card = SANDBOX_TEST_CARD) {
  const nonce = generateNonce(12);
  return {
    nonce,
    encrypted_card_number: encryptAesGcm(card.number, nonce),
    encrypted_expiry_month: encryptAesGcm(card.expiryMonth, nonce),
    encrypted_expiry_year: encryptAesGcm(card.expiryYear, nonce),
    encrypted_cvv: encryptAesGcm(card.cvv, nonce)
  };
}
async function initiateDirectCharge(params) {
  const name = splitName(params.name);
  const phoneDigits = (params.phone || "08000000000").replace(/\D/g, "").slice(-10);
  const body = {
    amount: params.amount,
    currency: params.currency || "NGN",
    reference: params.reference,
    redirect_url: params.redirectUrl,
    customer: {
      email: params.email,
      name,
      phone: { country_code: "234", number: phoneDigits },
      address: {
        city: "Lagos",
        country: "NG",
        line1: "Sigma Wealth Solution",
        postal_code: "100001",
        state: "Lagos"
      }
    },
    meta: params.meta || {}
  };
  if (params.paymentType === "opay") {
    body.payment_method = { type: "opay" };
  } else {
    const card = params.card || SANDBOX_TEST_CARD;
    body.payment_method = {
      type: "card",
      card: buildEncryptedCardPayload(card)
    };
  }
  return flwRequest("/orchestration/direct-charges", {
    method: "POST",
    body,
    idempotencyKey: params.reference,
    scenarioKey: isSandboxMode() ? "scenario:auth_3ds&issuer:approved" : void 0
  });
}
async function getCharge(chargeId) {
  return flwRequest(`/charges/${chargeId}`, { method: "GET" });
}
async function authorizeCharge(chargeId, authorization, scenarioKey) {
  return flwRequest(`/charges/${chargeId}`, {
    method: "PUT",
    body: { authorization },
    scenarioKey: scenarioKey || (isSandboxMode() ? "scenario:auth_3ds&issuer:approved" : void 0)
  });
}
async function getBanks(country = "NG") {
  return flwRequest(`/banks?country=${country}`);
}
async function resolveBankAccount(accountNumber, bankCode) {
  return flwRequest("/banks/account-resolve", {
    method: "POST",
    body: { account_number: accountNumber, bank_code: bankCode }
  });
}
async function createDirectTransfer(params) {
  return flwRequest("/direct-transfers", {
    method: "POST",
    body: {
      type: "bank",
      action: "instant",
      reference: params.reference,
      narration: params.narration,
      payment_instruction: {
        amount: { value: params.amount, applies_to: "destination_currency" },
        source_currency: "NGN",
        destination_currency: "NGN"
      },
      recipient: {
        bank: {
          account_number: params.accountNumber,
          code: params.bankCode
        }
      }
    },
    idempotencyKey: params.reference,
    scenarioKey: isSandboxMode() ? "scenario:transfer_success&issuer:approved" : void 0
  });
}
async function completeSandboxCharge(chargeId) {
  let charge = (await getCharge(chargeId)).data;
  let guard = 0;
  while (charge?.status === "pending" && charge.next_action && guard < 6) {
    guard += 1;
    const next = charge.next_action;
    if (next.type === "authorize" && next.authorization?.type === "pin") {
      const pinNonce = generateNonce(12);
      const res = await authorizeCharge(chargeId, {
        type: "pin",
        pin: {
          nonce: pinNonce,
          encrypted_pin: encryptAesGcm(SANDBOX_TEST_CARD.pin, pinNonce)
        }
      });
      charge = res.data;
      continue;
    }
    if (next.type === "redirect_url") {
      const url = next.redirect_url?.url || next.redirect_url;
      return { charge, redirectUrl: typeof url === "string" ? url : null };
    }
    break;
  }
  return { charge, redirectUrl: null };
}
export {
  SANDBOX_TEST_CARD,
  authorizeCharge,
  buildEncryptedCardPayload,
  completeSandboxCharge,
  createDirectTransfer,
  encryptAesGcm,
  flwRequest,
  generateNonce,
  getAccessToken,
  getBanks,
  getCharge,
  initiateDirectCharge,
  isFlutterwaveConfigured,
  isSandboxMode,
  resolveBankAccount,
  splitName
};
