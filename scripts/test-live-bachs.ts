import 'dotenv/config';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { FUNDING_PLAN_AMOUNTS } from '../lib/sigma/fundingPlans.js';
import { bachsRequest, decimalAmount } from '../server/lib/bachsPayments.js';
import { isPlatformConnectReady } from '../server/lib/bachsCapabilities.js';

// Explicit command only: creates unpaid sessions with the configured key.
// No saved cards, customers, charges, transfers or payouts are created.
async function main() {
const report: any = { testedAt: new Date().toISOString(), realProvider: true, moneyMoved: false, checkouts: [], deployment: [] };
const account = await bachsRequest('/v1/accounts/me');
report.account = { active: account.is_active, capabilities: account.enabled_capabilities, connectActive: await isPlatformConnectReady(account) };
const settings = await bachsRequest('/v1/accounts/checkout/settings');
report.checkoutSettings = { feePreference: settings.fee_preference, enabledPaymentMethods: settings.enabled_payment_methods };
for (const amount of FUNDING_PLAN_AMOUNTS) {
  const reference = `sigma-integration-test-${amount}-${crypto.randomUUID()}`;
  try {
    const session = await bachsRequest('/v1/checkout-sessions', { method: 'POST', idempotencyKey: reference, body: {
      pricing: { amount: decimalAmount(amount), currency: 'NGN' }, reference,
      metadata: { purpose: 'Unpaid integration verification', planAmount: String(amount) },
      success_url: 'https://sigmawealthsolution.com/dashboard?integration_test=1',
      cancel_url: 'https://sigmawealthsolution.com/dashboard?integration_test=1',
    } });
    assert.ok(session.checkout_id); assert.equal(session.status, 'open');
    assert.equal(new URL(session.checkout_url).hostname, process.env.BACHS_API_KEY?.startsWith('sk_sandbox_') ? 'sandbox-checkout.bachs.io' : 'checkout.bachs.io');
    const retrieved = await bachsRequest(`/v1/checkout-sessions/${encodeURIComponent(session.checkout_id)}`);
    assert.equal(decimalAmount(retrieved.amount), decimalAmount(amount));
    assert.equal(retrieved.currency, 'NGN'); assert.equal(retrieved.reference, reference);
    assert.equal(retrieved.status, 'open'); assert.ok(!retrieved.charge);
    report.checkouts.push({ amount, passed: true, checkoutId: session.checkout_id, status: retrieved.status, expiresAt: session.expires_at });
  } catch (error: any) {
    report.checkouts.push({ amount, passed: false, code: error.code, message: error.message });
  }
}
for (const base of ['https://sigmawealthsolution.com', 'https://sigmawealthsolutionbackend.onrender.com']) {
  const checks = await Promise.all(['/api/config','/api/admin/overview'].map(async path => {
    try {
      const response = await fetch(base+path, { signal: AbortSignal.timeout(60000) });
      const data = await response.json().catch(() => ({}));
      return { path, status: response.status, provider: data.paymentProvider, fixedPlans: data.fundingPlanAmounts, protected: path.includes('/admin/') ? response.status === 401 : undefined };
    } catch { return { path, reachable: false }; }
  }));
  report.deployment.push({ base, checks });
}
await fs.mkdir('reports', { recursive: true });
await fs.writeFile('reports/bachs-live-test.json', JSON.stringify(report, null, 2)+'\n');
console.log(JSON.stringify(report, null, 2));
if (report.checkouts.some((c: any) => !c.passed)) process.exitCode = 1;
}
main().catch(() => { console.error('Live provider test could not start; check account API access and network connectivity.'); process.exitCode = 1; });
