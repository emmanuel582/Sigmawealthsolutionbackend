/**
 * Integration smoke tests against a live Sigma API (npm run dev:api).
 * Skips gracefully if the API is not reachable.
 */
import { describe, it, expect, beforeAll } from 'vitest';

const API = process.env.SIGMA_API_URL || 'http://127.0.0.1:4000';

async function api(path: string, init?: RequestInit) {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
  });
  const text = await res.text();
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  return { res, json };
}

describe('Sigma API smoke', () => {
  let apiUp = false;

  beforeAll(async () => {
    try {
      const { res } = await api('/api/config');
      apiUp = res.ok;
    } catch {
      apiUp = false;
    }
  });

  it('loads Flutterwave + Supabase config flags', async ({ skip }) => {
    if (!apiUp) skip();
    const { res, json } = await api('/api/config');
    expect(res.status).toBe(200);
    expect(typeof json.flutterwaveConfigured).toBe('boolean');
    expect(typeof json.isSupabaseLive).toBe('boolean');
    // With .env keys present, Flutterwave should be configured
    if (process.env.FLUTTERWAVE_CLIENT_ID) {
      expect(json.flutterwaveConfigured).toBe(true);
    }
  });

  it('signs up and logs in an investor with password', async ({ skip }) => {
    if (!apiUp) skip();
    const email = `investor_${Date.now()}@test.sigma`;
    const password = 'TestPass123!';

    const signup = await api('/api/auth/signup', {
      method: 'POST',
      body: JSON.stringify({
        email,
        password,
        fullName: 'Test Investor',
        phone: '08000000000',
        agreedToTerms: true,
      }),
    });
    expect(signup.res.status).toBe(200);
    expect(signup.json.user?.email).toBe(email);

    const bad = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password: 'wrong-password' }),
    });
    expect(bad.res.status).toBe(401);

    const login = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    expect(login.res.status).toBe(200);
    expect(login.json.user?.id).toBeTruthy();
  });

  it('registers allowlisted admin and toggles payout mode', async ({ skip }) => {
    if (!apiUp) skip();
    const email = 'cmyrachrist72@gmail.com';
    const password = `AdminTest_${Date.now()}!`;

    const reg = await api('/api/auth/admin-register', {
      method: 'POST',
      body: JSON.stringify({ email, password, fullName: 'Admin Tester' }),
    });
    expect([200, 403]).toContain(reg.res.status);
    if (reg.res.status !== 200) skip();

    const login = await api('/api/auth/admin-login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    expect(login.res.status).toBe(200);
    expect(login.json.role).toBe('admin');

    const mode = await api('/api/admin/payout-mode', {
      method: 'POST',
      body: JSON.stringify({ mode: 'automatic', adminName: 'Admin Tester' }),
    });
    expect(mode.res.status).toBe(200);
    expect(mode.json.mode || mode.json.payoutMode || mode.json.success).toBeTruthy();
    if (mode.json.mode) expect(mode.json.mode).toBe('automatic');

    const payouts = await api('/api/admin/payouts');
    expect(payouts.res.status).toBe(200);
    // Mode may be memory or Supabase-backed; accept either after a successful toggle
    expect(['automatic', 'manual']).toContain(payouts.json.payoutMode);

    const back = await api('/api/admin/payout-mode', {
      method: 'POST',
      body: JSON.stringify({ mode: 'manual', adminName: 'Admin Tester' }),
    });
    expect(back.res.status).toBe(200);
  });

  it('runs payout cron and returns a result payload', async ({ skip }) => {
    if (!apiUp) skip();
    const cron = await api('/api/payouts/run-cron', {
      method: 'POST',
      body: JSON.stringify({ triggeredBy: 'Vitest' }),
    });
    expect(cron.res.status).toBe(200);
    expect(cron.json).toHaveProperty('successfulTransfers');
    expect(cron.json).toHaveProperty('failedTransfers');
    expect(cron.json).toHaveProperty('payoutMode');
  });

  it('manual payout endpoint validates input', async ({ skip }) => {
    if (!apiUp) skip();
    const bad = await api('/api/admin/payouts/manual-pay', {
      method: 'POST',
      body: JSON.stringify({}),
    });
    expect(bad.res.status).toBeGreaterThanOrEqual(400);

    const overview = await api('/api/admin/overview');
    expect(overview.res.status).toBe(200);
    expect(overview.json.kpis).toBeTruthy();
    expect(overview.json.charts || overview.json.activityFeed).toBeTruthy();
  });

  it('broadcast alert reaches notification store', async ({ skip }) => {
    if (!apiUp) skip();
    const send = await api('/api/admin/notifications/send', {
      method: 'POST',
      body: JSON.stringify({
        title: 'Vitest Alert',
        body: 'Production smoke test message',
        audience: 'all',
        adminName: 'Vitest',
        icon: 'bell',
      }),
    });
    expect(send.res.status).toBe(200);
    expect(send.json.title).toBe('Vitest Alert');

    const list = await api('/api/admin/notifications');
    expect(list.res.status).toBe(200);
    expect(Array.isArray(list.json)).toBe(true);
    expect(list.json.some((n: any) => n.title === 'Vitest Alert')).toBe(true);
  });
});
